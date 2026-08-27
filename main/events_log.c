#include "sdkconfig.h"

#include "events_log.h"

#if CONFIG_ENABLE_SD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_attr.h"

#include "config.h"
#include "sdcard.h"

static const char TAG[] = "EVENTS";

#define EV_DIR   CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define EV_CSV   EV_DIR "/events.csv"

/* Events awaiting an SD write, drained by the sysmon tick so SD I/O never
 * blocks the sniffer path. On overflow the oldest queued event is dropped. */
#define EV_EVENT_GAP_SEC 120  /* silence after which an event counts as over */
#define EV_QUEUE  32
static event_rec_t s_queue[EV_QUEUE];
static int s_qhead, s_qcount;
/* Monotone: a ring-index delta cannot tell "nothing moved" from exactly
 * EV_QUEUE evictions. Never reset; only compared across one write. */
static uint32_t s_evicted;
static SemaphoreHandle_t s_lock;
static uint32_t s_flushes;

void events_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

/* Events still being repeated, held back so their count can keep rising.
 * SEVERAL slots: senders interleave, and one slot flushes on every swap. */
#define EV_OPEN 8
static event_rec_t s_open[EV_OPEN];
static bool s_open_valid[EV_OPEN];

static void queue_locked(const event_rec_t *e)
{
    int i = (s_qhead + s_qcount) % EV_QUEUE;
    s_queue[i] = *e;
    if (s_qcount < EV_QUEUE)
        s_qcount++;
    else
    {
        s_qhead = (s_qhead + 1) % EV_QUEUE;   /* overwrite oldest */
        s_evicted++;
    }
}

/* 0 dBm is "the driver had no reading" (wired path), not a level -- it must
 * neither open nor widen the span. */
static inline void ev_rssi_fold(event_rec_t *e, int rssi)
{
    if (rssi >= 0 || rssi <= -128)
        return;
    if (!e->rssi_max || rssi > e->rssi_max) e->rssi_max = (int8_t)rssi;
    if (!e->rssi_min || rssi < e->rssi_min) e->rssi_min = (int8_t)rssi;
}

/* A second radio address on one ActionID means the warning was re-broadcast;
 * the station id stays the originator's, so only this can show it. */
static void ev_mac_fold(event_rec_t *e, const uint8_t *mac, uint32_t seconds)
{
    if (!e->n_macs)
    {
        memcpy(e->mac_a, mac, 6);
        e->n_macs = 1;
        return;
    }
    if (memcmp(e->mac_a, mac, 6) == 0)
        return;
    if (!e->count_b)
    {
        memcpy(e->mac_b, mac, 6);
        uint32_t d = seconds > e->seconds ? seconds - e->seconds : 0;
        e->b_after_s = d > 0xFFFFu ? 0xFFFFu : (uint16_t)d;
        e->n_macs = 2;
    }
    if (memcmp(e->mac_b, mac, 6) == 0)
    {
        if (e->count_b < 0xFFFF) e->count_b++;
    }
    else if (e->n_macs < 255)
        e->n_macs++;
}

void events_note(uint32_t seconds, uint8_t station_type, uint32_t sender_id, int rssi,
                 uint8_t message_id,
                 uint8_t cause, uint8_t subcause,
                 uint32_t action_station, uint16_t action_seq,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7,
                 const uint8_t *src_mac)
{
    if (message_id != 1 || !s_lock)   /* 1 = DENM (warning) */
        return;
    /* Reject pre-clock timestamps: a fictional `newest` makes the retention
     * cutoff below underflow and empties the whole file. */
    if (seconds < 1600000000u)
        return;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;

    /* An ActionID left at 0/0 would collapse every warning -- and different
     * senders with it -- into one row; synthesise an identity instead. */
    if (action_station == 0 && action_seq == 0)
    {
        action_station = sender_id;
        action_seq = (uint16_t)((cause << 8) | subcause);
    }

    /* Already tracking this event? Then this is just another broadcast of it
     * -- count it, keep the newest position. */
    int free_slot = -1, oldest = 0;
    for (int i = 0; i < EV_OPEN; i++)
    {
        if (!s_open_valid[i])
        {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (s_open[i].action_station == action_station &&
            s_open[i].action_seq == action_seq)
        {
            s_open[i].last_seen = seconds;
            if (s_open[i].count < 0xFFFF) s_open[i].count++;
            if (src_mac) ev_mac_fold(&s_open[i], src_mac, seconds);
            if (has_pos) { s_open[i].lat_e7 = lat_e7; s_open[i].lon_e7 = lon_e7; }
            /* Level only from the stored sender; id 0 means "unknown", so it must
             * not match 0 -- and it may be that same sender, hence no marker. */
            if (sender_id && (!s_open[i].sender_id || s_open[i].sender_id == sender_id))
            {
                s_open[i].sender_id = sender_id;   /* adopt the first id we learn */
                ev_rssi_fold(&s_open[i], rssi);
            }
            else if (sender_id)
                s_open[i].multi_sender = true;
            xSemaphoreGive(s_lock);
            return;
        }
        if (s_open[i].last_seen < s_open[oldest].last_seen)
            oldest = i;
    }

    int slot = free_slot;
    if (slot < 0)
    {
        slot = oldest;                 /* all busy: the stalest one is done */
        queue_locked(&s_open[slot]);
    }

    /* No id, no level: a synthesised ActionID groups unknown senders, and their
     * span would be an artefact rather than a measurement. */
    int8_t r0 = (sender_id && rssi < 0 && rssi > -128) ? (int8_t)rssi : 0;

    s_open[slot] = (event_rec_t){
        .seconds = seconds, .last_seen = seconds,
        .action_station = action_station, .action_seq = action_seq,
        .count = 1, .station_type = station_type, .cause = cause,
        .subcause = subcause,
        .lat_e7 = has_pos ? lat_e7 : 0, .lon_e7 = has_pos ? lon_e7 : 0,
        .sender_id = sender_id, .rssi_min = r0, .rssi_max = r0,
        .multi_sender = false,
    };
    /* A designated initialiser cannot copy an array; the literal zeroed it. */
    if (src_mac) { memcpy(s_open[slot].mac_a, src_mac, 6); s_open[slot].n_macs = 1; }
    s_open_valid[slot] = true;

    xSemaphoreGive(s_lock);
}

#define EV_TMP   EV_DIR "/events.tmp"

/* Streams to a temp file and swaps: a fixed read-all buffer silently drops the
 * NEWEST rows once the file outgrows it. */
static void prune(uint32_t keep_from_sec)
{
    FILE *f = fopen(EV_CSV, "r");
    if (!f)
        return;
    FILE *w = fopen(EV_TMP, "w");
    if (!w)
    {
        fclose(f);
        return;
    }

    char line[192];   /* a full 17-field row is 130 B; a split one would be copied as two */
    bool ok = true;
    while (fgets(line, sizeof(line), f))
    {
        unsigned long sec = strtoul(line, NULL, 10);
        if (sec < keep_from_sec)
            continue;
        if (fputs(line, w) == EOF) { ok = false; break; }
    }
    fclose(f);
    if (fclose(w) != 0)
        ok = false;

    if (ok)
    {
        remove(EV_CSV);
        rename(EV_TMP, EV_CSV);
    }
    else
        remove(EV_TMP);
}
void events_tick(void)
{
    if (!s_lock)
        return;

    /* An event that has gone quiet is finished -- hand it to the queue so it
     * shows up even when no other warning follows it. */
    if (xSemaphoreTake(s_lock, 0) == pdTRUE)
    {
        uint32_t now = (uint32_t)time(NULL);
        for (int i = 0; i < EV_OPEN; i++)
            if (s_open_valid[i] && now > s_open[i].last_seen &&
                now - s_open[i].last_seen > EV_EVENT_GAP_SEC)
            {
                queue_locked(&s_open[i]);
                s_open_valid[i] = false;
            }
        xSemaphoreGive(s_lock);
    }

    if (s_qcount == 0 || !sdcard_is_mounted())
        return;

    /* Guards append and prune against unmount/format and a concurrent
     * events_read(). Bounded: sysmon is the watchdog task and must not block. */
    if (!sdcard_io_begin_timeout(2000))
        return;

    /* Copy WITHOUT consuming; clear the queue only once the rows are on the
     * card, or a failed fopen throws the warnings away for good. */
    /* PSRAM: 1792 bytes of scarce internal RAM for a buffer only the sysmon
     * tick touches, never the packet path. */
    static EXT_RAM_BSS_ATTR event_rec_t batch[EV_QUEUE];
    int count;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE)
    {
        sdcard_io_end();
        return;
    }
    count = s_qcount;
    /* RE-CHECK under the lock: events_tick has two callers on different tasks,
     * so the other can drain the queue while we wait on the SD guard. */
    if (count == 0)
    {
        xSemaphoreGive(s_lock);
        sdcard_io_end();
        return;
    }
    uint32_t evicted_at_copy = s_evicted;
    for (int i = 0; i < count; i++)
        batch[i] = s_queue[(s_qhead + i) % EV_QUEUE];
    xSemaphoreGive(s_lock);

    mkdir(EV_DIR, 0777);
    FILE *f = fopen(EV_CSV, "a");
    if (!f)
    {
        ESP_LOGW(TAG, "cannot open %s", EV_CSV);
        sdcard_io_end();
        return;
    }
    uint32_t newest = 0;
    bool ok = true;
    for (int i = 0; i < count && ok; i++)
    {
        /* New columns are APPENDED, so old readers keep finding fields 1-8 in
         * place. multi_sender goes to the card too, or a restart would lose it. */
        const uint8_t *ma = batch[i].mac_a, *mb = batch[i].mac_b;
        ok = fprintf(f, "%lu,%u,%u,%ld,%ld,%u,%lu,%u,%lu,%d,%d,%u,"
                        "%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x,%u,%u,%u\n",
                     (unsigned long)batch[i].seconds, batch[i].station_type,
                     batch[i].cause, (long)batch[i].lat_e7, (long)batch[i].lon_e7,
                     (unsigned)batch[i].count, (unsigned long)batch[i].last_seen,
                     (unsigned)batch[i].subcause,
                     (unsigned long)batch[i].sender_id,
                     batch[i].rssi_min, batch[i].rssi_max,
                     batch[i].multi_sender ? 1u : 0u,
                     ma[0], ma[1], ma[2], ma[3], ma[4], ma[5],
                     mb[0], mb[1], mb[2], mb[3], mb[4], mb[5],
                     (unsigned)batch[i].count_b, (unsigned)batch[i].b_after_s,
                     (unsigned)batch[i].n_macs) > 0;
        if (batch[i].seconds > newest) newest = batch[i].seconds;
    }
    if (ok)
        ok = (fflush(f) == 0 && !ferror(f));
    if (fclose(f) != 0)          /* the commit point */
        ok = false;
    if (!ok)
    {
        ESP_LOGW(TAG, "events write failed, keeping %d queued", count);
        sdcard_io_end();
        return;                  /* queue untouched -- retried next tick */
    }
    /* An eviction meanwhile means we cannot say which entries were ours: drop
     * none, duplicates beat wrong deletions. No timeout -- already committed. */
    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE)
    {
        if (s_evicted == evicted_at_copy)
        {
            int drop = count < s_qcount ? count : s_qcount;
            s_qhead = (s_qhead + drop) % EV_QUEUE;
            s_qcount -= drop;
        }
        else
            ESP_LOGW(TAG, "event queue overran during the write, %d rows may repeat", count);
        xSemaphoreGive(s_lock);
    }

    /* %32==1, not ==0: the counter restarts at every boot, so a device that
     * reboots often would never reach a first prune. `newest` is defensive. */
    if (newest && ++s_flushes % 32 == 1)
    {
        uint32_t days = 30;
        config_get_u32(CONFIG_INDEX_EVENT_RETAIN_DAYS, &days);
        if (days == 0 || days > 30) days = 30;
        /* Never let the cutoff wrap: an underflowed cutoff keeps nothing and
         * deletes the entire history. */
        uint32_t span = days * 86400u;
        /* Unlinking events.csv under an in-flight download truncates it --
         * FATFS is built with FS_LOCK=0 and will not refuse. */
        if (sdcard_read_active() == 0)
            prune(newest > span ? newest - span : 0);
        else
            s_flushes--;
    }
    sdcard_io_end();
}

uint32_t events_evicted(void) { return s_evicted; }

/* 12 hex digits back into 6 bytes; anything shorter leaves the address zeroed. */
static void ev_hex_mac(const char *hex, uint8_t *out)
{
    if (strlen(hex) != 12)
        return;
    for (int i = 0; i < 6; i++)
    {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
}

int events_read(uint32_t hours, event_rec_t *out, int max, bool *history_ok,
                bool *capped)
{
    if (history_ok)
        *history_ok = true;
    if (capped)
        *capped = false;
    if (max <= 0)
        return 0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t from = (tv.tv_sec > (long)hours * 3600) ? (uint32_t)(tv.tv_sec - (long)hours * 3600) : 0;

    /* Keep a rolling window of the newest `max` matching rows. */
    int count = 0;
    /* Same lock as the writer, or prune() renames EV_CSV mid-read. Bounded:
     * this is the single httpd task, so a stuck writer would freeze the UI. */
    /* A lock miss must not skip the still-open events below -- those live in
     * RAM and need no card at all. */
    bool locked = sdcard_io_begin_timeout(2000);
    /* Without a card there is nothing stored to miss -- only a real lock miss
     * on a mounted card makes the list incomplete. */
    if (!locked && history_ok && sdcard_is_mounted())
        *history_ok = false;
    FILE *f = locked ? fopen(EV_CSV, "r") : NULL;
    if (f)
    {
        char line[192];   /* 17 fields are 130 B; a tail split off by fgets would parse
                           * as its own row and pass the tolerant got >= 3 check */
        while (fgets(line, sizeof(line), f))
        {
            /* Defaults MUST be set per line (this block stays inside the loop):
             * they are the compatibility with the 8-field rows written before. */
            unsigned long sec = 0, last = 0, sender = 0;
            unsigned st, cause, cnt = 1, multi = 0; long lat = 0, lon = 0;
            unsigned sub = 0; int rmin = 0, rmax = 0;
            unsigned cb = 0, aft = 0, nmac = 0;
            char ma[13] = "", mb[13] = "";
            int got = sscanf(line, "%lu,%u,%u,%ld,%ld,%u,%lu,%u,%lu,%d,%d,%u,"
                                   "%12[0-9a-fA-F],%12[0-9a-fA-F],%u,%u,%u",
                             &sec, &st, &cause, &lat, &lon, &cnt, &last, &sub,
                             &sender, &rmin, &rmax, &multi,
                             ma, mb, &cb, &aft, &nmac);
            /* Only a valid PAIR is a span -- clamping one half alone would put an
             * impossible "0 dBm" end into the table. */
            if (rmin >= 0 || rmin <= -128 || rmax >= 0 || rmax <= -128 || rmin > rmax)
                rmin = rmax = 0;
            /* Window by END time: an event that started earlier but was still
             * broadcast inside it counts, exactly as the RAM branch below. */
            uint32_t ends = (got >= 7 && last > sec) ? (uint32_t)last : (uint32_t)sec;
            if (got >= 3 && ends >= from)
            {
                /* Rows written before grouping existed have no count/last
                 * columns; treat them as single-message events. */
                if (got < 6) { cnt = 1; last = sec; }
                /* Designated on purpose: positional would silently shift lat/lon
                 * onto the fields appended after them. */
                event_rec_t e = {
                    .seconds = (uint32_t)sec, .last_seen = (uint32_t)last,
                    .action_station = 0, .action_seq = 0,
                    .count = (uint16_t)cnt, .station_type = (uint8_t)st,
                    .cause = (uint8_t)cause, .subcause = (uint8_t)sub,
                    .lat_e7 = (int32_t)lat, .lon_e7 = (int32_t)lon,
                    .sender_id = (uint32_t)sender,
                    .rssi_min = (int8_t)rmin, .rssi_max = (int8_t)rmax,
                    .multi_sender = multi != 0,
                };
                /* Only a row that carried ALL five appended fields has them;
                 * anything shorter is an older row and keeps n_macs 0. */
                if (got >= 17)
                {
                    ev_hex_mac(ma, e.mac_a);
                    ev_hex_mac(mb, e.mac_b);
                    e.count_b = (uint16_t)(cb > 0xFFFFu ? 0xFFFFu : cb);
                    e.b_after_s = (uint16_t)(aft > 0xFFFFu ? 0xFFFFu : aft);
                    e.n_macs = (uint8_t)(nmac > 255u ? 255u : nmac);
                }
                if (count < max)
                    out[count++] = e;
                else
                {
                    memmove(out, out + 1, (max - 1) * sizeof(*out));
                    out[max - 1] = e;
                    if (capped) *capped = true;
                }
            }
        }
        fclose(f);
    }
    if (locked)
        sdcard_io_end();

    /* Still-open events live only in RAM until they go quiet, so a warning
     * being repeated right now would otherwise be missing entirely. */
    if (s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE)
    {
        uint32_t now = (uint32_t)time(NULL);
        uint32_t cutoff = now > hours * 3600 ? now - hours * 3600 : 0;
        for (int i = 0; i < EV_OPEN; i++)
            if (s_open_valid[i] && s_open[i].last_seen >= cutoff)
            {
                /* A full list must not cost the running events: drop the
                 * oldest stored row instead. */
                if (count == max)
                {
                    if (max <= 1) break;
                    memmove(out, out + 1, (size_t)(max - 1) * sizeof(*out));
                    count--;
                    if (capped) *capped = true;
                }
                out[count++] = s_open[i];
            }
        xSemaphoreGive(s_lock);
    }
    /* Sort the WHOLE list, not just the appended tail: rows land in flush
     * order, i.e. by END time, so they are not ascending by start. */
    for (int i = 1; i < count; i++)
    {
        event_rec_t e = out[i];
        int j = i;
        while (j > 0 && out[j - 1].seconds < e.seconds) { out[j] = out[j - 1]; j--; }
        out[j] = e;   /* descending: newest start first */
    }
    return count;
}

#else  /* !CONFIG_ENABLE_SD */
void events_init(void) {}
void events_note(uint32_t seconds, uint8_t station_type, uint32_t sender_id, int rssi,
                 uint8_t message_id,
                 uint8_t cause, uint8_t subcause,
                 uint32_t action_station, uint16_t action_seq,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7,
                 const uint8_t *src_mac)
{ (void)seconds;(void)station_type;(void)sender_id;(void)rssi;(void)message_id;(void)cause;(void)subcause;
  (void)action_station;(void)action_seq;(void)has_pos;(void)lat_e7;(void)lon_e7;(void)src_mac; }
void events_tick(void) {}
uint32_t events_evicted(void) { return 0; }
int  events_read(uint32_t hours, event_rec_t *out, int max, bool *history_ok,
                 bool *capped)
{
    (void)hours; (void)out; (void)max;
    if (history_ok) *history_ok = true;
    if (capped) *capped = false;
    return 0;
}
#endif
