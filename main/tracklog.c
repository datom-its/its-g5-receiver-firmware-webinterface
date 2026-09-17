#include "sdkconfig.h"

#include "tracklog.h"

#if CONFIG_ENABLE_SD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_attr.h"
#include "esp_event.h"

#include "config.h"
#include "events.h"   /* CONFIG_EVENT_BASE */
#include "sdcard.h"

static const char TAG[] = "TRACKS";

#define TR_DIR   CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define TR_CSV   TR_DIR "/tracks.csv"

/* Points awaiting a write, drained by the sysmon tick so SD I/O never runs on the sniffer
 * path. On overflow the oldest point is dropped, or the new one if the writer holds it. */
#define TR_QUEUE 96
static track_pt_t s_queue[TR_QUEUE];

/* Absolute, monotone counters. Only a sequence is taken modulo TR_QUEUE to find
 * its slot, never a count. Occupancy is (uint32_t)(s_seq_in - s_seq_out). */
static uint32_t s_seq_in;      /* points ever accepted */
static uint32_t s_seq_out;     /* points ever removed (written or evicted) */
/* Sequences [s_busy_lo, s_busy_hi) are being written right now: the producer
 * must not recycle those slots, or a failed write loses the points entirely. */
static uint32_t s_busy_lo, s_busy_hi;
/* Guards the four counters above. Spinlock, not the mutex: the post-write
 * advance must not be able to time out, or rows get rewritten every tick. */
static portMUX_TYPE s_cur = portMUX_INITIALIZER_UNLOCKED;
static SemaphoreHandle_t s_lock;   /* guards s_last[] and the slot payloads */

/* Loss counters for tracklog_losses(). /system shows only the first two. */
static uint32_t s_evicted;      /* oldest dropped because the queue was full */
static uint32_t s_note_dropped; /* could not queue at all (busy or locked) */
static uint32_t s_write_fail;   /* a batch that did not reach the card */

/* Last point per station, so a vehicle standing at a red light does not fill
 * the log with the same coordinate. Only a handful are in range at once. */
#define TR_STATIONS 48
static struct {
    uint32_t sid, sec;
    int32_t  lat_e7, lon_e7;
} s_last[TR_STATIONS];
static int s_nlast;

/* About 9 m north-south (less east-west), and at least 2 s apart. Below that the
 * points would look the same on the map but would multiply the file. */
#define TR_MIN_MOVE_E7 800
#define TR_MIN_GAP_SEC 2

/* Cached, as in sdpcap. config_get_u8 reads flash under the one global NVS lock,
 * so a concurrent NVS write would stall reception on the packet path. */
static volatile bool cfg_tracks_on;

static void reload_config(void)
{
    uint8_t on = 0;
    config_get_u8(CONFIG_INDEX_TRACKS_ENABLE, &on);
    cfg_tracks_on = on != 0;
}

static void config_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base; (void)data;
    if (id == CONFIG_INDEX_TRACKS_ENABLE)
        reload_config();
}

void tracklog_losses(uint32_t *evicted, uint32_t *dropped, uint32_t *write_fail)
{
    portENTER_CRITICAL(&s_cur);
    if (evicted)    *evicted    = s_evicted;
    if (dropped)    *dropped    = s_note_dropped;
    if (write_fail) *write_fail = s_write_fail;
    portEXIT_CRITICAL(&s_cur);
}

void tracklog_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    reload_config();
    ESP_ERROR_CHECK(esp_event_handler_register(CONFIG_EVENT_BASE, ESP_EVENT_ANY_ID,
                                               config_event_handler, NULL));
}

static bool tracks_enabled(void)
{
    return cfg_tracks_on;
}

static uint32_t tracks_days(void)
{
    uint32_t d = 0;
    config_get_u32(CONFIG_INDEX_TRACKS_DAYS, &d);
    if (d < 1 || d > 7)
        d = 2;
    return d;
}

void tracklog_note(uint32_t seconds, uint32_t station_id, uint8_t station_type,
                   int32_t lat_e7, int32_t lon_e7)
{
    /* Station type 15 is roadside infrastructure. It never moves, so it has no
     * track to log. */
    if (station_type == 15 || station_id == 0 || (!lat_e7 && !lon_e7))
        return;
    if (!s_lock || !tracks_enabled())
        return;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
    {
        s_note_dropped++;   /* counted, as the header promises */
        return;             /* never block the packet path */
    }

    int slot = -1;
    for (int i = 0; i < s_nlast; i++)
        if (s_last[i].sid == station_id) { slot = i; break; }

    if (slot >= 0)
    {
        int32_t dlat = lat_e7 - s_last[slot].lat_e7;
        int32_t dlon = lon_e7 - s_last[slot].lon_e7;
        if (dlat < 0) dlat = -dlat;
        if (dlon < 0) dlon = -dlon;
        bool moved = dlat >= TR_MIN_MOVE_E7 || dlon >= TR_MIN_MOVE_E7;
        bool waited = seconds >= s_last[slot].sec + TR_MIN_GAP_SEC;
        if (!moved || !waited)
        {
            xSemaphoreGive(s_lock);
            return;
        }
    }
    else
    {
        /* New station. Take a free entry, or evict the least recently updated
         * one when the table is full. */
        if (s_nlast < TR_STATIONS)
            slot = s_nlast++;
        else
        {
            slot = 0;
            for (int i = 1; i < s_nlast; i++)
                if (s_last[i].sec < s_last[slot].sec) slot = i;
        }
        s_last[slot].sid = station_id;
    }
    s_last[slot].sec = seconds;
    s_last[slot].lat_e7 = lat_e7;
    s_last[slot].lon_e7 = lon_e7;

    uint32_t slot_seq;
    bool have_slot = true;
    portENTER_CRITICAL(&s_cur);
    if (s_seq_in - s_seq_out >= TR_QUEUE)
    {
        /* Queue full: drop the oldest point, unless the writer holds it. Dropping
         * a held point loses it if the write fails, so drop the new one instead. */
        if (s_seq_out != s_busy_lo || s_busy_lo == s_busy_hi)
        {
            s_seq_out++;
            s_evicted++;
        }
        else
        {
            have_slot = false;
            s_note_dropped++;
        }
    }
    slot_seq = s_seq_in;
    portEXIT_CRITICAL(&s_cur);

    if (have_slot)
    {
        track_pt_t *p = &s_queue[slot_seq % TR_QUEUE];
        p->seconds = seconds;
        p->station_id = station_id;
        p->station_type = station_type;
        p->lat_e7 = lat_e7;
        p->lon_e7 = lon_e7;
        portENTER_CRITICAL(&s_cur);
        s_seq_in++;            /* publish only once the payload is in the slot */
        portEXIT_CRITICAL(&s_cur);
    }

    xSemaphoreGive(s_lock);
}

/* Prunes by streaming to a temp file and swapping it in. Reading the whole file
 * into a fixed buffer would fail to allocate or silently drop the NEWEST rows. */
#define TR_TMP   TR_DIR "/tracks.tmp"

static void prune(uint32_t keep_from_sec)
{
    FILE *f = fopen(TR_CSV, "r");
    if (!f)
        return;
    FILE *w = fopen(TR_TMP, "w");
    if (!w)
    {
        fclose(f);
        return;
    }

    char line[64];
    bool ok = true;
    while (fgets(line, sizeof(line), f))
    {
        unsigned long sec = strtoul(line, NULL, 10);
        if (sec < keep_from_sec)
            continue;
        if (fputs(line, w) == EOF) { ok = false; break; }
    }
    if (ferror(f))
        ok = false;   /* a read error ends fgets like EOF would */
    fclose(f);
    if (fclose(w) != 0)
        ok = false;

    /* Replace the live file only if it was read to the end and every row was
     * written. A failed read or write must not cost the existing data. */
    if (ok)
    {
        remove(TR_CSV);
        rename(TR_TMP, TR_CSV);
    }
    else
        remove(TR_TMP);
}

void tracklog_tick(void)
{
    if (!s_lock || !sdcard_is_mounted())
        return;

    /* Bounded wait. sysmon is the watchdog task, and the flush before a restart
     * must not hang either. On sysmon a skipped cycle only delays the points. */
    if (!sdcard_io_begin_timeout(2000))
        return;

    /* Static, not a stack local: sysmon's stack cannot hold the batch plus
     * stdio. Safe because it is only used while the SD lock is held. */
    static track_pt_t batch[TR_QUEUE];
    int count = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE)
    {
        sdcard_io_end();
        return;
    }
    /* Copy WITHOUT consuming, and RESERVE the copied range. If a write fails while
     * the queue is full, the points would otherwise miss the card and lose their slots. */
    uint32_t first;
    portENTER_CRITICAL(&s_cur);
    first = s_seq_out;
    uint32_t avail = s_seq_in - s_seq_out;
    count = avail > TR_QUEUE ? TR_QUEUE : (int)avail;
    s_busy_lo = first;
    s_busy_hi = first + (uint32_t)count;
    portEXIT_CRITICAL(&s_cur);
    for (int i = 0; i < count; i++)
        batch[i] = s_queue[(first + (uint32_t)i) % TR_QUEUE];
    xSemaphoreGive(s_lock);

    if (count > 0)
    {
        mkdir(TR_DIR, 0775);
        bool ok = false;
        FILE *f = fopen(TR_CSV, "a");
        if (!f)
            ESP_LOGW(TAG, "cannot open %s", TR_CSV);
        else
        {
            ok = true;
            for (int i = 0; i < count && ok; i++)
                ok = fprintf(f, "%lu,%lu,%ld,%ld,%u\n",
                             (unsigned long)batch[i].seconds,
                             (unsigned long)batch[i].station_id,
                             (long)batch[i].lat_e7, (long)batch[i].lon_e7,
                             (unsigned)batch[i].station_type) > 0;
            if (ok)
                ok = (fflush(f) == 0 && !ferror(f));
            if (fclose(f) != 0)     /* the commit point */
                ok = false;
        }

        /* Only moves s_seq_out forward. The reservation already blocks evictions
         * during the write, so this is a guard. Release the reservation on both paths. */
        portENTER_CRITICAL(&s_cur);
        if (ok && (int32_t)(first + (uint32_t)count - s_seq_out) > 0)
            s_seq_out = first + (uint32_t)count;
        s_busy_lo = s_busy_hi = 0;
        portEXIT_CRITICAL(&s_cur);

        if (!ok)
        {
            s_write_fail++;
            ESP_LOGW(TAG, "tracks write failed, keeping %d points queued", count);
        }
    }
    else
    {
        portENTER_CRITICAL(&s_cur);
        s_busy_lo = s_busy_hi = 0;
        portEXIT_CRITICAL(&s_cur);
    }

    /* Counted in sysmon ticks of 5 s. Pre-loaded so the FIRST sweep runs a
     * minute after boot. Otherwise a device that reboots often never prunes. */
#define TR_PRUNE_TICKS   720   /* 1 h */
#define TR_PRUNE_FIRST    12   /* 1 min after boot */
    static uint32_t prune_ticks = TR_PRUNE_TICKS - TR_PRUNE_FIRST;
    if (++prune_ticks >= TR_PRUNE_TICKS)
    {
        time_t now = time(NULL);
        /* prune() unlinks tracks.csv. A /sdcard download holds it open under
         * the reader guard alone, so pruning during it truncates the transfer. */
        if (now > 1600000000 && sdcard_read_active() == 0)
        {
            prune_ticks = 0;
            /* Rewriting the whole file is slow BY DESIGN and must not look
             * like a wedged writer to the stall watchdog. */
            sdcard_io_long_begin();
            prune((uint32_t)(now - (time_t)tracks_days() * 86400));
            sdcard_io_long_end();
        }
        /* A skip (clock not set, or a download running) leaves the counter armed
         * on purpose. The sweep retries next tick instead of an hour later. */
    }
    sdcard_io_end();
}

static void track_pt_reverse(track_pt_t *a, int i, int j)
{
    while (i < j)
    {
        track_pt_t t = a[i];
        a[i++] = a[j];
        a[j--] = t;
    }
}

int tracklog_read(uint32_t days, track_pt_t *out, int max, bool *wrapped)
{
    if (wrapped)
        *wrapped = false;
    /* Bounded: runs on the httpd task (see events_read for the reasoning). */
    if (!out || max <= 0 || !sdcard_io_begin_timeout(2000))
        return 0;
    FILE *f = fopen(TR_CSV, "r");
    if (!f)
    {
        sdcard_io_end();
        return 0;
    }

    time_t now = time(NULL);
    uint32_t from = (now > 1600000000 && days)
                    ? (uint32_t)(now - (time_t)days * 86400) : 0;

    /* Keep the NEWEST points. Stopping at `max` would return the oldest. The ring
     * avoids a per-row shift, which would hold the SD lock on httpd for minutes. */
    int n = 0, head = 0;
    char line[64];
    while (fgets(line, sizeof(line), f))
    {
        unsigned long sec = 0, sid = 0;
        long la = 0, lo = 0;
        unsigned ty = 0;
        if (sscanf(line, "%lu,%lu,%ld,%ld,%u", &sec, &sid, &la, &lo, &ty) < 4)
            continue;
        if (sec < from)
            continue;
        track_pt_t p = { .seconds = (uint32_t)sec, .station_id = (uint32_t)sid,
                         .lat_e7 = (int32_t)la, .lon_e7 = (int32_t)lo,
                         .station_type = (uint8_t)ty };
        if (n < max)
            out[n++] = p;
        else
        {
            out[head] = p;                 /* overwrite the oldest, O(1) */
            head = (head + 1) % max;
            if (wrapped) *wrapped = true;
        }
    }
    fclose(f);
    sdcard_io_end();

    /* Restore chronological order in place. A second buffer would not fit here. */
    if (n == max && head > 0)
    {
        track_pt_reverse(out, 0, head - 1);
        track_pt_reverse(out, head, n - 1);
        track_pt_reverse(out, 0, n - 1);
    }
    return n;
}

#else  /* no SD card support compiled in */

void tracklog_init(void) {}
void tracklog_losses(uint32_t *e, uint32_t *d, uint32_t *w)
{ if (e) *e = 0; if (d) *d = 0; if (w) *w = 0; }
void tracklog_note(uint32_t s, uint32_t i, uint8_t t, int32_t a, int32_t o)
{ (void)s; (void)i; (void)t; (void)a; (void)o; }
void tracklog_tick(void) {}
int  tracklog_read(uint32_t d, track_pt_t *o, int m, bool *w)
{ (void)d; (void)o; (void)m; if (w) *w = false; return 0; }

#endif
