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

/* Small queue of events awaiting an SD write; drained by the sysmon tick so
 * SD I/O never blocks the sniffer path. Events (DENM) are rare, so this is
 * plenty. If it ever overflows, the oldest queued event is dropped. */
#define EV_EVENT_GAP_SEC 120  /* silence after which an event counts as over */
#define EV_QUEUE  32
static event_rec_t s_queue[EV_QUEUE];
static int s_qhead, s_qcount;
static SemaphoreHandle_t s_lock;
static uint32_t s_flushes;

void events_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

/* The event currently being repeated, held back from the queue so its count
 * can keep rising. Flushed when a different event starts or when it has gone
 * quiet (see EV_EVENT_GAP_SEC in events_tick). */
static event_rec_t s_open;
static bool s_open_valid;

static void queue_locked(const event_rec_t *e)
{
    int i = (s_qhead + s_qcount) % EV_QUEUE;
    s_queue[i] = *e;
    if (s_qcount < EV_QUEUE)
        s_qcount++;
    else
        s_qhead = (s_qhead + 1) % EV_QUEUE;   /* overwrite oldest */
}

void events_note(uint32_t seconds, uint8_t station_type, uint8_t message_id,
                 uint8_t cause, uint8_t subcause,
                 uint32_t action_station, uint16_t action_seq,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7)
{
    if (message_id != 1 || !s_lock)   /* 1 = DENM (warning) */
        return;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;

    /* Same ActionID as the event we're already tracking? Then this is just
     * another broadcast of it -- count it, keep the newest position. */
    if (s_open_valid && s_open.action_station == action_station &&
        s_open.action_seq == action_seq)
    {
        s_open.last_seen = seconds;
        if (s_open.count < 0xFFFF) s_open.count++;
        if (has_pos) { s_open.lat_e7 = lat_e7; s_open.lon_e7 = lon_e7; }
        xSemaphoreGive(s_lock);
        return;
    }

    if (s_open_valid)
        queue_locked(&s_open);        /* a different event starts: flush */

    s_open = (event_rec_t){
        .seconds = seconds, .last_seen = seconds,
        .action_station = action_station, .action_seq = action_seq,
        .count = 1, .station_type = station_type, .cause = cause,
        .subcause = subcause,
        .lat_e7 = has_pos ? lat_e7 : 0, .lon_e7 = has_pos ? lon_e7 : 0,
    };
    s_open_valid = true;

    xSemaphoreGive(s_lock);
}

#define EV_TMP   EV_DIR "/events.tmp"

/* Streams to a temp file and swaps -- the previous 64 KB read-all buffer
 * holds ~25 days of events at a busy site (grouped rows, ~51 bytes each);
 * beyond it the NEWEST rows were dropped on rewrite. Same defect family as
 * the track and stats prunes, fixed the same day, the same way. */
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

    char line[128];
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
        if (s_open_valid && now > s_open.last_seen &&
            now - s_open.last_seen > EV_EVENT_GAP_SEC)
        {
            queue_locked(&s_open);
            s_open_valid = false;
        }
        xSemaphoreGive(s_lock);
    }

    if (s_qcount == 0 || !sdcard_is_mounted())
        return;

    /* Guards the append and the prune rewrite against unmount/format, and
     * against events_read() having the file open at the same time. */
    if (!sdcard_io_begin())
        return;

    /* Snapshot and clear the queue under the lock, write outside it. */
    static event_rec_t batch[EV_QUEUE];
    int count;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE)
    {
        sdcard_io_end();
        return;
    }
    count = s_qcount;
    for (int i = 0; i < count; i++)
        batch[i] = s_queue[(s_qhead + i) % EV_QUEUE];
    s_qhead = 0;
    s_qcount = 0;
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
    for (int i = 0; i < count; i++)
    {
        fprintf(f, "%lu,%u,%u,%ld,%ld,%u,%lu,%u\n",
                (unsigned long)batch[i].seconds, batch[i].station_type,
                batch[i].cause, (long)batch[i].lat_e7, (long)batch[i].lon_e7,
                (unsigned)batch[i].count, (unsigned long)batch[i].last_seen,
                (unsigned)batch[i].subcause);
        if (batch[i].seconds > newest) newest = batch[i].seconds;
    }
    fclose(f);

    /* Prune roughly once every 32 flush cycles. */
    if (++s_flushes % 32 == 0 && newest)
    {
        uint32_t days = 30;
        config_get_u32(CONFIG_INDEX_EVENT_RETAIN_DAYS, &days);
        if (days == 0 || days > 30) days = 30;
        prune(newest - days * 86400);
    }
    sdcard_io_end();
}

int events_read(uint32_t hours, event_rec_t *out, int max)
{
    if (max <= 0)
        return 0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t from = (tv.tv_sec > (long)hours * 3600) ? (uint32_t)(tv.tv_sec - (long)hours * 3600) : 0;

    /* Keep a rolling window of the newest `max` matching rows. */
    int count = 0;
    /* Same lock as the writer: prune() renames EV_CSV out from under a
     * concurrent read otherwise. */
    if (!sdcard_io_begin())
        return 0;
    FILE *f = fopen(EV_CSV, "r");
    if (f)
    {
        char line[96];
        while (fgets(line, sizeof(line), f))
        {
            unsigned long sec, last = 0; unsigned st, cause, cnt = 1; long lat, lon;
            unsigned sub = 0;
            int got = sscanf(line, "%lu,%u,%u,%ld,%ld,%u,%lu,%u",
                             &sec, &st, &cause, &lat, &lon, &cnt, &last, &sub);
            if (got >= 3
                && (uint32_t)sec >= from)
            {
                /* Rows written before grouping existed have no count/last
                 * columns; treat them as single-message events. */
                if (got < 6) { cnt = 1; last = sec; }
                event_rec_t e = { (uint32_t)sec, (uint32_t)last, 0, 0,
                                  (uint16_t)cnt, (uint8_t)st, (uint8_t)cause,
                                  (uint8_t)sub, (int32_t)lat, (int32_t)lon };
                if (count < max)
                    out[count++] = e;
                else
                {
                    memmove(out, out + 1, (max - 1) * sizeof(*out));
                    out[max - 1] = e;
                }
            }
        }
        fclose(f);
    }
    sdcard_io_end();

    /* Reverse to newest-first. */
    for (int i = 0; i < count / 2; i++)
    {
        event_rec_t t = out[i];
        out[i] = out[count - 1 - i];
        out[count - 1 - i] = t;
    }
    return count;
}

#else  /* !CONFIG_ENABLE_SD */
void events_init(void) {}
void events_note(uint32_t seconds, uint8_t station_type, uint8_t message_id,
                 uint8_t cause, uint8_t subcause,
                 uint32_t action_station, uint16_t action_seq,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7)
{ (void)seconds;(void)station_type;(void)message_id;(void)cause;(void)subcause;
  (void)action_station;(void)action_seq;(void)has_pos;(void)lat_e7;(void)lon_e7; }
void events_tick(void) {}
int  events_read(uint32_t hours, event_rec_t *out, int max) { (void)hours;(void)out;(void)max; return 0; }
#endif
