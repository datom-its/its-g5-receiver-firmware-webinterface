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

#include "config.h"
#include "sdcard.h"

static const char TAG[] = "TRACKS";

#define TR_DIR   CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define TR_CSV   TR_DIR "/tracks.csv"

/* Points awaiting a write, drained by the sysmon tick so SD I/O never runs on
 * the sniffer path. At the measured 49-279 points an hour this is minutes of
 * headroom; on overflow the oldest queued point is dropped, which costs a bit
 * of detail in one track rather than blocking anything. */
#define TR_QUEUE 96
static track_pt_t s_queue[TR_QUEUE];
static int s_qhead, s_qcount;
static SemaphoreHandle_t s_lock;
static uint32_t s_flushes;

/* Last point recorded per station, so a vehicle standing at a red light does
 * not fill the log with the same coordinate. Small and fixed: only a handful
 * of vehicles are ever in range at once. */
#define TR_STATIONS 48
static struct {
    uint32_t sid, sec;
    int32_t  lat_e7, lon_e7;
} s_last[TR_STATIONS];
static int s_nlast;

/* Roughly 8 m at this latitude, and at least 2 s apart. Below that the points
 * would be visually indistinguishable on the map but would multiply the file. */
#define TR_MIN_MOVE_E7 800
#define TR_MIN_GAP_SEC 2

void tracklog_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

static bool tracks_enabled(void)
{
    uint8_t on = 0;
    config_get_u8(CONFIG_INDEX_TRACKS_ENABLE, &on);
    return on != 0;
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
    /* Station type 15 is roadside infrastructure -- it never moves, and its
     * ~30,000 messages an hour would swamp everything the vehicles say. */
    if (station_type == 15 || station_id == 0 || (!lat_e7 && !lon_e7))
        return;
    if (!s_lock || !tracks_enabled())
        return;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;   /* never block the packet path */

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
        /* Table full: evict the least recently updated station. */
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

    if (s_qcount >= TR_QUEUE)
    {
        s_qhead = (s_qhead + 1) % TR_QUEUE;
        s_qcount--;
    }
    track_pt_t *p = &s_queue[(s_qhead + s_qcount) % TR_QUEUE];
    p->seconds = seconds;
    p->station_id = station_id;
    p->station_type = station_type;
    p->lat_e7 = lat_e7;
    p->lon_e7 = lon_e7;
    s_qcount++;

    xSemaphoreGive(s_lock);
}

/* Rewrites the file without rows older than `keep_from_sec`, streaming to a
 * temporary file and swapping it in. The first version collected kept rows in
 * a malloc'd 256 KB block capped at 4096 lines -- that allocation would
 * likely fail outright on the internal heap (so pruning silently never ran),
 * and even when it worked, two days of tracks are ~7200 rows: everything
 * past the cap, i.e. the NEWEST rows, was dropped on rewrite. Streaming
 * needs no memory and has no cap. */
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
    fclose(f);
    if (fclose(w) != 0)
        ok = false;

    /* Only replace the live file once the copy is known-complete; a failed
     * write must not cost the existing data. */
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

    /* Guards the append and the prune rewrite below against unmount/format.
     * Bounded, NOT an unlimited wait: this runs on the sysmon task, which is
     * the watchdog. Blocking here on a stuck SD writer would wedge the very
     * task whose job it is to notice a wedge -- and one skipped cycle costs
     * nothing, the points stay queued for the next one. */
    if (!sdcard_io_begin_timeout(2000))
        return;

    /* Static, not a stack local: this runs on the sysmon task, whose whole
     * stack is 4096 bytes -- a 1.9 KB batch there plus stdio internals would
     * flirt with overflow. Only sysmon ever calls this, sequentially. */
    static track_pt_t batch[TR_QUEUE];
    int count = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE)
    {
        sdcard_io_end();
        return;
    }
    while (s_qcount > 0 && count < TR_QUEUE)
    {
        batch[count++] = s_queue[s_qhead];
        s_qhead = (s_qhead + 1) % TR_QUEUE;
        s_qcount--;
    }
    xSemaphoreGive(s_lock);

    if (count > 0)
    {
        mkdir(TR_DIR, 0775);
        FILE *f = fopen(TR_CSV, "a");
        if (!f)
        {
            ESP_LOGW(TAG, "cannot open %s", TR_CSV);
            sdcard_io_end();
            return;
        }
        for (int i = 0; i < count; i++)
            fprintf(f, "%lu,%lu,%ld,%ld,%u\n",
                    (unsigned long)batch[i].seconds,
                    (unsigned long)batch[i].station_id,
                    (long)batch[i].lat_e7, (long)batch[i].lon_e7,
                    (unsigned)batch[i].station_type);
        fclose(f);
        s_flushes++;
    }

    /* Pruning rewrites the whole file, so do it rarely -- roughly hourly at
     * the sysmon tick rate, which is ample for a days-long retention.
     * Counts TICKS, not flushes: keying it on the flush counter meant that
     * with nothing to write (night, no vehicles in range) the counter stayed
     * put at a multiple of 64 and every single tick rewrote the whole file --
     * hours of pointless traffic on the very SD bus behind the known crash. */
    static uint32_t prune_ticks;
    if (++prune_ticks >= 64)
    {
        prune_ticks = 0;
        time_t now = time(NULL);
        if (now > 1600000000)
            prune((uint32_t)(now - (time_t)tracks_days() * 86400));
    }
    sdcard_io_end();
}

int tracklog_read(uint32_t days, track_pt_t *out, int max)
{
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

    int n = 0;
    char line[64];
    while (n < max && fgets(line, sizeof(line), f))
    {
        unsigned long sec = 0, sid = 0;
        long la = 0, lo = 0;
        unsigned ty = 0;
        if (sscanf(line, "%lu,%lu,%ld,%ld,%u", &sec, &sid, &la, &lo, &ty) < 4)
            continue;
        if (sec < from)
            continue;
        out[n].seconds = (uint32_t)sec;
        out[n].station_id = (uint32_t)sid;
        out[n].lat_e7 = (int32_t)la;
        out[n].lon_e7 = (int32_t)lo;
        out[n].station_type = (uint8_t)ty;
        n++;
    }
    fclose(f);
    sdcard_io_end();
    return n;
}

#else  /* no SD card support compiled in */

void tracklog_init(void) {}
void tracklog_note(uint32_t s, uint32_t i, uint8_t t, int32_t a, int32_t o)
{ (void)s; (void)i; (void)t; (void)a; (void)o; }
void tracklog_tick(void) {}
int  tracklog_read(uint32_t d, track_pt_t *o, int m) { (void)d; (void)o; (void)m; return 0; }

#endif
