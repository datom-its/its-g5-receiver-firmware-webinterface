#include "sdkconfig.h"

#include "stats.h"

#if CONFIG_ENABLE_SD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/stat.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_attr.h"

#include "config.h"
#include "sdcard.h"

static const char TAG[] = "STATS";

#define STATS_DIR   CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define STATS_CSV   STATS_DIR "/traffic.csv"

/* current = hour being accumulated; pending = a completed hour waiting for
 * the sysmon tick to write it to SD (SD I/O must stay off the hot path). */
static stat_hour_t s_current;
static stat_hour_t s_pending;
static bool s_have_pending;
static SemaphoreHandle_t s_lock;
static uint32_t s_flushes;   /* completed-hour writes, for prune cadence */

static int cat_of(uint8_t st)
{
    switch (st)
    {
    case 5:                 return STAT_CAT_CAR;
    case 6:                 return STAT_CAT_BUS;
    case 7: case 8: case 9: return STAT_CAT_TRUCK;
    case 2: case 3: case 4: return STAT_CAT_TWOWHEEL;
    case 1:                 return STAT_CAT_PED;
    case 15:                return STAT_CAT_RSU;
    default:                return STAT_CAT_OTHER;
    }
}

void tstat_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

void tstat_note(uint8_t station_type, uint8_t message_id,
                bool has_speed, int32_t speed_cmps)
{
    (void)message_id;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if (tv.tv_sec < 1600000000 || !s_lock)   /* clock not set yet */
        return;
    uint32_t hour = (uint32_t)(tv.tv_sec / 3600);

    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;   /* never block the sniffer path for a stat */

    if (s_current.hour == 0)
        s_current.hour = hour;
    else if (hour != s_current.hour)
    {
        /* Hour rolled: hand the completed hour to the tick for SD write.
         * (If a previous pending wasn't flushed yet -- SD down for an hour --
         * it's overwritten; a single lost hour of stats is acceptable.) */
        s_pending = s_current;
        s_have_pending = true;
        memset(&s_current, 0, sizeof(s_current));
        s_current.hour = hour;
    }

    int c = cat_of(station_type);
    s_current.total++;
    s_current.cat[c]++;
    if (has_speed)
    {
        int32_t kmh = speed_cmps * 36 / 1000;   /* cm/s -> km/h */
        if (kmh > 0 && kmh < 400)                /* filter garbage readings */
        {
            s_current.sp_sum[c] += (uint32_t)kmh;
            s_current.sp_cnt[c]++;
            if ((uint32_t)kmh > s_current.sp_max[c])
                s_current.sp_max[c] = (uint32_t)kmh;
        }
    }

    xSemaphoreGive(s_lock);
}

/* CSV row: hour,total, then per-category counts, speed sums, speed counts and
 * speed maxima (each a block of STAT_NCAT values). Speed is stored as sum+cnt
 * (not a pre-averaged value) so any window can be averaged correctly. */
static void write_row(FILE *f, const stat_hour_t *h)
{
    fprintf(f, "%lu,%lu", (unsigned long)h->hour, (unsigned long)h->total);
    for (int c = 0; c < STAT_NCAT; c++) fprintf(f, ",%lu", (unsigned long)h->cat[c]);
    for (int c = 0; c < STAT_NCAT; c++) fprintf(f, ",%lu", (unsigned long)h->sp_sum[c]);
    for (int c = 0; c < STAT_NCAT; c++) fprintf(f, ",%lu", (unsigned long)h->sp_cnt[c]);
    for (int c = 0; c < STAT_NCAT; c++) fprintf(f, ",%lu", (unsigned long)h->sp_max[c]);
    fprintf(f, "\n");
}

/* Drop rows older than the retention window by streaming to a temp file and
 * swapping it in. The previous version read the whole file into a 64 KB
 * buffer -- but 30 days of hourly rows at real traffic volume measure about
 * 107 KB, so everything past the buffer, i.e. the NEWEST rows, would have
 * been silently dropped on every prune. Same defect family (and same fix) as
 * the vehicle-track log's prune. */
#define STATS_TMP   STATS_DIR "/traffic.tmp"

static void prune(uint32_t keep_from_hour)
{
    FILE *f = fopen(STATS_CSV, "r");
    if (!f)
        return;
    FILE *w = fopen(STATS_TMP, "w");
    if (!w)
    {
        fclose(f);
        return;
    }

    char line[256];
    bool ok = true;
    while (fgets(line, sizeof(line), f))
    {
        unsigned long h = strtoul(line, NULL, 10);
        if (h < keep_from_hour)
            continue;
        if (fputs(line, w) == EOF) { ok = false; break; }
    }
    fclose(f);
    if (fclose(w) != 0)
        ok = false;

    if (ok)
    {
        remove(STATS_CSV);
        rename(STATS_TMP, STATS_CSV);
    }
    else
        remove(STATS_TMP);
}

void tstat_tick(void)
{
    if (!s_lock || !s_have_pending || !sdcard_is_mounted())
        return;

    stat_hour_t row;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE)
        return;
    row = s_pending;
    s_have_pending = false;
    xSemaphoreGive(s_lock);

    mkdir(STATS_DIR, 0777);
    FILE *f = fopen(STATS_CSV, "a");
    if (!f)
    {
        ESP_LOGW(TAG, "cannot open %s", STATS_CSV);
        return;
    }
    write_row(f, &row);
    fclose(f);

    /* Prune roughly once a day. */
    if (++s_flushes % 24 == 0)
    {
        uint32_t days = 30;
        config_get_u32(CONFIG_INDEX_STATS_RETAIN_DAYS, &days);
        if (days == 0 || days > 30) days = 30;
        prune(row.hour - days * 24);
    }
}

int tstat_read(uint32_t hours, stat_hour_t *out, int max)
{
    if (max <= 0)
        return 0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t now_hour = (uint32_t)(tv.tv_sec / 3600);
    uint32_t from_hour = (hours >= now_hour) ? 0 : now_hour - hours;

    const int NF = 2 + 4 * STAT_NCAT;   /* fields in a full row */
    int count = 0;
    FILE *f = fopen(STATS_CSV, "r");
    if (f)
    {
        char line[256];
        while (fgets(line, sizeof(line), f))
        {
            unsigned long v[2 + 4 * STAT_NCAT] = {0};
            const char *p = line;
            int got = 0;
            for (; got < NF; got++)
            {
                char *end;
                v[got] = strtoul(p, &end, 10);
                if (end == p) break;
                p = end;
                if (*p == ',') p++;
            }
            /* Only full new-format rows; older/short rows are skipped. */
            if (got == NF && (uint32_t)v[0] >= from_hour)
            {
                stat_hour_t h = {0};
                h.hour = v[0]; h.total = v[1];
                int idx = 2;
                for (int c = 0; c < STAT_NCAT; c++) h.cat[c]    = v[idx++];
                for (int c = 0; c < STAT_NCAT; c++) h.sp_sum[c] = v[idx++];
                for (int c = 0; c < STAT_NCAT; c++) h.sp_cnt[c] = v[idx++];
                for (int c = 0; c < STAT_NCAT; c++) h.sp_max[c] = v[idx++];
                if (count < max)
                    out[count++] = h;
                else
                {
                    memmove(out, out + 1, (max - 1) * sizeof(*out));
                    out[max - 1] = h;
                }
            }
        }
        fclose(f);
    }

    /* Append the in-RAM current hour as the newest row. */
    if (s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE)
    {
        stat_hour_t cur = s_current;
        xSemaphoreGive(s_lock);
        if (cur.hour >= from_hour && cur.total > 0)
        {
            if (count < max)
                out[count++] = cur;
            else
            {
                memmove(out, out + 1, (max - 1) * sizeof(*out));
                out[max - 1] = cur;
            }
        }
    }
    return count;
}

#else  /* !CONFIG_ENABLE_SD */
void tstat_init(void) {}
void tstat_note(uint8_t st, uint8_t mid, bool hs, int32_t sp) { (void)st;(void)mid;(void)hs;(void)sp; }
void tstat_tick(void) {}
int  tstat_read(uint32_t hours, stat_hour_t *out, int max) { (void)hours;(void)out;(void)max; return 0; }
#endif
