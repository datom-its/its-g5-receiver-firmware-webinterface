#include "sdkconfig.h"

#include "stats.h"

#if CONFIG_ENABLE_SD

#include <errno.h>
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

/* Sender ids seen this hour: open addressing, linear probe, emptied on the hour
 * roll. Past 3/4 full it stops inserting and the hour is marked a lower bound. */
#define SEEN_SLOTS 2048
static EXT_RAM_BSS_ATTR uint32_t s_seen[SEEN_SLOTS];
static uint32_t s_seen_used;

/* True if the id was not in the set before (and got inserted). */
static bool seen_insert(uint32_t id)
{
    if (!id)
        return false;
    if (s_seen_used >= SEEN_SLOTS - SEEN_SLOTS / 4)
        return false;                      /* full: stop counting, not lying */
    uint32_t h = id * 2654435761u;         /* Knuth multiplicative */
    for (uint32_t i = 0; i < SEEN_SLOTS; i++)
    {
        uint32_t k = (h + i) % SEEN_SLOTS;
        if (s_seen[k] == id)
            return false;
        if (s_seen[k] == 0)
        {
            s_seen[k] = id;
            s_seen_used++;
            return true;
        }
    }
    return false;
}

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

void tstat_note(uint8_t station_type, uint32_t station_id, uint8_t message_id,
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
        /* Hour rolled: hand it to the tick for the SD write. An unflushed
         * previous pending is overwritten -- one lost hour is acceptable. */
        s_pending = s_current;
        s_have_pending = true;
        memset(&s_current, 0, sizeof(s_current));
        memset(s_seen, 0, sizeof(s_seen));
        s_seen_used = 0;
        s_current.hour = hour;
    }

    int c = cat_of(station_type);
    s_current.total++;
    s_current.cat[c]++;
    if (seen_insert(station_id))
        s_current.senders[c]++;
    else if (s_seen_used >= SEEN_SLOTS - SEEN_SLOTS / 4)
        s_current.senders_capped = true;
    /* An all-ones GN speed field means "not available" and decodes to -1 cm/s;
     * without this every vehicle that omits its speed counts as standing still. */
    if (has_speed && speed_cmps != -1)
    {
        int32_t kmh = speed_cmps * 36 / 1000;   /* cm/s -> km/h */
        if (kmh < 0) kmh = -kmh;                /* reversing is still movement */
        /* A standing vehicle is real traffic: dropping it took it out of the
         * DENOMINATOR too and pushed the average up. */
        if (kmh < 400)
        {
            s_current.sp_sum[c] += (uint32_t)kmh;
            s_current.sp_cnt[c]++;
            if ((uint32_t)kmh > s_current.sp_max[c])
                s_current.sp_max[c] = (uint32_t)kmh;
        }
    }

    xSemaphoreGive(s_lock);
}

/* CSV row: hour,total, then per-category counts, speed sum/cnt/max, distinct
 * senders, capped flag. Speed as sum+cnt so any window averages correctly. */
#define STATS_NF_OLD (2 + 4 * STAT_NCAT)
#define STATS_NF_NEW (STATS_NF_OLD + STAT_NCAT + 1)
/* Explicit trailing marker for how the speed columns were filled -- the column
 * count cannot tell, a build wrote the new columns under the old rule. */
#define STATS_NF_RULE (STATS_NF_NEW + 1)
#define STATS_SPEED_RULE 1u   /* 1 = standing vehicles in, "unavailable" out */

static void write_row(FILE *f, const stat_hour_t *h)
{
    fprintf(f, "%lu,%lu", (unsigned long)h->hour, (unsigned long)h->total);
    for (int c = 0; c < STAT_NCAT; c++) fprintf(f, ",%lu", (unsigned long)h->cat[c]);
    for (int c = 0; c < STAT_NCAT; c++) fprintf(f, ",%lu", (unsigned long)h->sp_sum[c]);
    for (int c = 0; c < STAT_NCAT; c++) fprintf(f, ",%lu", (unsigned long)h->sp_cnt[c]);
    for (int c = 0; c < STAT_NCAT; c++) fprintf(f, ",%lu", (unsigned long)h->sp_max[c]);
    for (int c = 0; c < STAT_NCAT; c++) fprintf(f, ",%lu", (unsigned long)h->senders[c]);
    fprintf(f, ",%u,%u\n", h->senders_capped ? 1u : 0u, STATS_SPEED_RULE);
}

/* Prunes by streaming to a temp file and swapping it in -- a fixed read buffer
 * capped the file and silently dropped the NEWEST rows. */
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

    /* Must hold the longest possible row whole -- a short buffer splits a line
     * and both halves mis-parse. Recount when columns are added. */
    char line[448];
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

    /* Guards append and prune rewrite against unmount/format and the other SD
     * writers. Bounded: this runs on the sysmon (watchdog) task. */
    if (!sdcard_io_begin_timeout(2000))
        return;

    stat_hour_t row;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE)
    {
        sdcard_io_end();
        return;
    }
    /* RE-CHECK under the lock: the flag clears only after a verified write, and
     * tstat_tick has two callers on different tasks. tstat_read SUMS same-hour rows. */
    if (!s_have_pending)
    {
        xSemaphoreGive(s_lock);
        sdcard_io_end();
        return;
    }
    row = s_pending;
    xSemaphoreGive(s_lock);   /* cleared only once the row is on the card */

    mkdir(STATS_DIR, 0777);
    /* A reset between prune()'s remove() and rename() leaves the whole history
     * in the temp file; put it back BEFORE appending, or an empty csv wins. */
    struct stat st;
    if (stat(STATS_CSV, &st) != 0 && stat(STATS_TMP, &st) == 0)
        rename(STATS_TMP, STATS_CSV);
    /* csv is live, so any tmp is a dead prune's leftover: left there, the restore
     * above would later promote it over a csv the user deleted. */
    else if (stat(STATS_TMP, &st) == 0)
        remove(STATS_TMP);
    FILE *f = fopen(STATS_CSV, "a");
    if (!f)
    {
        ESP_LOGW(TAG, "cannot open %s", STATS_CSV);
        sdcard_io_end();
        return;
    }
    write_row(f, &row);
    bool ok = (fflush(f) == 0 && !ferror(f));
    if (fclose(f) != 0)
        ok = false;
    if (!ok)
    {
        /* An hour of counts is worth a retry -- dropping the flag here loses it
         * silently on a full card. */
        ESP_LOGW(TAG, "stats row not written, keeping it pending");
        sdcard_io_end();
        return;
    }
    /* portMAX_DELAY, never bounded: the row is on the card, so a timed-out take
     * leaves the flag set and the same hour gets appended twice (and SUMMED). */
    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE)
    {
        /* Not if the hour rolled meanwhile: that pending row is a new one.
         * Blind to a roll inside tstat_flush_now() -- drops one partial hour. */
        if (s_pending.hour == row.hour)
            s_have_pending = false;
        xSemaphoreGive(s_lock);
    }

    /* Roughly daily, counted in completed-hour writes. Offset so the FIRST sweep
     * comes early: from zero, a device restarting often never prunes at all. */
    if (++s_flushes % 24 == 1)
    {
        uint32_t days = 30;
        config_get_u32(CONFIG_INDEX_STATS_RETAIN_DAYS, &days);
        if (days == 0 || days > 30) days = 30;
        /* prune() unlinks and recreates traffic.csv, which a streaming download
         * may hold open. Skipped then; the cadence counter is not consumed. */
        if (sdcard_read_active() == 0)
            prune(row.hour - days * 24);
        else
            s_flushes--;
    }
    sdcard_io_end();
}

/* Writes the hour still being accumulated -- without it a planned restart throws
 * away up to 59 minutes of counts. */
void tstat_flush_now(void)
{
    if (!s_lock)
        return;
    tstat_tick();                       /* whatever was already pending */
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) != pdTRUE)
        return;
    if (s_current.total == 0 || s_have_pending)
    {
        xSemaphoreGive(s_lock);
        return;
    }
    s_pending = s_current;
    s_have_pending = true;
    memset(&s_current, 0, sizeof(s_current));
    memset(s_seen, 0, sizeof(s_seen));
    s_seen_used = 0;
    s_current.hour = s_pending.hour;    /* same hour keeps accumulating */
    xSemaphoreGive(s_lock);
    tstat_tick();
}

/* Folds `src` into `dst` for the same hour. One place, because tstat_flush_now()
 * writes the running hour and keeps accumulating under that SAME hour. */
static void stat_hour_merge(stat_hour_t *dst, const stat_hour_t *src)
{
    dst->total += src->total;
    for (int c = 0; c < STAT_NCAT; c++)
    {
        dst->cat[c]    += src->cat[c];
        dst->sp_sum[c] += src->sp_sum[c];
        dst->sp_cnt[c] += src->sp_cnt[c];
        if (src->sp_max[c] > dst->sp_max[c]) dst->sp_max[c] = src->sp_max[c];
        /* Distinct senders cannot be summed -- the same vehicle may appear in
         * both halves. The larger half is the honest lower bound. */
        if (src->senders[c] > dst->senders[c]) dst->senders[c] = src->senders[c];
    }
    dst->senders_capped = dst->senders_capped || src->senders_capped;
    dst->speed_legacy   = dst->speed_legacy   || src->speed_legacy;
}

int tstat_read(uint32_t hours, stat_hour_t *out, int max, bool *history_ok)
{
    if (history_ok)
        *history_ok = true;
    if (max <= 0)
        return 0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t now_hour = (uint32_t)(tv.tv_sec / 3600);
    /* now_hour is the running (partial) hour, so "the last 24 h" is 23 completed
     * plus this one; subtracting the full count admits one bucket too many. */
    uint32_t span = hours ? hours - 1 : 0;
    uint32_t from_hour = (span >= now_hour) ? 0 : now_hour - span;

    int count = 0;
    /* Counted reader guard, NOT the writer lock -- that would block the recorders
     * for 720 rows. Unlink races it, so rows can be short: bounds-checked below. */
    bool locked = sdcard_read_begin();
    /* Without a card there IS no stored history -- only a real miss on a
     * mounted card (an unmount/format pending) is worth warning about. */
    if (!locked && history_ok && sdcard_is_mounted())
        *history_ok = false;
    FILE *f = locked ? fopen(STATS_CSV, "r") : NULL;
    /* A reset between prune()'s remove() and rename() leaves the complete
     * history in the temp file -- read it rather than show nothing. */
    if (locked && !f)
        f = fopen(STATS_TMP, "r");
    /* Both opens failed on a mounted card: the stored window is silently missing,
     * so warn. ENOENT is not a failure; errno here is the TMP open's. */
    if (locked && !f && errno != ENOENT && history_ok)
        *history_ok = false;
    if (f)
    {
        char line[448];
        while (fgets(line, sizeof(line), f))
        {
            unsigned long v[STATS_NF_RULE] = {0};
            const char *p = line;
            int got = 0;
            for (; got < STATS_NF_RULE; got++)
            {
                char *end;
                v[got] = strtoul(p, &end, 10);
                if (end == p) break;
                p = end;
                if (*p == ',') p++;
            }
            /* Rows written before the sender columns existed stay valid; their
             * missing fields read as zero. */
            if (got >= STATS_NF_OLD && (uint32_t)v[0] >= from_hour)
            {
                stat_hour_t h = {0};
                h.hour = v[0]; h.total = v[1];
                int idx = 2;
                for (int c = 0; c < STAT_NCAT; c++) h.cat[c]    = v[idx++];
                for (int c = 0; c < STAT_NCAT; c++) h.sp_sum[c] = v[idx++];
                for (int c = 0; c < STAT_NCAT; c++) h.sp_cnt[c] = v[idx++];
                for (int c = 0; c < STAT_NCAT; c++) h.sp_max[c] = v[idx++];
                if (got >= STATS_NF_NEW - 1)
                    for (int c = 0; c < STAT_NCAT; c++) h.senders[c] = v[idx++];
                if (got >= STATS_NF_NEW)
                    h.senders_capped = v[idx++] != 0;
                /* No marker, or one from a rule we do not know: treat the
                 * speed columns as following some other definition. */
                h.speed_legacy = (got < STATS_NF_RULE || v[idx] != STATS_SPEED_RULE);
                /* A restart splits one hour into two rows. Merge them so the
                 * chart shows one hour, not two short ones. */
                if (count > 0 && out[count - 1].hour == h.hour)
                    stat_hour_merge(&out[count - 1], &h);
                else if (count < max)
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
    if (locked)
        sdcard_read_end();

    /* Append the in-RAM current hour as the newest row. */
    if (s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE)
    {
        stat_hour_t cur = s_current;
        xSemaphoreGive(s_lock);
        if (cur.hour >= from_hour && cur.total > 0)
        {
            /* Through the SAME merge as the stored rows: after a planned
             * restart the CSV already holds a row for this very hour. */
            if (count > 0 && out[count - 1].hour == cur.hour)
                stat_hour_merge(&out[count - 1], &cur);
            else if (count < max)
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
void tstat_note(uint8_t st, uint32_t sid, uint8_t mid, bool hs, int32_t sp)
{ (void)st;(void)sid;(void)mid;(void)hs;(void)sp; }
void tstat_tick(void) {}
void tstat_flush_now(void) {}
int  tstat_read(uint32_t hours, stat_hour_t *out, int max, bool *history_ok)
{ (void)hours;(void)out;(void)max; if (history_ok) *history_ok = true; return 0; }
#endif
