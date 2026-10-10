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
#include "sd_csv.h"
#include "sd_rcache.h"
#include "sdcard.h"

static const char TAG[] = "STATS";

#define STATS_DIR   CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define STATS_CSV   STATS_DIR "/traffic.csv"

/* current = the hour being accumulated. pending = an hour waiting for the sysmon
 * tick to write it to SD, usually a completed one. SD I/O stays off the hot path. */
static stat_hour_t s_current;
static stat_hour_t s_pending;
static bool s_have_pending;
static SemaphoreHandle_t s_lock;
static uint32_t s_flushes;   /* hours written to SD, for prune cadence */
/* The last append failed and said so: one warning per streak of failures. */
static bool s_write_warned;

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
        /* Hour rolled: hand it to the tick for the SD write. An unflushed previous
         * pending is overwritten, so one hour can be lost. That is acceptable. */
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
    /* An all-ones GN speed field means "not available" and decodes to -1 cm/s.
     * Without this check a vehicle that omits its speed would count as standing. */
    if (has_speed && speed_cmps != -1)
    {
        int32_t kmh = speed_cmps * 36 / 1000;   /* cm/s -> km/h */
        if (kmh < 0) kmh = -kmh;                /* reversing is still movement */
        /* A standing vehicle is real traffic. Dropping it would take it out of
         * the DENOMINATOR too and push the average up. */
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
/* Explicit trailing marker for how the speed columns were filled. The column
 * count alone cannot tell. Rows can carry the new columns under the old rule. */
#define STATS_NF_RULE (STATS_NF_NEW + 1)
#define STATS_SPEED_RULE 1u   /* 1 = standing vehicles in, "unavailable" out */

/* One row in one buffer, so it goes out with one write-out check: 37 counts of at most 10 digits,
 * two flags, 38 commas and '\n' are 411 B of 448. False when it does not fit. */
static bool format_row(char *b, size_t cap, const stat_hour_t *h)
{
    const uint32_t *col[] = { h->cat, h->sp_sum, h->sp_cnt, h->sp_max, h->senders };
    int n = snprintf(b, cap, "%lu,%lu", (unsigned long)h->hour, (unsigned long)h->total);
    size_t at = n < 0 ? cap : (size_t)n;
    for (size_t k = 0; k < sizeof(col) / sizeof(col[0]); k++)
        for (int c = 0; c < STAT_NCAT && at < cap; c++)
        {
            n = snprintf(b + at, cap - at, ",%lu", (unsigned long)col[k][c]);
            at = n < 0 ? cap : at + (size_t)n;
        }
    if (at < cap)
    {
        n = snprintf(b + at, cap - at, ",%u,%u\n", h->senders_capped ? 1u : 0u, STATS_SPEED_RULE);
        at = n < 0 ? cap : at + (size_t)n;
    }
    return at < cap;
}

/* Prunes by streaming to a temp file and swapping it in. */
#define STATS_TMP   STATS_DIR "/traffic.tmp"

/* The append's row, the tail mend's look-back and the prune's line: 448 holds the widest row whole
 * (411 B with '\n'), recount for a new column. SD lock only: both tstat_tick callers hold it. */
static EXT_RAM_BSS_ATTR char s_row[448];

/* The rows of traffic.csv from s_rc_from on and tstat_read's place in the file: a refresh of
 * /traffic reads only what was added. httpd task only, like its arrays in web_traffic.c. */
#define TSTAT_RC 64
static EXT_RAM_BSS_ATTR stat_hour_t s_rc_rows[TSTAT_RC];
static int s_rc_n;
static uint32_t s_rc_from;
static EXT_RAM_BSS_ATTR sdrc_t s_rc;
/* Counts prunes and failed writes. The cache's anchor cannot see a prune that keeps the bytes
 * before the reader's place. Bumped after the rewrite, so a read that overlapped it never keeps
 * its place. */
static volatile uint32_t s_rgen;

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

    /* Whole rows only. picolibc's fgets hands back the part before a read error. */
    bool ok = true, rest = false, whole;
    while (sdcsv_gets(s_row, sizeof(s_row), f, &rest, &whole))
    {
        if (ferror(f)) { ok = false; break; }
        if (!whole)
            continue;
        unsigned long h = strtoul(s_row, NULL, 10);
        if (h < keep_from_hour)
            continue;
        if (fputs(s_row, w) == EOF) { ok = false; break; }
    }
    /* A read error ends fgets like EOF would, and the swap would delete every row after it. */
    if (ferror(f))
        ok = false;
    fclose(f);
    /* picolibc's fclose hides a failed flush: without this a cut traffic.tmp would replace
     * traffic.csv. */
    if (ok && (fflush(w) != 0 || ferror(w)))
        ok = false;
    if (fclose(w) != 0)
        ok = false;

    if (!ok)
        remove(STATS_TMP);
    /* FatFs does not rename onto an existing file, so traffic.csv goes first. If that remove
     * fails, traffic.csv still has every row. */
    else if (remove(STATS_CSV) != 0)
    {
        ESP_LOGW(TAG, "cannot remove %s, the next prune tries again", STATS_CSV);
        remove(STATS_TMP);
    }
    /* traffic.csv is gone: tstat_tick renames traffic.tmp back before the next append. */
    else if (rename(STATS_TMP, STATS_CSV) != 0)
        ESP_LOGW(TAG, "cannot rename %s, the next write tries again", STATS_TMP);
}

void tstat_tick(void)
{
    if (!s_lock || !s_have_pending || !sdcard_is_mounted())
        return;

    /* Guards append and prune rewrite against unmount/format and the other SD
     * writers. Bounded: no caller may hang here when SD is wedged. */
    /* Non-recursive, so it also holds a second tstat_tick off until the flag clears. */
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
    /* A reset between prune()'s remove() and rename() leaves the whole history in
     * the temp file. Put it back BEFORE appending, or an empty csv wins. */
    sdcsv_rc_t rc = sdcsv_recover_tmp(STATS_CSV, STATS_TMP);
    const char *fail = rc == SDCSV_FAIL ? "tmp rename" : "open";
    struct stat st;
    /* csv is live, so any tmp is a dead prune's leftover: left there, a later recovery would
     * promote it over a csv the user deleted. Not under a download (FS_LOCK=0). */
    if (rc == SDCSV_OK && stat(STATS_CSV, &st) == 0 && sdcard_read_active() == 0 &&
        stat(STATS_TMP, &st) == 0)
        remove(STATS_TMP);
    FILE *f = rc == SDCSV_OK ? fopen(STATS_CSV, "a+") : NULL;
    /* A row cut by a failed write goes first, or the retry would glue onto it. */
    if (rc == SDCSV_OK)
        rc = f ? sdcsv_mend_tail(f, s_row, sizeof(s_row)) : SDCSV_FAIL;
    if (f && rc != SDCSV_OK)
        fail = "mend";
    /* After the mend, which used s_row as its look-back. The widest row fits; one that does not
     * (a new column, no recount) never will, so its hour is dropped with an error, not kept. */
    bool fits = format_row(s_row, sizeof(s_row), &row);
    if (rc == SDCSV_OK && fits && !sdcsv_put(f, s_row))
    {
        rc = SDCSV_FAIL;
        fail = "write";
    }
    /* The commit point: FatFs may not have the row without it. */
    if (f && fclose(f) != 0)
    {
        if (rc != SDCSV_FAIL)
            fail = "close";
        rc = SDCSV_FAIL;
    }
    if (rc == SDCSV_OK && !fits)
        ESP_LOGE(TAG, "traffic row wider than %u B, the hour is lost", (unsigned)sizeof(s_row));
    /* An hour of counts is worth a retry: it stays pending. Waiting for a download is no
     * failure and ends no streak. A failed write starts the reader at 0 (as in priolog.c). */
    if (rc == SDCSV_FAIL)
        s_rgen++;
    if (rc == SDCSV_FAIL && !s_write_warned)
        ESP_LOGW(TAG, "%s: %s failed, the hour stays pending", STATS_CSV, fail);
    if (rc != SDCSV_WAIT)
        s_write_warned = rc == SDCSV_FAIL;
    if (rc != SDCSV_OK)
    {
        sdcard_io_end();
        return;
    }
    /* portMAX_DELAY, never bounded: the row is on the card, so a timed-out take
     * leaves the flag set and the same hour gets appended twice (and SUMMED). */
    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE)
    {
        /* Not if the hour rolled meanwhile: that pending row is a new one. A roll
         * inside tstat_flush_now() goes unnoticed and drops one partial hour. */
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
        {
            prune(row.hour - days * 24);
            s_rgen++;
        }
        else
            s_flushes--;
    }
    sdcard_io_end();
}

/* Writes the hour still being accumulated. Without it a planned restart throws
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
    /* s_seen[] and the sender counts SURVIVE: /poweroff and an aborted rollback
     * flush and keep running, and the rest of the hour must not recount. */
    uint32_t keep[STAT_NCAT];
    memcpy(keep, s_current.senders, sizeof(keep));
    bool keep_capped = s_current.senders_capped;
    memset(&s_current, 0, sizeof(s_current));
    memcpy(s_current.senders, keep, sizeof(keep));
    s_current.senders_capped = keep_capped;
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
        /* Distinct senders cannot be summed, because the same vehicle may appear
         * in both halves. The larger half is the safe lower bound. */
        if (src->senders[c] > dst->senders[c]) dst->senders[c] = src->senders[c];
    }
    /* Merging only happens for two parts of the SAME hour. A restart between the
     * parts loses s_seen[], so the merged sender count is only a lower bound. */
    dst->senders_capped = true;
    dst->speed_legacy   = dst->speed_legacy   || src->speed_legacy;
}

/* What tstat_note can write. A row cut and glued to the next breaks it: a receiver's traffic.csv
 * keeps 291 of 291 rows and 0 of its 22317 glued variants. The hour must fit a 32-bit clock. */
static bool row_plausible(const uint32_t *v, int got)
{
    const uint32_t *cat = v + 2, *sum = cat + STAT_NCAT, *cnt = sum + STAT_NCAT,
                   *max = cnt + STAT_NCAT;
    uint64_t total = 0;
    if (v[0] > UINT32_MAX / 3600u)
        return false;
    for (int c = 0; c < STAT_NCAT; c++)
    {
        /* Each frame counts in total and in its category. Speeds stay under 400 km/h. */
        total += cat[c];
        if (cnt[c] > cat[c] || max[c] > 399 || (uint64_t)sum[c] > 399ull * cnt[c])
            return false;
    }
    return total == v[1] && (got < STATS_NF_NEW || v[STATS_NF_NEW - 1] <= 1);
}

/* One row of traffic.csv as stat_hour_t; false for anything tstat_tick cannot have written. */
static bool tstat_parse(const char *line, stat_hour_t *h)
{
    uint32_t v[STATS_NF_RULE] = {0};
    const char *p = line;
    int got = 0;
    bool wide = false;
    for (; got < STATS_NF_RULE; got++)
    {
        char *end;
        /* 64 bits on host and device alike: a glued field over 32 bits is no count. */
        unsigned long long x = strtoull(p, &end, 10);
        if (end == p) break;
        if (x > UINT32_MAX || end - p > 10) wide = true;
        v[got] = (uint32_t)x;
        p = end;
        if (*p == ',') p++;
    }
    /* Rows written before the sender columns existed stay valid. Their missing fields read as
     * zero. */
    if (wide || *p != '\n' || !row_plausible(v, got) || got < STATS_NF_OLD)
        return false;
    memset(h, 0, sizeof(*h));
    h->hour = v[0]; h->total = v[1];
    int idx = 2;
    for (int c = 0; c < STAT_NCAT; c++) h->cat[c]    = v[idx++];
    for (int c = 0; c < STAT_NCAT; c++) h->sp_sum[c] = v[idx++];
    for (int c = 0; c < STAT_NCAT; c++) h->sp_cnt[c] = v[idx++];
    for (int c = 0; c < STAT_NCAT; c++) h->sp_max[c] = v[idx++];
    if (got >= STATS_NF_NEW - 1)
        for (int c = 0; c < STAT_NCAT; c++) h->senders[c] = v[idx++];
    if (got >= STATS_NF_NEW)
        h->senders_capped = v[idx++] != 0;
    /* No marker, or one from a rule we do not know: treat the speed columns as following some
     * other definition. */
    h->speed_legacy = (got < STATS_NF_RULE || v[idx] != STATS_SPEED_RULE);
    return true;
}

/* One hour into out[], oldest first. A restart splits one hour into two rows: they fold, so the
 * chart shows one hour, not two short ones. A full array lets its oldest row go. */
static void tstat_put(stat_hour_t *out, int *count, int max, const stat_hour_t *h)
{
    if (*count > 0 && out[*count - 1].hour == h->hour)
        stat_hour_merge(&out[*count - 1], h);
    else if (*count < max)
        out[(*count)++] = *h;
    else
    {
        memmove(out, out + 1, (max - 1) * sizeof(*out));
        out[max - 1] = *h;
    }
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
    /* Counted reader guard, NOT the writer lock. The writer lock would block the
     * recorders for 720 rows. Unlink races it, so rows can be short and are checked below. */
    bool locked = sdcard_read_begin();
    /* Without a card there IS no stored history. Only a real miss on a mounted
     * card (an unmount or format pending) is worth warning about. */
    if (!locked && history_ok && sdcard_is_mounted())
        *history_ok = false;
    /* Two passes at most: a tail that overflows the cache reads the file again from the start. */
    for (int pass = 0; locked && pass < 2; pass++)
    {
        /* The cache keeps the rows from s_rc_from on: a wider window reads from the start. */
        FILE *f = sdrc_open(&s_rc, STATS_CSV, s_rgen, pass == 0 && from_hour >= s_rc_from);
        bool cached = f != NULL, tail = cached && s_rc.tail;
        /* A reset between prune()'s remove() and rename() leaves the complete history
         * in the temp file. Only a missing csv is that case. */
        if (!f && errno == ENOENT)
            f = fopen(STATS_TMP, "r");
        /* Any other failed open on a mounted card: the stored window is missing, so warn. */
        if (!f && errno != ENOENT && history_ok)
            *history_ok = false;
        if (!f)
            break;
        /* Rows before the window never show again: the cache starts at from_hour now. */
        int k = 0;
        for (int i = 0; tail && i < s_rc_n; i++)
            if (s_rc_rows[i].hour >= from_hour)
                s_rc_rows[k++] = s_rc_rows[i];
        if (cached)
        {
            s_rc_n = k;
            s_rc_from = from_hour;
        }
        bool fits = true;
        /* Not s_row: this holds the reader guard, not the SD lock. */
        char line[448];
        bool rest = false, whole;
        while (sdcsv_gets(line, sizeof(line), f, &rest, &whole))
        {
            /* picolibc's fgets hands back the part before a read error: not a row. */
            if (ferror(f))
                break;
            if (cached)
                sdrc_piece(&s_rc, f, line, sizeof(line));
            stat_hour_t h;
            if (!whole || !tstat_parse(line, &h) || h.hour < from_hour)
                continue;
            /* A read from the start fills out[] as it goes, a tail from the cache below. */
            if (!tail)
                tstat_put(out, &count, max, &h);
            if (cached && s_rc_n < TSTAT_RC)
                s_rc_rows[s_rc_n++] = h;
            else if (cached)
                fits = false;
        }
        bool err = ferror(f);
        if (cached)
            sdrc_done(&s_rc, f, !err && fits);
        fclose(f);
        if (tail && !fits)
            continue;
        /* A read error ends fgets like EOF would: the hours after it are missing. */
        if (err && history_ok)
            *history_ok = false;
        for (int i = 0; tail && i < s_rc_n; i++)
            tstat_put(out, &count, max, &s_rc_rows[i]);
        break;
    }
    if (locked)
        sdcard_read_end();

    /* Append the in-RAM current hour as the newest row, through the SAME merge as the stored
     * rows: after a planned restart the CSV already holds a row for this very hour. */
    if (s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE)
    {
        stat_hour_t cur = s_current;
        xSemaphoreGive(s_lock);
        if (cur.hour >= from_hour && cur.total > 0)
            tstat_put(out, &count, max, &cur);
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
