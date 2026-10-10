#include "sdkconfig.h"

#include "ptlog.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_attr.h"
#include "esp_log.h"

/* Outside the #if on purpose: fold_locked() logs and is compiled in every
 * configuration, so a TAG inside the SD block breaks CONFIG_ENABLE_SD=n. */
static const char TAG[] = "PTLOG";

#if CONFIG_ENABLE_SD
#include <errno.h>
#include <sys/stat.h>
#include "sd_csv.h"
#include "sdcard.h"

#define PT_DIR CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define PT_CSV PT_DIR "/transit.csv"
#define PT_TMP PT_DIR "/transit.tmp"
#define PT_BAD PT_DIR "/transit.bad"
#define PT_PASS PT_DIR "/passages.csv"
#define PT_PASS_TMP PT_DIR "/passages.tmp"
#define PT_SAVE_TICKS 60        /* sysmon runs every 5 s -> save every 5 min */
/* Failed reads in a row before transit.csv goes to transit.bad: about 5 min of sysmon ticks,
 * as for senders.csv. */
#define PT_BAD_TICKS 60

/* Every row in and out of the two files: a passage is at most 56 B with '\n', a line of the
 * table 89 B. All users hold the SD lock, so one buffer serves them all, and it stays off the
 * sysmon stack. */
static EXT_RAM_BSS_ATTR char s_row[128];
/* The last append failed and said so: one warning per streak of failures. */
static bool s_pass_warned;
#endif

/* Evicting a slot splits one passage into two sightings, so this is sized
 * well above the vehicles realistically in range at once. */
#define PT_OPEN         32      /* vehicles trackable at the same time */
#define PT_GAP_SEC      90      /* silence after which a passage is over */
#define PT_PASS_MAX_SEC 900     /* longer than this and the passage is split in two */

/* One vehicle in range. Identity is station id + line + course, so two trams
 * of one line never merge (a pseudonym change splits the sighting instead). */
typedef struct {
    uint32_t station_id;
    uint32_t first_sec, last_sec;
    uint16_t line, dest;
    uint8_t  course;
    int16_t  dev_last;
    /* The last request other than 0 and the highest priority, so a later telegram
     * without them does not erase what the vehicle asked for. */
    uint8_t  req_last;
    uint8_t  prio_max;
    /* Same rule for the two OCIT fields: the last value other than 0 survives a later
     * telegram that leaves them empty. */
    uint16_t point_last;
    uint8_t  train_len;
    bool     used;
} pt_open_t;

/* Closed passages waiting for the tick to append them. A summary alone never
 * answers "WHEN was it late". */
#define PT_PQ 32
static pt_pass_t s_pq[PT_PQ];
static int s_pq_head, s_pq_count;
static uint32_t s_pass_dropped;   /* individual passage rows the queue could not take */
/* The queue-full line goes out once per streak, under s_lock, because without a card every
 * passage would log it. It is outside the SD block, because fold_locked is built without a card
 * too. */
static bool s_loss_logged;

static pt_open_t s_open[PT_OPEN];
static EXT_RAM_BSS_ATTR pt_line_t s_lines[PT_MAX_LINES];
static int s_line_count;
static SemaphoreHandle_t s_lock;
static bool s_dirty;
static volatile uint32_t s_gen;
static volatile bool s_wipe_pending;

void ptlog_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

/* Called with the lock held: a finished passage becomes one sighting. */
static void fold_locked(const pt_open_t *p)
{
    int idx = -1;
    for (int i = 0; i < s_line_count; i++)
        if (s_lines[i].line == p->line) { idx = i; break; }
    if (idx < 0 && s_line_count < PT_MAX_LINES)
    {
        idx = s_line_count++;
        s_lines[idx] = (pt_line_t){ .line = p->line, .first_seen = p->first_sec };
    }

    /* The passage happened, so it is logged even when the per-line table is full. */
    if (s_pq_count < PT_PQ)
    {
        int q = (s_pq_head + s_pq_count) % PT_PQ;
        uint32_t dur = p->last_sec > p->first_sec ? p->last_sec - p->first_sec : 0;
        s_pq[q] = (pt_pass_t){ .seconds = p->first_sec, .line = p->line,
                               .dest = p->dest, .course = p->course,
                               .deviation = (int8_t)p->dev_last,
                               .secs_in_range = dur > 0xFFFF ? 0xFFFF : (uint16_t)dur,
                               .request = p->req_last, .priority = p->prio_max,
                               .point = p->point_last, .train_len = p->train_len };
        s_pq_count++;
    }
    else
    {
        /* Queue full: only the individual row is lost. The aggregate line below
         * still gets the passage. The counter keeps the loss visible. */
        s_pass_dropped++;
        if (!s_loss_logged)
            ESP_LOGW(TAG, "passage queue full, %lu individual rows lost so far",
                     (unsigned long)s_pass_dropped);
        s_loss_logged = true;
    }
    if (idx < 0)
        return;

    pt_line_t *l = &s_lines[idx];
    l->sightings++;
    l->last_seen = p->last_sec;
    if (p->dev_last == 0)
        l->dev_zero++;
    else
    {
        l->dev_sum += p->dev_last;
        l->dev_count++;
        if (p->dev_last > l->worst_late)  l->worst_late  = (int8_t)p->dev_last;
        if (p->dev_last < l->worst_early) l->worst_early = (int8_t)p->dev_last;
        if (p->dev_last >= 7 || p->dev_last <= -7)
            l->saturated++;
    }
    s_dirty = true;
}

void ptlog_note(uint32_t seconds, uint32_t station_id, const its_decoded_t *d)
{
    if (!s_lock || !d->pt_telegram || !d->pt_line || !station_id)
        return;
    if (seconds < 1600000000u)     /* before the clock is set, times are fiction */
        return;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;

    int free_slot = -1, oldest = 0;
    for (int i = 0; i < PT_OPEN; i++)
    {
        if (!s_open[i].used)
        {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (s_open[i].station_id == station_id && s_open[i].line == d->pt_line &&
            s_open[i].course == d->pt_course)
        {
            /* Still the same passage. If it has been running far too long, a
             * vehicle is parked in range with a live unit, so split it. */
            if (seconds - s_open[i].first_sec > PT_PASS_MAX_SEC)
            {
                fold_locked(&s_open[i]);
                s_open[i].first_sec = seconds;
                s_open[i].req_last = 0;
                s_open[i].prio_max = 0;
            }
            s_open[i].last_sec = seconds;
            s_open[i].dev_last = d->pt_deviation;
            if (d->pt_dest) s_open[i].dest = d->pt_dest;
            if (d->pt_request) s_open[i].req_last = d->pt_request;
            if (d->pt_priority > s_open[i].prio_max) s_open[i].prio_max = d->pt_priority;
            if (d->pt_point) s_open[i].point_last = d->pt_point;
            if (d->pt_train_len) s_open[i].train_len = d->pt_train_len;
            xSemaphoreGive(s_lock);
            return;
        }
        if (s_open[i].last_sec < s_open[oldest].last_sec)
            oldest = i;
    }

    int slot = free_slot;
    if (slot < 0)
    {
        slot = oldest;
        fold_locked(&s_open[slot]);   /* all busy: the stalest one is done */
    }
    s_open[slot] = (pt_open_t){ .station_id = station_id, .first_sec = seconds,
                                .last_sec = seconds, .line = d->pt_line,
                                .dest = d->pt_dest, .course = d->pt_course,
                                .dev_last = d->pt_deviation, .req_last = d->pt_request,
                                .prio_max = d->pt_priority, .point_last = d->pt_point,
                                .train_len = d->pt_train_len, .used = true };
    xSemaphoreGive(s_lock);
}

int ptlog_snapshot(pt_line_t *out)
{
    if (!s_lock || !out)
        return 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return 0;
    int n = s_line_count;
    memcpy(out, s_lines, (size_t)n * sizeof(s_lines[0]));
    xSemaphoreGive(s_lock);

    for (int i = 1; i < n; i++)   /* busiest line first */
    {
        pt_line_t t = out[i];
        int j = i - 1;
        while (j >= 0 && out[j].sightings < t.sightings) { out[j + 1] = out[j]; j--; }
        out[j + 1] = t;
    }
    return n;
}

uint32_t ptlog_passages_dropped(void) { return s_pass_dropped; }

int ptlog_latest(uint16_t *line, uint32_t *sec)
{
    if (!s_lock)
        return 0;
    /* 50 ms is enough, because the holders are short and no card I/O runs under s_lock. */
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE)
        return -1;
    uint32_t best = 0;
    uint16_t bl = 0;
    for (int i = 0; i < PT_OPEN; i++)
        if (s_open[i].used && s_open[i].last_sec > best)
        {
            best = s_open[i].last_sec;
            bl = s_open[i].line;
        }
    for (int i = 0; i < s_line_count; i++)
        if (s_lines[i].last_seen > best)
        {
            best = s_lines[i].last_seen;
            bl = s_lines[i].line;
        }
    xSemaphoreGive(s_lock);
    if (!best)
        return 0;
    *line = bl;
    *sec = best;
    return 1;
}

int ptlog_open_count(void)
{
    int n = 0;
    for (int i = 0; i < PT_OPEN; i++)
        if (s_open[i].used) n++;
    return n;
}

#if CONFIG_ENABLE_SD

/* Staging for pt_load, merged into s_lines exactly ONCE at the end: the merge
 * is additive, so a partial merge plus a retry doubles. Static, not stack. */
static pt_line_t s_load_tmp[PT_MAX_LINES];
static int s_load_n;

static pt_line_t *load_row(uint16_t line)
{
    for (int i = 0; i < s_load_n; i++)
        if (s_load_tmp[i].line == line)
            return &s_load_tmp[i];
    if (s_load_n >= PT_MAX_LINES)
        return NULL;
    pt_line_t *l = &s_load_tmp[s_load_n++];
    *l = (pt_line_t){ .line = line };
    return l;
}

/* Reads in a row that failed with a fault of the file, under the SD lock. */
static int s_read_fails;

/* One more failed read of `path`. True once it moved to transit.bad, after an older one was
 * removed. A file that never reads again would stop every save, so it is moved, never deleted. */
static bool pt_read_failed(const char *path)
{
    /* No file handle, no memory or the volume lock busy: the file is not at fault. */
    int e = errno;
    if (e == ENFILE || e == EMFILE || e == ENOMEM || e == ETIMEDOUT || e == EACCES)
        return false;
    if (s_read_fails < PT_BAD_TICKS)
        s_read_fails++;
    /* FS_LOCK=0: no remove or rename while a download may hold either file. */
    if (s_read_fails < PT_BAD_TICKS || sdcard_read_active() != 0)
        return false;
    remove(PT_BAD);                  /* FatFs does not rename onto an existing file */
    if (rename(path, PT_BAD) != 0)
        return false;                /* stays at the limit: the next tick tries again */
    s_read_fails = 0;
    ESP_LOGW(TAG, "%s failed to read %d times in a row, moved to %s; the table starts empty",
             path, PT_BAD_TICKS, PT_BAD);
    return true;
}

/* False = nothing merged, so the caller must retry and must not save yet. A missing file counts
 * as success, and so do a file too big for the table and one just moved to transit.bad. */
static bool pt_load(void)
{
    bool lost = false;       /* transient: retry */
    bool truncated = false;  /* permanent: do NOT retry */
    uint32_t gen = s_gen;   /* a clear landing during the read must win */
    s_load_n = 0;
    if (!sdcard_io_begin_timeout(2000))
        return false;
    /* Only ENOENT means nothing is stored: after a bus error (EIO) a save would put the lines
     * since boot in its place. A power cut between remove and rename leaves only the tmp. */
    const char *path = PT_CSV;
    errno = 0;
    FILE *f = fopen(path, "r");
    if (!f && errno == ENOENT)
    {
        path = PT_TMP;
        errno = 0;
        f = fopen(path, "r");
    }
    if (!f)
    {
        bool ok = errno == ENOENT || pt_read_failed(path);
        sdcard_io_end();
        return ok;
    }
    bool rest = false, whole;
    while (sdcsv_gets(s_row, sizeof(s_row), f, &rest, &whole))
    {
        /* picolibc's fgets hands back the part before a read error: not a line. */
        if (ferror(f))
            break;
        if (!whole)
            continue;
        unsigned ln = 0, sat = 0;
        unsigned long sight = 0, dcount = 0, dzero = 0, first = 0, last = 0;
        long dsum = 0;
        int wl = 0, we = 0, n = 0;
        /* Every save wrote exactly these ten fields, then the '\n'. */
        if (sscanf(s_row, "%u,%lu,%ld,%lu,%lu,%u,%d,%d,%lu,%lu%n",
                   &ln, &sight, &dsum, &dcount, &dzero, &sat, &wl, &we,
                   &first, &last, &n) != 10 || !ln || s_row[n] != '\n')
            continue;
        pt_line_t *l = load_row((uint16_t)ln);
        if (!l)
        {
            /* Permanent, so it must NOT set `lost`: a retry reads the same
             * file and the module would never finish loading. Keep what fits. */
            truncated = true;
            continue;
        }
        l->sightings += (uint32_t)sight;
        l->dev_sum   += (int32_t)dsum;
        l->dev_count += (uint32_t)dcount;
        l->dev_zero  += (uint32_t)dzero;
        l->saturated = (uint16_t)(l->saturated + sat);
        if ((int8_t)wl > l->worst_late)  l->worst_late  = (int8_t)wl;
        if ((int8_t)we < l->worst_early) l->worst_early = (int8_t)we;
        if (first && (!l->first_seen || (uint32_t)first < l->first_seen))
            l->first_seen = (uint32_t)first;
        if ((uint32_t)last > l->last_seen) l->last_seen = (uint32_t)last;
    }
    /* A read error ends fgets like the end of the file, and the next save would drop every line
     * after it for good. Nothing is merged, so the next tick reads the file again. */
    bool read_ok = !ferror(f);
    int e = errno;           /* the read error's errno, kept for pt_read_failed after fclose */
    fclose(f);
    if (!read_ok)
    {
        errno = e;
        bool moved = pt_read_failed(path);
        sdcard_io_end();
        return moved;
    }
    s_read_fails = 0;        /* read whole, so a refused lock below retries without an old count */

    /* ONE merge: it adds (sightings folded before the card mounted must survive), so it may
     * run only once per successful load. */
    if (!lost && s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) == pdTRUE)
    {
        /* Cleared mid-read: merging now would resurrect what the user just
         * deleted. Drop the batch; the retry then reads an empty file. */
        if (gen != s_gen)
            lost = true;
        /* The loop never stops halfway for a retry, which would add the merged lines twice.
         * `lost` is settled above, and a stored line without room is skipped. The file lists
         * the busiest lines first. */
        for (int i = 0; i < s_load_n && !lost; i++)
        {
            const pt_line_t *src = &s_load_tmp[i];
            int idx = -1;
            for (int k = 0; k < s_line_count; k++)
                if (s_lines[k].line == src->line) { idx = k; break; }
            if (idx < 0 && s_line_count >= PT_MAX_LINES)
            {
                truncated = true;   /* permanent: the next save leaves this line out */
                continue;
            }
            if (idx < 0)
            {
                idx = s_line_count++;
                s_lines[idx] = (pt_line_t){ .line = src->line };
            }
            pt_line_t *l = &s_lines[idx];
            l->sightings += src->sightings;
            l->dev_sum   += src->dev_sum;
            l->dev_count += src->dev_count;
            l->dev_zero  += src->dev_zero;
            l->saturated = (uint16_t)(l->saturated + src->saturated);
            if (src->worst_late  > l->worst_late)  l->worst_late  = src->worst_late;
            if (src->worst_early < l->worst_early) l->worst_early = src->worst_early;
            if (src->first_seen && (!l->first_seen || src->first_seen < l->first_seen))
                l->first_seen = src->first_seen;
            if (src->last_seen > l->last_seen) l->last_seen = src->last_seen;
        }
        xSemaphoreGive(s_lock);
    }
    else
        lost = true;

    sdcard_io_end();
    if (truncated)
        ESP_LOGW(TAG, "transit.csv and the lines since the start exceed %d; the surplus is "
                 "not loaded", PT_MAX_LINES);
    /* `truncated` deliberately does NOT force a retry: the file will not
     * shrink, so retrying would loop forever and the table would never load. */
    return !lost;
}

/* File scope so ptlog_flush_now() honours it too: pt_save() is a FULL
 * rewrite, so saving before the load succeeded discards the stored lines. */
static bool s_loaded;

/* Appends the queued passages and trims now and then. Append, not rewrite:
 * a passage row never changes once written, unlike the per-line summary. */
static void pass_flush(void)
{
    /* Static, not a stack local, for the 4096-byte sysmon stack. Safe because it is
     * only used while the SD lock is held. */
    static pt_pass_t batch[PT_PQ];
    int count;
    if (!s_lock)
        return;
    /* SD lock BEFORE the copy and held across copy-write-advance: two tasks
     * call this, and copying first lets both write the same batch. */
    if (!sdcard_io_begin_timeout(2000))
        return;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
    {
        sdcard_io_end();
        return;
    }
    uint32_t gen = s_gen;   /* a clear resets head and count under this lock */
    count = s_pq_count;
    for (int i = 0; i < count; i++)
        batch[i] = s_pq[(s_pq_head + i) % PT_PQ];
    xSemaphoreGive(s_lock);
    if (!count)
    {
        sdcard_io_end();
        return;
    }

    mkdir(PT_DIR, 0777);
    const char *fail = "tmp rename";
    sdcsv_rc_t rc = sdcsv_recover_tmp(PT_PASS, PT_PASS_TMP);
    FILE *f = NULL;
    if (rc == SDCSV_OK)
    {
        f = fopen(PT_PASS, "a+");
        fail = f ? "mend" : "open";
        rc = f ? sdcsv_mend_tail(f, s_row, sizeof(s_row)) : SDCSV_FAIL;
    }
    /* Rows that reached the card, one by one: a failure costs this row and no earlier one. */
    int written = 0;
    for (int i = 0; i < count && rc == SDCSV_OK; i++)
    {
        const pt_pass_t *b = &batch[i];
        snprintf(s_row, sizeof(s_row), "%lu,%u,%u,%u,%d,%u,%u,%u,%u,%u\n",
                 (unsigned long)b->seconds, b->line, b->course, b->dest, b->deviation,
                 b->secs_in_range, b->request, b->priority, b->point, b->train_len);
        if (!sdcsv_put(f, s_row))
        {
            rc = SDCSV_FAIL;
            fail = "write";
            break;
        }
        written++;
    }
    /* fclose is the commit point. When it fails, FatFs may not have the rows, so every one
     * stays queued. */
    if (f && fclose(f) != 0)
    {
        if (rc != SDCSV_FAIL)
            fail = "close";
        rc = SDCSV_FAIL;
        written = 0;
    }
    /* Waiting for a download is no failure and ends no streak. */
    if (rc == SDCSV_FAIL && !s_pass_warned)
        ESP_LOGW(TAG, "%s: %s failed, %d rows stay queued", PT_PASS, fail, count - written);
    if (rc != SDCSV_WAIT)
        s_pass_warned = rc == SDCSV_FAIL;

    /* Longer than the usual 100 ms: the rows are already on the card, and
     * missing the dequeue means writing them a second time next tick. */
    if (written > 0)
    {
        if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(1000)) == pdTRUE)
        {
            /* Cleared between copy and confirm: head/count may already describe
             * NEW passages, so advancing by our count would discard those. */
            if (gen != s_gen)
                ESP_LOGW(TAG, "transit log cleared mid-write; %d rows not dequeued", written);
            else
            {
                /* Drop exactly what was written; entries queued meanwhile stay. */
                s_pq_head = (s_pq_head + written) % PT_PQ;
                s_pq_count -= written;
                s_loss_logged = false;
                /* Belt and braces: the count can only have grown since the copy. */
                if (s_pq_count < 0) s_pq_count = 0;
            }
            xSemaphoreGive(s_lock);
        }
        else
            ESP_LOGW(TAG, "passages written but not dequeued; %d rows will repeat", written);
    }

    /* `% 64 == 1` on a pre-incremented counter on purpose: the first trim must fall on the first
     * append, or a device that restarts often never trims. A failed append is not counted. */
    static uint32_t s_appends;
    if (rc == SDCSV_OK && ++s_appends % 64 == 1)
    {
        /* The trim unlinks passages.csv, which a streaming download holds
         * open. Un-count, so the trim retries on the next append. */
        if (sdcard_read_active() != 0)
            s_appends--;
        else
            sdcsv_keep_newest(PT_PASS, PT_PASS_TMP, PT_PASS_KEEP, s_row, sizeof(s_row));
    }
    sdcard_io_end();
}

static void pt_pass_reverse(pt_pass_t *a, int lo, int hi)
{
    while (lo < hi)
    {
        pt_pass_t t = a[lo]; a[lo] = a[hi]; a[hi] = t;
        lo++; hi--;
    }
}

int ptlog_read_passages(pt_pass_t *out, int max)
{
    if (!out || max <= 0 || !sdcard_io_begin_timeout(2000))
        return 0;
    FILE *f = fopen(PT_PASS, "r");
    /* Only a missing csv can mean a power cut between the trim's remove and rename. */
    if (!f && errno == ENOENT)
        f = fopen(PT_PASS_TMP, "r");
    if (!f)
    {
        sdcard_io_end();
        return 0;
    }
    int count = 0, head = 0;
    bool rest = false, whole;
    while (sdcsv_gets(s_row, sizeof(s_row), f, &rest, &whole))
    {
        /* picolibc's fgets hands back the part before a read error: the rows before it stay. */
        if (ferror(f))
            break;
        if (!whole)
            continue;
        unsigned long sec = 0;
        unsigned ln = 0, ku = 0, zi = 0, dur = 0, ha = 0, pr = 0, mp = 0, zl = 0;
        int dev = 0;
        int got = sscanf(s_row, "%lu,%u,%u,%u,%d,%u,%u,%u,%u,%u", &sec, &ln, &ku, &zi, &dev,
                         &dur, &ha, &pr, &mp, &zl);
        /* Each field may be at most as wide as its type prints, and the time at most 4294967295,
         * because sscanf overflows differently on riscv32 and on a 64-bit host. The widths are
         * counted between the commas. */
        static const uint8_t width[10] = { 10, 5, 3, 5, 4, 5, 3, 3, 5, 3 };
        int commas = 0, len = 0;
        bool wide = false;
        for (const char *c = s_row; *c && *c != '\n'; c++)
        {
            if (*c != ',')
                wide |= commas > 9 || ++len > width[commas];
            else
            {
                commas++;
                len = 0;
            }
        }
        /* Rows have 6, 8 or 10 fields and a time of 10 digits (ptlog_note keeps no time before
         * the clock is set). A row cut and glued to the next has more fields or a wider one. */
        if ((got != 6 && got != 8 && got != 10) || commas != got - 1 || wide ||
            strspn(s_row, "0123456789") != 10 || memcmp(s_row, "4294967295", 10) > 0 ||
            ln > 0xFFFF || ku > 0xFF || zi > 0xFFFF || dev < -128 || dev > 127 || dur > 0xFFFF)
            continue;
        /* Rows written before the request columns end after the sixth field. The test is fewer
         * THAN eight, not "other than eight", because a full row with the OCIT columns has ten. */
        if (got < 8 || ha > 3 || pr > 3)
            ha = pr = PT_REQ_UNKNOWN;
        if (got < 10 || mp > 0xFFFF || zl > 0xFF)
            mp = zl = 0;
        pt_pass_t r = { .seconds = (uint32_t)sec, .line = (uint16_t)ln, .dest = (uint16_t)zi,
                        .course = (uint8_t)ku, .deviation = (int8_t)dev,
                        .secs_in_range = (uint16_t)dur, .request = (uint8_t)ha,
                        .priority = (uint8_t)pr, .point = (uint16_t)mp,
                        .train_len = (uint8_t)zl };
        if (count < max)
            out[count++] = r;
        else
        {
            /* Ring, not a per-row shift: between trims the file can sit
             * thousands of rows above PT_PASS_KEEP. As in tracklog_read. */
            out[head] = r;                 /* overwrite the oldest, O(1) */
            head = (head + 1) % max;
        }
    }
    fclose(f);
    sdcard_io_end();

    /* Rotate the ring back into file order, then reverse the whole thing:
     * out[] ends up newest first, which is what the callers render. */
    if (count == max && head > 0)
    {
        pt_pass_reverse(out, 0, head - 1);
        pt_pass_reverse(out, head, count - 1);
    }
    else
        pt_pass_reverse(out, 0, count - 1);
    return count;
}

static bool pt_save(void)
{
    static EXT_RAM_BSS_ATTR pt_line_t snap[PT_MAX_LINES];
    /* SD lock BEFORE the snapshot: two tasks save and snap[] is shared. Re-sorted mid-write it
     * puts a line in twice, added twice at the next load. */
    if (!sdcard_io_begin_timeout(2000))
        return false;
    uint32_t gen = s_gen;
    int n = ptlog_snapshot(snap);
    if (n <= 0)
    {
        sdcard_io_end();
        return false;
    }

    mkdir(PT_DIR, 0777);
    /* A transit.tmp without transit.csv is the only copy, so it goes back to transit.csv before
     * "w" empties it. During a download it waits, and s_dirty retries. */
    if (sdcsv_recover_tmp(PT_CSV, PT_TMP) != SDCSV_OK)
    {
        sdcard_io_end();
        return false;
    }
    FILE *f = fopen(PT_TMP, "w");
    if (!f)
    {
        sdcard_io_end();
        return false;
    }
    /* Row by row: picolibc drops its buffer on a failed write-out and fclose does not tell. */
    bool ok = true;
    for (int i = 0; i < n && ok; i++)
    {
        const pt_line_t *l = &snap[i];
        snprintf(s_row, sizeof(s_row), "%u,%lu,%ld,%lu,%lu,%u,%d,%d,%lu,%lu\n",
                 l->line, (unsigned long)l->sightings, (long)l->dev_sum,
                 (unsigned long)l->dev_count, (unsigned long)l->dev_zero,
                 l->saturated, l->worst_late, l->worst_early,
                 (unsigned long)l->first_seen, (unsigned long)l->last_seen);
        ok = sdcsv_put(f, s_row);
    }
    if (fclose(f) != 0)
        ok = false;
    if (!ok)
        remove(PT_TMP);     /* a cut copy must not wait there for pt_load's fallback */
    else if (gen != s_gen)
    {
        remove(PT_TMP);     /* cleared meanwhile -- don't resurrect */
        ok = false;
    }
    else if (sdcard_read_active() != 0)
    {
        /* The swap unlinks transit.csv, which a streaming download holds
         * open. Never force it: keep the live file, s_dirty retries later. */
        ok = false;
    }
    /* FatFs renames onto no existing file, so transit.csv goes first. If it stays, it still has
     * every line. */
    else if (remove(PT_CSV) != 0 && errno != ENOENT)
    {
        ESP_LOGW(TAG, "cannot remove %s, the next save tries again", PT_CSV);
        remove(PT_TMP);
        ok = false;
    }
    /* transit.csv is gone: pt_load and the next save take transit.tmp back first. */
    else if (rename(PT_TMP, PT_CSV) != 0)
    {
        ESP_LOGW(TAG, "cannot rename %s, the next save tries again", PT_TMP);
        ok = false;
    }
    sdcard_io_end();
    return ok;
}

/* False = SD lock busy; remove() is idempotent, so retry. Not gated on
 * sdcard_read_active(): deferring would stall pass_flush behind a download. */
static bool pt_wipe(void)
{
    if (!sdcard_io_begin_timeout(2000))
        return false;
    remove(PT_CSV);
    remove(PT_TMP);
    remove(PT_PASS);
    remove(PT_PASS_TMP);
    sdcard_io_end();
    s_wipe_pending = false;
    return true;
}
#else  /* no card: passages are still folded into the per-line table */
int ptlog_read_passages(pt_pass_t *out, int max) { (void)out; (void)max; return 0; }
#endif /* CONFIG_ENABLE_SD */

void ptlog_tick(void)
{
    if (!s_lock)
        return;

    /* A passage that went quiet is over. Fold it so it shows up even when no
     * other vehicle follows. */
    if (xSemaphoreTake(s_lock, 0) == pdTRUE)
    {
        uint32_t now = (uint32_t)time(NULL);
        for (int i = 0; i < PT_OPEN; i++)
            if (s_open[i].used && now > s_open[i].last_sec &&
                now - s_open[i].last_sec > PT_GAP_SEC)
            {
                fold_locked(&s_open[i]);
                s_open[i].used = false;
            }
        xSemaphoreGive(s_lock);
    }

#if CONFIG_ENABLE_SD
    static int ticks;
    if (!sdcard_is_mounted())
        return;
    if (s_wipe_pending)
    {
        pt_wipe();
        return;
    }
    if (!s_loaded)
        s_loaded = pt_load();   /* retried until it really succeeded */
    /* passages.csv is a file of its own: it does not wait for the table. */
    pass_flush();
    if (!s_loaded)
        return;
    if (++ticks < PT_SAVE_TICKS || !s_dirty)
        return;
    ticks = 0;
    if (pt_save())
        s_dirty = false;
#endif
}

/* Folds every open passage and writes out. Call before a planned restart.
 * Splitting a running passage beats losing it and the unsaved aggregates. */
void ptlog_flush_now(void)
{
#if CONFIG_ENABLE_SD
    if (!s_lock)
        return;
    /* A deferred wipe must win here: s_wipe_pending is RAM only and does not
     * survive the reboot that follows, so the deleted rows would stay. */
    if (s_wipe_pending)
    {
        pt_wipe();
        return;
    }
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) == pdTRUE)
    {
        for (int i = 0; i < PT_OPEN; i++)
            if (s_open[i].used)
            {
                fold_locked(&s_open[i]);
                s_open[i].used = false;
            }
        xSemaphoreGive(s_lock);
    }
    /* passages.csv does not wait for the table, as in the tick. */
    pass_flush();
    /* Never write back a table we have not read yet. The tick follows the same
     * rule, and a restart is exactly when it matters most. */
    if (s_loaded)
        pt_save();
#endif
}

void ptlog_clear(void)
{
    /* portMAX_DELAY, not a timeout: the handler answers "OK" either way, so
     * blocking a few ms beats silently clearing nothing. Holders are short. */
    if (!s_lock || xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE)
        return;
    memset(s_lines, 0, sizeof(s_lines));
    memset(s_open, 0, sizeof(s_open));
    s_pq_head = s_pq_count = 0;
    s_line_count = 0;
    s_dirty = false;
#if CONFIG_ENABLE_SD
    /* Bumped under the lock, so a pt_load or pass_flush that is mid-flight
     * sees it the moment it re-takes the lock and drops its stale batch. */
    s_gen++;
#endif
    xSemaphoreGive(s_lock);

#if CONFIG_ENABLE_SD
    if (!pt_wipe())
        s_wipe_pending = true;
#endif
}
