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
#include <sys/stat.h>
#include "sdcard.h"

#define PT_DIR CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define PT_CSV PT_DIR "/transit.csv"
#define PT_TMP PT_DIR "/transit.tmp"
#define PT_PASS PT_DIR "/passages.csv"
#define PT_PASS_TMP PT_DIR "/passages.tmp"
#define PT_SAVE_TICKS 60        /* sysmon runs every 5 s -> save every 5 min */
#endif

/* Evicting a slot splits one passage into two sightings, so this is sized
 * well above the vehicles realistically in range at once. */
#define PT_OPEN         32      /* vehicles trackable at the same time */
#define PT_GAP_SEC      90      /* silence after which a passage is over */
#define PT_PASS_MAX_SEC 900     /* a parked vehicle must not hold a slot forever */

/* One vehicle in range. Identity is station id + line + course, so two trams
 * of one line never merge (a pseudonym change splits the sighting instead). */
typedef struct {
    uint32_t station_id;
    uint32_t first_sec, last_sec;
    uint16_t line, dest;
    uint8_t  course;
    int16_t  dev_last;
    bool     used;
} pt_open_t;

/* Closed passages waiting for the tick to append them; a summary alone never
 * answers "WHEN was it late". */
#define PT_PQ 32
static pt_pass_t s_pq[PT_PQ];
static int s_pq_head, s_pq_count;
static uint32_t s_pass_dropped;   /* individual passage rows the queue could not take */

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

    /* Logged even when the per-line table is full -- the passage happened. */
    if (s_pq_count < PT_PQ)
    {
        int q = (s_pq_head + s_pq_count) % PT_PQ;
        uint32_t dur = p->last_sec > p->first_sec ? p->last_sec - p->first_sec : 0;
        s_pq[q] = (pt_pass_t){ .seconds = p->first_sec, .line = p->line,
                               .dest = p->dest, .course = p->course,
                               .deviation = (int8_t)p->dev_last,
                               .secs_in_range = dur > 0xFFFF ? 0xFFFF : (uint16_t)dur };
        s_pq_count++;
    }
    else
    {
        /* Queue full: only the individual row is lost, the aggregate line
         * below still gets the passage. Counted so it is never silent. */
        s_pass_dropped++;
        ESP_LOGW(TAG, "passage queue full, %lu individual rows lost so far",
                 (unsigned long)s_pass_dropped);
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
            /* Still the same passage -- unless it has been going on far too
             * long, which means a vehicle parked in range with a live unit. */
            if (seconds - s_open[i].first_sec > PT_PASS_MAX_SEC)
            {
                fold_locked(&s_open[i]);
                s_open[i].first_sec = seconds;
            }
            s_open[i].last_sec = seconds;
            s_open[i].dev_last = d->pt_deviation;
            if (d->pt_dest) s_open[i].dest = d->pt_dest;
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
                                .dev_last = d->pt_deviation, .used = true };
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

/* False = nothing merged, so the caller must retry and must not save yet.
 * Missing file counts as success; so does a file too big for the table. */
static bool pt_load(void)
{
    bool lost = false;       /* transient: retry */
    bool truncated = false;  /* permanent: do NOT retry */
    uint32_t gen = s_gen;   /* a clear landing during the read must win */
    s_load_n = 0;
    if (!sdcard_io_begin_timeout(2000))
        return false;
    FILE *f = fopen(PT_CSV, "r");
    if (!f)
        f = fopen(PT_TMP, "r");   /* power cut between remove and rename */
    if (!f)
    {
        sdcard_io_end();
        return true;      /* nothing stored yet is a valid answer */
    }
    char line[192];
    while (fgets(line, sizeof(line), f))
    {
        unsigned ln = 0, sat = 0;
        unsigned long sight = 0, dcount = 0, dzero = 0, first = 0, last = 0;
        long dsum = 0;
        int wl = 0, we = 0;
        if (sscanf(line, "%u,%lu,%ld,%lu,%lu,%u,%d,%d,%lu,%lu",
                   &ln, &sight, &dsum, &dcount, &dzero, &sat, &wl, &we,
                   &first, &last) != 10 || !ln)
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
    fclose(f);

    /* ONE merge, all or nothing: it adds (sightings folded before the card
     * mounted must survive), so it may run only once per successful load. */
    if (!lost && s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) == pdTRUE)
    {
        /* Cleared mid-read: merging now would resurrect what the user just
         * deleted. Drop the batch; the retry then reads an empty file. */
        if (gen != s_gen)
            lost = true;
        /* Capacity FIRST, before any row is added: bailing out halfway plus
         * the retry would count the merged rows twice. Never move this down. */
        int need = 0;
        for (int i = 0; i < s_load_n; i++)
        {
            bool have = false;
            for (int k = 0; k < s_line_count; k++)
                if (s_lines[k].line == s_load_tmp[i].line) { have = true; break; }
            if (!have) need++;
        }
        if (s_line_count + need > PT_MAX_LINES)
            truncated = true;   /* permanent, and nothing has been touched yet */

        for (int i = 0; i < s_load_n && !lost && !truncated; i++)
        {
            const pt_line_t *src = &s_load_tmp[i];
            int idx = -1;
            for (int k = 0; k < s_line_count; k++)
                if (s_lines[k].line == src->line) { idx = k; break; }
            if (idx < 0)
            {
                idx = s_line_count++;   /* room was verified above */
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
        ESP_LOGW(TAG, "transit.csv holds more than %d lines; the surplus is not loaded",
                 PT_MAX_LINES);
    /* `truncated` deliberately does NOT force a retry: the file will not
     * shrink, so retrying would loop forever and the table would never load. */
    return !lost;
}

/* Appends the queued passages and trims now and then. Append, not rewrite:
 * a passage row never changes once written, unlike the per-line summary. */
/* File scope so ptlog_flush_now() honours it too: pt_save() is a FULL
 * rewrite, so saving before the load succeeded discards the stored lines. */
static bool s_loaded;

static void pass_flush(void)
{
    pt_pass_t batch[PT_PQ];
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
    FILE *f = fopen(PT_PASS, "a");
    if (!f)
    {
        sdcard_io_end();
        return;
    }
    bool ok = true;
    for (int i = 0; i < count; i++)
        if (fprintf(f, "%lu,%u,%u,%u,%d,%u\n",
                    (unsigned long)batch[i].seconds, batch[i].line,
                    batch[i].course, batch[i].dest, batch[i].deviation,
                    batch[i].secs_in_range) < 0)
            { ok = false; break; }
    if (fclose(f) != 0)
        ok = false;
    if (!ok)
    {
        sdcard_io_end();
        return;
    }
    /* Longer than the usual 100 ms: the rows are already on the card, and
     * missing the dequeue means writing them a second time next tick. */
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(1000)) == pdTRUE)
    {
        /* Cleared between copy and confirm: head/count may already describe
         * NEW passages, so advancing by our count would discard those. */
        if (gen != s_gen)
        {
            ESP_LOGW(TAG, "transit log cleared mid-write; %d rows not dequeued", count);
        }
        else
        {
            /* Drop exactly what was written; entries queued meanwhile stay. */
            s_pq_head = (s_pq_head + count) % PT_PQ;
            s_pq_count -= count;
            /* Belt and braces: the count can only have grown since the copy. */
            if (s_pq_count < 0) s_pq_count = 0;
        }
        xSemaphoreGive(s_lock);
    }
    else
        ESP_LOGW(TAG, "passages written but not dequeued; %d rows will repeat", count);

    /* Trim by streaming the tail out, so file size never bounds a buffer. */
    /* `% 64 == 1` on a pre-incremented counter on purpose: the first trim must
     * fall on the first append, or a device that restarts often never trims. */
    static uint32_t s_appends;
    if (++s_appends % 64 == 1)
    {
        /* The trim unlinks passages.csv, which a streaming download holds
         * open. Un-count, so the trim retries on the next append. */
        if (sdcard_read_active() != 0)
            s_appends--;
        else
        {
            FILE *r = fopen(PT_PASS, "r");
            if (r)
            {
                char line[96];
                uint32_t total = 0;
                while (fgets(line, sizeof(line), r)) total++;
                if (total > PT_PASS_KEEP)
                {
                    rewind(r);
                    FILE *w = fopen(PT_PASS_TMP, "w");
                    if (w)
                    {
                        uint32_t skip = total - PT_PASS_KEEP, i = 0;
                        bool tok = true;
                        while (fgets(line, sizeof(line), r))
                            if (i++ >= skip && fputs(line, w) == EOF) { tok = false; break; }
                        if (fclose(w) != 0) tok = false;
                        /* Rename first where possible; the reader falls back to
                         * the temp file if a power cut lands between the two. */
                        if (tok) { fclose(r); r = NULL; remove(PT_PASS); rename(PT_PASS_TMP, PT_PASS); }
                        else     remove(PT_PASS_TMP);
                    }
                }
                if (r) fclose(r);
            }
        }
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
    if (!f)
        f = fopen(PT_PASS_TMP, "r");   /* power cut between remove and rename */
    if (!f)
    {
        sdcard_io_end();
        return 0;
    }
    int count = 0, head = 0;
    char line[96];
    while (fgets(line, sizeof(line), f))
    {
        unsigned long sec = 0;
        unsigned ln = 0, ku = 0, zi = 0, dur = 0;
        int dev = 0;
        if (sscanf(line, "%lu,%u,%u,%u,%d,%u", &sec, &ln, &ku, &zi, &dev, &dur) != 6)
            continue;
        pt_pass_t r = { (uint32_t)sec, (uint16_t)ln, (uint16_t)zi,
                        (uint8_t)ku, (int8_t)dev, (uint16_t)dur };
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
    uint32_t gen = s_gen;
    int n = ptlog_snapshot(snap);
    if (n <= 0)
        return false;
    if (!sdcard_io_begin_timeout(2000))
        return false;

    mkdir(PT_DIR, 0777);
    FILE *f = fopen(PT_TMP, "w");
    if (!f)
    {
        sdcard_io_end();
        return false;
    }
    bool ok = true;
    for (int i = 0; i < n && ok; i++)
    {
        pt_line_t *l = &snap[i];
        if (fprintf(f, "%u,%lu,%ld,%lu,%lu,%u,%d,%d,%lu,%lu\n",
                    l->line, (unsigned long)l->sightings, (long)l->dev_sum,
                    (unsigned long)l->dev_count, (unsigned long)l->dev_zero,
                    l->saturated, l->worst_late, l->worst_early,
                    (unsigned long)l->first_seen, (unsigned long)l->last_seen) < 0)
            ok = false;
    }
    if (fclose(f) != 0)
        ok = false;
    if (ok && gen != s_gen)
    {
        remove(PT_TMP);     /* cleared meanwhile -- don't resurrect */
        ok = false;
    }
    else if (ok && sdcard_read_active() != 0)
    {
        /* The swap unlinks transit.csv, which a streaming download holds
         * open. Never force it: keep the live file, s_dirty retries later. */
        ok = false;
    }
    else if (ok)
    {
        remove(PT_CSV);
        rename(PT_TMP, PT_CSV);
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

    /* A passage that went quiet is over -- fold it so it shows up even when
     * no other vehicle follows. */
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
    {
        s_loaded = pt_load();   /* retried until it really succeeded */
        return;
    }
    pass_flush();
    if (++ticks < PT_SAVE_TICKS || !s_dirty)
        return;
    ticks = 0;
    if (pt_save())
        s_dirty = false;
#endif
}

/* Folds every open passage and writes out -- call before a planned restart.
 * Splitting a running passage beats losing it and the unsaved aggregates. */
void ptlog_flush_now(void)
{
#if CONFIG_ENABLE_SD
    /* Never write back a table we have not read yet -- same rule the tick
     * follows, and a restart is exactly when it would bite. */
    if (!s_lock || !s_loaded)
        return;
    /* A deferred wipe must win here: s_wipe_pending dies with the reboot that
     * follows, and writing now would put the cleared rows back on the card. */
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
    pass_flush();
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
