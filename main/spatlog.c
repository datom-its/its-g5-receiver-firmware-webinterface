#include "sdkconfig.h"

#include "spatlog.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_attr.h"
#include "esp_log.h"

static const char TAG[] = "SPATLOG";

/* The queue only has to bridge one sysmon tick. Ten groups of one intersection change at
 * most every few seconds, so 64 rows are several ticks of headroom. */
#define SPATLOG_Q 64

static spat_row_t s_q[SPATLOG_Q];
static int s_q_head, s_q_count;
static uint32_t s_dropped;
static SemaphoreHandle_t s_lock;
static volatile uint32_t s_gen;      /* a clear invalidates a batch already copied */
/* The queue-full warning comes once until the card takes rows again. Without a card, every
 * phase would write a line. */
static bool s_loss_logged;

#if CONFIG_ENABLE_SD
#include <errno.h>
#include <sys/stat.h>
#include "sd_csv.h"
#include "sd_rcache.h"
#include "sdcard.h"

#define SPAT_DIR CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define SPAT_CSV SPAT_DIR "/phases.csv"
#define SPAT_TMP SPAT_DIR "/phases.tmp"

static volatile bool s_wipe_pending;
/* Deletes in a row that failed with another error than a missing file. Module lock. */
static uint8_t s_wipe_fails;
/* The last append failed and said so: one warning per streak of failures. */
static bool s_write_warned;
/* A row is at most 41 B + NUL: '%lu,%u,%u,%u,%u,%u,%u\n' with 10+5+5+3+3+5+3 digits. Also the
 * look-back of the tail mend and the trim's line. SD lock only. */
static EXT_RAM_BSS_ATTR char s_wr[96];
/* The reader's line, httpd only and under the SD lock. */
static EXT_RAM_BSS_ATTR char s_rd[96];
/* The newest rows /traffic shows and the reader's place in phases.csv, under the SD lock: a
 * refresh reads only what was added. s_rgen counts deletes, trims and failed writes. */
#define SPAT_RC 120
static EXT_RAM_BSS_ATTR spat_row_t s_rc_rows[SPAT_RC];
static int s_rc_n, s_rc_head;
static EXT_RAM_BSS_ATTR sdrc_t s_rc;
static uint32_t s_rgen;
#endif

void spatlog_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

uint32_t spatlog_dropped(void)
{
    return s_dropped;
}

void spatlog_note(uint32_t seconds, uint16_t region, uint16_t id, uint8_t sg,
                  uint8_t phase, uint16_t dur_sec, uint8_t next)
{
    if (!s_lock)
        return;
    /* The packet path calls this and must never block. A missed row is cheaper than a stall. */
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
    {
        s_dropped++;
        return;
    }
    if (s_q_count >= SPATLOG_Q)
    {
        s_dropped++;
        if (!s_loss_logged)
            ESP_LOGW(TAG, "queue full, %lu phase rows lost so far", (unsigned long)s_dropped);
        s_loss_logged = true;
    }
    else
    {
        s_q[(s_q_head + s_q_count) % SPATLOG_Q] = (spat_row_t){
            .seconds = seconds, .region = region, .id = id, .dur_sec = dur_sec,
            .sg = sg, .phase = phase, .next = next };
        s_q_count++;
    }
    xSemaphoreGive(s_lock);
}

#if CONFIG_ENABLE_SD
/* Under the SD lock, which comes before the module lock as in the tick. remove() runs without
 * the module lock. False: no delete was due. */
static bool spat_wipe(void)
{
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return true;
    /* The flag stays set while the files go: a reader that looks meanwhile must not show them. */
    bool wipe = s_wipe_pending;
    xSemaphoreGive(s_lock);
    if (!wipe)
        return false;
    bool ok = sdcsv_wipe(SPAT_CSV, SPAT_TMP);
    int e = errno;
    s_rgen++;
    bool give_up = false;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE)
    {
        /* Three tries, then the rows show again: a card that refuses must not blind the page. */
        if (ok || ++s_wipe_fails >= 3)
        {
            give_up = !ok;
            s_wipe_fails = 0;
            s_wipe_pending = false;
        }
        xSemaphoreGive(s_lock);
    }
    if (give_up)
        ESP_LOGW(TAG, "cannot remove %s (%s), its rows stay", SPAT_CSV, strerror(e));
    return true;
}
#endif

void spatlog_clear(void)
{
    if (!s_lock)
        return;
    /* No timeout, like ptlog_clear: the page answers OK either way, and every holder is short. */
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE)
        return;
    s_q_head = s_q_count = 0;
    s_gen++;                 /* a batch copied before this must not advance the queue */
#if CONFIG_ENABLE_SD
    s_wipe_pending = true;
#endif
    xSemaphoreGive(s_lock);
#if CONFIG_ENABLE_SD
    /* At once when the card is free: a reload after the OK must not show the rows again. */
    if (sdcard_is_mounted() && sdcard_io_begin_timeout(2000))
    {
        spat_wipe();
        sdcard_io_end();
    }
#endif
}

#if CONFIG_ENABLE_SD

void spatlog_tick(void)
{
    static spat_row_t batch[SPATLOG_Q];
    if (!s_lock)
        return;
    /* A look first: an idle tick every 5 s must not take the card from the other writers. */
    bool mounted = sdcard_is_mounted();
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return;
    /* sdcard.h counts no mounts: an old delete must not reach a card put in later. */
    bool dropped = s_wipe_pending && !mounted;
    if (dropped)
    {
        s_wipe_pending = false;
        s_wipe_fails = 0;
    }
    bool idle = !s_q_count && !s_wipe_pending;
    xSemaphoreGive(s_lock);
    if (dropped)
        ESP_LOGW(TAG, "no card, the delete of %s is dropped", SPAT_CSV);
    if (idle || !mounted)
        return;
    /* SD lock before the copy, held to the advance: the sysmon tick and the restart flush both
     * call this. A clear in between only empties the queue, and s_gen keeps the advance off. */
    if (!sdcard_io_begin_timeout(2000))
        return;
    /* The delete first, and nothing written in this tick. */
    if (spat_wipe())
    {
        sdcard_io_end();
        return;
    }
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
    {
        sdcard_io_end();
        return;
    }
    uint32_t gen = s_gen;
    int count = s_q_count;
    for (int i = 0; i < count; i++)
        batch[i] = s_q[(s_q_head + i) % SPATLOG_Q];
    xSemaphoreGive(s_lock);
    if (!count)
    {
        sdcard_io_end();
        return;
    }

    mkdir(SPAT_DIR, 0777);
    const char *fail = "tmp rename";
    sdcsv_rc_t rc = sdcsv_recover_tmp(SPAT_CSV, SPAT_TMP);
    FILE *f = NULL;
    if (rc == SDCSV_OK)
    {
        f = fopen(SPAT_CSV, "a+");
        fail = f ? "mend" : "open";
        rc = f ? sdcsv_mend_tail(f, s_wr, sizeof(s_wr)) : SDCSV_FAIL;
    }
    /* Rows that left the batch: on the card, or lost as wider than s_wr. */
    int written = 0;
    for (int i = 0; i < count && rc == SDCSV_OK; i++)
    {
        const spat_row_t *b = &batch[i];
        int n = snprintf(s_wr, sizeof(s_wr), "%lu,%u,%u,%u,%u,%u,%u\n",
                         (unsigned long)b->seconds, b->region, b->id,
                         b->sg, b->phase, b->dur_sec, b->next);
        if (n < 0 || (size_t)n >= sizeof(s_wr))
        {
            /* Only an s_wr too small for the row format gets here. The row counts as written,
             * or it would block the queue. */
            ESP_LOGE(TAG, "phase row wider than %u B, lost", (unsigned)sizeof(s_wr));
            written++;
            continue;
        }
        if (!sdcsv_put(f, s_wr))
        {
            rc = SDCSV_FAIL;
            fail = "write";
            break;
        }
        written++;
    }
    /* The commit point: FatFs may not have the rows without it, so every one stays queued. */
    if (f && fclose(f) != 0)
    {
        if (rc != SDCSV_FAIL)
            fail = "close";
        rc = SDCSV_FAIL;
        written = 0;
    }
    /* Waiting for a download is no failure and ends no streak. A failed write may have hit the
     * sector before the reader's place: the next read starts at 0. */
    if (rc == SDCSV_FAIL)
        s_rgen++;
    if (rc == SDCSV_FAIL && !s_write_warned)
        ESP_LOGW(TAG, "%s: %s failed, %d rows stay queued", SPAT_CSV, fail, count - written);
    if (rc != SDCSV_WAIT)
        s_write_warned = rc == SDCSV_FAIL;

    /* Advance only what landed, and only when no clear came in between. A row written twice
     * would count a phase twice, so no timeout: the rows are on the card already. */
    if (written > 0 && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE)
    {
        if (s_gen == gen)
        {
            s_q_head = (s_q_head + written) % SPATLOG_Q;
            s_q_count -= written;
        }
        s_loss_logged = false;
        xSemaphoreGive(s_lock);
    }

    /* Trim on every 64th append, and only after a whole append: a card that just failed is not
     * rewritten. */
    static uint32_t s_appends;
    if (rc == SDCSV_OK && ++s_appends % 64 == 1)
    {
        if (sdcard_read_active() != 0)
            s_appends--;           /* a download holds the file open: retry next time */
        else
        {
            sdcsv_keep_newest(SPAT_CSV, SPAT_TMP, SPATLOG_KEEP, s_wr, sizeof(s_wr));
            s_rgen++;
        }
    }
    sdcard_io_end();
}

static void reverse(spat_row_t *a, int i, int j)
{
    while (i < j)
    {
        spat_row_t t = a[i];
        a[i++] = a[j];
        a[j--] = t;
    }
}

int spatlog_read(spat_row_t *out, int max)
{
    if (!out || max <= 0)
        return 0;
    /* A delete that waits for the card must not show the rows it will remove. */
    if (s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE)
    {
        bool pending = s_wipe_pending;
        xSemaphoreGive(s_lock);
        if (pending)
            return 0;
    }
    if (!sdcard_io_begin_timeout(2000))
        return 0;
    /* The cache holds the newest SPAT_RC rows. A longer list reads the whole file into out[]. */
    bool cached = max <= SPAT_RC;
    FILE *f = cached ? sdrc_open(&s_rc, SPAT_CSV, s_rgen, true) : fopen(SPAT_CSV, "r");
    /* Only a missing csv is the power cut between the trim's remove and rename. */
    if (!f && errno == ENOENT)
    {
        f = fopen(SPAT_TMP, "r");
        cached = false;
    }
    if (!f)
    {
        sdcard_io_end();
        return 0;
    }
    bool tail = cached && s_rc.tail;
    spat_row_t *ring = cached ? s_rc_rows : out;
    int lcount = 0, lhead = 0;
    int *count = cached ? &s_rc_n : &lcount, *head = cached ? &s_rc_head : &lhead;
    int cap = cached ? SPAT_RC : max;
    if (!tail)
        *count = *head = 0;
    bool rest = false, whole;
    while (sdcsv_gets(s_rd, sizeof(s_rd), f, &rest, &whole))
    {
        /* picolibc's fgets hands back the part before a read error: the rows before it stay. */
        if (ferror(f))
            break;
        if (cached)
            sdrc_piece(&s_rc, f, s_rd, sizeof(s_rd));
        if (!whole)
            continue;
        unsigned long sec = 0;
        unsigned reg = 0, id = 0, sg = 0, ph = 0, dur = 0, nx = 0;
        int n = 0;
        /* Exactly 7 fields and a time of at most 10 digits: a row glued onto a cut one has more
         * fields, or, with a synced clock, more digits if cut in the time. */
        if (strspn(s_rd, "0123456789") > 10 ||
            sscanf(s_rd, "%lu,%u,%u,%u,%u,%u,%u%n", &sec, &reg, &id, &sg, &ph, &dur, &nx, &n) < 7 ||
            s_rd[n] != '\n')
            continue;
        spat_row_t r = { .seconds = (uint32_t)sec, .region = (uint16_t)reg,
                         .id = (uint16_t)id, .dur_sec = (uint16_t)dur,
                         .sg = (uint8_t)sg, .phase = (uint8_t)ph, .next = (uint8_t)nx };
        if (*count < cap)
            ring[(*count)++] = r;
        else
        {
            ring[*head] = r;        /* ring: the file can exceed SPATLOG_KEEP between trims */
            *head = (*head + 1) % cap;
        }
    }
    if (cached)
        sdrc_done(&s_rc, f, !ferror(f));
    fclose(f);
    sdcard_io_end();

    if (!cached)
    {
        if (lcount == max && lhead > 0)
        {
            reverse(out, 0, lhead - 1);
            reverse(out, lhead, lcount - 1);
        }
        else
            reverse(out, 0, lcount - 1);
        return lcount;
    }
    /* Newest first, the newest `max` of the cache: the same rows a ring of `max` would keep. */
    int k = s_rc_n < max ? s_rc_n : max;
    for (int i = 0; i < k; i++)
        out[i] = s_rc_rows[(s_rc_head + s_rc_n - 1 - i) % SPAT_RC];
    return k;
}

#else  /* !CONFIG_ENABLE_SD */

void spatlog_tick(void) { }

int spatlog_read(spat_row_t *out, int max)
{
    (void)out;
    (void)max;
    return 0;
}

#endif
