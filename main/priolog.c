#include "sdkconfig.h"

#include "priolog.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_attr.h"
#include "esp_log.h"

/* Outside the #if, like ptlog's: the queue and the drop counter exist in every
 * configuration, only the file does not. */
static const char TAG[] = "PRIOLOG";

/* Rows waiting for the tick. One SREM can add three at once (MSG_PRIO_ITEMS), and the
 * light answers every request, so this holds a few seconds of a busy intersection. */
#define PRIO_Q 32

static prio_row_t s_q[PRIO_Q];
static int s_q_head, s_q_count;
static uint32_t s_dropped;
static SemaphoreHandle_t s_lock;
static volatile uint32_t s_gen;      /* a clear invalidates a batch already copied */
/* The queue-full warning comes once until the card takes rows again. Without a card, every
 * request would write a line. */
static bool s_loss_logged;

#if CONFIG_ENABLE_SD
#include <errno.h>
#include <sys/stat.h>
#include "sd_csv.h"
#include "sd_rcache.h"
#include "sdcard.h"

#define PRIO_DIR CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define PRIO_CSV PRIO_DIR "/priority.csv"
#define PRIO_TMP PRIO_DIR "/priority.tmp"

static volatile bool s_wipe_pending;
/* Deletes in a row that failed with another error than a missing file. Module lock. */
static uint8_t s_wipe_fails;
/* The last append failed and said so: one warning per streak of failures. */
static bool s_write_warned;
/* A row is at most 120 B + NUL: 13 numbers at their widest (kind 9/10), name 23, route 15,
 * 14 commas and '\n'. Also the look-back of the tail mend and the trim's line. SD lock only. */
static EXT_RAM_BSS_ATTR char s_wr[160];
/* The reader's line, httpd only and under the SD lock. */
static EXT_RAM_BSS_ATTR char s_rd[160];
/* The newest rows /traffic shows and the reader's place in priority.csv, under the SD lock: a
 * refresh reads only what was added. s_rgen counts deletes, trims and failed writes. */
#define PRIO_RC 120
static EXT_RAM_BSS_ATTR prio_row_t s_rc_rows[PRIO_RC];
static int s_rc_n, s_rc_head;
static EXT_RAM_BSS_ATTR sdrc_t s_rc;
static uint32_t s_rgen;
#endif

void priolog_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

uint32_t priolog_dropped(void)
{
    return s_dropped;
}

/* Free text from the air goes into a CSV column: a comma or a newline would move every
 * following field. The decoder already replaced control characters with '?'. */
static void copy_field(char *out, size_t cap, const char *in)
{
    size_t o = 0;
    for (size_t i = 0; in[i] && o + 1 < cap; i++)
        out[o++] = (in[i] == ',' || in[i] == '\n' || in[i] == '\r') ? ' ' : in[i];
    out[o] = '\0';
}

/* Called under the lock. */
static void push_locked(const prio_row_t *r)
{
    if (s_q_count >= PRIO_Q)
    {
        /* Only the single row is lost. Logged once per streak, so a card that cannot keep up
         * is visible in the log and not just in a counter. */
        s_dropped++;
        if (!s_loss_logged)
            ESP_LOGW(TAG, "queue full, %lu request rows lost so far",
                     (unsigned long)s_dropped);
        s_loss_logged = true;
        return;
    }
    s_q[(s_q_head + s_q_count) % PRIO_Q] = *r;
    s_q_count++;
}

void priolog_note(uint32_t seconds, uint32_t station_id, const msg_prio_t *p)
{
    if (!s_lock || !p || (p->message_id != 9 && p->message_id != 10) || !p->n_items)
        return;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE)
    {
        s_dropped++;
        return;
    }
    for (uint8_t i = 0; i < p->n_items && i < MSG_PRIO_ITEMS; i++)
    {
        const msg_prio_item_t *it = &p->item[i];
        prio_row_t r = {
            .seconds = seconds,
            .station_id = station_id,
            /* An SREM names its requester in the message, an SSEM per answer. */
            .requester_id = p->message_id == 9 ? p->requestor_id : it->requester_id,
            .region = it->has_region ? it->region : 0,
            .id = it->id,
            .kind = p->message_id,
            .request_id = it->request_id,
            .code = it->code,
            .role = p->has_role ? p->role : PRIO_NO_ROLE,
            .in_kind = it->in.kind,
            .out_kind = it->out.kind,
            .in_val = it->in.value,
            .out_val = it->out.value,
        };
        copy_field(r.name, sizeof(r.name), p->name);
        copy_field(r.route, sizeof(r.route), p->route);
        push_locked(&r);
    }
    xSemaphoreGive(s_lock);
}

#if CONFIG_ENABLE_SD
/* Under the SD lock, which comes before the module lock as in the tick. remove() runs without
 * the module lock, or the receive path would wait for the card. False: no delete was due. */
static bool prio_wipe(void)
{
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return true;
    /* The flag stays set while the files go: a reader that looks meanwhile must not show them. */
    bool wipe = s_wipe_pending;
    xSemaphoreGive(s_lock);
    if (!wipe)
        return false;
    bool ok = sdcsv_wipe(PRIO_CSV, PRIO_TMP);
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
        ESP_LOGW(TAG, "cannot remove %s (%s), its rows stay", PRIO_CSV, strerror(e));
    return true;
}
#endif

void priolog_clear(void)
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
        prio_wipe();
        sdcard_io_end();
    }
#endif
}

#if CONFIG_ENABLE_SD

void priolog_tick(void)
{
    /* Static, not on the 4096-byte sysmon stack. Only used while the SD lock is held. */
    static prio_row_t batch[PRIO_Q];
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
        ESP_LOGW(TAG, "no card, the delete of %s is dropped", PRIO_CSV);
    if (idle || !mounted)
        return;
    /* SD lock before the copy, held to the advance: the sysmon tick and the restart flush both
     * call this. A clear in between only empties the queue, and s_gen keeps the advance off. */
    if (!sdcard_io_begin_timeout(2000))
        return;
    /* The delete first, and nothing written in this tick. */
    if (prio_wipe())
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
        batch[i] = s_q[(s_q_head + i) % PRIO_Q];
    xSemaphoreGive(s_lock);
    if (!count)
    {
        sdcard_io_end();
        return;
    }

    mkdir(PRIO_DIR, 0777);
    const char *fail = "tmp rename";
    sdcsv_rc_t rc = sdcsv_recover_tmp(PRIO_CSV, PRIO_TMP);
    FILE *f = NULL;
    if (rc == SDCSV_OK)
    {
        f = fopen(PRIO_CSV, "a+");
        fail = f ? "mend" : "open";
        rc = f ? sdcsv_mend_tail(f, s_wr, sizeof(s_wr)) : SDCSV_FAIL;
    }
    /* Rows that left the batch: on the card, or lost as wider than s_wr. */
    int written = 0;
    for (int i = 0; i < count && rc == SDCSV_OK; i++)
    {
        const prio_row_t *b = &batch[i];
        int n = snprintf(s_wr, sizeof(s_wr), "%lu,%u,%lu,%u,%u,%u,%u,%u,%lu,%u,%u,%u,%u,%s,%s\n",
                         (unsigned long)b->seconds, b->kind, (unsigned long)b->station_id,
                         b->region, b->id, b->request_id, b->code, b->role,
                         (unsigned long)b->requester_id, b->in_kind, b->in_val, b->out_kind,
                         b->out_val, b->name, b->route);
        if (n < 0 || (size_t)n >= sizeof(s_wr))
        {
            /* Only an s_wr too small for the row format gets here. The row counts as written,
             * or it would block the queue. */
            ESP_LOGE(TAG, "request row wider than %u B, lost", (unsigned)sizeof(s_wr));
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
        ESP_LOGW(TAG, "%s: %s failed, %d rows stay queued", PRIO_CSV, fail, count - written);
    if (rc != SDCSV_WAIT)
        s_write_warned = rc == SDCSV_FAIL;

    /* Advance only what landed, and only when no clear came in between. No timeout: the rows
     * are on the card already, and a skipped advance would write them twice. */
    if (written > 0 && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE)
    {
        if (s_gen == gen)
        {
            s_q_head = (s_q_head + written) % PRIO_Q;
            s_q_count -= written;
        }
        s_loss_logged = false;
        xSemaphoreGive(s_lock);
    }

    /* Trim on every 64th append, like the passage log, and only after a whole append: a card that
     * just failed is not rewritten. A trim unlinks the file, so it is put off while a streaming
     * download holds the file open. */
    static uint32_t s_appends;
    if (rc == SDCSV_OK && ++s_appends % 64 == 1)
    {
        if (sdcard_read_active() != 0)
            s_appends--;
        else
        {
            sdcsv_keep_newest(PRIO_CSV, PRIO_TMP, PRIO_KEEP, s_wr, sizeof(s_wr));
            s_rgen++;
        }
    }
    sdcard_io_end();
}

static void reverse(prio_row_t *a, int i, int j)
{
    while (i < j)
    {
        prio_row_t t = a[i];
        a[i++] = a[j];
        a[j--] = t;
    }
}

/* One text column: from after its ',' up to the next ',' or the row end, cut to `cap`. */
static const char *take_text(const char *p, char *out, size_t cap)
{
    size_t len = 0;
    if (*p == ',')
        len = strcspn(++p, ",\n");
    size_t k = len < cap - 1 ? len : cap - 1;
    memcpy(out, p, k);
    out[k] = '\0';
    return p + len;
}

int priolog_read(prio_row_t *out, int max)
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
    /* The cache holds the newest PRIO_RC rows. A longer list reads the whole file into out[]. */
    bool cached = max <= PRIO_RC;
    FILE *f = cached ? sdrc_open(&s_rc, PRIO_CSV, s_rgen, true) : fopen(PRIO_CSV, "r");
    /* Only a missing csv is the power cut between the trim's remove and rename. */
    if (!f && errno == ENOENT)
    {
        f = fopen(PRIO_TMP, "r");
        cached = false;
    }
    if (!f)
    {
        sdcard_io_end();
        return 0;
    }
    bool tail = cached && s_rc.tail;
    prio_row_t *ring = cached ? s_rc_rows : out;
    int lcount = 0, lhead = 0;
    int *count = cached ? &s_rc_n : &lcount, *head = cached ? &s_rc_head : &lhead;
    int cap = cached ? PRIO_RC : max;
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
        unsigned long sec = 0, sid = 0, rid = 0;
        unsigned kind = 0, reg = 0, id = 0, req = 0, code = 0, role = 0;
        unsigned ik = 0, iv = 0, ok2 = 0, ov = 0;
        int n = 0;
        int got = sscanf(s_rd, "%lu,%u,%lu,%u,%u,%u,%u,%u,%lu,%u,%u,%u,%u%n",
                         &sec, &kind, &sid, &reg, &id, &req, &code, &role, &rid,
                         &ik, &iv, &ok2, &ov, &n);
        /* Rows need a time of at most 10 digits and a ',' before name and route. With a synced
         * clock, a row cut in its time and glued to the next has more digits. Every writer wrote
         * both texts. */
        if (got < 13 || n == 0 || (kind != 9 && kind != 10) || strspn(s_rd, "0123456789") > 10 ||
            s_rd[n] != ',' || !strchr(s_rd + n + 1, ','))
            continue;
        prio_row_t r = { .seconds = (uint32_t)sec, .station_id = (uint32_t)sid,
                         .requester_id = (uint32_t)rid, .region = (uint16_t)reg,
                         .id = (uint16_t)id, .kind = (uint8_t)kind,
                         .request_id = (uint8_t)req, .code = (uint8_t)code,
                         .role = (uint8_t)role, .in_kind = (uint8_t)ik,
                         .out_kind = (uint8_t)ok2, .in_val = (uint16_t)iv,
                         .out_val = (uint16_t)ov };
        /* Parsed by hand, because a scanset needs at least one character: an empty name would
         * end the scan there and lose the route. Exactly 15 fields: a row glued onto a cut one
         * has more. */
        char name[ITS_SREM_NAME_LEN], route[ITS_SREM_ROUTE_LEN];
        if (*take_text(take_text(s_rd + n, name, sizeof(name)), route, sizeof(route)) != '\n')
            continue;
        copy_field(r.name, sizeof(r.name), name);
        copy_field(r.route, sizeof(r.route), route);
        if (*count < cap)
            ring[(*count)++] = r;
        else
        {
            /* Ring, not a shift per row: between trims the file can grow far past PRIO_KEEP
             * rows. Same as ptlog_read_passages. */
            ring[*head] = r;
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
        out[i] = s_rc_rows[(s_rc_head + s_rc_n - 1 - i) % PRIO_RC];
    return k;
}

#else  /* !CONFIG_ENABLE_SD */

void priolog_tick(void) { }

int priolog_read(prio_row_t *out, int max)
{
    (void)out;
    (void)max;
    return 0;
}

#endif
