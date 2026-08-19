#include "sdkconfig.h"

#include "sdpcap.h"

#if CONFIG_ENABLE_SD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_heap_caps.h"

#include "pcap.h"

#include "config.h"
#include "events.h"
#include "its_decode.h"
#include "sdcard.h"

static const char TAG[] = "SDPCAP";

#define PCAP_DIR CONFIG_SNIFFER_MOUNT_POINT "/pcap"

/* Finer than the minimum flush interval so size/time/boundary checks fire
 * promptly; a tick is a few compares, SD is touched only when one trips. */
#define TASK_POLL_MS       1000
#define PRUNE_INTERVAL_MS  60000  /* retention sweep cadence, independent of flush cadence */

#define PCAP_BUF_MB_MIN    1
#define PCAP_BUF_MB_MAX    4
/* Long enough to outlast a normal in-flight flush, short enough that a wedged
 * writer cannot stall a restart. */
#define SDPCAP_FLUSH_LOCK_MS 3000
/* Per hourly file, and effectively the walk's whole budget: first timeout ends
 * it. Below the writer's worst hold on purpose -- callers report PARTIAL. */
#define SDPCAP_WALK_LOCK_MS 10000

#define PCAP_FLUSH_SEC_MIN 8
#define PCAP_FLUSH_SEC_MAX 3600

#define PCAP_MAX_FRAME 2048  /* generous max realistic 802.11 frame size */

/* Mirrors what the vendored espressif__pcap library writes; records are built
 * here directly for the bulk ring flush, so both layouts must stay in sync. */
typedef struct { uint32_t magic; uint16_t vmaj, vmin; int32_t tz; uint32_t sig, snap, net; } pcap_global_hdr_t;
typedef struct { uint32_t sec, usec, caplen, len; } pcap_rec_hdr_t;

/* ================================================================== */
/*  PSRAM ring buffer                                                  */
/* ================================================================== */

/* Ring of formatted pcap records, flushed in bulk -- few large SD writes instead
 * of many small ones on the bus shared with Ethernet. */
typedef struct {
    uint8_t *buf;
    size_t   size;
    size_t   head;    /* write index */
    size_t   tail;    /* read index  */
    size_t   used;
    SemaphoreHandle_t lock;
    uint32_t gen;   /* bumped by ring_clear; see ring_discard */
} pcap_ring_t;

static pcap_ring_t s_ring;

static bool ring_init(pcap_ring_t *r, size_t size)
{
    r->buf = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (!r->buf)
        return false;
    r->size = size;
    r->head = r->tail = r->used = 0;
    r->lock = xSemaphoreCreateMutex();
    return r->lock != NULL;
}

/* Drops the whole record (never a partial write) if it doesn't fit or the lock
 * is contended past `wait` -- a torn record is undetectable to the reader. */
static bool ring_append(pcap_ring_t *r, const void *data, size_t len, TickType_t wait)
{
    if (len == 0 || len > r->size)
        return false;
    if (xSemaphoreTake(r->lock, wait) != pdTRUE)
        return false;
    if (len > r->size - r->used)
    {
        xSemaphoreGive(r->lock);
        return false;
    }
    size_t first = r->size - r->head;
    if (first > len) first = len;
    memcpy(r->buf + r->head, data, first);
    if (len > first)
        memcpy(r->buf, (const uint8_t *)data + first, len - first);
    r->head = (r->head + len) % r->size;
    r->used += len;
    xSemaphoreGive(r->lock);
    return true;
}

/* Copies out up to max bytes WITHOUT consuming them; split from the consume
 * step so a failed write leaves the data in the ring for the next attempt. */
static size_t ring_peek(pcap_ring_t *r, uint8_t *out, size_t max, uint32_t *gen)
{
    if (xSemaphoreTake(r->lock, portMAX_DELAY) != pdTRUE)
        return 0;
    if (gen)
        *gen = r->gen;
    size_t n = r->used < max ? r->used : max;
    size_t first = r->size - r->tail;
    if (first > n) first = n;
    memcpy(out, r->buf + r->tail, first);
    if (n > first)
        memcpy(out + first, r->buf, n - first);
    xSemaphoreGive(r->lock);
    return n;
}

/* Drops the n bytes a successful write took. ring_clear() runs OUTSIDE the SD
 * lock, so the generation -- not the lock -- is what makes this safe. */
static void ring_discard(pcap_ring_t *r, size_t n, uint32_t gen)
{
    if (n == 0 || xSemaphoreTake(r->lock, portMAX_DELAY) != pdTRUE)
        return;
    /* Cleared since the peek? Then these bytes are already gone; subtracting
     * them would wrap `used` and leave the ring permanently "full". */
    if (r->gen == gen && n <= r->used)
    {
        r->tail = (r->tail + n) % r->size;
        r->used -= n;
    }
    xSemaphoreGive(r->lock);
}

/* Unlocked; a size-threshold heuristic only, so a stale read just means the
 * flush fires one poll tick early or late. */
static size_t ring_used(const pcap_ring_t *r)
{
    return r->used;
}

/* Bumps the generation so a discard from a peek taken before the clear does
 * nothing -- otherwise `used -= n` underflows and the ring reads as always full. */
static void ring_clear(pcap_ring_t *r)
{
    if (xSemaphoreTake(r->lock, portMAX_DELAY) != pdTRUE)
        return;
    r->head = r->tail = r->used = 0;
    r->gen++;
    xSemaphoreGive(r->lock);
}

/* ================================================================== */
/*  Config                                                             */
/* ================================================================== */

static volatile bool s_ready;
static volatile bool cfg_enabled;
static volatile uint32_t cfg_retain_hours;
/* Hour bucket the buffered data belongs to (0 = not established yet). File scope
 * so flush_now writes the same file as the writer task; the clock would not. */
static volatile time_t s_ring_bucket;
/* Bytes owed to the PREVIOUS hour's file -- the oldest in the ring, which drains
 * from the tail. SD lock guards it; the disable branch only ever zeroes it. */
static volatile size_t s_stale_left;

/* Steps ONE hour at a time, not straight to `now`: what is still in the ring was
 * captured just after the boundary, so it belongs to the next hour, not later. */
static void bucket_advance(time_t now_bucket)
{
    /* 0 is the "not established" sentinel, not a steppable hour -- otherwise the
     * one-hour-per-tick rule would crawl up from 1970 after every enable. */
    if (s_ring_bucket == 0 || ring_used(&s_ring) == 0 ||
        now_bucket <= s_ring_bucket + 3600)
        s_ring_bucket = now_bucket;
    else
        s_ring_bucket += 3600;
}
static volatile uint32_t cfg_max_mb;
static volatile uint32_t cfg_flush_sec;
static volatile uint8_t  cfg_filter;
static uint32_t s_dropped;
/* Running average of one ring record; the boundary-drop path turns lost bytes
 * back into a frame count. volatile: written and read from different tasks. */
static volatile uint32_t s_avg_rec = 300;

/* Buffer size itself is read once at boot in sdpcap_init, not here --
 * the PSRAM block backing it is allocated exactly once. */
static void reload_config(void)
{
    uint8_t en = 0, filt = 0;
    uint32_t hours = 24, mb = 300, flush_sec = 300;
    config_get_u8(CONFIG_INDEX_PCAP_ENABLE, &en);
    config_get_u8(CONFIG_INDEX_PCAP_FILTER, &filt);
    config_get_u32(CONFIG_INDEX_PCAP_RETAIN_HOURS, &hours);
    config_get_u32(CONFIG_INDEX_PCAP_MAX_MB, &mb);
    config_get_u32(CONFIG_INDEX_PCAP_FLUSH_SEC, &flush_sec);
    if (flush_sec < PCAP_FLUSH_SEC_MIN) flush_sec = PCAP_FLUSH_SEC_MIN;
    if (flush_sec > PCAP_FLUSH_SEC_MAX) flush_sec = PCAP_FLUSH_SEC_MAX;
    cfg_enabled = en;
    cfg_retain_hours = hours;
    cfg_max_mb = mb;
    cfg_flush_sec = flush_sec;
    cfg_filter = filt;
}

static void config_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg; (void)base; (void)data;
    if (id == CONFIG_INDEX_PCAP_ENABLE || id == CONFIG_INDEX_PCAP_RETAIN_HOURS ||
        id == CONFIG_INDEX_PCAP_MAX_MB || id == CONFIG_INDEX_PCAP_FLUSH_SEC ||
        id == CONFIG_INDEX_PCAP_FILTER)
        reload_config();
}

/* Thinning filter: repetitive infrastructure messages dominate the recording.
 * 0 = keep all, 1 = infra chatter to 1/s per type, 2 = vehicles+warnings only. */
static uint32_t s_filtered;
static uint32_t s_last_kept[256];   /* last second kept, per messageId */

static bool pcap_keep_frame(const uint8_t *frame, size_t len, uint32_t sec)
{
    /* Cached value, never NVS: this runs on the receive path for every frame. */
    uint8_t mode = cfg_filter;
    if (mode == 0)
        return true;

    uint8_t mid = its_peek_message_id(frame, len);
    /* Only SPATEM (4) and MAPEM (5) are the repetitive infrastructure ones; the
     * filter names what it drops, so unknown types are kept, never lost. */
    bool infra = (mid == 4 || mid == 5);
    if (!infra)
        return true;
    if (mode == 2)
        return false;

    if (s_last_kept[mid] == sec)
        return false;
    s_last_kept[mid] = sec;
    return true;
}

/* Sniffer hot path: never block, never malloc. Assembly buffer is static -- the
 * 4 KB sniffer stack can't afford ~2 KB locals; single sequential caller. */
void sdpcap_handle_packet(sniffer_packet_info_t *packet)
{
    if (!s_ready || !cfg_enabled || !packet)
        return;
    if (packet->length > PCAP_MAX_FRAME)
    {
        s_dropped++;
        return;
    }

    /* Timestamp comes from the sniffer callback: this runs after the queue, so
     * asking the clock here would stamp the dequeue, not the reception. */
    if (!pcap_keep_frame(packet->payload, packet->length, packet->seconds))
    {
        s_filtered++;
        return;
    }

    static EXT_RAM_BSS_ATTR uint8_t rec[sizeof(pcap_rec_hdr_t) + PCAP_MAX_FRAME];
    pcap_rec_hdr_t hdr = {
        .sec = packet->seconds,
        .usec = packet->microseconds,
        .caplen = packet->length,
        .len = packet->length,
    };
    memcpy(rec, &hdr, sizeof(hdr));
    memcpy(rec + sizeof(hdr), packet->payload, packet->length);

    size_t reclen = sizeof(hdr) + packet->length;
    /* Sliding average (1/16), so it tracks the traffic mix without a counter
     * that could overflow over weeks of uptime. */
    s_avg_rec = (s_avg_rec * 15u + (uint32_t)reclen) / 16u;
    if (!ring_append(&s_ring, rec, reclen, 0))
        s_dropped++;
}

/* ================================================================== */
/*  Writer task                                                       */
/* ================================================================== */

/* Local-time name so a human can find "the file from around 5pm". Do NOT switch
 * to UTC: it would orphan every file already on the card (DST clash accepted). */
static void sdpcap_current_path(char *out, size_t out_size, time_t now)
{
    time_t bucket = now - (now % 3600);
    struct tm tm_local;
    localtime_r(&bucket, &tm_local);
    char name[32];
    strftime(name, sizeof(name), "pcap-%Y%m%d-%H%M%S.pcap", &tm_local);
    snprintf(out, out_size, "%s/%s", PCAP_DIR, name);
}

/* Does this look like a real record header for a file covering `hour`? The
 * timestamp test is what makes resync reliable: garbage rarely fits the hour. */
static bool pcap_rec_plausible(const pcap_rec_hdr_t *rh, uint32_t hour, size_t maxcap)
{
    /* +5 s slack past the hour: records are stamped at enqueue and flushed in
     * batches, so an hour's last records legitimately sit past the boundary. */
    return rh->caplen >= 24 && rh->caplen <= maxcap &&
           rh->len >= rh->caplen && rh->len <= maxcap &&
           rh->usec < 1000000u &&
           rh->sec >= hour && rh->sec < hour + 3605u;
}

/* Resync scans in-memory 2 KB chunks; per-byte fseek+fread thrashed the card. */
#define PCAP_RESYNC_MAX 262144   /* 256 KB of garbage before giving up */

static bool pcap_resync(FILE *f, pcap_rec_hdr_t *rh, uint32_t hour, size_t maxcap)
{
    long pos = ftell(f);
    if (pos < 0)
        return false;
    pos -= (long)sizeof(*rh);   /* back to the header that failed */

    /* Static: runs on the httpd task, whose stack cannot spare 2 KB. A second
     * concurrent request would merely rescan, so sharing it is harmless. */
    static uint8_t chunk[2048 + sizeof(pcap_rec_hdr_t)];

    long scanned = 0;
    while (scanned < PCAP_RESYNC_MAX)
    {
        /* Overlap by header size so a header straddling two chunks is seen. */
        if (fseek(f, pos + 1 + scanned, SEEK_SET) != 0)
            return false;
        size_t got = fread(chunk, 1, sizeof(chunk), f);
        if (got < sizeof(*rh))
            return false;       /* end of file: nothing plausible left */
        for (size_t i = 0; i + sizeof(*rh) <= got; i++)
        {
            memcpy(rh, chunk + i, sizeof(*rh));
            if (pcap_rec_plausible(rh, hour, maxcap))
            {
                if (fseek(f, pos + 1 + scanned + (long)i + (long)sizeof(*rh),
                          SEEK_SET) != 0)
                    return false;
                return true;
            }
        }
        scanned += (long)(got - sizeof(*rh) + 1);
    }
    return false;
}

/* Shared walk behind both public readers: exactly one of pos_cb/frame_cb is
 * set (frame_cb sees every frame, pos_cb only those with a position). */
static bool sdpcap_walk(uint32_t from_sec, uint32_t to_sec,
                        sdpcap_position_cb_t pos_cb, sdpcap_frame_cb_t frame_cb,
                        void *ctx)
{
    if (!pos_cb && !frame_cb)
        return false;

    bool aborted = false;
    time_t bucket = (time_t)from_sec - ((time_t)from_sec % 3600);
    for (; bucket <= (time_t)to_sec && !aborted; bucket += 3600)
    {
        /* Writer lock held per hour file, not across the whole walk: keeping the
         * writers out for a long range would overflow the ring. */
        /* Giving a mutex does not preempt for a LOWER-priority waiter -- without
         * this yield the httpd walk re-takes the lock before the writer runs. */
        vTaskDelay(1);
        if (!sdcard_io_begin_timeout(SDPCAP_WALK_LOCK_MS))
            return false;   /* couldn't read the rest -- caller must not claim it did */
        /* One hourly file can be hundreds of MB; reading it is slow BY DESIGN
         * and must not look like a wedged writer to the stall watchdog. */
        sdcard_io_long_begin();

        char path[96];
        sdpcap_current_path(path, sizeof(path), bucket);

        FILE *f = fopen(path, "rb");
        if (!f)
        {
            sdcard_io_long_end();
            sdcard_io_end();
            continue;  /* no capture stored for this hour -- fine, just skip it */
        }

        pcap_global_hdr_t gh;
        if (fread(&gh, sizeof(gh), 1, f) != 1 || gh.magic != 0xa1b2c3d4)
        {
            fclose(f);
            sdcard_io_long_end();
            sdcard_io_end();
            continue;
        }

        static EXT_RAM_BSS_ATTR uint8_t buf[PCAP_MAX_FRAME];
        pcap_rec_hdr_t rh;
        while (fread(&rh, sizeof(rh), 1, f) == 1)
        {
            /* A torn write desynchronises the framing; resync forward instead of
             * discarding the rest of the hour. */
            if (!pcap_rec_plausible(&rh, (uint32_t)bucket, sizeof(buf)))
            {
                if (!pcap_resync(f, &rh, (uint32_t)bucket, sizeof(buf)))
                    break;  /* nothing plausible left in this file */
            }
            if (fread(buf, 1, rh.caplen, f) != rh.caplen)
                break;
            if (rh.sec < from_sec || rh.sec > to_sec)
                continue;

            its_decoded_t d;
            its_decode_frame(buf, rh.caplen, &d);
            bool keep = true;
            if (frame_cb)
                keep = frame_cb(rh.sec, rh.usec, buf, rh.caplen, &d, ctx);
            else if (d.has_position)
                keep = pos_cb(rh.sec, rh.usec, &d, ctx);
            if (!keep)
            {
                aborted = true;   /* consumer gave up (e.g. client hung up) */
                break;
            }
        }
        fclose(f);
        sdcard_io_long_end();
        sdcard_io_end();
    }
    return true;
}

uint32_t sdpcap_dropped(void)  { return s_dropped; }
uint32_t sdpcap_filtered(void) { return s_filtered; }

bool sdpcap_read_positions(uint32_t from_sec, uint32_t to_sec, sdpcap_position_cb_t cb, void *ctx)
{
    return sdpcap_walk(from_sec, to_sec, cb, NULL, ctx);
}

bool sdpcap_read_frames(uint32_t from_sec, uint32_t to_sec, sdpcap_frame_cb_t cb, void *ctx)
{
    return sdpcap_walk(from_sec, to_sec, NULL, cb, ctx);
}

/* `limit` caps the drain (0 = all), so records arriving mid-flush stay for the
 * next hour. Return = "reached the card", *consumed = "left the ring": differ. */
static bool sdpcap_flush_to(const char *path, size_t limit, size_t *consumed)
{
    if (consumed)
        *consumed = 0;
    FILE *f = fopen(path, "ab");
    if (!f)
        return false;

    struct stat st;
    bool need_header = (stat(path, &st) != 0 || st.st_size == 0);

    pcap_config_t cfg = {
        .fp = f,
        .major_version = PCAP_DEFAULT_VERSION_MAJOR,
        .minor_version = PCAP_DEFAULT_VERSION_MINOR,
        .time_zone = PCAP_DEFAULT_TIME_ZONE_GMT,
    };
    pcap_file_handle_t h;
    if (pcap_new_session(&cfg, &h) != ESP_OK)
    {
        fclose(f);  /* session was never created, so it never took ownership of f */
        return false;
    }
    if (need_header && pcap_write_header(h, PCAP_LINK_TYPE_802_11) != ESP_OK)
    {
        pcap_del_session(h);
        return false;
    }

    static EXT_RAM_BSS_ATTR uint8_t chunk[4096];
    size_t written = 0, n;
    bool failed = false;
    size_t remaining = limit ? limit : (size_t)-1;
    while (remaining > 0)
    {
        size_t want = remaining < sizeof(chunk) ? remaining : sizeof(chunk);
        uint32_t gen;
        n = ring_peek(&s_ring, chunk, want, &gen);
        if (n == 0)
            break;
        size_t put = fwrite(chunk, 1, n, f);
        /* Discard exactly what LANDED: keeping the whole chunk would duplicate
         * bytes already on the card, dropping it would lose the rest. */
        ring_discard(&s_ring, put, gen);
        remaining -= put;
        written += put;
        if (put != n)
        {
            failed = true;   /* card struggling/removed: stop hammering it */
            break;
        }
    }
    /* A full card only surfaces when the stdio buffer is pushed out, and
     * pcap_del_session() drops the fclose result -- so fflush here or never. */
    if (fflush(f) != 0 || ferror(f))
        failed = true;
    pcap_del_session(h);  /* closes f */
    /* Reported even on failure: those bytes are gone from the ring either way,
     * so a caller tracking a debt must subtract them. */
    if (consumed)
        *consumed = written;
    return !failed;
}

uint32_t sdpcap_flush_sec(void)
{
    return cfg_flush_sec;
}

size_t sdpcap_buffered(void)
{
    return s_ready ? ring_used(&s_ring) : 0;
}

size_t sdpcap_flush_now(bool *ok)
{
    if (ok)
        *ok = true;              /* nothing buffered is a successful no-op */
    if (!s_ready)
        return 0;
    /* Bounded: this runs on the restart/power-off path, which must not hang
     * if a writer is stuck holding the lock. */
    if (!sdcard_io_begin_timeout(SDPCAP_FLUSH_LOCK_MS))
    {
        if (ok && ring_used(&s_ring) > 0)
            *ok = false;         /* buffered data we could not get to the card */
        return 0;
    }

    size_t pending = ring_used(&s_ring);
    if (pending > 0)
    {
        time_t bucket = s_ring_bucket;
        if (bucket == 0)
        {
            time_t now = time(NULL);
            bucket = now - (now % 3600);
        }
        char path[96];
        sdpcap_current_path(path, sizeof(path), bucket);
        mkdir(PCAP_DIR, 0777);   /* the periodic task may not have run yet */
        /* While a boundary flush is owed, the oldest bytes belong to the frozen
         * bucket and the rest to the current hour -- pay only the debt here. */
        if (s_stale_left > 0 && s_stale_left < pending)
            pending = s_stale_left;
        size_t consumed = 0;
        bool done = sdpcap_flush_to(path, pending, &consumed);
        bool was_stale = s_stale_left > 0;
        if (was_stale)
            s_stale_left -= consumed < s_stale_left ? consumed : s_stale_left;
        /* Only "did the write land", NOT "is the ring empty": the sniffer appends
         * continuously, so every export would otherwise be stamped incomplete. */
        if (ok)
            *ok = done;
        /* Must move the bucket too, or the writer's next tick takes a fresh
         * boundary snapshot against the old hour and re-attributes the ring. */
        if (was_stale && s_stale_left == 0)
        {
            time_t t = time(NULL);
            bucket_advance(t - (t % 3600));
        }
        pending = consumed;      /* bytes that actually left the ring */
    }
    sdcard_io_end();
    return pending;
}

/* Age+size retention sweep, rate-limited: delete beyond cfg_retain_hours by
 * filename (names sort chronologically), then oldest-first until under cfg_max_mb. */
static void sdpcap_prune(void)
{
    char current[96];
    sdpcap_current_path(current, sizeof(current), time(NULL));
    const char *current_name = strrchr(current, '/');
    current_name = current_name ? current_name + 1 : current;

    /* Files are named for the START of their hour, so round the cutoff down --
     * a mid-hour cutoff deletes the file that still holds wanted minutes. */
    time_t cutoff = time(NULL) - (time_t)cfg_retain_hours * 3600;
    cutoff -= cutoff % 3600;
    struct tm tm_cutoff;
    localtime_r(&cutoff, &tm_cutoff);  /* must match sdpcap_current_path's local-time naming */
    char cutoff_name[32];
    strftime(cutoff_name, sizeof(cutoff_name), "pcap-%Y%m%d-%H%M%S.pcap", &tm_cutoff);

    DIR *dir = opendir(PCAP_DIR);
    if (!dir)
        return;

    /* Pass 1: age-based prune, and tally remaining total size. */
    uint64_t total = 0;
    struct dirent *de;
    while ((de = readdir(dir)) != NULL)
    {
        if (strncmp(de->d_name, "pcap-", 5) != 0)
            continue;
        if (strcmp(de->d_name, current_name) == 0)
            continue;

        char full[300];  /* generous vs. the compiler's worst-case 255-byte d_name assumption */
        snprintf(full, sizeof(full), "%s/%s", PCAP_DIR, de->d_name);

        if (strcmp(de->d_name, cutoff_name) < 0)
        {
            remove(full);
            continue;
        }
        struct stat st;
        if (stat(full, &st) == 0)
            total += (uint64_t)st.st_size;
    }
    closedir(dir);

    uint64_t budget = (uint64_t)cfg_max_mb * 1024ULL * 1024ULL;
    if (total <= budget)
        return;

    /* Pass 2: delete oldest-first, re-scanning each round since directory order
     * isn't sorted. O(n^2), but only runs while over budget. */
    while (total > budget)
    {
        dir = opendir(PCAP_DIR);
        if (!dir)
            return;
        char oldest[256] = {0};
        while ((de = readdir(dir)) != NULL)
        {
            if (strncmp(de->d_name, "pcap-", 5) != 0)
                continue;
            if (strcmp(de->d_name, current_name) == 0)
                continue;
            if (oldest[0] == '\0' || strcmp(de->d_name, oldest) < 0)
                strlcpy(oldest, de->d_name, sizeof(oldest));
        }
        closedir(dir);
        if (oldest[0] == '\0')
            return;  /* nothing left to delete but still "over budget" -- give up this cycle */

        char full[300];  /* generous vs. the compiler's worst-case 255-byte d_name assumption */
        snprintf(full, sizeof(full), "%s/%s", PCAP_DIR, oldest);
        struct stat st;
        uint64_t sz = (stat(full, &st) == 0) ? (uint64_t)st.st_size : 0;
        remove(full);
        total -= sz;
    }
}

static void sdpcap_task(void *arg)
{
    (void)arg;
    bool dir_ok = false;
    uint32_t prune_elapsed_ms = 0;
    uint32_t since_flush_ms = 0;
    uint32_t stale_tries = 0;
#define STALE_MAX_TRIES 60   /* ~1 min at TASK_POLL_MS, then cut the losses */

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(TASK_POLL_MS));

        /* The SD lock below is held across the whole flush/prune: an unmount or
         * format landing mid-fwrite would free the filesystem this task uses. */
        /* Must stay BEFORE that lock -- nothing here touches the card, and with
         * the card gone a disable would otherwise never clear ring or bucket. */
        if (!cfg_enabled)
        {
            /* Mid-run disable drops whatever's buffered rather than flushing
             * it later under a stale bucket. */
            ring_clear(&s_ring);
            s_ring_bucket = 0;
            s_stale_left = 0;    /* nothing is owed to a bucket that is gone */
            stale_tries = 0;
            since_flush_ms = 0;
            dir_ok = false;      /* re-create the directory when it comes back */
            continue;
        }

        if (!sdcard_io_begin())
        {
            dir_ok = false;
            continue;
        }
        if (!dir_ok)
        {
            mkdir(PCAP_DIR, 0777);
            dir_ok = true;
        }

        time_t now = time(NULL);
        time_t bucket_now = now - (now % 3600);

        /* Hour boundary: flush to the OLD bucket first so every record lands in the
         * file matching its own hour (playback's bucket lookup relies on it). */
        /* ONE-SHOT via s_stale_left == 0, or it re-fires every tick and stalls the
         * flush; s_ring_bucket != 0 keeps it from firing on the NTP step. */
        if (s_ring_bucket != 0 && bucket_now != s_ring_bucket && s_stale_left == 0)
        {
            /* Buffered now = the old hour. Do NOT re-add a "starved too long, drop
             * the ring" guard -- ring_append rejects when full, never overwrites. */
            s_stale_left = ring_used(&s_ring);
            stale_tries = 0;
            since_flush_ms = 0;
        }
        /* Clamp BEFORE the test: flush_now drains the same ring, so the debt can
         * outlive its bytes -- and limit 0 means UNLIMITED, not "nothing". */
        {
            size_t have = ring_used(&s_ring);
            if (s_stale_left > have)
                s_stale_left = have;
        }
        if (s_stale_left > 0)
        {
            char old_path[96];
            sdpcap_current_path(old_path, sizeof(old_path), s_ring_bucket);
            size_t put = 0;
            bool landed = sdpcap_flush_to(old_path, s_stale_left, &put);
            s_stale_left -= put < s_stale_left ? put : s_stale_left;
            /* Debt paid yet the write failed (typically a full card): nothing is
             * left to retry, so this is the one loss that would go unreported. */
            if (!landed && s_stale_left == 0)
                ESP_LOGW(TAG, "hour boundary: %u bytes left the ring but %s reports a failed write",
                         (unsigned)put, old_path);
            if (s_stale_left > 0 && ++stale_tries >= STALE_MAX_TRIES)
            {
                /* Drop rather than prepend to the NEXT hour's file: a stale block
                 * outgrows PCAP_RESYNC_MAX and would cost that whole hour. */
                ESP_LOGE(TAG, "hour boundary: dropping %u buffered bytes that never reached %s",
                         (unsigned)s_stale_left, old_path);
                /* Largest loss this module can take, so it belongs in the /system
                 * losses counter; bytes converted via the measured record size. */
                s_dropped += (uint32_t)(s_stale_left / s_avg_rec) + 1u;
                /* Under the SD lock and with no peek outstanding, so the
                 * generation cannot have moved -- read it and pass it on. */
                ring_discard(&s_ring, s_stale_left, s_ring.gen);
                s_stale_left = 0;
            }
        }
        if (s_stale_left == 0)
            bucket_advance(bucket_now);

        since_flush_ms += TASK_POLL_MS;

        size_t buf_threshold = s_ring.size - (s_ring.size / 8);  /* flush a bit before completely full, not exactly at the edge */
        bool due_to_size = ring_used(&s_ring) >= buf_threshold;
        bool due_to_time = since_flush_ms >= cfg_flush_sec * 1000UL;

        /* Not while the previous hour is owed: the ring drains from the tail, so
         * those same bytes would land in the current hour's file. */
        size_t due_now = ring_used(&s_ring);
        if (s_stale_left == 0 && due_now > 0 && (due_to_size || due_to_time))
        {
            char path[96];
            /* The bucket, not the clock -- where they disagree the bucket wins. */
            sdpcap_current_path(path, sizeof(path), s_ring_bucket);
            /* Capped at what is buffered RIGHT NOW: with limit 0 the drain also
             * swallows records appended during it, into the wrong hour's file. */
            size_t put = 0;
            if (!sdpcap_flush_to(path, due_now, &put))
                ESP_LOGW(TAG, "mid-hour flush failed after %u of %u bytes",
                         (unsigned)put, (unsigned)due_now);
            since_flush_ms = 0;
        }

        prune_elapsed_ms += TASK_POLL_MS;
        /* Same reader interlock as tracklog/stats: an unlink mid-stream truncates
         * a /sdcard download. Does NOT cover sdpcap_walk (writer lock instead). */
        if (prune_elapsed_ms >= PRUNE_INTERVAL_MS && sdcard_read_active() == 0)
        {
            prune_elapsed_ms = 0;
            /* A full-window sweep can run for minutes, and the stall watchdog
             * would read that as a wedged writer and REBOOT. */
            sdcard_io_long_begin();
            sdpcap_prune();
            sdcard_io_long_end();
        }
        sdcard_io_end();
    }
}

void sdpcap_init(void)
{
    reload_config();

    uint32_t buf_mb = 1;  /* boot-time only, not live-reloadable */
    config_get_u32(CONFIG_INDEX_PCAP_BUF_MB, &buf_mb);
    if (buf_mb < PCAP_BUF_MB_MIN) buf_mb = PCAP_BUF_MB_MIN;
    if (buf_mb > PCAP_BUF_MB_MAX) buf_mb = PCAP_BUF_MB_MAX;

    if (!ring_init(&s_ring, (size_t)buf_mb * 1024 * 1024))
    {
        ESP_LOGE(TAG, "Failed to allocate %luMB PSRAM pcap ring buffer", (unsigned long)buf_mb);
        return;
    }

    if (xTaskCreate(sdpcap_task, "sdpcap", 4096, NULL, 3, NULL) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create sdpcap task");
        return;
    }

    s_ready = true;

    ESP_ERROR_CHECK(esp_event_handler_register(CONFIG_EVENT_BASE, ESP_EVENT_ANY_ID,
                                               config_event_handler, NULL));
    ESP_LOGI(TAG, "SD pcap capture ready (enabled=%d, buf=%luMB, flush=%lus, retain=%luh, max=%luMB)",
             cfg_enabled, (unsigned long)buf_mb, (unsigned long)cfg_flush_sec,
             (unsigned long)cfg_retain_hours, (unsigned long)cfg_max_mb);
}

#else /* !CONFIG_ENABLE_SD */

void sdpcap_init(void) {}
void sdpcap_handle_packet(sniffer_packet_info_t *packet) { (void)packet; }
size_t sdpcap_buffered(void) { return 0; }
uint32_t sdpcap_flush_sec(void) { return 0; }
size_t sdpcap_flush_now(bool *ok) { if (ok) *ok = true; return 0; }
uint32_t sdpcap_dropped(void)  { return 0; }
uint32_t sdpcap_filtered(void) { return 0; }

bool sdpcap_read_positions(uint32_t from_sec, uint32_t to_sec, sdpcap_position_cb_t cb, void *ctx)
{
    (void)from_sec; (void)to_sec; (void)cb; (void)ctx;
    return true;
}
bool sdpcap_read_frames(uint32_t from_sec, uint32_t to_sec, sdpcap_frame_cb_t cb, void *ctx)
{
    (void)from_sec; (void)to_sec; (void)cb; (void)ctx;
    return true;
}

#endif
