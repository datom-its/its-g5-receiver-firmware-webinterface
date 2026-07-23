#include "sdkconfig.h"

#include "sdpcap.h"

#if CONFIG_ENABLE_SD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>
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

/* Finer than any real flush-interval setting (min 8s) so the size/time/
 * hour-boundary checks fire promptly; a poll tick itself is just a few
 * integer compares, SD is only touched when a check actually trips. */
#define TASK_POLL_MS       1000
#define PRUNE_INTERVAL_MS  60000  /* retention sweep cadence, independent of flush cadence */

#define PCAP_BUF_MB_MIN    1
#define PCAP_BUF_MB_MAX    4
#define PCAP_FLUSH_SEC_MIN 8
#define PCAP_FLUSH_SEC_MAX 3600

#define PCAP_MAX_FRAME 2048  /* generous max realistic 802.11 frame size */

/* pcap on-disk record layout, mirrors what the vendored pcap library
 * (managed_components/espressif__pcap) writes -- built directly here
 * instead of calling into that library per record (see the ring buffer
 * below), so this struct is the single source of truth for both paths. */
typedef struct { uint32_t magic; uint16_t vmaj, vmin; int32_t tz; uint32_t sig, snap, net; } pcap_global_hdr_t;
typedef struct { uint32_t sec, usec, caplen, len; } pcap_rec_hdr_t;

/* ================================================================== */
/*  PSRAM ring buffer                                                  */
/* ================================================================== */

/* Holds formatted pcap records (header+payload, back to back) until the
 * writer task flushes them to SD in one bulk write -- bounds RAM use in
 * otherwise-idle PSRAM while allowing a large flush interval, and turns
 * many small SD writes into few large ones (fewer SPI-bus acquisitions on
 * the bus shared with Ethernet). */
typedef struct {
    uint8_t *buf;
    size_t   size;
    size_t   head;    /* write index */
    size_t   tail;    /* read index  */
    size_t   used;
    SemaphoreHandle_t lock;
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

/* Drops the whole record (never a partial write) if it doesn't fit or the
 * lock is contended past `wait` -- a torn record would be undetectable to
 * the reader. */
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

/* Copies out up to max bytes (not necessarily a whole number of records --
 * the caller only cares that this matches what it then fwrites). */
static size_t ring_drain(pcap_ring_t *r, uint8_t *out, size_t max)
{
    if (xSemaphoreTake(r->lock, portMAX_DELAY) != pdTRUE)
        return 0;
    size_t n = r->used < max ? r->used : max;
    size_t first = r->size - r->tail;
    if (first > n) first = n;
    memcpy(out, r->buf + r->tail, first);
    if (n > first)
        memcpy(out + first, r->buf, n - first);
    r->tail = (r->tail + n) % r->size;
    r->used -= n;
    xSemaphoreGive(r->lock);
    return n;
}

/* Unlocked; a size-threshold heuristic only, so a stale read just means the
 * flush fires one poll tick early or late. */
static size_t ring_used(const pcap_ring_t *r)
{
    return r->used;
}

static void ring_clear(pcap_ring_t *r)
{
    if (xSemaphoreTake(r->lock, portMAX_DELAY) != pdTRUE)
        return;
    r->head = r->tail = r->used = 0;
    xSemaphoreGive(r->lock);
}

/* ================================================================== */
/*  Config                                                             */
/* ================================================================== */

static volatile bool s_ready;
static volatile bool cfg_enabled;
static volatile uint32_t cfg_retain_hours;
static volatile uint32_t cfg_max_mb;
static volatile uint32_t cfg_flush_sec;
static volatile uint8_t  cfg_filter;
static uint32_t s_dropped;

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

/* Thinning filter. One traffic light accounts for 85% of everything recorded
 * here -- 26,679 SPATEM an hour, the same intersection repeating itself ten
 * times a second, 12.1 of the 14.3 MB. Dropping the security envelope from
 * each frame would save less (a factor of three) while making the recording
 * no longer a faithful capture; skipping repeats costs nothing structurally
 * and saves more. Modes: 0 keep everything, 1 thin the infrastructure
 * chatter to one message a second per type, 2 keep only vehicles and
 * warnings. */
static uint32_t s_filtered;
static uint32_t s_last_kept[256];   /* last second kept, per messageId */

static bool pcap_keep_frame(const uint8_t *frame, size_t len, uint32_t sec)
{
    /* Reads the cached value, never NVS: this runs on the receive path for
     * every frame, about thirty times a second. */
    uint8_t mode = cfg_filter;
    if (mode == 0)
        return true;

    uint8_t mid = its_peek_message_id(frame, len);
    /* Only SPATEM (4) and MAPEM (5) are the repetitive infrastructure ones;
     * anything else -- vehicles, warnings, message types we do not yet know
     * -- is always kept. Being wrong here means silently losing data, so the
     * filter names what it drops rather than what it keeps. */
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

/* Called from the sniffer's hot path -- must never block, never malloc.
 * The record-assembly buffer is `static`, not a stack local:
 * CONFIG_SNIFFER_TASK_STACK_SIZE is only 4096 bytes total, and a ~2 KB
 * local array here would eat half of it. Safe as `static` since only
 * sniffer_task ever calls this, sequentially. */
void sdpcap_handle_packet(sniffer_packet_info_t *packet)
{
    if (!s_ready || !cfg_enabled || !packet)
        return;
    if (packet->length > PCAP_MAX_FRAME)
    {
        s_dropped++;
        return;
    }

    /* packet->seconds/.microseconds are a radio/PHY counter, not wall-clock
     * epoch time -- gettimeofday() instead (correct once NTP has synced). */
    struct timeval tv;
    gettimeofday(&tv, NULL);

    if (!pcap_keep_frame(packet->payload, packet->length, (uint32_t)tv.tv_sec))
    {
        s_filtered++;
        return;
    }

    static EXT_RAM_BSS_ATTR uint8_t rec[sizeof(pcap_rec_hdr_t) + PCAP_MAX_FRAME];
    pcap_rec_hdr_t hdr = {
        .sec = (uint32_t)tv.tv_sec,
        .usec = (uint32_t)tv.tv_usec,
        .caplen = packet->length,
        .len = packet->length,
    };
    memcpy(rec, &hdr, sizeof(hdr));
    memcpy(rec + sizeof(hdr), packet->payload, packet->length);

    if (!ring_append(&s_ring, rec, sizeof(hdr) + packet->length, 0))
        s_dropped++;
}

/* ================================================================== */
/*  Writer task                                                       */
/* ================================================================== */

/* Filename uses local time (so a human can find "the file from around
 * 5pm"); bucket rounding stays correct regardless, since only the label
 * changes. DST fall-back can merge two real hours into one filename once a
 * year -- harmless, just a naming quirk. */
static void sdpcap_current_path(char *out, size_t out_size, time_t now)
{
    time_t bucket = now - (now % 3600);
    struct tm tm_local;
    localtime_r(&bucket, &tm_local);
    char name[32];
    strftime(name, sizeof(name), "pcap-%Y%m%d-%H%M%S.pcap", &tm_local);
    snprintf(out, out_size, "%s/%s", PCAP_DIR, name);
}

/* Does this look like a real record header for a file covering `hour`?
 * The timestamp check is what makes resynchronisation reliable: random frame
 * bytes almost never form a plausible second inside this one hour. */
static bool pcap_rec_plausible(const pcap_rec_hdr_t *rh, uint32_t hour, size_t maxcap)
{
    /* +5 s slack past the hour: the writer stamps records at enqueue time and
     * flushes in batches, so the last records of an hour can legitimately sit
     * just past the boundary -- the real 18:00 file ends on a record at
     * exactly 19:00:00, which a strict bound rejected and dropped. */
    return rh->caplen >= 24 && rh->caplen <= maxcap &&
           rh->len >= rh->caplen && rh->len <= maxcap &&
           rh->usec < 1000000u &&
           rh->sec >= hour && rh->sec < hour + 3605u;
}

/* Slides forward from the current position until a plausible record header
 * is found, leaving the stream positioned just after it. Scans in-memory
 * chunks: the first version issued an fseek+fread pair PER BYTE, which on a
 * thoroughly damaged file meant up to 262,144 SD accesses before giving up --
 * the same scan over 2 KB chunks is 128 reads. Bounded either way so a broken
 * file cannot stall the request indefinitely. */
#define PCAP_RESYNC_MAX 262144   /* 256 KB of garbage before giving up */

static bool pcap_resync(FILE *f, pcap_rec_hdr_t *rh, uint32_t hour, size_t maxcap)
{
    long pos = ftell(f);
    if (pos < 0)
        return false;
    pos -= (long)sizeof(*rh);   /* back to the header that failed */

    /* Static: this runs on the httpd task; the chunk plus header overlap
     * would be an unnecessary 2 KB of its stack. Only one playback request
     * runs at a time in practice, and a second would merely rescan. */
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

void sdpcap_read_positions(uint32_t from_sec, uint32_t to_sec, sdpcap_position_cb_t cb, void *ctx)
{
    if (!cb || !sdcard_is_mounted())
        return;

    time_t bucket = (time_t)from_sec - ((time_t)from_sec % 3600);
    for (; bucket <= (time_t)to_sec; bucket += 3600)
    {
        char path[96];
        sdpcap_current_path(path, sizeof(path), bucket);

        FILE *f = fopen(path, "rb");
        if (!f)
            continue;  /* no capture stored for this hour -- fine, just skip it */

        pcap_global_hdr_t gh;
        if (fread(&gh, sizeof(gh), 1, f) != 1 || gh.magic != 0xa1b2c3d4)
        {
            fclose(f);
            continue;
        }

        static EXT_RAM_BSS_ATTR uint8_t buf[PCAP_MAX_FRAME];
        pcap_rec_hdr_t rh;
        while (fread(&rh, sizeof(rh), 1, f) == 1)
        {
            /* A torn SD write desynchronises the record framing, and giving up
             * at that point threw away the rest of the hour -- measured on a
             * real file: readable up to 19:07, 50 minutes of perfectly good
             * frames beyond it lost. So resynchronise instead: slide forward
             * a byte at a time until a header looks plausible again (timestamp
             * inside this file's own hour, sane lengths). */
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
            if (d.has_position)
                cb(rh.sec, rh.usec, &d, ctx);
        }
        fclose(f);
    }
}

/* Flushes the ring to `path` (the file for the hour its contents belong to
 * -- see sdpcap_task's hour-boundary handling), draining in fixed 4 KB
 * chunks rather than needing a buffer the size of the whole ring. */
static void sdpcap_flush_to(const char *path)
{
    FILE *f = fopen(path, "ab");
    if (!f)
        return;

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
        return;
    }
    if (need_header && pcap_write_header(h, PCAP_LINK_TYPE_802_11) != ESP_OK)
    {
        pcap_del_session(h);
        return;
    }

    static EXT_RAM_BSS_ATTR uint8_t chunk[4096];
    size_t n;
    while ((n = ring_drain(&s_ring, chunk, sizeof(chunk))) > 0)
    {
        if (fwrite(chunk, 1, n, f) != n)
            break;  /* card struggling/removed: stop hammering it, retry next flush */
    }
    pcap_del_session(h);  /* closes f (implicit fflush via fclose) */
}

/* Age+size retention sweep, rate-limited to PRUNE_INTERVAL_MS (not every
 * poll tick): delete files older than cfg_retain_hours by filename
 * comparison (UTC-aligned names sort chronologically by construction), then
 * if the directory is still over cfg_max_mb, delete oldest-first until under
 * budget. The currently-active bucket is never pruned. */
static void sdpcap_prune(void)
{
    char current[96];
    sdpcap_current_path(current, sizeof(current), time(NULL));
    const char *current_name = strrchr(current, '/');
    current_name = current_name ? current_name + 1 : current;

    time_t cutoff = time(NULL) - (time_t)cfg_retain_hours * 3600;
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

    /* Pass 2: still over budget -- delete oldest-first, re-scanning each
     * round since directory order isn't sorted. O(n^2) but only runs when
     * over budget, on at most a few hundred files. */
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
    time_t current_bucket = 0;   /* hour bucket the ring's buffered data belongs to, 0 = not yet established */

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(TASK_POLL_MS));

        if (!sdcard_is_mounted())
        {
            dir_ok = false;
            continue;
        }
        if (!dir_ok)
        {
            mkdir(PCAP_DIR, 0777);
            dir_ok = true;
        }

        if (!cfg_enabled)
        {
            /* Mid-run disable drops whatever's buffered rather than
             * flushing it later with a stale timestamp bucket. */
            ring_clear(&s_ring);
            current_bucket = 0;
            since_flush_ms = 0;
            continue;
        }

        time_t now = time(NULL);
        time_t bucket_now = now - (now % 3600);

        /* Hour boundary: flush to the OLD bucket's file first, so every
         * record lands in the file matching its own hour (required for
         * sdpcap_read_positions' bucket lookup). Polling every second means
         * whatever's still buffered here is guaranteed to predate the
         * boundary. */
        if (current_bucket != 0 && bucket_now != current_bucket)
        {
            if (ring_used(&s_ring) > 0)
            {
                char old_path[96];
                sdpcap_current_path(old_path, sizeof(old_path), current_bucket);
                sdpcap_flush_to(old_path);
            }
            since_flush_ms = 0;
        }
        current_bucket = bucket_now;

        since_flush_ms += TASK_POLL_MS;

        size_t buf_threshold = s_ring.size - (s_ring.size / 8);  /* flush a bit before completely full, not exactly at the edge */
        bool due_to_size = ring_used(&s_ring) >= buf_threshold;
        bool due_to_time = since_flush_ms >= cfg_flush_sec * 1000UL;

        if (ring_used(&s_ring) > 0 && (due_to_size || due_to_time))
        {
            char path[96];
            sdpcap_current_path(path, sizeof(path), now);
            sdpcap_flush_to(path);
            since_flush_ms = 0;
        }

        prune_elapsed_ms += TASK_POLL_MS;
        if (prune_elapsed_ms >= PRUNE_INTERVAL_MS)
        {
            prune_elapsed_ms = 0;
            sdpcap_prune();
        }
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
void sdpcap_read_positions(uint32_t from_sec, uint32_t to_sec, sdpcap_position_cb_t cb, void *ctx)
{
    (void)from_sec; (void)to_sec; (void)cb; (void)ctx;
}

#endif
