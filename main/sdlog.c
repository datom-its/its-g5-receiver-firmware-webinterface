#include "sdkconfig.h"

#include "sdlog.h"

#if CONFIG_ENABLE_SD

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_event.h"

#include "config.h"
#include "events.h"
#include "sdcard.h"

static const char TAG[] = "SDLOG";

#define LOG_DIR        CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define SYS_LOG        LOG_DIR "/system.log"
#define SYS_LOG_OLD    LOG_DIR "/system.1.log"
#define FRAME_LOG      LOG_DIR "/frames.csv"
#define FRAME_LOG_OLD  LOG_DIR "/frames.1.csv"

#define SYS_RING_SIZE    (16 * 1024)   /* PSRAM buffer, low-volume text */
#define FRAME_RING_SIZE  (64 * 1024)   /* PSRAM buffer, higher volume   */
#define FLUSH_INTERVAL_MS 2000
#define FRAME_HEX_BYTES   32           /* first N bytes logged as hex   */

/* Fixed slice of the total budget reserved for the (low-volume) system log;
 * the rest goes to the frame log. Each stream keeps 2 rotated files. */
#define SYS_BUDGET_MB     4

/* ================================================================== */
/*  Byte ring buffer (allocated in PSRAM)                             */
/* ================================================================== */

typedef struct {
    char   *buf;
    size_t  size;
    size_t  head;      /* write index */
    size_t  tail;      /* read index  */
    size_t  used;
    uint32_t dropped;  /* bytes dropped due to overflow */
    SemaphoreHandle_t lock;
} ring_t;

static bool ring_init(ring_t *r, size_t size)
{
    r->buf = heap_caps_malloc(size, MALLOC_CAP_SPIRAM);
    if (!r->buf)
    {
        /* Fall back to internal RAM only if PSRAM is unavailable. */
        r->buf = malloc(size);
        if (!r->buf)
            return false;
    }
    r->size = size;
    r->head = r->tail = r->used = 0;
    r->dropped = 0;
    r->lock = xSemaphoreCreateMutex();
    return r->lock != NULL;
}

/* Append bytes; drops the whole chunk if it does not fit (best effort). */
static void ring_append(ring_t *r, const char *data, size_t len, TickType_t wait)
{
    if (len == 0 || !r->buf)
        return;
    if (xSemaphoreTake(r->lock, wait) != pdTRUE)
        return;
    if (len > r->size - r->used)
    {
        r->dropped += len;
        xSemaphoreGive(r->lock);
        return;
    }
    size_t first = r->size - r->head;
    if (first > len) first = len;
    memcpy(r->buf + r->head, data, first);
    if (len > first)
        memcpy(r->buf, data + first, len - first);
    r->head = (r->head + len) % r->size;
    r->used += len;
    xSemaphoreGive(r->lock);
}

/* Copy out up to max bytes; returns number copied. */
static size_t ring_drain(ring_t *r, char *out, size_t max)
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

/* ================================================================== */
/*  Streams + cached config                                           */
/* ================================================================== */

typedef struct {
    const char *path;
    const char *path_old;
    size_t      file_cap;   /* bytes per file before rotation */
    ring_t      ring;
} stream_t;

static stream_t sys_stream   = { SYS_LOG,   SYS_LOG_OLD,   0, {0} };
static stream_t frame_stream = { FRAME_LOG, FRAME_LOG_OLD, 0, {0} };

static volatile bool s_ready;
static volatile bool cfg_log_sys;
static volatile bool cfg_log_frames;

static vprintf_like_t s_orig_vprintf;

/* ESP-IDF's log timestamps are time-only (HH:MM:SS.mmm), so a multi-day
 * system.log can't be pinned to a calendar day. We inject a dated header
 * line whenever the local date rolls over (and on the first line after NTP
 * sync). s_next_day_boundary caches the epoch-second of the next local
 * midnight so the expensive localtime_r/strftime runs once per day, not per
 * log line. */
static time_t s_next_day_boundary;

/* Called from the vprintf hook (any task). Appends a date header to the sys
 * ring iff the local day changed. Suppressed until the clock is plausibly
 * NTP-set, to avoid a bogus 1970 header at boot. */
static void sdlog_emit_date_marker_if_needed(void)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if (tv.tv_sec < 1600000000)   /* ~2020-09, i.e. clock still unset */
        return;
    if (tv.tv_sec < s_next_day_boundary)
        return;

    struct tm lt;
    localtime_r(&tv.tv_sec, &lt);
    char marker[48];
    int mn = (int)strftime(marker, sizeof(marker), "===== %Y-%m-%d (%a) =====\n", &lt);
    if (mn > 0)
        ring_append(&sys_stream.ring, marker, (size_t)mn, 0);

    /* Next local midnight; tm_isdst=-1 lets mktime resolve DST correctly. */
    lt.tm_mday += 1;
    lt.tm_hour = 0;
    lt.tm_min = 0;
    lt.tm_sec = 0;
    lt.tm_isdst = -1;
    s_next_day_boundary = mktime(&lt);
}

static void reload_config(void)
{
    uint8_t sys = 0, frames = 0;
    uint32_t mb = 50;
    config_get_u8(CONFIG_INDEX_LOG_SYS, &sys);
    config_get_u8(CONFIG_INDEX_LOG_FRAMES, &frames);
    config_get_u32(CONFIG_INDEX_LOG_MAX_MB, &mb);
    cfg_log_sys = sys;
    cfg_log_frames = frames;

    /* Split the budget: SYS_BUDGET_MB for the system log, the rest for frames.
     * Each stream keeps 2 files, so per-file cap is half the stream budget. */
    uint32_t sys_mb = mb > SYS_BUDGET_MB * 2 ? SYS_BUDGET_MB : (mb / 2 ? mb / 2 : 1);
    uint32_t frame_mb = mb > sys_mb ? mb - sys_mb : 1;
    sys_stream.file_cap = (size_t)(sys_mb * 1024UL * 1024UL) / 2;
    frame_stream.file_cap = (size_t)(frame_mb * 1024UL * 1024UL) / 2;
    if (sys_stream.file_cap < 4096) sys_stream.file_cap = 4096;
    if (frame_stream.file_cap < 4096) frame_stream.file_cap = 4096;
}

static void config_event_handler(void *arg, esp_event_base_t base,
                                 int32_t id, void *data)
{
    (void)arg; (void)base; (void)data;
    if (id == CONFIG_INDEX_LOG_SYS || id == CONFIG_INDEX_LOG_FRAMES ||
        id == CONFIG_INDEX_LOG_MAX_MB)
        reload_config();
}

/* ================================================================== */
/*  Writer task                                                       */
/* ================================================================== */

static void flush_stream(stream_t *s)
{
    if (s->ring.used == 0)
        return;

    FILE *f = fopen(s->path, "a");
    if (!f)
        return;

    char scratch[1024];
    size_t n;
    while ((n = ring_drain(&s->ring, scratch, sizeof(scratch))) > 0)
    {
        if (fwrite(scratch, 1, n, f) != n)
            break;  /* write error (card full/removed): stop, retry next cycle */
    }
    fclose(f);

    /* Rotate: current file full -> drop the old backup, current becomes backup. */
    struct stat st;
    if (stat(s->path, &st) == 0 && (size_t)st.st_size >= s->file_cap)
    {
        remove(s->path_old);
        rename(s->path, s->path_old);
    }
}

static void sdlog_task(void *arg)
{
    (void)arg;
    bool dir_ok = false;
    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(FLUSH_INTERVAL_MS));

        /* Held across the flush so an unmount/format can't free the
         * filesystem while this task is inside fwrite. */
        if (!sdcard_io_begin())
        {
            dir_ok = false;
            continue;
        }
        if (!dir_ok)
        {
            mkdir(LOG_DIR, 0777);   /* harmless if it already exists */
            dir_ok = true;
        }

        if (sys_stream.ring.used)
            flush_stream(&sys_stream);
        if (frame_stream.ring.used)
            flush_stream(&frame_stream);
        sdcard_io_end();
    }
}

void sdlog_flush_now(void)
{
    /* Bounded for the same reason as sdpcap_flush_now(): restart paths must
     * not hang on a stuck writer. */
    if (!s_ready || !sdcard_io_begin_timeout(2000))
        return;
    mkdir(LOG_DIR, 0777);   /* the writer task may not have run yet */
    if (sys_stream.ring.used)
        flush_stream(&sys_stream);
    if (frame_stream.ring.used)
        flush_stream(&frame_stream);
    sdcard_io_end();
}

/* ================================================================== */
/*  System-log hook                                                   */
/* ================================================================== */

static int sdlog_vprintf(const char *fmt, va_list args)
{
    /* Always pass through to the original sink (UART) first. */
    va_list ap;
    va_copy(ap, args);
    int ret = s_orig_vprintf ? s_orig_vprintf(fmt, ap) : vprintf(fmt, ap);
    va_end(ap);

    if (s_ready && cfg_log_sys)
    {
        char line[256];
        int n = vsnprintf(line, sizeof(line), fmt, args);
        if (n > 0)
        {
            if (n > (int)sizeof(line) - 1)
                n = sizeof(line) - 1;
            sdlog_emit_date_marker_if_needed();
            /* Never block a logging call: give up the line if contended. */
            ring_append(&sys_stream.ring, line, (size_t)n, 0);
        }
    }
    return ret;
}

/* ================================================================== */
/*  Public API                                                        */
/* ================================================================== */

void sdlog_handle_packet(sniffer_packet_info_t *packet)
{
    if (!s_ready || !cfg_log_frames || !packet)
        return;

    /* Readable local wall-clock time (TZ set in webserver_init). Correct once
     * NTP has synced; before that it reflects the unset device clock. */
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm tm_local;
    localtime_r(&tv.tv_sec, &tm_local);
    char ts[24];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm_local);

    char line[48 + FRAME_HEX_BYTES * 2 + 8];
    int off = snprintf(line, sizeof(line), "%s.%03ld,%d,%lu,",
                       ts, (long)(tv.tv_usec / 1000),
                       packet->rssi, (unsigned long)packet->length);
    if (off < 0)
        return;

    size_t hexn = packet->length < FRAME_HEX_BYTES ? packet->length : FRAME_HEX_BYTES;
    const uint8_t *p = (const uint8_t *)packet->payload;
    static const char hexd[] = "0123456789abcdef";
    for (size_t i = 0; i < hexn && off + 2 < (int)sizeof(line); i++)
    {
        line[off++] = hexd[p[i] >> 4];
        line[off++] = hexd[p[i] & 0xF];
    }
    if (off < (int)sizeof(line))
        line[off++] = '\n';

    ring_append(&frame_stream.ring, line, (size_t)off, pdMS_TO_TICKS(10));
}

void sdlog_init(void)
{
    reload_config();

    if (!ring_init(&sys_stream.ring, SYS_RING_SIZE) ||
        !ring_init(&frame_stream.ring, FRAME_RING_SIZE))
    {
        ESP_LOGE(TAG, "Failed to allocate log ring buffers");
        return;
    }

    if (xTaskCreate(sdlog_task, "sdlog", 4096, NULL, 3, NULL) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create sdlog task");
        return;
    }

    /* Install the log hook last, so it is only active once buffers exist. */
    s_orig_vprintf = esp_log_set_vprintf(sdlog_vprintf);
    s_ready = true;

    ESP_ERROR_CHECK(esp_event_handler_register(CONFIG_EVENT_BASE, ESP_EVENT_ANY_ID,
                                               config_event_handler, NULL));
    ESP_LOGI(TAG, "SD logger ready (sys=%d frames=%d)", cfg_log_sys, cfg_log_frames);
}

#else /* !CONFIG_ENABLE_SD */

void sdlog_init(void) {}
void sdlog_handle_packet(sniffer_packet_info_t *packet) { (void)packet; }
void sdlog_flush_now(void) {}

#endif
