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
#include "esp_attr.h"
#include "sdcard.h"

static const char TAG[] = "SDLOG";

#define LOG_DIR        CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define SYS_LOG        LOG_DIR "/system.log"
#define SYS_LOG_OLD    LOG_DIR "/system.1.log"

/* Upper bound for the log budget: keeps the byte arithmetic in 32 bit and
 * a runaway setting from eating the card. */
#define SYS_BUDGET_MAX_MB SDLOG_MAX_MB

#define SYS_RING_SIZE    (16 * 1024)   /* PSRAM buffer, low-volume text */
#define FLUSH_INTERVAL_MS 2000

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

/* Append bytes, or drop the whole chunk if it does not fit (best effort). */
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

/* Copy out up to max bytes and return the number copied. */
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

static volatile bool s_ready;
static volatile bool cfg_log_sys;

/* The last console lines, kept in RAM. The SD log needs the card, so it cannot
 * record why a mount failed. */
#define RLOG_LINES 64
#define RLOG_LEN   160
static EXT_RAM_BSS_ATTR char rlog[RLOG_LINES][RLOG_LEN];
static uint32_t rlog_next;      /* number of lines ever written */
static portMUX_TYPE rlog_mux = portMUX_INITIALIZER_UNLOCKED;

/* Tags that log on a timer fill the 64-line ring within minutes, until it holds
 * nothing but temperature. Only their info lines are dropped, so a failing
 * sensor still shows. Every line still reaches the UART and the SD log. */
static bool rlog_noisy(const char *line)
{
    /* The level letter comes first because log colours are off in every
     * sdkconfig. With colours on, nothing is dropped. */
    if (line[0] != 'I')
        return false;
    static const char *const tags[] = { ") TEMPERATURE: " };
    for (size_t i = 0; i < sizeof(tags) / sizeof(tags[0]); i++)
        if (strstr(line, tags[i])) return true;
    return false;
}

static void rlog_put(const char *line, int n)
{
    if (n <= 0) return;
    if (n > RLOG_LEN - 1) n = RLOG_LEN - 1;
    /* sdlog_recent() adds a newline to each line, so strip the logged one. */
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) n--;
    portENTER_CRITICAL_SAFE(&rlog_mux);
    memcpy(rlog[rlog_next % RLOG_LINES], line, (size_t)n);
    rlog[rlog_next % RLOG_LINES][n] = '\0';
    rlog_next++;
    portEXIT_CRITICAL_SAFE(&rlog_mux);
}

size_t sdlog_recent(char *out, size_t cap)
{
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    size_t o = 0;
    /* Only the index is read under the lock. rlog is in PSRAM, and copying
     * 10 KB of it with interrupts off would stall the packet path. */
    portENTER_CRITICAL_SAFE(&rlog_mux);
    uint32_t total = rlog_next;
    portEXIT_CRITICAL_SAFE(&rlog_mux);

    uint32_t have = total < RLOG_LINES ? total : RLOG_LINES;
    for (uint32_t i = 0; i < have; i++)
    {
        /* Full-width copy plus a forced terminator: a line the writer is
         * replacing right now may be torn, but it can never run off the slot. */
        char slot[RLOG_LEN];
        memcpy(slot, rlog[(total - have + i) % RLOG_LINES], RLOG_LEN);
        slot[RLOG_LEN - 1] = '\0';
        size_t len = strlen(slot);
        if (o + len + 2 > cap) break;
        memcpy(out + o, slot, len); o += len;
        out[o++] = '\n';
    }
    out[o] = '\0';
    return o;
}

static vprintf_like_t s_orig_vprintf;

/* IDF log timestamps have no date. Insert a dated header line at local midnight
 * and after NTP sync. The cached boundary means localtime runs once a day. */
static time_t s_next_day_boundary;

/* Called from the vprintf hook (any task). Suppressed until the clock is
 * plausibly NTP-set, to avoid a bogus 1970 header at boot. */
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

    /* Next local midnight. tm_isdst=-1 lets mktime resolve DST correctly. */
    lt.tm_mday += 1;
    lt.tm_hour = 0;
    lt.tm_min = 0;
    lt.tm_sec = 0;
    lt.tm_isdst = -1;
    s_next_day_boundary = mktime(&lt);
}

static void reload_config(void)
{
    uint8_t sys = 0;
    uint32_t mb = 50;
    config_get_u8(CONFIG_INDEX_LOG_SYS, &sys);
    config_get_u32(CONFIG_INDEX_LOG_MAX_MB, &mb);
    cfg_log_sys = sys;

    /* Per-file cap is half the budget because 2 rotated files are kept. Clamped
     * because "config set" on the console accepts values that overflow 32-bit math. */
    uint32_t sys_mb = mb ? mb : 1;
    if (sys_mb > SYS_BUDGET_MAX_MB) sys_mb = SYS_BUDGET_MAX_MB;
    sys_stream.file_cap = (size_t)((uint64_t)sys_mb * 1024u * 1024u / 2u);
    if (sys_stream.file_cap < 4096) sys_stream.file_cap = 4096;
}

static void config_event_handler(void *arg, esp_event_base_t base,
                                 int32_t id, void *data)
{
    (void)arg; (void)base; (void)data;
    if (id == CONFIG_INDEX_LOG_SYS ||
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
    {
        /* A format wipes /logs with the card still mounted, so the task's
         * one-shot mkdir never re-runs. Retry once before calling it a failure. */
        mkdir(LOG_DIR, 0777);
        f = fopen(s->path, "a");
    }
    if (!f)
    {
        sdcard_note_write(false);
        return;
    }

    char scratch[1024];
    size_t n;
    bool ok = true;
    while ((n = ring_drain(&s->ring, scratch, sizeof(scratch))) > 0)
    {
        if (fwrite(scratch, 1, n, f) != n)
        {
            ok = false;
            break;  /* write error: this chunk is lost, but the ring keeps the rest */
        }
    }
    /* picolibc's fclose hides a failed last write-out. With a quiet log that write-out is the
     * only one, and sdcard_note_write must see its result. */
    if (ok && (fflush(f) != 0 || ferror(f)))
        ok = false;
    if (fclose(f) != 0)
        ok = false;
    sdcard_note_write(ok);

    /* Rotate once the file is full. It replaces the old backup. */
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

    char line[256];
    int n = vsnprintf(line, sizeof(line), fmt, args);
    /* Ahead of the SD-log check on purpose, so the RAM copy also fills while the
     * SD log is off. After a failed mount it is the only place that shows why. */
    if (n > 0 && !rlog_noisy(line))
        rlog_put(line, n);

    if (s_ready && cfg_log_sys)
    {
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

void sdlog_init(void)
{
    /* A frames.csv from older firmware is kept on purpose. It is outside the /logs
     * budget, but it is captured data. Only the operator should delete it. */

    reload_config();

    if (!ring_init(&sys_stream.ring, SYS_RING_SIZE))
    {
        ESP_LOGE(TAG, "Failed to allocate log ring buffer");
        return;
    }

    if (xTaskCreate(sdlog_task, "sdlog", 4096, NULL, 3, NULL) != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create sdlog task");
        return;
    }

    /* Install the log hook only after the ring buffer and writer task exist. */
    s_orig_vprintf = esp_log_set_vprintf(sdlog_vprintf);
    s_ready = true;

    ESP_ERROR_CHECK(esp_event_handler_register(CONFIG_EVENT_BASE, ESP_EVENT_ANY_ID,
                                               config_event_handler, NULL));
    ESP_LOGI(TAG, "SD logger ready (sys=%d)", cfg_log_sys);
}

#else /* !CONFIG_ENABLE_SD */

void sdlog_init(void) {}
void sdlog_flush_now(void) {}

/* Without SD support there is no logger, but the getter must still link. */
size_t sdlog_recent(char *out, size_t cap) { if (out && cap) out[0] = '\0'; return 0; }

#endif
