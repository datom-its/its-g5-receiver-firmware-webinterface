#include "sdkconfig.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <time.h>
#include <sys/time.h>
#if CONFIG_ENABLE_SD
#include <dirent.h>
#include <sys/stat.h>
#endif

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_chip_info.h"
#include "esp_console.h"
#include "esp_core_dump.h"
#include "esp_event.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_idf_version.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif_sntp.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_sntp.h"
#include "esp_vfs_fat.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "mbedtls/base64.h"

#include "config.h"
#include "settings_apply.h"
#include "cmd_sniffer.h"
#include "events.h"
#include "its_certcache.h"
#include "its_decode.h"
#include "its_msgsig.h"
#include "msg_extra.h"
#include "ota.h"
#include "sysmon.h"
#include "mqtt.h"
#if CONFIG_ENABLE_SD
#include "sdcard.h"
#include "sdlog.h"
#include "sdpcap.h"
#endif
#ifdef CONFIG_ENABLE_TEMPERATURE
#include "temperature.h"
#endif
#include "stats.h"
#include "events_log.h"
#include "tracklog.h"
#include "inventory.h"
#include "ptlog.h"
#include "priolog.h"
#include "infolog.h"
#include "spatem.h"
#include "bt_stream.h"
#include "cpm_store.h"

#include "webserver.h"
#include "web_strings.h"
#include "webserver_priv.h"
#include "webserver_ring.h"
#include "web_tar.h"
#include "web_files.h"
#include "web_settings.h"
#include "web_system.h"
#include "web_traffic.h"
#include "web_msgdetail.h"
#include "web_msgsig.h"
#include "web_sechdr.h"
#include "web_gn.h"
#include "web_backup.h"
#include "web_trust.h"
#include "web_auth.h"
#include "web_faults.h"
#include "web_nav.h"
#include "web_rsu.h"
#include "web_fmt.h"
#include "web_start.h"
#include "web_messages.h"
#include "web_map.h"
#include "web_cpm.h"
#include "web_csrf.h"
#include "its_utf8.h"

/* Icons embedded via CMake EMBED_FILES (see main/CMakeLists.txt). */
extern const uint8_t favicon_png_start[]          asm("_binary_favicon_png_start");
extern const uint8_t favicon_png_end[]            asm("_binary_favicon_png_end");
extern const uint8_t apple_touch_icon_png_start[] asm("_binary_apple_touch_icon_png_start");
extern const uint8_t apple_touch_icon_png_end[]   asm("_binary_apple_touch_icon_png_end");
extern const uint8_t icon_192_png_start[]         asm("_binary_icon_192_png_start");
extern const uint8_t icon_192_png_end[]           asm("_binary_icon_192_png_end");
extern const uint8_t icon_512_png_start[]         asm("_binary_icon_512_png_start");
extern const uint8_t icon_512_png_end[]           asm("_binary_icon_512_png_end");
/* Separate 52 px logo for the nav bar, which draws it at 26 px. The 192 px
 * icon stays for the web-app manifest, where a browser needs that size. */
extern const uint8_t logo_52_png_start[]          asm("_binary_logo_52_png_start");
extern const uint8_t logo_52_png_end[]            asm("_binary_logo_52_png_end");
/* Vendored Leaflet (map JS library) for the /map page, embedded like the icons
 * above so the web UI stays self-contained. Only the map tile images come from
 * the internet (see S_MAP_HINT). */
extern const uint8_t leaflet_js_gz_start[]           asm("_binary_leaflet_js_gz_start");
extern const uint8_t leaflet_js_gz_end[]             asm("_binary_leaflet_js_gz_end");
extern const uint8_t leaflet_css_gz_start[]          asm("_binary_leaflet_css_gz_start");
extern const uint8_t leaflet_css_gz_end[]            asm("_binary_leaflet_css_gz_end");
/* Shared page stylesheet, out of the HTML so the browser caches it once
 * instead of re-reading it in the head of every page. */
extern const uint8_t s_css_gz_start[]                asm("_binary_s_css_gz_start");
extern const uint8_t s_css_gz_end[]                  asm("_binary_s_css_gz_end");

static const char TAG[] = "WEBSERVER";

/* Page markup is built with HTML_PRINTF from webserver_priv.h, which logs a
 * truncated buffer instead of silently serving a cut-off page. */

/* ================================================================== */
/*  Language: one slot per serving task. The texts are in            */
/*  web_strings.c, the switching stays here.                          */
/* ================================================================== */

/* Per-request language, one slot per serving task (httpd and slow worker).
 * A streaming search must not flip the language of a concurrently rendered page. */
static lang_t lang_httpd = LANG_DE;
#if CONFIG_ENABLE_SD
static lang_t lang_worker = LANG_DE;
static TaskHandle_t slow_worker_handle;
#endif

static inline lang_t *cur_lang_slot(void)
{
#if CONFIG_ENABLE_SD
    if (slow_worker_handle && xTaskGetCurrentTaskHandle() == slow_worker_handle)
        return &lang_worker;
#endif
    return &lang_httpd;
}
#define current_lang (*cur_lang_slot())

lang_t web_lang(void) { return current_lang; }

/* ================================================================== */
/*  State tracked via events                                          */
/* ================================================================== */

bool mqtt_connected_state;

static void mqtt_event_handler(void *arg, esp_event_base_t base, int32_t event_id, void *data)
{
    switch (event_id)
    {
    case MQTT_CONNECTED:
        mqtt_connected_state = true;
        break;
    case MQTT_DISCONNECTED:
        mqtt_connected_state = false;
        break;
    default:
        break;
    }
}

/* ================================================================== */
/*  NTP time synchronisation                                          */
/* ================================================================== */

/* Both sniffer paths stamp gettimeofday, which counts seconds since boot while
 * the clock is unset. Wall-clock times need this SNTP client first. */

/* Applies the configured time zone for every task, so pages, log lines and file names agree.
 * It is here because config.h stays out of web_fmt.c, so every host suite links that file
 * without a stub. */
void web_tz_reload(void)
{
    uint8_t z = FMT_ZONE_DEFAULT;
    config_get_u8(CONFIG_INDEX_TIMEZONE, &z);
    fmt_tz_set(z);
}

static bool sntp_started;

/* ESP_NETIF_SNTP_DEFAULT_CONFIG stores the hostname pointer, not a copy, and
 * the sntp_started guard keeps esp_netif_sntp_init() to a single call, so this
 * buffer must stay alive for the SNTP client's whole lifetime. A configured
 * server takes effect after a reboot, like the other network settings. */
static char ntp_server_buf[CONFIG_NTP_SERVER_BUFFER_SIZE];

/* Uptime second of the last NTP answer, plus 1, so 0 means none since boot. The SNTP callback
 * writes it in the lwIP task, and httpd reads it without a lock. That is safe for one aligned
 * word. */
static uint32_t s_ntp_sync_sec1;

static void ntp_synced(struct timeval *tv)
{
    (void)tv;
    s_ntp_sync_sec1 = (uint32_t)(esp_timer_get_time() / 1000000) + 1;
}

/* Uptime second of the first IP address, plus 1, so 0 means none yet. The fault bar waits 5
 * minutes after it before it calls the clock unset. One aligned word like s_ntp_sync_sec1,
 * because 64 bit could tear on RV32. */
static uint32_t s_ip_since_sec1;

uint32_t web_ip_age_sec(void)
{
    uint32_t t1 = s_ip_since_sec1;
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000);
    return t1 && now + 1 > t1 ? now + 1 - t1 : 0;
}

static void time_sync_event_handler(void *arg, esp_event_base_t base,
                                    int32_t event_id, void *event_data)
{
    (void)arg; (void)base; (void)event_data;

    if (event_id != APP_ETHERNET_MGMT_INTERFACE_GOT_IP)
        return;

    if (!s_ip_since_sec1)
        s_ip_since_sec1 = (uint32_t)(esp_timer_get_time() / 1000000) + 1;

    if (sntp_started)
    {
        /* Network came back: trigger a fresh resync. */
        esp_sntp_restart();
        return;
    }

    size_t ntp_size = sizeof(ntp_server_buf);
    config_get_str(CONFIG_INDEX_NTP_SERVER, ntp_server_buf, &ntp_size);

    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG(ntp_server_buf);
    /* For "last set N ago" on /system and /settings. */
    config.sync_cb = ntp_synced;
    esp_err_t err = esp_netif_sntp_init(&config);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "SNTP init failed: %s", esp_err_to_name(err));
        return;
    }
    sntp_started = true;
    ESP_LOGI(TAG, "SNTP client started (%s)", ntp_server_buf);
}

/* True once the system clock has been set from NTP. Checking the clock itself
 * is robust: sntp_get_sync_status() resets to RESET after being read once, so
 * it is not a reliable persistent "synced" flag. */
static bool time_is_synced(void)
{
    return time(NULL) > 31536000; /* > 1 year past epoch => clock has been set */
}

/* The clock in one line for /system and /settings. The system time survives a software
 * restart (RTC), so "set" and "never answered" can both be true. */
void web_clock_state(char *out, size_t cap, bool on_system)
{
    if (!cap)
        return;
    out[0] = '\0';
    bool set = web_clock_set((uint32_t)time(NULL));
    int n = 0;
    if (!set)
        n = web_addf(out, cap, n, "<span class='v-warn'>%s</span> &middot; ", T(S_CLOCK_UNSET));
    uint32_t sync1 = s_ntp_sync_sec1;
    if (sync1)
    {
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000);
        char ago[FMT_AGE_MAX];
        fmt_age(now + 1 > sync1 ? now + 1 - sync1 : 0, FMT_DUR_TWO, current_lang, ago, sizeof(ago));
        n = web_addf(out, cap, n, "%s %s", T(S_CLOCK_LAST), ago);
    }
    else
        n = web_addf(out, cap, n, "%s", T(S_CLOCK_NOANSWER));
    if (!on_system)
        return;
    /* The server in use. A newly saved one works only after a restart. The name is empty
     * until the first address. */
    char srv[sizeof(ntp_server_buf) * 6];
    html_escape(ntp_server_buf, srv, sizeof(srv));
    if (srv[0])
        n = web_addf(out, cap, n, " &middot; %s", srv);
    /* The time zone that all times on the pages use. */
    char lbl[48];
    fmt_tz_label(fmt_tz(), current_lang, lbl, sizeof(lbl));
    n = web_addf(out, cap, n, " &middot; %s %s", T(S_TZ), lbl);
    if (!set)
        web_addf(out, cap, n, " <a href='/settings?lang=%s#g-net'>%s</a>",
                 current_lang == LANG_EN ? "en" : "de", T(S_CLOCK_FIX));
}

/* ================================================================== */
/*  Received-message ring buffer                                      */
/* ================================================================== */

EXT_RAM_BSS_ATTR web_msg_entry_t msg_ring[WEB_MSG_RING_SIZE];
size_t msg_ring_head;
size_t msg_ring_count;
uint32_t msg_total_count;
/* Uptime second of the last message, biased by 1 so 0 means "none yet".
 * 32 bit keeps the lockless read on the httpd task free of torn values. */
uint32_t msg_last_sec1;
SemaphoreHandle_t msg_ring_mutex;

/* Recent-DENM tracker so /map can flag senders for ~60 s. No lock: every field
 * is a single aligned word or byte, and the data is only cosmetic. */
#define DENM_TRACK_N 32
#define DENM_RECENT_SEC 60
/* Remembers the cause as well, so a map popup can name the warning instead of
 * showing a generic marker. */
static struct { uint32_t sid; uint32_t sec; uint8_t cause, subcause; } s_denm_recent[DENM_TRACK_N];

static void denm_note(uint32_t station_id, uint8_t cause, uint8_t subcause)
{
    uint32_t now = (uint32_t)time(NULL);
    int freeslot = -1, oldest = 0;
    for (int i = 0; i < DENM_TRACK_N; i++)
    {
        if (s_denm_recent[i].sid == station_id)
        {
            s_denm_recent[i].sec = now;
            /* Keep the last cause that actually decoded. A later message that
             * fails to decode shouldn't blank a known warning. */
            if (cause) { s_denm_recent[i].cause = cause; s_denm_recent[i].subcause = subcause; }
            return;
        }
        if (s_denm_recent[i].sid == 0 && freeslot < 0) freeslot = i;
        if (s_denm_recent[i].sec < s_denm_recent[oldest].sec) oldest = i;
    }
    int slot = freeslot >= 0 ? freeslot : oldest;
    s_denm_recent[slot].sid = station_id;
    s_denm_recent[slot].sec = now;
    s_denm_recent[slot].cause = cause;
    s_denm_recent[slot].subcause = subcause;
}

/* The cause last seen from this station, 0 if none/unknown. */
static uint8_t denm_cause_of(uint32_t station_id, uint8_t *subcause)
{
    for (int i = 0; i < DENM_TRACK_N; i++)
        if (s_denm_recent[i].sid == station_id)
        {
            if (subcause) *subcause = s_denm_recent[i].subcause;
            return s_denm_recent[i].cause;
        }
    return 0;
}

static bool denm_is_recent(uint32_t station_id, uint32_t now)
{
    if (station_id == 0) return false;
    for (int i = 0; i < DENM_TRACK_N; i++)
        if (s_denm_recent[i].sid == station_id)
            return now >= s_denm_recent[i].sec &&
                   (now - s_denm_recent[i].sec) <= DENM_RECENT_SEC;
    return false;
}

msg_type_stat_t msg_type_stats[MSG_TYPE_STATS_SLOTS];
/* Counts the messages whose label no longer fits in msg_type_stats, so the row still adds up
 * to the total shown over it. Written and read under msg_ring_mutex like the table. */
uint32_t msg_type_stats_other;

static void msg_type_stats_record(const char *label)
{
    for (size_t i = 0; i < MSG_TYPE_STATS_SLOTS; i++)
    {
        if (msg_type_stats[i].label[0] == '\0')
        {
            strlcpy(msg_type_stats[i].label, label, sizeof(msg_type_stats[i].label));
            msg_type_stats[i].count = 1;
            return;
        }
        if (strcmp(msg_type_stats[i].label, label) == 0)
        {
            msg_type_stats[i].count++;
            return;
        }
    }
    /* All slots hold distinct labels. A slot that was hit exactly once holds a one-off,
     * for example a GeoNet protocol number, and gives it up. A burst of odd labels then
     * cannot push the types that keep coming out of the row. */
    for (size_t i = 0; i < MSG_TYPE_STATS_SLOTS; i++)
        if (msg_type_stats[i].count == 1)
        {
            msg_type_stats_other++;   /* the evicted single, so the row still adds up */
            strlcpy(msg_type_stats[i].label, label, sizeof(msg_type_stats[i].label));
            msg_type_stats[i].count = 1;
            return;
        }
    /* Every slot has been hit more than once. The new label is dropped, so the table cannot
     * grow without bound. Its count is kept, or the row would silently stop matching the
     * message total above it. */
    msg_type_stats_other++;
}

rate_bucket_t rate_buckets[RATE_WINDOW_SECS];

static void rate_record_packet(void)
{
    uint64_t now_sec = esp_timer_get_time() / 1000000ull;
    rate_bucket_t *b = &rate_buckets[now_sec % RATE_WINDOW_SECS];
    if (b->sec != now_sec)
    {
        b->sec = now_sec;
        b->count = 0;
    }
    b->count++;
    msg_last_sec1 = (uint32_t)now_sec + 1;
}

uint32_t rate_packets_last_minute(void)
{
    uint64_t now_sec = esp_timer_get_time() / 1000000ull;
    uint32_t sum = 0;
    for (size_t i = 0; i < RATE_WINDOW_SECS; i++)
        if (rate_buckets[i].sec != 0 && now_sec - rate_buckets[i].sec < RATE_WINDOW_SECS)
            sum += rate_buckets[i].count;
    return sum;
}

/* A stopped receiver is a choice, not a fault. Counting from the start keeps a Start click
 * from inheriting the silence before it. */
long web_rx_quiet_s(void)
{
    uint32_t start1 = sniffer_started_sec1();
    if (!sniffer_is_running() || !start1)
        return -1;
    uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000ull), last1 = msg_last_sec1;
    uint32_t from = (last1 > start1 ? last1 : start1) - 1;
    return now > from ? (long)(now - from) : 0;
}

/* s_rx_steady keeps its value through a silence, because it describes the time before the
 * silence. A site that never receives never sets it, so the fault bar does not show a fault
 * there forever. */
static volatile bool s_rx_steady;
#define RX_STEADY_MIN 10    /* minutes, set in hist_tick */

bool web_rx_steady(void) { return s_rx_steady; }

/* Kept in PSRAM, so 720 bytes of internal RAM stay free. Every field is 32 or
 * 16 bit and aligned, so no single field can tear on this RV32 part. */
EXT_RAM_BSS_ATTR hist_slot_t hist_ring[HIST_MINUTES];
uint32_t hist_count;     /* samples taken, newest at (hist_count-1)%60 */

/* Once a minute from its own timer. Reads only values that are already sampled
 * elsewhere, so webserver_handle_packet is not touched and takes no extra lock. */
static void hist_tick(void *arg)
{
    (void)arg;
    uint32_t n = hist_count + 1;
    hist_slot_t *s = &hist_ring[(n - 1) % HIST_MINUTES];
    /* Stamp voided first and written last, so a reader that catches the slot
     * mid-write sees a number matching no sample and drops it as a gap. */
    s->stamp = 0;
    HIST_BARRIER();
    s->rate = rate_packets_last_minute();
    /* A silence counts as a fault only after RX_STEADY_MIN minutes in a row with frames
     * (web_rx_steady). A minute without frames restarts the count. */
    static uint8_t s_rx_run;
    if (!sniffer_is_running())
    {
        s_rx_run = 0;
        s_rx_steady = false;
    }
    else if (s->rate)
    {
        if (s_rx_run < UINT8_MAX)
            s_rx_run++;
        s_rx_steady = s_rx_run >= RX_STEADY_MIN;
    }
    else
        s_rx_run = 0;
#ifdef CONFIG_ENABLE_TEMPERATURE
    float t = temperature_get();
    /* Same range guard as the status cell: a wild reading must not become a
     * band that flattens the whole hour. */
    s->temp_dc = (t == t && t > -100.0f && t < 200.0f)
                 ? (int16_t)(t * 10.0f + (t < 0.0f ? -0.5f : 0.5f))
                 : HIST_TEMP_NONE;
#else
    s->temp_dc = HIST_TEMP_NONE;
#endif
    HIST_BARRIER();
    s->stamp = n;
    /* Count last: it is what tells the reader the slot is worth looking at. */
    HIST_BARRIER();
    hist_count = n;
}

/* One place maps a decode result onto a message entry. The live ring and the
 * archive search share it, so their columns cannot drift apart. */
void entry_from_decoded(web_msg_entry_t *e, const its_decoded_t *d)
{
    snprintf(e->msgtype, sizeof(e->msgtype), "%s", d->label);
    e->has_position = d->has_position;
    e->lat_e7 = d->lat_e7;
    e->lon_e7 = d->lon_e7;
    e->station_id = d->station_id;
    e->has_speed = d->has_speed;
    e->speed_cmps = d->speed_cmps;
    e->length_dm = d->veh.valid ? d->veh.length_dm : 0;
    e->width_dm = d->veh.valid ? d->veh.width_dm : 0;
    memcpy(e->src_mac, d->src_mac, sizeof(e->src_mac));
    e->has_src_mac = d->has_src_mac;
    e->pt_line = d->pt_line;
    e->pt_course = d->pt_course;
    e->pt_dest = d->pt_dest;
    e->pt_point = d->pt_point;
    e->pt_train_len = d->pt_train_len;
    e->pt_request = d->pt_request;
    e->pt_priority = d->pt_priority;
    e->pt_deviation = d->pt_deviation;
    e->pt_telegram = d->pt_telegram;
    /* Only the CAM's heading. The fallback to the GN position vector needs the frame, so the
     * callers that have it (the live ring, the archive search) set it again after
     * msg_extra_from_frame. */
    e->heading_ddeg = its_gn_heading(d, NULL);
    e->has_alt = d->cam.has_alt;
    e->alt_cm = d->cam.alt_cm;
    e->has_long_accel = d->cam.has_long_accel;
    e->long_accel = d->cam.long_accel;
    e->drive_dir = d->cam.drive_dir;
    e->has_lane = d->cam.has_lane;
    e->lane = d->cam.lane;
    e->has_accel_ctrl = d->cam.has_accel_ctrl;
    e->accel_ctrl = d->cam.accel_ctrl;
    e->has_lights = d->cam.has_lights;
    e->ext_lights = d->cam.ext_lights;
    e->role = d->cam.role;
    e->embarking = d->pt_embarking;
    e->n_path = d->cam.n_path;
    memcpy(e->path_lat_e7, d->cam.path_lat_e7, sizeof(e->path_lat_e7));
    memcpy(e->path_lon_e7, d->cam.path_lon_e7, sizeof(e->path_lon_e7));
    /* Set for every frame: the ring reuses its slots. */
    e->spat_n = d->spat.valid ? d->spat.n : 0;
    e->spat_green = 0;
    for (uint8_t i = 0; i < e->spat_n && i < ITS_SPAT_MAX_SG; i++)
        if (spatem_phase_is_green(d->spat.phase[i]))
            e->spat_green++;
}

/* The verify task calls this after each check. The result reaches the listed copy only while
 * that copy is in the ring (20 frames, under a second at 30 a second). A later result shows
 * per certificate and on /trust. */
static void msgsig_sink(uint32_t serial, uint8_t state, uint8_t why)
{
    if (!msg_ring_mutex || xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(100)) != pdTRUE)
        return;
    for (size_t i = 0; i < WEB_MSG_RING_SIZE; i++)
    {
        its_msgsig_t *m = &msg_ring[i].extra.msgsig;
        if (m->state == ITS_MSGSIG_PENDING && m->serial == serial)
        {
            m->state = state;
            m->why = why;
        }
    }
    xSemaphoreGive(msg_ring_mutex);
}

void webserver_handle_packet(sniffer_packet_info_t *packet)
{
    if (!msg_ring_mutex)
        return;
    if (xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(10)) != pdTRUE)
        return;

    web_msg_entry_t *e = &msg_ring[msg_ring_head];
    /* Prefer real wall-clock time once NTP has synced, so /messages shows
     * HH:MM:SS. Before sync (or if it never happens) fall back to the packet's
     * own timestamp: both sniffer paths stamp gettimeofday, which before sync
     * counts seconds since boot, not epoch. */
    if (time_is_synced())
    {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        e->seconds = (uint32_t)tv.tv_sec;
        e->microseconds = (uint32_t)tv.tv_usec;
    }
    else
    {
        e->seconds = packet->seconds;
        e->microseconds = packet->microseconds;
    }
    e->length = packet->length;
    e->rssi = packet->rssi;
    /* Decode the whole frame, not a short prefix: the BTP header of a CAM or
     * DENM comes after the 802.11, GeoNetworking and security headers. */
    /* Static, because the sniffer task has a 4 KB stack. Only that task calls this
     * function, and it holds msg_ring_mutex while it does. */
    static EXT_RAM_BSS_ATTR its_decoded_t d;
    static EXT_RAM_BSS_ATTR msg_extra_scratch_t xs;
    its_decode_frame(packet->payload, packet->length, &d);
    entry_from_decoded(e, &d);
    msg_extra_from_frame(&e->extra, packet->payload, packet->length, &d, true, e->seconds, &xs);
    /* Check the signature of the message itself, for a sample of the frames. When this frame
     * was not signed, xs.sec still holds an earlier one. its_msgsig_note reads xs.sec only when
     * the signer kind of this frame says signed. */
    its_msgsig_note(packet->payload, packet->length, &xs.sec, &e->extra.sig, xs.pdu_station,
                    d.station_type, its_msg_kind(d.pdu_version, d.message_id), e->seconds,
                    &e->extra.msgsig);
    /* Pass the reception stamp, because e->seconds may be when the frame left the queue. */
    its_sechdr_note_rx(&e->extra.sechdr, packet->seconds, packet->microseconds);
    its_gn_note_rx(&e->extra.gn, packet->seconds, packet->microseconds);
    /* Set after msg_extra_from_frame has read the GN headers and before tracklog_note keeps
     * the heading. The CAM's heading wins, else the position vector's. srch_cb and the playback
     * use the same rule. */
    e->heading_ddeg = its_gn_heading(&d, &e->extra.gn);
    uint8_t st_code = d.station_type, msg_id = d.message_id;
    msg_type_stats_record(e->msgtype);
    tstat_note(st_code, e->station_id, msg_id, e->has_speed, e->speed_cmps);
    inventory_note(e->seconds, e->rssi, &d, &e->extra);
    /* The objects and areas for the map layer, from the decode msg_extra_from_frame just ran. */
    if (e->extra.cpm.read)
        cpm_store_note_frame(packet->payload, packet->length, &d, &e->extra.cpm, xs.cpm_all,
                             xs.cpm_all_n);
    ptlog_note(e->seconds, e->station_id, &d);
    /* Priority requests and the light's answers. The summary is already in e->extra,
     * decoded for the permission check, so this costs one call and no second decode. */
    priolog_note(e->seconds, e->station_id, &e->extra.prio);
    /* The newest CPM, EVCSN, POIM and RTCMEM per sender, for /traffic and the SD card logs. */
    infolog_note(e->seconds, e->rssi, d.has_src_mac ? d.src_mac : NULL, &d, &e->extra,
                 xs.pdu_station);
    /* Log the hazard where it IS, not where the sender is -- the DENM's own
     * eventPosition when it carried one, the sender's position otherwise. */
    /* station_id comes only with a position. Without one the ActionID supplies
     * the originator, because a 0 would fold unrelated senders into one row. */
    events_note(e->seconds, st_code,
                e->station_id ? e->station_id : d.denm_station, e->rssi,
                msg_id, d.denm_cause, d.denm_subcause,
                d.denm_station, d.denm_seq,
                d.has_denm_pos || e->has_position,
                d.has_denm_pos ? d.denm_lat_e7 : e->lat_e7,
                d.has_denm_pos ? d.denm_lon_e7 : e->lon_e7,
                d.has_src_mac ? d.src_mac : NULL, &d, &e->extra.gn);
    /* Vehicle track for the map overlay. Skipped internally when disabled,
     * for RSUs, and for a vehicle that hasn't moved far enough yet. */
    if (e->has_position)
    {
        /* Heading, length, role and lane go into the track row as well. With them the path
         * becomes a track with a direction instead of a cloud of points. Each field has its
         * own value for "missing". */
        track_extra_t tx = {
            .heading_ddeg = e->heading_ddeg,
            .len_dm = e->length_dm,
            .role = e->role,
            .lane = e->has_lane ? e->lane : TRACK_NO_LANE,
        };
        tracklog_note(e->seconds, e->station_id, st_code, e->lat_e7, e->lon_e7, &tx);
    }

    if (d.spat.valid)
        spatem_note(&d.spat, e->station_id, e->seconds, e->has_position, e->lat_e7, e->lon_e7);
    if (d.map.valid)
    {
        spatem_note_name(&d.map, d.map_has_alt, d.map_alt_cm, e->seconds);
        /* Returns immediately once this intersection's revision is cached,
         * so the full geometry walk runs once, not on every MAPEM. */
        spatem_note_geometry(packet->payload, packet->length, &d.map);
    }
    if (msg_id == 1 /* DENM */ && e->has_position)
        denm_note(e->station_id, d.denm_cause, d.denm_subcause);

    msg_ring_head = (msg_ring_head + 1) % WEB_MSG_RING_SIZE;
    if (msg_ring_count < WEB_MSG_RING_SIZE)
        msg_ring_count++;
    msg_total_count++;

    rate_record_packet();
    xSemaphoreGive(msg_ring_mutex);
}

/* ================================================================== */
/*  Helpers: formatting                                               */
/* ================================================================== */

/* "Xd Xh Xm Xs", only for the uptime field of /status.json and /system.json. Programs that
 * read these endpoints parse this spelling, and the README promises to keep it. Pages use
 * fmt_dur(). */
void format_uptime(uint64_t total_sec, char *out, size_t out_size)
{
    uint32_t days = total_sec / 86400;
    uint32_t hours = (total_sec % 86400) / 3600;
    uint32_t mins = (total_sec % 3600) / 60;
    uint32_t secs = total_sec % 60;

    if (days)
        snprintf(out, out_size, "%lud %luh %lum %lus",
                 (unsigned long)days, (unsigned long)hours,
                 (unsigned long)mins, (unsigned long)secs);
    else if (hours)
        snprintf(out, out_size, "%luh %lum %lus",
                 (unsigned long)hours, (unsigned long)mins, (unsigned long)secs);
    else if (mins)
        snprintf(out, out_size, "%lum %lus", (unsigned long)mins, (unsigned long)secs);
    else
        snprintf(out, out_size, "%lus", (unsigned long)secs);
}

/* Threshold -> CSS class (see .v-* in s.css). One place, so two pages
 * showing the same value cannot end up disagreeing about its colour. */
const char *lvl_class(unsigned v, unsigned warn, unsigned alarm)
{
    if (v >= alarm) return "v-bad";
    if (v >= warn)  return "v-warn";
    return "";
}

#if CONFIG_ENABLE_SD
/* total/free may be NULL. If nothing is mounted and no mount ever failed,
 * somebody unmounted on purpose: sdcard_unmount() leaves the error at OK. */
sd_state_t sd_state(uint64_t *total, uint64_t *freeb)
{
    if (!sdcard_is_mounted())
    {
        if (sdcard_taken_out())
            return SDST_WRITE_FAILED;
        esp_err_t e = sdcard_last_mount_error();
        return e == ESP_OK   ? SDST_UNMOUNTED
             : e == ESP_FAIL ? SDST_NO_FS
                             : SDST_NO_CARD;
    }
    uint64_t t = 0, f = 0;
    esp_err_t e = sdcard_usage(&t, &f);
    if (total) *total = t;
    if (freeb) *freeb = f;
    return (e == ESP_OK && t) ? SDST_OK : SDST_NO_USAGE;
}
#endif

/* Appends at `at`. The result stays below cap, so a chain of calls cannot run past the buffer. */
int web_addf(char *buf, size_t cap, int at, const char *fmt, ...)
{
    if (cap == 0)
        return 0;
    if (at < 0)
        at = 0;
    if ((size_t)at >= cap - 1)
    {
        buf[cap - 1] = '\0';          /* full: ends the text here, whoever wrote before */
        return (int)cap - 1;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf + at, cap - (size_t)at, fmt, ap);
    va_end(ap);
    if (n < 0)
        return at;
    if ((size_t)at + (size_t)n >= cap)
    {
        ESP_LOGE(TAG, "text cut at %d of %u bytes (the piece had %d)", at, (unsigned)cap, n);
        return (int)cap - 1;
    }
    return at + n;
}

void web_send_parts(httpd_req_t *req, ...)
{
    va_list ap;
    va_start(ap, req);
    for (const char *s = va_arg(ap, const char *); s; s = va_arg(ap, const char *))
        if (*s)
            httpd_resp_send_chunk(req, s, HTTPD_RESP_USE_STRLEN);
    va_end(ap);
}

void web_send_unlinked(httpd_req_t *req, const char *text)
{
    const char *p = text;
    while (*p)
    {
        const char *a = strstr(p, "<a "), *e = strstr(p, "</a>");
        const char *tag = a && (!e || a < e) ? a : e;
        const char *gt = tag == a && a ? strchr(a, '>') : NULL;
        /* No tag is left, or an opening tag lacks its '>'. Send the rest as it is. */
        if (!tag || (tag == a && !gt))
        {
            httpd_resp_send_chunk(req, p, HTTPD_RESP_USE_STRLEN);
            return;
        }
        /* Never a chunk of length 0: it would end the response. */
        if (tag > p)
            httpd_resp_send_chunk(req, p, tag - p);
        p = tag == a ? gt + 1 : e + 4;
    }
}

/* Minimal HTML escaping for user-writable config values. */
void html_escape(const char *in, char *out, size_t out_size)
{
    size_t o = 0;
    for (; *in != '\0'; in++)
    {
        const char *rep;
        char single[2] = { *in, '\0' };
        switch (*in)
        {
        case '<':  rep = "&lt;";   break;
        case '>':  rep = "&gt;";   break;
        case '&':  rep = "&amp;";  break;
        case '"':  rep = "&quot;"; break;
        case '\'': rep = "&#39;";  break;
        default:   rep = single;   break;
        }
        size_t rep_len = strlen(rep);
        if (o + rep_len + 1 > out_size)
            break;
        memcpy(out + o, rep, rep_len);
        o += rep_len;
    }
    out[o] = '\0';
}

/* A node ID may hold anything the form accepted, and one bad byte would break the
 * /status.json poll of the start page and of every peer page. Keeps whole valid UTF-8
 * characters, escapes quote and backslash, and drops broken bytes and every character
 * its_utf8_unshown() names. Never cuts inside a character. The output is at most twice the
 * input. */
static void json_esc(const char *in, char *out, size_t cap)
{
    size_t o = 0;
    if (!cap)
        return;
    while (*in)
    {
        const uint8_t *u = (const uint8_t *)in;
        uint8_t lo, hi;
        size_t w = its_utf8_lead(u[0], &lo, &hi);
        bool ok = w > 0;
        /* The NUL at the end fails the bounds, so this never reads past the string. */
        for (size_t j = 1; ok && j < w; j++)
            if (u[j] < (j == 1 ? lo : 0x80) || u[j] > (j == 1 ? hi : 0xBF))
                ok = false;
        if (!ok || its_utf8_unshown(its_utf8_cp(u, w)))
        {
            in += ok ? w : 1;
            continue;
        }
        size_t need = (w == 1 && (*in == '"' || *in == '\\')) ? 2 : w;
        if (o + need + 1 > cap)
            break;
        if (need == 2 && w == 1)
            out[o++] = '\\';
        memcpy(out + o, in, w);
        o += w;
        in += w;
    }
    out[o] = '\0';
}

void web_json_esc(const char *in, char *out, size_t cap) { json_esc(in, out, cap); }

/* URL-decode in place (handles %XX and +). */
void url_decode(char *s)
{
    char *out = s;
    for (char *in = s; *in; in++)
    {
        if (*in == '%' && in[1] && in[2])
        {
            char hex[3] = { in[1], in[2], 0 };
            *out++ = (char)strtol(hex, NULL, 16);
            in += 2;
        }
        else if (*in == '+')
            *out++ = ' ';
        else
            *out++ = *in;
    }
    *out = '\0';
}

/* esp-idf v6.1 copies nothing when the query does not fit (httpd_parse.c), so a cut buffer
 * held stack garbage. This keeps the head of the query, where the pages put lang= and chk=1. */
static esp_err_t url_query_head(httpd_req_t *req, char *buf, size_t cap)
{
    esp_err_t r = httpd_req_get_url_query_str(req, buf, cap);
    if (r == ESP_ERR_HTTPD_RESULT_TRUNC)
    {
        const char *q = strchr(req->uri, '?');
        strlcpy(buf, q ? q + 1 : "", cap);
    }
    return r;
}

/* A page load (a GET that accepts HTML) gets a readable page. fetch() keeps the short reply,
 * which its script replaces. A future fetch() that sends Accept text/html would get HTML.
 * resolve_language() asks this too, because only a page load follows the browser's
 * language. */
static bool wants_page(httpd_req_t *req)
{
    if (req->method != HTTP_GET)
        return false;
#if CONFIG_ENABLE_SD
    /* header[] and the other page statics belong to the httpd task. */
    if (slow_worker_handle && xTaskGetCurrentTaskHandle() == slow_worker_handle)
        return false;
#endif
    /* Browsers put text/html first, so a cut header still carries it. */
    char acc[160];
    esp_err_t r = httpd_req_get_hdr_value_str(req, "Accept", acc, sizeof(acc));
    return (r == ESP_OK || r == ESP_ERR_HTTPD_RESULT_TRUNC) && strstr(acc, "text/html");
}

/* True when the browser names a first language other than German. de, de-AT and de_CH are
 * German. No header, an empty one or * keep German. Only the first tag counts, so 16 bytes
 * are enough. noinline keeps al[] and the Accept buffer out of the callers' frames. */
static __attribute__((noinline)) bool browser_wants_english(httpd_req_t *req)
{
    if (!wants_page(req))
        return false;
    char al[16];
    esp_err_t r = httpd_req_get_hdr_value_str(req, "Accept-Language", al, sizeof(al));
    if (r != ESP_OK && r != ESP_ERR_HTTPD_RESULT_TRUNC)
        return false;
    const char *p = al + strspn(al, " \t");
    int c0 = (unsigned char)p[0] | 0x20;
    if (c0 < 'a' || c0 > 'z')
        return false;
    if (c0 != 'd' || ((unsigned char)p[1] | 0x20) != 'e')
        return true;
    /* p[2] is read only after two letters, so never past al[15]. A third letter is another tag. */
    int c2 = (unsigned char)p[2] | 0x20;
    return c2 >= 'a' && c2 <= 'z';
}

/* Sets the language of this request. ?lang= wins: en is English, any other value German. The
 * flags and links put it first. Without it a page load follows the browser. fetch(), JSON,
 * POSTs and the slow worker stay German, as external programs and the page scripts expect. */
void resolve_language(httpd_req_t *req)
{
    current_lang = LANG_DE;
    /* 512, not the full 4096 URI limit, which would not fit the httpd stack. A truncated
     * query still carries lang=, because the flag links put it first. */
    char query[512];
    char val[8];
    esp_err_t qr = url_query_head(req, query, sizeof(query));
    if (qr == ESP_OK || qr == ESP_ERR_HTTPD_RESULT_TRUNC)
    {
        esp_err_t kr = httpd_query_key_value(query, "lang", val, sizeof(val));
        /* A lang= too long for val is still the reader's word, just not en. */
        if (kr == ESP_OK || kr == ESP_ERR_HTTPD_RESULT_TRUNC)
        {
            if (kr == ESP_OK && strcmp(val, "en") == 0)
                current_lang = LANG_EN;
            return;
        }
    }
    if (browser_wants_english(req))
        current_lang = LANG_EN;
}

/* ================================================================== */
/*  Shared HTML chrome                                                */
/* ================================================================== */

static const char PAGE_HEADER_FMT[] =
    "<!DOCTYPE html><html lang='%s'><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    /* From the text table like every other visible text, so the German page gets a German
     * description. The attribute is single-quoted, so the text must hold no apostrophe. */
    "<meta name='description' content='%s'>"
    /* ?v= busts the browser's aggressive per-origin favicon cache. Bump it
     * whenever the icon changes. */
    "<link rel='icon' href='/favicon.png?v=2' type='image/png'>"
    "<link rel='apple-touch-icon' sizes='180x180' href='/apple-touch-icon.png?v=2'>"
    "<link rel='manifest' href='/manifest.webmanifest'>"
    "<meta name='theme-color' content='#f2b134'>"
    "<meta name='apple-mobile-web-app-capable' content='yes'>"
    "<meta name='apple-mobile-web-app-status-bar-style' content='black-translucent'>"
    "<meta name='apple-mobile-web-app-title' content='%s'>"
    "%s"  /* optional auto-refresh script */
    /* The language picked with a flag, kept per browser. A page opened without lang= reloads
     * itself once with that choice. With lang= in the address nothing happens, so it cannot
     * loop. */
    "<script>try{var l=localStorage.getItem('lang'),s=location.search;"
    "if((l==='de'||l==='en')&&l!==document.documentElement.lang&&!/[?&]lang=/.test(s))"
    "location.replace('?lang='+l+(s.length>1?'&'+s.slice(1):'')+location.hash);}catch(e){}</script>"
    /* Before the stylesheet, so the explanations never flash up and vanish. They are hidden
     * unless this browser chose otherwise, and a browser without storage gets them hidden too.
     * The pause state is set here as well, so the live switch never shows the wrong sign. */
    "<script>(function(){var h=1,p=0;try{h=localStorage.getItem('hlp')!=='1';"
    "p=localStorage.getItem('ar')==='0';}catch(e){}"
    "if(h)document.documentElement.classList.add('nohelp');"
    "if(p)document.documentElement.classList.add('arpause');})();</script>"
    /* The stylesheet is served from /s.css. ?v= is the ELF hash prefix, so every new build
     * gets a fresh, uncached URL, not just a version bump. */
    "<link rel='stylesheet' href='/s.css?v=%s'>"
    /* The connection bar, empty on pages that neither poll nor stream. It comes before .wrap,
     * so it spans the width and sticks at the top. */
    "<title>%s</title></head><body>%s<div class='wrap'>"
    /* Context line above the nav: weekday, date, clock, node. With auto-refresh
     * the clock stays current. Without it the clock names the load time, which
     * shows how old the figures below are. */
    "%s"
    "<nav>"
    /* Logo (Tokyo-tower app icon), a link to the start page. Outside .navlinks, so it is
     * never taken for the Status group. */
    "<a class='logo' href='/?lang=%s'><img src='/logo.png' alt='ITS G5' height='26' width='26'></a>"
    /* Hidden checkbox + label = the CSS-only hamburger toggle (see the .brgr
     * / .nvt rules). Placed before .navlinks so the ".nvt:checked~.navlinks"
     * sibling selector can reveal it. &#9776; = the hamburger glyph. data-pg names the
     * group of this page for the phone bar. */
    "<input type='checkbox' id='nvt' class='nvt'>"
    "<label for='nvt' class='brgr' aria-label='%s' data-pg='%s'>&#9776;</label>"
    /* The four groups (.navlinks) and the tab row of this page's group (.subnav) come from
     * web_nav.c; .lang stays a separate flex item, anchored top-right from 641px. */
    "%s"
    /* Flag toggle (Austria/UK), current language highlighted. The flags are HTML
     * numeric entities (regional indicator symbols), not raw UTF-8 in the C source. */
    /* The live switch on pages that can pause their poll or stream. Pages that neither poll
     * nor stream get the reload button of the home-screen app here instead. */
    "<span class='lang'>%s"
    /* The explanation switch shares the pill with the flags, because both are reader choices
     * that hold on every page. It names its state. Both texts are sent, and CSS shows one. */
    "<button type='button' id='hlpb' class='hlpb' title='%s' aria-pressed='false'>&#9432;"
    "<span class='h0'> %s</span><span class='h1'> %s</span></button>"
    "<a href='?lang=de' class='%s' title='Deutsch'>&#127462;&#127481;</a>"
    "<a href='?lang=en' class='%s' title='English'>&#127468;&#127463;</a>"
    "</span></nav>"
    /* Sent with the page header, not the footer: the flags are clickable long
     * before the page finishes streaming, and until this runs they drop the query. */
    "<script>var lq=location.search.replace(/^\\?/,'').split('&').filter(function(s){"
    "return s&&s.indexOf('=')>0&&s.slice(0,5).toLowerCase()!=='lang=';});"
    "document.querySelectorAll('nav .lang a').forEach(function(a){var c=a.getAttribute('href').slice(-2);"
    /* lang= first, not last: resolve_language reads only the first 511 bytes
     * of the query, and a long one would push it out of reach. */
    "a.setAttribute('href','?'+['lang='+c].concat(lq).join('&')+location.hash);"
    /* The flag also remembers the choice for this browser. The head script reads it. */
    "a.onclick=function(){try{localStorage.setItem('lang',c);}catch(e){}};});"
    /* The choice is kept per browser, so every page and every later visit follows it. */
    "(function(){var d=document.documentElement,b=document.getElementById('hlpb');"
    "function u(){b.setAttribute('aria-pressed',d.classList.contains('nohelp')?'false':'true');}"
    /* Amber ring until this browser has used the switch once. Without storage there is
     * none, or it would never go away. */
    "try{if(localStorage.getItem('hlp')===null)b.classList.add('hlpnew');}catch(e){}"
    "u();b.onclick=function(){d.classList.toggle('nohelp');b.classList.remove('hlpnew');"
    "try{localStorage.setItem('hlp',d.classList.contains('nohelp')?'0':'1');}catch(e){}u();};})();"
    "</script>"
    /* <main> around the page body, closed in PAGE_FOOTER. The nav stays
     * outside it, and no CSS rule targets main, so nothing moves. */
    "<main><h1>%s</h1>";

const char PAGE_FOOTER[] =
    "</main>"
    /* Deliberately no (c): the tree carries third-party parts (see NOTICE),
     * a blanket claim would overreach. Name and source link only. */
    "<div class='foot'><a href='https://codeberg.org/datom/its-g5-receiver-firmware-webinterface'"
    " target='_blank' rel='noopener'>datom &middot; Codeberg</a></div>"
    /* The active group and page come marked from the server (web_nav.c). */
    "<script>"
    /* Phone only: underlines the chip of the section in view. The sections are looked up by
     * id on every scroll, because /traffic swaps its sections every few seconds. The row
     * scrolls only when another chip lights up, so a scroll does not undo a swipe of the row. */
    "(function(){var as=[].slice.call(document.querySelectorAll('.jump a[href^=\"#\"]'));"
    "if(!as.length)return;var q=0,lc=null;function f(){q=0;var c=null,e=document.documentElement;"
    "as.forEach(function(a){var g=document.getElementById(a.getAttribute('href').slice(1));"
    "if(g&&g.getBoundingClientRect().top<innerHeight/3)c=a;});"
    "if(c&&innerHeight+scrollY>=e.scrollHeight-4)c=as[as.length-1];"
    "as.forEach(function(a){a.classList.toggle('on',a===c);});"
    "if(c&&c!==lc){lc=c;c.parentNode.scrollLeft=c.offsetLeft-8;}}"
    "addEventListener('scroll',function(){if(!q){q=1;requestAnimationFrame(f);}},{passive:true});f();})();"
    /* Shared reboot: poll until the device answers, then reload. First poll
     * delayed so a not-yet-rebooted device cannot "succeed". */
    /* (ask, msg, slow, denied), in the order the callers pass them. */
    /* Returns a promise: false means no restart was started, and the caller
     * has to undo whatever it did in anticipation (a disabled button). */
    "window.itsReboot=function(ask,msg,slow,denied){"
    "if(ask&&!confirm(ask))return Promise.resolve(false);"
    /* r.ok first: /reboot is password-gated, and a refused request must not
     * look like a running restart. */
    "function w(){"
    "document.body.innerHTML=\"<div class='wrap'><p id='itsrb'></p></div>\";"
    "var t0=Date.now(),e=document.getElementById('itsrb');"
    "e.innerHTML=msg;"   /* entities, not textContent */
    "setTimeout(function(){var iv=setInterval(function(){"
    "var n=Math.round((Date.now()-t0)/1000);"
    /* Bounded: without this the page counts up forever on a device that never
     * comes back, and the operator has nothing but a growing number. */
    "if(n>120){clearInterval(iv);e.innerHTML=slow;return;}"
    "e.innerHTML=msg+' ('+n+' s)';"
    "fetch('/favicon.png?x='+Date.now(),{cache:'no-store'}).then(function(ok){"
    "if(!ok.ok)return;clearInterval(iv);location.reload();}).catch(function(){});"
    "},2000);},6000);}"
    /* A POST that dies in flight usually means the device restarted before it
     * could answer -- so wait either way rather than leaving a dead page. */
    "return fetch('/reboot?lang='+document.documentElement.lang,{method:'POST'}).then(function(r){"
    /* A 403 is the refusal of web_csrf.c, for example behind a proxy that rewrites Host. Its
     * text names the cause, and a password would not help. ?lang= above picks its language. */
    "if(r.status==403)return r.text().then(function(t){alert(t);return false;},"
    "function(){alert(r.status+' '+r.statusText);return false;});"
    "if(!r.ok){alert(denied);return false;}w();return true;})"
    ".catch(function(){w();return true;});};"
    "</script>"
    "</div></body></html>";

/* Watches the live pages and marks a page stale when no answer came in time. */
static const char LINK_SCRIPT[] =
    "<script>(function(){var d=document.documentElement,last=Date.now(),due=last,lim=0,pz=0,iv=0,"
    "act=0,cb=[];"
    /* Read here too: a page without the head script still pauses. */
    "try{if(localStorage.getItem('ar')==='0')d.classList.add('arpause');}catch(e){}"
    "function pa(){return d.classList.contains('arpause');}"
    /* A list redrawn under the thumb loses the reader's place. The listeners use the capture
     * phase, so a table scrolled sideways counts too. */
    "['scroll','pointerdown','keydown','input'].forEach(function(t){"
    "window.addEventListener(t,function(){act=Date.now();},{passive:true,capture:true});});"
    "document.addEventListener('selectionchange',function(){act=Date.now();});"
    /* The live switch in the header has one state for every page, kept as 'ar'. */
    "window.itsLive={paused:pa,on:function(f){cb.push(f);},idle:function(){return Date.now()-act;}};"
    "var lb=document.getElementById('lvb');"
    "function lu(){if(lb)lb.setAttribute('aria-pressed',pa()?'false':'true');}lu();"
    "if(lb)lb.onclick=function(){d.classList.toggle('arpause');var p=pa();"
    "try{localStorage.setItem('ar',p?'0':'1');}catch(e){}lu();due=Date.now();"
    "cb.forEach(function(f){f(p);});};"
    /* Time-based, so a fetch that hangs counts too. A paused poll never shows the bar. */
    "function chk(){if(!lim||document.hidden)return;"
    "if(pz&&pa()){due=Date.now();d.classList.remove('stale');return;}"
    "if(d.classList.contains('stale')||Date.now()-Math.max(last,due)<=lim)return;"
    /* The time of the last answer in device time (itsTz). */
    "var e=document.getElementById('stlt');"
    "if(e)e.textContent=itsTz.hm(last);d.classList.add('stale');}"
    "window.itsWatch=function(ms,usesPause){lim=ms;pz=usesPause?1:0;due=Date.now();"
    "if(!iv)iv=setInterval(chk,1000);};"
    /* Only the fault bar, from a JSON with probs_html or a fetched page with #probs. It is no
     * sign of life, because the /faults.json poll says nothing about the page's own stream. */
    "window.itsProbs=function(j){if(!j)return;"
    "var e=document.getElementById('probs'),h;if(!e)return;"
    "if(j.getElementById){var n=j.getElementById('probs');if(!n)return;h=n.innerHTML;}"
    "else h=j.probs_html;if(typeof h==='string'){e.innerHTML=h;e.hidden=!h;}};"
    /* A sign of life, and the fault bar when the answer carries it. */
    "window.itsSeen=function(j){last=due=Date.now();d.classList.remove('stale');if(j)itsProbs(j);};"
    /* A tab back from the background gets a fresh window: its timers were frozen. */
    "document.addEventListener('visibilitychange',function(){if(!document.hidden)due=Date.now();});"
    "})();</script>";

/* The fault bar of /map and /messages, because their WebSocket carries no faults. It calls
 * itsProbs, not itsSeen, so a dead stream still turns stale while HTTP answers. Needs
 * LINK_SCRIPT (live). */
const char FAULT_POLL_JS[] =
    "<script>(function(){if(!window.itsProbs)return;"
    "var u='/faults.json?lang='+(document.documentElement.lang==='en'?'en':'de');"
    /* A page with the live switch (/messages) waits while paused: a new bar line would move the
     * list being read. It asks once when resumed. /map has no switch and always asks. */
    "var lv=window.itsLive&&document.getElementById('lvb');"
    "function f(){if(document.hidden||(lv&&itsLive.paused()))return;fetch(u,{cache:'no-store'})"
    ".then(function(r){return r.ok?r.json():null;}).then(itsProbs).catch(function(){});}"
    /* Every 30 s, and once when the tab comes back: hidden tabs do not ask. */
    "setInterval(f,30000);document.addEventListener('visibilitychange',f);"
    "if(lv)itsLive.on(function(p){if(!p)f();});"
    "})();</script>";

/* The banner goes on every page, not just the start page: an unconfirmed update rolls back at
 * the next reboot, or after 30 minutes when the timer runs, and whoever lands elsewhere would
 * never see it. The same place carries the notice after a failed update. noinline, because if
 * it were inlined, its locals would add to the frame of page_header, which on /map is part of
 * the deepest stack path of httpd. */
static __attribute__((noinline)) void send_ota_banner(httpd_req_t *req)
{
    /* The POSTs have no query string of their own. Without ?lang= here,
     * resolve_language() on those requests defaults to German. */
    const char *lc = current_lang == LANG_DE ? "de" : "en";
    if (!ota_is_pending_verify())
    {
        /* Pending and failed never hold at once: while pending, the other slot is the old
         * valid firmware. */
        ota_failed_t f;
        if (!ota_failed_get(&f) || f.acked)
            return;
        /* The slot can hold any image, so its version is not our text. 186 of 192. */
        char fver[192];
        html_escape(f.version, fver, sizeof(fver));
        /* 411 of 512 (German, both versions at their widest). */
        static EXT_RAM_BSS_ATTR char ftext[512];
        snprintf(ftext, sizeof(ftext), T(f.aborted ? S_UPD_FAILED_ABORT : S_UPD_FAILED_INVALID),
                 fver, esp_app_get_description()->version);
        /* 1024 against 926 measured (German). The box is removed instead of
         * reloading, so /settings keeps unsaved edits. */
        static EXT_RAM_BSS_ATTR char alarm[1024];
        HTML_PRINTF(alarm,
            "<div class='alarm'><p>%s</p>"
            "<button onclick=\"var e=this.parentNode;"
            "fetch('/update/ack?lang=%s',{method:'POST'}).then(function(r){"
            "if(r.status===401){alert('%s');return;}"
            "if(r.status===403){r.text().then(alert);return;}if(r.ok)e.remove();})"
            ".catch(function(){alert('%s');})\">%s</button></div>",
            ftext, lc, T(S_UPD_HIDE_DENIED), T(S_UPD_HIDE_NOCONN), T(S_UPD_FAILED_HIDE));
        httpd_resp_send_chunk(req, alarm, HTTPD_RESP_USE_STRLEN);
        return;
    }
    /* Text and number from one reading: the timer can run out between two calls. */
    int64_t left = ota_rollback_left_us();
    /* 356 and 195 of their sizes (German). */
    static EXT_RAM_BSS_ATTR char ctext[512];
    static EXT_RAM_BSS_ATTR char tick[256];
    tick[0] = '\0';
    if (left >= 0)
    {
        unsigned long mins = (unsigned long)((left + 59999999) / 60000000);
        char minel[48];     /* 29 at most */
        snprintf(minel, sizeof(minel), "<b id='otamin'>%lu</b>", mins);
        /* The table text is the format, like S_SD_USED_OF. */
        snprintf(ctext, sizeof(ctext), T(S_CONFIRM_NEEDED), minel);
        /* Counts against the browser clock, so the number never goes stale on an open page. */
        snprintf(tick, sizeof(tick),
            "<script>(function(){var e=document.getElementById('otamin'),t=Date.now()+%lu;"
            "setInterval(function(){var m=Math.ceil((t-Date.now())/60000);"
            "if(e)e.textContent=m>0?m:0;},20000);})();</script>",
            (unsigned long)(left / 1000));
    }
    else
        snprintf(ctext, sizeof(ctext), "%s", T(S_CONFIRM_NEEDED_NT));
    /* 2048: 1312 measured in German (confirm text with the minutes, alerts, button, countdown
     * script), 1527 with ctext and tick at full size. A cut would break the script; PSRAM. */
    static EXT_RAM_BSS_ATTR char banner[2048];
    HTML_PRINTF(banner,
        "<div class='warn'><p>%s</p>"
        /* The banner appears on /settings too, where a reload would drop unsaved
         * edits. The guard also works on pages that define no ITS_UNSAVED_LEAVE. */
        "<button onclick=\"if(document.body.classList.contains('dirty')&&"
        "typeof ITS_UNSAVED_LEAVE!=='undefined'&&!confirm(ITS_UNSAVED_LEAVE))return;"
        "fetch('/confirm?lang=%s',{method:'POST'}).then(function(r){"
        "if(r.status===401){alert('%s');return null;}return r.text();})"
        /* The confirm already accepted losing the edits. Without the remove, /settings
         * would ask a second time on the reload. */
        ".then(function(t){if(t===null)return;alert(t);"
        "document.body.classList.remove('dirty');location.reload();})"
        /* Without the catch a network error left the button looking dead. */
        ".catch(function(){alert('%s');})\">%s</button>%s"
        "</div>",
        ctext, lc, T(S_CONFIRM_AUTH), T(S_CONFIRM_NOCONN), T(S_CONFIRM_BTN), tick);
    httpd_resp_send_chunk(req, banner, HTTPD_RESP_USE_STRLEN);
}

/* `json_url` enables the poll that feeds window.arApply. There is no full reload, so CSS
 * animations never restart. `live` adds the connection bar and its watcher, for pages that
 * poll or stream. Pausable pages get the live switch in the header, and `every_s` is the
 * interval it names, 0 for a stream. Pages that neither poll nor stream get the reload
 * button of the home-screen app there instead. */
static void page_header(httpd_req_t *req, const char *heading, const char *json_url, bool live,
                        bool pausable, uint32_t every_s)
{
    /* static EXT_RAM_BSS_ATTR, not a stack buffer: the httpd task has only
     * 16384 bytes of stack in total (see webserver_init). 660 of 1280 (ri at 10 digits,
     * /system.json?lang=en). */
    static EXT_RAM_BSS_ATTR char refresh_tag[1280];
    /* Static doesn't auto-reset between calls; clear explicitly so a page
     * with json_url==NULL can't inherit a previous request's script. */
    refresh_tag[0] = '\0';
    uint32_t ri = 5;
    if (json_url)
    {
        config_get_u32(CONFIG_INDEX_REFRESH_SEC, &ri);
        if (ri > 0 && ri < 0xFFFFFFFF)
            snprintf(refresh_tag, sizeof(refresh_tag),
                "<script>(function(){var ri=%lu,url='%s',t=null,lt=0;"
                "function tick(){lt=Date.now();fetch(url).then(function(r){return r.json();})"
                ".then(function(d){itsSeen(d);if(window.arApply)window.arApply(d);}).catch(function(){});}"
                /* The switch in the header (itsLive, LINK_SCRIPT) stops and restarts the poll. */
                "function run(){clearInterval(t);t=null;"
                "if(!itsLive.paused()){tick();t=setInterval(tick,ri*1000);}}"
                /* Stale after two missed polls plus 3 s. The 1 lets the live switch
                 * pause the stale check. */
                "window.addEventListener('load',function(){itsWatch(ri*2000+3000,1);run();itsLive.on(run);"
                /* Mobile browsers freeze setInterval while the screen is off. The
                 * 1 s guard is in wake(), not in tick(), so tick can still run at ri=1. */
                "function wake(){if(document.hidden||Date.now()-lt<1000)return;"
                "if(!itsLive.paused())tick();}"
                "document.addEventListener('visibilitychange',wake);"
                /* e.persisted tells a bfcache return from a normal load. A normal
                 * load already gets its tick from the load handler above. */
                "window.addEventListener('pageshow',function(e){if(e.persisted)wake();});"
                "});})();</script>",
                (unsigned long)ri, json_url);
    }
    /* A refresh interval of 0 polls nothing, so nothing can go stale. */
    if (json_url)
        live = refresh_tag[0] != '\0';
    /* The live switch, only where something can be paused: a poll that really runs, or a
     * stream page that asked for it. Live switch 273, reload button 284 of 320 (German). */
    static EXT_RAM_BSS_ATTR char livebtn[320];
    livebtn[0] = '\0';
    if (live && (json_url || pausable))
    {
        uint32_t ev = json_url ? ri : every_s;
        char every[40] = "";
        if (ev)
        {
            /* The interval in the page's duration format: 5 s, or 600 as 10 min. */
            char evs[FMT_DUR_MAX];
            fmt_dur(ev, FMT_DUR_EXACT, evs, sizeof(evs));
            snprintf(every, sizeof(every), " &middot; %s", evs);
        }
        /* &#65038; asks iOS for the text form of the sign, not an emoji. */
        HTML_PRINTF(livebtn,
            "<button type='button' id='lvb' class='lvb' title='%s' aria-pressed='true'>"
            "<b class='l0'>&#9208;&#65038;<i> %s%s</i></b>"
            "<b class='l1'>&#9654;&#65038;<i> %s</i></b></button>",
            T(S_LIVE_TIP), T(S_LIVE_ON), every, T(S_LIVE_OFF));
    }
    else if (!live && req->method == HTTP_GET)
    {
        /* The home-screen app has no reload of its own. CSS shows this button only under
         * html.pwa, which is set from navigator.standalone (iOS) or display-mode. GET only,
         * because a reload resends a form. */
        HTML_PRINTF(livebtn,
            "<button type='button' class='rlb' title='%s' aria-label='%s' onclick='location.reload()'>&#10227;</button>"
            "<script>try{if(navigator.standalone||matchMedia('(display-mode: standalone)').matches)"
            "document.documentElement.classList.add('pwa');}catch(e){}</script>",
            T(S_RELOAD_PAGE), T(S_RELOAD_PAGE));
    }

    const char *lc = current_lang == LANG_DE ? "de" : "en";
    const char *lang_de_active = (current_lang == LANG_DE) ? "active" : "";
    const char *lang_en_active = (current_lang == LANG_EN) ? "active" : "";

    /* The tab and home-screen title show the node id, so you can tell several
     * receivers apart. The nodeid is user-editable, hence HTML-escaped. */
    char nodeid_raw[CONFIG_NODEID_BUFFER_SIZE] = {0};
    size_t nodeid_raw_size = sizeof(nodeid_raw);
    config_get_str(CONFIG_INDEX_NODEID, nodeid_raw, &nodeid_raw_size);
    /* Capped at 24 chars before escaping. A tab title has no use for the full
     * 64-byte nodeid, and the cap holds header[]'s worst case (a nodeid of
     * nothing but '&') to a few hundred bytes instead of a few thousand. */
    char nodeid_disp[25];
    /* Deliberate truncation to a fixed display width. A bounded copy, not
     * snprintf("%s", ...): -Werror=format-truncation cannot tell shortening on
     * purpose from a buffer too small, and fails the build on that shape. */
    size_t nodeid_disp_len = strlen(nodeid_raw);
    if (nodeid_disp_len > sizeof(nodeid_disp) - 1)
        nodeid_disp_len = sizeof(nodeid_disp) - 1;
    memcpy(nodeid_disp, nodeid_raw, nodeid_disp_len);
    nodeid_disp[nodeid_disp_len] = '\0';
    static EXT_RAM_BSS_ATTR char nodeid_esc[sizeof(nodeid_disp) * 6];
    html_escape(nodeid_disp, nodeid_esc, sizeof(nodeid_esc));
    static EXT_RAM_BSS_ATTR char page_title[sizeof(nodeid_esc) + 16];
    if (nodeid_esc[0])
        snprintf(page_title, sizeof(page_title), "ITS G5 - %s", nodeid_esc);
    else
        snprintf(page_title, sizeof(page_title), "ITS G5 Node");

    /* /s.css cache key. The ELF hash, not the app version: a test build that
     * edits s.css without bumping version.txt must still reach the browser. */
    char css_ver[9];
    esp_app_get_elf_sha256(css_ver, sizeof(css_ver));

    char clk[80];
    fmt_clockline(clk, sizeof(clk), "&middot;", current_lang);
    static EXT_RAM_BSS_ATTR char ctxline[sizeof(nodeid_esc) + 160];
    /* Clock in its own span so a poll can replace just that part. */
    HTML_PRINTF(ctxline, "<div class='ctx'><span id='st-clk'>%s</span>%s</div>",
                clk, nodeid_esc);

    /* 123 of 320 (German); the sign comes from s.css, the time inside <b> from LINK_SCRIPT. */
    static EXT_RAM_BSS_ATTR char linkbar[320];
    linkbar[0] = '\0';
    if (live)
    {
        int ln = web_addf(linkbar, sizeof(linkbar), 0, "<div class='stale-bar' role='status'>");
        ln = web_addf(linkbar, sizeof(linkbar), ln, T(S_LINK_LOST), "<b id='stlt'></b>");
        web_addf(linkbar, sizeof(linkbar), ln, "</div>");
    }

    /* The menu from web_nav.c: 428 of 640 (German, with SD, a page of the device group).
     * Static like header[]: page_header runs on the httpd task only. */
    static EXT_RAM_BSS_ATTR char navbuf[640];
    const char *nav_pg = web_nav_build(navbuf, sizeof(navbuf), req->uri, lc);

    /* With the CSS out of the format string, -Wformat-truncation can no longer
     * bound this call. The assert does it instead: 420 = 100 for the heading, the group name
     * of the phone bar and the two language codes (measured 60), 200 for the meta description
     * plus the menu label (123), 120 for the three texts of the explanation switch (95); menu
     * and live switch count at their buffer sizes. 7168 with the language redirect and the
     * flag memory: 6168 of 7168. */
    static EXT_RAM_BSS_ATTR char header[7168];
    _Static_assert(sizeof(PAGE_HEADER_FMT) + sizeof(refresh_tag)
                   + 2 * sizeof(page_title) + sizeof(css_ver) + sizeof(ctxline)
                   + sizeof(linkbar) + sizeof(navbuf) + sizeof(livebtn) + 420 <= sizeof(header),
                   "page header worst case no longer fits");
    HTML_PRINTF(header, PAGE_HEADER_FMT,
             lc, T(S_META_DESC), page_title, refresh_tag, css_ver, page_title, linkbar, ctxline,
             lc, T(S_NAV_MENU), nav_pg, navbuf,
             livebtn,
             T(S_HELP_TIP), T(S_HELP_OFF), T(S_HELP_ON),
             lang_de_active, lang_en_active,
             heading);
    /* No other site may frame a page, because a hidden frame turns a click there into a click
     * on the buttons here (clickjacking). Every page passes here. Old browsers know only the
     * first header. */
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Content-Security-Policy", "frame-ancestors 'none'");
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send_chunk(req, header, HTTPD_RESP_USE_STRLEN);
    /* On every page, so pickers, playback clock, stale note and durations count in device
     * time, not browser time. Own chunks, so header[] is untouched. */
    /* 35 of 48. Never an empty or cut chunk: an empty one ends the page, a cut one swallows
     * it. Without ITZ the script falls back to Central Europe. */
    static EXT_RAM_BSS_ATTR char tzjs[48];
    int zn = fmt_tz_js(tzjs, sizeof(tzjs));
    if (zn > 0 && (size_t)zn < sizeof(tzjs))
        httpd_resp_send_chunk(req, tzjs, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, FMT_ZONE_JS, HTTPD_RESP_USE_STRLEN);
    /* Before any poller: the pollers start on load or at the end of the page. */
    if (live)
        httpd_resp_send_chunk(req, LINK_SCRIPT, HTTPD_RESP_USE_STRLEN);
    send_ota_banner(req);
    /* The fault bar under every page heading, after the update notice. */
    web_faults_send(req);
}

void send_page_header_refresh(httpd_req_t *req, const char *heading, const char *json_url)
{
    page_header(req, heading, json_url, true, true, 0);
}

void send_page_header_live(httpd_req_t *req, const char *heading)
{
    page_header(req, heading, NULL, true, false, 0);
}

void send_page_header_pausable(httpd_req_t *req, const char *heading, uint32_t every_s)
{
    page_header(req, heading, NULL, true, true, every_s);
}

void send_page_header(httpd_req_t *req, const char *heading)
{
    page_header(req, heading, NULL, false, false, 0);
}

#if CONFIG_HTTPD_WS_SUPPORT
/* ================================================================== */
/*  /ws -- live feed for /messages                                    */
/*                                                                    */
/*  A periodic timer (see webserver_init) queues a broadcast onto the */
/*  httpd task with httpd_queue_work, roughly once a second, but only */
/*  when the ring changed and no earlier pass still waits. ESP-IDF    */
/*  wants httpd_ws_send_frame_async called from such a queued work    */
/*  function, so building the JSON and listing the clients both       */
/*  happen there, not in the timer callback.                          */
/* ================================================================== */

static httpd_handle_t g_httpd_server;
static uint32_t ws_last_broadcast_count = UINT32_MAX;
/* One pass waiting is enough: it reads the ring when it runs. More would fill httpd's
 * control queue (CONFIG_LWIP_UDP_RECVMBOX_SIZE slots) while an upload holds the task. */
static volatile bool ws_broadcast_queued;
/* Uptime second of the waiting pass, 32 bits so the timer never tears a read. An SD hang has
 * held httpd for about 58 s, an OTA holds it for about 14 s. */
#define WS_WAIT_LOG_S 30
static volatile uint32_t ws_queued_s;
static volatile bool ws_wait_logged;
/* A pass httpd accepted but lost below it (lwIP parks or drops the loopback datagram) would stop
 * the feed for good: one more try every WS_REQUEUE_S, whose send also flushes a parked loop. */
#define WS_REQUEUE_S (2 * WS_WAIT_LOG_S)
static volatile uint32_t ws_retry_s;
#endif /* CONFIG_HTTPD_WS_SUPPORT */

/* The JSON/text builders below are shared: the WS live feed, the /messages
 * page and /markers.json (multi-receiver map) all use them, so they must
 * exist even when websocket support is compiled out. */

/* Compact JSON for the browser to turn into table rows. Short field names keep
 * the payload small: t/r/l/y/sm/h always, sn for a named roadside unit, and a/o/i
 * (lat/lon/stationId) only when a position was decoded. */

/* Emits the warning keys for a station: `d` that a warning is recent, `dt` what
 * the warning was. The text comes from our own tables and needs no escaping. */
size_t denm_json(uint32_t station_id, uint32_t now, char *out, size_t cap)
{
    if (!denm_is_recent(station_id, now))
        return 0;
    uint8_t sub = 0;
    uint8_t cause = denm_cause_of(station_id, &sub);
    const char *ct = denm_cause_text(cause);
    const char *st = denm_sub_text(cause, sub);
    /* web_addf, not snprintf: the length that comes back must be one that fit. */
    if (ct && st)
        return (size_t)web_addf(out, cap, 0, ",\"d\":1,\"dt\":\"%s (%s)\"", ct, st);
    if (ct)
        return (size_t)web_addf(out, cap, 0, ",\"d\":1,\"dt\":\"%s\"", ct);
    return (size_t)web_addf(out, cap, 0, ",\"d\":1");
}

/* Optional CAM-detail keys shared by live feed and map seed; hd also for other messages of a
 * vehicle (its_gn_heading). Short keys are crowded, so check for collisions before adding one
 * (`h` is the detail text). Every key set, in its widest form: 338 bytes, 215 of them the path. */
size_t cam_json_extra(const web_msg_entry_t *e, char *out, size_t cap)
{
    int n = 0;
    if (e->heading_ddeg != 0xFFFF)
        n = web_addf(out, cap, n, ",\"hd\":%u", (unsigned)e->heading_ddeg);
    /* Sent whenever the field was PRESENT, including all-bits-zero. Omitting
     * zero made "no pedal pressed" look identical to "this message didn't
     * carry the field", and the client -- which keeps the last known value --
     * would then hold a stale "braking" instead of clearing it. */
    if (e->has_accel_ctrl)
        n = web_addf(out, cap, n, ",\"ac\":%u", (unsigned)e->accel_ctrl);
    if (e->has_lights)
        n = web_addf(out, cap, n, ",\"el\":%u", (unsigned)e->ext_lights);
    /* Altitude in centimetres and longitudinal acceleration in 0.1 m/s^2. dd goes out only
     * for a reported backward drive, because a 0 would mean "forward" and is no hint. */
    if (e->has_alt)
        n = web_addf(out, cap, n, ",\"al\":%ld", (long)e->alt_cm);
    if (e->has_long_accel)
        n = web_addf(out, cap, n, ",\"la\":%d", (int)e->long_accel);
    if (e->drive_dir == 1)
        n = web_addf(out, cap, n, ",\"dd\":1");
    if (e->has_lane)
        n = web_addf(out, cap, n, ",\"lp\":%d", (int)e->lane);
    /* The 0 goes out too, for the same reason as ac above: the browser keeps the last value
     * per station. ITS_CAM_R[0] is the empty string, so the popup shows no role line. */
    if (e->role != 0xFF)
        n = web_addf(out, cap, n, ",\"vr\":%u", (unsigned)e->role);
    /* R09 telegram detail. `pd` is sent even when zero -- but zero means "on
     * time OR the field was not transmitted", the two are indistinguishable in
     * R09.16. The client keeps the last value per station. */
    if (e->pt_telegram && e->pt_course)
        n = web_addf(out, cap, n, ",\"pk\":%u", (unsigned)e->pt_course);
    if (e->pt_telegram && e->pt_dest)
        n = web_addf(out, cap, n, ",\"pz\":%u", (unsigned)e->pt_dest);
    if (e->pt_telegram)
        n = web_addf(out, cap, n, ",\"pd\":%d", (int)e->pt_deviation);
    if (e->embarking)
        n = web_addf(out, cap, n, ",\"eb\":1");
    /* Where the vehicle just came from, as [[lat,lon],...] in 1e-7 degrees.
     * Up to 8 points -- 215 bytes, by far the largest key here, so it goes
     * last and is skipped entirely when the sender doesn't provide one. */
    if (e->n_path)
    {
        n = web_addf(out, cap, n, ",\"ph\":[");
        for (uint8_t i = 0; i < e->n_path; i++)
            n = web_addf(out, cap, n, "%s[%ld,%ld]", i ? "," : "",
                         (long)e->path_lat_e7[i], (long)e->path_lon_e7[i]);
        n = web_addf(out, cap, n, "]");
    }
    return (size_t)n;
}

#define SND_CACHE_SEC 30
EXT_RAM_BSS_ATTR snd_name_t s_snd_cache[SND_CACHE_N];

/* The name of the listed sender with this MAC, "" for none. now_s is the uptime plus 1:
 * the wall clock can jump. The answer lives in tab until the next call. */
const char *snd_name(snd_name_t *tab, int n, const uint8_t mac[6], uint32_t now_s)
{
    int slot = 0;
    for (int i = 0; i < n; i++)
    {
        if (tab[i].at && memcmp(tab[i].mac, mac, 6) == 0)
        {
            if (now_s - tab[i].at < SND_CACHE_SEC)
                return tab[i].hit ? tab[i].name : "";
            /* Expired: asked again into the same slot, so one MAC never holds two. */
            slot = i;
            break;
        }
        if (tab[i].at < tab[slot].at)
            slot = i;
    }
    char nm[INV_NAME_LEN];
    int r = inventory_lookup_mac(mac, nm, sizeof(nm), NULL);
    if (r < 0)
        return "";
    snd_name_t *c = &tab[slot];
    memcpy(c->mac, mac, 6);
    c->at = now_s;
    c->hit = r == 1 && nm[0];
    memcpy(c->name, nm, sizeof(c->name));
    return c->hit ? c->name : "";
}

/* One-line human summary of what was decoded from a frame. The raw bytes are
 * not repeated here. They only go into the PCAP recording. */
void msg_detail_text(const web_msg_entry_t *e, uint32_t now,
                            char *out, size_t cap)
{
    static const char *ROLE_DE[16] = { NULL, "&Ouml;PNV", "Schwertransport",
        "Gefahrgut", "Baustelle", "Bergung", "Einsatzfahrzeug",
        "Sicherungsfahrzeug", "Landwirtschaft", "Lieferverkehr",
        "Milit&auml;r", "Stra&szlig;endienst", "Taxi", NULL, NULL, NULL };
    static const char *ROLE_EN[16] = { NULL, "public transport",
        "special transport", "dangerous goods", "roadworks", "rescue",
        "emergency", "safety car", "agriculture", "commercial", "military",
        "road operator", "taxi", NULL, NULL, NULL };
    /* Two tables, as for the role: NO/O/SO are German, NE/E/SE English, the same words as
     * ITS_CAM_C of the map popup. */
    static const char *COMPASS_DE[8] = { "N", "NO", "O", "SO", "S", "SW", "W", "NW" };
    static const char *COMPASS_EN[8] = { "N", "NE", "E", "SE", "S", "SW", "W", "NW" };
    bool de = current_lang == LANG_DE;
    int n = 0;
    out[0] = '\0';

    #define DETAIL_SEP (n ? " &middot; " : "")
    /* What the light says comes first: an RSU sends the same position in every frame. */
    if (e->spat_n)
        n = web_addf(out, cap, n, T(S_MSG_SPAT_GREEN), (unsigned)e->spat_green,
                     (unsigned)e->spat_n);
    if (e->has_position && (e->lat_e7 || e->lon_e7))
        n = web_addf(out, cap, n, "%s%.5f, %.5f", DETAIL_SEP,
                     e->lat_e7 / 1e7, e->lon_e7 / 1e7);
    /* -1 cm/s is the GN "not available" pattern, not a reading. Printing it
     * would show "-0 km/h". */
    if (e->has_speed && e->speed_cmps != -1)
        n = web_addf(out, cap, n, "%s%.0f km/h", DETAIL_SEP,
                     e->speed_cmps * 0.036);
    if (e->heading_ddeg != 0xFFFF)
    {
        unsigned deg = e->heading_ddeg / 10;
        n = web_addf(out, cap, n, "%s%u&deg; %s", DETAIL_SEP, deg,
                     (de ? COMPASS_DE : COMPASS_EN)[((deg + 22) / 45) % 8]);
    }
    if (e->length_dm && e->width_dm)
    {
        const char *ds = de ? "," : ".";
        n = web_addf(out, cap, n, "%s%u%s%u &times; %u%s%u m", DETAIL_SEP,
                     e->length_dm / 10, ds, e->length_dm % 10,
                     e->width_dm / 10, ds, e->width_dm % 10);
    }
    if (e->pt_line)
        n = web_addf(out, cap, n, "%s%s %u", DETAIL_SEP,
                     T(S_MAP_LINE), (unsigned)e->pt_line);
    /* Course number distinguishes the individual run of a line; the schedule
     * deviation is what makes a delayed tram visible. */
    if (e->pt_telegram && e->pt_course)
        n = web_addf(out, cap, n, "%s%s %u", DETAIL_SEP,
                     T(S_MAP_COURSE), (unsigned)e->pt_course);
    if (e->pt_telegram && e->pt_dest)
        n = web_addf(out, cap, n, "%s%s %u", DETAIL_SEP,
                     T(S_MAP_DEST), (unsigned)e->pt_dest);
    /* MP and ZL only when they are not 0, because in R09.16 a zero cannot be told from "not
     * sent". At the site where this was written, all twelve telegrams send 0. */
    if (e->pt_telegram && e->pt_point)
        n = web_addf(out, cap, n, "%s%s %u", DETAIL_SEP,
                     T(S_PT_POINT), (unsigned)e->pt_point);
    if (e->pt_telegram && e->pt_train_len)
        n = web_addf(out, cap, n, "%s%s %u", DETAIL_SEP,
                     T(S_PT_TRAINLEN), (unsigned)e->pt_train_len);
    if (e->pt_telegram && e->pt_deviation)
        /* Same end-stop as the /transit table: R09 cannot carry more than
         * 7 minutes, so +-7 is a bound, not an exact value. */
        n = web_addf(out, cap, n, "%s%s%+d %s", DETAIL_SEP,
                     e->pt_deviation >= 7 ? "&ge;" :
                     e->pt_deviation <= -7 ? "&le;" : "",
                     (int)e->pt_deviation, T(S_UNIT_MIN));
    /* Priority request and turn request are what the telegram is actually FOR
     * -- they are why the traffic light lets this vehicle through. */
    if (e->pt_telegram && e->pt_priority)
        n = web_addf(out, cap, n, "%s%s %u", DETAIL_SEP,
                     T(S_PT_PRIORITY), (unsigned)e->pt_priority);
    /* The guard 1..3 keeps S_COUNT away from web_str(), which has no bounds check. */
    if (e->pt_telegram && e->pt_request && e->pt_request < 4)
    {
        static const str_id_t HA[4] = { S_COUNT, S_DIR_STRAIGHT, S_DIR_LEFT, S_DIR_RIGHT };
        n = web_addf(out, cap, n, "%s%s %s", DETAIL_SEP,
                     T(S_PT_REQUEST), T(HA[e->pt_request]));
    }
    if (e->role != 0xFF && e->role < 16 && (de ? ROLE_DE : ROLE_EN)[e->role])
        n = web_addf(out, cap, n, "%s%s", DETAIL_SEP,
                     (de ? ROLE_DE : ROLE_EN)[e->role]);
    /* All seven bits, not only brake and throttle, because emergency brake and collision
     * warning matter most. The same words as the map popup (ITS_CAM_A), in the standard's
     * bit order, MSB first. */
    if (e->has_accel_ctrl)
    {
        static const char *const AC_DE[7] = { "bremst", "Gas", "Notbremse",
            "Kollisionswarnung", "ACC", "Tempomat", "Speedlimiter" };
        static const char *const AC_EN[7] = { "braking", "throttle", "emergency brake",
            "collision warning", "ACC", "cruise control", "speed limiter" };
        for (int b = 0; b < 7; b++)
            if (e->accel_ctrl & (1u << (6 - b)))
                n = web_addf(out, cap, n, "%s%s", DETAIL_SEP,
                             (de ? AC_DE : AC_EN)[b]);
    }
    /* How hard, not only whether: emergency braking is at -4 m/s^2 and beyond. The minus is
     * printed on its own, or -0.5 (light braking) would show as 0.5. */
    if (e->has_long_accel && e->long_accel)
    {
        unsigned a = (unsigned)(e->long_accel < 0 ? -e->long_accel : e->long_accel);
        n = web_addf(out, cap, n, "%s%s%u%s%u m/s%s", DETAIL_SEP,
                     e->long_accel < 0 ? "-" : "", a / 10, de ? "," : ".", a % 10, "&sup2;");
    }
    if (e->drive_dir == 1)
        n = web_addf(out, cap, n, "%s%s", DETAIL_SEP, T(S_MAP_REVERSE));
    /* LanePosition counts the driving lanes 1..13 from the inside, the left in right-hand
     * traffic. 0 and 14 are the inner and outer hard shoulder and -1 is off the road, so a
     * number would be wrong for those three. */
    if (e->has_lane)
    {
        if (e->lane > 0 && e->lane < 14)
            n = web_addf(out, cap, n, "%s%s %d", DETAIL_SEP, T(S_MAP_LANEPOS),
                         (int)e->lane);
        else
            n = web_addf(out, cap, n, "%s%s", DETAIL_SEP,
                         T(e->lane < 0 ? S_LANE_OFFROAD : S_LANE_SHOULDER));
    }
    /* Altitude above the reference ellipsoid, in metres with one decimal. The same form as
     * for DENM, POIM and RTCMEM (fmt_alt_cm). */
    if (e->has_alt)
    {
        char alt[FMT_ALT_MAX];
        fmt_alt_cm(e->alt_cm, current_lang, alt, sizeof(alt));
        n = web_addf(out, cap, n, "%s%s %s", DETAIL_SEP, T(S_MAP_ALT), alt);
    }
    /* The same words as ITS_CAM_L of the map popup. */
    if (e->has_lights)
    {
        if (e->ext_lights & ITS_LIGHT_LEFT)
            n = web_addf(out, cap, n, "%s%s", DETAIL_SEP, T(S_DET_IND_LEFT));
        if (e->ext_lights & ITS_LIGHT_RIGHT)
            n = web_addf(out, cap, n, "%s%s", DETAIL_SEP, T(S_DET_IND_RIGHT));
    }
    if (e->embarking)
        n = web_addf(out, cap, n, "%s%s", DETAIL_SEP, T(S_DET_BOARDING));
    if (denm_is_recent(e->station_id, now))
    {
        uint8_t sub = 0;
        const char *ct = denm_cause_text(denm_cause_of(e->station_id, &sub));
        /* An active warning in one colour on every page: .wact, sign from s.css. */
        if (ct)
            n = web_addf(out, cap, n, "%s<span class='wact'>%s</span>", DETAIL_SEP, ct);
    }
    #undef DETAIL_SEP
    /* The listed message keeps only the signer, so the chain verdict is looked up by the
     * identifier of the certificate. On the stack because the archive search runs in parallel. */
    its_certcache_entry_t cc;
    bool have_cc = e->extra.sig.has_id && its_certcache_lookup(e->extra.sig.id, &cc);
    n = (int)web_msgdetail_append_content(&e->extra, current_lang, out, (size_t)n, cap);
    if (n == 0)
        n = web_addf(out, cap, 0, "&ndash;");
    /* The signature as a small second line under what the message says. Six bytes are kept
     * back, so a full line never leaves the div open. */
    static const char SUB_OPEN[] = "<div class='sub'>";
    if ((size_t)n + sizeof(SUB_OPEN) + 6 < cap)
    {
        size_t k = (size_t)n + sizeof(SUB_OPEN) - 1;
        memcpy(out + n, SUB_OPEN, sizeof(SUB_OPEN));
        size_t m = web_msgdetail_append_sign(&e->extra, e->has_src_mac ? e->src_mac : NULL,
                                             have_cc ? &cc : NULL, current_lang, out, k, cap - 6);
        if (m > k)
        {
            memcpy(out + m, "</div>", 7);
            n = (int)m + 6;
        }
        else
            out[n] = '\0';
    }
}

/* Only two consumers: the websocket broadcast and /markers.json (SD builds).
 * Guarded so a build with neither doesn't carry a dead function. */
#if CONFIG_HTTPD_WS_SUPPORT || CONFIG_ENABLE_SD
size_t build_msg_json(char *out, size_t out_size)
{
    static EXT_RAM_BSS_ATTR web_msg_entry_t snapshot[WEB_MSG_RING_SIZE];
    size_t count = 0;
    if (msg_ring_mutex && xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
    {
        count = msg_ring_count;
        size_t start = (msg_ring_head + WEB_MSG_RING_SIZE - count) % WEB_MSG_RING_SIZE;
        for (size_t i = 0; i < count; i++)
            snapshot[i] = msg_ring[(start + i) % WEB_MSG_RING_SIZE];
        xSemaphoreGive(msg_ring_mutex);
    }

    uint32_t jnow = (uint32_t)time(NULL);
    uint32_t now_s = (uint32_t)(esp_timer_get_time() / 1000000) + 1;
    size_t o = (size_t)web_addf(out, out_size, 0, "[");
    for (size_t n = 0; n < count && o < out_size; n++)
    {
        web_msg_entry_t *e = &snapshot[count - 1 - n];

        /* Static: only the httpd task builds the feed (ws via httpd_queue_work, /markers.json). */
        static EXT_RAM_BSS_ATTR char detail[MSG_DETAIL_MAX];
        msg_detail_text(e, jnow, detail, sizeof(detail));

        char clock[24];
        fmt_clock(e->seconds, e->microseconds, current_lang, clock, sizeof(clock));

        /* r keeps its unit for the map popup and for peers on older firmware. The table
         * strips it. */
        char rssi_str[16];
        if (e->rssi != 0)
            snprintf(rssi_str, sizeof(rssi_str), "%d dBm", e->rssi);
        else
            snprintf(rssi_str, sizeof(rssi_str), "-");

        /* Every key in its widest form: base 47, speed/size/line 47, CAM detail 338 (the
         * path is 215 of it), warning 82 -- 514 bytes. */
        char possuffix[576] = "";
        if (e->has_position)
        {
            int po = web_addf(possuffix, sizeof(possuffix), 0, ",\"a\":%ld,\"o\":%ld,\"i\":%lu",
                              (long)e->lat_e7, (long)e->lon_e7, (unsigned long)e->station_id);
            /* -1 cm/s is the GN "speed unavailable" pattern, not a reading --
             * emitting it printed "-0.0 km/h" in the popup. */
            if (e->has_speed && e->speed_cmps != -1)
                po = web_addf(possuffix, sizeof(possuffix), po, ",\"s\":%ld", (long)e->speed_cmps);
            if (e->length_dm && e->width_dm)
                po = web_addf(possuffix, sizeof(possuffix), po, ",\"vl\":%u,\"vw\":%u",
                              (unsigned)e->length_dm, (unsigned)e->width_dm);
            if (e->pt_line)
                po = web_addf(possuffix, sizeof(possuffix), po, ",\"pl\":%u", (unsigned)e->pt_line);
            /* po stays below the size, so both get at least the byte for the terminator. */
            po += (int)cam_json_extra(e, possuffix + po, sizeof(possuffix) - (size_t)po);
            denm_json(e->station_id, jnow, possuffix + po, sizeof(possuffix) - (size_t)po);
        }

        /* The detail line goes in raw and can carry text from the air (EVCSN, POIM).
         * add_text_utf8() and add_text_utf8_n() in web_msgdetail.c keep it safe for a JSON
         * string in a WebSocket
         * text frame: valid UTF-8, no quote, no backslash. The name of a roadside unit below
         * is escaped. Everything else here is our own tables and numbers, and entities or
         * <span> are fine via innerHTML. */
        /* Measure first and stop while the closing `]` still fits: without it
         * the client's JSON.parse fails. Newest entry first, oldest drop out. */
        char mac_str[20];
        if (e->has_src_mac)
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     e->src_mac[0], e->src_mac[1], e->src_mac[2],
                     e->src_mac[3], e->src_mac[4], e->src_mac[5]);
        else
            snprintf(mac_str, sizeof(mac_str), "-");

        /* The name of a roadside unit, escaped for HTML and JSON alike: names restored
         * from the card can hold any byte. 242 of 256 with a 39-character name. Static: only
         * the httpd task builds this feed. */
        static EXT_RAM_BSS_ATTR char snsuffix[256], esc[INV_NAME_LEN * 6];
        snsuffix[0] = '\0';
        if (e->has_src_mac)
        {
            const char *nm = snd_name(s_snd_cache, SND_CACHE_N, e->src_mac, now_s);
            if (nm[0])
            {
                web_msgdetail_escape(nm, esc, sizeof(esc));
                snprintf(snsuffix, sizeof(snsuffix), ",\"sn\":\"%s\"", esc);
            }
        }

        static const char ENTRY_FMT[] =
            "%s{\"t\":\"%s\",\"r\":\"%s\",\"l\":%lu,\"y\":\"%s\",\"sm\":\"%s\",\"h\":\"%s\"%s%s}";
        int need = snprintf(NULL, 0, ENTRY_FMT,
            n == 0 ? "" : ",", clock, rssi_str, (unsigned long)e->length,
            e->msgtype, mac_str, detail, snsuffix, possuffix);
        if (need < 0 || o + (size_t)need + 2 > out_size)
            break;
        o = (size_t)web_addf(out, out_size, (int)o, ENTRY_FMT,
            n == 0 ? "" : ",", clock, rssi_str, (unsigned long)e->length,
            e->msgtype, mac_str, detail, snsuffix, possuffix);
    }
    /* Always closes: the loop above never consumes the two bytes kept back. */
    out[o++] = ']';
    out[o] = '\0';
    return o;
}
#endif /* CONFIG_HTTPD_WS_SUPPORT || CONFIG_ENABLE_SD */

#if CONFIG_HTTPD_WS_SUPPORT
/* Sockets whose last send failed are skipped for a while: a dirty-closed tab
 * stays "live" for minutes and warns on every send. Expiry lets reused fds recover. */
#define WS_DEAD_N        8
#define WS_DEAD_HOLD_SEC 60

static struct { int fd; uint32_t until; } s_ws_dead[WS_DEAD_N];

static bool ws_recently_failed(int fd, uint32_t now)
{
    for (int i = 0; i < WS_DEAD_N; i++)
        if (s_ws_dead[i].fd == fd && now < s_ws_dead[i].until)
            return true;
    return false;
}

static void ws_mark_failed(int fd, uint32_t now)
{
    int slot = 0;
    for (int i = 0; i < WS_DEAD_N; i++)
    {
        if (s_ws_dead[i].fd == fd) { slot = i; break; }
        if (s_ws_dead[i].until < s_ws_dead[slot].until) slot = i;
    }
    s_ws_dead[slot].fd = fd;
    s_ws_dead[slot].until = now + WS_DEAD_HOLD_SEC;
}

/* The language a socket named in its first frame, kept in the session's own ctx so it
 * dies with the socket. A value, not a pointer, hence the no-op free: esp_http_server
 * would otherwise free() it (httpd_sess_free_ctx). */
#define WS_CTX_DE ((void *)(intptr_t)1)
#define WS_CTX_EN ((void *)(intptr_t)2)

static void ws_lang_no_free(void *ctx) { (void)ctx; }

/* A socket that has not named its language reads as German, the same default
 * resolve_language() uses. */
static lang_t ws_fd_lang(int fd)
{
    return httpd_sess_get_ctx(g_httpd_server, fd) == WS_CTX_EN ? LANG_EN : LANG_DE;
}

static void ws_broadcast_work(void *arg)
{
    (void)arg;
    /* Read before the flag clears: after that the timer may queue anew and reset ws_queued_s. */
    uint32_t waited = (uint32_t)(esp_timer_get_time() / 1000000) - ws_queued_s;
    /* Cleared before the ring is read: a frame from here on needs the next pass. */
    ws_broadcast_queued = false;
    bool logged = ws_wait_logged;
    ws_wait_logged = false;
    /* Only after a "busy" line, so a hang reads as two lines. The time counts from the
     * queuing. */
    if (logged)
        ESP_LOGW(TAG, "live feed: web server free again after %lu s", (unsigned long)waited);
    if (!g_httpd_server)
        return;

    size_t max_fds = CONFIG_LWIP_MAX_SOCKETS;
    int client_fds[CONFIG_LWIP_MAX_SOCKETS];
    if (httpd_get_client_list(g_httpd_server, &max_fds, client_fds) != ESP_OK)
        return;

    uint32_t now = (uint32_t)time(NULL);
    /* Entries that do not fit are left out, oldest first. */
    /* 20 entries, each with up to MSG_DETAIL_MAX bytes of detail text and a 576-byte position
     * part. 16 KB would silently make the stream shorter than the table on the page. */
    static EXT_RAM_BSS_ATTR char json[49152];
    /* One pass per language instead of one JSON for everyone: the detail text is
     * translated, and this task's slot holds whoever loaded a page last. Built
     * lazily, so a single-language audience still builds it exactly once. */
    lang_t saved = current_lang;
    for (int li = 0; li < 2; li++)
    {
        lang_t pass = li ? LANG_EN : LANG_DE;
        size_t len = 0;   /* 0 = not built yet; build_msg_json returns >= 2 */
        for (size_t i = 0; i < max_fds; i++)
        {
            int fd = client_fds[i];
            if (httpd_ws_get_fd_info(g_httpd_server, fd) != HTTPD_WS_CLIENT_WEBSOCKET)
                continue;
            if (ws_recently_failed(fd, now))
                continue;
            if (ws_fd_lang(fd) != pass)
                continue;
            if (len == 0)
            {
                current_lang = pass;
                len = build_msg_json(json, sizeof(json));
            }
            httpd_ws_frame_t frame = { .type = HTTPD_WS_TYPE_TEXT,
                                       .payload = (uint8_t *)json, .len = len };
            /* A failed send means the client is gone, but esp_http_server does not
             * notice that on its own. Without the close, the dead session would hold a
             * max_open_sockets slot forever. */
            if (httpd_ws_send_frame_async(g_httpd_server, fd, &frame) != ESP_OK)
            {
                ws_mark_failed(fd, now);
                httpd_sess_trigger_close(g_httpd_server, fd);
            }
        }
    }
    current_lang = saved;
}

/* Fires roughly once a second (see webserver_init). It does nothing when nothing new
 * arrived. While a pass still waits, it only logs a long wait and queues one more try
 * every WS_REQUEUE_S. */
static void ws_broadcast_tick(void *arg)
{
    (void)arg;
    uint32_t now_s = (uint32_t)(esp_timer_get_time() / 1000000);
    uint32_t seen = msg_total_count;
    if (ws_broadcast_queued)
    {
        /* One busy line per hang, from WS_WAIT_LOG_S on: an OTA (about 14 s) stays below it. */
        if (!ws_wait_logged && now_s - ws_queued_s >= WS_WAIT_LOG_S)
        {
            ws_wait_logged = true;
            ESP_LOGW(TAG, "live feed: web server busy for %lu s",
                     (unsigned long)(now_s - ws_queued_s));
        }
        /* A real hang uses one more slot per WS_REQUEUE_S (6 slots: 5 min); a lost pass is replaced. */
        if (now_s - ws_retry_s >= WS_REQUEUE_S)
        {
            ws_retry_s = now_s;
            (void)httpd_queue_work(g_httpd_server, ws_broadcast_work, NULL);
        }
        return;
    }
    if (seen == ws_last_broadcast_count)
        return;
    ws_queued_s = ws_retry_s = now_s;
    ws_broadcast_queued = true;
    /* Counted as sent only once queued: a full queue retries on the next tick. */
    if (httpd_queue_work(g_httpd_server, ws_broadcast_work, NULL) == ESP_OK)
        ws_last_broadcast_count = seen;
    else
        ws_broadcast_queued = false;
}

static esp_err_t ws_get_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET)
    {
        /* A WebSocket never gets here: esp_http_server answers the handshake itself (httpd_uri.c,
         * "do not call the uri->handler"). A plain GET does get here. Unanswered, it would hold
         * its socket. */
        httpd_resp_set_status(req, "426 Upgrade Required");
        httpd_resp_set_hdr(req, "Upgrade", "websocket");
        return httpd_resp_send(req, NULL, 0);
    }

    /* The socket learns its language from the first frame, sent in ws.onopen. */

    /* The client sends its language once, right after opening ("de" or "en"), and "p" every
     * 5 s, which is echoed. Everything else is drained so it cannot desync the next frame.
     * Oversized frames (never from our own JS) close the connection by returning an error. */
    httpd_ws_frame_t pkt = {0};
    pkt.type = HTTPD_WS_TYPE_TEXT;
    esp_err_t ret = httpd_ws_recv_frame(req, &pkt, 0);
    if (ret != ESP_OK)
        return ret;
    if (pkt.len > 0 && pkt.len < 256)
    {
        uint8_t buf[256];
        pkt.payload = buf;
        ret = httpd_ws_recv_frame(req, &pkt, sizeof(buf));
        if (ret != ESP_OK)
            return ret;
        /* The live pages send p every 5 s and wait for the echo, because silence is the only
         * sign of a device that lost power. */
        if (pkt.len == 1 && buf[0] == 'p')
        {
            static uint8_t pong[1] = { 'p' };
            httpd_ws_frame_t f = { .type = HTTPD_WS_TYPE_TEXT, .payload = pong, .len = 1 };
            return httpd_ws_send_frame(req, &f);
        }
        /* Exactly the two words, nothing else: a stray frame must not switch anybody's
         * language. Kept in the session's own slot, so it dies with the socket. */
        if (pkt.len == 2 && (memcmp(buf, "en", 2) == 0 || memcmp(buf, "de", 2) == 0))
        {
            req->sess_ctx = buf[0] == 'e' ? WS_CTX_EN : WS_CTX_DE;
            req->free_ctx = ws_lang_no_free;
        }
        return ESP_OK;
    }
    return pkt.len == 0 ? ESP_OK : ESP_FAIL;
}
#endif /* CONFIG_HTTPD_WS_SUPPORT */

#if CONFIG_ENABLE_SD
/* The one period picker of the search, the map playback and the re-send. The caption is
 * above both fields, like the labels of /settings. The ids stay the ones the scripts read.
 * 235 of 320 (German, OEZ/OESZ). */
const char *web_range_html(const char *idf, const char *idt)
{
    static EXT_RAM_BSS_ATTR char rng[320];
    /* The caption names the zone the fields count in. */
    char span[24];
    fmt_tz_span(web_lang(), span, sizeof(span));
    web_addf(rng, sizeof(rng), 0,
        "<span class='fld'><label class='cap' for='%s'>%s <small>(%s)</small></label><span><input type='datetime-local' id='%s' aria-label='%s'> &ndash; <input type='datetime-local' id='%s' aria-label='%s'></span></span>",
        idf, T(S_TRF_WINDOW), span, idf, T(S_PLAYBACK_FROM), idt, T(S_PLAYBACK_TO));
    return rng;
}
#endif

#if CONFIG_ENABLE_SD
/* True when everything captured so far reached the card. Must be asked AFTER
 * the flush: the recorder drains the ring itself, so a 0-byte flush is no error. */
static bool pcap_on_card(void)
{
    if (sdpcap_buffered() == 0)
        return true;
    /* Ring-empty and `landed` are separate questions. The byte count answers
     * neither: it is 0 for an empty ring and for a failed write alike. */
    /* Up to three passes: a single call pays only an outstanding hour-boundary
     * debt and returns, leaving the current hour's records in RAM while the
     * export would be stamped complete. Bounded so a failing card cannot spin
     * here on the request task. */
    bool landed = false;
    for (int i = 0; i < 3; i++)
    {
        size_t before = sdpcap_buffered();
        sdpcap_flush_now(&landed);
        if (!landed || sdpcap_buffered() == 0 || sdpcap_buffered() >= before)
            break;
    }
    /* Only whether the write landed. With a live sniffer the ring is never
     * empty, so testing that too would mark every export partial. */
    return landed;
}

/* Same question, but only asked where the ring can still hold part of the
 * answer -- a false "partial" invites an RSU re-send, and a re-send ADDS. */
bool pcap_window_on_card(uint32_t to_sec)
{
    /* Bound by the CONFIGURED flush interval, never a fixed guess: the writer
     * empties the ring only on that interval. Doubled plus 60 s for the write. */
    uint32_t now = (uint32_t)time(NULL);
    uint32_t behind = sdpcap_flush_sec() * 2u + 60u;
    if (now > behind && to_sec < now - behind)
        return true;
    return pcap_on_card();
}
#endif

/* ==================================================================
 *  GET /senders -- roadside units (traffic lights and others), kept
 *  across restarts. Pure RAM, no SD access, so it runs on the httpd
 *  task. This page only prints the re-send form. The job itself runs
 *  in its own task (web_files.c).
 * ================================================================== */

/* The kinds 1..15 inventory.c keeps a bit for, named by its_decode.c's table as on /messages.
 * The bit is the kind (its_msg_kind), so an old EVCSN (id 3 at version 0) sets 11, not 3. In
 * an older file without the INV_MARK line, bit 3 is dropped when it loads. */
static const char *inv_msg_name(uint8_t bit)
{
    return bit < 16 ? its_msgid_name(bit) : NULL;
}

static esp_err_t senders_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    send_page_header(req, T(S_TITLE_SENDERS));

    /* Opens the page's one group. The reset button below closes it. In pieces, because
     * the text outgrew a fixed buffer once (912 bytes in 512). */
    web_send_parts(req, "<div class='grp top'><p class='note hlp'>", T(S_SND_INTRO),
                   "</p><p class='note hlp'>", T(S_SND_SEC_HINT),
                   "</p><p class='note hlp'>", T(S_SND_SN_HINT), "</p>", NULL);

    static EXT_RAM_BSS_ATTR inv_station_t snap[INV_MAX_STATIONS];
    int n = inventory_snapshot(snap);

    if (n == 0)
    {
        char none[192];
        HTML_PRINTF(none, "<p class='note'>%s</p>", T(S_SND_NONE));
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        char head[512];
        HTML_PRINTF(head,
            "<div class='scroll'><table><thead><tr><th>%s</th>"
            "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
            "</tr></thead><tbody>",
            T(S_SND_STATION), T(S_SND_TYPES), T(S_SND_FRAMES),
            T(S_COL_RSSI), T(S_COL_SIG), T(S_SND_POS), T(S_SND_LAST));
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

        uint32_t now = (uint32_t)time(NULL);
        for (int i = 0; i < n; i++)
        {
            inv_station_t *s = &snap[i];

            /* All fifteen names, three of them links: 236 bytes, DE and EN alike. One entry
             * is 59 at most, so the 64 kept free always hold the next (the last starts at 231). */
            char types[296] = "";
            int to = 0;
            for (uint8_t b = 0; b < 16 && (size_t)to + 64 < sizeof(types); b++)
                if (s->msg_mask & (1u << b))
                {
                    const char *nm = inv_msg_name(b);
                    if (!nm) continue;
#if CONFIG_ENABLE_SD
                    /* hours=720, because the 24 h default hides all but the
                     * newest few. Only under SD, because without it /traffic is not built. */
                    const char *anchor = strcmp(nm, "DENM") == 0 ? "denm" :
                        (strcmp(nm, "SPATEM") == 0 || strcmp(nm, "MAPEM") == 0) ? "lights" : NULL;
                    if (anchor)
                    {
                        to = web_addf(types, sizeof(types), to,
                                      "%s<a href='/traffic?hours=720&amp;lang=%s#%s'>%s</a>",
                                      to ? " " : "", current_lang == LANG_EN ? "en" : "de",
                                      anchor, nm);
                        continue;
                    }
#endif
                    to = web_addf(types, sizeof(types), to, "%s%s", to ? " " : "", nm);
                }

            char nameesc[INV_NAME_LEN * 6];
            html_escape(s->name, nameesc, sizeof(nameesc));

            /* Signal range plus average: one bad reflection or one close pass
             * says little, the spread over thousands of frames says a lot. */
            /* 96, not 64: the markup and three numbers need 68 counted
             * at their widest rather than trusting the int16 range. The head
             * names the unit. An empty cell shows &ndash;, as on every page. */
            char sig[96] = "&ndash;";
            if (s->rssi_cnt)
                snprintf(sig, sizeof(sig), "%d&hellip;%d <small>(&oslash; %ld)</small>",
                         s->rssi_min, s->rssi_max,
                         (long)(s->rssi_sum / (int64_t)s->rssi_cnt));
            /* The sender's own transmit power belongs next to how strongly it arrives. */
            char radio[160] = "";
            if (s->has_dcc)
            {
                char rt[128];
                web_msgdetail_radio(s->tx_power_dbm, s->cbr_max, current_lang, rt, sizeof(rt));
                snprintf(radio, sizeof(radio), "<div class='sub'>%s</div>", rt);
            }
            char signer[192];
            if (!web_msgdetail_sig(&s->sig, s->has_mac ? s->mac : NULL, current_lang,
                                   signer, sizeof(signer)))
                snprintf(signer, sizeof(signer), "&ndash;");
            /* Second line of the same cell: what the chain check says about that certificate,
             * and the way to it on /trust. 186 of 224. */
            char trust[224] = "";
            its_certcache_entry_t cc;
            if (s->sig.has_id && its_certcache_lookup(s->sig.id, &cc))
            {
                char verdict[128];
                if (web_msgdetail_trust_short(&cc, current_lang, verdict, sizeof(verdict)))
                    snprintf(trust, sizeof(trust),
                             "<div class='sub'><a href='/trust?lang=%s#t-seen'>%s</a></div>",
                             current_lang == LANG_EN ? "en" : "de", verdict);
            }
            /* Below it: the message signatures of that certificate checked so far
             * (its_msgsig.c). mv: widest 70 of 96 (EN, both counts at 65535), msl 93 of 128. */
            static EXT_RAM_BSS_ATTR char msl[128];
            msl[0] = '\0';
            its_msgsig_cert_t mc;
            if (s->sig.has_id && its_msgsig_cert(s->sig.id, &mc))
            {
                char mv[96];
                if (web_msgsig_cert(&mc, true, current_lang, mv, sizeof(mv)))
                    snprintf(msl, sizeof(msl), "<div class='sub'>%s</div>", mv);
            }
            /* Third line: what the signature headers of this unit said (web_sechdr.c). su: the
             * widest line is 194 of 224 (DE); secl 246 of 256 with su at its size. */
            char su[224];
            static EXT_RAM_BSS_ATTR char secl[256];
            secl[0] = '\0';
            if (web_sechdr_unit(&s->sec, current_lang, su, sizeof(su)) > 0)
                snprintf(secl, sizeof(secl), "<div class='sub'>%s</div>", su);
            /* Under the frame count: what the unit's sequence numbers said (web_gn.c). gu: widest
             * 73 of 96 (DE), gnl 118 of 128 with gu full; gu's block adds no stack. */
            static EXT_RAM_BSS_ATTR char gnl[128];
            gnl[0] = '\0';
            {
                char gu[96];
                if (web_gn_unit(&s->gnu, current_lang, gu, sizeof(gu)) > 0)
                    snprintf(gnl, sizeof(gnl), "<div class='sub'>%s</div>", gu);
            }

            /* Deep link: the map centres on the sender instead of dropping the
             * reader on an overview to hunt for it. */
            char pos[96] = "&ndash;";
            if (s->has_pos)
                snprintf(pos, sizeof(pos),
                         "<a href='/map?lang=%s&amp;lat=%ld&amp;lon=%ld'>%.5f, %.5f</a>",
                         current_lang == LANG_EN ? "en" : "de",
                         (long)s->lat_e7, (long)s->lon_e7,
                         s->lat_e7 / 1e7, s->lon_e7 / 1e7);

            char first[32], last[32];
            fmt_when(s->first_seen, 0, 0, current_lang, first, sizeof(first));
            /* Recent activity is what the reader looks for, so show an age
             * rather than a second clock time. */
            uint32_t age = now > s->last_seen ? now - s->last_seen : 0;
            /* One unit, days included, the same steps as on /transit. */
            fmt_age(age, FMT_DUR_ONE, current_lang, last, sizeof(last));

            /* Vendor prefix tells sibling units apart at a glance; vehicles use
             * locally administered (random) addresses, roadside units do not. */
            char mac[20] = "&ndash;";
            if (s->has_mac)
                snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                         s->mac[0], s->mac[1], s->mac[2], s->mac[3], s->mac[4], s->mac[5]);

            /* The MAPEM intersection name IS the identity where there is one.
             * Station id and MAC become detail under it. */
            char ident[248], idmac[64];
            if (nameesc[0])
            {
                snprintf(ident, sizeof(ident), "%s", nameesc);
                snprintf(idmac, sizeof(idmac), "%lu%s%s", (unsigned long)s->station_id,
                         s->has_mac ? " &middot; " : "", s->has_mac ? mac : "");
            }
            else
            {
                snprintf(ident, sizeof(ident), "%lu", (unsigned long)s->station_id);
                snprintf(idmac, sizeof(idmac), "%s", s->has_mac ? mac : "&ndash;");
            }
            char firstline[48];
            snprintf(firstline, sizeof(firstline), "%s %s", T(S_SND_SINCE), first);

            /* 2148 of 2304 with every part at its buffer size (2021 before msl[128]). Static: only
             * the httpd task serves this page. */
            static EXT_RAM_BSS_ATTR char row[2304];
            HTML_PRINTF(row,
                "<tr><td class='wrapcell'>%s<div class='sub mono'>%s</div></td>"
                "<td>%s</td><td>%lu%s</td>"
                "<td class='mono'>%s%s</td><td class='wrapcell'>%s%s%s%s</td>"
                "<td class='mono'>%s</td>"
                "<td>%s<div class='sub'>%s</div></td></tr>",
                ident, idmac,
                types[0] ? types : "&ndash;", (unsigned long)s->frames, gnl, sig, radio, signer,
                trust, msl, secl, pos, last, firstline);
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
    }

    if (inventory_overflow())
    {
        /* Units past the table are not recorded, so a warning (s.css). 96 of 256. */
        char full[256];
        HTML_PRINTF(full, "<div class='warn'><p>%s</p></div>", T(S_SND_FULL));
        httpd_resp_send_chunk(req, full, HTTPD_RESP_USE_STRLEN);
    }

    char veh[384];
    char vtext[288];
    snprintf(vtext, sizeof(vtext), T(S_SND_VEHICLES),
             (unsigned long)inventory_vehicle_frames());
    HTML_PRINTF(veh, "<p class='note'>%s</p>", vtext);
    httpd_resp_send_chunk(req, veh, HTTPD_RESP_USE_STRLEN);
    /* The count stays visible, and what it means goes with the other explanations. /traffic
     * exists only with SD. Without it the page name stays and the link goes. */
#if CONFIG_ENABLE_SD
    web_send_parts(req, "<p class='note hlp'>", T(S_SND_VEH_HINT), "</p>", NULL);
#else
    web_send_parts(req, "<p class='note hlp'>", NULL);
    web_send_unlinked(req, T(S_SND_VEH_HINT));
    web_send_parts(req, "</p>", NULL);
#endif

    /* 512 against 313 measured (German). */
    char clr[512];
    HTML_PRINTF(clr,
        /* r.ok, because this page is ungated but the POST is not. Reloading after a 401
         * would show the untouched list as if the reset had happened. A 403 shows its text in
         * the page's language, set by ?lang=, because a bare POST would answer German. */
        "<p class='btnrow'><button class='dngr' onclick=\"if(confirm('%s'))fetch('/senders/clear"
        "?lang='+document.documentElement.lang,{method:'POST'}).then(function(r){"
        "if(r.ok)location.reload();else if(r.status==403)r.text().then(alert);});\">%s</button>"
        "</p></div>",
        T(S_SND_CLEAR_CONFIRM), T(S_SND_CLEAR));
    httpd_resp_send_chunk(req, clr, HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD
    /* The re-send reads the recording, not this list, so it follows as its own group. */
    web_rsu_section(req);
#endif

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ==================================================================
 *  GET /transit -- R09 telegrams per tram/bus line. The table is RAM;
 *  the passage list reads the card, so a busy card just omits it.
 * ================================================================== */

#if CONFIG_ENABLE_SD
/* Median headway without an O(n log n) sort on the httpd task: gaps bucketed by
 * the minute. The last bucket is "60 or more", i.e. no regular service. */
#define PT_GAP_BUCKETS 61
#define PT_DEST_SLOTS 8
#define PT_NEWEST_ROWS 5
typedef struct {
    uint16_t line;
    uint32_t prev_sec;              /* last passage folded in, 0 = none yet */
    uint32_t n, ngap;
    uint32_t first_sod, last_sod;   /* seconds into the operating day */
    uint16_t dest[PT_DEST_SLOTS];
    uint32_t dcnt[PT_DEST_SLOTS];
    uint32_t nreq;                  /* passages with a signal request or a priority */
} pt_ops_t;

/* A passage's signal request as table text, for example "straight, priority 2". */
static void pt_request_text(uint8_t req, uint8_t prio, char *out, size_t cap)
{
    static const str_id_t DIR[] = { S_PT_REQ_NONE, S_DIR_STRAIGHT, S_DIR_LEFT, S_DIR_RIGHT };
    if (req > 3)
        snprintf(out, cap, "%s", T(S_UNKNOWN));
    else if (!prio)
        snprintf(out, cap, "%s", T(DIR[req]));
    else if (!req)
        snprintf(out, cap, "%s %u", T(S_PT_PRIORITY), (unsigned)prio);
    else
        snprintf(out, cap, "%s, %s %u", T(DIR[req]), T(S_PT_PRIORITY), (unsigned)prio);
}

/* Head of a passage table, for the newest rows at the top and the full list. */
static void pt_send_pass_head(httpd_req_t *req)
{
    /* Measured 207 of 320. */
    char phead[320];
    HTML_PRINTF(phead,
        "<div class='scroll'><table><thead><tr><th>%s</th>"
        "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
        "<th>%s</th></tr></thead><tbody>",
        T(S_COL_TIME), T(S_PT_LINE), T(S_PT_COURSE),
        T(S_PT_DEST), T(S_PT_DEV), T(S_PT_INRANGE), T(S_PT_POINT),
        T(S_PT_REQUEST));
    httpd_resp_send_chunk(req, phead, HTTPD_RESP_USE_STRLEN);
}

/* One builder for the top rows and the full table, so the two cannot drift apart. */
static void pt_send_pass_row(httpd_req_t *req, const pt_pass_t *p)
{
    char when[FMT_WHEN_MAX];
    fmt_when(p->seconds, 0, FMT_SEC, current_lang, when, sizeof(when));
    char dev[24] = "&ndash;";
    /* ZW is 3 bits plus a sign bit, so 7 means "7 or more late" and
     * -7 "7 or more early". The early end therefore needs &le;, not &ge;. */
    if (p->deviation)
        snprintf(dev, sizeof(dev), "%s%+d min",
                 p->deviation >= 7 ? "&ge;" :
                 p->deviation <= -7 ? "&le;" : "",
                 p->deviation);
    char reqt[64];
    pt_request_text(p->request, p->priority, reqt, sizeof(reqt));
    /* 0 s would read as "was not there". The value is the span between the first and
     * the last telegram, and that is zero for a single message. */
    char inr[FMT_DUR_MAX];
    if (p->secs_in_range)
        fmt_dur(p->secs_in_range, FMT_DUR_PHASE, inr, sizeof(inr));
    else
        snprintf(inr, sizeof(inr), "&lt;1\u00a0s");
    /* The report point from the OCIT part. In R09.16 a 0 means "not sent" AND
     * "point 0", so the cell shows a dash instead of a number. The train length
     * goes next to it as a small note when it was sent. */
    char mp[64];
    if (p->point && p->train_len)
        snprintf(mp, sizeof(mp), "%u <small>%s %u</small>",
                 p->point, T(S_PT_TRAINLEN), p->train_len);
    else if (p->point)
        snprintf(mp, sizeof(mp), "%u", p->point);
    else if (p->train_len)
        snprintf(mp, sizeof(mp), "&ndash; <small>%s %u</small>",
                 T(S_PT_TRAINLEN), p->train_len);
    else
        snprintf(mp, sizeof(mp), "&ndash;");
    /* Measured 305 of 448. */
    char prow[448];
    HTML_PRINTF(prow,
        "<tr><td>%s</td><td><b>%u</b></td><td>%u</td><td>%u</td><td>%s</td>"
        "<td>%s</td><td>%s</td><td>%s</td></tr>",
        when, p->line, p->course, p->dest, dev,
        inr, mp, reqt);
    httpd_resp_send_chunk(req, prow, HTTPD_RESP_USE_STRLEN);
}
#endif

static esp_err_t transit_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    send_page_header(req, T(S_TITLE_TRANSIT));

    static EXT_RAM_BSS_ATTR pt_line_t snap[PT_MAX_LINES];
    int n = ptlog_snapshot(snap);

    /* Groups: the newest passages and all passages only when some are stored, the lines
     * always. Each opening chunk closes the one before. The </div> of the reset button
     * closes the last. */
    bool newest = false;
#if CONFIG_ENABLE_SD
    /* Read BEFORE the line rows go out -- a sent chunk cannot be amended. The
     * file is read whole either way, so PT_PASS_KEEP costs no extra card time. */
    static EXT_RAM_BSS_ATTR pt_pass_t pass[PT_PASS_KEEP];
    static EXT_RAM_BSS_ATTR uint16_t gap_hist[PT_MAX_LINES][PT_GAP_BUCKETS];
    static EXT_RAM_BSS_ATTR pt_ops_t ops[PT_MAX_LINES];
    /* Statics, so they must be cleared on entry -- otherwise the second view
     * of this page counts every passage a second time. */
    memset(gap_hist, 0, sizeof(gap_hist));
    memset(ops, 0, sizeof(ops));
    int pn = ptlog_read_passages(pass, PT_PASS_KEEP);
    for (int i = 0; i < n; i++)
        ops[i].line = snap[i].line;
    /* Backwards through a newest-first array is chronological order. */
    for (int k = pn - 1; k >= 0; k--)
    {
        int idx = -1;
        for (int i = 0; i < n; i++)
            if (ops[i].line == pass[k].line) { idx = i; break; }
        if (idx < 0)
            continue;                  /* line no longer in the aggregate table */
        pt_ops_t *o = &ops[idx];
        if (o->prev_sec && pass[k].seconds > o->prev_sec)
        {
            uint32_t m = (pass[k].seconds - o->prev_sec) / 60;
            if (m >= PT_GAP_BUCKETS) m = PT_GAP_BUCKETS - 1;
            gap_hist[idx][m]++;
            o->ngap++;
        }
        o->prev_sec = pass[k].seconds;
        /* Operating day starts at 03:00, so a trip just after midnight stays
         * with the day it belongs to instead of opening the next one. */
        time_t ots = (time_t)pass[k].seconds - 3 * 3600;
        struct tm olt;
        localtime_r(&ots, &olt);
        uint32_t sod = (uint32_t)(olt.tm_hour * 3600 + olt.tm_min * 60 + olt.tm_sec);
        if (!o->n || sod < o->first_sod) o->first_sod = sod;
        if (!o->n || sod > o->last_sod)  o->last_sod  = sod;
        o->n++;
        if (pass[k].request != PT_REQ_UNKNOWN && (pass[k].request || pass[k].priority))
            o->nreq++;
        for (int d = 0; d < PT_DEST_SLOTS; d++)
        {
            if (o->dcnt[d] && o->dest[d] != pass[k].dest) continue;
            o->dest[d] = pass[k].dest;
            o->dcnt[d]++;
            break;
        }
    }

    /* A jump row needs three targets, so it comes only with stored passages. It goes before
     * the first group, so it stays under the menu the whole page. 166 of 256. */
    if (pn > 0)
    {
        char ptjump[256];
        HTML_PRINTF(ptjump,
            "<p class='jump'>%s: <a href='#pt-new'>%s</a> &middot; "
            "<a href='#pt-lines'>%s</a> &middot; <a href='#pt-pass'>%s</a></p>",
            T(S_TRF_JUMP), T(S_PT_NEWEST), T(S_PT_LINES), T(S_PT_PASSAGES));
        httpd_resp_send_chunk(req, ptjump, HTTPD_RESP_USE_STRLEN);
        /* "When did the last one pass" is what most visits ask. pass[] is newest-first
         * and already read, so there is no second card read. */
        web_send_parts(req, "<div class='grp top' id='pt-new'><p class='note hlp'>", T(S_PT_INTRO),
                       "</p><h2>", T(S_PT_NEWEST), "</h2>", NULL);
        pt_send_pass_head(req);
        for (int k = 0; k < pn && k < PT_NEWEST_ROWS; k++)
            pt_send_pass_row(req, &pass[k]);
        httpd_resp_send_chunk(req, "</tbody></table></div></div><div class='grp' id='pt-lines'>",
                              HTTPD_RESP_USE_STRLEN);
        newest = true;
    }
#endif
    /* Without stored passages the lines open the page and carry the introduction. */
    if (!newest)
        web_send_parts(req, "<div class='grp top' id='pt-lines'><p class='note hlp'>",
                       T(S_PT_INTRO), "</p>", NULL);
    web_send_parts(req, "<h2>", T(S_PT_LINES), "</h2>", NULL);

    if (n == 0)
    {
        char none[192];
        HTML_PRINTF(none, "<p class='note'>%s</p>", T(S_PT_NONE));
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        /* Last seen is the third column, so on a phone the line, the count and last seen
         * show without scrolling sideways, with the line cell wrapping. 208 of 512. */
        char head[512];
        HTML_PRINTF(head,
            "<div class='scroll'><table><thead><tr><th>%s</th><th>%s</th><th>%s</th>"
            "<th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
            T(S_PT_LINE), T(S_PT_SIGHTINGS), T(S_PT_LAST), T(S_PT_AVG),
            T(S_PT_LATE), T(S_PT_EARLY), T(S_PT_UNKNOWN));
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

        uint32_t now = (uint32_t)time(NULL);
        bool any_ops = false;
        for (int i = 0; i < n; i++)
        {
            pt_line_t *l = &snap[i];

            /* &ndash;: the empty value of every page. */
            char avg[24] = "&ndash;";
            if (l->dev_count)
            {
                /* One decimal: the source values are whole minutes, so more
                 * would only pretend precision the format never carried. */
                double a = (double)l->dev_sum / (double)l->dev_count;
                /* The page's decimal separator. */
                char an[20];
                fmt_dec(a, 1, true, current_lang, an, sizeof(an));
                snprintf(avg, sizeof(avg), "%s min", an);
            }
            /* Both ends get &ge;, unlike the passage rows (pt_send_pass_row): this column
              * shows how many minutes EARLY, as a positive number, so "7 or
              * more early" is &ge;7 here and &le;-7 there. */
            char late[24] = "&ndash;", early[24] = "&ndash;";
            if (l->worst_late > 0)
                snprintf(late, sizeof(late), "%s%d min",
                         l->worst_late >= 7 ? "&ge;" : "", l->worst_late);
            if (l->worst_early < 0)
                snprintf(early, sizeof(early), "%s%d min",
                         l->worst_early <= -7 ? "&ge;" : "", -l->worst_early);

            /* One unit like on /senders, and below a minute in seconds, not 0m. */
            char last[FMT_AGE_MAX];
            uint32_t age = now > l->last_seen ? now - l->last_seen : 0;
            fmt_age(age, FMT_DUR_ONE, current_lang, last, sizeof(last));

            /* Empty whenever the passage log no longer holds a run of this
             * line. A dash there would claim something was measured. */
            char tsub[256] = "";
#if CONFIG_ENABLE_SD
            if (ops[i].n)
            {
                bool sep = false;
                snprintf(tsub, sizeof(tsub), "<div class='sub'>");
                size_t to = strlen(tsub);
                if (ops[i].ngap)
                {
                    uint32_t half = (ops[i].ngap + 1) / 2, acc = 0;
                    uint32_t med = PT_GAP_BUCKETS - 1;
                    for (uint32_t b = 0; b < PT_GAP_BUCKETS; b++)
                    {
                        acc += gap_hist[i][b];
                        if (acc >= half) { med = b; break; }
                    }
                    if (med >= PT_GAP_BUCKETS - 1)
                        snprintf(tsub + to, sizeof(tsub) - to, "%s", T(S_PT_HEADWAY_NONE));
                    else
                        snprintf(tsub + to, sizeof(tsub) - to, "%s ~%lu min",
                                 T(S_PT_HEADWAY), (unsigned long)med);
                    to = strlen(tsub);
                    sep = true;
                }
                uint32_t fs = (ops[i].first_sod + 3 * 3600) % 86400;
                uint32_t ls = (ops[i].last_sod  + 3 * 3600) % 86400;
                if (ops[i].n > 1)
                    snprintf(tsub + to, sizeof(tsub) - to,
                             "%s%02lu:%02lu&ndash;%02lu:%02lu", sep ? " &middot; " : "",
                             (unsigned long)(fs / 3600), (unsigned long)(fs % 3600 / 60),
                             (unsigned long)(ls / 3600), (unsigned long)(ls % 3600 / 60));
                else
                    snprintf(tsub + to, sizeof(tsub) - to, "%s%s %02lu:%02lu",
                             sep ? " &middot; " : "", T(S_PT_OPS_FIRST),
                             (unsigned long)(fs / 3600), (unsigned long)(fs % 3600 / 60));
                to = strlen(tsub);
                int b1 = -1, b2 = -1;
                for (int d = 0; d < PT_DEST_SLOTS; d++)
                {
                    /* 0 is "not stated" in R09, not a destination number. */
                    if (!ops[i].dcnt[d] || !ops[i].dest[d]) continue;
                    if (b1 < 0 || ops[i].dcnt[d] > ops[i].dcnt[b1]) { b2 = b1; b1 = d; }
                    else if (b2 < 0 || ops[i].dcnt[d] > ops[i].dcnt[b2]) b2 = d;
                }
                if (b1 >= 0)
                {
                    snprintf(tsub + to, sizeof(tsub) - to, " &middot; %s %u (%lu)",
                             T(S_PT_DIR), (unsigned)ops[i].dest[b1],
                             (unsigned long)ops[i].dcnt[b1]);
                    to = strlen(tsub);
                    if (b2 >= 0)
                    {
                        snprintf(tsub + to, sizeof(tsub) - to, " / %u (%lu)",
                                 (unsigned)ops[i].dest[b2], (unsigned long)ops[i].dcnt[b2]);
                        to = strlen(tsub);
                    }
                }
                if (ops[i].nreq)
                {
                    snprintf(tsub + to, sizeof(tsub) - to, " &middot; %s: %lu",
                             T(S_PT_REQ_COUNT), (unsigned long)ops[i].nreq);
                    to = strlen(tsub);
                }
                snprintf(tsub + to, sizeof(tsub) - to, "</div>");
                any_ops = true;
            }
#endif

            /* 481 worst case (96 of markup, tsub[256], the other cells at their widest). wrapcell
             * lets the grey line wrap. Unwrapped it took 343 of 390 px and pushed the last-seen
             * column off the screen. */
            char row[512];
            HTML_PRINTF(row,
                "<tr><td class='wrapcell'><b>%u</b>%s</td><td>%lu</td><td>%s</td><td>%s</td>"
                "<td>%s</td><td>%s</td><td>%lu</td></tr>",
                l->line, tsub, (unsigned long)l->sightings, last, avg, late, early,
                (unsigned long)l->dev_zero);
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

        char note[768];
        HTML_PRINTF(note, "<p class='note hlp'>%s</p>", T(S_PT_LIMIT));
        httpd_resp_send_chunk(req, note, HTTPD_RESP_USE_STRLEN);
        if (any_ops)
        {
            /* In pieces: a cut-off </details> eats the rest of the page, and the text grew
             * to 1004 of the 1024 its buffer had. */
            web_send_parts(req, "<details class='dtl'><summary>", T(S_PT_OPS_SUM),
                           "</summary><p class='note'>", T(S_PT_OPS_HINT), "</p></details>", NULL);
        }
    }

#if CONFIG_ENABLE_SD
    /* The summary says how late a line usually is; this says WHEN. */
    {
        if (pn > 0)
        {
            /* Closes the lines group and opens its own. The one
             * unconditional </div> below then balances either path. */
            web_send_parts(req, "</div><div class='grp' id='pt-pass'><h2>", T(S_PT_PASSAGES),
                           "</h2>", NULL);
            pt_send_pass_head(req);
            /* The array feeds the headway maths and the newest rows at the top. The table
             * stays at 120 rows, because 2000 rows would be hundreds of kilobytes of markup. */
            int pshow = pn < 120 ? pn : 120;
            for (int k = 0; k < pshow; k++)
                pt_send_pass_row(req, &pass[k]);
            httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
            if (pn > pshow)
            {
                char pcap[256];
                HTML_PRINTF(pcap, "<p class='note'>%s</p>", T(S_PT_CAPPED));
                httpd_resp_send_chunk(req, pcap, HTTPD_RESP_USE_STRLEN);
            }
            web_send_parts(req, "<p class='note hlp'>", T(S_PT_REQ_HINT), "</p>", NULL);
        }
    }
#endif

    /* The count is a state, the rule behind it an explanation, so only that one is hlp.
     * 151 of 256 and 34 of 192 (German, %d at its widest). */
    char act[256], atext[192];
    snprintf(atext, sizeof(atext), T(S_PT_ACTIVE), ptlog_open_count());
    HTML_PRINTF(act, "<p class='note'>%s</p><p class='note hlp'>%s</p>", atext,
                T(S_PT_ACTIVE_HINT));
    httpd_resp_send_chunk(req, act, HTTPD_RESP_USE_STRLEN);

    /* 512 against 315 measured (German). */
    char clr[512];
    HTML_PRINTF(clr,
        /* r.ok, because this page is ungated but the POST is not. Reloading after a 401
         * would show the untouched list as if the reset had happened. A 403 shows its text in
         * the page's language, set by ?lang=, because a bare POST would answer German. */
        "<p class='btnrow'><button class='dngr' onclick=\"if(confirm('%s'))fetch('/transit/clear"
        "?lang='+document.documentElement.lang,{method:'POST'}).then(function(r){"
        "if(r.ok)location.reload();else if(r.status==403)r.text().then(alert);});\">%s</button>"
        "</p></div>",
        T(S_PT_CLEAR_CONFIRM), T(S_PT_CLEAR));
    httpd_resp_send_chunk(req, clr, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* Both clear handlers below must answer a failed check_update_auth() with
 * send_auth_required(): without the 401 the browser's fetch() just hangs. */

static esp_err_t transit_clear_post_handler(httpd_req_t *req)
{
    /* Destroys persisted user data, so it belongs behind the same gate as the
     * firmware update and the raw downloads. */
    if (!check_update_auth(req))
        return send_auth_required(req);
    ptlog_clear();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t senders_clear_post_handler(httpd_req_t *req)
{
    /* Destroys persisted user data, so it belongs behind the same gate as the
     * firmware update and the raw downloads. */
    if (!check_update_auth(req))
        return send_auth_required(req);
    inventory_clear();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* ================================================================== */
/*  Basic Auth for /update and /settings write                        */
/* ================================================================== */

bool check_update_auth(httpd_req_t *req)
{
    char stored_hash[CONFIG_WEB_PASSWORD_BUFFER_SIZE] = {0};
    size_t hash_size = sizeof(stored_hash);
    esp_err_t res = config_get_str(CONFIG_INDEX_WEB_PASSWORD, stored_hash, &hash_size);

    if (res != ESP_OK || hash_size <= 1)
        return true;  /* no password set => open */

    size_t hdr_len = httpd_req_get_hdr_value_len(req, "Authorization");
    if (hdr_len == 0 || hdr_len > 512)
        return false;

    char *auth_hdr = malloc(hdr_len + 1);
    if (!auth_hdr)
        return false;

    bool ok = false;
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_hdr, hdr_len + 1) == ESP_OK &&
        strncmp(auth_hdr, "Basic ", 6) == 0)
    {
        unsigned char decoded[384];
        size_t declen = 0;
        if (mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &declen,
                                  (const unsigned char *)auth_hdr + 6, strlen(auth_hdr + 6)) == 0)
        {
            decoded[declen] = '\0';
            if (strncmp((char *)decoded, "admin:", 6) == 0)
            {
                char attempt_hash[65];
                config_hash_web_password((char *)decoded + 6, attempt_hash);
                ok = strcmp(attempt_hash, stored_hash) == 0;
            }
        }
    }
    free(auth_hdr);
    return ok;
}

/* webserver_init silences httpd_uri's line for a refused password, so guessing would leave no
 * trace. One line a minute at most, as web_csrf.c does. cold keeps it off the handlers' own
 * path. */
static __attribute__((noinline, cold)) void log_wrong_password(httpd_req_t *req)
{
    static uint32_t last1;   /* uptime second + 1 of the last line, 0 before the first */
    static unsigned quiet;   /* wrong passwords since that line; httpd task (defer_gated) */
    uint32_t now1 = (uint32_t)(esp_timer_get_time() / 1000000) + 1;
    if (last1 && now1 - last1 < 60)
    {
        quiet++;
        return;
    }
    ESP_LOGW(TAG, "%s %.48s: wrong web password (%u more since the last line)",
             req->method == HTTP_POST ? "POST" : "GET", req->uri, quiet);
    last1 = now1;
    quiet = 0;
}

esp_err_t send_auth_required(httpd_req_t *req)
{
    /* Without Authorization it is the browser's first ask, not a guess. */
    if (httpd_req_get_hdr_value_len(req, "Authorization") > 0)
        log_wrong_password(req);
    /* Both answers keep 401 and this header, or the browser never asks. */
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"its-g5-receiver\"");
    if (!wants_page(req))
    {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return web_auth_page(req);
}

/* ================================================================== */
/*  /settings  - now in web_settings.c                                */
/* ================================================================== */

/* ================================================================== */
/*  /sniffer, /reboot, /confirm                                       */
/* ================================================================== */

static esp_err_t sniffer_post_handler(httpd_req_t *req)
{
    /* Stopping reception destroys data that was never recorded, so it belongs
     * behind the same gate as the clear endpoints and the downloads. */
    if (!check_update_auth(req))
        return send_auth_required(req);

    char query[32] = {0};
    char action[16] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
        httpd_query_key_value(query, "action", action, sizeof(action));

    int ret;
    esp_err_t run_res;
    if (strcmp(action, "start") == 0)
    {
        /* do_sniffer_cmd assigns the channel global before sniffer_start()
         * refuses -- a second Start would retune a running capture via resume. */
        if (sniffer_is_running())
        {
            httpd_resp_set_type(req, "text/plain");
            httpd_resp_sendstr(req, "OK");
            return ESP_OK;
        }
        uint32_t chan = 0;
        config_get_u32(CONFIG_INDEX_AUTOSTART_CHAN, &chan);
        /* channel is an MHz frequency for phy_change_channel(), not a WLAN
         * channel: without -c the console default (1) is no valid frequency. */
        if (chan < 5800 || chan > 5900)
        {
            /* Only reachable via "no autostart" on /settings; the button starts
             * anyway, because an explicit click asks for reception. */
            ESP_LOGW(TAG, "autostart disabled, start button uses G5CC");
            chan = 5900;
        }
        char cmd[32];
        snprintf(cmd, sizeof(cmd), "sniffer -c %lu", (unsigned long)chan);
        run_res = esp_console_run(cmd, &ret);
    }
    else if (strcmp(action, "stop") == 0)
        run_res = esp_console_run("sniffer --stop", &ret);
    else
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "action must be start or stop");
        return ESP_FAIL;
    }

    if (run_res != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_console_run failed: %s", esp_err_to_name(run_res));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "command failed");
        return ESP_FAIL;
    }
    /* run_res only says the line was parsed and dispatched. ret is what the
     * command itself returned (do_sniffer_cmd: 0 ok, 1 failed). Without this check a
     * failed command would answer 200, and the button would flip to a state the
     * receiver never reached. */
    if (ret != 0)
    {
        ESP_LOGE(TAG, "sniffer command returned %d", ret);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "command failed");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_timer_handle_t reboot_timer_handle;

static void reboot_timer_cb(void *arg)
{
    esp_restart();
}

static esp_err_t reboot_post_handler(httpd_req_t *req)
{
    /* Same gate as /poweroff and /sniffer: a POST here restarts a mounted
     * receiver, so it needs the password. */
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* Before the restart, not after the reply: esp_restart() is as abrupt for
     * the SD card as pulling the plug, so without this a reboot silently
     * discards whatever the PCAP ring had not written yet (minutes of it). */
    sysmon_flush_persistent();
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "Rebooting...");
    esp_timer_start_once(reboot_timer_handle, 1000000);
    return ESP_OK;
}

/* POST /poweroff: flushes every buffer and unmounts. The reply IS the "safe to
 * unplug" signal, so it runs inline. Recording stays off until a remount or reboot. */
#if CONFIG_ENABLE_SD
static esp_err_t poweroff_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* Leaves the card unmounted with auto-remount inhibited, so recording,
     * tracks, transit log and pcap stop. Same gate as /sdcard/mount, which undoes it. */
    if (!check_update_auth(req))
        return send_auth_required(req);

    /* Same flush the restart paths use, plus the unmount that only makes
     * sense when nothing is going to run afterwards. */
    size_t unsaved = sysmon_flush_persistent();

    /* Before the unmount: sysmon would otherwise mount the card straight
     * back after 30 s, undoing the safe state while the user walks over. */
    sdcard_inhibit_auto_remount();

    esp_err_t err = sdcard_unmount();
    bool ok = (err == ESP_OK);
    ESP_LOGW(TAG, "prepare-for-power-off: unmount %s",
             ok ? "ok" : esp_err_to_name(err));
    if (!ok)
        sdcard_allow_auto_remount();  /* power-off didn't happen -- normal operation resumes */

    /* Before the body: once it is sent the status is fixed, and returning
     * ESP_FAIL afterwards only closes the connection. Without this every
     * outcome answered 200 and a caller could cut power on a mounted card. */
    if (!ok)
        httpd_resp_set_status(req, err == ESP_ERR_TIMEOUT ? "503 Busy"
                                                          : "500 Internal Server Error");
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    /* ESP_ERR_TIMEOUT = a worker-side download still streams from the card
     * (sdcard_read_begin) -- unmounting would free FATFS under its open FILE. */
    const char *msg = ok ? T(S_POWEROFF_OK)
                    : err == ESP_ERR_TIMEOUT ? T(S_POWEROFF_DOWNLOAD)
                    : err == ESP_ERR_INVALID_STATE ? T(S_POWEROFF_BLOCKED)
                                                   : T(S_POWEROFF_FAIL);
    /* A failed flush does not change the status. On a wedged card the power
     * cut is the remedy, so the answer names the loss instead of refusing. */
    char unsaved_hdr[12];
    char body[256];
    if (unsaved > 0)
    {
        snprintf(unsaved_hdr, sizeof(unsaved_hdr), "%u", (unsigned)unsaved);
        httpd_resp_set_hdr(req, "X-Unsaved-Bytes", unsaved_hdr);
        char sz[24];
        fmt_bytes((uint64_t)unsaved, current_lang, sz, sizeof(sz));
        int n = snprintf(body, sizeof(body), "%s ", msg);
        if (n > 0 && (size_t)n < sizeof(body))
            snprintf(body + n, sizeof(body) - n, T(S_POWEROFF_UNSAVED), sz);
        msg = body;
    }
    httpd_resp_sendstr(req, msg);
    return ok ? ESP_OK : ESP_FAIL;
}
#endif

static esp_err_t confirm_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* Cancels the rollback, so it closes the only way back after a bad
     * update -- same gate as /update and /reboot. */
    if (!check_update_auth(req))
        return send_auth_required(req);
    bool ok = ota_confirm();
    /* Before the body, for the same reason as /poweroff. A caller that only reads the
     * status must not take a failed confirm for a done one, because the device would
     * roll back at the next reboot, or half an hour later when the timer runs. */
    if (!ok)
        httpd_resp_set_status(req, "500 Internal Server Error");
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, ok ? T(S_CONFIRMED) : T(S_CONFIRM_ERROR));
    return ok ? ESP_OK : ESP_FAIL;
}

/* The hide button of the failed-update notice. Same gate as /confirm: it removes a
 * notice every visitor should see. */
static esp_err_t update_ack_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    bool ok = ota_failed_ack();
    if (!ok)
        httpd_resp_set_status(req, HTTPD_500);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, "", 0);
    return ESP_OK;
}

/* ================================================================== */
/*  Icons + PWA web-app manifest                                      */
/* ================================================================== */

static esp_err_t send_asset(httpd_req_t *req, const uint8_t *start, const uint8_t *end,
                             const char *content_type, const char *cache_control)
{
    httpd_resp_set_type(req, content_type);
    httpd_resp_set_hdr(req, "Cache-Control", cache_control);
    return httpd_resp_send(req, (const char *)start, end - start);
}

/* Same as send_asset(), for the assets that are embedded gzip-compressed. The
 * firmware cannot unpack them, so a client without gzip is told so instead. */
static esp_err_t send_asset_gz(httpd_req_t *req, const uint8_t *start, const uint8_t *end,
                                const char *content_type, const char *cache_control)
{
    char accept[96] = "";
    size_t len = httpd_req_get_hdr_value_len(req, "Accept-Encoding");
    /* A list too long for the buffer always names gzip somewhere, so only a
     * header that fits and lacks it counts as a client that cannot take it. */
    bool gzip_ok = len >= sizeof(accept);
    if (!gzip_ok && len > 0 &&
        httpd_req_get_hdr_value_str(req, "Accept-Encoding", accept, sizeof(accept)) == ESP_OK)
        gzip_ok = strstr(accept, "gzip") != NULL;
    if (!gzip_ok)
    {
        httpd_resp_set_status(req, "406 Not Acceptable");
        httpd_resp_set_type(req, "text/plain");
        return httpd_resp_sendstr(req, "This file is stored gzipped; request it with gzip accepted.\n");
    }
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    /* Cache-Control says immutable, so a shared cache must not hand the packed
     * copy to a client that asked without gzip. */
    httpd_resp_set_hdr(req, "Vary", "Accept-Encoding");
    return send_asset(req, start, end, content_type, cache_control);
}

static esp_err_t send_png(httpd_req_t *req, const uint8_t *start, const uint8_t *end)
{
    return send_asset(req, start, end, "image/png", "max-age=86400");
}

/* Vendored Leaflet -- see the extern decls above. 1-year "immutable" cache is
 * safe: the file only changes when the whole device gets reflashed with a
 * new firmware, which is a brand new binary regardless of any URL. */
static esp_err_t leaflet_js_get_handler(httpd_req_t *req)
{
    return send_asset_gz(req, leaflet_js_gz_start, leaflet_js_gz_end,
                       "application/javascript", "max-age=31536000, immutable");
}

/* Shared page stylesheet. Immutable is safe because the page links it with
 * ?v=<ELF hash>: every new build is a new URL, so no stale sheet survives. */
static esp_err_t s_css_get_handler(httpd_req_t *req)
{
    return send_asset_gz(req, s_css_gz_start, s_css_gz_end,
                       "text/css", "max-age=31536000, immutable");
}

static esp_err_t leaflet_css_get_handler(httpd_req_t *req)
{
    return send_asset_gz(req, leaflet_css_gz_start, leaflet_css_gz_end,
                       "text/css", "max-age=31536000, immutable");
}

/* Nav-bar logo, 52 px for the 26 px box so it stays sharp on a 2x display. */
static esp_err_t logo_get_handler(httpd_req_t *req)
{
    return send_png(req, logo_52_png_start, logo_52_png_end);
}

/* Browser tab / favicon. Wildcard-matched (/favicon*) so favicon.ico probes
 * are answered too instead of 404'ing into the log. */
static esp_err_t favicon_get_handler(httpd_req_t *req)
{
    return send_png(req, favicon_png_start, favicon_png_end);
}

/* iOS home-screen icon. Wildcard (/apple-touch-icon*) covers the sized variants
 * iOS probes (…-152x152.png, …-precomposed.png). Full-bleed PNG so iOS applies
 * its own rounded mask (no white border). */
static esp_err_t apple_icon_get_handler(httpd_req_t *req)
{
    return send_png(req, apple_touch_icon_png_start, apple_touch_icon_png_end);
}

static esp_err_t icon192_get_handler(httpd_req_t *req)
{
    return send_png(req, icon_192_png_start, icon_192_png_end);
}

static esp_err_t icon512_get_handler(httpd_req_t *req)
{
    return send_png(req, icon_512_png_start, icon_512_png_end);
}

/* Web-app manifest: lets iOS/Android save the page as a standalone web app. */
static esp_err_t manifest_get_handler(httpd_req_t *req)
{
    /* Carries the node id for the same reason the tab title does. Without it, two
     * receivers would show on the home screen under one name. Both fields get it,
     * because a launcher may use either. */
    char nodeid[CONFIG_NODEID_BUFFER_SIZE] = {0};
    size_t nodeid_size = sizeof(nodeid);
    config_get_str(CONFIG_INDEX_NODEID, nodeid, &nodeid_size);
    /* A name stored before set_is_utf8() existed can still be broken UTF-8. One bad
     * byte makes the whole manifest unparseable, and then the icon loses its name too.
     * The generic name is the better half-failure. */
    if (!set_is_utf8(nodeid))
        nodeid[0] = '\0';
    /* A JSON string, not markup. A quote or backslash would break the manifest, and an
     * HTML entity would show up literally under the icon. The few unsafe bytes are
     * therefore dropped instead of escaped. They are all below 0x80, so no UTF-8
     * sequence is cut in half. */
    char safe[CONFIG_NODEID_BUFFER_SIZE];
    size_t so = 0;
    for (size_t i = 0; nodeid[i] && so + 1 < sizeof(safe); i++)
        if ((unsigned char)nodeid[i] >= 0x20 && nodeid[i] != '"' && nodeid[i] != '\\')
            safe[so++] = nodeid[i];
    safe[so] = '\0';

    /* Brand first, id after, in the same order as the tab title, so the two
     * cannot disagree about what this receiver is called. */
    char name[sizeof(safe) + 16];
    if (safe[0])
        snprintf(name, sizeof(name), "ITS G5 - %s", safe);
    else
        snprintf(name, sizeof(name), "ITS G5 Node");

    /* 512: 320 bytes of fixed JSON plus twice the 79-byte name = 479. */
    char m[512];
    snprintf(m, sizeof(m),
        "{\"name\":\"%s\",\"short_name\":\"%s\",\"start_url\":\"/\","
        /* Same ground as body in s.css -- otherwise the home-screen splash
         * flashes the old, lighter colour before the page paints. */
        "\"display\":\"standalone\",\"background_color\":\"#06070b\","
        "\"theme_color\":\"#f2b134\",\"icons\":["
        "{\"src\":\"/apple-touch-icon.png\",\"sizes\":\"180x180\",\"type\":\"image/png\"},"
        "{\"src\":\"/icon-192.png\",\"sizes\":\"192x192\",\"type\":\"image/png\"},"
        "{\"src\":\"/icon-512.png\",\"sizes\":\"512x512\",\"type\":\"image/png\"}]}",
        name, name);
    httpd_resp_set_type(req, "application/manifest+json");
    /* An hour, not a day, because the manifest carries the node id. A renamed
     * receiver would otherwise keep the old home-screen name until the next day. */
    httpd_resp_set_hdr(req, "Cache-Control", "max-age=3600");
    return httpd_resp_send(req, m, HTTPD_RESP_USE_STRLEN);
}

/* ================================================================== */
/*  system  - now in web_system.c                                     */
/* ================================================================== */
/* ================================================================== */
/*  GET/POST /update                                                  */
/* ================================================================== */

/* Unlike the playback bar, this one shows a real percentage: XMLHttpRequest
 * reports upload progress. The button is disabled while it runs, because a
 * second upload mid-flash would be harmful, not merely wasteful. */
static const char UPDATE_FORM_FMT[] =
    "<p class='note hlp'>%s</p>"
    "<input type='file' id='fw' accept='.bin' aria-label='%s'>"
    "<button id='upbtn' onclick='upload()'>%s</button>"
    "<style>@keyframes upflash{0%%{background-position:0 0}"
    "100%%{background-position:40px 0}}"
    "#upbar.busy{background-image:linear-gradient(115deg,"
    "rgba(255,255,255,.35) 25%%,transparent 25%%,transparent 50%%,"
    "rgba(255,255,255,.35) 50%%,rgba(255,255,255,.35) 75%%,transparent 75%%);"
    "background-size:40px 40px;animation:upflash .9s linear infinite}</style>"
    "<div id='upwrap' style='display:none;margin:12px 0;max-width:360px'>"
    "<div style='height:8px;border-radius:4px;background:#2a3138;overflow:hidden'>"
    "<div id='upbar' style='height:100%%;width:0;border-radius:4px;"
    "background:linear-gradient(90deg,#f2b134,#ffc861);transition:width .2s'></div></div>"
    "<p style='margin:6px 0 0'><small id='uppct'></small></p></div>"
    "<p id='result'></p>"
    "<script>"
    /* Reads the image head: 0xE9 at 0, chip id at 12, app magic 0xABCD5432 at 32, version at
     * 48, project at 80. An app image passes, a bootloader, partition table or ota_data image
     * fails. Output only via textContent. */
    /* UPDS: the page's decimal separator for the MB count. */
    "var UPV='%s',UPC=%u,UPP='%s',UPMAX=%lu,upWant=null,upBad=null,upOther=false,"
    "UPDS=document.documentElement.lang=='de'?',':'.';"
    "document.getElementById('fw').onchange=function(){"
    "var f=this.files[0],r=document.getElementById('result');"
    "r.className='';r.textContent='';upWant=null;upBad=null;upOther=false;"
    "if(!f)return;"
    "if(f.size>UPMAX)upBad='%s';else if(f.size<256)upBad='%s';"
    "if(upBad){r.className='alarm';r.textContent=upBad;return;}"
    "if(!window.FileReader||!window.DataView)return;"
    "var fr=new FileReader();fr.onload=function(){"
    "var a=fr.result,b=new Uint8Array(a),d=new DataView(a);"
    "function s(o){var t='';for(var i=o;i<o+32&&b[i];i++)t+=String.fromCharCode(b[i]);"
    "return t.replace(/[^ -~]/g,'');}"
    "if(b[0]!==233||d.getUint32(32,true)!==2882360370)upBad='%s';"
    "else if(d.getUint16(12,true)!==UPC)upBad='%s';"
    "if(upBad){r.className='alarm';r.textContent=upBad;return;}"
    "upWant=s(48);var p=s(80);upOther=p!==UPP;"
    "r.textContent='%s '+upWant+(upWant===UPV?' \\u00b7 %s':'')+(upOther?' \\u00b7 '+p:'');};"
    "fr.readAsArrayBuffer(f.slice(0,112));};"
    "function upload(){"
    "var f=document.getElementById('fw').files[0];"
    "if(!f){alert('%s');return;}"
    "if(upBad){alert(upBad);return;}if(upOther&&!confirm('%s'))return;"
    "var b=document.getElementById('upbtn'),w=document.getElementById('upwrap'),"
    "bar=document.getElementById('upbar'),pct=document.getElementById('uppct');"
    "b.disabled=true;b.style.opacity=0.6;w.style.display='';bar.style.width='0';"
    "var xhr=new XMLHttpRequest();"
    "xhr.open('POST','/update?lang=%s');"
    "xhr.upload.onprogress=function(e){if(!e.lengthComputable)return;"
    "var p=Math.round(e.loaded*100/e.total);bar.style.width=p+'%%';"
    "pct.textContent=p+'%% \\u00b7 '+(e.loaded/1048576).toFixed(1).replace('.',UPDS)+'/'"
    "+(e.total/1048576).toFixed(1).replace('.',UPDS)+' MB';};"
    /* onprogress measures the browser's send, not the device's flashing -- so
     * this phase shows an indeterminate stripe instead of reading as a freeze. */
    "xhr.upload.onload=function(){bar.style.width='100%%';bar.className='busy';"
    "pct.textContent='%s';};"
    "xhr.onload=function(){b.disabled=false;b.style.opacity=1;"
    "bar.className='';pct.textContent='';"
    /* A 401 carries the English default text of httpd, because XHR never gets the 401 page.
     * Every other answer is a sentence from the table (the update error texts and
     * S_UPD_NOT_CONFIRMED). */
    "var r=document.getElementById('result');r.className=xhr.status===200?'':'alarm';"
    "r.innerText=xhr.status===401?'%s':xhr.responseText;"
    "if(xhr.status===200)waitBack();};"
    /* Polls /status.json until the device answers, then compares fw with the version read
     * from the file: another version means the bootloader went back. Bounded like itsReboot. */
    "function waitBack(){var t0=Date.now(),r=document.getElementById('result'),"
    "base=r.innerText;"
    "setTimeout(function(){var iv=setInterval(function(){"
    "var n=Math.round((Date.now()-t0)/1000);"
    "if(n>120){clearInterval(iv);r.className='alarm';r.textContent='%s';return;}"
    "r.innerText=base+' %s ('+n+' s)';"
    /* Both requests carry the language, or resolve_language() would answer German
     * after an English update page. */
    "fetch('/status.json?lang=%s',{cache:'no-store'})"
    ".then(function(x){return x.ok?x.json():null;}).then(function(d){"
    "if(!d)return;clearInterval(iv);"
    "if(upWant&&d.fw!==upWant){r.className='alarm';r.textContent='%s'+(d.fw?' ('+d.fw+')':'');return;}"
    "location.href='/?lang=%s';}).catch(function(){});"
    "},2000);},6000);}"
    "xhr.onerror=function(){b.disabled=false;b.style.opacity=1;bar.className='';"
    "w.style.display='none';"
    "var r=document.getElementById('result');r.className='alarm';r.innerText='%s';};"
    "document.getElementById('result').innerText='%s';"
    "xhr.send(f);"
    "}"
    /* The </div> closes the group that update_get_handler opens before the form. */
    "</script></div>";

static esp_err_t update_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    /* The upload POST carries no query string of its own, so it must be told
     * the current language here. Otherwise resolve_language() on that request
     * defaults to German, whatever the page shows. */
    const char *lc = current_lang == LANG_DE ? "de" : "en";
    const esp_app_desc_t *app = esp_app_get_description();

    /* The browser refuses a file larger than the slot. Without a slot the device answers. */
    const esp_partition_t *up = esp_ota_get_next_update_partition(NULL);
    unsigned long upmax = up ? (unsigned long)up->size : 0xFFFFFFFFUL;
    /* 6144 against 5035 measured (German; English 4906). In PSRAM:
     * only the httpd task runs this handler, and 5 KB would crowd its 16 KB stack. A cut
     * <script> would silently disable the upload. */
    static EXT_RAM_BSS_ATTR char form[6144];
    HTML_PRINTF(form, UPDATE_FORM_FMT,
             T(S_UPD_INTRO), T(S_UPD_FILE_LABEL), T(S_UPLOAD),
             app->version, (unsigned)CONFIG_IDF_FIRMWARE_CHIP_ID, app->project_name, upmax,
             T(S_UPD_ERR_SIZE), T(S_UPD_ERR_NOFW), T(S_UPD_ERR_NOFW), T(S_UPD_ERR_CHIP),
             T(S_UPD_FILEVER), T(S_UPD_SAMEVER),
             T(S_UPD_CHOOSE_FILE), T(S_UPD_OTHER_PROJ), lc,
             T(S_UPD_FLASHING), T(S_UPD_DENIED),
             T(S_UPD_SLOW), T(S_UPD_WAIT), lc, T(S_UPD_BACK_OLD), lc,
             T(S_UPLOAD_FAIL), T(S_UPLOADING));

    send_page_header(req, T(S_TITLE_UPDATE));
    /* A state, not an explanation, so no hlp: which firmware runs and whether it is
     * confirmed. The last failure shows only once its red notice was hidden. */
    ota_run_t rs = ota_running_state();
    const char *stsep = rs == OTA_RUN_OTHER ? "" : " &middot; ";
    const char *stw = rs == OTA_RUN_CONFIRMED ? T(S_UPD_ST_OK)
                    : rs == OTA_RUN_PENDING   ? T(S_UPD_ST_PENDING) : "";
    char failpart[256] = "";    /* 216 at most */
    ota_failed_t f;
    if (ota_failed_get(&f) && f.acked)
    {
        char fver[192];         /* 186 at most: 31 characters escaped */
        html_escape(f.version, fver, sizeof(fver));
        snprintf(failpart, sizeof(failpart), "<br>%s %s", T(S_UPD_LAST_FAILED), fver);
    }
    /* 512 against 327 measured (German). */
    char upst[512];
    HTML_PRINTF(upst, "<p class='note'>%s <b>%s</b>%s%s%s</p>",
                T(S_UPD_RUNNING), app->version, stsep, stw, failpart);
    httpd_resp_send_chunk(req, upst, HTTPD_RESP_USE_STRLEN);
    /* Outside the form and without hlp: the file name and the confirm step stay on the
     * page when the explanations are off. The group opened here closes in UPDATE_FORM_FMT. */
    web_send_parts(req, "<div class='grp top'><p class='note'>", T(S_UPD_FILE), "</p>", NULL);
    httpd_resp_send_chunk(req, form, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ESP_OK, not ESP_FAIL, because then httpd drains the body (httpd_req_delete, v6.1
 * httpd_parse.c). A socket closed on unread data resets, and the browser shows its own error
 * instead of this sentence. */
static esp_err_t upd_fail(httpd_req_t *req, httpd_err_code_t code, str_id_t id, esp_err_t e)
{
    char uerr[256];     /* 185 at most (German, an error name of 48) */
    if (id == S_UPD_ERR_FLASH)
        snprintf(uerr, sizeof(uerr), T(id), esp_err_to_name(e));
    else
        snprintf(uerr, sizeof(uerr), "%s", T(id));
    httpd_resp_send_err(req, code, uerr);
    return ESP_OK;
}

static esp_err_t update_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    if (req->content_len == 0)
        return upd_fail(req, HTTPD_400_BAD_REQUEST, S_UPD_ERR_NOFW, ESP_OK);

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition)
        return upd_fail(req, HTTPD_500_INTERNAL_SERVER_ERROR, S_UPD_ERR_FLASH, ESP_ERR_NOT_FOUND);
    if (req->content_len > update_partition->size)
        return upd_fail(req, HTTPD_413_CONTENT_TOO_LARGE, S_UPD_ERR_SIZE, ESP_OK);

    ESP_LOGI(TAG, "Web OTA: %u bytes -> %s", (unsigned)req->content_len, update_partition->label);

    /* Checked before esp_ota_begin, because begin erases the other slot and a wrong file
     * would wipe the previous firmware, the only way back. */
    char buf[1024];
    size_t want = req->content_len < sizeof(buf) ? req->content_len : sizeof(buf);
    size_t head = 0;
    int timeout_retries = 0;
    while (head < want)
    {
        int received = httpd_req_recv(req, buf + head, want - head);
        if (received == HTTPD_SOCK_ERR_TIMEOUT)
        {
            if (++timeout_retries > 5)
                break;
            continue;
        }
        if (received <= 0)
            break;
        timeout_retries = 0;
        head += (size_t)received;
    }
    if (head < want)
        return upd_fail(req, HTTPD_500_INTERNAL_SERVER_ERROR, S_UPD_ERR_CUT, ESP_OK);
    /* Image header, first segment header, then the app descriptor with its magic word. */
    const size_t magic_at = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
    uint32_t magic = 0;
    uint16_t chip = 0;
    if (head >= magic_at + sizeof(magic))
    {
        memcpy(&magic, buf + magic_at, sizeof(magic));
        memcpy(&chip, buf + offsetof(esp_image_header_t, chip_id), sizeof(chip));
    }
    if ((uint8_t)buf[0] != ESP_IMAGE_HEADER_MAGIC || magic != ESP_APP_DESC_MAGIC_WORD)
        return upd_fail(req, HTTPD_400_BAD_REQUEST, S_UPD_ERR_NOFW, ESP_OK);
    if (chip != CONFIG_IDF_FIRMWARE_CHIP_ID)
        return upd_fail(req, HTTPD_400_BAD_REQUEST, S_UPD_ERR_CHIP, ESP_OK);

    esp_ota_handle_t ota_handle;
    esp_err_t err = esp_ota_begin(update_partition, req->content_len, &ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
        if (err == ESP_ERR_OTA_ROLLBACK_INVALID_STATE)
            return upd_fail(req, HTTPD_500_INTERNAL_SERVER_ERROR, S_UPD_NOT_CONFIRMED, err);
        return upd_fail(req, HTTPD_500_INTERNAL_SERVER_ERROR, S_UPD_ERR_FLASH, err);
    }

    /* A broken connection and a refused write stay apart: only the second is about the file. */
    bool cut = false;
    esp_err_t werr = esp_ota_write(ota_handle, buf, head);
    size_t remaining = req->content_len - head;
    timeout_retries = 0;
    while (werr == ESP_OK && remaining > 0)
    {
        int to_read = remaining < sizeof(buf) ? (int)remaining : (int)sizeof(buf);
        int received = httpd_req_recv(req, buf, to_read);

        if (received == HTTPD_SOCK_ERR_TIMEOUT)
        {
            if (++timeout_retries > 5) { cut = true; break; }
            continue;
        }
        if (received <= 0) { cut = true; break; }
        timeout_retries = 0;

        werr = esp_ota_write(ota_handle, buf, received);
        remaining -= received;
    }

    if (cut || werr != ESP_OK)
    {
        esp_ota_abort(ota_handle);
        if (cut)
            return upd_fail(req, HTTPD_500_INTERNAL_SERVER_ERROR, S_UPD_ERR_CUT, ESP_OK);
        ESP_LOGE(TAG, "esp_ota_write failed: %s", esp_err_to_name(werr));
        if (werr == ESP_ERR_OTA_VALIDATE_FAILED)
            return upd_fail(req, HTTPD_400_BAD_REQUEST, S_UPD_ERR_NOFW, werr);
        return upd_fail(req, HTTPD_500_INTERNAL_SERVER_ERROR, S_UPD_ERR_FLASH, werr);
    }

    err = esp_ota_end(ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
        if (err == ESP_ERR_OTA_VALIDATE_FAILED)
            return upd_fail(req, HTTPD_400_BAD_REQUEST, S_UPD_ERR_NOFW, err);
        return upd_fail(req, HTTPD_500_INTERNAL_SERVER_ERROR, S_UPD_ERR_FLASH, err);
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(err));
        return upd_fail(req, HTTPD_500_INTERNAL_SERVER_ERROR, S_UPD_ERR_FLASH, err);
    }
    /* A new image in the slot: if this build fails too, its notice must show again. */
    ota_failed_forget();

    ESP_LOGI(TAG, "Web OTA successful, rebooting");
    sysmon_flush_persistent();   /* same reason as /reboot */
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, T(S_UPLOAD_OK));
    esp_timer_start_once(reboot_timer_handle, 1000000);
    return ESP_OK;
}

#if CONFIG_ENABLE_SD
/* ================================================================== */
/*  /sdcard and /fs  - now in web_files.c                             */
/* ================================================================== */

/* ================================================================== */
/*  Streaming tar (ustar) writer - now in web_tar.c                   */
/* ================================================================== */
/* ==================================================================
 *  Slow-request worker: long downloads move off the single httpd
 *  task, so the UI keeps answering during a multi-MB transfer.
 * ================================================================== */

typedef struct { httpd_req_t *req; esp_err_t (*fn)(httpd_req_t *); } slow_job_t;
static QueueHandle_t slow_q;

static void slow_worker_task(void *arg)
{
    (void)arg;
    slow_job_t j;
    for (;;)
    {
        if (xQueueReceive(slow_q, &j, portMAX_DELAY) != pdTRUE)
            continue;
        /* httpd closes a failed request by itself only on its own task, so the worker does it
         * here. Otherwise the browser waits for the rest of a broken download. This must come
         * before complete, while the socket still belongs to this request. */
        if (j.fn(j.req) != ESP_OK)
            httpd_sess_trigger_close(j.req->handle, httpd_req_to_sockfd(j.req));
        httpd_req_async_handler_complete(j.req);
    }
}

/* No worker (at boot, or when it could not be created) means inline, because nothing runs
 * beside it. A saturated worker means a refusal, because the handlers share statics
 * (tar_full/tar_hdr, partbuf) and a second inline instance would silently corrupt both
 * streams. */
static esp_err_t defer_to_worker(httpd_req_t *req, esp_err_t (*fn)(httpd_req_t *))
{
    if (!slow_q)
        return fn(req);
    httpd_req_t *copy = NULL;
    if (uxQueueSpacesAvailable(slow_q) == 0 ||
        httpd_req_async_handler_begin(req, &copy) != ESP_OK)
    {
        httpd_resp_set_status(req, "503 Busy");
        httpd_resp_set_type(req, "text/plain; charset=utf-8");
        /* Same header the deferred handlers set themselves: without it a peer's
         * browser drops the 503 as a CORS error and never sees the reason. */
        httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
        httpd_resp_sendstr(req, "Beschäftigt – eine andere Übertragung läuft noch. / "
                                "Busy – another transfer is still running.");
        return ESP_OK;
    }
    slow_job_t j = { .req = copy, .fn = fn };
    xQueueSend(slow_q, &j, 0);  /* space checked above; httpd is the only producer */
    return ESP_OK;
}

/* Password first, on the httpd task: a refusal gets the 401 page, whose buffers belong to
 * this task. The handlers keep their own check for the inline path at boot. */
static esp_err_t defer_gated(httpd_req_t *req, esp_err_t (*fn)(httpd_req_t *))
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    return defer_to_worker(req, fn);
}

static esp_err_t messages_search_async(httpd_req_t *req)  { return defer_to_worker(req, messages_search_stream); }

/* ?chk=1 only asks whether an export could run, so the page can say why instead of handing
 * out an empty file. No password: /status.json names the SD state too. */
static esp_err_t messages_export_async(httpd_req_t *req)
{
    /* The page puts chk=1 first, so the 64-byte head always holds it. */
    char q[64], v[4];
    esp_err_t qr = url_query_head(req, q, sizeof(q));
    if ((qr == ESP_OK || qr == ESP_ERR_HTTPD_RESULT_TRUNC) &&
        httpd_query_key_value(q, "chk", v, sizeof(v)) == ESP_OK)
    {
        resolve_language(req);
        httpd_resp_set_type(req, "text/plain; charset=utf-8");
        if (!sdcard_is_mounted())
        {
            httpd_resp_set_status(req, "409 Conflict");
            return httpd_resp_sendstr(req, T(S_SD_NOT_MOUNTED));
        }
        if (slow_q && uxQueueSpacesAvailable(slow_q) == 0)
        {
            httpd_resp_set_status(req, "503 Busy");
            return httpd_resp_sendstr(req, T(S_ARCH_BUSY));
        }
        return httpd_resp_sendstr(req, "OK");
    }
    return defer_gated(req, messages_export_stream);
}

static esp_err_t sdcard_download_async(httpd_req_t *req)  { return defer_gated(req, sdcard_download_handler); }
static esp_err_t sdcard_tar_async(httpd_req_t *req)       { return defer_gated(req, sdcard_tar_handler); }
static esp_err_t internal_tar_async(httpd_req_t *req)     { return defer_gated(req, internal_tar_handler); }
static esp_err_t internal_download_async(httpd_req_t *req){ return defer_gated(req, internal_download_handler); }
static esp_err_t partimg_download_async(httpd_req_t *req) { return defer_gated(req, partimg_download_handler); }
static esp_err_t playback_get_async(httpd_req_t *req)     { return defer_to_worker(req, playback_get_handler); }
/* 7.5 s at days=7, far too long to run on the one httpd task. */
static esp_err_t tracks_get_async(httpd_req_t *req)       { return defer_to_worker(req, tracks_get_handler); }

/* ================================================================== */
/*  /logs  -- view the SD log files inline in the browser             */
/* ================================================================== */

#define LOGS_TAIL_KB 24   /* how much of the file tail to show */

/* True if `s` starts with an ESP-IDF log prefix carrying a millisecond
 * timestamp, as in "I (05:12:44.623)". Only that exact shape is accepted. */
static bool log_line_has_msec(const char *s, size_t len)
{
    if (len < 16) return false;
    if (!(s[0] >= 'A' && s[0] <= 'Z')) return false;
    if (s[1] != ' ' || s[2] != '(') return false;
    for (int i = 0; i < 8; i++)
    {
        char c = s[3 + i];
        bool digit = (c >= '0' && c <= '9');
        if ((i == 2 || i == 5) ? (c != ':') : !digit) return false;
    }
    if (s[11] != '.') return false;
    return s[12] >= '0' && s[12] <= '9' &&
           s[13] >= '0' && s[13] <= '9' &&
           s[14] >= '0' && s[14] <= '9' && s[15] == ')';
}

/* Streams the log tail HTML-escaped, line by line so the millisecond trim
 * always sees a whole timestamp. Dates come from the log's daily markers. False after a read
 * error: picolibc's fgets ends on it like on the end of the file. */
static bool stream_tail_escaped(httpd_req_t *req, FILE *f, long start)
{
    fseek(f, start, SEEK_SET);
    char line[512];
    char out[sizeof(line) * 5];

    /* Starting mid-file lands in the middle of a line; drop that remnant. */
    if (start > 0 && !fgets(line, sizeof(line), f))
        return !ferror(f);

    bool at_line_start = true;
    while (fgets(line, sizeof(line), f))
    {
        /* picolibc hands back the piece before a read error: it is no line. */
        if (ferror(f))
            break;
        size_t len = strlen(line);
        size_t i = 0;
        /* Only at a line start and only for the log's own prefix: drop ".623"
         * from "(05:12:44.623)". The file on the card keeps its milliseconds. */
        if (at_line_start && log_line_has_msec(line, len))
        {
            memcpy(out, line, 11);        /* "I (05:12:44" */
            httpd_resp_send_chunk(req, out, 11);
            i = 15;                       /* skip ".623", resume at ')' */
        }
        /* A line longer than the buffer comes back in pieces; only the piece
         * that actually ended with a newline starts a new line. */
        at_line_start = (len > 0 && line[len - 1] == '\n');

        size_t o = 0;
        for (; i < len; i++)
        {
            const char *rep;
            switch (line[i])
            {
            case '<': rep = "&lt;";  break;
            case '>': rep = "&gt;";  break;
            case '&': rep = "&amp;"; break;
            default:  out[o++] = line[i]; continue;
            }
            size_t rl = strlen(rep);
            memcpy(out + o, rep, rl);
            o += rl;
        }
        if (o)
            httpd_resp_send_chunk(req, out, o);
    }
    return !ferror(f);
}

#define RLOG_SNAP 10496   /* 64 lines of 160 plus separators */
#define RLOG_ESC  1200    /* one line, worst case 6x through html_escape */

/* The RAM console, as its own group. Streamed line by line: 64 lines can reach
 * 60 KB once escaped, which no single buffer here should have to hold. */
static void send_console_block(httpd_req_t *req)
{
    /* Measured 304 of 512. */
    char head[512];
    HTML_PRINTF(head,
        "<div class='grp'><h2>%s</h2><p class='note hlp'>%s</p>"
        "<div class='scroll'><pre id='rlpre' class='logpre'>",
        T(S_LOGS_CONSOLE), T(S_LOGS_CONSOLE_HINT));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

    /* Only the httpd task reaches this page (no defer_to_worker), so static is
     * safe and keeps 10 KB off the 16 KB stack. */
    static EXT_RAM_BSS_ATTR char raw[RLOG_SNAP];
    size_t n = sdlog_recent(raw, sizeof(raw));
    char *line = raw;
    while (n && line < raw + n)
    {
        char *nl = memchr(line, '\n', (size_t)(raw + n - line));
        size_t len = nl ? (size_t)(nl - line) : (size_t)(raw + n - line);
        if (len)
        {
            char esc[RLOG_ESC];
            char tmp[192];
            if (len > sizeof(tmp) - 1) len = sizeof(tmp) - 1;
            memcpy(tmp, line, len);
            tmp[len] = '\0';
            html_escape(tmp, esc, sizeof(esc));
            httpd_resp_send_chunk(req, esc, HTTPD_RESP_USE_STRLEN);
            httpd_resp_send_chunk(req, "\n", HTTPD_RESP_USE_STRLEN);
        }
        if (!nl) break;
        line = nl + 1;
    }
    if (!n)
        httpd_resp_send_chunk(req, "&ndash;", HTTPD_RESP_USE_STRLEN);
    /* The newest lines are at the bottom, so the box opens there. The script follows the
     * <pre>, because the filter script of the page runs before this block exists. */
    httpd_resp_send_chunk(req,
        "</pre></div><script>(function(){var c=document.getElementById('rlpre');"
        "c.scrollTop=c.scrollHeight;})();</script></div>", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t logs_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    /* Whitelist, never a path from the query: ?f=1 selects the rotated file
     * and nothing else, so no ?p=-style traversal can reach fopen() here. */
    char q[256] = {0}, fv[8] = {0};
    bool old = false;
    if (httpd_req_get_url_query_str(req, q, sizeof(q)) == ESP_OK &&
        httpd_query_key_value(q, "f", fv, sizeof(fv)) == ESP_OK)
        old = (strcmp(fv, "1") == 0);

    const char *path = old ? CONFIG_SNIFFER_MOUNT_POINT "/logs/system.1.log"
                           : CONFIG_SNIFFER_MOUNT_POINT "/logs/system.log";
    const char *lc = current_lang == LANG_DE ? "de" : "en";

    send_page_header(req, T(S_TITLE_LOGS));

    /* The two view links go out before fopen(), so the switch to the other file
     * stays reachable when this one is missing. The <p> closes after it. 248 of 512. */
    char nav[512];
    HTML_PRINTF(nav,
        /* The group opens after the links: they must stay reachable when the
         * file is missing, and that branch closes the group itself. */
        "<p class='tools'><a class='sgb' href='/logs?f=0&amp;lang=%s'%s>%s</a> "
        "<a class='sgb' href='/logs?f=1&amp;lang=%s'%s>%s</a> "
        "<a class='sgb' href='/logs?f=%s&amp;lang=%s'>&#8635; %s</a>",
        lc, old ? "" : " aria-current='page'", T(S_LOGS_SYS),
        lc, old ? " aria-current='page'" : "", T(S_LOGS_OLD),
        old ? "1" : "0", lc, T(S_LOGS_REFRESH));
    httpd_resp_send_chunk(req, nav, HTTPD_RESP_USE_STRLEN);

    /* Counted reader -- the tail stream sends many chunks with the FILE open;
     * see sdcard_download_handler. */
    bool rd = sdcard_read_begin();
    FILE *f = rd ? fopen(path, "rb") : NULL;

    /* Only with a file behind it: /sdcard/download answers 404 for a missing
     * one, and the link sat next to "no log file" all the same. 83 of 192. */
    if (f)
    {
        char dl[192];
        HTML_PRINTF(dl,
            " <a class='dlb' href='/sdcard/download?p=logs/%s'>&#8595; %s</a>",
            old ? "system.1.log" : "system.log", T(S_LOGS_DOWNLOAD));
        httpd_resp_send_chunk(req, dl, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "</p><div class='grp top'>", HTTPD_RESP_USE_STRLEN);

    if (!f)
    {
        if (rd)
            sdcard_read_end();
        /* For the previous log a missing file is normal, for the current one it is not, so
         * each has its own sentence. 192 is enough: the longer of the two texts needs 169
         * bytes with its markup. */
        char msg[192];
        snprintf(msg, sizeof(msg), "<p class='note'>%s</p></div>",
                 T(old ? S_LOGS_NONE_OLD : S_LOGS_NONE));
        httpd_resp_send_chunk(req, msg, HTTPD_RESP_USE_STRLEN);
        send_console_block(req);
        httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, NULL, 0);
        return ESP_OK;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    long start = size > (LOGS_TAIL_KB * 1024) ? size - (LOGS_TAIL_KB * 1024) : 0;

    /* Only now that the file is open: on the error path above there is no
     * <pre> and no filter script, so live controls there would be dead. */
    /* Disabled until the script below defines lgf(): a dead button that looks
     * live is worse than one that visibly is not ready (CSS: #lgb0:disabled). */
    /* Measured 398 of 640. */
    char tools[640];
    HTML_PRINTF(tools,
        "<p class='btnrow tools'><button id='lgb0' disabled aria-pressed='true' onclick='lgf(0)'>%s</button> "
        "<button id='lgb1' disabled aria-pressed='false' onclick='lgf(1)'>%s</button> "
        "<input id='lgq' disabled oninput='lgf()' placeholder='%s' aria-label='%s' size='16'> "
        "<span id='lgcnt' class='cap'>%s</span> <small>%s</small></p>",
        T(S_LOGS_F_ALL), T(S_LOGS_F_PROB), T(S_LOGS_SEARCH), T(S_LOGS_SEARCH),
        T(S_LOGS_LOADING), T(S_LOGS_LINES));
    httpd_resp_send_chunk(req, tools, HTTPD_RESP_USE_STRLEN);

    /* Temperature info lines fill about four fifths of the 24 KB: this state line (not hlp) says
     * how many the filter hides and brings them back. Hidden until lgf() runs. Measured 274 of 320. */
    char tline[320];
    HTML_PRINTF(tline,
        "<p id='lgtmp' class='note' hidden><span id='lgtn'></span> "
        "<span class='lg0'>%s</span><span class='lg1'>%s</span> &middot; "
        "<a href='#' id='lgtl'><span class='lg0'>%s</span><span class='lg1'>%s</span></a></p>",
        T(S_LOGS_TEMP_HID), T(S_LOGS_TEMP_SHOWN), T(S_LOGS_SHOW), T(S_LOGS_HIDE));
    httpd_resp_send_chunk(req, tline, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "<pre id='lgpre' class='logpre'>", HTTPD_RESP_USE_STRLEN);

    bool whole = stream_tail_escaped(req, f, start);
    fclose(f);
    sdcard_read_end();

    httpd_resp_send_chunk(req, "</pre>", HTTPD_RESP_USE_STRLEN);
    /* Without it a read error would pass for the end of the log. In pieces: no buffer here. */
    if (!whole)
        web_send_parts(req, "<div class='warn'><p>", T(S_LOGS_READ_ERR), "</p></div>", NULL);
    /* Filtering happens in the browser on the text already delivered. Read via
     * textContent, written as text nodes and spans via textContent, never innerHTML,
     * because log lines are unescaped foreign material. */
    httpd_resp_send_chunk(req,
        "<script>(function(){"
        "var pre=document.getElementById('lgpre'),tp=document.getElementById('lgtmp');"
        "var lines=pre.textContent.split('\\n'),mode=0,total=0,tmp=0,showT=false;"
        /* Matches the ESP-IDF prefix "W (05:12:44) "; the server already
         * trimmed the milliseconds, so the shape is fixed. */
        "function lvl(s){return (s.length>2&&s[0]>='A'&&s[0]<='Z'&&s[1]===' '&&s[2]==='(')?s[0]:'';}"
        /* The same test as rlog_noisy() in sdlog.c: info lines only, so a failing
         * sensor's W and E lines always show. */
        "function isT(s){return s[0]==='I'&&s.indexOf(') TEMPERATURE: ')>0;}"
        "for(var i=0;i<lines.length;i++)if(lvl(lines[i])){total++;if(isT(lines[i]))tmp++;}"
        "document.getElementById('lgtn').textContent=tmp;"
        "document.getElementById('lgtl').onclick=function(){showT=!showT;"
        "tp.classList.toggle('on',showT);lgf();return false;};"
        "window.lgf=function(m){"
        "if(m!==undefined)mode=m;"
        "var q=document.getElementById('lgq').value.toLowerCase(),n=0,buf=[],cls='',"
        "f=document.createDocumentFragment();"
        "function out(s,c){if(c){if(buf.length){f.appendChild(document.createTextNode(buf.join('\\n')+'\\n'));buf=[];}"
        "var sp=document.createElement('span');sp.className=c;sp.textContent=s+'\\n';"
        "f.appendChild(sp);}else buf.push(s);}"
        /* Lines without a prefix (backtraces, wrapped long lines) inherit the visibility
         * and the colour of the line above; unfiltered they must start visible. */
        "var keep=(mode===0&&!q);"
        "for(var i=0;i<lines.length;i++){var s=lines[i],l=lvl(s);"
        /* The daily marker has no prefix and would be inherited away, taking
         * the only date reference in the filtered view with it. */
        "if(s.indexOf('=====')===0){out(s,'');continue;}"
        "if(l){cls=l==='W'?'lw':l==='E'?'le':'';keep=(mode===0)||(l==='W'||l==='E');"
        "if(keep&&!showT&&isT(s))keep=false;"
        "if(keep&&q)keep=s.toLowerCase().indexOf(q)>=0;"
        "if(keep)n++;}"
        "if(keep)out(s,cls);}"
        "if(buf.length)f.appendChild(document.createTextNode(buf.join('\\n')));"
        "pre.textContent='';pre.appendChild(f);"
        "document.getElementById('lgcnt').textContent=n+' / '+total;"
        "document.getElementById('lgb0').setAttribute('aria-pressed',mode===0?'true':'false');"
        "document.getElementById('lgb1').setAttribute('aria-pressed',mode===1?'true':'false');"
        /* The temperature line only in the view of all lines (mode 0), because the problem
         * filter drops these lines anyway. */
        "tp.hidden=!(mode===0&&tmp>0);"
        /* Open at the newest line, and again after every filter change. */
        "pre.scrollTop=pre.scrollHeight;};"
        "['lgb0','lgb1','lgq'].forEach(function(i){"
        "document.getElementById(i).disabled=false;});"
        /* The newest lines on the first screen (s.css .logpre.fit): the box ends where the
         * screen ends, measured once from its top after lgf(0) showed the temperature line. */
        "lgf(0);pre.style.setProperty('--lgtop',Math.round(pre.getBoundingClientRect().top+scrollY)+'px');"
        "pre.classList.add('fit');pre.scrollTop=pre.scrollHeight;})();</script>", HTTPD_RESP_USE_STRLEN);
    /* Below the box: above it, the explanations pushed the newest lines off a 360x640 screen.
     * Two buffers, not one appended: both formats come from T(), appending needs a clamped return. */
    char note[128], hint[256];
    httpd_resp_send_chunk(req, "<p class='note hlp'>", HTTPD_RESP_USE_STRLEN);
    snprintf(note, sizeof(note), T(S_LOGS_TAIL), LOGS_TAIL_KB);
    httpd_resp_send_chunk(req, note, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, " ", HTTPD_RESP_USE_STRLEN);
    snprintf(hint, sizeof(hint), T(S_LOGS_FILTER_HINT), LOGS_TAIL_KB);
    httpd_resp_send_chunk(req, hint, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "</p>", HTTPD_RESP_USE_STRLEN);
    /* Own chunk so the closing tag of the page's group is findable. */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    send_console_block(req);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}
#endif // CONFIG_ENABLE_SD

/* ================================================================== */
/*  Init                                                               */
/* ================================================================== */

void webserver_init(void)
{
    /* Browsers abort keep-alive connections all the time, on page reloads and
     * when navigating away. Each one logs a harmless "httpd_sock_err: error in
     * recv : 104" (ECONNRESET) warning, pure noise in the SD log. */
    esp_log_level_set("httpd_txrx", ESP_LOG_ERROR);
    /* A dirty-closed tab makes every broadcast warn -- hundreds of lines a day
     * describing a browser that left. Genuine faults still log at E. */
    esp_log_level_set("httpd_ws", ESP_LOG_ERROR);
    /* Unthrottled W lines per failed handler (401, 403 too), 400, 404, 405, 414, 431, 501, 505:
     * another site could fill the 64-line console. web_csrf.c and the 401 log once a minute. */
    esp_log_level_set("httpd_uri", ESP_LOG_ERROR);
    esp_log_level_set("httpd_parse", ESP_LOG_ERROR);

    msg_ring_mutex = xSemaphoreCreateMutex();
    if (!msg_ring_mutex)
        ESP_LOGE(TAG, "Failed to create message ring mutex");
    /* Before the sniffer's first CPM: without its lock the store notes nothing. */
    cpm_store_init();
    its_certcache_init();
    /* Before the sniffer's first frame, like the cache: the lock comes first. */
    its_msgsig_init();
    its_msgsig_set_sink(msgsig_sink);
    /* Reads the crash-dump flag once, before httpd starts; afterwards only the httpd task touches it. */
    web_coredump_scan();

    esp_timer_create_args_t timer_args = {
        .callback = reboot_timer_cb, .arg = NULL, .name = "web_reboot"
    };
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &reboot_timer_handle));

    /* Own timer, not sysmon's 5 s pass: that one writes to the SD card in the
     * same round, so a stalling card would silently stretch a "minute". */
    /* Task dispatch, not ISR: the ring is in PSRAM. Started before httpd so a
     * server that fails to come up still leaves an hour of history behind. */
    static esp_timer_handle_t hist_tick_handle;
    esp_timer_create_args_t hist_args = {
        .callback = hist_tick, .arg = NULL, .name = "hist_tick",
        /* A missed minute stays a gap. Catching up would write the same
         * 60-second window into several slots and stretch the hour. */
        .skip_unhandled_events = true
    };
    ESP_ERROR_CHECK(esp_timer_create(&hist_args, &hist_tick_handle));
    ESP_ERROR_CHECK(esp_timer_start_periodic(hist_tick_handle, 60000000ull));

    ESP_ERROR_CHECK(esp_event_handler_register(MQTT_EVENT_BASE, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL));

    /* The configured time zone first, then NTP once we get an IP. */
    web_tz_reload();
    ESP_ERROR_CHECK(esp_event_handler_register(APP_EVENT_BASE, APP_ETHERNET_MGMT_INTERFACE_GOT_IP,
                                               time_sync_event_handler, NULL));

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.stack_size = 16384;
    config.lru_purge_enable = true;
    /* This must stay above the number of routes below (61 with SD and WebSocket). A route
     * past the limit is not registered, and the loop logs it. */
    config.max_uri_handlers = 64;
    /* /messages and /map each hold a /ws socket open for as long as the tab
     * is open. Dead sessions pile up until ws_broadcast_work reaps them. */
    config.max_open_sockets = 11;
    /* sdkconfig raises CONFIG_HTTPD_MAX_URI_LEN to 4096 for bulk selections.
     * req->uri is sized at compile time, so config.max_uri_len cannot lift it. */
    /* Wildcard matching lets one handler answer all the icon variants a browser
     * probes (/favicon*, /apple-touch-icon*). Exact routes still match exactly. */
    config.uri_match_fn = httpd_uri_match_wildcard;

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        return;
    }
#if CONFIG_HTTPD_WS_SUPPORT
    g_httpd_server = server;
    /* Started only after httpd is up: the tick queues work onto the httpd
     * task, so ticking earlier (or with a failed server) would be pointless. */
    static esp_timer_handle_t ws_tick_handle;
    esp_timer_create_args_t ws_tick_args = {
        .callback = ws_broadcast_tick, .arg = NULL, .name = "ws_tick"
    };
    ESP_ERROR_CHECK(esp_timer_create(&ws_tick_args, &ws_tick_handle));
    ESP_ERROR_CHECK(esp_timer_start_periodic(ws_tick_handle, 1000000)); /* 1s */
#endif

    static const httpd_uri_t uris[] = {
        { .uri = "/",         .method = HTTP_GET,  .handler = status_page_handler },
        { .uri = "/status.json", .method = HTTP_GET, .handler = status_json_get_handler },
        /* The fault bar alone, polled by /map and /messages (web_faults.c). */
        { .uri = "/faults.json", .method = HTTP_GET, .handler = web_faults_json_get_handler },
        { .uri = "/messages", .method = HTTP_GET,  .handler = messages_get_handler },
        { .uri = "/settings", .method = HTTP_GET,  .handler = settings_get_handler },
        { .uri = "/settings", .method = HTTP_POST, .handler = settings_post_handler },
        { .uri = "/settings/export.json", .method = HTTP_GET, .handler = settings_export_get_handler },
        { .uri = "/settings/import", .method = HTTP_POST, .handler = settings_import_post_handler },
        { .uri = "/update",   .method = HTTP_GET,  .handler = update_get_handler },
        { .uri = "/update",   .method = HTTP_POST, .handler = update_post_handler },
        { .uri = "/sniffer",  .method = HTTP_POST, .handler = sniffer_post_handler },
        { .uri = "/reboot",   .method = HTTP_POST, .handler = reboot_post_handler },
#if CONFIG_ENABLE_SD
        { .uri = "/poweroff", .method = HTTP_POST, .handler = poweroff_post_handler },
#endif
        { .uri = "/confirm",  .method = HTTP_POST, .handler = confirm_post_handler },
        { .uri = "/update/ack", .method = HTTP_POST, .handler = update_ack_post_handler },
        { .uri = "/system",   .method = HTTP_GET,  .handler = system_get_handler },
        { .uri = "/system.json", .method = HTTP_GET, .handler = system_json_get_handler },
        { .uri = "/system/coredump/clear", .method = HTTP_POST, .handler = coredump_clear_post_handler },
        { .uri = "/system/stats/clear", .method = HTTP_POST, .handler = stats_clear_post_handler },
        { .uri = "/trust",    .method = HTTP_GET,  .handler = trust_get_handler },
        { .uri = "/map",         .method = HTTP_GET, .handler = map_get_handler },
        { .uri = "/senders",     .method = HTTP_GET, .handler = senders_get_handler },
        { .uri = "/senders/clear", .method = HTTP_POST, .handler = senders_clear_post_handler },
        { .uri = "/transit",     .method = HTTP_GET, .handler = transit_get_handler },
        { .uri = "/transit/clear", .method = HTTP_POST, .handler = transit_clear_post_handler },
        { .uri = "/spatem.json", .method = HTTP_GET, .handler = spatem_json_handler },
        { .uri = "/lanes.json",  .method = HTTP_GET, .handler = lanes_json_handler },
        /* RAM only, so in every build: the CPM layer of /map and other receivers' maps. */
        { .uri = "/cpm.json",    .method = HTTP_GET, .handler = web_cpm_json_get_handler },
#if CONFIG_ENABLE_SD
        /* Hourly statistics live on the SD card; without one the page has
         * nothing to show, and its handler is compiled out. */
        { .uri = "/traffic",     .method = HTTP_GET, .handler = traffic_get_handler },
        { .uri = "/warning_areas.json", .method = HTTP_GET, .handler = traffic_areas_json_handler },
        /* The two delete buttons of /traffic, behind the web password like /senders/clear. */
        { .uri = "/traffic/prio/clear", .method = HTTP_POST,
          .handler = traffic_prio_clear_post_handler },
        { .uri = "/traffic/phases/clear", .method = HTTP_POST,
          .handler = traffic_phases_clear_post_handler },
#endif
        { .uri = "/leaflet.js",  .method = HTTP_GET, .handler = leaflet_js_get_handler },
        { .uri = "/leaflet.css", .method = HTTP_GET, .handler = leaflet_css_get_handler },
        { .uri = "/s.css",       .method = HTTP_GET, .handler = s_css_get_handler },
        { .uri = "/favicon*",          .method = HTTP_GET, .handler = favicon_get_handler },
        { .uri = "/apple-touch-icon*", .method = HTTP_GET, .handler = apple_icon_get_handler },
        { .uri = "/logo.png",         .method = HTTP_GET, .handler = logo_get_handler },
        { .uri = "/icon-192.png",      .method = HTTP_GET, .handler = icon192_get_handler },
        { .uri = "/icon-512.png",      .method = HTTP_GET, .handler = icon512_get_handler },
        { .uri = "/manifest.webmanifest", .method = HTTP_GET, .handler = manifest_get_handler },
#if CONFIG_HTTPD_WS_SUPPORT
        /* Another site's page gets no WebSocket: web_csrf.c checks Origin in the handshake. */
        { .uri = "/ws", .method = HTTP_GET, .handler = ws_get_handler, .is_websocket = true,
          .ws_pre_handshake_cb = web_csrf_ws_gate },
#endif
#if CONFIG_ENABLE_SD
        { .uri = "/map/playback",    .method = HTTP_GET,  .handler = playback_get_async },
        { .uri = "/tracks.json",     .method = HTTP_GET,  .handler = tracks_get_async },
        { .uri = "/markers.json",    .method = HTTP_GET,  .handler = markers_json_handler },
        { .uri = "/sdcard",          .method = HTTP_GET,  .handler = sdcard_get_handler },
        { .uri = "/sdcard/download", .method = HTTP_GET,  .handler = sdcard_download_async },
        { .uri = "/sdcard/upload",   .method = HTTP_POST, .handler = sdcard_upload_handler },
        { .uri = "/sdcard/delete",   .method = HTTP_POST, .handler = sdcard_delete_handler },
        { .uri = "/sdcard/format",   .method = HTTP_POST, .handler = sdcard_format_handler },
        { .uri = "/sdcard/upload_rsu", .method = HTTP_POST, .handler = rsu_upload_post_handler },
        { .uri = "/sdcard/upload_rsu/status", .method = HTTP_GET, .handler = rsu_upload_status_handler },
        { .uri = "/messages/search", .method = HTTP_GET, .handler = messages_search_async },
        { .uri = "/messages/export.pcap", .method = HTTP_GET, .handler = messages_export_async },
        { .uri = "/sdcard/mount",    .method = HTTP_POST, .handler = sdcard_mount_handler },
        { .uri = "/fs",              .method = HTTP_GET,  .handler = internal_get_handler },
        { .uri = "/fs/download",     .method = HTTP_GET,  .handler = internal_download_async },
        { .uri = "/fs/part",         .method = HTTP_GET,  .handler = partimg_download_async },
        { .uri = "/fs/tar",          .method = HTTP_GET,  .handler = internal_tar_async },
        { .uri = "/sdcard/tar",      .method = HTTP_GET,  .handler = sdcard_tar_async },
        { .uri = "/logs",            .method = HTTP_GET,  .handler = logs_get_handler },
#endif
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++)
    {
        httpd_uri_t u = uris[i];
        /* Every POST meets web_csrf.c first, the ones without a password check too. The route
         * waits in user_ctx; httpd keeps its own copy of u. */
        if (u.method == HTTP_POST)
        {
            u.handler = web_csrf_gate;
            u.user_ctx = (void *)&uris[i];
        }
        if (httpd_register_uri_handler(server, &u) != ESP_OK)
            ESP_LOGE(TAG, "route %s not registered", u.uri);
    }

#if CONFIG_ENABLE_SD
    /* One worker is deliberate: transfers serialise among themselves (the SD
     * is a serial device anyway) while the httpd task stays responsive. */
    slow_q = xQueueCreate(2, sizeof(slow_job_t));
    if (!slow_q ||
        xTaskCreate(slow_worker_task, "httpslow", 12288, NULL, 4, &slow_worker_handle) != pdPASS)
    {
        ESP_LOGW(TAG, "slow-request worker unavailable, downloads serve inline");
        if (slow_q) { vQueueDelete(slow_q); slow_q = NULL; }
        slow_worker_handle = NULL;
    }
#endif

    ESP_LOGI(TAG, "Web server started on port %d", config.server_port);
}
