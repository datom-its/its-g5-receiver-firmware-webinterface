#include "sdkconfig.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
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
#include "cmd_sniffer.h"
#include "ethernet.h"
#include "events.h"
#include "its_decode.h"
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
#include "sysstat.h"
#include "stats.h"
#include "events_log.h"
#include "tracklog.h"
#include "inventory.h"
#include "ptlog.h"
#include "spatem.h"
#include "bt_stream.h"

#include "webserver.h"
#include "web_strings.h"
#include "webserver_priv.h"
#include "web_tar.h"
#include "web_files.h"
#include "web_settings.h"
#include "web_system.h"
#include "web_traffic.h"

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

/* Europe/Berlin with automatic CET/CEST daylight-saving switch. */
#define LOCAL_TZ   "CET-1CEST,M3.5.0,M10.5.0/3"

static bool sntp_started;

/* ESP_NETIF_SNTP_DEFAULT_CONFIG stores the hostname pointer, not a copy, and
 * the sntp_started guard keeps esp_netif_sntp_init() to a single call, so this
 * buffer must stay alive for the SNTP client's whole lifetime. A configured
 * server takes effect after a reboot, like the other network settings. */
static char ntp_server_buf[CONFIG_NTP_SERVER_BUFFER_SIZE];

static void time_sync_event_handler(void *arg, esp_event_base_t base,
                                    int32_t event_id, void *event_data)
{
    (void)arg; (void)base; (void)event_data;

    if (event_id != APP_ETHERNET_MGMT_INTERFACE_GOT_IP)
        return;

    if (sntp_started)
    {
        /* Network came back: trigger a fresh resync. */
        esp_sntp_restart();
        return;
    }

    size_t ntp_size = sizeof(ntp_server_buf);
    config_get_str(CONFIG_INDEX_NTP_SERVER, ntp_server_buf, &ntp_size);

    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG(ntp_server_buf);
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

/* ================================================================== */
/*  Received-message ring buffer                                      */
/* ================================================================== */

#define WEB_MSG_RING_SIZE   20

#define WEB_MSG_TYPE_LEN 32

typedef struct {
    uint32_t seconds;
    uint32_t microseconds;
    uint32_t length;

    int      rssi;
    char     msgtype[WEB_MSG_TYPE_LEN];
    bool     has_position; /* true if lat_e7/lon_e7/station_id below are valid (CAM's own
                             * referencePosition, or a GN-layer fallback for anything else
                             * that reached an ITS PDU header -- see its_decode_frame) */
    int32_t  lat_e7;       /* WGS84 latitude,  1e-7 degree units */
    int32_t  lon_e7;       /* WGS84 longitude, 1e-7 degree units */
    uint32_t station_id;   /* ItsPduHeader.stationId; stable per sender, only meaningful if has_position */
    bool     has_speed;    /* true if speed_cmps below is valid (vehicles only, not RSUs) */
    int32_t  speed_cmps;   /* speed in cm/s (0.01 m/s units, matches the wire encoding) */
    uint16_t length_dm;    /* CAM vehicle size, decimetres; 0 = not sent/unavailable */
    uint8_t  width_dm;
    uint8_t  src_mac[6];   /* 802.11 sender address (Addr2) */
    bool     has_src_mac;
    /* VDV R09.16 telegram out of a public-transport CAM, 0 = not carried. */
    uint16_t pt_line;      /* LN Liniennummer */
    uint8_t  pt_course;    /* KN Kursnummer */
    uint16_t pt_dest;      /* ZN Zielnummer */
    uint8_t  pt_request;   /* HA 0=none, 1=straight, 2=left, 3=right */
    uint8_t  pt_priority;  /* PR */
    int16_t  pt_deviation; /* ZW, signed: positive = running late */
    bool     pt_telegram;
    /* CAM detail (see its_cam_detail_t). The path history costs 64 bytes an
     * entry, i.e. 1.3 KB across this 20-slot ring in PSRAM -- cheap enough
     * to carry rather than re-derive. */
    uint8_t  n_path;
    int32_t  path_lat_e7[ITS_PATH_MAX], path_lon_e7[ITS_PATH_MAX];
    uint16_t heading_ddeg; /* 0.1 deg, 0xFFFF = not sent */
    uint8_t  accel_ctrl;   /* ITS_ACC_*, only valid if has_accel_ctrl */
    bool     has_accel_ctrl;
    uint8_t  ext_lights;   /* ITS_LIGHT_*, only valid if has_lights */
    bool     has_lights;
    uint8_t  role;         /* VehicleRole, 0xFF = not sent */
    bool     embarking;    /* public transport: doors open */
} web_msg_entry_t;

static EXT_RAM_BSS_ATTR web_msg_entry_t msg_ring[WEB_MSG_RING_SIZE];
static size_t msg_ring_head;
static size_t msg_ring_count;
static uint32_t msg_total_count;
/* Uptime second of the last message, biased by 1 so 0 means "none yet".
 * 32 bit keeps the lockless read on the httpd task free of torn values. */
static uint32_t msg_last_sec1;
static SemaphoreHandle_t msg_ring_mutex;

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

/* Message-type breakdown for the small stats block on the status page. The
 * labels come from its_decode: the message type, prefixed with the station type
 * when that is known, e.g. "CAM", "Bus CAM" or "RSU GeoNet:2004". Those
 * combinations are why the table has this many slots. A linear scan over a
 * fixed table needs no dynamic allocation. */
#define MSG_TYPE_STATS_SLOTS 24
typedef struct {
    char     label[WEB_MSG_TYPE_LEN];
    uint32_t count;
} msg_type_stat_t;
static msg_type_stat_t msg_type_stats[MSG_TYPE_STATS_SLOTS];

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
    /* All slots taken by distinct labels, which shouldn't happen in practice.
     * Drop the label rather than grow this table unbounded. */
}

/* Packet-rate tracking: per-second buckets in a 60-second ring. */
#define RATE_WINDOW_SECS 60
typedef struct {
    uint64_t sec;
    uint32_t count;
} rate_bucket_t;
static rate_bucket_t rate_buckets[RATE_WINDOW_SECS];

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

static uint32_t rate_packets_last_minute(void)
{
    uint64_t now_sec = esp_timer_get_time() / 1000000ull;
    uint32_t sum = 0;
    for (size_t i = 0; i < RATE_WINDOW_SECS; i++)
        if (rate_buckets[i].sec != 0 && now_sec - rate_buckets[i].sec < RATE_WINDOW_SECS)
            sum += rate_buckets[i].count;
    return sum;
}

/* Minute history behind the two one-hour sparklines: one writer (hist_tick, on
 * the esp_timer task), one reader (httpd). Ordering is spelled out at both ends. */
#define HIST_MINUTES    60
#define HIST_RATE_MIN   60          /* msgs/min floor, so a quiet hour stays flat */
#define HIST_TEMP_SPAN  5           /* K, narrowest band, so noise cannot fill the box */
#define HIST_TEMP_NONE  INT16_MIN
/* Compiler-only barrier. The part is single-core, so no CPU fence is needed. Not
 * __atomic_signal_fence: that orders atomics, and clang sinks plain loads past it. */
#define HIST_BARRIER()  __asm__ __volatile__("" ::: "memory")

typedef struct {
    uint32_t stamp;     /* sample number held here; 0 = empty or being written */
    uint32_t rate;      /* frames counted in that minute */
    int16_t  temp_dc;   /* 0.1 C, HIST_TEMP_NONE if the sensor did not answer */
    int16_t  pad;
} hist_slot_t;

/* Kept in PSRAM, so 720 bytes of internal RAM stay free. Every field is 32 or
 * 16 bit and aligned, so no single field can tear on this RV32 part. */
static EXT_RAM_BSS_ATTR hist_slot_t hist_ring[HIST_MINUTES];
static uint32_t hist_count;     /* samples taken, newest at (hist_count-1)%60 */

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
static void entry_from_decoded(web_msg_entry_t *e, const its_decoded_t *d)
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
    e->pt_request = d->pt_request;
    e->pt_priority = d->pt_priority;
    e->pt_deviation = d->pt_deviation;
    e->pt_telegram = d->pt_telegram;
    e->heading_ddeg = d->cam.has_heading ? d->cam.heading_ddeg : 0xFFFF;
    e->has_accel_ctrl = d->cam.has_accel_ctrl;
    e->accel_ctrl = d->cam.accel_ctrl;
    e->has_lights = d->cam.has_lights;
    e->ext_lights = d->cam.ext_lights;
    e->role = d->cam.role;
    e->embarking = d->pt_embarking;
    e->n_path = d->cam.n_path;
    memcpy(e->path_lat_e7, d->cam.path_lat_e7, sizeof(e->path_lat_e7));
    memcpy(e->path_lon_e7, d->cam.path_lon_e7, sizeof(e->path_lon_e7));
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
    its_decoded_t d;
    its_decode_frame(packet->payload, packet->length, &d);
    entry_from_decoded(e, &d);
    uint8_t st_code = d.station_type, msg_id = d.message_id;
    msg_type_stats_record(e->msgtype);
    tstat_note(st_code, e->station_id, msg_id, e->has_speed, e->speed_cmps);
    inventory_note(e->seconds, e->rssi, &d);
    ptlog_note(e->seconds, e->station_id, &d);
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
                d.has_src_mac ? d.src_mac : NULL);
    /* Vehicle track for the map overlay. Skipped internally when disabled,
     * for RSUs, and for a vehicle that hasn't moved far enough yet. */
    if (e->has_position)
        tracklog_note(e->seconds, e->station_id, st_code, e->lat_e7, e->lon_e7);

    if (d.spat.valid)
        spatem_note(&d.spat, e->station_id, e->seconds, e->has_position, e->lat_e7, e->lon_e7);
    if (d.map.valid)
    {
        spatem_note_name(&d.map, e->seconds);
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

/* Format seconds as "Xd Xh Xm Xs" (omitting leading zero units). */
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

/* The same states as the /status.json reasons. "not_mounted" means the card
 * never answered, "unmounted" means somebody unmounted it on purpose. */
static const char *sd_state_reason(sd_state_t st)
{
    switch (st) {
    case SDST_NO_USAGE:  return "usage_error";
    case SDST_NO_FS:     return "no_fs";
    case SDST_UNMOUNTED: return "unmounted";
    case SDST_WRITE_FAILED: return "write_failed";
    default:             return "not_mounted";
    }
}
#endif

#ifdef CONFIG_ENABLE_TEMPERATURE
/* Enclosure temperature, not a chip limit: the LM75 is on the board next to
 * the chip, so these are the numbers the operator should watch. */
static const char *temp_class(float tc)
{
    if (tc != tc) return "v-off"; /* NaN = sensor not answering */
    if (tc < 0.0f) return "";
    return lvl_class((unsigned)tc, 60, 75);
}
#endif

/* Format a byte count as B, KiB or MiB for readability. */

void format_bytes(uint32_t bytes, char *out, size_t out_size)
{
    if (bytes >= 1024 * 1024)
        snprintf(out, out_size, "%.2f MiB", (double)bytes / (1024.0 * 1024.0));
    else if (bytes >= 1024)
        snprintf(out, out_size, "%.1f KiB", (double)bytes / 1024.0);
    else
        snprintf(out, out_size, "%lu B", (unsigned long)bytes);
}

/* Format a unix-epoch seconds value as local HH:MM:SS (TZ = Europe/Berlin). */
static void format_clock(uint32_t epoch_sec, uint32_t usec, char *out, size_t out_size)
{
    /* Once NTP has synced, webserver_handle_packet stamps frames with real
     * epoch time and this shows local HH:MM:SS. Before sync the stored value is
     * a device-relative clock (< 1 year), shown as raw seconds.milliseconds. */
    if (epoch_sec > 31536000) /* > 1 year => looks like real wall-clock */
    {
        time_t t = (time_t)epoch_sec;
        struct tm tm_local;
        localtime_r(&t, &tm_local);
        snprintf(out, out_size, "%02d:%02d:%02d", tm_local.tm_hour, tm_local.tm_min, tm_local.tm_sec);
    }
    else
    {
        /* device-relative: show seconds.milliseconds */
        snprintf(out, out_size, "%lu.%03lus",
                 (unsigned long)epoch_sec, (unsigned long)(usec / 1000));
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

/* Resolve request language from ?lang=de|en query, default German. */
void resolve_language(httpd_req_t *req)
{
    current_lang = LANG_DE;
    /* 512, not the full 4096 URI limit -- that would not fit the httpd stack.
     * A truncated query still carries lang=, which the flag links put first. */
    char query[512];
    char val[8];
    esp_err_t qr = httpd_req_get_url_query_str(req, query, sizeof(query));
    if ((qr == ESP_OK || qr == ESP_ERR_HTTPD_RESULT_TRUNC) &&
        httpd_query_key_value(query, "lang", val, sizeof(val)) == ESP_OK)
    {
        if (strcmp(val, "en") == 0)
            current_lang = LANG_EN;
    }
}

/* ================================================================== */
/*  Shared HTML chrome                                                */
/* ================================================================== */

static const char PAGE_HEADER_FMT[] =
    "<!DOCTYPE html><html lang='%s'><head><meta charset='utf-8'>"
    "<meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<meta name='description' content='ITS-G5 roadside receiver: live status, "
    "decoded messages, map, traffic statistics and logs.'>"
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
    /* Stylesheet is served from /s.css; ?v= is the ELF hash prefix, so every
     * new build -- not just a version bump -- gets a fresh, uncached URL. */
    "<link rel='stylesheet' href='/s.css?v=%s'>"
    "<title>%s</title></head><body><div class='wrap'>"
    /* Context line above the nav: weekday, date, clock, node. With auto-refresh
     * the clock stays current. Without it the clock names the load time, which
     * shows how old the figures below are. */
    "%s"
    /* .navlinks is a separate flex item from .lang (see CSS) so the page
     * links can wrap onto multiple rows on narrow screens while the flag
     * switch stays anchored top-right instead of dropping onto its own,
     * disconnected-looking full-width row. */
    "<nav>"
    /* Logo (Tokyo-tower app icon), top-left. Plain image, not a link -- as a
     * nav <a> to '/' it would get the amber "active" highlight on the status
     * page, which looked wrong. */
    "<span class='logo'><img src='/logo.png' alt='ITS G5' height='26' width='26'></span>"
    /* Hidden checkbox + label = the CSS-only hamburger toggle (see the .brgr
     * / .nvt rules). Placed before .navlinks so the ".nvt:checked~.navlinks"
     * sibling selector can reveal it. &#9776; = the hamburger glyph. */
    "<input type='checkbox' id='nvt' class='nvt'>"
    "<label for='nvt' class='brgr' aria-label='Men&uuml;'>&#9776;</label>"
    "<div class='navlinks'>"
    "<a href='/?lang=%s'>%s</a><a href='/messages?lang=%s'>%s</a>"
    "<a href='/settings?lang=%s'>%s</a><a href='/update?lang=%s'>%s</a>"
    "<a href='/map?lang=%s'>%s</a>"
    "<a href='/senders?lang=%s'>%s</a>"
    "<a href='/transit?lang=%s'>%s</a>"
#if CONFIG_ENABLE_SD
    "<a href='/traffic?lang=%s'>%s</a>"
#endif
    "<a href='/system?lang=%s'>%s</a>"
#if CONFIG_ENABLE_SD
    "<a href='/sdcard?lang=%s'>%s</a><a href='/logs?lang=%s'>%s</a>"
#endif
    "</div>"
    /* Flag toggle (Austria/UK), current language highlighted. The flags are HTML
     * numeric entities (regional indicator symbols), not raw UTF-8 in the C source. */
    "<span class='lang'>"
    "<a href='?lang=de' class='%s' title='Deutsch'>&#127462;&#127481;</a>"
    "<a href='?lang=en' class='%s' title='English'>&#127468;&#127463;</a>"
    "</span></nav>"
    /* Sent with the page header, not the footer: the flags are clickable long
     * before the page finishes streaming, and until this runs they drop the query. */
    "<script>var lq=location.search.replace(/^\\?/,'').split('&').filter(function(s){"
    "return s&&s.indexOf('=')>0&&s.slice(0,5).toLowerCase()!=='lang=';});"
    "document.querySelectorAll('nav .lang a').forEach(function(a){"
    /* lang= first, not last: resolve_language reads only the first 511 bytes
     * of the query, and a long one would push it out of reach. */
    "a.setAttribute('href','?'+['lang='+a.getAttribute('href').slice(-2)]"
    ".concat(lq).join('&')+location.hash);});</script>"
    /* <main> around the page body, closed in PAGE_FOOTER. The nav stays
     * outside it, and no CSS rule targets main, so nothing moves. */
    "<main><h1>%s</h1>";

const char PAGE_FOOTER[] =
    "</main>"
    /* Deliberately no (c): the tree carries third-party parts (see NOTICE),
     * a blanket claim would overreach. Name and source link only. */
    "<div class='foot'><a href='https://codeberg.org/datom/its-g5-receiver-firmware-webinterface'"
    " target='_blank' rel='noopener'>datom &middot; Codeberg</a></div>"
    "<script>document.querySelectorAll('nav a').forEach(function(a){"
    "var h=(a.getAttribute('href')||'').split('?')[0];"
    "if(h&&h===location.pathname)a.className='active';});"
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
    "return fetch('/reboot',{method:'POST'}).then(function(r){"
    "if(!r.ok){alert(denied);return false;}w();return true;})"
    ".catch(function(){w();return true;});};"
    "</script>"
    "</div></body></html>";

/* On every page, not just /status: an unconfirmed update rolls back after 30
 * minutes, and whoever lands elsewhere never sees the warning. */
static void send_pending_verify_banner(httpd_req_t *req)
{
    if (!ota_is_pending_verify())
        return;
    /* The POST has no query string of its own. Without ?lang= here,
     * resolve_language() on that request defaults to German. */
    const char *lc = current_lang == LANG_DE ? "de" : "en";
    static EXT_RAM_BSS_ATTR char banner[1280];
    snprintf(banner, sizeof(banner),
        "<div class='warn'><p>%s</p>"
        /* The banner appears on /settings too, where a reload would drop unsaved
         * edits. The guard also works on pages that define no ITS_UNSAVED_WARN. */
        "<button onclick=\"if(document.body.classList.contains('dirty')&&"
        "typeof ITS_UNSAVED_WARN!=='undefined'&&!confirm(ITS_UNSAVED_WARN))return;"
        "fetch('/confirm?lang=%s',{method:'POST'}).then(function(r){"
        "if(r.status===401){alert('%s');return null;}return r.text();})"
        ".then(function(t){if(t===null)return;alert(t);location.reload();})"
        /* Without the catch a network error left the button looking dead. */
        ".catch(function(){alert('%s');})\">%s</button>"
        "</div>",
        T(ota_rollback_armed() ? S_CONFIRM_NEEDED : S_CONFIRM_NEEDED_NT),
        lc, T(S_CONFIRM_AUTH), T(S_CONFIRM_NOCONN), T(S_CONFIRM_BTN));
    httpd_resp_send_chunk(req, banner, HTTPD_RESP_USE_STRLEN);
}

/* `json_url` enables the pause/resume button + polling loop feeding
 * window.arApply -- no full reload, so CSS animations never restart. */
/* "Fr, 21.08.2026 <sep> 14:02 <sep> " from the device clock, or empty if it was
 * never set. A 1970 date would read as a fault, not as a missing sync. */
void format_clockline(char *out, size_t cap, const char *sep)
{
    out[0] = '\0';
    time_t now = time(NULL);
    struct tm lt;
    /* Same threshold the rest of the tree uses for "the clock is real". */
    if (now < 1600000000 || !localtime_r(&now, &lt)) return;
    /* Weekday short names come from the traffic page's list, so this line
     * needs no vocabulary of its own. */
    char wd[64];
    snprintf(wd, sizeof(wd), "%s", T(S_TRF_WDAYS));
    const char *day = wd;
    for (int i = 0; i < lt.tm_wday && day; i++)
    {
        const char *c = strchr(day, ',');
        day = c ? c + 1 : NULL;
    }
    char dbuf[16] = "";
    if (day)
    {
        size_t n = 0;
        while (day[n] && day[n] != ',' && n + 1 < sizeof(dbuf)) { dbuf[n] = day[n]; n++; }
        dbuf[n] = '\0';
    }
    snprintf(out, cap, "%s%s%02d.%02d.%04d %s %02d:%02d %s ",
             dbuf, dbuf[0] ? ", " : "",
             lt.tm_mday, lt.tm_mon + 1, lt.tm_year + 1900,
             sep, lt.tm_hour, lt.tm_min, sep);
}

void send_page_header_refresh(httpd_req_t *req, const char *heading, const char *json_url)
{
    /* static EXT_RAM_BSS_ATTR, not a stack buffer: the httpd task has only
     * 16384 bytes of stack in total (see webserver_init). */
    static EXT_RAM_BSS_ATTR char refresh_tag[1280];
    /* Static doesn't auto-reset between calls; clear explicitly so a page
     * with json_url==NULL can't inherit a previous request's script. */
    refresh_tag[0] = '\0';
    if (json_url)
    {
        uint32_t ri = 5;
        config_get_u32(CONFIG_INDEX_REFRESH_SEC, &ri);
        if (ri > 0 && ri < 0xFFFFFFFF)
            snprintf(refresh_tag, sizeof(refresh_tag),
                "<script>(function(){var ri=%lu,url='%s',t=null,lt=0;"
                "function tick(){lt=Date.now();fetch(url).then(function(r){return r.json();})"
                ".then(function(d){if(window.arApply)window.arApply(d);}).catch(function(){});}"
                "window.addEventListener('load',function(){"
                "var b=document.createElement('button');"
                "b.style.cssText='position:fixed;bottom:12px;right:12px;z-index:99;opacity:.9;border-radius:4px;box-shadow:0 1px 4px #000';"
                "function u(){b.textContent=(localStorage.getItem('ar')!=='0'?'\\u23f8 ':'\\u25b6 ')+ri+'s';}"
                "b.onclick=function(){var on=localStorage.getItem('ar')==='0';"
                "localStorage.setItem('ar',on?'1':'0');"
                "if(on){tick();t=setInterval(tick,ri*1000);}else{if(t)clearInterval(t);}u();};"
                "u();document.body.appendChild(b);"
                "if(localStorage.getItem('ar')!=='0'){tick();t=setInterval(tick,ri*1000);}"
                /* Mobile browsers freeze setInterval while the screen is off. The
                 * 1 s guard is in wake(), not in tick(), so tick can still run at ri=1. */
                "function wake(){if(document.hidden||Date.now()-lt<1000)return;"
                "if(localStorage.getItem('ar')!=='0')tick();}"
                "document.addEventListener('visibilitychange',wake);"
                /* e.persisted tells a bfcache return from a normal load. A normal
                 * load already gets its tick from the load handler above. */
                "window.addEventListener('pageshow',function(e){if(e.persisted)wake();});"
                "});})();</script>",
                (unsigned long)ri, json_url);
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
    format_clockline(clk, sizeof(clk), "&middot;");
    static EXT_RAM_BSS_ATTR char ctxline[sizeof(nodeid_esc) + 160];
    /* Clock in its own span so a poll can replace just that part. */
    HTML_PRINTF(ctxline, "<div class='ctx'><span id='st-clk'>%s</span>%s</div>",
                clk, nodeid_esc);

    /* With the CSS out of the format string, -Wformat-truncation can no longer
     * bound this call. The assert does it instead (200 bytes for nav + heading). */
    static EXT_RAM_BSS_ATTR char header[4096];
    _Static_assert(sizeof(PAGE_HEADER_FMT) + sizeof(refresh_tag)
                   + 2 * sizeof(page_title) + sizeof(css_ver) + sizeof(ctxline)
                   + 200 <= sizeof(header),
                   "page header worst case no longer fits");
    HTML_PRINTF(header, PAGE_HEADER_FMT,
             lc, page_title, refresh_tag, css_ver, page_title, ctxline,
             lc, T(S_NAV_STATUS),
             lc, T(S_NAV_MESSAGES),
             lc, T(S_NAV_SETTINGS),
             lc, T(S_NAV_UPDATE),
             lc, T(S_NAV_MAP),
             lc, T(S_NAV_SENDERS),
             lc, T(S_NAV_TRANSIT),
#if CONFIG_ENABLE_SD
             lc, T(S_NAV_TRAFFIC),
#endif
             lc, T(S_NAV_SYSTEM),
#if CONFIG_ENABLE_SD
             lc, T(S_NAV_SD),
             lc, T(S_NAV_LOGS),
#endif
             lang_de_active, lang_en_active,
             heading);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send_chunk(req, header, HTTPD_RESP_USE_STRLEN);
    send_pending_verify_banner(req);
}

void send_page_header(httpd_req_t *req, const char *heading)
{
    send_page_header_refresh(req, heading, NULL);
}

/* One sample per completed second; the 60th ring slot is the second still
 * being counted, so only 59 of them can ever be shown. */
#define SPARK_POINTS    (RATE_WINDOW_SECS - 1)
#define SPARK_PEAK_MIN  10  /* msgs/s floor, so a quiet minute stays flat */
#define SPARK_DECAY_SEC 30

/* Fixed y-scale: rescaling to the window maximum flattened nearly every sample
 * and moved the axis between polls. Lockless: only the httpd task renders. */
static uint32_t spark_peak = SPARK_PEAK_MIN;
static uint64_t spark_decay_at;

static uint32_t spark_scale(const uint32_t *counts, size_t n, uint64_t now_sec)
{
    uint32_t wmax = 0;
    for (size_t i = 0; i < n; i++)
        if (counts[i] > wmax) wmax = counts[i];

    if (!spark_decay_at) spark_decay_at = now_sec;
    if (wmax > spark_peak)
    {
        spark_peak = wmax;
        spark_decay_at = now_sec;
    }
    else if (now_sec - spark_decay_at >= SPARK_DECAY_SEC)
    {
        /* Whole steps, capped: a tab left closed for a day must not repeat
         * the decay thousands of times. */
        uint32_t steps = (uint32_t)((now_sec - spark_decay_at) / SPARK_DECAY_SEC);
        if (steps > 64) steps = 64;
        while (steps-- && spark_peak > SPARK_PEAK_MIN)
            spark_peak -= (spark_peak / 4) ? (spark_peak / 4) : 1;
        if (spark_peak < SPARK_PEAK_MIN) spark_peak = SPARK_PEAK_MIN;
        /* Never below what the window holds: a lower peak would clip the top
         * of the line flat and make the label flicker by one. */
        if (spark_peak < wmax) spark_peak = wmax;
        spark_decay_at = now_sec;
    }
    return spark_peak;
}

/* Builds the sparkline as a polyline "points" list; the <svg>/<polyline> shell
 * is emitted once and later polls only setAttribute('points'). */
static void build_spark_points(char *out, size_t out_size, uint32_t *peak_out)
{
    uint64_t now_sec = esp_timer_get_time() / 1000000ull;
    uint32_t counts[SPARK_POINTS];
    if (msg_ring_mutex && xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
    {
        for (size_t i = 0; i < SPARK_POINTS; i++)
        {
            /* Ends at now_sec - 1: the current second is still filling up and
             * as a line endpoint it twitched downwards on every poll. */
            uint64_t sec = now_sec - SPARK_POINTS + i;
            rate_bucket_t *b = &rate_buckets[sec % RATE_WINDOW_SECS];
            counts[i] = (b->sec == sec) ? b->count : 0;
        }
        xSemaphoreGive(msg_ring_mutex);
    }
    else
    {
        memset(counts, 0, sizeof(counts));
    }

    uint32_t peak = spark_scale(counts, SPARK_POINTS, now_sec);
    if (peak_out) *peak_out = peak;

    out[0] = '\0';
    size_t o = 0;
    for (size_t i = 0; i < SPARK_POINTS && o + 12 < out_size; i++)
    {
        /* h stays in 1..36 so the 2 px stroke never clips at the viewBox edge.
         * A silent second drops to the baseline, which is the honest reading. */
        uint32_t h = counts[i] ? 4 + (counts[i] * 32) / peak : 1;
        if (h > 36) h = 36;
        o += (size_t)snprintf(out + o, out_size - o, "%s%u,%u",
                              o ? " " : "", (unsigned)(i * 4), (unsigned)(40 - h));
    }
}

/* What one pass over the minute ring found; peak and band have to come from the
 * same pass as the points, or a label names a scale the line was not drawn to. */
typedef struct {
    uint32_t peak;      /* msgs/min the rate line was scaled against */
    uint32_t nvalid;    /* minutes the ring actually holds */
    uint32_t nrate;     /* of those, minutes with at least one frame */
    int      tlo, thi;  /* whole-degree band the temperature line was scaled to */
    bool     ttemp;     /* any usable temperature sample in the window */
} hist_view_t;

/* Snapshots the minute ring into two polyline point lists. Lock-free by
 * design: taking msg_ring_mutex here could make the sniffer drop a frame. */
static void build_hour_points(char *rout, size_t rsize, char *tout, size_t tsize,
                              hist_view_t *v)
{
    uint32_t n = hist_count;
    uint32_t r[HIST_MINUTES];
    int16_t  t[HIST_MINUTES];
    bool     ok[HIST_MINUTES];
    int lo = 0, hi = 0;

    memset(v, 0, sizeof(*v));
    v->peak = HIST_RATE_MIN;

    for (uint32_t k = 0; k < HIST_MINUTES; k++)
    {
        ok[k] = false;
        /* k = 59 is the newest minute. k = 0 is also the slot the writer takes
         * next, which is why the stamp is read again below the values. */
        if (n + k < HIST_MINUTES)
            continue;
        uint32_t m = n + k - (HIST_MINUTES - 1);
        hist_slot_t *s = &hist_ring[(m - 1) % HIST_MINUTES];
        uint32_t st = s->stamp;
        if (st != m)
            continue;
        HIST_BARRIER();
        uint32_t rv = s->rate;
        int16_t  tv = s->temp_dc;
        HIST_BARRIER();
        /* The stamp is read again after the values: a reader preempted here
         * comes back to a slot that already holds a minute from an hour later. */
        if (s->stamp != st)
            continue;
        r[k] = rv;
        t[k] = tv;
        ok[k] = true;
        v->nvalid++;
        if (rv)
        {
            v->nrate++;
            if (rv > v->peak) v->peak = rv;
        }
        if (tv != HIST_TEMP_NONE)
        {
            if (!v->ttemp) { lo = hi = tv; v->ttemp = true; }
            else { if (tv < lo) lo = tv; if (tv > hi) hi = tv; }
        }
    }

    /* Whole degrees outwards, then widened to HIST_TEMP_SPAN: a fixed 0..100
     * scale would be a straight line, an exact one would magnify sensor noise. */
    if (v->ttemp)
    {
        v->tlo = (lo >= 0 ? lo : lo - 9) / 10;
        v->thi = (hi >= 0 ? hi + 9 : hi) / 10;
        if (v->thi - v->tlo < HIST_TEMP_SPAN)
        {
            int mid = (v->tlo + v->thi) / 2;
            v->tlo = mid - HIST_TEMP_SPAN / 2;
            v->thi = v->tlo + HIST_TEMP_SPAN;
        }
    }

    rout[0] = tout[0] = '\0';
    size_t ro = 0, to = 0;
    unsigned rn = 0, tn = 0, ry = 0, ty = 0, tk = 0;
    int span_dc = (v->thi - v->tlo) * 10;
    for (uint32_t k = 0; k < HIST_MINUTES; k++)
    {
        if (!ok[k])
            continue;   /* only ever at the left, while the first hour fills */
        /* h stays in 1..36 like the minute line, so the 2 px stroke never
         * clips at the viewBox edge and a silent minute sits on the floor. */
        uint32_t h = r[k] ? 4 + (r[k] * 32) / v->peak : 1;
        if (h > 36) h = 36;
        ry = (unsigned)(40 - h);
        if (ro + 12 < rsize)
        {
            ro += (size_t)snprintf(rout + ro, rsize - ro, "%s%u,%u",
                                   ro ? " " : "", (unsigned)(k * 4), ry);
            rn++;
        }
        if (t[k] == HIST_TEMP_NONE || span_dc <= 0)
            continue;
        int th = 4 + ((t[k] - v->tlo * 10) * 32) / span_dc;
        if (th < 1) th = 1;
        if (th > 36) th = 36;
        ty = (unsigned)(40 - th);
        tk = k;
        if (to + 12 < tsize)
        {
            to += (size_t)snprintf(tout + to, tsize - to, "%s%u,%u",
                                   to ? " " : "", (unsigned)(k * 4), ty);
            tn++;
        }
    }
    /* A polyline with one point draws nothing, so the first minute after a
     * boot would show an empty box -- repeat it as a short dash instead. */
    if (rn == 1) snprintf(rout, rsize, "232,%u 236,%u", ry, ry);
    /* At the sample's own x, not at the right edge: a lone temperature reading
     * can sit anywhere in the hour, and a dash on the right claims "now". */
    if (tn == 1)
    {
        unsigned x = tk * 4;
        snprintf(tout, tsize, "%u,%u %u,%u", x >= 4 ? x - 4 : 0, ty, x, ty);
    }
}

/* One place decides which of the three states the hour label reports, so the
 * page and /status.json can never disagree about it. */
static void hist_scale_text(const hist_view_t *v, char *out, size_t size)
{
    if (!v->nvalid)     snprintf(out, size, "%s", T(S_HIST_WAIT));
    /* Not S_ACTIVITY_NONE: that one says "none since boot" and would contradict
     * the message counter right above it. Goes to textContent, so no entities. */
    else if (!v->nrate) snprintf(out, size, "%s", T(S_HIST_IDLE));
    else snprintf(out, size, "%s %lu/min", T(S_ACTIVITY_SCALE),
                  (unsigned long)v->peak);
}

#ifdef CONFIG_ENABLE_TEMPERATURE
/* The dash and the degree sign come from the caller: the page needs HTML
 * entities, /status.json the literal UTF-8 that arApply writes as text. */
static void hist_band_text(const hist_view_t *v, char *out, size_t size,
                           const char *dash, const char *deg)
{
    if (v->ttemp)       snprintf(out, size, "%d%s%d%s", v->tlo, dash, v->thi, deg);
    else if (v->nvalid) snprintf(out, size, "%s", dash);
    else                snprintf(out, size, "%s", T(S_HIST_WAIT));
}
#endif

/* Builds the per-type count breakdown text, e.g. "CAM 812 &middot; RSU
 * SPATEM 449" (empty if nothing received yet -- caller substitutes the
 * "no activity" string). Shared between the page and /status.json. */
static void build_typeline_html(char *out, size_t out_size)
{
    static msg_type_stat_t type_snapshot[MSG_TYPE_STATS_SLOTS];
    if (msg_ring_mutex && xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
    {
        memcpy(type_snapshot, msg_type_stats, sizeof(type_snapshot));
        xSemaphoreGive(msg_ring_mutex);
    }
    else
    {
        memset(type_snapshot, 0, sizeof(type_snapshot));
    }

    out[0] = '\0';
    size_t tl = 0;
    for (size_t i = 0; i < MSG_TYPE_STATS_SLOTS; i++)
    {
        if (type_snapshot[i].label[0] == '\0')
            continue;
        char typeesc[WEB_MSG_TYPE_LEN * 6];
        html_escape(type_snapshot[i].label, typeesc, sizeof(typeesc));
        int n = snprintf(out + tl, out_size - tl, "%s%s %lu",
            tl ? " &middot; " : "", typeesc, (unsigned long)type_snapshot[i].count);
        if (n > 0 && (size_t)n < out_size - tl)
            tl += (size_t)n;
    }
}

/* The status page's "Activity" sparklines and message-type breakdown, from
 * the counters webserver_handle_packet already fills in. */
/* The hour line arrives finished: its caller draws the temperature line from
 * the SAME snapshot, and a second pass here could disagree with it. */
static void render_activity_stats(httpd_req_t *req, const char *hourpts,
                                  const char *hourscale)
{
    /* Sent as separate chunks: the point list is built before the label,
     * because the label has to name the scale it was drawn against. */
    uint32_t peak = 0;
    static EXT_RAM_BSS_ATTR char spark[512];
    build_spark_points(spark, sizeof(spark), &peak);

    /* The two halves below cover DIFFERENT periods, so each names its own.
     * Under a single heading the type totals read as a 60 s snapshot. */
    char scaletxt[48];
    snprintf(scaletxt, sizeof(scaletxt), "%s %lu/s", T(S_ACTIVITY_SCALE),
             (unsigned long)peak);
    /* Opens the section. The matching </div> is appended to hintblock at the
     * end of this function, so everything in between belongs to the group. */
    char sparklbl[320];
    HTML_PRINTF(sparklbl,
        "<div class='grp' id='sec-act'><h2>%s</h2>"
        "<div class='lbl'>%s &middot; <span id='st-sparkmax'>%s</span></div>",
        T(S_ACTIVITY_TITLE), T(S_ACTIVITY_SPARK), scaletxt);
    httpd_resp_send_chunk(req, sparklbl, HTTPD_RESP_USE_STRLEN);

    /* id='st-spark' kept though unused: an older tab still polling would throw
     * on a null element. vector-effect: else the stroke stretches with x. */
    char svgopen[320];
    HTML_PRINTF(svgopen,
        "<div class='spark'>"
        "<svg id='st-spark' viewBox='0 0 %d 40' width='100%%' height='40' preserveAspectRatio='none'>"
        "<polyline id='st-sparkl' fill='none' stroke='#f2b134' stroke-width='2'"
        " vector-effect='non-scaling-stroke' points='",
        (SPARK_POINTS - 1) * 4);
    httpd_resp_send_chunk(req, svgopen, HTTPD_RESP_USE_STRLEN);
    /* Same guard as the hour list below: today this one always fills, but an
     * empty string here would silently truncate the page. */
    if (spark[0])
        httpd_resp_send_chunk(req, spark, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "'/></svg></div>", HTTPD_RESP_USE_STRLEN);

    /* Same quantity one window up: the minute line answers "is it receiving
     * now", the hour line "has it been receiving all along". */
    char hourlbl[512];
    HTML_PRINTF(hourlbl,
        "<div class='lbl sp'>%s &middot; <span id='st-hourmax'>%s</span></div>"
        "<div class='spark sm'>"
        "<svg viewBox='0 0 %d 40' width='100%%' height='40' preserveAspectRatio='none'>"
        "<polyline id='st-hourl' fill='none' stroke='#f2b134' stroke-width='2'"
        " vector-effect='non-scaling-stroke' points='",
        T(S_HIST_HOUR), hourscale, (HIST_MINUTES - 1) * 4);
    httpd_resp_send_chunk(req, hourlbl, HTTPD_RESP_USE_STRLEN);
    /* Never send this one blind: a zero-length chunk ENDS the response, and the
     * list is empty for the first minute after a boot, before any sample. */
    if (hourpts[0])
        httpd_resp_send_chunk(req, hourpts, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "'/></svg></div>", HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR char typeline[1024];
    build_typeline_html(typeline, sizeof(typeline));
    char typeblock[1408];
    snprintf(typeblock, sizeof(typeblock),
        "<div class='lbl sp'>%s</div><div class='types' id='st-type'>%s</div>",
        T(S_ACTIVITY_TYPES), typeline[0] ? typeline : T(S_ACTIVITY_NONE));
    httpd_resp_send_chunk(req, typeblock, HTTPD_RESP_USE_STRLEN);

    char hintblock[768];
    snprintf(hintblock, sizeof(hintblock), "<p class='note'>%s</p></div>", T(S_TYPE_HINT));
    httpd_resp_send_chunk(req, hintblock, HTTPD_RESP_USE_STRLEN);
}

/* ================================================================== */
/*  GET /  -- status dashboard                                        */
/* ================================================================== */

static esp_err_t status_page_handler(httpd_req_t *req)
{
    resolve_language(req);

    char nodeid[CONFIG_NODEID_BUFFER_SIZE] = {0};
    size_t nodeid_size = sizeof(nodeid);
    config_get_str(CONFIG_INDEX_NODEID, nodeid, &nodeid_size);
    char nodeid_esc[CONFIG_NODEID_BUFFER_SIZE * 6];
    html_escape(nodeid, nodeid_esc, sizeof(nodeid_esc));

    uint8_t mac[6];
    ethernet_get_mac(mac);

    const esp_app_desc_t *app_desc = esp_app_get_description();
    uint64_t uptime_s = esp_timer_get_time() / 1000000ull;
    char uptime_str[48];
    format_uptime(uptime_s, uptime_str, sizeof(uptime_str));

    uint32_t channel = sniffer_get_channel();
    bool running = sniffer_is_running();
    uint32_t rate = rate_packets_last_minute();
    /* Memory details are on /system, which is their single source of truth.
     * This page shows operational state only. */

    const char *chan_name;
    switch (channel)
    {
    case 5900: chan_name = "G5CC";  break;
    case 5890: chan_name = "G5SC2"; break;
    case 5880: chan_name = "G5SC1"; break;
    case 5870: chan_name = "G5SC3"; break;
    case 5860: chan_name = "G5SC4"; break;
    default:   chan_name = NULL;    break;
    }
    char chan_str[32];
    if (channel && chan_name)
        snprintf(chan_str, sizeof(chan_str), "%s (%lu MHz)", chan_name, (unsigned long)channel);
    else
        snprintf(chan_str, sizeof(chan_str), "-");

    send_page_header_refresh(req, T(S_TITLE_STATUS),
                             current_lang == LANG_EN ? "/status.json?lang=en"
                                                     : "/status.json?lang=de");

    {
        /* Two charts stand between the top of the page and the device group,
         * so the figures most often looked up sit below a screenful. */
        char peers_probe[CONFIG_PEERS_BUFFER_SIZE] = "";
        size_t pp = sizeof(peers_probe);
        config_get_str(CONFIG_INDEX_PEERS, peers_probe, &pp);
        char stjump[320];
        HTML_PRINTF(stjump,
            "<p class='jump'>%s: <a href='#sec-act'>%s</a> &middot; "
            "<a href='#sec-dev'>%s</a>%s%s%s</p>",
            T(S_TRF_JUMP), T(S_ACTIVITY_TITLE), T(S_SYS_GRP_DEVICE),
            /* The peer group is only emitted with peers configured; without
             * them the third link would point at nothing. */
            peers_probe[0] ? " &middot; <a href='#sec-peer'>" : "",
            peers_probe[0] ? T(S_PEER_TITLE) : "",
            peers_probe[0] ? "</a>" : "");
        httpd_resp_send_chunk(req, stjump, HTTPD_RESP_USE_STRLEN);
    }

    /* SD usage answers "is the card filling up" at a glance. */
    /* Text and class kept apart: T(S_SD_USED_OF) is itself the format
     * string, so the wrapping span cannot be appended to it. */
    /* The share is the cell's value, the byte text its detail line. */
    char sdval[48] = "&ndash;";
    /* Empty, not a dash: the detail line then renders blank instead of putting
     * a second dash under the one in the value. */
    char sdtxt[128] = "";
    const char *sdcls = "";
#if CONFIG_ENABLE_SD
    {
        uint64_t sd_total = 0, sd_free = 0;
        sd_state_t sdst = sd_state(&sd_total, &sd_free);
        if (sdst == SDST_OK)
        {
            char u[24], t[24], f[24];
            unsigned pct = (unsigned)(((sd_total - sd_free) * 100ull) / sd_total);
            format_bytes64(sd_total - sd_free, u, sizeof(u));
            format_bytes64(sd_total, t, sizeof(t));
            format_bytes64(sd_free, f, sizeof(f));
            snprintf(sdtxt, sizeof(sdtxt), T(S_SD_USED_OF), u, t, f);
            /* %% is a literal percent sign in the value, not a conversion. */
            snprintf(sdval, sizeof(sdval), "%u<span class='e'>%%</span>", pct);
            sdcls = lvl_class(pct, 80, 92);
        }
        else
        {
            /* A mounted card whose size query failed is not a missing one. */
            snprintf(sdtxt, sizeof(sdtxt), "%s",
                     sdst == SDST_NO_USAGE     ? T(S_SD_ERR_USAGE)
                     : sdst == SDST_WRITE_FAILED ? T(S_SD_TAKEN_OUT)
                                               : T(S_SD_NOT_MOUNTED));
            /* Grey, not red: running without a card is a valid setup, not a fault. */
            sdcls = "v-off";
        }
    }
#endif
    /* Threshold colour and its tooltip go on the label, which is where the
     * state dot is. */
    const char *sdtitle = strcmp(sdcls, "v-bad") == 0    ? T(S_TH_ALARM)
                          : strcmp(sdcls, "v-warn") == 0 ? T(S_TH_WARN) : "";

#ifdef CONFIG_ENABLE_TEMPERATURE
    /* Read once: the class and the number must not come from two samples,
     * and a failed read prints "nan" unless it is caught here. */
    float tc = temperature_get();
    char tstr[64];
    /* Range check, not just NaN: a wild reading would push the closing tag out
     * of the buffer, and a cut </span> swallows the rest of the page. */
    if (tc == tc && tc > -100.0f && tc < 200.0f)
        snprintf(tstr, sizeof(tstr), "%.1f<span class='e'>&deg;C</span>", (double)tc);
    else
        snprintf(tstr, sizeof(tstr), "&ndash;");
#endif

    /* id='st-*' on every cell that /status.json can update -- see arApply
     * below. Node ID/MAC/firmware never change without a reboot
     * (a full page load already happens then), so those stay static. */
    /* One buffer for both halves: the second snprintf only runs once the first
     * chunk is out, and the httpd task's stack is 16 KB in total. */
    char body[3584];
    /* No heading on the top row -- position says it. Channel and sniffer state
     * ride in the detail line of the value they belong to, label included. */
    snprintf(body, sizeof(body),
        "<div class='grid'>"
        "<div class='cell'><div class='l'>%s</div>"
        "<div class='v' id='st-msgs'>%lu</div><div class='d'>%s</div></div>"
        "<div class='cell'><div class='l'>%s</div>"
        "<div class='v' id='st-rate'>%lu</div>"
        "<div class='d'>%s <span id='st-chan'>%s</span></div></div>"
        "<div class='cell'><div class='l %s' id='st-upl'>%s</div>"
        "<div class='v' id='st-uptime'>%s</div>"
        "<div class='d'>%s <span class='%s' id='st-sniff'>%s</span></div></div>"
        "</div>",
        T(S_MSGS_RECEIVED), (unsigned long)msg_total_count, T(S_SINCE_BOOT),
        T(S_RATE), (unsigned long)rate,
        T(S_CHANNEL), chan_str,
        running ? "v-ok" : "v-off", T(S_UPTIME), uptime_str,
        T(S_SNIFFER), running ? "ok" : "bad",
        running ? T(S_RUNNING) : T(S_STOPPED));
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);

    /* ONE snapshot for both hour charts: the rate line below and the
     * temperature line further down have to describe the same minute. */
    /* Only the httpd task ever runs this handler (no defer_to_worker), so
     * static is safe here and keeps 1 KB off its 16 KB stack. */
    static EXT_RAM_BSS_ATTR char hourr[512], hourt[512];
    hist_view_t hv;
    build_hour_points(hourr, sizeof(hourr), hourt, sizeof(hourt), &hv);
    char hscale[64];
    hist_scale_text(&hv, hscale, sizeof(hscale));
#ifdef CONFIG_ENABLE_TEMPERATURE
    char hband[48];
    hist_band_text(&hv, hband, sizeof(hband), "&ndash;", "&nbsp;&deg;C");
#endif

    render_activity_stats(req, hourr, hscale);

    /* The SD value gets no state class: arApply never rewrites this cell (the
     * sd field in /status.json is for monitors), so a colour would freeze. */
    snprintf(body, sizeof(body),
        "<div class='grp' id='sec-dev'><h2>%s</h2><div class='grid'>"
        "<div class='cell'><div class='l %s' id='st-sdl' title='%s'>%s</div>"
        "<div class='v'>%s</div><div class='d'>%s</div></div>"
#ifdef CONFIG_ENABLE_TEMPERATURE
        "<div class='cell'><div class='l %s' id='st-templ'>%s</div>"
        "<div class='v %s' id='st-temp'>%s</div></div>"
#endif
        "<div class='cell'><div class='l %s' id='st-mqttl'>%s</div>"
        "<div class='v' id='st-mqtt'>%s</div></div>"
        "<div class='cell'><div class='l'>%s</div><div class='v'>%s</div>"
        "<div class='d'>%s %02x:%02x:%02x:%02x:%02x:%02x</div></div>"
        "<div class='cell'><div class='l'>%s</div><div class='v'>%s</div></div>"
        /* Closes .grid only. The group stays open past this chunk so the
         * temperature strip below can still land inside it. */
        "</div>",
        T(S_SYS_GRP_DEVICE),
        sdcls, sdtitle, T(S_SD_CARD), sdval, sdtxt,
#ifdef CONFIG_ENABLE_TEMPERATURE
        temp_class(tc), T(S_TEMPERATURE), temp_class(tc), tstr,
#endif
        mqtt_connected_state ? "v-ok" : "v-bad", T(S_MQTT),
        mqtt_connected_state ? T(S_CONNECTED) : T(S_DISCONNECTED),
        /* An empty nodeid would leave a bare 36px gap under its label. */
        T(S_NODEID), nodeid_esc[0] ? nodeid_esc : "&ndash;",
        T(S_MAC), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        T(S_FW_VERSION), app_desc->version);
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);

#ifdef CONFIG_ENABLE_TEMPERATURE
    /* Own chunk, and only when there is something to draw: a sensor that never
     * answers would leave a labelled 56px box with nothing in it. */
    if (hv.ttemp || !hv.nvalid)
    {
        /* Reuses body: it went out as a chunk a few lines up, and a second
         * kilobyte on the httpd stack would buy nothing. */
        HTML_PRINTF(body,
            "<div class='lbl sp'>%s &middot; <span id='st-tempband'>%s</span></div>"
            "<div class='spark sm'>"
            "<svg viewBox='0 0 %d 40' width='100%%' height='40' preserveAspectRatio='none'>"
            /* Link blue, not --warn: a permanently orange curve reads as a
             * standing warning about the temperature. */
            "<polyline id='st-temphl' fill='none' stroke='#4fb8e0' stroke-width='2'"
            " vector-effect='non-scaling-stroke' points='%s'/></svg></div>",
            T(S_HIST_TEMP), hband, (HIST_MINUTES - 1) * 4, hourt);
        httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);
    }
#endif
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);

    /* No reload on click -- fetch the toggle, then let window.stSetSniff
     * (defined in applyscript below) update the button + status span from
     * the action just taken, same as a poll would. */
    /* 1152: the German worst case is 1009 bytes, and a truncated onclick would
     * silently produce a dead button rather than an error. */
    char buttons[1152];
    snprintf(buttons, sizeof(buttons),
        /* .btnrow keeps these buttons quiet without touching the global amber
         * button, which /settings' own savebar still relies on. */
        "<p class='btnrow'>"
        "<button id='st-sniffbtn' data-action='%s' onclick=\"var a=this.getAttribute('data-action');"
        /* r.ok, not "it returned": /sniffer is password-gated, and a rejected
         * request must not flip the label. The status poll re-asserts the truth. */
        "fetch('/sniffer?action='+a,{method:'POST'}).then(function(r){if(r.ok&&window.stSetSniff)window.stSetSniff(a==='start');})\">%s</button> "
        "<button class='pwr' onclick=\"itsReboot('%s','%s','%s','%s')\">%s</button>"
#if CONFIG_ENABLE_SD
        /* Result goes into its own span rather than replacing the page: if the
         * unmount fails the operator has to stay on the page and see why. */
        " <button class='pwr' onclick=\"if(!confirm('%s'))return;"
        "var s=document.getElementById('po-res');s.innerText='%s';"
        "fetch('/poweroff',{method:'POST'}).then(function(r){return r.text();})"
        ".then(function(t){s.innerText=t;}).catch(function(){s.innerText='%s';})\">%s</button>"
        " <span id='po-res'></span>"
#endif
        "</p>",
        running ? "stop" : "start",
        running ? T(S_SNIFF_STOP) : T(S_SNIFF_START),
        T(S_REBOOT_CONFIRM), T(S_REBOOTING), T(S_REBOOT_SLOW), T(S_REBOOT_DENIED), T(S_REBOOT)
#if CONFIG_ENABLE_SD
        , T(S_POWEROFF_CONFIRM), T(S_POWEROFF_BUSY), T(S_POWEROFF_FAIL), T(S_POWEROFF)
#endif
        );
    httpd_resp_send_chunk(req, buttons, HTTPD_RESP_USE_STRLEN);

    /* Applies /status.json to the cells; innerHTML because labels can carry
     * entities, and the Start/Stop button swaps label+action in the same pass. */
    /* className REPLACES the class list, so every id that also carries a layout
     * class ('v', 'l') has to get that class written back with it. */
    /* Off the stack and grown: the two hour charts add ~380 bytes of JS, and a
     * truncated script would take the whole poll down, not just one cell. */
    static EXT_RAM_BSS_ATTR char applyscript[2560];
    HTML_PRINTF(applyscript,
        "<script>(function(){"
        "var RUN='%s',STOP='%s',CONN='%s',DISC='%s',BSTART='%s',BSTOP='%s',SCL='%s';"
        "function cls(i,c){var e=document.getElementById(i);if(e)e.className=c;}"
        "window.stSetSniff=function(r){"
        "var sn=document.getElementById('st-sniff');sn.className=r?'ok':'bad';sn.innerHTML=r?RUN:STOP;"
        "cls('st-upl','l '+(r?'v-ok':'v-off'));"
        "var sb=document.getElementById('st-sniffbtn');"
        "if(sb){sb.textContent=r?BSTOP:BSTART;sb.setAttribute('data-action',r?'stop':'start');}"
        "};"
        "window.arApply=function(d){"
        /* Otherwise the clock freezes on the minute the page was loaded. */
        "var ck=document.getElementById('st-clk');"
        "if(ck&&d.clk!==undefined)ck.textContent=d.clk;"
        "document.getElementById('st-msgs').textContent=d.msgs;"
        "document.getElementById('st-rate').textContent=d.rate;"
        "document.getElementById('st-uptime').textContent=d.uptime;"
        "document.getElementById('st-chan').textContent=d.chan;"
        /* setAttribute, not innerHTML: the polyline is one SVG element. */
        "var sl=document.getElementById('st-sparkl');"
        "if(sl&&d.sparkp!==undefined)sl.setAttribute('points',d.sparkp);"
        "var sm=document.getElementById('st-sparkmax');"
        "if(sm&&d.smax!==undefined)sm.textContent=SCL+' '+d.smax+'/s';"
        /* The hour label arrives finished -- it has three forms, and picking
         * between them in JS would need the texts a second time. */
        "var hl=document.getElementById('st-hourl');"
        "if(hl&&d.hrp!==undefined)hl.setAttribute('points',d.hrp);"
        "var hm=document.getElementById('st-hourmax');"
        "if(hm&&d.hrs!==undefined)hm.textContent=d.hrs;"
        "var tl=document.getElementById('st-temphl');"
        "if(tl&&d.htp!==undefined)tl.setAttribute('points',d.htp);"
        "var tb=document.getElementById('st-tempband');"
        "if(tb&&d.htb!==undefined)tb.textContent=d.htb;"
        "document.getElementById('st-type').innerHTML=d.types;"
        "window.stSetSniff(d.sniff);"
        "document.getElementById('st-mqtt').innerHTML=d.mqtt?CONN:DISC;"
        "cls('st-mqttl','l '+(d.mqtt?'v-ok':'v-bad'));"
        /* null = sensor not answering; the class has to follow the value,
         * or the colour freezes on whatever the page was loaded with. */
        "var te=document.getElementById('st-temp');"
        "if(te&&d.temp!==undefined&&d.temp!==null){"
        "te.innerHTML=d.temp.toFixed(1)+'<span class=e>\\u00b0C</span>';"
        "te.className='v '+(d.tcl||'');cls('st-templ','l '+(d.tcl||''));}"
        /* Defined by the peer block below, which is skipped without peers. */
        "if(window.peerPoll)window.peerPoll();"
        "};})();</script>",
        T(S_RUNNING), T(S_STOPPED), T(S_CONNECTED), T(S_DISCONNECTED),
        T(S_SNIFF_START), T(S_SNIFF_STOP), T(S_ACTIVITY_SCALE));
    httpd_resp_send_chunk(req, applyscript, HTTPD_RESP_USE_STRLEN);

    /* Neighbours at a glance: without this table every receiver needs its own
     * browser tab, and the comparison between them is the actual information. */
    {
        char peers_cfg[CONFIG_PEERS_BUFFER_SIZE] = "";
        size_t psz = sizeof(peers_cfg);
        config_get_str(CONFIG_INDEX_PEERS, peers_cfg, &psz);
        if (peers_cfg[0])
        {
            char plist[CONFIG_PEERS_BUFFER_SIZE * 2] = {0};
            size_t o = 0;
            bool first = true, open_q = false;
            for (const char *p = peers_cfg; *p && o + 4 < sizeof(plist); p++)
            {
                bool ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                          (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == ':';
                if (ok)
                {
                    if (!open_q)
                    {
                        if (!first) plist[o++] = ',';
                        plist[o++] = '"';
                        open_q = true; first = false;
                    }
                    plist[o++] = *p;
                }
                else if (open_q) { plist[o++] = '"'; open_q = false; }
            }
            if (open_q && o + 1 < sizeof(plist)) plist[o++] = '"';
            plist[o] = '\0';

            static EXT_RAM_BSS_ATTR char peerblk[3072];
            /* Every literal %% below is JavaScript modulo, not a conversion. */
            HTML_PRINTF(peerblk,
                /* Stays a table: its four column heads are firmware texts and
                 * rows compare across peers better than tiles would. */
                "<div class='grp' id='sec-peer'><h2>%s</h2>"
                "<div class='scroll'><table id='peertbl'><thead><tr>"
                "<th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead>"
                "<tbody id='peerbody'></tbody></table></div>"
                "<script>(function(){var P=[%s];var B=document.getElementById('peerbody');"
                "if(!P.length){return;}"
                "var ND='%s',IDLE=120,R={},busy=false;"
                /* Same d/h/m/s spelling as format_uptime, so language-neutral. */
                "function dur(s){var d=Math.floor(s/86400),h=Math.floor(s%%86400/3600),"
                "m=Math.floor(s%%3600/60),x=s%%60;"
                "return (d?d+'d ':'')+(d||h?h+'h ':'')+(d||h||m?m+'m ':'')+x+'s';}"
                "function lnk(h){return \"<td><a href='http://\"+h+\"/'>\"+h+\"</a></td>\";}"
                /* d.msgs===0 also catches peers still on firmware without idle,
                 * which is exactly the deaf-since-boot case. */
                "function rt(d){var q=(d.idle!==undefined)?(d.idle<0||d.idle>=IDLE):(d.msgs===0);"
                "if(!q)return \"<td>\"+d.rate+\"</td>\";"
                "return \"<td><span class='bad'>\"+ND+' '+(d.idle>0?dur(d.idle):d.uptime)+\"</span></td>\";}"
                "function one(h){var tr=R[h];"
                "return fetch('http://'+h+'/status.json',{cache:'no-store'})"
                ".then(function(r){return r.json();}).then(function(d){"
                "tr.innerHTML=lnk(h)+rt(d)+\"<td>\"+d.uptime+\"</td><td>\""
                "+(d.mqtt?'&#10003;':'&#10007;')+\"</td>\";})"
                /* A blocked cross-origin read and a dead host both land in
                 * catch(). A no-cors probe tells them apart, so an older peer
                 * is not reported as offline. */
                ".catch(function(){"
                "return fetch('http://'+h+'/status.json',{mode:'no-cors',cache:'no-store'})"
                ".then(function(){tr.innerHTML=lnk(h)+\"<td colspan=3><small class='v-warn'>%s</small></td>\";})"
                ".catch(function(){tr.innerHTML=\"<td>\"+h"
                "+\"</td><td colspan=3><span class='bad'>%s</span></td>\";});"
                "});}"
                /* Re-polled from arApply: the idle time is a DURATION, and a
                 * frozen one still claims 12s of silence hours later. */
                "window.peerPoll=function(){if(busy)return;busy=true;"
                "Promise.all(P.map(function(h){return one(h);})).then(function(){busy=false;},"
                "function(){busy=false;});};"
                "P.forEach(function(h){var tr=document.createElement('tr');"
                "tr.innerHTML=lnk(h)+'<td colspan=3>&hellip;</td>';B.appendChild(tr);R[h]=tr;});"
                "window.peerPoll();})();</script></div>",
                T(S_PEER_TITLE), T(S_PEER_NODE), T(S_PEER_RATE), T(S_PEER_UPTIME),
                T(S_PEER_MQTT), plist, T(S_PEER_NODATA), T(S_PEER_OLDFW),
                T(S_PEER_OFFLINE));
            httpd_resp_send_chunk(req, peerblk, HTTPD_RESP_USE_STRLEN);
        }
    }

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* GET /status.json -- the dynamic subset of the status page, polled by the
 * script send_page_header_refresh() injects. Keeps the same field set the
 * page itself computes, just as compact JSON instead of HTML. */
static esp_err_t status_json_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    bool running = sniffer_is_running();
    uint32_t rate = rate_packets_last_minute();
    uint64_t uptime_s = esp_timer_get_time() / 1000000ull;
    char uptime_str[48];
    format_uptime(uptime_s, uptime_str, sizeof(uptime_str));

    uint32_t channel = sniffer_get_channel();
    const char *chan_name;
    switch (channel)
    {
    case 5900: chan_name = "G5CC";  break;
    case 5890: chan_name = "G5SC2"; break;
    case 5880: chan_name = "G5SC1"; break;
    case 5870: chan_name = "G5SC3"; break;
    case 5860: chan_name = "G5SC4"; break;
    default:   chan_name = NULL;    break;
    }
    char chan_str[32];
    if (channel && chan_name)
        snprintf(chan_str, sizeof(chan_str), "%s (%lu MHz)", chan_name, (unsigned long)channel);
    else
        snprintf(chan_str, sizeof(chan_str), "-");

    /* Middle dot as raw UTF-8: this one goes through textContent, not markup. */
    char clkj[80];
    format_clockline(clkj, sizeof(clkj), "\u00b7");

#ifdef CONFIG_ENABLE_TEMPERATURE
    /* "nan" is not valid JSON and would kill the whole poll, not just this
     * one field, so a failed read goes out as null. */
    float tc = temperature_get();
    char tval[24];
    if (tc == tc) snprintf(tval, sizeof(tval), "%.1f", (double)tc);
    else          snprintf(tval, sizeof(tval), "null");
#endif

    uint32_t peak = 0;
    static EXT_RAM_BSS_ATTR char spark[512];
    build_spark_points(spark, sizeof(spark), &peak);
    static EXT_RAM_BSS_ATTR char typeline[1024];
    build_typeline_html(typeline, sizeof(typeline));

    /* Only the httpd task answers this route, so static is safe here too. */
    static EXT_RAM_BSS_ATTR char hourr[512], hourt[512];
    hist_view_t hv;
    build_hour_points(hourr, sizeof(hourr), hourt, sizeof(hourt), &hv);
    char hscale[64];
    hist_scale_text(&hv, hscale, sizeof(hscale));
#ifdef CONFIG_ENABLE_TEMPERATURE
    /* Literal UTF-8, not entities: arApply writes this one with textContent. */
    char hband[48];
    hist_band_text(&hv, hband, sizeof(hband), "\u2013", " \u00b0C");
#endif

    /* -1 = nothing ever received (0 would read as "just now"); clamped at 0
     * because a frame arriving between the two reads would underflow. */
    uint32_t last1 = msg_last_sec1, now32 = (uint32_t)uptime_s;
    long idle = last1 ? (long)(now32 > last1 - 1 ? now32 - (last1 - 1) : 0) : -1;

    /* Machine-readable SD state, same states the file page names. 176 carries
     * the worst case GCC assumes: 61 literal + 10 + 20 + 20 + 10 + 10 + NUL. */
    char sdj[176] = ",\"sd\":{\"ok\":false,\"reason\":\"no_sd_build\"}";
#if CONFIG_ENABLE_SD
    {
        uint64_t sdt = 0, sdf = 0;
        sd_state_t sdst = sd_state(&sdt, &sdf);
        if (sdst == SDST_OK)
            snprintf(sdj, sizeof(sdj),
                ",\"sd\":{\"ok\":true,\"pct\":%u,\"used\":%llu,\"total\":%llu,"
                "\"fails\":%lu,\"held_ms\":%lu}",
                (unsigned)(((sdt - sdf) * 100ull) / sdt),
                (unsigned long long)(sdt - sdf), (unsigned long long)sdt,
                /* Both peaks since boot, like the loss table: the live streak
                 * reads 0 during long ops, so a poll would never see it. */
                (unsigned long)sdcard_io_fail_max(),
                (unsigned long)sdcard_io_held_max_ms());
        else
            /* usage_error = mounted but unreadable size, no_fs = no FAT,
             * not_mounted = never answered, unmounted = on purpose,
             * write_failed = taken out after failed writes. retry = sysmon
             * keeps trying to mount it. */
            snprintf(sdj, sizeof(sdj), ",\"sd\":{\"ok\":false,\"reason\":\"%s\"%s}",
                     sd_state_reason(sdst),
                     sdst == SDST_NO_USAGE ? ""   /* mounted: nothing to retry */
                     : sdcard_auto_remount_inhibited() ? ",\"retry\":false" : ",\"retry\":true");
    }
#endif

    /* Losses that outlive a reboot, next to the per-boot values: the lifetime
     * figure says "this card is tired", the jump inside one boot is the alarm.
     * 192 carries the worst case: 90 literal + six 10-digit values + NUL. */
    char lossj[192] = "";
#if CONFIG_ENABLE_SD
    {
        uint32_t lst = 0, flf = 0, unm = 0;
        sysstat_sd_get(&lst, &flf, &unm);
        snprintf(lossj, sizeof(lossj),
            ",\"loss\":{\"lost\":%lu,\"flushfail\":%lu,\"unmounts\":%lu,"
            "\"lost_boot\":%lu,\"flushfail_boot\":%lu,\"unmounts_boot\":%lu}",
            (unsigned long)lst, (unsigned long)flf, (unsigned long)unm,
            (unsigned long)sdpcap_dropped(), (unsigned long)sdpcap_flush_fails(),
            (unsigned long)sdcard_takeouts());
    }
#endif

    static EXT_RAM_BSS_ATTR char json[8192];
    snprintf(json, sizeof(json),
        "{\"msgs\":%lu,\"rate\":%lu,\"uptime\":\"%s\",\"sniff\":%s,\"chan\":\"%s\",\"mqtt\":%s,"
        /* sparkp, not spark: the old field carried <rect> markup, this one
         * carries polyline coordinates -- a renamed field breaks louder. */
        "\"sparkp\":\"%s\",\"smax\":%lu,\"idle\":%ld,\"types\":\"%s\""
        /* Literal UTF-8, not an entity: arApply writes it with textContent,
         * which would show "&middot;" verbatim. */
        ",\"clk\":\"%s\""
        ",\"hrp\":\"%s\",\"hrs\":\"%s\""
#ifdef CONFIG_ENABLE_TEMPERATURE
        ",\"temp\":%s,\"tcl\":\"%s\""
        ",\"htp\":\"%s\",\"htb\":\"%s\""
#endif
        "%s%s}",
        (unsigned long)msg_total_count, (unsigned long)rate, uptime_str,
        running ? "true" : "false", chan_str,
        mqtt_connected_state ? "true" : "false",
        spark, (unsigned long)peak, idle,
        typeline[0] ? typeline : T(S_ACTIVITY_NONE),
        clkj, hourr, hscale
#ifdef CONFIG_ENABLE_TEMPERATURE
        , tval, temp_class(tc), hourt, hband
#endif
        /* Last, so the temperature block above keeps its argument order. */
        , sdj, lossj
    );
    /* The peer row on another node's status page reads this cross-origin,
     * exactly like /markers.json and /tracks.json already allow. */
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

#if CONFIG_HTTPD_WS_SUPPORT
/* ================================================================== */
/*  /ws -- live feed for /messages                                    */
/*                                                                    */
/*  A periodic timer (see webserver_init) queues a broadcast roughly   */
/*  once a second, but only while the ring actually changed, onto the  */
/*  httpd task via httpd_queue_work -- this is the only place raw      */
/*  frame data crosses to another task, and httpd_ws_send_frame_async  */
/*  must be called from the httpd task itself (ESP-IDF requirement),   */
/*  so building the JSON *and* enumerating clients happens inside that */
/*  one queued work function rather than in the timer callback.        */
/* ================================================================== */

static httpd_handle_t g_httpd_server;
static uint32_t ws_last_broadcast_count = UINT32_MAX;
#endif /* CONFIG_HTTPD_WS_SUPPORT */

/* The JSON/text builders below are shared: the WS live feed, the /messages
 * page and /markers.json (multi-receiver map) all use them, so they must
 * exist even when websocket support is compiled out. */

/* Compact JSON for the browser to turn into table rows. Short field names keep
 * the payload small: t/r/l/y/sm/h always, and a/o/i (lat/lon/stationId) only
 * when a position was decoded. */

/* Emits the warning keys for a station: `d` that a warning is recent, `dt` what
 * the warning was. The text comes from our own tables and needs no escaping. */
static size_t denm_json(uint32_t station_id, uint32_t now, char *out, size_t cap)
{
    if (!denm_is_recent(station_id, now))
        return 0;
    uint8_t sub = 0;
    uint8_t cause = denm_cause_of(station_id, &sub);
    const char *ct = denm_cause_text(cause);
    const char *st = denm_sub_text(cause, sub);
    if (ct && st)
        return (size_t)snprintf(out, cap, ",\"d\":1,\"dt\":\"%s (%s)\"", ct, st);
    if (ct)
        return (size_t)snprintf(out, cap, ",\"d\":1,\"dt\":\"%s\"", ct);
    return (size_t)snprintf(out, cap, ",\"d\":1");
}

/* Optional CAM-detail keys shared by live feed and map seed. Short keys are
 * crowded, so check for collisions before adding one (`h` is the detail text). */
static size_t cam_json_extra(const web_msg_entry_t *e, char *out, size_t cap)
{
    size_t n = 0;
    if (e->heading_ddeg != 0xFFFF && n < cap)
        n += snprintf(out + n, cap - n, ",\"hd\":%u", (unsigned)e->heading_ddeg);
    /* Sent whenever the field was PRESENT, including all-bits-zero. Omitting
     * zero made "no pedal pressed" look identical to "this message didn't
     * carry the field", and the client -- which keeps the last known value --
     * would then hold a stale "braking" instead of clearing it. */
    if (e->has_accel_ctrl && n < cap)
        n += snprintf(out + n, cap - n, ",\"ac\":%u", (unsigned)e->accel_ctrl);
    if (e->has_lights && n < cap)
        n += snprintf(out + n, cap - n, ",\"el\":%u", (unsigned)e->ext_lights);
    /* role 0 is "default" -- nothing worth showing, so only send 1..15. */
    if (e->role != 0xFF && e->role != 0 && n < cap)
        n += snprintf(out + n, cap - n, ",\"vr\":%u", (unsigned)e->role);
    /* R09 telegram detail. `pd` is sent even when zero -- but zero means "on
     * time OR the field was not transmitted", the two are indistinguishable in
     * R09.16. The client keeps the last value per station. */
    if (e->pt_telegram && e->pt_course && n < cap)
        n += snprintf(out + n, cap - n, ",\"pk\":%u", (unsigned)e->pt_course);
    if (e->pt_telegram && e->pt_dest && n < cap)
        n += snprintf(out + n, cap - n, ",\"pz\":%u", (unsigned)e->pt_dest);
    if (e->pt_telegram && n < cap)
        n += snprintf(out + n, cap - n, ",\"pd\":%d", (int)e->pt_deviation);
    if (e->embarking && n < cap)
        n += snprintf(out + n, cap - n, ",\"eb\":1");
    /* Where the vehicle just came from, as [[lat,lon],...] in 1e-7 degrees.
     * Up to 8 points -- ~200 bytes, by far the largest key here, so it goes
     * last and is skipped entirely when the sender doesn't provide one. */
    if (e->n_path && n < cap)
    {
        n += snprintf(out + n, cap - n, ",\"ph\":[");
        for (uint8_t i = 0; i < e->n_path && n < cap; i++)
            n += snprintf(out + n, cap - n, "%s[%ld,%ld]", i ? "," : "",
                          (long)e->path_lat_e7[i], (long)e->path_lon_e7[i]);
        if (n < cap)
            n += snprintf(out + n, cap - n, "]");
    }
    return n;
}

/* One-line human summary of what was decoded from a frame. The raw bytes are
 * not repeated here. They only go into the PCAP recording. */
static void msg_detail_text(const web_msg_entry_t *e, uint32_t now,
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
    static const char *COMPASS[8] = { "N", "NO", "O", "SO", "S", "SW", "W", "NW" };
    bool de = current_lang == LANG_DE;
    size_t n = 0;
    out[0] = '\0';

    #define DETAIL_SEP (n ? " &middot; " : "")
    if (e->has_position && (e->lat_e7 || e->lon_e7))
        n += snprintf(out + n, cap - n, "%s%.5f, %.5f", DETAIL_SEP,
                      e->lat_e7 / 1e7, e->lon_e7 / 1e7);
    /* -1 cm/s is the GN "not available" pattern, not a reading. Printing it
     * would show "-0 km/h". */
    if (e->has_speed && e->speed_cmps != -1 && n < cap)
        n += snprintf(out + n, cap - n, "%s%.0f km/h", DETAIL_SEP,
                      e->speed_cmps * 0.036);
    if (e->heading_ddeg != 0xFFFF && n < cap)
    {
        unsigned deg = e->heading_ddeg / 10;
        n += snprintf(out + n, cap - n, "%s%u&deg; %s", DETAIL_SEP, deg,
                      COMPASS[((deg + 22) / 45) % 8]);
    }
    if (e->length_dm && e->width_dm && n < cap)
        n += snprintf(out + n, cap - n, "%s%u,%u &times; %u,%u m", DETAIL_SEP,
                      e->length_dm / 10, e->length_dm % 10,
                      e->width_dm / 10, e->width_dm % 10);
    if (e->pt_line && n < cap)
        n += snprintf(out + n, cap - n, "%s%s %u", DETAIL_SEP,
                      de ? "Linie" : "line", (unsigned)e->pt_line);
    /* Course number distinguishes the individual run of a line; the schedule
     * deviation is what makes a delayed tram visible. */
    if (e->pt_telegram && e->pt_course && n < cap)
        n += snprintf(out + n, cap - n, "%s%s %u", DETAIL_SEP,
                      de ? "Kurs" : "course", (unsigned)e->pt_course);
    if (e->pt_telegram && e->pt_dest && n < cap)
        n += snprintf(out + n, cap - n, "%s%s %u", DETAIL_SEP,
                      de ? "Ziel" : "dest", (unsigned)e->pt_dest);
    if (e->pt_telegram && e->pt_deviation && n < cap)
        n += snprintf(out + n, cap - n, "%s%+d %s", DETAIL_SEP,
                      (int)e->pt_deviation, de ? "Min" : "min");
    /* Priority request and turn request are what the telegram is actually FOR
     * -- they are why the traffic light lets this vehicle through. */
    if (e->pt_telegram && e->pt_priority && n < cap)
        n += snprintf(out + n, cap - n, "%s%s %u", DETAIL_SEP,
                      de ? "Prio" : "prio", (unsigned)e->pt_priority);
    if (e->pt_telegram && e->pt_request && e->pt_request < 4 && n < cap)
    {
        static const char *const HA_DE[] = { "", "geradeaus", "links", "rechts" };
        static const char *const HA_EN[] = { "", "straight", "left", "right" };
        n += snprintf(out + n, cap - n, "%s%s %s", DETAIL_SEP,
                      de ? "Wunsch" : "request",
                      (de ? HA_DE : HA_EN)[e->pt_request]);
    }
    if (e->role != 0xFF && e->role < 16 && (de ? ROLE_DE : ROLE_EN)[e->role] && n < cap)
        n += snprintf(out + n, cap - n, "%s%s", DETAIL_SEP,
                      (de ? ROLE_DE : ROLE_EN)[e->role]);
    if (e->has_accel_ctrl && n < cap)
    {
        if (e->accel_ctrl & ITS_ACC_BRAKE)
            n += snprintf(out + n, cap - n, "%s%s", DETAIL_SEP, de ? "bremst" : "braking");
        else if (e->accel_ctrl & ITS_ACC_GAS)
            n += snprintf(out + n, cap - n, "%s%s", DETAIL_SEP, de ? "Gas" : "throttle");
    }
    if (e->has_lights && n < cap)
    {
        if (e->ext_lights & ITS_LIGHT_LEFT)
            n += snprintf(out + n, cap - n, "%s%s", DETAIL_SEP, de ? "Blinker links" : "left indicator");
        if (e->ext_lights & ITS_LIGHT_RIGHT && n < cap)
            n += snprintf(out + n, cap - n, "%s%s", DETAIL_SEP, de ? "Blinker rechts" : "right indicator");
    }
    if (e->embarking && n < cap)
        n += snprintf(out + n, cap - n, "%s%s", DETAIL_SEP,
                      de ? "Fahrgastwechsel" : "boarding");
    if (denm_is_recent(e->station_id, now) && n < cap)
    {
        uint8_t sub = 0;
        const char *ct = denm_cause_text(denm_cause_of(e->station_id, &sub));
        if (ct)
            n += snprintf(out + n, cap - n,
                          "%s<span style='color:#e74c3c'>&#9888; %s</span>",
                          DETAIL_SEP, ct);
    }
    #undef DETAIL_SEP
    if (n == 0)
        snprintf(out, cap, "&ndash;");
}

/* Only two consumers: the websocket broadcast and /markers.json (SD builds).
 * Guarded so a build with neither doesn't carry a dead function. */
#if CONFIG_HTTPD_WS_SUPPORT || CONFIG_ENABLE_SD
static size_t build_msg_json(char *out, size_t out_size)
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
    size_t o = 0;
    o += snprintf(out + o, out_size - o, "[");
    for (size_t n = 0; n < count && o < out_size; n++)
    {
        web_msg_entry_t *e = &snapshot[count - 1 - n];

        char detail[384];
        msg_detail_text(e, jnow, detail, sizeof(detail));

        char clock[24];
        format_clock(e->seconds, e->microseconds, clock, sizeof(clock));

        char rssi_str[16];
        if (e->rssi != 0)
            snprintf(rssi_str, sizeof(rssi_str), "%d dBm", e->rssi);
        else
            snprintf(rssi_str, sizeof(rssi_str), "-");

        /* Base keys ~60 + speed/size/line ~44 + CAM detail up to ~250
         * (the path history dominates) + the warning flag. */
        char possuffix[576] = "";
        if (e->has_position)
        {
            size_t po = snprintf(possuffix, sizeof(possuffix), ",\"a\":%ld,\"o\":%ld,\"i\":%lu",
                     (long)e->lat_e7, (long)e->lon_e7, (unsigned long)e->station_id);
            /* -1 cm/s is the GN "speed unavailable" pattern, not a reading --
             * emitting it printed "-0.0 km/h" in the popup. */
            if (e->has_speed && e->speed_cmps != -1 && po < sizeof(possuffix))
                po += snprintf(possuffix + po, sizeof(possuffix) - po, ",\"s\":%ld", (long)e->speed_cmps);
            if (e->length_dm && e->width_dm && po < sizeof(possuffix))
                po += snprintf(possuffix + po, sizeof(possuffix) - po,
                               ",\"vl\":%u,\"vw\":%u",
                               (unsigned)e->length_dm, (unsigned)e->width_dm);
            if (e->pt_line && po < sizeof(possuffix))
                po += snprintf(possuffix + po, sizeof(possuffix) - po,
                               ",\"pl\":%u", (unsigned)e->pt_line);
            if (po < sizeof(possuffix))
                po += cam_json_extra(e, possuffix + po, sizeof(possuffix) - po);
            if (po < sizeof(possuffix))
                denm_json(e->station_id, jnow, possuffix + po, sizeof(possuffix) - po);
        }

        /* All inputs here are our own tables and formatted numbers, nothing frame-
         * controlled -- no JSON escaping needed; entities/<span> are fine via innerHTML. */
        /* Measure first and stop while the closing `]` still fits: without it
         * the client's JSON.parse fails. Newest entry first, oldest drop out. */
        char mac_str[20];
        if (e->has_src_mac)
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     e->src_mac[0], e->src_mac[1], e->src_mac[2],
                     e->src_mac[3], e->src_mac[4], e->src_mac[5]);
        else
            snprintf(mac_str, sizeof(mac_str), "-");

        static const char ENTRY_FMT[] =
            "%s{\"t\":\"%s\",\"r\":\"%s\",\"l\":%lu,\"y\":\"%s\",\"sm\":\"%s\",\"h\":\"%s\"%s}";
        int need = snprintf(NULL, 0, ENTRY_FMT,
            n == 0 ? "" : ",", clock, rssi_str, (unsigned long)e->length,
            e->msgtype, mac_str, detail, possuffix);
        if (need < 0 || o + (size_t)need + 2 > out_size)
            break;
        o += snprintf(out + o, out_size - o, ENTRY_FMT,
            n == 0 ? "" : ",", clock, rssi_str, (unsigned long)e->length,
            e->msgtype, mac_str, detail, possuffix);
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

static void ws_broadcast_work(void *arg)
{
    (void)arg;
    if (!g_httpd_server)
        return;

    static EXT_RAM_BSS_ATTR char json[6144];
    size_t len = build_msg_json(json, sizeof(json));

    size_t max_fds = CONFIG_LWIP_MAX_SOCKETS;
    int client_fds[CONFIG_LWIP_MAX_SOCKETS];
    if (httpd_get_client_list(g_httpd_server, &max_fds, client_fds) != ESP_OK)
        return;

    uint32_t now = (uint32_t)time(NULL);
    httpd_ws_frame_t frame = { .type = HTTPD_WS_TYPE_TEXT, .payload = (uint8_t *)json, .len = len };
    for (size_t i = 0; i < max_fds; i++)
    {
        int fd = client_fds[i];
        if (httpd_ws_get_fd_info(g_httpd_server, fd) != HTTPD_WS_CLIENT_WEBSOCKET)
            continue;
        if (ws_recently_failed(fd, now))
            continue;
        /* A failed send means the client is gone, but esp_http_server won't
         * notice on its own -- the dead session would occupy a
         * max_open_sockets slot forever otherwise. */
        if (httpd_ws_send_frame_async(g_httpd_server, fd, &frame) != ESP_OK)
        {
            ws_mark_failed(fd, now);
            httpd_sess_trigger_close(g_httpd_server, fd);
        }
    }
}

/* Fires roughly once a second (see webserver_init); cheap no-op when nothing
 * new arrived, so idle browsers don't cause httpd work-queue churn. */
static void ws_broadcast_tick(void *arg)
{
    (void)arg;
    if (msg_total_count == ws_last_broadcast_count)
        return;
    ws_last_broadcast_count = msg_total_count;
    httpd_queue_work(g_httpd_server, ws_broadcast_work, NULL);
}

static esp_err_t ws_get_handler(httpd_req_t *req)
{
    if (req->method == HTTP_GET)
        return ESP_OK; /* handshake done; client just receives broadcasts */

    /* We never expect the browser to send anything meaningful -- just drain
     * whatever arrived so it doesn't desync the next frame. Oversized frames
     * (shouldn't happen from our own JS) close the connection by returning
     * an error, per httpd_uri_t's contract. */
    httpd_ws_frame_t pkt = {0};
    pkt.type = HTTPD_WS_TYPE_TEXT;
    esp_err_t ret = httpd_ws_recv_frame(req, &pkt, 0);
    if (ret != ESP_OK)
        return ret;
    if (pkt.len > 0 && pkt.len < 256)
    {
        uint8_t buf[256];
        pkt.payload = buf;
        return httpd_ws_recv_frame(req, &pkt, sizeof(buf));
    }
    return pkt.len == 0 ? ESP_OK : ESP_FAIL;
}
#endif /* CONFIG_HTTPD_WS_SUPPORT */

/* ================================================================== */
/*  GET /messages                                                     */
/* ================================================================== */

static esp_err_t messages_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* Live-updated over WebSocket (see /ws) instead of a periodic full-page
     * reload, so the table refreshes without flicker or losing scroll
     * position. */
    send_page_header(req, T(S_TITLE_MESSAGES));

#if CONFIG_ENABLE_SD
    /* Only with a card: without one the two archive groups are never emitted,
     * and the links would point at nothing. */
    char mjump[256];
    HTML_PRINTF(mjump,
        "<p class='jump'>%s: <a href='#m-srch'>%s</a> &middot; "
        "<a href='#m-rsu'>%s</a></p>",
        T(S_TRF_JUMP), T(S_SRCH_TITLE), T(S_RSU_UP_TITLE));
    httpd_resp_send_chunk(req, mjump, HTTPD_RESP_USE_STRLEN);
#endif

    /* Opens the page's first group; closed once before the archive block. */
    char intro[256];
    snprintf(intro, sizeof(intro), "<div class='grp top'><p class='note'>");
    size_t l = strlen(intro);
    snprintf(intro + l, sizeof(intro) - l, T(S_MSG_INTRO), WEB_MSG_RING_SIZE);
    l = strlen(intro);
    snprintf(intro + l, sizeof(intro) - l, "</p>");
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);

    /* Own chunk (not concatenated into intro above): T(S_TYPE_HINT) alone can
     * approach several hundred bytes, which intro's small fixed buffer isn't
     * sized for. */
    char typehint[768];
    snprintf(typehint, sizeof(typehint), "<p class='note'>%s</p>", T(S_TYPE_HINT));
    httpd_resp_send_chunk(req, typehint, HTTPD_RESP_USE_STRLEN);

    /* Formatted output is ~300 bytes. A cut inside the open <script> makes the
     * browser swallow the rest of the table as script text. */
    char fbar[512];
    HTML_PRINTF(fbar,
        /* Colon inside the label: as its own text node it would become a flex
         * item of .tools and sit a gap away from the word. */
        "<p class='tools'><label class='cap' for='lf'>%s:</label>"
        "<input id='lf' size='18' oninput='applyf()'></p>"
        "<script>window.applyf=function(){"
        "var n=document.getElementById('lf').value.toLowerCase();"
        "document.querySelectorAll('#msgtbody tr').forEach(function(r){"
        "r.style.display=(!n||r.textContent.toLowerCase().indexOf(n)>=0)?'':'none';});};"
        "</script>",
        T(S_SRCH_FILTER));
    httpd_resp_send_chunk(req, fbar, HTTPD_RESP_USE_STRLEN);

    char thead[384];
    snprintf(thead, sizeof(thead),
        "<div class='scroll'><table id='mtbl'><thead><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead>"
        "<tbody id='msgtbody'>",
        T(S_COL_NUM), T(S_COL_TIME), T(S_COL_RSSI), T(S_COL_LENGTH), T(S_COL_TYPE),
        T(S_COL_SENDER), T(S_COL_PREVIEW));
    httpd_resp_send_chunk(req, thead, HTTPD_RESP_USE_STRLEN);

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

    for (size_t n = 0; n < count; n++)
    {
        web_msg_entry_t *e = &snapshot[count - 1 - n];

        char detail[384];
        msg_detail_text(e, (uint32_t)time(NULL), detail, sizeof(detail));

        char clock[24];
        format_clock(e->seconds, e->microseconds, clock, sizeof(clock));

        char rssi_str[16];
        if (e->rssi != 0)
            snprintf(rssi_str, sizeof(rssi_str), "%d dBm", e->rssi);
        else
            snprintf(rssi_str, sizeof(rssi_str), "-");

        char typeesc[WEB_MSG_TYPE_LEN * 6];
        html_escape(e->msgtype, typeesc, sizeof(typeesc));

        char mac_str[20];
        if (e->has_src_mac)
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     e->src_mac[0], e->src_mac[1], e->src_mac[2],
                     e->src_mac[3], e->src_mac[4], e->src_mac[5]);
        else
            snprintf(mac_str, sizeof(mac_str), "-");

        char row[896];
        HTML_PRINTF(row,
            "<tr><td>%zu</td><td>%s</td><td>%s</td><td>%lu</td>"
            "<td class='wrapcell'>%s</td><td class='mono'>%s</td><td class='wrapcell'>%s</td></tr>",
            n + 1, clock, rssi_str, (unsigned long)e->length, typeesc, mac_str, detail);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

#if CONFIG_HTTPD_WS_SUPPORT
    /* Reconnects with backoff if the socket drops (e.g. Wi-Fi hiccup on the
     * client, or the device rebooting) -- the static rows above still work
     * without JS/WebSocket, just without the live updates. */
    static const char ws_script[] =
        "<script>(function(){"
        "var delay=1000,ws,closing=false;"
        "function connect(){"
        "var proto=location.protocol==='https:'?'wss://':'ws://';"
        "ws=new WebSocket(proto+location.host+'/ws');"
        "ws.onmessage=function(ev){"
        "var d=JSON.parse(ev.data);var h='';"
        "for(var i=0;i<d.length;i++){var m=d[i];"
        /* Vehicle size, when the CAM carried it, goes into the type cell
         * rather than costing the table another mostly-empty column. */
        "var ty=m.y+(m.pl?' <b>'+m.pl+'</b>':'')+((m.vl&&m.vw)?' <small>'+(m.vl/10).toFixed(1)+'\\u00d7'+(m.vw/10).toFixed(1)+'m</small>':'');"
        "h+='<tr><td>'+(i+1)+'</td><td>'+m.t+'</td><td>'+m.r+'</td><td>'+m.l+'</td><td class=\"wrapcell\">'+ty+'</td><td class=\"mono\">'+(m.sm||'-')+'</td><td class=\"wrapcell\">'+m.h+'</td></tr>';}"
        "document.getElementById('msgtbody').innerHTML=h;if(window.applyf)window.applyf();delay=1000;};"
        "ws.onclose=function(){if(closing)return;setTimeout(connect,delay);delay=Math.min(delay*2,30000);};"
        "}"
        "connect();"
        /* Navigating away/reloading without this leaves the socket to be
         * reaped later by the server-side dead-client check in
         * ws_broadcast_work instead of freeing it immediately. */
        "window.addEventListener('pagehide',function(){closing=true;if(ws)ws.close();});"
        "})();</script>";
    httpd_resp_send_chunk(req, ws_script, HTTPD_RESP_USE_STRLEN);
#endif

    /* Closes .grp top unconditionally -- the archive block below is SD-only
     * and must not be the one carrying the closing tag. */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD
    /* Archive tools belong next to the messages they operate on: search the
     * PCAP recording, and the manual re-send of stationary senders. */
    {
        /* 2.6 KB of literal plus 19 substituted strings; sized with room and
         * checked, because a cut here swallows the rest of the page. */
        static EXT_RAM_BSS_ATTR char arch[6144];
        HTML_PRINTF(arch,
            "<div class='grp' id='m-srch'><h2>%s</h2><p class='note'>%s</p>"
            "<p class='tools'><input type='datetime-local' id='sf' aria-label='%s'> &ndash; "
            "<input type='datetime-local' id='st' aria-label='%s'> "
            "<label class='cap' for='sq'>%s:</label> "
            "<input id='sq' size='14' maxlength='32'> "
            "<button onclick='srch()'>%s</button> "
            "<button onclick='expp()'>%s</button></p>"
            "<p class='note'>%s</p>"
            "<div id='sr'></div></div>"
            "<div class='grp' id='m-rsu'><h2>%s</h2><p class='note'>%s</p>"
            "<p class='tools'><input type='datetime-local' id='rf' aria-label='%s'> &ndash; "
            "<input type='datetime-local' id='rt' aria-label='%s'> "
            "<label class='cap' for='rth'>%s:</label> "
            "<select id='rth'><option value='0' selected>%s</option>"
            "<option value='3600'>1/h</option>"
            "<option value='600'>1/10 min</option></select> "
            "<button onclick='rsuup()'>%s</button></p>"
            "<pre id='rr' class='logpre'></pre></div>"
            "<script>"
            "(function(){function f(d){var p=function(n){return (n<10?'0':'')+n;};"
            "return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())+'T'+p(d.getHours())+':'+p(d.getMinutes());}"
            "var n=new Date();"
            "document.getElementById('st').value=f(n);"
            "document.getElementById('sf').value=f(new Date(n.getTime()-216e5));"
            "document.getElementById('rt').value=f(n);"
            "document.getElementById('rf').value=f(new Date(n.getTime()-864e5));})();"
            "function srch(){"
            "var f=Math.floor(new Date(document.getElementById('sf').value).getTime()/1000);"
            "var t=Math.floor(new Date(document.getElementById('st').value).getTime()/1000);"
            "if(!f||!t)return;"
            "var o=document.getElementById('sr');o.textContent='%s';"
            "fetch('/messages/search?from='+f+'&to='+t+'&q='+encodeURIComponent(document.getElementById('sq').value)+'&lang=%s')"
            ".then(function(r){return r.text();}).then(function(x){o.innerHTML=x;})"
            ".catch(function(){o.textContent='Fehler';});}"
            "function expp(){"
            "var f=Math.floor(new Date(document.getElementById('sf').value).getTime()/1000);"
            "var t=Math.floor(new Date(document.getElementById('st').value).getTime()/1000);"
            "if(!f||!t)return;"
            "location.href='/messages/export.pcap?from='+f+'&to='+t"
            "+'&q='+encodeURIComponent(document.getElementById('sq').value);}"
            "var RS='%s';"
            "function rsuup(){"
            "var f=Math.floor(new Date(document.getElementById('rf').value).getTime()/1000);"
            "var t=Math.floor(new Date(document.getElementById('rt').value).getTime()/1000);"
            "if(!f||!t)return;"
            "var o=document.getElementById('rr');o.textContent=RS;"
            "fetch('/sdcard/upload_rsu?from='+f+'&to='+t+'&thin='+document.getElementById('rth').value+'&lang=%s',{method:'POST'})"
            ".then(function(r){return r.text();}).then(function(x){"
            "if(x!=='OK'){o.textContent=x;return;}"
            "var iv=setInterval(function(){"
            "fetch('/sdcard/upload_rsu/status',{cache:'no-store'}).then(function(r){return r.json();})"
            ".then(function(s){if(s.run){o.textContent=RS+' '+s.sent;}"
            "else{o.textContent=s.msg;clearInterval(iv);}})"
            ".catch(function(){});},1500);})"
            ".catch(function(){o.textContent='Fehler';});}"
            "</script>",
            T(S_SRCH_TITLE), T(S_SRCH_HINT),
            T(S_PLAYBACK_FROM), T(S_PLAYBACK_TO), T(S_SRCH_FILTER), T(S_SRCH_BTN),
            T(S_SRCH_EXPORT), T(S_SRCH_EXPORT_HINT),
            T(S_RSU_UP_TITLE), T(S_RSU_UP_HINT),
            T(S_PLAYBACK_FROM), T(S_PLAYBACK_TO), T(S_RSU_UP_THIN), T(S_RSU_UP_ONCE),
            T(S_RSU_UP_BTN),
            /* The fetches carry the page's language along. Without it the
             * search table and the upload status come back German on ?lang=en. */
            T(S_SRCH_RUN), current_lang == LANG_EN ? "en" : "de",
            T(S_RSU_UP_RUN), current_lang == LANG_EN ? "en" : "de");
        httpd_resp_send_chunk(req, arch, HTTPD_RESP_USE_STRLEN);
    }
#endif

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  GET /map -- live positions from CAM and GeoNetworking headers     */
/* ================================================================== */

static esp_err_t map_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    send_page_header(req, T(S_TITLE_MAP));

    /* Collapsible via native <details>, no JS needed. Collapsed by default,
     * because the full explanation pushes the map below the fold on a phone.
     * The summary takes one line. */
    /* Measured: 1398 bytes in German, 557 of them the hint text. Sized with
     * headroom, because a cut here ends the markup mid-tag and takes the map
     * container with it. */
    char hint[2560];
    HTML_PRINTF(hint,
        "<details class='dtl'>"
        "<summary>%s</summary>"
        "<p class='note'>%s</p></details>"
        "<link rel='stylesheet' href='/leaflet.css'>"
        "<script src='/leaflet.js'></script>"
        /* The icon box grew to 40px to hold the heading needle; the popup is
         * restyled dark because the page itself is dark and a white bubble
         * over a dark basemap is glaring. */
        "<style>.its-emoji-icon{font-size:20px;line-height:40px;text-align:center}"
        ".leaflet-popup-content-wrapper,.leaflet-popup-tip{background:#15191d;"
        "color:#edf0f2;box-shadow:0 3px 16px rgba(0,0,0,.6)}"
        ".leaflet-popup-content{margin:10px 13px;font-size:13px}"
        ".leaflet-container a.leaflet-popup-close-button{color:#94a0a8}"
        ".leaflet-container a.leaflet-popup-close-button:hover{color:#edf0f2}"
        ".leaflet-control-layers{background:#15191d;color:#edf0f2;"
        "border:1px solid #2a2f34}"
        ".leaflet-bar a{background:#15191d;color:#edf0f2;border-bottom:1px solid #2a2f34}"
        ".leaflet-bar a:hover{background:#1d2227;color:#edf0f2}</style>"
        "<div id='map' style='height:70vh;border-radius:12px;overflow:hidden'></div>",
        T(S_MAP_HELP), T(S_MAP_HINT));
    httpd_resp_send_chunk(req, hint, HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD && CONFIG_HTTPD_WS_SUPPORT
    /* Playback controls: hidden until pbLoad() (see MAP_SCRIPT) finds at
     * least one entry. Default from/to values are filled in by JS, not
     * here, since datetime-local needs the *browser's* local time. */
    /* Reading a multi-hour window off the SD card takes seconds, and with no
     * feedback at all the page looked dead -- so an indeterminate bar runs
     * while the request is in flight. Indeterminate rather than percentage:
     * the response is streamed and its total length isn't known up front. */
    /* Measured worst case (German) is 1149 bytes; a truncated closing tag
     * here would collapse the page layout, so keep real headroom. */
    char pbctl[1536];
    HTML_PRINTF(pbctl,
        "<style>@keyframes pbslide{0%%{left:-40%%}100%%{left:100%%}}"
        "#pbbar{display:none;width:160px;height:6px;border-radius:3px;"
        "background:#2a3138;overflow:hidden;position:relative;"
        "vertical-align:middle;margin-left:8px}"
        "#pbbar i{position:absolute;top:0;height:100%%;width:40%%;border-radius:3px;"
        "background:#f2b134;animation:pbslide 1.1s infinite linear}</style>"
        "<div class='grp nohd'>"
        "<label>%s <input type='datetime-local' id='pbfrom'></label> "
        "<label>%s <input type='datetime-local' id='pbto'></label> "
        "<button id='pbload'>%s</button>"
        "<span id='pbbar'><i></i></span> "
        "<span id='pbmsg'></span>"
        "<span id='pbctl' style='display:none'>"
        "<button id='pbplay'>&#9654;</button> "
        "<input id='pbslider' type='range' min='0' max='0' value='0' step='10' "
        "style='width:220px;vertical-align:middle'> "
        "<span id='pbtime'></span>"
        /* Step size drives both the slider granularity and how far each
         * play tick advances, so it doubles as the replay speed. */
        " <label style='margin-left:10px'>%s "
        "<select id='pbstep'>"
        "<option value='1'>1 s</option>"
        "<option value='2'>2 s</option>"
        "<option value='5'>5 s</option>"
        "<option value='10' selected>10 s</option>"
        "<option value='30'>30 s</option>"
        "<option value='60'>60 s</option>"
        "</select></label>"
        /* Own row with real top margin -- on phone, Live would otherwise
         * wrap directly under Play with no gap, easy to fat-finger. */
        "<div style='margin-top:10px'><button id='pblive'>%s</button></div>"
        "</span></div>",
        T(S_PLAYBACK_FROM), T(S_PLAYBACK_TO), T(S_PLAYBACK_LOAD),
        T(S_PLAYBACK_STEP), T(S_PLAYBACK_LIVE));
    httpd_resp_send_chunk(req, pbctl, HTTPD_RESP_USE_STRLEN);
#endif

    /* The localized strings and settings the client script needs, passed in as
     * JS vars so MAP_SCRIPT below can stay one fixed static string, not a
     * per-request snprintf. */
    uint32_t stale = 60;
    config_get_u32(CONFIG_INDEX_MAP_STALE_SEC, &stale);
    uint32_t trkdays = 2;
    config_get_u32(CONFIG_INDEX_TRACKS_DAYS, &trkdays);

    /* Peer list -> a JS array literal. Only letters, digits, '.', '-' and ':'
     * survive the filter below, so nothing from the setting can break out of
     * the quotes into the surrounding script. */
    char peers[CONFIG_PEERS_BUFFER_SIZE] = {0};
    size_t peersz = sizeof(peers);
    config_get_str(CONFIG_INDEX_PEERS, peers, &peersz);
    /* This device's own name, so a marker can say which receiver heard it
     * even when the answer is "this one". */
    char selfname[CONFIG_NODEID_BUFFER_SIZE] = "";
    size_t selfsz = sizeof(selfname);
    config_get_str(CONFIG_INDEX_NODEID, selfname, &selfsz);
    for (char *c = selfname; *c; c++)
        if (!((*c >= 'a' && *c <= 'z') || (*c >= 'A' && *c <= 'Z') ||
              (*c >= '0' && *c <= '9') || *c == '.' || *c == '-' || *c == '_'))
            *c = '-';

    char peerjs[CONFIG_PEERS_BUFFER_SIZE * 2] = {0};
    {
        size_t o = 0;
        bool first = true, open_q = false;
        for (const char *p = peers; *p && o + 4 < sizeof(peerjs); p++)
        {
            bool ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                      (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == ':';
            if (ok)
            {
                if (!open_q)
                {
                    if (!first) peerjs[o++] = ',';
                    peerjs[o++] = '"';
                    open_q = true;
                    first = false;
                }
                peerjs[o++] = *p;
            }
            else if (open_q)
            {
                peerjs[o++] = '"';
                open_q = false;
            }
        }
        if (open_q && o + 1 < sizeof(peerjs)) peerjs[o++] = '"';
        peerjs[o] = '\0';
    }
    char labels[1792];   /* worst case ~1354 with all texts, peers and node id */
    HTML_PRINTF(labels,
             "<script>var ITS_MAP_L_STREETS=\"%s\",ITS_MAP_L_SAT=\"%s\","
             "ITS_MAP_L_DARK=\"%s\",ITS_MAP_L_LIGHT=\"%s\","
             "ITS_MAP_L_TRACKS=\"%s\",ITS_MAP_L_TRACKS_P=\"%s\","
             "ITS_MAP_TRACK_PTS=\"%s\",ITS_MAP_TRACK_CAP=\"%s\",ITS_MAP_TRACK_DAYS=%lu,"
             "ITS_MAP_TRACK_DUR=\"%s\",ITS_MAP_BUSY=\"%s\","
             "ITS_MAP_SEEN_BY=\"%s\",ITS_MAP_PEERS=[%s],ITS_MAP_SELF=\"%s\","
             "ITS_PB_NONE=\"%s\",ITS_PB_ERROR=\"%s\",ITS_PB_BUSY=\"%s\","
             "ITS_PB_PART=\"%s\","
             "ITS_MAP_DENM=\"%s\","
             "ITS_MAP_STALE=%lu,ITS_MAP_LINE=\"%s\","
             "ITS_MAP_KURS=\"%s\",ITS_MAP_ZIEL=\"%s\","
             "ITS_MAP_LATE=\"%s\",ITS_MAP_EARLY=\"%s\",ITS_MAP_ONTIME=\"%s\";</script>",
             T(S_MAP_LAYER_STREETS), T(S_MAP_LAYER_SATELLITE),
             T(S_MAP_LAYER_DARK), T(S_MAP_LAYER_LIGHT),
             T(S_MAP_LAYER_TRACKS), T(S_MAP_LAYER_TRACKS_P),
             T(S_MAP_TRACK_PTS), T(S_MAP_TRACK_CAP), (unsigned long)trkdays,
             T(S_MAP_TRACK_DUR), T(S_MAP_BUSY),
             T(S_MAP_SEEN_BY), peerjs, selfname,
             T(S_PLAYBACK_NONE), T(S_PLAYBACK_ERROR), T(S_PLAYBACK_BUSY),
             T(S_PLAYBACK_PARTIAL),
             T(S_MAP_DENM),
             (unsigned long)stale, T(S_MAP_LINE),
             T(S_MAP_COURSE), T(S_MAP_DEST),
             T(S_MAP_LATE), T(S_MAP_EARLY), T(S_MAP_ONTIME));
    httpd_resp_send_chunk(req, labels, HTTPD_RESP_USE_STRLEN);

    /* Labels for the CAM detail in the popup. Emitted inline as JS vars rather
     * than ~40 more string-table entries, the same shortcut spat_status_text()
     * takes. These are leaf words that appear in exactly one place. Order in
     * ITS_CAM_A and ITS_CAM_L is the standard's bit order, MSB first. */
    char camlbl[1024];
    if (current_lang == LANG_DE)
        HTML_PRINTF(camlbl,
            "<script>var ITS_CAM_A=['bremst','Gas','Notbremse','Kollisionswarnung',"
            "'ACC','Tempomat','Speedlimiter'],"
            "ITS_CAM_L=['Abblendlicht','Fernlicht','Blinker links','Blinker rechts',"
            "'Tagfahrlicht','R&uuml;ckfahrlicht','Nebellicht','Standlicht'],"
            "ITS_CAM_R=['','&Ouml;PNV','Schwertransport','Gefahrgut','Baustelle',"
            "'Bergung','Einsatzfahrzeug','Sicherungsfahrzeug','Landwirtschaft',"
            "'Lieferverkehr','Milit&auml;r','Stra&szlig;endienst','Taxi','','',''],"
            "ITS_CAM_EMB='Fahrgastwechsel',ITS_CAM_DIR='Richtung',"
            "ITS_CAM_C=['N','NO','O','SO','S','SW','W','NW'];</script>");
    else
        HTML_PRINTF(camlbl,
            "<script>var ITS_CAM_A=['braking','throttle','emergency brake',"
            "'collision warning','ACC','cruise control','speed limiter'],"
            "ITS_CAM_L=['low beam','high beam','left indicator','right indicator',"
            "'daytime running','reversing light','fog light','parking light'],"
            "ITS_CAM_R=['','public transport','special transport','dangerous goods',"
            "'roadworks','rescue','emergency','safety car','agriculture',"
            "'commercial','military','road operator','taxi','','',''],"
            "ITS_CAM_EMB='boarding',ITS_CAM_DIR='heading',"
            "ITS_CAM_C=['N','NE','E','SE','S','SW','W','NW'];</script>");
    httpd_resp_send_chunk(req, camlbl, HTTPD_RESP_USE_STRLEN);

    /* Seed the map from the ring buffer so it isn't empty for up to ~1s
     * waiting for the next /ws tick. msgtype, clock and RSSI hold only
     * digits, letters, spaces, ':', '-' and '.', so they need no escaping. */
    httpd_resp_send_chunk(req, "<script>var ITS_MAP_SEED=[", HTTPD_RESP_USE_STRLEN);

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

    bool first = true;
    for (size_t n = 0; n < count; n++)
    {
        web_msg_entry_t *e = &snapshot[n];
        if (!e->has_position)
            continue;
        char clock[24];
        format_clock(e->seconds, e->microseconds, clock, sizeof(clock));
        char rssi_str[16];
        if (e->rssi != 0) snprintf(rssi_str, sizeof(rssi_str), "%d dBm", e->rssi);
        else              snprintf(rssi_str, sizeof(rssi_str), "-");
        char speedsuffix[24] = "";
        if (e->has_speed && e->speed_cmps != -1)   /* -1 = not available */
            snprintf(speedsuffix, sizeof(speedsuffix), ",\"s\":%ld", (long)e->speed_cmps);
        char denmsuffix[160] = "";
        denm_json(e->station_id, (uint32_t)time(NULL), denmsuffix, sizeof(denmsuffix));
        char dimsuffix[32] = "";
        if (e->length_dm && e->width_dm)
            snprintf(dimsuffix, sizeof(dimsuffix), ",\"vl\":%u,\"vw\":%u",
                     (unsigned)e->length_dm, (unsigned)e->width_dm);
        char ptsuffix[24] = "";
        if (e->pt_line)
            snprintf(ptsuffix, sizeof(ptsuffix), ",\"pl\":%u", (unsigned)e->pt_line);
        char camsuffix[384] = "";   /* worst case with pk/pz/pd + 8-point path ~270 */
        cam_json_extra(e, camsuffix, sizeof(camsuffix));
        /* Sized for the two large optional parts. The CAM detail takes up to
         * 384 bytes and the DENM text up to 160, on top of ids, clock and RSSI. */
        char entry[768];
        snprintf(entry, sizeof(entry),
                 "%s{\"i\":%lu,\"a\":%ld,\"o\":%ld,\"y\":\"%s\",\"t\":\"%s\",\"r\":\"%s\",\"l\":%lu%s%s%s%s%s}",
                 first ? "" : ",", (unsigned long)e->station_id,
                 (long)e->lat_e7, (long)e->lon_e7, e->msgtype, clock, rssi_str,
                 (unsigned long)e->length, speedsuffix, dimsuffix, ptsuffix,
                 camsuffix, denmsuffix);
        httpd_resp_send_chunk(req, entry, HTTPD_RESP_USE_STRLEN);
        first = false;
    }
    httpd_resp_send_chunk(req, "];</script>", HTTPD_RESP_USE_STRLEN);

#if CONFIG_HTTPD_WS_SUPPORT
    /* Reuses the /ws feed keys. Markers keyed by station_id, evicted after the configured
     * stale time. Initial view from the browser timezone, plain HTTP has no geolocation. */
    static const char MAP_SCRIPT[] =
        "<script>(function(){"
        "var TZVIEW={'Europe/Vienna':[47.6,14.5,7],'Europe/Berlin':[51,10.3,6],"
        "'Europe/Zurich':[46.9,8.2,7],'Europe':[50,10,4],'Africa':[2,20,3],"
        "'America':[40,-95,3],'Asia':[30,100,3],'Australia':[-25,135,4],'Pacific':[-20,-140,3]};"
        "var tz='';try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'';}catch(e){}"
        "var g=TZVIEW[tz]||TZVIEW[tz.split('/')[0]]||[20,0,2];"
        "var map=L.map('map').setView([g[0],g[1]],g[2]);"
        /* Dark and streets are the SAME tiles -- dark just inverts them in CSS.
         * Switching between the two is free, the browser already has them. */
        "var OSMU='https://tile.openstreetmap.org/{z}/{x}/{y}.png';"
        "var OSMA='&copy; OpenStreetMap contributors';"
        "var streets=L.tileLayer(OSMU,{maxZoom:19,attribution:OSMA});"
        "var dark=L.tileLayer(OSMU,{maxZoom:19,attribution:OSMA}).addTo(map);"
        "var sat=L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/"
        "World_Imagery/MapServer/tile/{z}/{y}/{x}',"
        "{maxZoom:19,attribution:'Tiles &copy; Esri'});"
        /* Esri Canvas for the quiet light map: CARTO now stamps "API KEY
         * REQUIRED" across its free tiles. Its data stops at zoom 16. */
        "var ECV='https://server.arcgisonline.com/ArcGIS/rest/services/Canvas/';"
        "var ECO={maxZoom:19,maxNativeZoom:16,"
        "attribution:'Tiles &copy; Esri &mdash; '+OSMA};"
        "var light=L.layerGroup(["
        "L.tileLayer(ECV+'World_Light_Gray_Base/MapServer/tile/{z}/{y}/{x}',ECO),"
        "L.tileLayer(ECV+'World_Light_Gray_Reference/MapServer/tile/{z}/{y}/{x}',ECO)]);"
        /* Only the tile pane is inverted, so tracks, pins and popups keep the
         * colours that carry meaning. */
        "function paintDark(on){var c=map.getContainer();"
        "L.DomUtil[on?'addClass':'removeClass'](c,'mapdark');}"
        "paintDark(true);"
        "map.on('baselayerchange',function(e){paintDark(e.layer===dark);});"
        /* Listed with the default first, so the checked entry is the one at
         * the top rather than somewhere in the middle. */
        "var baseLayers={};baseLayers[ITS_MAP_L_DARK]=dark;"
        "baseLayers[ITS_MAP_L_STREETS]=streets;baseLayers[ITS_MAP_L_LIGHT]=light;"
        "baseLayers[ITS_MAP_L_SAT]=sat;"
        /* collapsed:false, because the collapsed control's toggle icon needs
         * Leaflet's images/layers.png. No image assets are vendored for the
         * map, so the icon would be a blank white box until clicked or hovered. */
        /* Vehicle tracks as a switchable overlay, loaded only when actually
         * switched on -- it is a separate request against the SD card, and
         * most visits to the map do not want it. */
        /* ONE shared canvas renderer for all track polylines -- per-line L.canvas()
         * cost megabytes each on retina, and mobile Safari killed the tab. */
        "var trackRenderer=L.canvas();"
        "var trackLayer=L.layerGroup(),tracksLoaded=false;"
        /* The point cap means points are missing, not rounded off. The overlay
         * says so rather than drawing a shortened history that looks complete. */
        "var trackCap=false,trackCapSelf=false,trackCapPeer=false,trackNote=null;"
        "function updateTrackNote(){"
        "if(!trackCap){if(trackNote){trackNote.remove();trackNote=null;}return;}"
        "if(trackNote)return;"
        "trackNote=L.control({position:'bottomleft'});"
        "trackNote.onAdd=function(){var d=L.DomUtil.create('div','tracknote');"
        "d.style.cssText='background:rgba(20,22,24,.85);color:#e0b050;padding:4px 8px;"
        "border-radius:4px;font-size:12px';d.textContent=ITS_MAP_TRACK_CAP;return d;};"
        "trackNote.addTo(map);}"
        /* Separate overlay for peers' tracks, never merged per vehicle -- no
         * timestamps to order points across receivers, and separate lines show the overlap. */
        "var peerTrackLayer=L.layerGroup(),peerTracksLoaded=false;"
        "var overlays={};overlays[ITS_MAP_L_TRACKS]=trackLayer;"
        "if(ITS_MAP_PEERS.length)overlays[ITS_MAP_L_TRACKS_P]=peerTrackLayer;"
        "L.control.layers(baseLayers,overlays,{collapsed:false}).addTo(map);"
        "map.on('overlayadd',function(e){"
        "if(e.layer===trackLayer&&!tracksLoaded)loadTracks();"
        "if(e.layer===peerTrackLayer&&!peerTracksLoaded)loadPeerTracks();});"
        /* Thin and translucent on purpose: where many vehicles took the same
         * road the lines stack up and that road simply gets brighter, which
         * is the "imprint" effect without needing a heat map. */
        /* Deliberately clear of PEER_COLORS and of the traffic-light colours:
         * a local bus and a peer's line must not come out the same green. */
        "function trkColor(y){if(y===6)return '#46d9a0';"
        "if(y===7||y===8||y===9)return '#d98cb0';"
        "if(y===2||y===3||y===4)return '#9aa6ff';"
        "if(y===11)return '#e0b050';"
        "if(y===1)return '#cfd6da';return '#4fb8e0';}"
        /* Numeric station type, so not emojiFor() -- that one keys on the type
         * NAME. Blank for unknown rather than claiming a road-user type. */
        "function trkIcon(y){if(y===6)return '\\ud83d\\ude8c ';"
        "if(y===7||y===8||y===9)return '\\ud83d\\ude9a ';"
        "if(y===2||y===3||y===4)return '\\ud83c\\udfcd ';"
        "if(y===1)return '\\ud83d\\udeb6 ';"
        "if(y===11)return '\\ud83d\\ude8a ';"
        "if(y===5)return '\\ud83d\\ude97 ';return '';}"
        /* A fixed colour means a peer: those stay one colour each and are
         * dashed, so origin and road-user type read on separate channels. */
        "function drawTracks(a,layer,color,who){"
        "for(var i=0;i<a.length;i++){var t=a[i];if(!t.p||t.p.length<2)continue;"
        "var pts=t.p.map(function(q){return [q[0]/1e7,q[1]/1e7];});"
        "var pl=L.polyline(pts,{color:color||trkColor(t.t),weight:2,opacity:0.35,"
        "dashArray:color?'6,5':null,renderer:trackRenderer});"
        "pl.bindPopup(trkIcon(t.t)+'#'+t.i+' \\u00b7 '+pts.length+' '+ITS_MAP_TRACK_PTS"
        "+(t.d!==undefined?' \\u00b7 '+ITS_MAP_TRACK_DUR+' '+t.d+' s':'')"
        "+(who?'<br><small>'+ITS_MAP_SEEN_BY+' '+htxt(who)+'</small>':''));"
        "pl.addTo(layer);}}"
        /* A peer on older firmware answers /tracks.json with a bare array
         * instead of {"t":[...],"c":1}. Without this its tracks would vanish
         * into the catch that also hides an unreachable receiver. */
        "function trkArr(d){return Array.isArray(d)?d:((d&&d.t)||[]);}"
        /* /tracks.json runs on the shared slow worker now, so a busy worker
         * answers 503 text/plain -- without this the layer just stays empty. */
        "function loadTracks(){tracksLoaded=true;"
        "fetch('/tracks.json?days='+ITS_MAP_TRACK_DAYS,{cache:'no-store'})"
        ".then(function(r){if(r.status===503)throw 503;return r.json();}).then(function(d){"
        "trackLayer.clearLayers();drawTracks(trkArr(d),trackLayer,null,ITS_MAP_SELF);"
        "trackCapSelf=!!(d&&d.c);trackCap=trackCapSelf||trackCapPeer;updateTrackNote();"
        "}).catch(function(e){tracksLoaded=false;if(e===503)alert(ITS_MAP_BUSY);});}"
        /* One colour per peer, in the order they are configured, so the same
         * receiver keeps the same colour across reloads. Chosen to stay apart
         * from the local blue and from the amber UI accent. */
        "var PEER_COLORS=['#e07a4f','#7ad07a','#c07ae0','#e0c04f','#4fe0c0'];"
        /* Peers run the same firmware, so they answer 503 too. Reported once
         * per attempt: five peers must not mean five alert boxes. */
        "var peerTrkBusy=false;"
        "function loadPeerTracks(){peerTracksLoaded=true;trackCapPeer=false;peerTrkBusy=false;"
        "peerTrackLayer.clearLayers();"
        "ITS_MAP_PEERS.forEach(function(hp,idx){"
        "fetch('http://'+hp+'/tracks.json?days='+ITS_MAP_TRACK_DAYS,{cache:'no-store'})"
        ".then(function(r){if(r.status===503)throw 503;return r.json();}).then(function(d){"
        "drawTracks(trkArr(d),peerTrackLayer,PEER_COLORS[idx%PEER_COLORS.length],hp);"
        "if(d&&d.c)trackCapPeer=true;trackCap=trackCapSelf||trackCapPeer;updateTrackNote();"
        /* A peer that is off or unreachable is skipped silently, exactly like
         * the live marker poll -- one missing receiver must not cost the
         * others their tracks. */
        "}).catch(function(e){if(e===503&&!peerTrkBusy){peerTrkBusy=true;"
        "peerTracksLoaded=false;alert(ITS_MAP_BUSY);}});});}"
        "var markers={};var VMEM={};var haveView=false;var liveMode=true;"
        "var EMOJI={Ped:'\\ud83d\\udeb6',Cyclist:'\\ud83d\\udeb4',Moped:'\\ud83d\\udef5',"
        "Motorcycle:'\\ud83c\\udfcd',Car:'\\ud83d\\ude97',Bus:'\\ud83d\\ude8c',"
        "LTruck:'\\ud83d\\ude9a',HTruck:'\\ud83d\\ude9b',Trailer:'\\ud83d\\ude9b',"
        "Special:'\\ud83d\\udea7',Tram:'\\ud83d\\ude8a',RSU:'\\ud83d\\udea6'};"
        "function emojiFor(y){for(var k in EMOJI){if(y===k||y.indexOf(k+' ')===0)return EMOJI[k];}return '\\ud83d\\udccd';}"
        /* Heading is a CSS border-triangle needle orbiting the emoji (rotating the
         * glyph reads as a rendering fault; a text arrow never showed on device). */
        "function iconFor(y,hd){var a='';"
        "if(hd!==undefined)a='<span style=\"position:absolute;top:0;left:50%;'"
        "+'width:0;height:0;margin-left:-5px;'"
        "+'border-left:5px solid transparent;border-right:5px solid transparent;'"
        "+'border-bottom:9px solid #f2b134;'"
        "+'transform-origin:50% 20px;transform:rotate('+(hd/10)+'deg);'"
        "+'filter:drop-shadow(0 0 1px rgba(0,0,0,.9))\"></span>';"
        "return L.divIcon({html:'<div style=\"position:relative;width:40px;height:40px;'"
        "+'line-height:40px;text-align:center\">'+a+emojiFor(y)+'</div>',"
        "className:'its-emoji-icon',iconSize:[40,40],iconAnchor:[20,20]});}"
        /* Live traffic-light phases, fetched from /spatem.json, keyed by the
         * RSU stationId -- appended to that marker's popup (see spatChips). */
        "var SPAT={};"
        "function spatColor(p){if(p===5||p===6)return '#2ecc40';"
        "if(p===7||p===8||p===9)return '#f2b134';if(p===2||p===3)return '#e74c3c';"
        "if(p===4)return '#e67e22';return '#888';}"
        /* Escapes text before it goes into a popup's HTML. Popup strings are
         * rendered via innerHTML, and some values interpolated below arrive
         * over the air (MAPEM intersection name) or from configuration
         * (receiver names) -- neither is trustworthy markup. */
        "function htxt(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')"
        ".replace(/>/g,'&gt;').replace(/\"/g,'&quot;');}"
        "function spatChips(i){var d=SPAT[i];if(!d)return '';"
        "var lbl=d.nm?htxt(d.nm):(d.rg+'/'+d.id);"
        "var h='<br>\\ud83d\\udea6 <b>'+lbl+'</b> <small>('+d.age+'s)</small><br>';"
        "for(var j=0;j<d.g.length;j++){"
        "h+='<span style=\"display:inline-block;margin:1px 5px 1px 0;white-space:nowrap\">"
        "<span style=\"display:inline-block;width:11px;height:11px;border-radius:50%;"
        "background:'+spatColor(d.g[j][1])+';vertical-align:middle;margin-right:3px\"></span>'"
        "+(d.g[j][3]?d.g[j][3]+' <small>('+d.g[j][0]+')</small>':d.g[j][0])+(d.g[j][2]>=0?' <small>\\u2265'+d.g[j][2]+'s</small>':'')+'</span>';}return h;}"
        /* Renders the set bits of a BIT STRING as a comma-separated line.
         * Bit 0 is the MSB, hence 1<<(w-1-i). */
        "function bits(v,names,w){if(!v)return '';var o=[];"
        "for(var i=0;i<w;i++)if(v&(1<<(w-1-i)))o.push(names[i]);"
        "return o.length?'<br>'+o.join(', '):'';}"
        "function popupHtml(m){var h='<b>'+(m.y||'?')+'</b><br>'+(m.t||'-')+' &middot; '"
        "+(m.r||'-')+' &middot; '+(m.l||'-')+' B<br>#'+m.i;"
        "if(m.sm&&m.sm!=='-')h+='<br><code>'+htxt(m.sm)+'</code>';"
        "if(m.s!==undefined)h+='<br>'+(m.s*0.036).toFixed(1)+' km/h';"
        "if(m.pl)h+='<br><b>'+ITS_MAP_LINE+' '+m.pl+'</b>';"
        "if(m.pk)h+=' &middot; '+ITS_MAP_KURS+' '+m.pk;"
        "if(m.pz)h+=' &middot; '+ITS_MAP_ZIEL+' '+m.pz;"
        /* pd is the schedule deviation: >0 late, <0 early. Zero is ambiguous
         * (on time OR not transmitted) -- the label says so, see S_MAP_ONTIME. */
        "if(m.pd!==undefined)h+='<br>'+(m.pd>0?m.pd+' '+ITS_MAP_LATE:"
        "(m.pd<0?(-m.pd)+' '+ITS_MAP_EARLY:ITS_MAP_ONTIME));"
        "if(m.vl&&m.vw)h+='<br>'+(m.vl/10).toFixed(1)+' \\u00d7 '+(m.vw/10).toFixed(1)+' m';"
        /* Heading: degrees plus the compass point, since "214 deg" alone
         * means little at a glance. 3600 tenths = full circle. */
        "if(m.hd!==undefined){var deg=m.hd/10;"
        "h+='<br>'+ITS_CAM_DIR+' '+deg.toFixed(0)+'\\u00b0 '"
        "+ITS_CAM_C[Math.round(deg/45)%8];}"
        "if(m.vr&&ITS_CAM_R[m.vr])h+='<br><b>'+ITS_CAM_R[m.vr]+'</b>';"
        "if(m.eb)h+='<br>'+ITS_CAM_EMB;"
        /* Both are bit strings whose bit 0 is the MSB, so bit n of a
         * width-w field is tested with 1<<(w-1-n). */
        "h+=bits(m.ac,ITS_CAM_A,7);h+=bits(m.el,ITS_CAM_L,8);"
        "if(m.d)h+='<br><span style=\"color:#e74c3c\">\\u26a0 '+(m.dt||ITS_MAP_DENM)+'</span>';"
        /* Which receiver picked this up -- only shown when other receivers
         * are configured, since with one device it says nothing. */
        "if(ITS_MAP_PEERS.length&&m.srcs)"
        "h+='<br><small>'+ITS_MAP_SEEN_BY+' '+htxt(m.srcs)+'</small>';"
        "h+=spatChips(m.i);"
        "return h;}"
        /* Removes a marker and, if it has one, its path trail. Every caller
         * must drop both, or the trail stays on the map forever. */
        "function dropMarker(k){if(!markers[k])return;map.removeLayer(markers[k].marker);"
        "if(markers[k].trail)map.removeLayer(markers[k].trail);delete markers[k];}"
        "function apply(arr){var now=Date.now();"
        "for(var i=0;i<arr.length;i++){var m=arr[i];if(m.a===undefined)continue;"
        "var lat=m.a/1e7,lon=m.o/1e7,key=String(m.i);"
        "if(markers[key]){markers[key].marker.setLatLng([lat,lon]);}"
        "else{markers[key]={marker:L.marker([lat,lon],{icon:iconFor(m.y||'',m.hd)}).addTo(map)};"
        "markers[key].hd=m.hd;}"
        /* The icon is built once, so a turning vehicle needs it rebuilt --
         * but only when the heading actually changed, since setIcon replaces
         * the DOM node and would otherwise churn on every message. */
        "if(m.hd!==undefined&&m.hd!==markers[key].hd){"
        "markers[key].marker.setIcon(iconFor(m.y||'',m.hd));markers[key].hd=m.hd;}"
        /* The line number belongs to the vehicle, not to the single message:
         * only ~30% of a bus's CAMs carry the public-transport container, so
         * remember it per station and keep showing it on the later messages
         * that omit it (otherwise it just flickers past). */
        /* Not every CAM carries every field, so keep the last value per station.
         * VMEM is separate from `markers` because a playback seek rebuilds those. */
        "var mem=VMEM[key]||(VMEM[key]={});"
        "['pl','pk','pz','pd','vr','ac','el','hd','vl','vw','dt'].forEach(function(f){"
        "if(m[f]!==undefined)mem[f]=m[f]; else if(mem[f]!==undefined)m[f]=mem[f];});"
        /* Which receivers heard this station, as a timestamped set -- a single field
         * would be overwritten by whichever update landed last. */
        "var who=m.src||ITS_MAP_SELF;"
        "mem.src=mem.src||{};mem.src[who]=now;"
        "var lst=[];for(var w in mem.src){"
        "if(now-mem.src[w]<=ITS_MAP_STALE*1000)lst.push(w);else delete mem.src[w];}"
        "m.srcs=lst.sort().join(', ');"
        /* Where the vehicle has just been, as a faint trail ending at the
         * marker. Replaced rather than appended: each CAM carries the whole
         * (short) history, so accumulating them would draw it many times. */
        "if(m.ph&&m.ph.length){var pts=m.ph.map(function(q){return [q[0]/1e7,q[1]/1e7];});"
        "pts.push([lat,lon]);"
        "if(markers[key].trail)markers[key].trail.setLatLngs(pts);"
        "else markers[key].trail=L.polyline(pts,{color:'#f2b134',weight:2,"
        "opacity:0.55,dashArray:'3,4'}).addTo(map);}"
        "markers[key].marker.bindPopup(popupHtml(m));"
        "markers[key].lastSeen=now;"
        "if(!haveView){map.setView([lat,lon],15);haveView=true;}}}"
        /* ?lat=&lon= (1e-7 degrees) centres on one sender -- the senders page
         * links here, and without it the reader lands on an overview. */
        "(function(){var q=new URLSearchParams(location.search);"
        "var la=parseInt(q.get('lat'),10),lo=parseInt(q.get('lon'),10);"
        "if(la&&lo){map.setView([la/1e7,lo/1e7],17);haveView=true;"
        "L.circle([la/1e7,lo/1e7],{radius:25,color:'#f2b134',weight:2,fill:false}).addTo(map);}})();"
        "apply(window.ITS_MAP_SEED||[]);"
        /* The handle is kept so playback can stop and restart the sweep. The sweep
         * compares against real Date.now(), which means nothing while replaying. */
        "var sweepTimer;"
        /* Drop the marker and its VMEM entry together, so a new pseudonym reusing
         * that station id starts clean. The second loop bounds VMEM's growth. */
        "function startSweep(){sweepTimer=setInterval(function(){var now=Date.now();"
        "for(var k in markers){if(now-markers[k].lastSeen>ITS_MAP_STALE*1000){"
        "dropMarker(k);delete VMEM[k];}}"
        "for(var k in VMEM){if(!markers[k])delete VMEM[k];}},5000);}"
        "startSweep();"
        "var delay=1000,ws,closing=false;"
        "function connect(){"
        "var proto=location.protocol==='https:'?'wss://':'ws://';"
        "ws=new WebSocket(proto+location.host+'/ws');"
        "ws.onmessage=function(ev){if(liveMode)apply(JSON.parse(ev.data));delay=1000;};"
        "ws.onclose=function(){if(closing)return;setTimeout(connect,delay);delay=Math.min(delay*2,30000);};"
        "}"
        "connect();"
        /* Poll traffic-light phases; refreshed into SPAT so the next popup
         * render (each /ws tick rebinds popups) shows current phases. Only in
         * live mode -- historical playback has no phase data. */
        /* Peers merged in the browser; markers keyed by station id, so shared
         * vehicles collapse and range overlap becomes visible. Failures stay silent. */
        /* One request per peer in flight: hung fetches against a dead host pile up
         * when re-fired every two seconds (mobile Safari minds first). */
        "var peerBusy={};"
        "function fetchPeers(){if(!liveMode||!ITS_MAP_PEERS.length)return;"
        "ITS_MAP_PEERS.forEach(function(hp){"
        "if(peerBusy[hp])return;peerBusy[hp]=true;"
        "fetch('http://'+hp+'/markers.json',{cache:'no-store'})"
        ".then(function(r){return r.json();}).then(function(a){"
        "peerBusy[hp]=false;"
        "if(!liveMode)return;"
        "for(var i=0;i<a.length;i++)a[i].src=hp;"
        "apply(a);}).catch(function(){peerBusy[hp]=false;});});}"
        "if(ITS_MAP_PEERS.length){fetchPeers();setInterval(fetchPeers,2000);}"
        "function fetchSpat(){if(!liveMode)return;"
        "fetch('/spatem.json',{cache:'no-store'}).then(function(r){return r.json();})"
        ".then(function(a){var m={};for(var i=0;i<a.length;i++){m[a[i].i]=a[i];"
        "var k=a[i].rg+'/'+a[i].id;PHASE[k]={};MTXT[k]={};"
        "for(var j=0;j<a[i].g.length;j++){PHASE[k][a[i].g[j][0]]=a[i].g[j][1];"
        /* Field 3 is the ready-translated movement text the server already sends. */
        "MTXT[k][a[i].g[j][0]]=a[i].g[j][3];}}"
        "SPAT=m;paintLanes();}).catch(function(){});}"
        "fetchSpat();setInterval(fetchSpat,3000);"
        /* Lane geometry is reloaded every two minutes and recoloured whenever new
         * phases arrive. A lane without a signal group stays neutral grey. */
        /* MTXT shares this var statement with PHASE on purpose: fetchSpat() runs
         * before this line and only its async callback may touch either. */
        "var LANES=[],PHASE={},MTXT={};"
        "function paintLanes(){for(var i=0;i<LANES.length;i++){var o=LANES[i];"
        "var ph=(PHASE[o.k]||{})[o.sg];"
        "o.line.setStyle({color:(o.sg<0?'#7a848c':spatColor(ph)),"
        "weight:(o.t==1?3:4),opacity:(o.sg<0?0.5:0.9),dashArray:(o.t==1?'4,4':null)});"
        /* Movement text arrives with every phase poll, the popup was bound once.
         * Not run through htxt(): it comes from the T() table and carries entities. */
        "var mv=(MTXT[o.k]||{})[o.sg];"
        "if(o.pt){var pc=o.pt+(mv?' \\u00b7 '+mv:'');"
        /* Only on change -- rewriting an open popup every 3s drops a selection. */
        "if(pc!==o.pc){o.pc=pc;o.line.setPopupContent(pc);}}}}"
        "function loadLanes(){fetch('/lanes.json',{cache:'no-store'})"
        ".then(function(r){return r.json();}).then(function(a){"
        "for(var i=0;i<LANES.length;i++)map.removeLayer(LANES[i].line);LANES=[];"
        "for(var i=0;i<a.length;i++){var X=a[i],k=X.rg+'/'+X.id;"
        /* `ln` deliberately not named L -- that is Leaflet's own global. */
        "for(var j=0;j<X.lanes.length;j++){var ln=X.lanes[j];"
        "var pts=ln.p.map(function(p){return [p[0]/1e7,p[1]/1e7];});"
        "var pt='Spur '+ln.l+(ln.sg>=0?' \\u00b7 SG '+ln.sg:'')"
        "+(ln.t==1?' \\u00b7 \\u00dcbergang':'');"
        "var pl=L.polyline(pts,{color:'#7a848c',weight:4,opacity:0.8}).addTo(map);"
        "pl.bindPopup(pt);"
        "LANES.push({line:pl,sg:ln.sg,t:ln.t,k:k,pt:pt});}}"
        "paintLanes();}).catch(function(){});}"
        "loadLanes();setInterval(loadLanes,120000);"
        "window.addEventListener('pagehide',function(){closing=true;if(ws)ws.close();});"
        /* Playback answers {e:[...],p:1?}. Entries carry the /ws feed's i, a, o
         * and y keys, plus t as unix seconds, so apply() can render them. */
        "var pbData=null,pbTimer=null,pbPlaying=false;"
        "function pbSeek(t){t=+t;document.getElementById('pbslider').value=t;"
        "document.getElementById('pbtime').textContent=new Date(t*1000).toLocaleTimeString();"
        "var latest={};"
        "for(var i=0;i<pbData.length;i++){var e=pbData[i];if(e.t>t)break;latest[e.i]=e;}"
        /* Same staleness rule as the live sweep, measured in playback time
         * (t - entry.t) rather than real Date.now(). Without it a station's
         * last position would stay on the map for the rest of the window. */
        "for(var k in latest){if(t-latest[k].t>ITS_MAP_STALE)delete latest[k];}"
        /* Remove markers for stations absent at time t, because apply() only
         * adds and moves markers and never drops the ones it was not given. */
        "for(var k in markers){if(!(k in latest))dropMarker(k);}"
        "apply(Object.keys(latest).map(function(k){return latest[k];}));}"
        /* Busy state: the bar plus a disabled button, so a slow SD read can't
         * be mistaken for a dead page or fired off twice by an impatient
         * second click. Cleared on every exit path, including errors. */
        "function pbBusy(on){document.getElementById('pbbar').style.display=on?'inline-block':'none';"
        "var b=document.getElementById('pbload');b.disabled=on;b.style.opacity=on?0.6:1;"
        "document.getElementById('pbmsg').textContent=on?ITS_PB_BUSY:'';}"
        "function pbLoad(){"
        "var from=Math.floor(new Date(document.getElementById('pbfrom').value).getTime()/1000);"
        "var to=Math.floor(new Date(document.getElementById('pbto').value).getTime()/1000);"
        "var msg=document.getElementById('pbmsg');msg.textContent='';"
        "if(!from||!to||to<=from){msg.textContent=ITS_PB_ERROR;return;}"
        "pbBusy(true);"
        /* Response is {e:[...],p:1?} -- p flags a partly-read period (SD lock
         * contention), shown instead of silently pretending the range is empty. */
        "fetch('/map/playback?from='+from+'&to='+to+'&lang='+(location.search.indexOf('lang=en')>=0?'en':'de')).then(function(r){"
        "if(!r.ok)throw new Error('http '+r.status);return r.json();"
        "}).then(function(data){"
        "pbBusy(false);"
        "pbData=data.e;"
        "if(!pbData.length){msg.textContent=data.p?ITS_PB_PART:ITS_PB_NONE;return;}"
        "if(data.p)msg.textContent=ITS_PB_PART;"
        "liveMode=false;clearInterval(sweepTimer);VMEM={};"
        "for(var k in markers)dropMarker(k);markers={};"
        "var sl=document.getElementById('pbslider');"
        "sl.min=pbData[0].t;sl.max=pbData[pbData.length-1].t;sl.step=pbStep();"
        "document.getElementById('pbctl').style.display='';"
        /* Reframe on the loaded window itself. apply() auto-zooms only on the
         * very first fix it ever sees (haveView), live or seed. */
        "map.fitBounds(L.latLngBounds(pbData.map(function(e){return [e.a/1e7,e.o/1e7];})),"
        "{padding:[30,30],maxZoom:16});"
        "haveView=true;"
        /* Start at the beginning, so Play still has something to play. */
        "pbSeek(sl.min);"
        "}).catch(function(){pbBusy(false);msg.textContent=ITS_PB_ERROR;});}"
        /* One setting for both the slider's granularity and how far a play
         * tick advances -- so it reads as "seconds per step" and doubles as
         * the replay speed (10 = ten times real time). */
        "function pbStep(){return +document.getElementById('pbstep').value||10;}"
        "function pbToggle(){pbPlaying=!pbPlaying;"
        "document.getElementById('pbplay').innerHTML=pbPlaying?'&#9208;':'&#9654;';"
        "if(pbPlaying){var sl=document.getElementById('pbslider');"
        "pbTimer=setInterval(function(){var t=+sl.value+pbStep();"
        "if(t>=+sl.max){t=+sl.max;pbPlaying=false;"
        "document.getElementById('pbplay').innerHTML='&#9654;';clearInterval(pbTimer);}"
        "pbSeek(t);},1000);}else{clearInterval(pbTimer);}}"
        "function pbLive(){liveMode=true;pbPlaying=false;clearInterval(pbTimer);VMEM={};"
        "document.getElementById('pbplay').innerHTML='&#9654;';"
        "document.getElementById('pbctl').style.display='none';"
        "for(var k in markers)dropMarker(k);markers={};"
        "apply(window.ITS_MAP_SEED||[]);startSweep();}"
        /* Wired here, not inline onclick= -- inline handlers run in global scope and
         * can't see functions private to this IIFE. */
        "document.getElementById('pbload').onclick=pbLoad;"
        "document.getElementById('pbplay').onclick=pbToggle;"
        "document.getElementById('pbslider').oninput=function(){pbSeek(this.value);};"
        /* Changing the step retunes the slider itself, so dragging snaps to
         * the same granularity the play button advances by. */
        "document.getElementById('pbstep').onchange=function(){"
        "document.getElementById('pbslider').step=pbStep();};"
        "document.getElementById('pblive').onclick=pbLive;"
        /* Default to the last hour. Built from getFullYear() and the other local
         * getters because datetime-local needs local time, not UTC. */
        "(function(){function p(n){return (n<10?'0':'')+n;}"
        "function fmt(d){return d.getFullYear()+'-'+p(d.getMonth()+1)+'-'+p(d.getDate())"
        "+'T'+p(d.getHours())+':'+p(d.getMinutes());}"
        "var now=new Date();"
        "document.getElementById('pbto').value=fmt(now);"
        "document.getElementById('pbfrom').value=fmt(new Date(now.getTime()-3600000));})();"
        "})();</script>";
    httpd_resp_send_chunk(req, MAP_SCRIPT, HTTPD_RESP_USE_STRLEN);
#endif

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* GET /spatem.json -- current traffic-light phases, keyed by the RSU's
 * stationId so /map can enrich that marker's popup. RAM-only (no SD needed),
 * so it lives outside the SD guard below. Shape:
 * [{"i":stationId,"rg":region,"id":id,"rev":n,"age":secs,"nm":"name",
 *   "g":[[sg,phase,secsLeft,"movement text"],...]}] */
/* spat_movement_text() below comes from web_traffic.c. */

static esp_err_t spatem_json_handler(httpd_req_t *req)
{
    static spatem_intersection_t ints[SPATEM_MAX_INT];
    int ni = spatem_snapshot(ints, SPATEM_MAX_INT);
    uint32_t now = (uint32_t)time(NULL);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, "[", HTTPD_RESP_USE_STRLEN);
    for (int i = 0; i < ni; i++)
    {
        spatem_intersection_t *e = &ints[i];
        /* phase_seen, not last_seen: this number sits beside the phase dots and
         * must say how old THEY are, not when a MAPEM last arrived. An entry
         * seeded by a MAPEM alone has no phases yet (phase_seen 0 = never) --
         * fall back to last_seen, else its age froze at 0 = "just now". */
        uint32_t seen = e->phase_seen ? e->phase_seen : e->last_seen;
        unsigned long age = (seen && now > seen) ? (unsigned long)(now - seen) : 0;
        /* The name comes off the air unauthenticated and the popup renders markup, so
         * strip quotes AND angle brackets here; the client escapes again (htxt) -- both on purpose. */
        char nm[ITS_MAP_NAME_LEN];
        size_t nw = 0;
        for (size_t k = 0; e->name[k] && nw + 1 < sizeof(nm); k++)
        {
            char c = e->name[k];
            if (c != '"' && c != '\\' && c != '<' && c != '>' && c != '&')
                nm[nw++] = c;
        }
        nm[nw] = '\0';

        char head[ITS_MAP_NAME_LEN + 160];
        snprintf(head, sizeof(head),
            "%s{\"i\":%lu,\"rg\":%u,\"id\":%u,\"rev\":%u,\"age\":%lu,\"nm\":\"%s\",\"g\":[",
            i ? "," : "", (unsigned long)e->station_id, (unsigned)e->region,
            (unsigned)e->id, (unsigned)e->revision, age, nm);
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);
        for (int s = 0; s < e->n; s++)
        {
            /* [signalGroup, phase, secondsUntilChange, movement text]. A -1 means
             * no timing. The seconds come from minEndTime, the EARLIEST the phase
             * may end, so every renderer must show them as a lower bound. */
            long left = -1;
            if (e->change_at[s] > now && e->change_at[s] - now <= 600)
                left = (long)(e->change_at[s] - now);
            char mv[64];
            spat_movement_text(e, e->sg[s], mv, sizeof(mv));
            char pair[128];
            snprintf(pair, sizeof(pair), "%s[%u,%u,%ld,\"%s\"]", s ? "," : "",
                     (unsigned)e->sg[s], (unsigned)e->phase[s], left, mv);
            httpd_resp_send_chunk(req, pair, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "]}", HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "]", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* GET /lanes.json -- cached MAPEM lane geometry, for drawing intersections.
 * /map reloads it every two minutes and recolours it from the phases in
 * /spatem.json. Shape:
 * [{"rg":N,"id":N,"lanes":[{"l":11,"t":0,"sg":1,"p":[[lat,lon],..]}]}] */
static esp_err_t lanes_json_handler(httpd_req_t *req)
{
    static spatem_intersection_t ints[SPATEM_MAX_INT];
    int ni = spatem_snapshot(ints, SPATEM_MAX_INT);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, "[", HTTPD_RESP_USE_STRLEN);
    bool first = true;
    /* One intersection at a time, copied under the lock and sent outside it.
     * Holding it across the chunked send would let a stalled browser block the
     * packet path, which takes this same lock (50 ms timeout) while holding
     * msg_ring_mutex. */
    static EXT_RAM_BSS_ATTR its_map_geom_t geombuf;
    for (int i = 0; i < ni; i++)
    {
        spatem_geometry_lock();
        const its_map_geom_t *src = spatem_geometry(ints[i].region, ints[i].id);
        bool have = src != NULL;
        if (have)
            memcpy(&geombuf, src, sizeof(geombuf));
        spatem_geometry_unlock();
        if (!have)
            continue;
        const its_map_geom_t *g = &geombuf;
        char head[64];
        snprintf(head, sizeof(head), "%s{\"rg\":%u,\"id\":%u,\"lanes\":[",
                 first ? "" : ",", (unsigned)g->region, (unsigned)g->id);
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);
        first = false;

        /* Separator keys off what was actually emitted -- a skipped lane 0 would
         * emit a leading comma: malformed JSON that silently kills the whole overlay. */
        bool first_lane = true;
        for (uint8_t l = 0; l < g->n_lanes; l++)
        {
            const its_lane_geom_t *L = &g->lane[l];
            if (L->n_nodes < 2)
                continue;                 /* nothing to draw */
            char lh[64];
            snprintf(lh, sizeof(lh), "%s{\"l\":%u,\"t\":%u,\"sg\":%d,\"p\":[",
                     first_lane ? "" : ",", (unsigned)L->lane_id, (unsigned)L->lane_type,
                     L->signal_group == 0xFF ? -1 : (int)L->signal_group);
            first_lane = false;
            httpd_resp_send_chunk(req, lh, HTTPD_RESP_USE_STRLEN);
            for (uint8_t n = 0; n < L->n_nodes; n++)
            {
                char pt[48];
                snprintf(pt, sizeof(pt), "%s[%ld,%ld]", n ? "," : "",
                         (long)L->lat_e7[n], (long)L->lon_e7[n]);
                httpd_resp_send_chunk(req, pt, HTTPD_RESP_USE_STRLEN);
            }
            httpd_resp_send_chunk(req, "]}", HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "]}", HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "]", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  GET /map/playback -- historical positions from stored PCAP files  */
/* ================================================================== */

#if CONFIG_ENABLE_SD
/* An RSU repeats an unchanged position ~10x/s; re-emit only on movement (plus
 * an occasional keep-alive) or playback JSON runs to megabytes. */
#define PB_MAX_STATIONS  96   /* distinct senders tracked; beyond that, no dedup */
#define PB_BUF_CAP  (256 * 1024)  /* PSRAM collect buffer; larger windows resume in segments */
#define PB_ENTRY_MAX 576      /* worst-case JSON entry; reserved up front in playback_emit */
#define PB_MIN_GAP_SEC    1   /* fastest re-emit for a station that IS moving */
#define PB_KEEPALIVE_SEC 30   /* re-emit an unmoved station this often */

typedef struct {
    uint32_t station_id, last_sec;
    int32_t  lat_e7, lon_e7;
} pb_seen_t;

typedef struct {
    httpd_req_t *req;
    bool first;
    /* Set once a chunk write fails, i.e. the browser is gone. Without it the
     * walk keeps decoding whole hours of PCAP into a dead socket. */
    bool client_gone;
    /* Entries collect here, sent only with the SD writer lock RELEASED; a
     * full buffer stops the walk, the handler resumes at resume_sec. */
    char *buf;              /* PSRAM, allocated by the handler */
    size_t cap, len;
    bool full;
    uint32_t resume_sec;
    pb_seen_t seen[PB_MAX_STATIONS];
    int n_seen;
    uint32_t emitted, skipped;
} playback_ctx_t;

static void playback_flush(playback_ctx_t *ctx)
{
    if (ctx->len && !ctx->client_gone)
    {
        if (httpd_resp_send_chunk(ctx->req, ctx->buf, ctx->len) != ESP_OK)
            ctx->client_gone = true;
    }
    ctx->len = 0;
}

/* True when this frame adds something the replay actually needs. */
static bool playback_want(playback_ctx_t *ctx, uint32_t sec, const its_decoded_t *d)
{
    pb_seen_t *s = NULL;
    for (int i = 0; i < ctx->n_seen; i++)
        if (ctx->seen[i].station_id == d->station_id)
        {
            s = &ctx->seen[i];
            break;
        }

    if (!s)
    {
        if (ctx->n_seen >= PB_MAX_STATIONS)
            return true;   /* table full: stop deduplicating rather than drop */
        s = &ctx->seen[ctx->n_seen++];
        s->station_id = d->station_id;
        s->last_sec = sec;
        s->lat_e7 = d->lat_e7;
        s->lon_e7 = d->lon_e7;
        return true;
    }

    bool moved = (s->lat_e7 != d->lat_e7 || s->lon_e7 != d->lon_e7);
    uint32_t age = sec > s->last_sec ? sec - s->last_sec : 0;
    if (!(moved ? age >= PB_MIN_GAP_SEC : age >= PB_KEEPALIVE_SEC))
        return false;

    s->last_sec = sec;
    s->lat_e7 = d->lat_e7;
    s->lon_e7 = d->lon_e7;
    return true;
}

/* msgtype/label only ever contains digits/letters/spaces/':'/'-'/'.' (see
 * its_decode_frame), same as everywhere else it's embedded in JSON in this
 * file -- no attacker-controlled bytes, no escaping needed. */
static bool playback_emit(uint32_t sec, uint32_t usec, const its_decoded_t *d, void *ctx_)
{
    (void)usec;
    playback_ctx_t *ctx = (playback_ctx_t *)ctx_;

    if (ctx->client_gone)
        return false;

    /* Reserve space BEFORE playback_want commits to the seen table -- a
     * committed-then-dropped frame would be lost as a duplicate on resume. */
    if (ctx->len + PB_ENTRY_MAX >= ctx->cap)
    {
        ctx->full = true;
        ctx->resume_sec = sec;
        return false;
    }

    /* A DENM is an event, not a position sample -- never suppress one. */
    if (d->message_id != 1 && !playback_want(ctx, sec, d))
    {
        ctx->skipped++;
        return true;
    }

    /* Same optional keys as the live /ws feed, so the map's popupHtml renders
     * a replayed marker exactly like a live one. */
    /* MUST be initialised: frames without these optional keys (every RSU) would
     * otherwise print uninitialised stack bytes into the JSON. */
    char extra[320] = "";
    size_t eo = 0;
    if (d->has_speed && d->speed_cmps != -1)   /* -1 = not available */
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"s\":%ld", (long)d->speed_cmps);
    if (d->veh.valid && d->veh.length_dm && d->veh.width_dm && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"vl\":%u,\"vw\":%u",
                       (unsigned)d->veh.length_dm, (unsigned)d->veh.width_dm);
    if (d->has_src_mac && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo,
                       ",\"sm\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",
                       d->src_mac[0], d->src_mac[1], d->src_mac[2],
                       d->src_mac[3], d->src_mac[4], d->src_mac[5]);
    if (d->pt_line && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"pl\":%u", (unsigned)d->pt_line);
    if (d->pt_telegram && d->pt_course && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"pk\":%u", (unsigned)d->pt_course);
    if (d->pt_telegram && d->pt_dest && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"pz\":%u", (unsigned)d->pt_dest);
    if (d->pt_telegram && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"pd\":%d", (int)d->pt_deviation);
    /* Same CAM detail the live feed sends -- replayed markers should look
     * exactly like live ones (this was forgotten once already for the line
     * number and vehicle size, and the replay silently lost them). */
    if (d->cam.has_heading && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"hd\":%u",
                       (unsigned)d->cam.heading_ddeg);
    if (d->cam.has_accel_ctrl && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"ac\":%u",
                       (unsigned)d->cam.accel_ctrl);
    if (d->cam.has_lights && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"el\":%u",
                       (unsigned)d->cam.ext_lights);
    if (d->cam.role != 0xFF && d->cam.role != 0 && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"vr\":%u",
                       (unsigned)d->cam.role);
    if (d->pt_embarking && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"eb\":1");
    /* Live mode flags a station that warned recently. In playback the frame
     * being replayed IS the warning, so flag that one. */
    if (d->message_id == 1 && eo < sizeof(extra))
    {
        const char *ct = denm_cause_text(d->denm_cause);
        const char *st = denm_sub_text(d->denm_cause, d->denm_subcause);
        if (ct && st)
            snprintf(extra + eo, sizeof(extra) - eo, ",\"d\":1,\"dt\":\"%s (%s)\"", ct, st);
        else if (ct)
            snprintf(extra + eo, sizeof(extra) - eo, ",\"d\":1,\"dt\":\"%s\"", ct);
        else
            snprintf(extra + eo, sizeof(extra) - eo, ",\"d\":1");
    }

    char entry[576];
    int n = snprintf(entry, sizeof(entry),
             "%s{\"t\":%lu,\"i\":%lu,\"a\":%ld,\"o\":%ld,\"y\":\"%s\"%s}",
             ctx->first ? "" : ",", (unsigned long)sec, (unsigned long)d->station_id,
             (long)d->lat_e7, (long)d->lon_e7, d->label, extra);
    if (n < 0)
        return true;
    if (ctx->len + (size_t)n >= ctx->cap)
    {
        /* Nothing may be sent while the SD writer lock is held, so stop the
         * walk. The handler flushes lock-free and resumes from this second. */
        ctx->full = true;
        ctx->resume_sec = sec;
        return false;
    }
    memcpy(ctx->buf + ctx->len, entry, (size_t)n);
    ctx->len += (size_t)n;
    ctx->first = false;
    ctx->emitted++;
    return true;
}

/* ================================================================== */
/*  The map's data: /markers.json, /tracks.json, /map/playback.       */
/*  (GET /traffic moved to web_traffic.c.)                            */
/* ================================================================== */

/* GET /tracks.json?days=N -- vehicle tracks for the map overlay, grouped by
 * station and split into a fresh polyline after a long gap. Points come from
 * the small running log, NOT from the PCAP archive: see tracklog.h for why. */
/* The same array the live feed pushes, as a plain request so another receiver's
 * map can merge it -- deliberately read by the browser, not polled device-to-device. */
static esp_err_t markers_json_handler(httpd_req_t *req)
{
    static EXT_RAM_BSS_ATTR char json[6144];
    size_t len = build_msg_json(json, sizeof(json));
    httpd_resp_set_type(req, "application/json");
    /* The page doing the reading is served by a different receiver, so the
     * browser needs this to permit the cross-origin read. What it exposes is
     * the same read-only telemetry the map already shows, and no credential
     * is involved -- the endpoint neither reads nor sets anything. */
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_send(req, json, len);
}

/* A vehicle standing still emits no point at all (tracklog's TR_MIN_MOVE_E7),
 * so this has to sit above a signal stop, not near the 2 s sampling floor. */
#define TRK_SPLIT_SEC 600

static esp_err_t tracks_get_handler(httpd_req_t *req)
{
    uint32_t days = 2;
    char query[48];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char val[8];
        if (httpd_query_key_value(query, "days", val, sizeof(val)) == ESP_OK)
        {
            long d = strtol(val, NULL, 10);
            if (d >= 1 && d <= 7) days = (uint32_t)d;
        }
    }

    /* Sized for MAX retention (~25k points), not typical: a smaller cap makes
     * the read drop the oldest points of the window. Transient 520 KB PSRAM. */
    const int MAXPT = 26000;
    track_pt_t *pts = heap_caps_malloc(sizeof(track_pt_t) * MAXPT, MALLOC_CAP_SPIRAM);
    if (!pts)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
        return ESP_FAIL;
    }
    bool tracks_wrapped = false;
    int n = tracklog_read(days, pts, MAXPT, &tracks_wrapped);
    /* Only a real wrap loses points, and it drops the oldest of the window.
     * Exactly MAXPT rows fit without loss. The reply carries the flag so the
     * overlay can warn instead of drawing a short day that looks complete. */
    bool capped = tracks_wrapped;

    httpd_resp_set_type(req, "application/json");
    /* Same reasoning as /markers.json: another receiver's map page reads this
     * cross-origin to draw all receivers' tracks on one map. Read-only, no
     * credential involved. */
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    /* {"t":[tracks],"c":1} -- "c" marks a reply that lost points. All
     * receivers on a map are expected to run the same firmware, so this reads
     * the same shape from a peer as from itself. */
    httpd_resp_send_chunk(req, "{\"t\":[", HTTPD_RESP_USE_STRLEN);

    /* The log is in time order, so a station's points are scattered through it.
     * Walk it once per station rather than sorting 26,000 records in place.
     * Station counts are small (tens), so peak memory stays at the one array. */
    bool first_track = true;
    bool client_gone = false;
    for (int i = 0; i < n && !client_gone; i++)
    {
        if (pts[i].station_id == 0)
            continue;                      /* already consumed */
        uint32_t sid = pts[i].station_id;
        /* No second point inside the gap means a lone sighting: consume it
         * and emit nothing, because the map skips p.length<2 anyway. */
        bool pair = false;
        for (int j = i + 1; j < n; j++)
        {
            bool past = pts[j].seconds > pts[i].seconds &&
                        pts[j].seconds - pts[i].seconds > TRK_SPLIT_SEC;
            if (pts[j].station_id == sid) { pair = !past; break; }
            if (past) break;               /* time-ordered: none can follow */
        }
        if (!pair)
        {
            pts[i].station_id = 0;
            continue;
        }
        char head[64];
        snprintf(head, sizeof(head), "%s{\"i\":%lu,\"t\":%u,\"p\":[",
                 first_track ? "" : ",", (unsigned long)sid,
                 (unsigned)pts[i].station_type);
        /* A failed chunk send means the browser hung up (tab closed, phone
         * locked). Without this check the handler would format and "send" all
         * 26,000 points into a dead socket. */
        if (httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN) != ESP_OK)
        {
            client_gone = true;
            break;
        }
        first_track = false;

        char buf[1024];
        size_t bl = 0;
        bool first_pt = true;
        uint32_t first_sec = pts[i].seconds, last_sec = first_sec;
        for (int j = i; j < n && !client_gone; j++)
        {
            if (pts[j].station_id != sid)
                continue;
            /* Leave the rest to the outer loop, which picks the station up
             * again and makes a second trip of it. */
            if (!first_pt && pts[j].seconds > last_sec &&
                pts[j].seconds - last_sec > TRK_SPLIT_SEC)
                break;
            int k = snprintf(buf + bl, sizeof(buf) - bl, "%s[%ld,%ld]",
                             first_pt ? "" : ",",
                             (long)pts[j].lat_e7, (long)pts[j].lon_e7);
            if (k < 0) break;
            if (bl + (size_t)k >= sizeof(buf) - 32)
            {
                if (httpd_resp_send_chunk(req, buf, bl) != ESP_OK)
                {
                    client_gone = true;
                    break;
                }
                bl = 0;
                k = snprintf(buf, sizeof(buf), "%s[%ld,%ld]",
                             first_pt ? "" : ",",
                             (long)pts[j].lat_e7, (long)pts[j].lon_e7);
            }
            bl += (size_t)k;
            first_pt = false;
            if (pts[j].seconds > last_sec) last_sec = pts[j].seconds;
            pts[j].station_id = 0;         /* consumed */
        }
        if (bl && httpd_resp_send_chunk(req, buf, bl) != ESP_OK)
            client_gone = true;
        /* "d" at the END of the object, so the point stream stays untouched
         * and a peer on older firmware simply ignores the extra key. */
        char tail[32];
        snprintf(tail, sizeof(tail), "],\"d\":%lu}",
                 (unsigned long)(last_sec - first_sec));
        if (!client_gone &&
            httpd_resp_send_chunk(req, tail, HTTPD_RESP_USE_STRLEN) != ESP_OK)
            client_gone = true;
    }

    if (!client_gone)
    {
        httpd_resp_send_chunk(req, capped ? "],\"c\":1}" : "]}", HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, NULL, 0);
    }
    heap_caps_free(pts);
    return client_gone ? ESP_FAIL : ESP_OK;
}

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

static esp_err_t playback_get_handler(httpd_req_t *req)
{
    /* Runs on the worker: without this, DENM cause texts ("dt") rendered in
     * whatever language the last /messages/search left in lang_worker. */
    resolve_language(req);

    /* Explicit from/to in unix seconds, not "last N minutes from now": with a
     * retention of a day or more, any stored window must stay reachable. */
    time_t now = time(NULL);
    long from = (long)now - 3600, to = (long)now;
    char query[64];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char val[16];
        if (httpd_query_key_value(query, "from", val, sizeof(val)) == ESP_OK)
            from = strtol(val, NULL, 10);
        if (httpd_query_key_value(query, "to", val, sizeof(val)) == ESP_OK)
            to = strtol(val, NULL, 10);
    }
    if (to > (long)now) to = (long)now;  /* can't play back the future */
    if (from < 0)       from = 0;
    if (to <= from)      to = from + 60;
    if (to - from > 240L * 60)  /* bound how many hourly files one request walks */
        to = from + 240L * 60;

    uint32_t from_sec = (uint32_t)from;
    uint32_t to_sec = (uint32_t)to;

    /* Without this an unmounted card yields an empty array, which the page
     * shows as "no data in this range" -- same look as a genuinely empty one. */
    if (!sdcard_is_mounted())
    {
        /* The httpd error enum has no 503, so 500 it is. What matters is that
         * the page sees an error instead of an empty array. */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "SD card not mounted");
        return ESP_FAIL;
    }

    char *pbuf = heap_caps_malloc(PB_BUF_CAP, MALLOC_CAP_SPIRAM);
    if (!pbuf)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, "{\"e\":[", HTTPD_RESP_USE_STRLEN);
    /* ~1.6 KB struct on the worker stack. Not static, so an inline-served
     * request cannot corrupt a deferred one's state. */
    playback_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.req = req;
    ctx.first = true;
    ctx.buf = pbuf;
    ctx.cap = PB_BUF_CAP;

    /* The newest minutes are still in the ring, not in the files. That only
     * matters for a window that runs up to "now", see pcap_window_on_card(). */
    bool flushed = pcap_window_on_card(to_sec);
    bool partial = !flushed;   /* unflushed frames are missing from the window */
    uint32_t cursor = from_sec;
    uint32_t last_full_sec = 0;
    bool have_full_sec = false;
    for (;;)
    {
        ctx.full = false;
        bool complete = sdpcap_read_positions(cursor, to_sec, playback_emit, &ctx);
        playback_flush(&ctx);            /* walk done -- SD lock released, safe to send */
        if (ctx.client_gone)
            break;
        if (!complete)
        {
            partial = true;              /* lock timeout or card gone -- reported as "p" */
            break;
        }
        if (!ctx.full)
            break;
        /* Forward-progress guard: a pathological second could pin resume_sec
         * forever and wedge the worker. Skip a repeated one and flag partial. */
        if (have_full_sec && ctx.resume_sec == last_full_sec)
        {
            partial = true;
            if (ctx.resume_sec >= to_sec)
                break;
            cursor = ctx.resume_sec + 1;
            have_full_sec = false;
            continue;
        }
        last_full_sec = ctx.resume_sec;
        have_full_sec = true;
        cursor = ctx.resume_sec;         /* buffer filled at this second -- continue there */
    }
    heap_caps_free(pbuf);
    ESP_LOGI(TAG, "playback %lu..%lu: %lu entries, %lu duplicates dropped%s%s",
             (unsigned long)from_sec, (unsigned long)to_sec,
             (unsigned long)ctx.emitted, (unsigned long)ctx.skipped,
             partial ? " (partial)" : "",
             ctx.client_gone ? " (client gone, aborted)" : "");
    if (ctx.client_gone)
        return ESP_FAIL;   /* socket is dead; closing the chunked reply would only error again */
    httpd_resp_send_chunk(req, partial ? "],\"p\":1}" : "]}", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}
#endif

/* ==================================================================
 *  GET /senders -- stationary senders (RSU/traffic light), kept across
 *  restarts. Pure RAM, no SD access, so it runs on the httpd task.
 * ================================================================== */

static const char *inv_msg_name(uint8_t bit)
{
    switch (bit)
    {
    case 1:  return "DENM";
    case 2:  return "CAM";
    case 4:  return "SPATEM";
    case 5:  return "MAPEM";
    case 6:  return "IVIM";
    case 9:  return "SREM";
    case 10: return "SSEM";
    case 13: return "RTCMEM";
    default: return NULL;
    }
}

static esp_err_t senders_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    send_page_header(req, T(S_TITLE_SENDERS));

    /* Opens the page's one group; the reset button below closes it. */
    char intro[512];
    HTML_PRINTF(intro, "<div class='grp top'><p class='note'>%s</p>", T(S_SND_INTRO));
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);

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
            "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
            "</tr></thead><tbody>",
            T(S_SND_STATION), T(S_SND_TYPES), T(S_SND_FRAMES),
            T(S_SND_RSSI), T(S_SND_POS), T(S_SND_LAST));
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

        uint32_t now = (uint32_t)time(NULL);
        for (int i = 0; i < n; i++)
        {
            inv_station_t *s = &snap[i];

            char types[288] = "";
            size_t to = 0;
            for (uint8_t b = 0; b < 16 && to + 64 < sizeof(types); b++)
                if (s->msg_mask & (1u << b))
                {
                    const char *nm = inv_msg_name(b);
                    if (!nm) continue;
#if CONFIG_ENABLE_SD
                    /* hours=720 because the 24 h default hides all but the
                     * newest few. Only under SD -- else /traffic is not built. */
                    const char *anchor = strcmp(nm, "DENM") == 0 ? "denm" :
                        (strcmp(nm, "SPATEM") == 0 || strcmp(nm, "MAPEM") == 0) ? "lights" : NULL;
                    if (anchor)
                    {
                        to += snprintf(types + to, sizeof(types) - to,
                                       "%s<a href='/traffic?hours=720&amp;lang=%s#%s'>%s</a>",
                                       to ? " " : "", current_lang == LANG_EN ? "en" : "de",
                                       anchor, nm);
                        continue;
                    }
#endif
                    to += snprintf(types + to, sizeof(types) - to, "%s%s", to ? " " : "", nm);
                }

            char nameesc[INV_NAME_LEN * 6];
            html_escape(s->name, nameesc, sizeof(nameesc));

            /* Signal range plus average: one bad reflection or one close pass
             * says little, the spread over thousands of frames says a lot. */
            char sig[64] = "-";
            if (s->rssi_cnt)
                snprintf(sig, sizeof(sig), "%d&hellip;%d <small>(&oslash;%ld)</small>",
                         s->rssi_min, s->rssi_max,
                         (long)(s->rssi_sum / (int64_t)s->rssi_cnt));

            /* Deep link: the map centres on the sender instead of dropping the
             * reader on an overview to hunt for it. */
            char pos[96] = "-";
            if (s->has_pos)
                snprintf(pos, sizeof(pos),
                         "<a href='/map?lang=%s&amp;lat=%ld&amp;lon=%ld'>%.5f, %.5f</a>",
                         current_lang == LANG_EN ? "en" : "de",
                         (long)s->lat_e7, (long)s->lon_e7,
                         s->lat_e7 / 1e7, s->lon_e7 / 1e7);

            char first[32], last[32];
            struct tm lt;
            time_t t1 = (time_t)s->first_seen;
            localtime_r(&t1, &lt);
            strftime(first, sizeof(first), "%d.%m. %H:%M", &lt);
            /* Recent activity is what the reader looks for, so show an age
             * rather than a second clock time. */
            uint32_t age = now > s->last_seen ? now - s->last_seen : 0;
            if (age < 60)        snprintf(last, sizeof(last), "%lus", (unsigned long)age);
            else if (age < 3600) snprintf(last, sizeof(last), "%lum", (unsigned long)(age / 60));
            else                 snprintf(last, sizeof(last), "%luh", (unsigned long)(age / 3600));

            /* Vendor prefix tells sibling units apart at a glance; vehicles use
             * locally administered (random) addresses, roadside units do not. */
            char mac[20] = "-";
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

            char row[1152];
            HTML_PRINTF(row,
                "<tr><td class='wrapcell'>%s<div class='sub mono'>%s</div></td>"
                "<td>%s</td><td>%lu</td>"
                "<td class='mono'>%s</td><td class='mono'>%s</td>"
                "<td>%s<div class='sub'>%s</div></td></tr>",
                ident, idmac,
                types[0] ? types : "-", (unsigned long)s->frames, sig, pos,
                last, firstline);
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
    }

    if (inventory_overflow())
    {
        char full[256];
        HTML_PRINTF(full, "<p class='note'>&#9888; %s</p>", T(S_SND_FULL));
        httpd_resp_send_chunk(req, full, HTTPD_RESP_USE_STRLEN);
    }

    char veh[384];
    char vtext[288];
    snprintf(vtext, sizeof(vtext), T(S_SND_VEHICLES),
             (unsigned long)inventory_vehicle_frames());
    HTML_PRINTF(veh, "<p class='note'>%s</p>", vtext);
    httpd_resp_send_chunk(req, veh, HTTPD_RESP_USE_STRLEN);

    char clr[512];
    HTML_PRINTF(clr,
        /* r.ok: this page is ungated but the POST is not -- reloading after a
         * 401 would show the untouched list as if the reset had happened. */
        "<p class='btnrow'><button class='dngr' onclick=\"if(confirm('%s'))fetch('/senders/clear',"
        "{method:'POST'}).then(function(r){if(r.ok)location.reload();});\">%s</button></p></div>",
        T(S_SND_CLEAR_CONFIRM), T(S_SND_CLEAR));
    httpd_resp_send_chunk(req, clr, HTTPD_RESP_USE_STRLEN);

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
typedef struct {
    uint16_t line;
    uint32_t prev_sec;              /* last passage folded in, 0 = none yet */
    uint32_t n, ngap;
    uint32_t first_sod, last_sod;   /* seconds into the operating day */
    uint16_t dest[PT_DEST_SLOTS];
    uint32_t dcnt[PT_DEST_SLOTS];
} pt_ops_t;
#endif

static esp_err_t transit_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    send_page_header(req, T(S_TITLE_TRANSIT));

    /* Opens the first group; the passage block below swaps it for its own,
     * and one unconditional </div> further down closes whichever is open. */
    char intro[640];
    HTML_PRINTF(intro, "<div class='grp top'><p class='note'>%s</p>", T(S_PT_INTRO));
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR pt_line_t snap[PT_MAX_LINES];
    int n = ptlog_snapshot(snap);

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
        for (int d = 0; d < PT_DEST_SLOTS; d++)
        {
            if (o->dcnt[d] && o->dest[d] != pass[k].dest) continue;
            o->dest[d] = pass[k].dest;
            o->dcnt[d]++;
            break;
        }
    }

    /* The only link worth having here: the passage table is 20 k of markup
     * below, and it is not emitted at all when nothing was stored. */
    if (pn > 0)
    {
        char ptjump[192];
        HTML_PRINTF(ptjump, "<p class='jump'>%s: <a href='#pt-pass'>%s</a></p>",
                    T(S_TRF_JUMP), T(S_PT_PASSAGES));
        httpd_resp_send_chunk(req, ptjump, HTTPD_RESP_USE_STRLEN);
    }
#endif

    if (n == 0)
    {
        char none[192];
        HTML_PRINTF(none, "<p class='note'>%s</p>", T(S_PT_NONE));
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        char head[512];
        HTML_PRINTF(head,
            "<div class='scroll'><table><thead><tr><th>%s</th><th>%s</th><th>%s</th>"
            "<th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
            T(S_PT_LINE), T(S_PT_SIGHTINGS), T(S_PT_AVG), T(S_PT_LATE),
            T(S_PT_EARLY), T(S_PT_UNKNOWN), T(S_PT_LAST));
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

        uint32_t now = (uint32_t)time(NULL);
        bool any_ops = false;
        for (int i = 0; i < n; i++)
        {
            pt_line_t *l = &snap[i];

            char avg[24] = "-";
            if (l->dev_count)
            {
                /* One decimal: the source values are whole minutes, so more
                 * would only pretend precision the format never carried. */
                double a = (double)l->dev_sum / (double)l->dev_count;
                snprintf(avg, sizeof(avg), "%+.1f min", a);
            }
            char late[24] = "-", early[24] = "-";
            if (l->worst_late > 0)
                snprintf(late, sizeof(late), "%s%d min",
                         l->worst_late >= 7 ? "&ge;" : "", l->worst_late);
            if (l->worst_early < 0)
                snprintf(early, sizeof(early), "%s%d min",
                         l->worst_early <= -7 ? "&ge;" : "", -l->worst_early);

            char last[24];
            uint32_t age = now > l->last_seen ? now - l->last_seen : 0;
            if (age < 3600)       snprintf(last, sizeof(last), "%lum", (unsigned long)(age / 60));
            else if (age < 86400) snprintf(last, sizeof(last), "%luh", (unsigned long)(age / 3600));
            else                  snprintf(last, sizeof(last), "%lud", (unsigned long)(age / 86400));

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
                snprintf(tsub + to, sizeof(tsub) - to, "</div>");
                any_ops = true;
            }
#endif

            /* 79 bytes of markup + tsub[256] + the five cells: 457 worst case. */
            char row[512];
            HTML_PRINTF(row,
                "<tr><td><b>%u</b>%s</td><td>%lu</td><td>%s</td><td>%s</td>"
                "<td>%s</td><td>%lu</td><td>%s</td></tr>",
                l->line, tsub, (unsigned long)l->sightings, avg, late, early,
                (unsigned long)l->dev_zero, last);
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

        char note[768];
        HTML_PRINTF(note, "<p class='note'>%s</p>", T(S_PT_LIMIT));
        httpd_resp_send_chunk(req, note, HTTPD_RESP_USE_STRLEN);
        if (any_ops)
        {
            /* 1024, not 640: the wrapper and the German texts already need 620
             * bytes, and a cut-off </details> eats the rest of the page. */
            char ohint[1024];
            HTML_PRINTF(ohint,
                "<details class='dtl'><summary>%s</summary><p class='note'>%s</p></details>",
                T(S_PT_OPS_SUM), T(S_PT_OPS_HINT));
            httpd_resp_send_chunk(req, ohint, HTTPD_RESP_USE_STRLEN);
        }
    }

#if CONFIG_ENABLE_SD
    /* The summary says how late a line usually is; this says WHEN. */
    {
        if (pn > 0)
        {
            char ph[384];
            HTML_PRINTF(ph,
                /* Closes the intro group and opens its own -- the one
                 * unconditional </div> below then balances either path. */
                "</div><div class='grp' id='pt-pass'><h2>%s</h2><div class='scroll'><table><thead><tr><th>%s</th>"
                "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
                "</tr></thead><tbody>",
                T(S_PT_PASSAGES), T(S_PT_WHEN), T(S_PT_LINE), T(S_PT_COURSE),
                T(S_PT_DEST), T(S_PT_DEV), T(S_PT_INRANGE));
            httpd_resp_send_chunk(req, ph, HTTPD_RESP_USE_STRLEN);
            /* The array feeds the headway maths above. The table stays at 120
             * rows, because 2000 rows would be hundreds of kilobytes of markup. */
            int pshow = pn < 120 ? pn : 120;
            for (int k = 0; k < pshow; k++)
            {
                time_t t = (time_t)pass[k].seconds;
                struct tm lt;
                localtime_r(&t, &lt);
                char when[24];
                strftime(when, sizeof(when), "%d.%m. %H:%M:%S", &lt);
                char dev[24] = "-";
                if (pass[k].deviation)
                    snprintf(dev, sizeof(dev), "%s%+d min",
                             (pass[k].deviation >= 7 || pass[k].deviation <= -7) ? "&ge;" : "",
                             pass[k].deviation);
                char prow[320];
                HTML_PRINTF(prow,
                    "<tr><td>%s</td><td><b>%u</b></td><td>%u</td><td>%u</td><td>%s</td>"
                    "<td>%u s</td></tr>",
                    when, pass[k].line, pass[k].course, pass[k].dest, dev,
                    pass[k].secs_in_range);
                httpd_resp_send_chunk(req, prow, HTTPD_RESP_USE_STRLEN);
            }
            httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
        }
    }
#endif

    char act[256], atext[192];
    snprintf(atext, sizeof(atext), T(S_PT_ACTIVE), ptlog_open_count());
    HTML_PRINTF(act, "<p class='note'>%s</p>", atext);
    httpd_resp_send_chunk(req, act, HTTPD_RESP_USE_STRLEN);

    char clr[512];
    HTML_PRINTF(clr,
        /* r.ok: this page is ungated but the POST is not -- reloading after a
         * 401 would show the untouched list as if the reset had happened. */
        "<p class='btnrow'><button class='dngr' onclick=\"if(confirm('%s'))fetch('/transit/clear',"
        "{method:'POST'}).then(function(r){if(r.ok)location.reload();});\">%s</button></p></div>",
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

esp_err_t send_auth_required(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"its-g5-receiver\"");
    httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
    return ESP_FAIL;
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
        format_bytes((uint32_t)unsaved, sz, sizeof(sz));
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
    /* Before the body, same reason as /poweroff: a caller that only reads the
     * status must not take a failed confirm for a done one -- the device would
     * roll back half an hour later. */
    if (!ok)
        httpd_resp_set_status(req, "500 Internal Server Error");
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, ok ? T(S_CONFIRMED) : T(S_CONFIRM_ERROR));
    return ok ? ESP_OK : ESP_FAIL;
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
    static const char m[] =
        "{\"name\":\"ITS G5 Node\",\"short_name\":\"ITS G5\",\"start_url\":\"/\","
        /* Same ground as body in s.css -- otherwise the home-screen splash
         * flashes the old, lighter colour before the page paints. */
        "\"display\":\"standalone\",\"background_color\":\"#06070b\","
        "\"theme_color\":\"#f2b134\",\"icons\":["
        "{\"src\":\"/apple-touch-icon.png\",\"sizes\":\"180x180\",\"type\":\"image/png\"},"
        "{\"src\":\"/icon-192.png\",\"sizes\":\"192x192\",\"type\":\"image/png\"},"
        "{\"src\":\"/icon-512.png\",\"sizes\":\"512x512\",\"type\":\"image/png\"}]}";
    httpd_resp_set_type(req, "application/manifest+json");
    httpd_resp_set_hdr(req, "Cache-Control", "max-age=86400");
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
    "<div class='grp top'><p class='note'>%s</p>"
    "<input type='file' id='fw' aria-label='%s'>"
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
    "function upload(){"
    "var f=document.getElementById('fw').files[0];"
    "if(!f){alert('%s');return;}"
    "var b=document.getElementById('upbtn'),w=document.getElementById('upwrap'),"
    "bar=document.getElementById('upbar'),pct=document.getElementById('uppct');"
    "b.disabled=true;b.style.opacity=0.6;w.style.display='';bar.style.width='0';"
    "var xhr=new XMLHttpRequest();"
    "xhr.open('POST','/update?lang=%s');"
    "xhr.upload.onprogress=function(e){if(!e.lengthComputable)return;"
    "var p=Math.round(e.loaded*100/e.total);bar.style.width=p+'%%';"
    "pct.textContent=p+'%% \\u00b7 '+(e.loaded/1048576).toFixed(1)+'/'"
    "+(e.total/1048576).toFixed(1)+' MB';};"
    /* onprogress measures the browser's send, not the device's flashing -- so
     * this phase shows an indeterminate stripe instead of reading as a freeze. */
    "xhr.upload.onload=function(){bar.style.width='100%%';bar.className='busy';"
    "pct.textContent='%s';};"
    "xhr.onload=function(){b.disabled=false;b.style.opacity=1;"
    "bar.className='';pct.textContent='';"
    "document.getElementById('result').innerText=xhr.responseText;"
    "if(xhr.status===200)waitBack();};"
    /* Poll a tiny asset until the device answers again, then return to the status
     * page. The first poll is delayed so a not-yet-rebooted device cannot "succeed". */
    "function waitBack(){var t0=Date.now(),r=document.getElementById('result'),"
    "base=r.innerText;"
    "setTimeout(function(){var iv=setInterval(function(){"
    "r.innerText=base+' '+'%s'+' ('+Math.round((Date.now()-t0)/1000)+' s)';"
    "fetch('/favicon.png?x='+Date.now(),{cache:'no-store'}).then(function(ok){"
    "if(!ok.ok)return;clearInterval(iv);location.href='/';}).catch(function(){});"
    "},2000);},6000);}"
    "xhr.onerror=function(){b.disabled=false;b.style.opacity=1;bar.className='';"
    "w.style.display='none';"
    "document.getElementById('result').innerText='%s';};"
    "document.getElementById('result').innerText='%s';"
    "xhr.send(f);"
    "}"
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

    /* The German form measures about 2.5 KB; 2560 left only 42 bytes of slack, and a
     * truncated <script> here would silently disable the whole upload. */
    char form[3072];
    HTML_PRINTF(form, UPDATE_FORM_FMT,
             T(S_UPD_INTRO), T(S_UPD_CHOOSE_FILE), T(S_UPLOAD), T(S_UPD_CHOOSE_FILE), lc,
             T(S_UPD_FLASHING), T(S_UPD_WAIT), T(S_UPLOAD_FAIL), T(S_UPLOADING));

    send_page_header(req, T(S_TITLE_UPDATE));
    httpd_resp_send_chunk(req, form, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t update_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    if (req->content_len == 0)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty body");
        return ESP_FAIL;
    }

    const esp_partition_t *update_partition = esp_ota_get_next_update_partition(NULL);
    if (!update_partition)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "No free OTA partition");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Web OTA: %u bytes -> %s", (unsigned)req->content_len, update_partition->label);

    esp_ota_handle_t ota_handle;
    esp_err_t err = esp_ota_begin(update_partition, req->content_len, &ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ota_begin failed: %s", esp_err_to_name(err));
        if (err == ESP_ERR_OTA_ROLLBACK_INVALID_STATE)
        {
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, T(S_UPD_NOT_CONFIRMED));
        }
        else
        {
            char msg[96];
            snprintf(msg, sizeof(msg), "esp_ota_begin failed: %s", esp_err_to_name(err));
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, msg);
        }
        return ESP_FAIL;
    }

    char buf[1024];
    size_t remaining = req->content_len;
    bool upload_error = false;
    int timeout_retries = 0;

    while (remaining > 0)
    {
        int to_read = remaining < sizeof(buf) ? (int)remaining : (int)sizeof(buf);
        int received = httpd_req_recv(req, buf, to_read);

        if (received == HTTPD_SOCK_ERR_TIMEOUT)
        {
            if (++timeout_retries > 5) { upload_error = true; break; }
            continue;
        }
        if (received <= 0) { upload_error = true; break; }
        timeout_retries = 0;

        err = esp_ota_write(ota_handle, buf, received);
        if (err != ESP_OK) { upload_error = true; break; }
        remaining -= received;
    }

    if (upload_error)
    {
        esp_ota_abort(ota_handle);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Upload interrupted");
        return ESP_FAIL;
    }

    err = esp_ota_end(ota_handle);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ota_end failed: %s", esp_err_to_name(err));
        char msg[96];
        if (err == ESP_ERR_OTA_VALIDATE_FAILED)
            snprintf(msg, sizeof(msg), "Image validation failed (wrong/corrupt .bin file?)");
        else
            snprintf(msg, sizeof(msg), "esp_ota_end failed: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, msg);
        return ESP_FAIL;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "esp_ota_set_boot_partition failed: %s", esp_err_to_name(err));
        char msg[96];
        snprintf(msg, sizeof(msg), "esp_ota_set_boot_partition failed: %s", esp_err_to_name(err));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, msg);
        return ESP_FAIL;
    }

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
        j.fn(j.req);
        httpd_req_async_handler_complete(j.req);
    }
}

/* No worker at boot -> inline (nothing runs beside it). Saturated worker ->
 * refuse: the handlers share statics (tar_full/tar_hdr, partbuf), a second
 * inline instance would silently corrupt both streams. */
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

/* ==================================================================
 *  GET /messages/search -- searches the PCAP archive. RSSI is shown
 *  as "-": the recording carries the raw frames, not reception meta.
 * ================================================================== */

#define SRCH_LIMIT 200
#define SRCH_ROW_MAX 896
#define SRCH_OUT_CAP (SRCH_LIMIT * SRCH_ROW_MAX)

typedef struct {
    /* Rows collect here (PSRAM), sent only AFTER the walk. A send from the
     * callback would run under the SD writer lock, paced by the client. */
    char *out;
    size_t out_len;
    char q[129];                /* lowercase needle, up to 32 UTF-8 chars decoded */
    uint32_t shown;
    bool limit_hit;
} srch_ctx_t;

static bool srch_cb(uint32_t sec, uint32_t usec, const uint8_t *frame,
                    size_t frame_len, const its_decoded_t *d, void *vctx)
{
    (void)usec; (void)frame; (void)frame_len;
    srch_ctx_t *c = (srch_ctx_t *)vctx;

    web_msg_entry_t e = { 0 };
    entry_from_decoded(&e, d);
    e.seconds = sec;
    e.length = (uint32_t)frame_len;

    char mac_str[20] = "-";
    if (e.has_src_mac)
        snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                 e.src_mac[0], e.src_mac[1], e.src_mac[2],
                 e.src_mac[3], e.src_mac[4], e.src_mac[5]);

    if (c->q[0])
    {
        char hay[96];
        snprintf(hay, sizeof(hay), "%s %s %lu",
                 e.msgtype, mac_str, (unsigned long)e.station_id);
        for (char *p = hay; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        if (!strstr(hay, c->q))
            return true;
    }

    if (c->shown >= SRCH_LIMIT)
    {
        c->limit_hit = true;
        return false;               /* enough -- stop reading the card */
    }

    char detail[384];
    msg_detail_text(&e, sec, detail, sizeof(detail));

    char clock[24];
    struct tm tm_local;
    time_t t = (time_t)sec;
    localtime_r(&t, &tm_local);
    strftime(clock, sizeof(clock), "%d.%m. %H:%M:%S", &tm_local);

    char typeesc[WEB_MSG_TYPE_LEN * 6];
    html_escape(e.msgtype, typeesc, sizeof(typeesc));

    char row[SRCH_ROW_MAX];
    int rl = snprintf(row, sizeof(row),
        "<tr><td>%lu</td><td>%s</td><td>-</td><td>%lu</td>"
        "<td class='wrapcell'>%s</td><td class='mono'>%s</td><td class='wrapcell'>%s</td></tr>",
        (unsigned long)++c->shown, clock, (unsigned long)e.length,
        typeesc, mac_str, detail);
    if (rl < 0)
        return true;
    if ((size_t)rl >= sizeof(row))
        rl = sizeof(row) - 1;
    if (c->out_len + (size_t)rl > SRCH_OUT_CAP)
    {
        c->limit_hit = true;
        return false;
    }
    memcpy(c->out + c->out_len, row, (size_t)rl);
    c->out_len += (size_t)rl;
    return true;
}

/* Streams an HTML fragment; runs on the slow worker via the wrapper below. */
static esp_err_t messages_search_stream(httpd_req_t *req)
{
    resolve_language(req);

    time_t now = time(NULL);
    long from = (long)now - 6 * 3600, to = (long)now;
    srch_ctx_t ctx = { 0 };

    /* Sized for the worst legal input. A shorter buffer returns a truncation
     * error here, so every parameter is dropped and the search uses defaults. */
    char query[512];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char val[224];
        if (httpd_query_key_value(query, "from", val, sizeof(val)) == ESP_OK)
            from = strtol(val, NULL, 10);
        if (httpd_query_key_value(query, "to", val, sizeof(val)) == ESP_OK)
            to = strtol(val, NULL, 10);
        esp_err_t qe = httpd_query_key_value(query, "q", val, sizeof(val));
        if (qe == ESP_OK)
        {
            url_decode(val);
            if (strlcpy(ctx.q, val, sizeof(ctx.q)) >= sizeof(ctx.q))
            {
                /* This needle is longer than any searched field. A truncated
                 * copy could half-match, so use one that never matches. */
                ctx.q[0] = '\x01';
                ctx.q[1] = '\0';
            }
            for (char *p = ctx.q; *p; p++)
                *p = (char)tolower((unsigned char)*p);
        }
        else if (qe == ESP_ERR_HTTPD_RESULT_TRUNC)
        {
            /* The needle did not fit val[] (3-byte UTF-8 takes 9 encoded bytes
             * each). Unfiltered it would fake matches, so match nothing. */
            ctx.q[0] = '\x01';
            ctx.q[1] = '\0';
        }
    }
    if (to > (long)now) to = (long)now;
    if (from < 0)       from = 0;
    if (to <= from)     to = from + 3600;
    if (to - from > 24L * 3600)
        from = to - 24L * 3600;

    ctx.out = heap_caps_malloc(SRCH_OUT_CAP, MALLOC_CAP_SPIRAM);
    if (!ctx.out)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    char head[512];
    snprintf(head, sizeof(head),
        "<div class='scroll'><table><thead><tr><th>#</th><th>%s</th><th>%s</th>"
        "<th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
        T(S_COL_TIME), T(S_COL_RSSI), T(S_COL_LENGTH), T(S_COL_TYPE),
        T(S_COL_SENDER), T(S_COL_PREVIEW));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

    /* The newest minutes are still in the PSRAM ring; without this the search
     * reports them as "nothing found". Same reason as in the export -- and,
     * for a window that already closed, the ring is not asked at all. */
    bool flushed = pcap_window_on_card((uint32_t)to);
    bool complete = sdpcap_read_frames((uint32_t)from, (uint32_t)to, srch_cb, &ctx) && flushed;

    /* Rows go out AFTER the walk, so the send does not hold the SD writer
     * lock. Capped at 200 rows, that is at most ~175 KB. */
    if (ctx.out_len)
        httpd_resp_send_chunk(req, ctx.out, ctx.out_len);
    heap_caps_free(ctx.out);

    char foot[256];
    snprintf(foot, sizeof(foot), "</tbody></table></div><p><small>%s%s%s</small></p>",
        ctx.shown == 0 ? T(S_SRCH_NONE) : "",
        ctx.limit_hit ? T(S_SRCH_LIMIT) : "",
        (!complete && !ctx.limit_hit) ? T(S_SRCH_PARTIAL) : "");
    httpd_resp_send_chunk(req, foot, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ==================================================================
 *  GET /messages/export.pcap -- the frames behind a search, as one
 *  .pcap file. Collected during the walk, sent afterwards.
 * ================================================================== */

#define EXP_CAP (4 * 1024 * 1024)
#define EXP_REC_HDR 16
#define EXP_SNAPLEN 2048        /* matches the recorder's frame cap */

typedef struct {
    uint8_t *buf;
    size_t   len;
    char     q[129];            /* lowercase needle; empty = everything */
    uint32_t kept;
    bool     full;
} exp_ctx_t;

static bool exp_cb(uint32_t sec, uint32_t usec, const uint8_t *frame,
                   size_t frame_len, const its_decoded_t *d, void *vctx)
{
    exp_ctx_t *c = (exp_ctx_t *)vctx;

    if (c->q[0])
    {
        web_msg_entry_t e = { 0 };
        entry_from_decoded(&e, d);
        char mac_str[20] = "-";
        if (e.has_src_mac)
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     e.src_mac[0], e.src_mac[1], e.src_mac[2],
                     e.src_mac[3], e.src_mac[4], e.src_mac[5]);
        char hay[96];
        snprintf(hay, sizeof(hay), "%s %s %lu",
                 e.msgtype, mac_str, (unsigned long)e.station_id);
        for (char *p = hay; *p; p++)
            *p = (char)tolower((unsigned char)*p);
        if (!strstr(hay, c->q))
            return true;
    }

    if (c->len + EXP_REC_HDR + frame_len > EXP_CAP)
    {
        c->full = true;         /* size cap -- stated in the file name */
        return false;
    }

    uint32_t hdr[4] = { sec, usec, (uint32_t)frame_len, (uint32_t)frame_len };
    memcpy(c->buf + c->len, hdr, sizeof(hdr));
    c->len += sizeof(hdr);
    memcpy(c->buf + c->len, frame, frame_len);
    c->len += frame_len;
    c->kept++;
    return true;
}

static esp_err_t messages_export_stream(httpd_req_t *req)
{
    /* Raw frames, i.e. exactly what /sdcard/download hands out -- so the same
     * password applies. The search beside it only shows decoded summaries. */
    if (!check_update_auth(req))
        return send_auth_required(req);

    time_t now = time(NULL);
    long from = (long)now - 3600, to = (long)now;
    exp_ctx_t ctx = { 0 };

    char query[512];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char val[224];
        if (httpd_query_key_value(query, "from", val, sizeof(val)) == ESP_OK)
            from = strtol(val, NULL, 10);
        if (httpd_query_key_value(query, "to", val, sizeof(val)) == ESP_OK)
            to = strtol(val, NULL, 10);
        esp_err_t qe = httpd_query_key_value(query, "q", val, sizeof(val));
        if (qe == ESP_OK)
        {
            url_decode(val);
            if (strlcpy(ctx.q, val, sizeof(ctx.q)) >= sizeof(ctx.q))
                { ctx.q[0] = '\x01'; ctx.q[1] = '\0'; }
            for (char *p = ctx.q; *p; p++)
                *p = (char)tolower((unsigned char)*p);
        }
        else if (qe == ESP_ERR_HTTPD_RESULT_TRUNC)
            { ctx.q[0] = '\x01'; ctx.q[1] = '\0'; }
    }
    if (to > (long)now) to = (long)now;
    if (from < 0)       from = 0;
    if (to <= from)     to = from + 3600;
    if (to - from > 24L * 3600)
        from = to - 24L * 3600;

    ctx.buf = heap_caps_malloc(EXP_CAP, MALLOC_CAP_SPIRAM);
    if (!ctx.buf)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
        return ESP_FAIL;
    }

    /* One pass, one buffer -- do not segment this: resuming duplicates the
     * boundary second and loses records written past an hour boundary. */
    /* The newest minutes still sit in the PSRAM ring; without this the export
     * would silently end before them and still claim to be complete. Only for
     * a window running up to "now" -- an older one is on the card already. */
    bool flushed = pcap_window_on_card((uint32_t)to);
    bool complete = sdpcap_read_frames((uint32_t)from, (uint32_t)to, exp_cb, &ctx) && flushed;

    /* Nothing has been sent yet, so the name can still state the truth. */
    char disp[144];
    snprintf(disp, sizeof(disp), "attachment; filename=\"its-%ld-%ld%s.pcap\"",
             from, to, ctx.full ? "-GEKUERZT" : (complete ? "" : "-teilweise"));
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    /* Classic pcap global header, native byte order (the magic states it),
     * link type 105 = IEEE 802.11 -- same as the stored hourly files. */
    struct __attribute__((packed)) {
        uint32_t magic;
        uint16_t ver_major, ver_minor;
        int32_t  thiszone;
        uint32_t sigfigs, snaplen, network;
    } gh = { 0xa1b2c3d4u, 2, 4, 0, 0, EXP_SNAPLEN, 105 };
    httpd_resp_send_chunk(req, (const char *)&gh, sizeof(gh));

    bool gone = false;
    for (size_t off = 0; off < ctx.len; )
    {
        size_t n = ctx.len - off;
        if (n > 8192) n = 8192;
        if (httpd_resp_send_chunk(req, (const char *)ctx.buf + off, n) != ESP_OK)
            { gone = true; break; }
        off += n;
    }
    heap_caps_free(ctx.buf);
    ESP_LOGI(TAG, "export %ld..%ld: %lu frames, %u bytes%s%s", from, to,
             (unsigned long)ctx.kept, (unsigned)ctx.len,
             ctx.full ? " (size cap hit)" : "", complete ? "" : " (partial)");
    if (gone)
        return ESP_FAIL;
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t messages_search_async(httpd_req_t *req)  { return defer_to_worker(req, messages_search_stream); }
static esp_err_t messages_export_async(httpd_req_t *req)  { return defer_to_worker(req, messages_export_stream); }

static esp_err_t sdcard_download_async(httpd_req_t *req)  { return defer_to_worker(req, sdcard_download_handler); }
static esp_err_t sdcard_tar_async(httpd_req_t *req)       { return defer_to_worker(req, sdcard_tar_handler); }
static esp_err_t internal_tar_async(httpd_req_t *req)     { return defer_to_worker(req, internal_tar_handler); }
static esp_err_t internal_download_async(httpd_req_t *req){ return defer_to_worker(req, internal_download_handler); }
static esp_err_t partimg_download_async(httpd_req_t *req) { return defer_to_worker(req, partimg_download_handler); }
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
 * always sees a whole timestamp. Dates come from the log's daily markers. */
static void stream_tail_escaped(httpd_req_t *req, FILE *f, long start)
{
    fseek(f, start, SEEK_SET);
    char line[512];
    char out[sizeof(line) * 5];

    /* Starting mid-file lands in the middle of a line; drop that remnant. */
    if (start > 0 && !fgets(line, sizeof(line), f))
        return;

    bool at_line_start = true;
    while (fgets(line, sizeof(line), f))
    {
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
}

#define RLOG_SNAP 10496   /* 64 lines of 160 plus separators */
#define RLOG_ESC  1200    /* one line, worst case 6x through html_escape */

/* The RAM console, as its own group. Streamed line by line: 64 lines can reach
 * 60 KB once escaped, which no single buffer here should have to hold. */
static void send_console_block(httpd_req_t *req)
{
    char head[512];
    HTML_PRINTF(head,
        "<div class='grp'><h2>%s</h2><p class='note'>%s</p>"
        "<div class='scroll'><pre class='logpre'>",
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
    httpd_resp_send_chunk(req, "</pre></div></div>", HTTPD_RESP_USE_STRLEN);
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

    /* Links go out before fopen() so the switch to the other file stays
     * reachable when this one is missing; the filter controls do not (see below). */
    char nav[512];
    HTML_PRINTF(nav,
        /* The group opens after the links: they must stay reachable when the
         * file is missing, and that branch closes the group itself. */
        "<p class='jump'><b>%s</b> &middot; <a href='/logs?f=%s&amp;lang=%s'>%s</a>"
        " &middot; <a href='/logs?f=%s&amp;lang=%s'>%s</a>"
        " &middot; <a href='/sdcard/download?p=logs/%s'>&#8595; %s</a></p>"
        "<div class='grp top'>",
        old ? T(S_LOGS_OLD) : T(S_LOGS_SYS),
        old ? "1" : "0", lc, T(S_LOGS_REFRESH),
        old ? "0" : "1", lc, old ? T(S_LOGS_SYS) : T(S_LOGS_OLD),
        old ? "system.1.log" : "system.log", T(S_LOGS_DOWNLOAD));
    httpd_resp_send_chunk(req, nav, HTTPD_RESP_USE_STRLEN);

    /* Counted reader -- the tail stream sends many chunks with the FILE open;
     * see sdcard_download_handler. */
    bool rd = sdcard_read_begin();
    FILE *f = rd ? fopen(path, "rb") : NULL;
    if (!f)
    {
        if (rd)
            sdcard_read_end();
        char msg[192];
        snprintf(msg, sizeof(msg), "<p class='note'>%s</p></div>", T(S_LOGS_NONE));
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
    char tools[640];
    HTML_PRINTF(tools,
        "<p class='btnrow tools'><button id='lgb0' disabled onclick='lgf(0)'>%s</button> "
        "<button id='lgb1' disabled onclick='lgf(1)'>%s</button> "
        "<input id='lgq' disabled oninput='lgf()' placeholder='%s' aria-label='%s' size='16'> "
        "<span id='lgcnt' class='cap'>%s</span> <small>%s</small></p>",
        T(S_LOGS_F_ALL), T(S_LOGS_F_PROB), T(S_LOGS_SEARCH), T(S_LOGS_SEARCH),
        T(S_LOGS_LOADING), T(S_LOGS_LINES));
    httpd_resp_send_chunk(req, tools, HTTPD_RESP_USE_STRLEN);

    /* Two buffers, not one appended: both formats come from T(), and only a
     * hand-clamped snprintf return would keep a long translation in bounds. */
    char note[128], hint[256];
    httpd_resp_send_chunk(req, "<p class='note'>", HTTPD_RESP_USE_STRLEN);
    snprintf(note, sizeof(note), T(S_LOGS_TAIL), LOGS_TAIL_KB);
    httpd_resp_send_chunk(req, note, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, " ", HTTPD_RESP_USE_STRLEN);
    snprintf(hint, sizeof(hint), T(S_LOGS_FILTER_HINT), LOGS_TAIL_KB);
    httpd_resp_send_chunk(req, hint, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "</p><pre id='lgpre' class='logpre'>",
                          HTTPD_RESP_USE_STRLEN);

    stream_tail_escaped(req, f, start);
    fclose(f);
    sdcard_read_end();

    httpd_resp_send_chunk(req, "</pre>", HTTPD_RESP_USE_STRLEN);
    /* Filtering happens in the browser on the text already delivered. Read and
     * written via textContent only -- log lines are unescaped foreign material. */
    httpd_resp_send_chunk(req,
        "<script>(function(){"
        "var pre=document.getElementById('lgpre');"
        "var lines=pre.textContent.split('\\n'),mode=0,total=0;"
        /* Matches the ESP-IDF prefix "W (05:12:44) "; the server already
         * trimmed the milliseconds, so the shape is fixed. */
        "function lvl(s){return (s.length>2&&s[0]>='A'&&s[0]<='Z'&&s[1]===' '&&s[2]==='(')?s[0]:'';}"
        "for(var i=0;i<lines.length;i++)if(lvl(lines[i]))total++;"
        "window.lgf=function(m){"
        "if(m!==undefined)mode=m;"
        "var q=document.getElementById('lgq').value.toLowerCase(),out=[],n=0;"
        /* Lines without a prefix (backtraces, wrapped long lines) inherit the
         * visibility of the line above; unfiltered they must start visible. */
        "var keep=(mode===0&&!q);"
        "for(var i=0;i<lines.length;i++){var s=lines[i],l=lvl(s);"
        /* The daily marker has no prefix and would be inherited away, taking
         * the only date reference in the filtered view with it. */
        "if(s.indexOf('=====')===0){out.push(s);continue;}"
        "if(l){keep=(mode===0)||(l==='W'||l==='E');"
        "if(keep&&q)keep=s.toLowerCase().indexOf(q)>=0;"
        "if(keep)n++;}"
        "if(keep)out.push(s);}"
        "pre.textContent=out.join('\\n');"
        "document.getElementById('lgcnt').textContent=n+' / '+total;};"
        "['lgb0','lgb1','lgq'].forEach(function(i){"
        "document.getElementById(i).disabled=false;});"
        "lgf(0);})();</script>", HTTPD_RESP_USE_STRLEN);
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

    msg_ring_mutex = xSemaphoreCreateMutex();
    if (!msg_ring_mutex)
        ESP_LOGE(TAG, "Failed to create message ring mutex");

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

    /* Local timezone for /messages timestamps, and start NTP once we get an IP. */
    setenv("TZ", LOCAL_TZ, 1);
    tzset();
    ESP_ERROR_CHECK(esp_event_handler_register(APP_EVENT_BASE, APP_ETHERNET_MGMT_INTERFACE_GOT_IP,
                                               time_sync_event_handler, NULL));

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.stack_size = 16384;
    config.lru_purge_enable = true;
    config.max_uri_handlers = 58; /* 51 routes today, plus headroom */
    /* /messages and /map each hold a /ws socket open for as long as the tab
     * is open. Dead sessions pile up until ws_broadcast_work reaps them. */
    config.max_open_sockets = 11;
    /* sdkconfig raises CONFIG_HTTPD_MAX_URI_LEN to 4096 for bulk selections;
     * req->uri is sized at compile time, config.max_uri_len cannot lift it. */
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
        { .uri = "/messages", .method = HTTP_GET,  .handler = messages_get_handler },
        { .uri = "/settings", .method = HTTP_GET,  .handler = settings_get_handler },
        { .uri = "/settings", .method = HTTP_POST, .handler = settings_post_handler },
        { .uri = "/update",   .method = HTTP_GET,  .handler = update_get_handler },
        { .uri = "/update",   .method = HTTP_POST, .handler = update_post_handler },
        { .uri = "/sniffer",  .method = HTTP_POST, .handler = sniffer_post_handler },
        { .uri = "/reboot",   .method = HTTP_POST, .handler = reboot_post_handler },
#if CONFIG_ENABLE_SD
        { .uri = "/poweroff", .method = HTTP_POST, .handler = poweroff_post_handler },
#endif
        { .uri = "/confirm",  .method = HTTP_POST, .handler = confirm_post_handler },
        { .uri = "/system",   .method = HTTP_GET,  .handler = system_get_handler },
        { .uri = "/system.json", .method = HTTP_GET, .handler = system_json_get_handler },
        { .uri = "/system/coredump/clear", .method = HTTP_POST, .handler = coredump_clear_post_handler },
        { .uri = "/system/stats/clear", .method = HTTP_POST, .handler = stats_clear_post_handler },
        { .uri = "/map",         .method = HTTP_GET, .handler = map_get_handler },
        { .uri = "/senders",     .method = HTTP_GET, .handler = senders_get_handler },
        { .uri = "/senders/clear", .method = HTTP_POST, .handler = senders_clear_post_handler },
        { .uri = "/transit",     .method = HTTP_GET, .handler = transit_get_handler },
        { .uri = "/transit/clear", .method = HTTP_POST, .handler = transit_clear_post_handler },
        { .uri = "/spatem.json", .method = HTTP_GET, .handler = spatem_json_handler },
        { .uri = "/lanes.json",  .method = HTTP_GET, .handler = lanes_json_handler },
#if CONFIG_ENABLE_SD
        /* Hourly statistics live on the SD card; without one the page has
         * nothing to show, and its handler is compiled out. */
        { .uri = "/traffic",     .method = HTTP_GET, .handler = traffic_get_handler },
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
        { .uri = "/ws", .method = HTTP_GET, .handler = ws_get_handler, .is_websocket = true },
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
        httpd_register_uri_handler(server, &uris[i]);

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
