#include "sdkconfig.h"

#include <stdio.h>
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

#include "esp_app_desc.h"
#include "esp_console.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif_sntp.h"
#include "esp_ota_ops.h"
#include "esp_sntp.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "mbedtls/base64.h"

#include "config.h"
#include "cmd_sniffer.h"
#include "ethernet.h"
#include "events.h"
#include "ota.h"
#if CONFIG_ENABLE_SD
#include "sdcard.h"
#endif
#ifdef CONFIG_ENABLE_TEMPERATURE
#include "temperature.h"
#endif

#include "webserver.h"

static const char TAG[] = "WEBSERVER";

/* ================================================================== */
/*  Internationalization (i18n) - German default, English optional    */
/* ================================================================== */

typedef enum { LANG_DE = 0, LANG_EN = 1 } lang_t;

/* String IDs */
typedef enum {
    S_NAV_STATUS, S_NAV_MESSAGES, S_NAV_SETTINGS, S_NAV_UPDATE,
    S_TITLE_STATUS, S_TITLE_MESSAGES, S_TITLE_SETTINGS, S_TITLE_UPDATE,
    S_NODEID, S_MAC, S_FW_VERSION, S_HW_VARIANT, S_UPTIME, S_SNIFFER,
    S_CHANNEL, S_MQTT, S_MSGS_RECEIVED, S_RATE, S_FREE_HEAP, S_FREE_PSRAM, S_TEMPERATURE,
    S_RUNNING, S_STOPPED, S_CONNECTED, S_DISCONNECTED,
    S_START, S_STOP, S_REBOOT, S_REBOOT_CONFIRM, S_REBOOTING,
    S_SNIFFER_LABEL, S_AUTO_REFRESH,
    S_CONFIRM_NEEDED, S_CONFIRM_BTN, S_CONFIRMED,
    S_MSG_INTRO, S_COL_NUM, S_COL_TIME, S_COL_RSSI, S_COL_LENGTH, S_COL_PREVIEW,
    S_SET_INTRO, S_MQTT_URI, S_AUTOSTART_CHAN, S_CHAN_NONE,
    S_LED_BRIGHTNESS, S_SAVE, S_SAVED,
    S_WEB_PASSWORD, S_WEB_PASSWORD_SET, S_WEB_PASSWORD_NONE, S_WEB_PASSWORD_CLEAR,
    S_UPD_INTRO, S_UPLOAD, S_UPLOADING, S_UPLOAD_OK, S_UPLOAD_FAIL,
    S_NAV_SD, S_TITLE_SD, S_SD_NOT_MOUNTED, S_SD_MOUNT, S_SD_USAGE, S_SD_USED_OF,
    S_SD_NAME, S_SD_SIZE, S_SD_EMPTY, S_SD_PARENT, S_SD_DELETE, S_SD_DELETE_CONFIRM,
    S_SD_FORMAT, S_SD_FORMAT_CONFIRM, S_SD_FORMATTING, S_SD_UP_HERE, S_SD_UP_BTN,
    S_LANG_OTHER, S_LANG_OTHER_CODE,
    S_COUNT
} str_id_t;

static const char *STR[S_COUNT][2] = {
    /*                        DE                          EN                     */
    [S_NAV_STATUS]      = { "Status",                   "Status" },
    [S_NAV_MESSAGES]    = { "Nachrichten",              "Messages" },
    [S_NAV_SETTINGS]    = { "Einstellungen",            "Settings" },
    [S_NAV_UPDATE]      = { "Firmware-Update",          "Firmware Update" },
    [S_TITLE_STATUS]    = { "Status",                   "Status" },
    [S_TITLE_MESSAGES]  = { "Empfangene Nachrichten",   "Received messages" },
    [S_TITLE_SETTINGS]  = { "Einstellungen",            "Settings" },
    [S_TITLE_UPDATE]    = { "Firmware-Update",          "Firmware update" },
    [S_NODEID]          = { "Node-ID",                  "Node ID" },
    [S_MAC]             = { "MAC-Adresse",              "MAC" },
    [S_FW_VERSION]      = { "Firmware-Version",         "Firmware version" },
    [S_HW_VARIANT]      = { "HW-Variante",              "HW variant" },
    [S_UPTIME]          = { "Laufzeit",                 "Uptime" },
    [S_SNIFFER]         = { "Sniffer",                  "Sniffer" },
    [S_CHANNEL]         = { "Kanal",                    "Channel" },
    [S_MQTT]            = { "MQTT",                     "MQTT" },
    [S_MSGS_RECEIVED]   = { "Empfangene Nachrichten",   "Messages received" },
    [S_RATE]            = { "Rate (letzte 60s)",        "Rate (last 60s)" },
    [S_FREE_HEAP]       = { "Freier Speicher (intern)",  "Free heap (internal)" },
    [S_FREE_PSRAM]      = { "Freier Speicher (PSRAM)",   "Free heap (PSRAM)" },
    [S_TEMPERATURE]     = { "Temperatur",               "Temperature" },
    [S_RUNNING]         = { "l&auml;uft",               "running" },
    [S_STOPPED]         = { "gestoppt",                 "stopped" },
    [S_CONNECTED]       = { "verbunden",                "connected" },
    [S_DISCONNECTED]    = { "getrennt",                 "disconnected" },
    [S_START]           = { "Starten",                  "Start" },
    [S_STOP]            = { "Stoppen",                  "Stop" },
    [S_REBOOT]          = { "Neustart",                 "Reboot" },
    /* Shown in a JS confirm() dialog, which does not decode HTML entities, so
     * this uses a JS \u escape instead of &auml;. */
    [S_REBOOT_CONFIRM]  = { "Ger\\u00e4t neu starten?", "Reboot the device?" },
    [S_REBOOTING]       = { "Neustart l&auml;uft...",   "Rebooting..." },
    [S_SNIFFER_LABEL]   = { "Sniffer",                  "sniffer" },
    [S_AUTO_REFRESH]    = { "Aktualisiert automatisch alle 5 Sekunden.",
                            "Auto-refreshing every 5 seconds." },
    [S_CONFIRM_NEEDED]  = { "Diese Firmware wurde per Update installiert und ist noch nicht best&auml;tigt. "
                            "Ohne Best&auml;tigung wird nach 30 Minuten automatisch zur&uuml;ckgerollt.",
                            "This firmware was installed via update and is not yet confirmed. "
                            "Without confirmation it will roll back automatically after 30 minutes." },
    [S_CONFIRM_BTN]     = { "Update jetzt best&auml;tigen", "Confirm update now" },
    /* Sent as a plain-text response and shown via JS alert(); it is not parsed
     * as HTML, so this uses a literal UTF-8 "ä" (served with charset=utf-8)
     * rather than the &auml; entity. */
    [S_CONFIRMED]       = { "Bestätigt. Rollback abgebrochen.",
                            "Confirmed. Rollback cancelled." },
    [S_MSG_INTRO]       = { "Die letzten %d empfangenen Frames, neueste zuerst (nur Vorschau, erste %d Bytes).",
                            "Last %d received frames, newest first (preview only, first %d bytes)." },
    [S_COL_NUM]         = { "#",                        "#" },
    [S_COL_TIME]        = { "Zeit",                     "Time" },
    [S_COL_RSSI]        = { "RSSI",                     "RSSI" },
    [S_COL_LENGTH]      = { "L&auml;nge",               "Length" },
    [S_COL_PREVIEW]     = { "Vorschau (hex)",           "Preview (hex)" },
    [S_SET_INTRO]       = { "&Auml;nderungen werden im NVS gespeichert. Die meisten wirken nach einem Neustart.",
                            "Changes are saved to NVS. Most take effect after a reboot." },
    [S_MQTT_URI]        = { "MQTT-URI",                 "MQTT URI" },
    [S_AUTOSTART_CHAN]  = { "Autostart-Kanal",          "Autostart channel" },
    [S_CHAN_NONE]       = { "(keiner)",                 "(none)" },
    [S_LED_BRIGHTNESS]  = { "LED-Helligkeit",           "LED brightness" },
    [S_SAVE]            = { "Speichern",                "Save" },
    [S_SAVED]           = { "%d Einstellung(en) gespeichert.", "Saved %d setting(s)." },
    [S_WEB_PASSWORD]    = { "Web-Passwort (Benutzer &quot;admin&quot;)",
                            "Web password (user &quot;admin&quot;)" },
    [S_WEB_PASSWORD_SET]  = { "gesetzt &ndash; leer lassen = unver&auml;ndert",
                              "set &ndash; leave empty to keep unchanged" },
    [S_WEB_PASSWORD_NONE] = { "kein Passwort &ndash; sch&uuml;tzt /update und /settings",
                              "no password &ndash; protects /update and /settings" },
    [S_WEB_PASSWORD_CLEAR] = { "Passwortschutz entfernen",
                               "Remove password protection" },
    [S_UPD_INTRO]       = { "W&auml;hle eine Firmware-Datei (.bin) und klicke Hochladen. Das Ger&auml;t "
                            "flasht sie auf die inaktive OTA-Partition und startet neu. Danach musst du "
                            "das Update im Status best&auml;tigen, sonst wird es zur&uuml;ckgerollt.",
                            "Select a firmware (.bin) file and click Upload. The device flashes it to the "
                            "inactive OTA partition and reboots. Afterwards you must confirm the update on "
                            "the status page, otherwise it will be rolled back." },
    [S_UPLOAD]          = { "Hochladen",                "Upload" },
    /* S_UPLOADING is injected into JS and shown via innerText, which does NOT
     * decode HTML entities. Use a JS \u escape (not &auml;) so it renders. */
    [S_UPLOADING]       = { "L\\u00e4dt hoch...",       "Uploading..." },
    [S_UPLOAD_OK]       = { "OK, erfolgreich geflasht. Neustart...",
                            "OK, flashed successfully. Rebooting..." },
    [S_UPLOAD_FAIL]     = { "Upload fehlgeschlagen (Verbindungsfehler)",
                            "Upload failed (connection error)" },
    [S_NAV_SD]          = { "SD-Karte",                 "SD card" },
    [S_TITLE_SD]        = { "SD-Karte",                 "SD card" },
    [S_SD_NOT_MOUNTED]  = { "Keine SD-Karte eingebunden.", "No SD card mounted." },
    [S_SD_MOUNT]        = { "Einbinden",               "Mount" },
    [S_SD_USAGE]        = { "Belegung",                 "Usage" },
    [S_SD_USED_OF]      = { "%s von %s belegt (%s frei)", "%s of %s used (%s free)" },
    [S_SD_NAME]         = { "Name",                     "Name" },
    [S_SD_SIZE]         = { "Gr&ouml;&szlig;e",         "Size" },
    [S_SD_EMPTY]        = { "(leer)",                   "(empty)" },
    [S_SD_PARENT]       = { ".. (h&ouml;her)",          ".. (up)" },
    [S_SD_DELETE]       = { "L&ouml;schen",             "Delete" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SD_DELETE_CONFIRM] = { "Datei löschen?",         "Delete file?" },
    [S_SD_FORMAT]       = { "Karte formatieren",        "Format card" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SD_FORMAT_CONFIRM] = { "Karte wirklich formatieren? Alle Daten gehen verloren!",
                              "Really format the card? All data will be lost!" },
    /* Set via JS innerText -> JS \u escape, no HTML entity. */
    [S_SD_FORMATTING]   = { "Formatiere\\u2026",        "Formatting\\u2026" },
    [S_SD_UP_HERE]      = { "Datei hierher hochladen",  "Upload a file here" },
    [S_SD_UP_BTN]       = { "Hochladen",                "Upload" },
    [S_LANG_OTHER]      = { "English",                  "Deutsch" },
    [S_LANG_OTHER_CODE] = { "en",                       "de" },
};

/* Per-request language, resolved from ?lang= or a cookie. Because
 * esp_http_server handles requests sequentially in one task, a single
 * global is safe here. */
static lang_t current_lang = LANG_DE;

static inline const char *T(str_id_t id) { return STR[id][current_lang]; }

/* ================================================================== */
/*  State tracked via events                                          */
/* ================================================================== */

static bool mqtt_connected_state;

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

/* WiFi frames only carry a device-relative microsecond timestamp, so the
 * message list cannot show a real wall-clock time on its own. We start an SNTP
 * client once the network is up; from then on webserver_handle_packet stamps
 * each frame with the synced wall-clock time and /messages shows HH:MM:SS. */

#define NTP_SERVER "pool.ntp.org"
/* Europe/Berlin with automatic CET/CEST daylight-saving switch. */
#define LOCAL_TZ   "CET-1CEST,M3.5.0,M10.5.0/3"

static bool sntp_started;

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

    esp_sntp_config_t config = ESP_NETIF_SNTP_DEFAULT_CONFIG(NTP_SERVER);
    esp_err_t err = esp_netif_sntp_init(&config);
    if (err != ESP_OK)
    {
        ESP_LOGW(TAG, "SNTP init failed: %s", esp_err_to_name(err));
        return;
    }
    sntp_started = true;
    ESP_LOGI(TAG, "SNTP client started (%s)", NTP_SERVER);
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
#define WEB_MSG_PREVIEW_LEN 32

typedef struct {
    uint32_t seconds;
    uint32_t microseconds;
    uint32_t length;
    uint32_t preview_len;
    int      rssi;
    uint8_t  preview[WEB_MSG_PREVIEW_LEN];
} web_msg_entry_t;

static web_msg_entry_t msg_ring[WEB_MSG_RING_SIZE];
static size_t msg_ring_head;
static size_t msg_ring_count;
static uint32_t msg_total_count;
static SemaphoreHandle_t msg_ring_mutex;

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

void webserver_handle_packet(sniffer_packet_info_t *packet)
{
    if (!msg_ring_mutex)
        return;
    if (xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(10)) != pdTRUE)
        return;

    web_msg_entry_t *e = &msg_ring[msg_ring_head];
    /* Prefer real wall-clock time once NTP has synced, so /messages shows
     * HH:MM:SS. Before sync (or if it never happens) fall back to the packet's
     * own timestamp: a device-relative microsecond clock for WiFi frames,
     * gettimeofday epoch for Ethernet. */
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
    e->preview_len = packet->length < WEB_MSG_PREVIEW_LEN ? packet->length : WEB_MSG_PREVIEW_LEN;
    memcpy(e->preview, packet->payload, e->preview_len);

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
static void format_uptime(uint64_t total_sec, char *out, size_t out_size)
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

/* Format a byte count as KiB or MiB for readability. */
static void format_bytes(uint32_t bytes, char *out, size_t out_size)
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
static void html_escape(const char *in, char *out, size_t out_size)
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
static void url_decode(char *s)
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
static void resolve_language(httpd_req_t *req)
{
    current_lang = LANG_DE;
    char query[64];
    char val[8];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
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
    "%s"  /* optional auto-refresh meta tag */
    "<style>"
    "body{font-family:sans-serif;margin:2em;background:#111;color:#eee}"
    "a{color:#6cf}"
    "table{border-collapse:collapse;width:100%%}"
    "td,th{border:1px solid #444;padding:4px 8px;text-align:left;font-size:0.9em}"
    "nav a{margin-right:1em}"
    "button{background:#333;color:#eee;border:1px solid #555;padding:6px 12px;margin:2px;cursor:pointer}"
    "input,select{background:#222;color:#eee;border:1px solid #555;padding:4px}"
    ".ok{color:#4c4}.bad{color:#c44}"
    ".warn{background:#4a3c00;border:1px solid #aa8800;padding:1em;margin:1em 0;border-radius:4px}"
    ".lang{float:right;font-size:0.85em}"
    "</style><title>%s</title></head><body>"
    "<nav><a href='/?lang=%s'>%s</a><a href='/messages?lang=%s'>%s</a>"
    "<a href='/settings?lang=%s'>%s</a><a href='/update?lang=%s'>%s</a>"
#if CONFIG_ENABLE_SD
    "<a href='/sdcard?lang=%s'>%s</a>"
#endif
    "<span class='lang'><a href='?lang=%s'>%s</a></span></nav>"
    "<h1>%s</h1>";

static const char PAGE_FOOTER[] = "</body></html>";

static void send_page_header_refresh(httpd_req_t *req, const char *heading, int refresh_secs)
{
    char refresh_tag[64] = "";
    if (refresh_secs > 0)
        snprintf(refresh_tag, sizeof(refresh_tag),
                 "<meta http-equiv='refresh' content='%d'>", refresh_secs);

    const char *lc = current_lang == LANG_DE ? "de" : "en";

    char header[1400];
    snprintf(header, sizeof(header), PAGE_HEADER_FMT,
             lc, refresh_tag, heading,
             lc, T(S_NAV_STATUS),
             lc, T(S_NAV_MESSAGES),
             lc, T(S_NAV_SETTINGS),
             lc, T(S_NAV_UPDATE),
#if CONFIG_ENABLE_SD
             lc, T(S_NAV_SD),
#endif
             T(S_LANG_OTHER_CODE), T(S_LANG_OTHER),
             heading);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send_chunk(req, header, HTTPD_RESP_USE_STRLEN);
}

static void send_page_header(httpd_req_t *req, const char *heading)
{
    send_page_header_refresh(req, heading, 0);
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
    /* Internal SRAM is the scarce resource (~400 KB); PSRAM (8 MB) would
     * otherwise dominate esp_get_free_heap_size() and hide it. Report them
     * separately using heap_caps. */
    char heap_str[24];
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_INTERNAL), heap_str, sizeof(heap_str));
    char minheap_str[24];
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL), minheap_str, sizeof(minheap_str));
#ifdef CONFIG_SPIRAM
    char psram_str[24];
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_SPIRAM), psram_str, sizeof(psram_str));
    char minpsram_str[24];
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM), minpsram_str, sizeof(minpsram_str));
#endif

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

    send_page_header_refresh(req, T(S_TITLE_STATUS), 5);

    /* Confirm banner if this firmware is pending verification */
    if (ota_is_pending_verify())
    {
        char banner[512];
        snprintf(banner, sizeof(banner),
            "<div class='warn'><p>%s</p>"
            "<button onclick=\"fetch('/confirm',{method:'POST'}).then(r=>r.text()).then(t=>{alert(t);location.reload();})\">%s</button>"
            "</div>",
            T(S_CONFIRM_NEEDED), T(S_CONFIRM_BTN));
        httpd_resp_send_chunk(req, banner, HTTPD_RESP_USE_STRLEN);
    }

    char body[3072];
    snprintf(body, sizeof(body),
        "<table>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%02x:%02x:%02x:%02x:%02x:%02x</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td class='%s'>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td class='%s'>%s</td></tr>"
        "<tr><th>%s</th><td>%lu</td></tr>"
        "<tr><th>%s</th><td>%lu</td></tr>"
        "<tr><th>%s</th><td>%s (min %s)</td></tr>"
#ifdef CONFIG_SPIRAM
        "<tr><th>%s</th><td>%s (min %s)</td></tr>"
#endif
#ifdef CONFIG_ENABLE_TEMPERATURE
        "<tr><th>%s</th><td>%.1f &deg;C</td></tr>"
#endif
        "</table>"
        "<p>"
        "<button onclick=\"fetch('/sniffer?action=%s',{method:'POST'}).then(()=>location.reload())\">%s %s</button> "
        "<button onclick=\"if(confirm('%s'))fetch('/reboot',{method:'POST'}).then(()=>{document.body.innerHTML='<p>%s</p>';})\">%s</button>"
        "</p>"
        "<p style='color:#888;font-size:0.8em'>%s</p>",
        T(S_NODEID), nodeid_esc,
        T(S_MAC), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        T(S_FW_VERSION), app_desc->version,
        T(S_HW_VARIANT), CONFIG_HW_VARIANT,
        T(S_UPTIME), uptime_str,
        T(S_SNIFFER), running ? "ok" : "bad", running ? T(S_RUNNING) : T(S_STOPPED),
        T(S_CHANNEL), chan_str,
        T(S_MQTT), mqtt_connected_state ? "ok" : "bad",
        mqtt_connected_state ? T(S_CONNECTED) : T(S_DISCONNECTED),
        T(S_MSGS_RECEIVED), (unsigned long)msg_total_count,
        T(S_RATE), (unsigned long)rate,
        T(S_FREE_HEAP), heap_str, minheap_str,
#ifdef CONFIG_SPIRAM
        T(S_FREE_PSRAM), psram_str, minpsram_str,
#endif
#ifdef CONFIG_ENABLE_TEMPERATURE
        T(S_TEMPERATURE), (double)temperature_get(),
#endif
        running ? "stop" : "start",
        running ? T(S_STOP) : T(S_START), T(S_SNIFFER_LABEL),
        T(S_REBOOT_CONFIRM), T(S_REBOOTING), T(S_REBOOT),
        T(S_AUTO_REFRESH)
    );
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  GET /messages                                                     */
/* ================================================================== */

static esp_err_t messages_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    send_page_header_refresh(req, T(S_TITLE_MESSAGES), 5);

    char intro[256];
    snprintf(intro, sizeof(intro), "<p>");
    size_t l = strlen(intro);
    snprintf(intro + l, sizeof(intro) - l, T(S_MSG_INTRO), WEB_MSG_RING_SIZE, WEB_MSG_PREVIEW_LEN);
    l = strlen(intro);
    snprintf(intro + l, sizeof(intro) - l,
        "</p><table><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>",
        T(S_COL_NUM), T(S_COL_TIME), T(S_COL_RSSI), T(S_COL_LENGTH), T(S_COL_PREVIEW));
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);

    static web_msg_entry_t snapshot[WEB_MSG_RING_SIZE];
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

        char hex[WEB_MSG_PREVIEW_LEN * 3 + 1] = {0};
        for (uint32_t b = 0; b < e->preview_len; b++)
            snprintf(hex + b * 3, 4, "%02x ", e->preview[b]);

        char clock[24];
        format_clock(e->seconds, e->microseconds, clock, sizeof(clock));

        char rssi_str[16];
        if (e->rssi != 0)
            snprintf(rssi_str, sizeof(rssi_str), "%d dBm", e->rssi);
        else
            snprintf(rssi_str, sizeof(rssi_str), "-");

        char row[512];
        snprintf(row, sizeof(row),
            "<tr><td>%zu</td><td>%s</td><td>%s</td><td>%lu</td><td><code>%s</code></td></tr>",
            n + 1, clock, rssi_str, (unsigned long)e->length, hex);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</table>", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  Basic Auth for /update and /settings write                        */
/* ================================================================== */

static bool check_update_auth(httpd_req_t *req)
{
    char password[CONFIG_WEB_PASSWORD_BUFFER_SIZE] = {0};
    size_t pw_size = sizeof(password);
    esp_err_t res = config_get_str(CONFIG_INDEX_WEB_PASSWORD, password, &pw_size);

    if (res != ESP_OK || pw_size <= 1)
        return true;  /* no password set => open */

    size_t hdr_len = httpd_req_get_hdr_value_len(req, "Authorization");
    if (hdr_len == 0)
        return false;

    char *auth_hdr = malloc(hdr_len + 1);
    if (!auth_hdr)
        return false;

    bool ok = false;
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth_hdr, hdr_len + 1) == ESP_OK)
    {
        char credentials[6 + CONFIG_WEB_PASSWORD_BUFFER_SIZE] = "admin:";
        strncat(credentials, password, sizeof(credentials) - strlen(credentials) - 1);

        unsigned char b64[128];
        size_t olen = 0;
        if (mbedtls_base64_encode(b64, sizeof(b64) - 1, &olen,
                                  (const unsigned char *)credentials, strlen(credentials)) == 0)
        {
            b64[olen] = '\0';
            char expected[8 + sizeof(b64)];
            snprintf(expected, sizeof(expected), "Basic %s", b64);
            ok = strcmp(auth_hdr, expected) == 0;
        }
    }
    free(auth_hdr);
    return ok;
}

static esp_err_t send_auth_required(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"its-g5-receiver\"");
    httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
    return ESP_FAIL;
}

/* ================================================================== */
/*  /settings  -- view and change configuration                       */
/* ================================================================== */

static void settings_get_str(config_index_t index, char *out, size_t out_size)
{
    char raw[256] = {0};
    size_t raw_size = sizeof(raw);
    if (config_get_str(index, raw, &raw_size) == ESP_OK)
        html_escape(raw, out, out_size);
    else
        out[0] = '\0';
}

static esp_err_t settings_get_handler(httpd_req_t *req)
{
    resolve_language(req);

    char nodeid[CONFIG_NODEID_BUFFER_SIZE * 6] = {0};
    char mqtt_uri[CONFIG_MQTT_URI_BUFFER_SIZE * 6] = {0};
    settings_get_str(CONFIG_INDEX_NODEID, nodeid, sizeof(nodeid));
    settings_get_str(CONFIG_INDEX_MQTT_URI, mqtt_uri, sizeof(mqtt_uri));

    uint32_t chan = 0;
    config_get_u32(CONFIG_INDEX_AUTOSTART_CHAN, &chan);
    uint8_t brightness = 0;
    config_get_u8(CONFIG_INDEX_LED_BRIGHTNESS, &brightness);

    /* Whether a web password is currently set. We never echo the password
     * itself back into the page, only whether one exists. */
    char cur_pw[CONFIG_WEB_PASSWORD_BUFFER_SIZE] = {0};
    size_t cur_pw_size = sizeof(cur_pw);
    bool pw_set = config_get_str(CONFIG_INDEX_WEB_PASSWORD, cur_pw, &cur_pw_size) == ESP_OK
                  && cur_pw_size > 1;

    char body[5120];
    snprintf(body, sizeof(body),
        "<p>%s</p>"
        "<table>"
        "<tr><th>%s</th><td><input id='nodeid' value='%s' size='24'></td></tr>"
        "<tr><th>%s</th><td><input id='mqtturi' value='%s' size='40'></td></tr>"
        "<tr><th>%s</th><td><select id='chan'>"
        "<option value='0'%s>%s</option>"
        "<option value='5900'%s>G5CC (5900)</option>"
        "<option value='5890'%s>G5SC2 (5890)</option>"
        "<option value='5880'%s>G5SC1 (5880)</option>"
        "<option value='5870'%s>G5SC3 (5870)</option>"
        "<option value='5860'%s>G5SC4 (5860)</option>"
        "</select></td></tr>"
        "<tr><th>%s</th><td>"
        "<input type='range' id='led' min='0' max='255' value='%u' "
        "oninput=\"document.getElementById('ledval').innerText=this.value\">"
        "<span id='ledval'>%u</span></td></tr>"
        "<tr><th>%s</th><td>"
        "<input type='password' id='webpasswd' size='24' autocomplete='new-password'>"
        "<br><small>%s</small>"
        "<br><label><input type='checkbox' id='webpwclear'> %s</label>"
        "</td></tr>"
        "</table>"
        "<p><button onclick=\"save()\">%s</button> <span id='result'></span></p>"
        "<script>"
        "function save(){"
        "var p=new URLSearchParams();"
        "p.append('nodeid',document.getElementById('nodeid').value);"
        "p.append('mqtturi',document.getElementById('mqtturi').value);"
        "p.append('chan',document.getElementById('chan').value);"
        "p.append('led',document.getElementById('led').value);"
        "p.append('webpasswd',document.getElementById('webpasswd').value);"
        "if(document.getElementById('webpwclear').checked)p.append('webpwclear','1');"
        "fetch('/settings',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:p.toString()})"
        ".then(r=>r.text()).then(t=>{document.getElementById('result').innerText=t;});"
        "}"
        "</script>",
        T(S_SET_INTRO),
        T(S_NODEID), nodeid,
        T(S_MQTT_URI), mqtt_uri,
        T(S_AUTOSTART_CHAN),
        chan == 0 ? " selected" : "", T(S_CHAN_NONE),
        chan == 5900 ? " selected" : "",
        chan == 5890 ? " selected" : "",
        chan == 5880 ? " selected" : "",
        chan == 5870 ? " selected" : "",
        chan == 5860 ? " selected" : "",
        T(S_LED_BRIGHTNESS), brightness, brightness,
        T(S_WEB_PASSWORD),
        pw_set ? T(S_WEB_PASSWORD_SET) : T(S_WEB_PASSWORD_NONE),
        T(S_WEB_PASSWORD_CLEAR),
        T(S_SAVE)
    );

    send_page_header(req, T(S_TITLE_SETTINGS));
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t settings_post_handler(httpd_req_t *req)
{
    resolve_language(req);

    if (!check_update_auth(req))
        return send_auth_required(req);

    if (req->content_len == 0 || req->content_len > 1024)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
        return ESP_FAIL;
    }

    char buf[1024] = {0};
    int received = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (received <= 0)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "recv failed");
        return ESP_FAIL;
    }
    buf[received] = '\0';

    char value[256];
    int saved = 0;

    if (httpd_query_key_value(buf, "nodeid", value, sizeof(value)) == ESP_OK)
    {
        url_decode(value);
        if (value[0] && config_set_str(CONFIG_INDEX_NODEID, value) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "mqtturi", value, sizeof(value)) == ESP_OK)
    {
        url_decode(value);
        if (value[0] && config_set_str(CONFIG_INDEX_MQTT_URI, value) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "chan", value, sizeof(value)) == ESP_OK)
    {
        url_decode(value);
        if (config_set_u32(CONFIG_INDEX_AUTOSTART_CHAN, (uint32_t)strtoul(value, NULL, 10)) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "led", value, sizeof(value)) == ESP_OK)
    {
        url_decode(value);
        long b = strtol(value, NULL, 10);
        if (b < 0) b = 0;
        if (b > 255) b = 255;
        /* config_set_u8 fires a config event, so LED brightness updates live */
        if (config_set_u8(CONFIG_INDEX_LED_BRIGHTNESS, (uint8_t)b) == ESP_OK) saved++;
    }
    /* Web password: an explicit "remove" checkbox clears it; otherwise a
     * non-empty value sets it. An empty value leaves the current one unchanged
     * so other settings can be saved without wiping the password. Storing an
     * empty string disables protection (check_update_auth treats it as open). */
    if (httpd_query_key_value(buf, "webpwclear", value, sizeof(value)) == ESP_OK
        && strcmp(value, "1") == 0)
    {
        if (config_set_str(CONFIG_INDEX_WEB_PASSWORD, "") == ESP_OK) saved++;
    }
    else if (httpd_query_key_value(buf, "webpasswd", value, sizeof(value)) == ESP_OK)
    {
        url_decode(value);
        if (value[0] && config_set_str(CONFIG_INDEX_WEB_PASSWORD, value) == ESP_OK) saved++;
    }

    char msg[64];
    snprintf(msg, sizeof(msg), T(S_SAVED), saved);
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, msg);
    return ESP_OK;
}

/* ================================================================== */
/*  /sniffer, /reboot, /confirm                                       */
/* ================================================================== */

static esp_err_t sniffer_post_handler(httpd_req_t *req)
{
    char query[32] = {0};
    char action[16] = {0};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
        httpd_query_key_value(query, "action", action, sizeof(action));

    int ret;
    esp_err_t run_res;
    if (strcmp(action, "start") == 0)
        run_res = esp_console_run("sniffer", &ret);
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
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "Rebooting...");
    esp_timer_start_once(reboot_timer_handle, 1000000);
    return ESP_OK;
}

static esp_err_t confirm_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    bool ok = ota_confirm();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, ok ? T(S_CONFIRMED) : "Error");
    return ok ? ESP_OK : ESP_FAIL;
}

/* ================================================================== */
/*  GET/POST /update                                                  */
/* ================================================================== */

static const char UPDATE_FORM_FMT[] =
    "<p>%s</p>"
    "<input type='file' id='fw'><button onclick='upload()'>%s</button>"
    "<p id='result'></p>"
    "<script>"
    "function upload(){"
    "var f=document.getElementById('fw').files[0];"
    "if(!f){alert('choose a file first');return;}"
    "var xhr=new XMLHttpRequest();"
    "xhr.open('POST','/update');"
    "xhr.onload=function(){document.getElementById('result').innerText=xhr.responseText;};"
    "xhr.onerror=function(){document.getElementById('result').innerText='%s';};"
    "document.getElementById('result').innerText='%s';"
    "xhr.send(f);"
    "}"
    "</script>";

static esp_err_t update_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    char form[1024];
    snprintf(form, sizeof(form), UPDATE_FORM_FMT,
             T(S_UPD_INTRO), T(S_UPLOAD), T(S_UPLOAD_FAIL), T(S_UPLOADING));

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
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "esp_ota_begin failed");
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
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
            err == ESP_ERR_OTA_VALIDATE_FAILED ? "Image validation failed" : "esp_ota_end failed");
        return ESP_FAIL;
    }

    err = esp_ota_set_boot_partition(update_partition);
    if (err != ESP_OK)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "set_boot_partition failed");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Web OTA successful, rebooting");
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, T(S_UPLOAD_OK));
    esp_timer_start_once(reboot_timer_handle, 1000000);
    return ESP_OK;
}

#if CONFIG_ENABLE_SD
/* ================================================================== */
/*  /sdcard  -- browse, upload, format the SD card                    */
/* ================================================================== */

#define SD_PATH_MAX 320

/* Format a 64-bit byte count (SD cards exceed the uint32_t range). */
static void format_bytes64(uint64_t bytes, char *out, size_t out_size)
{
    if (bytes >= (1ULL << 30))
        snprintf(out, out_size, "%.2f GiB", (double)bytes / (double)(1ULL << 30));
    else if (bytes >= (1ULL << 20))
        snprintf(out, out_size, "%.1f MiB", (double)bytes / (double)(1ULL << 20));
    else if (bytes >= 1024)
        snprintf(out, out_size, "%.1f KiB", (double)bytes / 1024.0);
    else
        snprintf(out, out_size, "%llu B", (unsigned long long)bytes);
}

/* Percent-encode a path for safe use in an href/query. */
static void url_encode(const char *in, char *out, size_t out_size)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (; *in && o + 4 < out_size; in++)
    {
        unsigned char c = (unsigned char)*in;
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                          c == '.' || c == '~' || c == '/';
        if (unreserved)
            out[o++] = (char)c;
        else { out[o++] = '%'; out[o++] = hex[c >> 4]; out[o++] = hex[c & 0xF]; }
    }
    out[o] = '\0';
}

/* Read the ?p= query into rel (relative to the mount point). Rejects any path
 * containing ".." so a request can never escape the mount point. */
/* True if any byte is a control character (CR, LF, ...). Used to reject paths
 * that could otherwise inject extra HTTP response headers (e.g. via
 * Content-Disposition) or other control-character trickery. */
static bool has_control_char(const char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20)
            return true;
    return false;
}

static bool sd_get_relpath(httpd_req_t *req, char *rel, size_t rel_size)
{
    rel[0] = '\0';
    char query[SD_PATH_MAX];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char val[SD_PATH_MAX];
        if (httpd_query_key_value(query, "p", val, sizeof(val)) == ESP_OK)
        {
            url_decode(val);
            if (strstr(val, "..") != NULL || has_control_char(val))
                return false;
            strlcpy(rel, val, rel_size);
        }
    }
    return true;
}

static void sd_full_path(const char *rel, char *out, size_t out_size)
{
    if (rel && rel[0])
        snprintf(out, out_size, "%s/%s", sdcard_mount_point(), rel);
    else
        snprintf(out, out_size, "%s", sdcard_mount_point());
}

static esp_err_t sdcard_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* SD contents can be arbitrary/sensitive (whatever got uploaded), so
     * browsing is gated by the same web password as write actions. */
    if (!check_update_auth(req))
        return send_auth_required(req);

    /* Parse/validate the path BEFORE sending any output, so a rejected path can
     * still return a clean HTTP error instead of a half-streamed page. */
    char rel[SD_PATH_MAX];
    if (sdcard_is_mounted() && !sd_get_relpath(req, rel, sizeof(rel)))
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }

    send_page_header(req, T(S_TITLE_SD));

    if (!sdcard_is_mounted())
    {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "<p>%s</p><form method='post' action='/sdcard/mount'>"
            "<button>%s</button></form>",
            T(S_SD_NOT_MOUNTED), T(S_SD_MOUNT));
        httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, NULL, 0);
        return ESP_OK;
    }

    /* Usage + upload form + format button */
    uint64_t total = 0, freeb = 0;
    char usage[256] = "";
    if (sdcard_usage(&total, &freeb) == ESP_OK)
    {
        char t[24], u[24], f[24];
        format_bytes64(total, t, sizeof(t));
        format_bytes64(total - freeb, u, sizeof(u));
        format_bytes64(freeb, f, sizeof(f));
        char used_of[128];
        snprintf(used_of, sizeof(used_of), T(S_SD_USED_OF), u, t, f);
        snprintf(usage, sizeof(usage), "<p><b>%s:</b> %s</p>", T(S_SD_USAGE), used_of);
    }

    char relenc[SD_PATH_MAX * 3];
    url_encode(rel, relenc, sizeof(relenc));
    /* rel is attacker-controlled (from ?p=) and gets displayed as a path
     * breadcrumb below; escape it so it can't inject HTML/JS. */
    char relesc[SD_PATH_MAX * 6];
    html_escape(rel, relesc, sizeof(relesc));

    char top[2560];
    snprintf(top, sizeof(top),
        "%s"
        "<p>%s: <input type='file' id='fw'><button onclick='up()'>%s</button> "
        "<span id='ur'></span></p>"
        "<p><button onclick='fmt()'>%s</button> <span id='fr'></span></p>"
        "<script>"
        "var P='%s';"
        "function up(){var f=document.getElementById('fw').files[0];if(!f){return;}"
        "var x=new XMLHttpRequest();"
        "x.open('POST','/sdcard/upload?p='+encodeURIComponent(P)+'&name='+encodeURIComponent(f.name));"
        "x.onload=function(){location.reload();};"
        "document.getElementById('ur').innerText='%s';x.send(f);}"
        "function fmt(){if(!confirm('%s'))return;"
        "var x=new XMLHttpRequest();x.open('POST','/sdcard/format');"
        "x.onload=function(){location.reload();};"
        "document.getElementById('fr').innerText='%s';x.send();}"
        "function del(p){if(!confirm('%s'))return;"
        "var x=new XMLHttpRequest();x.open('POST','/sdcard/delete?p='+encodeURIComponent(p));"
        "x.onload=function(){location.reload();};x.send();}"
        "</script>",
        usage,
        T(S_SD_UP_HERE), T(S_SD_UP_BTN),
        T(S_SD_FORMAT),
        relenc,
        T(S_UPLOADING),
        T(S_SD_FORMAT_CONFIRM), T(S_SD_FORMATTING),
        T(S_SD_DELETE_CONFIRM));
    httpd_resp_send_chunk(req, top, HTTPD_RESP_USE_STRLEN);

    /* Own (small) chunk: the path breadcrumb is attacker-controlled (?p=), so
     * it is kept separate from the buffer above and always HTML-escaped. */
    char breadcrumb[SD_PATH_MAX * 6 + 96];
    snprintf(breadcrumb, sizeof(breadcrumb),
        "<p><b>/%s</b></p><table><tr><th>%s</th><th>%s</th><th></th></tr>",
        relesc, T(S_SD_NAME), T(S_SD_SIZE));
    httpd_resp_send_chunk(req, breadcrumb, HTTPD_RESP_USE_STRLEN);

    /* Parent-directory link */
    if (rel[0])
    {
        char parent[SD_PATH_MAX];
        strlcpy(parent, rel, sizeof(parent));
        char *slash = strrchr(parent, '/');
        if (slash) *slash = '\0'; else parent[0] = '\0';
        char penc[SD_PATH_MAX * 3];
        url_encode(parent, penc, sizeof(penc));
        char row[SD_PATH_MAX * 3 + 128];
        snprintf(row, sizeof(row),
            "<tr><td><a href='/sdcard?p=%s'>%s</a></td><td></td><td></td></tr>",
            penc, T(S_SD_PARENT));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Directory entries */
    char full[SD_PATH_MAX];
    sd_full_path(rel, full, sizeof(full));
    DIR *dir = opendir(full);
    size_t entries = 0;
    if (dir)
    {
        struct dirent *de;
        while ((de = readdir(dir)) != NULL)
        {
            if (de->d_name[0] == '.')
                continue;
            entries++;

            char childrel[SD_PATH_MAX + 256];
            if (rel[0]) snprintf(childrel, sizeof(childrel), "%s/%s", rel, de->d_name);
            else        snprintf(childrel, sizeof(childrel), "%s", de->d_name);

            char childfull[SD_PATH_MAX + 288];
            sd_full_path(childrel, childfull, sizeof(childfull));
            struct stat st;
            bool is_dir = (stat(childfull, &st) == 0) && S_ISDIR(st.st_mode);

            char nameesc[256], relenc2[SD_PATH_MAX * 3];
            html_escape(de->d_name, nameesc, sizeof(nameesc));
            url_encode(childrel, relenc2, sizeof(relenc2));

            /* row holds relenc2 twice (href + delete) plus the escaped name. */
            char row[SD_PATH_MAX * 6 + 512];
            if (is_dir)
            {
                snprintf(row, sizeof(row),
                    "<tr><td><a href='/sdcard?p=%s'>%s/</a></td><td></td><td></td></tr>",
                    relenc2, nameesc);
            }
            else
            {
                char sz[32];
                format_bytes64((uint64_t)st.st_size, sz, sizeof(sz));
                snprintf(row, sizeof(row),
                    "<tr><td><a href='/sdcard/download?p=%s'>%s</a></td><td>%s</td>"
                    "<td><button onclick=\"del('%s')\">%s</button></td></tr>",
                    relenc2, nameesc, sz, relenc2, T(S_SD_DELETE));
            }
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        closedir(dir);
    }

    if (entries == 0)
    {
        char row[128];
        snprintf(row, sizeof(row), "<tr><td>%s</td><td></td><td></td></tr>", T(S_SD_EMPTY));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</table>", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t sdcard_download_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    if (!sdcard_is_mounted())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)) || rel[0] == '\0')
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }
    char full[SD_PATH_MAX];
    sd_full_path(rel, full, sizeof(full));
    FILE *f = fopen(full, "rb");
    if (!f)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
        return ESP_FAIL;
    }
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    char disp[SD_PATH_MAX + 64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", base);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        if (httpd_resp_send_chunk(req, buf, n) != ESP_OK)
        {
            fclose(f);
            return ESP_FAIL;
        }
    }
    fclose(f);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t sdcard_upload_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    if (!sdcard_is_mounted())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }

    char reldir[SD_PATH_MAX] = "", name[128] = "";
    char query[SD_PATH_MAX];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char v[SD_PATH_MAX];
        if (httpd_query_key_value(query, "p", v, sizeof(v)) == ESP_OK)
        {
            url_decode(v);
            if (strstr(v, "..")) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path"); return ESP_FAIL; }
            strlcpy(reldir, v, sizeof(reldir));
        }
        if (httpd_query_key_value(query, "name", v, sizeof(v)) == ESP_OK)
        {
            url_decode(v);
            strlcpy(name, v, sizeof(name));
        }
    }
    /* A filename must be a single path component. */
    if (name[0] == '\0' || strchr(name, '/') || strstr(name, "..") || has_control_char(name))
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad name");
        return ESP_FAIL;
    }
    if (req->content_len == 0)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty");
        return ESP_FAIL;
    }

    char full[SD_PATH_MAX * 2];
    if (reldir[0]) snprintf(full, sizeof(full), "%s/%s/%s", sdcard_mount_point(), reldir, name);
    else           snprintf(full, sizeof(full), "%s/%s", sdcard_mount_point(), name);

    FILE *f = fopen(full, "wb");
    if (!f)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "open failed");
        return ESP_FAIL;
    }

    char buf[1024];
    size_t remaining = req->content_len;
    int retries = 0;
    bool ok = true;
    while (remaining > 0)
    {
        int to_read = remaining < sizeof(buf) ? (int)remaining : (int)sizeof(buf);
        int r = httpd_req_recv(req, buf, to_read);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) { if (++retries > 5) { ok = false; break; } continue; }
        if (r <= 0) { ok = false; break; }
        retries = 0;
        if (fwrite(buf, 1, r, f) != (size_t)r) { ok = false; break; }
        remaining -= r;
    }
    fclose(f);
    if (!ok)
    {
        remove(full);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "write failed");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static esp_err_t sdcard_delete_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    if (!sdcard_is_mounted())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)) || rel[0] == '\0')
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }
    char full[SD_PATH_MAX];
    sd_full_path(rel, full, sizeof(full));
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    if (remove(full) == 0)
    {
        httpd_resp_sendstr(req, "OK");
        return ESP_OK;
    }
    httpd_resp_sendstr(req, "Error");
    return ESP_FAIL;
}

static esp_err_t sdcard_format_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    esp_err_t e = sdcard_format();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, e == ESP_OK ? "OK" : "Error");
    return e == ESP_OK ? ESP_OK : ESP_FAIL;
}

static esp_err_t sdcard_mount_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    sdcard_mount();
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/sdcard");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}
#endif // CONFIG_ENABLE_SD

/* ================================================================== */
/*  Init                                                               */
/* ================================================================== */

void webserver_init(void)
{
    msg_ring_mutex = xSemaphoreCreateMutex();
    if (!msg_ring_mutex)
        ESP_LOGE(TAG, "Failed to create message ring mutex");

    esp_timer_create_args_t timer_args = {
        .callback = reboot_timer_cb, .arg = NULL, .name = "web_reboot"
    };
    ESP_ERROR_CHECK(esp_timer_create(&timer_args, &reboot_timer_handle));

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
    config.max_uri_handlers = 16;

    httpd_handle_t server = NULL;
    esp_err_t err = httpd_start(&server, &config);
    if (err != ESP_OK)
    {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        return;
    }

    static const httpd_uri_t uris[] = {
        { .uri = "/",         .method = HTTP_GET,  .handler = status_page_handler },
        { .uri = "/messages", .method = HTTP_GET,  .handler = messages_get_handler },
        { .uri = "/settings", .method = HTTP_GET,  .handler = settings_get_handler },
        { .uri = "/settings", .method = HTTP_POST, .handler = settings_post_handler },
        { .uri = "/update",   .method = HTTP_GET,  .handler = update_get_handler },
        { .uri = "/update",   .method = HTTP_POST, .handler = update_post_handler },
        { .uri = "/sniffer",  .method = HTTP_POST, .handler = sniffer_post_handler },
        { .uri = "/reboot",   .method = HTTP_POST, .handler = reboot_post_handler },
        { .uri = "/confirm",  .method = HTTP_POST, .handler = confirm_post_handler },
#if CONFIG_ENABLE_SD
        { .uri = "/sdcard",          .method = HTTP_GET,  .handler = sdcard_get_handler },
        { .uri = "/sdcard/download", .method = HTTP_GET,  .handler = sdcard_download_handler },
        { .uri = "/sdcard/upload",   .method = HTTP_POST, .handler = sdcard_upload_handler },
        { .uri = "/sdcard/delete",   .method = HTTP_POST, .handler = sdcard_delete_handler },
        { .uri = "/sdcard/format",   .method = HTTP_POST, .handler = sdcard_format_handler },
        { .uri = "/sdcard/mount",    .method = HTTP_POST, .handler = sdcard_mount_handler },
#endif
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++)
        httpd_register_uri_handler(server, &uris[i]);

    ESP_LOGI(TAG, "Web server started on port %d", config.server_port);
}
