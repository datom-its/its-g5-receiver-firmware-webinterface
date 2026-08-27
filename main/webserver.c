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

/* Icons embedded via CMake EMBED_FILES (see main/CMakeLists.txt). */
extern const uint8_t favicon_png_start[]          asm("_binary_favicon_png_start");
extern const uint8_t favicon_png_end[]            asm("_binary_favicon_png_end");
extern const uint8_t apple_touch_icon_png_start[] asm("_binary_apple_touch_icon_png_start");
extern const uint8_t apple_touch_icon_png_end[]   asm("_binary_apple_touch_icon_png_end");
extern const uint8_t icon_192_png_start[]         asm("_binary_icon_192_png_start");
extern const uint8_t icon_192_png_end[]           asm("_binary_icon_192_png_end");
extern const uint8_t icon_512_png_start[]         asm("_binary_icon_512_png_start");
extern const uint8_t icon_512_png_end[]           asm("_binary_icon_512_png_end");
/* Vendored Leaflet (map JS library) for the /map page -- same embedding as
 * the icons above, so the web UI stays self-contained; only the actual map
 * tile images need the internet (see S_MAP_HINT). */
extern const uint8_t leaflet_js_start[]           asm("_binary_leaflet_js_start");
extern const uint8_t leaflet_js_end[]             asm("_binary_leaflet_js_end");
extern const uint8_t leaflet_css_start[]          asm("_binary_leaflet_css_start");
extern const uint8_t leaflet_css_end[]            asm("_binary_leaflet_css_end");
/* Shared page stylesheet, out of the HTML so the browser caches it once
 * instead of re-reading it in the head of every page. */
extern const uint8_t s_css_start[]                asm("_binary_s_css_start");
extern const uint8_t s_css_end[]                  asm("_binary_s_css_end");

static const char TAG[] = "WEBSERVER";

/* snprintf that logs when it truncated: cut markup drops closing tags and the
 * browser swallows the rest of the page; -Wformat-truncation can't see runtime strings. */
#define HTML_PRINTF(buf, ...)                                                  \
    do {                                                                       \
        int _hp_n = snprintf((buf), sizeof(buf), __VA_ARGS__);                 \
        if (_hp_n < 0 || (size_t)_hp_n >= sizeof(buf))                         \
            ESP_LOGE(TAG, "%s:%d: markup truncated, need %d of %u bytes",      \
                     __func__, __LINE__, _hp_n, (unsigned)sizeof(buf));        \
    } while (0)

/* ================================================================== */
/*  Internationalization (i18n) - German default, English optional    */
/* ================================================================== */

typedef enum { LANG_DE = 0, LANG_EN = 1 } lang_t;

/* String IDs */
typedef enum {
    S_NAV_STATUS, S_NAV_MESSAGES, S_NAV_SETTINGS, S_NAV_UPDATE,
    S_TITLE_STATUS, S_TITLE_MESSAGES, S_TITLE_SETTINGS, S_TITLE_UPDATE,
    S_NODEID, S_MAC, S_FW_VERSION, S_SD_CARD, S_UPTIME, S_SNIFFER,
    S_CHANNEL, S_MQTT, S_MSGS_RECEIVED, S_RATE, S_FREE_HEAP, S_FREE_PSRAM, S_TEMPERATURE,
    S_RUNNING, S_STOPPED, S_CONNECTED, S_DISCONNECTED,
    S_START, S_STOP, S_REBOOT, S_REBOOT_CONFIRM, S_REBOOTING, S_REBOOT_SLOW,
    S_REBOOT_DENIED, S_UNSAVED_WARN, S_SAVE_NOCONN,
    S_POWEROFF, S_POWEROFF_CONFIRM, S_POWEROFF_BUSY, S_POWEROFF_OK, S_POWEROFF_FAIL,
    S_POWEROFF_DOWNLOAD,
    S_SNIFFER_LABEL, S_SNIFF_START, S_SNIFF_STOP, S_AUTO_REFRESH,
    S_CONFIRM_NEEDED, S_CONFIRM_NEEDED_NT, S_CONFIRM_BTN, S_CONFIRMED, S_CONFIRM_ERROR,
    S_CONFIRM_AUTH, S_CONFIRM_NOCONN, S_SD_ACTION_FAILED,
    S_MSG_INTRO, S_COL_NUM, S_COL_TIME, S_COL_RSSI, S_COL_LENGTH, S_COL_PREVIEW, S_COL_SENDER,
    S_SET_INTRO, S_MQTT_URI, S_AUTOSTART_CHAN, S_CHAN_NONE,
    S_SET_GROUP_GENERAL, S_SET_GROUP_NETWORK, S_SET_GROUP_MQTT,
    S_SET_GROUP_STORAGE, S_SET_GROUP_SECURITY, S_SET_GROUP_TRAFFIC,
    S_STATS_RETAIN_DAYS, S_EVENT_RETAIN_DAYS,
    S_MAP_STALE_SEC, S_MAP_STALE_HINT, S_MAP_LINE, S_MAP_COURSE, S_MAP_DEST,
    S_MAP_LATE, S_MAP_EARLY, S_MAP_ONTIME, S_EVT_TRAFFIC,
    S_BROADCAST_ONLY, S_BROADCAST_ONLY_HINT,
    S_LED_OVERRIDE, S_LED_OVERRIDE_HINT,
    S_LED_BRIGHTNESS, S_SAVE, S_SAVE_REBOOT, S_SAVED, S_SAVED_REJECTED, S_SET_BAD,
    S_WEB_PASSWORD, S_WEB_PASSWORD_SET, S_WEB_PASSWORD_NONE, S_WEB_PASSWORD_CLEAR,
    S_REFRESH_SEC,
    S_ETH_DHCP, S_ETH_IP, S_ETH_NETMASK, S_ETH_GATEWAY, S_ETH_DNS, S_ETH_NET_NOTE,
    S_ETH_CURRENT, S_ETH_CUR_NOT_UP,
    S_NTP_SERVER, S_COL_TYPE, S_ACTIVITY_TITLE, S_ACTIVITY_SPARK, S_ACTIVITY_TYPES,
    S_ACTIVITY_NONE, S_TYPE_HINT, S_ACTIVITY_SCALE,
    S_LOG_SYS, S_LOG_BUDGET, S_LOG_HINT,
    S_PCAP_ENABLE, S_PCAP_RETAIN_HOURS, S_PCAP_MAX_MB, S_PCAP_HINT,
    S_PCAP_BUF_MB, S_PCAP_BUF_HINT, S_PCAP_FLUSH_SEC,
    S_PLAYBACK_FROM, S_PLAYBACK_TO, S_PLAYBACK_LOAD, S_PLAYBACK_LIVE, S_PLAYBACK_NONE, S_PLAYBACK_ERROR,
    S_PLAYBACK_BUSY, S_PLAYBACK_PARTIAL, S_PLAYBACK_STEP, S_MAP_LAYER_DARK, S_MAP_LAYER_LIGHT, S_MAP_LAYER_TRACKS, S_MAP_LAYER_TRACKS_P, S_MAP_TRACK_PTS, S_UPD_WAIT, S_UPD_FLASHING,
    S_PEERS, S_PEERS_HINT, S_MAP_SEEN_BY, S_UNSAVED,
    S_TRACKS_ENABLE, S_TRACKS_DAYS, S_TRACKS_HINT,
    S_ETH_LEDS, S_ETH_LEDS_HINT,
    S_BT_ENABLE, S_BT_HINT,
    S_PCAP_FILTER, S_PCAP_FILT_ALL, S_PCAP_FILT_THIN, S_PCAP_FILT_VEH, S_PCAP_FILT_HINT,
    S_UPD_INTRO, S_UPLOAD, S_UPLOADING, S_UPLOAD_OK, S_UPLOAD_FAIL, S_UPD_CHOOSE_FILE,
    S_UPD_NOT_CONFIRMED,
    S_NAV_SD, S_TITLE_SD, S_FS_PARTITIONS, S_FS_SDCARD, S_FS_USED, S_FS_MOUNT_AT,
    S_FS_INTERNAL, S_FS_NOTE, S_TAR_SELECTED, S_TAR_NONE, S_TAR_HINT,
    S_SD_DELETE_SELECTED, S_SD_DELETE_SEL_CONFIRM,
    S_RSU_UP_TITLE, S_RSU_UP_HINT, S_RSU_UP_BTN, S_RSU_UP_NOMQTT, S_RSU_UP_RUN,
    S_RSU_UP_THIN, S_RSU_UP_ONCE, S_RSU_UP_BUSY,
    S_SRCH_TITLE, S_SRCH_HINT, S_SRCH_FILTER, S_SRCH_BTN, S_SRCH_RUN,
    S_SRCH_NONE, S_SRCH_LIMIT, S_SRCH_PARTIAL, S_SRCH_EXPORT, S_SRCH_EXPORT_HINT,
    S_SD_NOT_MOUNTED, S_SD_UNMOUNTED_HINT, S_SD_MOUNT, S_SD_USAGE, S_SD_USED_OF,
    S_SD_NAME, S_SD_SIZE, S_SD_EMPTY, S_SD_PARENT, S_SD_DELETE, S_SD_DELETE_CONFIRM,
    S_SD_FORMAT, S_SD_FORMAT_CONFIRM, S_SD_FORMATTING, S_SD_UP_HERE, S_SD_UP_BTN,
    S_PEER_TITLE, S_PEER_NODE, S_PEER_RATE, S_PEER_UPTIME, S_PEER_MQTT,
    S_PEER_OFFLINE, S_PEER_OLDFW, S_PEER_NODATA,
    S_LOSS_TITLE, S_LOSS_SNIFFER, S_LOSS_MQTT, S_LOSS_PCAP, S_LOSS_THINNED,
    S_LOSS_HINT, S_LOSS_BT_PAUSED,
    S_NAV_SYSTEM, S_TITLE_SYSTEM, S_SYS_CHIP, S_SYS_CORES, S_SYS_CPU_FREQ,
    S_SYS_IDF, S_SYS_RESET, S_SYS_FLASH, S_SYS_RAM_INT, S_SYS_RAM_PSRAM,
    S_SYS_TRIPLE, S_SYS_TASKS, S_SYS_COL_STATE, S_SYS_COL_PRIO, S_SYS_COL_CPU,
    S_SYS_COL_STACK,
    S_SYS_GRP_DEVICE, S_SYS_GRP_STABILITY, S_SYS_GRP_LOAD, S_SYS_LOAD,
    S_SYS_CRASH_HINT, S_TH_WARN, S_TH_ALARM,
    S_STAT_BOOTS, S_STAT_CRASHES, S_STAT_LASTCRASH, S_STAT_MAXUP, S_STAT_NEVER,
    S_STAT_RESET, S_STAT_RESET_CONFIRM,
    S_NAV_LOGS, S_TITLE_LOGS, S_LOGS_SYS, S_LOGS_REFRESH,
    S_LOGS_NONE, S_LOGS_TAIL, S_LOGS_OLD, S_LOGS_DOWNLOAD,
    S_LOGS_F_ALL, S_LOGS_F_PROB, S_LOGS_SEARCH, S_LOGS_LINES, S_LOGS_FILTER_HINT,
    S_LOGS_LOADING,
    S_NAV_SENDERS, S_TITLE_SENDERS, S_SND_INTRO, S_SND_NONE, S_SND_ID, S_SND_NAME,
    S_SND_TYPES, S_SND_FRAMES, S_SND_FIRST, S_SND_LAST, S_SND_POS, S_SND_VEHICLES,
    S_SND_FULL, S_SND_CLEAR, S_SND_CLEAR_CONFIRM, S_SND_RSSI,
    S_SND_STATION, S_SND_SINCE,
    S_NAV_TRANSIT, S_TITLE_TRANSIT, S_PT_INTRO, S_PT_NONE, S_PT_LINE,
    S_PT_SIGHTINGS, S_PT_AVG, S_PT_LATE, S_PT_EARLY, S_PT_UNKNOWN, S_PT_LAST,
    S_PT_LIMIT, S_PT_ACTIVE, S_PT_CLEAR, S_PT_CLEAR_CONFIRM,
    S_PT_PASSAGES, S_PT_WHEN, S_PT_COURSE, S_PT_DEST, S_PT_DEV, S_PT_INRANGE,
    S_NAV_TRAFFIC, S_TITLE_TRAFFIC, S_TRF_DAY, S_TRF_SENDERS, S_TRF_SENDERS_NOTE,
    S_TRF_SENDERS_DAY, S_TRF_SG, S_TRF_CYCLES, S_TRF_PH_WAIT, S_TRF_BUSY, S_TRF_IDENT_NOTE, S_TRF_INTRO, S_TRF_WINDOW, S_TRF_W_24H, S_TRF_W_7D,
    S_TRF_W_30D, S_TRF_STATS, S_TRF_TOTAL, S_TRF_HOUR, S_TRF_SPEED, S_TRF_NODATA,
    S_CAT_CAR, S_CAT_BUS, S_CAT_TRUCK, S_CAT_TWOWHEEL, S_CAT_PED, S_CAT_RSU, S_CAT_OTHER,
    S_EVT_TITLE, S_EVT_NONE, S_EVT_TIME, S_EVT_SENDER, S_EVT_WARNING, S_EVT_DENM, S_EVT_MULTI,
    S_TRF_SPEED_BY_TYPE, S_TRF_SPEED_MIXED, S_EVT_CAPPED, S_MAP_TRACK_CAP, S_LOSS_TRACKS,
    S_TRF_JUMP, S_TRF_SILENT, S_TRF_WEAKHOURS, S_TRF_AVAIL_HINT, S_EVT_SHOWPOS,
    S_TRF_LIGHTS, S_TRF_LIGHTS_NONE, S_TRF_INTERSECTION,
    S_TRF_LIGHTS_INTRO, S_TRF_PH_GREEN, S_TRF_PH_AMBER, S_TRF_PH_RED, S_TRF_PH_OTHER,
    S_TRF_PH_REDAMBER, S_TRF_PH_SINCE,
    S_DIR_STRAIGHT, S_DIR_LEFT, S_DIR_RIGHT, S_DIR_UTURN, S_DIR_PED,
    S_NAV_MAP, S_TITLE_MAP, S_MAP_HINT, S_MAP_HELP, S_MAP_LAYER_STREETS, S_MAP_LAYER_SATELLITE,
    S_MAP_DENM,
    S_SYS_COREDUMP, S_SYS_COREDUMP_DOWNLOAD, S_SYS_COREDUMP_CLEAR, S_SYS_COREDUMP_CLEAR_CONFIRM,
    S_LOSS_BT_NOTIFY, S_LOSS_BT_QUEUE, S_LOSS_PASSAGES, S_LOSS_EVENTS,
    S_LOSS_SD_FAILS, S_LOSS_SD_HELD,
    S_EVT_RELAYED, S_EVT_RELAY_VIA, S_EVT_RELAY_UNKNOWN, S_EVT_RELAY_AFTER,
    S_EVT_RELAY_HINT,
    S_EVT_BYHOUR, S_EVT_BYWDAY, S_EVT_PERHOUR, S_EVT_PROFILE_HINT, S_TRF_WDAYS,
    S_PT_HEADWAY, S_PT_HEADWAY_NONE, S_PT_DIR, S_PT_OPS_FIRST, S_PT_OPS_HINT,
    S_MAP_BUSY, S_MAP_TRACK_DUR, S_SINCE_BOOT,
    S_LOSS_SUM, S_PT_OPS_SUM,
    S_HIST_HOUR, S_HIST_TEMP, S_HIST_WAIT, S_HIST_IDLE,
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
    [S_SD_CARD]         = { "SD-Karte",                 "SD card" },
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
    /* &quot;, never an apostrophe: this goes into a single-quoted JS string
     * inside a double-quoted onclick attribute. A bare ' ends the string. */
    [S_REBOOT_SLOW]     = { "Das Ger&auml;t meldet sich nicht. "
                            "<a href=&quot;/&quot;>Seite neu laden</a>",
                            "The device is not answering. "
                            "<a href=&quot;/&quot;>Reload the page</a>" },
    /* These two go into alert()/confirm(): plain text, no entities. */
    [S_REBOOT_DENIED]   = { "Neustart abgelehnt \u2013 Web-Passwort n\u00f6tig.",
                            "Reboot refused - web password required." },
    [S_UNSAVED_WARN]    = { "Es gibt ungespeicherte \u00c4nderungen. Diese gehen beim "
                            "Neustart verloren. Trotzdem neu starten?",
                            "There are unsaved changes. Rebooting discards them. "
                            "Reboot anyway?" },
    /* innerText, so literal UTF-8. A transport failure is not a bad value. */
    [S_SAVE_NOCONN]     = { "Nicht gespeichert \u2013 keine Verbindung zum Ger\u00e4t:",
                            "Not saved - no connection to the device:" },
    [S_POWEROFF]        = { "Zum Ausschalten vorbereiten",
                                                        "Prepare for power-off" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_POWEROFF_CONFIRM]= { "Aufzeichnung sichern und SD-Karte aush\\u00e4ngen? "
                            "Danach zeichnet das Ger\\u00e4t bis zum Neustart nicht mehr auf.",
                            "Save the recording and unmount the SD card? "
                            "The device stops recording afterwards until it is restarted." },
    /* These three are shown via .innerText, which does NOT interpret escapes
     * -- literal UTF-8 here, unlike the confirm() string above. */
    [S_POWEROFF_BUSY]   = { "Puffer werden geschrieben...",
                                                        "Writing buffers..." },
    [S_POWEROFF_OK]     = { "Fertig. Das Gerät kann jetzt vom Strom getrennt werden.",
                            "Done. The device can now be disconnected from power." },
    [S_POWEROFF_FAIL]   = { "Fehlgeschlagen – SD-Karte nicht sauber ausgehängt.",
                            "Failed – the SD card was not cleanly unmounted." },
    [S_POWEROFF_DOWNLOAD] = { "Nicht ausgehängt – ein Download läuft noch. Danach erneut versuchen.",
                              "Not unmounted – a download is still running. Try again afterwards." },
    [S_SNIFFER_LABEL]   = { "Sniffer",                  "sniffer" },
    [S_SNIFF_START]     = { "Sniffer starten",          "Start sniffer" },
    [S_SNIFF_STOP]      = { "Sniffer stoppen",          "Stop sniffer" },
    [S_AUTO_REFRESH]    = { "Aktualisiert automatisch alle 5 Sekunden.",
                            "Auto-refreshing every 5 seconds." },
    [S_CONFIRM_NEEDED]  = { "Diese Firmware wurde per Update installiert und ist noch nicht best&auml;tigt. "
                            "Ohne Best&auml;tigung wird nach 30 Minuten automatisch zur&uuml;ckgerollt.",
                            "This firmware was installed via update and is not yet confirmed. "
                            "Without confirmation it will roll back automatically after 30 minutes." },
    /* No rollback timer running: promising "30 minutes" would be untrue. */
    [S_CONFIRM_NEEDED_NT] = { "Diese Firmware wurde per Update installiert und ist noch nicht "
                              "best&auml;tigt. Solange sie unbest&auml;tigt ist, werden weitere "
                              "Updates abgelehnt.",
                              "This firmware was installed by an update and is not confirmed "
                              "yet. While it stays unconfirmed, further updates are refused." },
    [S_CONFIRM_BTN]     = { "Update jetzt best&auml;tigen", "Confirm update now" },
    /* Sent as a plain-text response and shown via JS alert(); it is not parsed
     * as HTML, so this uses a literal UTF-8 "ä" (served with charset=utf-8)
     * rather than the &auml; entity. */
    [S_CONFIRMED]       = { "Bestätigt. Rollback abgebrochen.",
                            "Confirmed. Rollback cancelled." },
    /* Shown via alert(t) after fetch('/confirm').then(r=>r.text()) if
     * ota_confirm() itself fails (very rare -- was hardcoded English before). */
    [S_CONFIRM_ERROR]   = { "Fehler beim Bestätigen.", "Error confirming." },
    /* alert() texts: literal UTF-8, no apostrophes (they sit in a JS string).
     * No route named -- the browser may prompt for the password itself. */
    [S_CONFIRM_AUTH]    = { "Anmeldung nötig. Bitte mit dem Web-Passwort anmelden "
                            "und erneut bestätigen.",
                            "Sign-in required. Please sign in with the web password "
                            "and confirm again." },
    [S_CONFIRM_NOCONN]  = { "Bestätigung nicht gesendet – keine Verbindung zum Gerät.",
                            "Confirmation not sent – no connection to the device." },
    [S_SD_ACTION_FAILED] = { "Der Vorgang ist fehlgeschlagen.",
                             "The operation failed." },
    [S_MSG_INTRO]       = { "Die letzten %d empfangenen Frames, neueste zuerst, mit dem was sich "
                            "aus jedem dekodieren lie&szlig;.",
                            "Last %d received frames, newest first, with whatever could be decoded "
                            "from each." },
    [S_COL_NUM]         = { "#",                        "#" },
    [S_COL_TIME]        = { "Zeit",                     "Time" },
    [S_COL_RSSI]        = { "RSSI",                     "RSSI" },
    [S_COL_SENDER]      = { "Absender",                 "Sender" },
    [S_COL_LENGTH]      = { "L&auml;nge",               "Length" },
    [S_COL_PREVIEW]     = { "Details",                  "Details" },
    [S_SET_INTRO]       = { "&Auml;nderungen liegen im NVS. Die meisten wirken sofort, einzelne erst nach einem Neustart.",
                            "Changes live in NVS. Most take effect at once, a few only after a reboot." },
    [S_MQTT_URI]        = { "MQTT-URI",                 "MQTT URI" },
    [S_AUTOSTART_CHAN]  = { "Autostart-Kanal",          "Autostart channel" },
    [S_CHAN_NONE]       = { "(keiner)",                 "(none)" },
    [S_SET_GROUP_GENERAL] = { "Allgemein",              "General" },
    [S_SET_GROUP_NETWORK] = { "Netzwerk",               "Network" },
    [S_SET_GROUP_MQTT]    = { "MQTT",                   "MQTT" },
    [S_SET_GROUP_STORAGE] = { "Speicher (SD)",          "Storage (SD)" },
    [S_SET_GROUP_TRAFFIC] = { "Verkehr-Seite",          "Traffic page" },
    [S_STATS_RETAIN_DAYS] = { "Statistik-Aufbewahrung (Tage)",  "Statistics retention (days)" },
    [S_EVENT_RETAIN_DAYS] = { "Warnungs-Aufbewahrung (Tage)",   "Warning-log retention (days)" },
    [S_MAP_STALE_SEC]   = { "Karte: Marker-Standzeit (s)", "Map: marker hold time (s)" },
    [S_MAP_STALE_HINT]  = { "Wie lange ein Sender ohne neue Nachricht auf der Karte bleibt.",
                            "How long a sender stays on the map without a new message." },
    [S_SET_GROUP_SECURITY]= { "Sicherheit",             "Security" },
    [S_BROADCAST_ONLY]  = { "Nur Broadcast erfassen",   "Capture broadcast only" },
    [S_BROADCAST_ONLY_HINT] = { "Aus: erfasst auch Unicast-Frames (deutlich mehr Datenaufkommen).",
                                "Off: also captures unicast frames (significantly more traffic)." },
    [S_LED_OVERRIDE]     = { "Feste LED-Farbe",          "Fixed LED color" },
    [S_LED_OVERRIDE_HINT] = { "&Uuml;bersteuert die normale Status-Anzeige. Schwarz = normales Verhalten (aus).",
                              "Overrides the normal status indication. Black = normal behaviour (off)." },
    [S_LED_BRIGHTNESS]  = { "LED-Helligkeit",           "LED brightness" },
    [S_SAVE]            = { "Speichern",                "Save" },
    [S_SAVE_REBOOT]     = { "Speichern &amp; Neustart",  "Save &amp; reboot" },
    [S_UNSAVED]         = { "Nicht gespeicherte &Auml;nderungen",
                            "Unsaved changes" },
    [S_SAVED]           = { "%d Einstellung(en) gespeichert.", "Saved %d setting(s)." },
    /* Rendered via textContent, so plain UTF-8 -- no entities. */
    [S_SET_BAD]         = { "Nicht gespeichert, Wert außerhalb des Bereichs:",
                            "Not saved, value out of range:" },
    /* Silently dropping an out-of-range value while reporting success is how a
     * setting appears to "reset itself" -- the page has to say it refused. */
    /* Goes out as text/plain, which decodes NO entities -- literal UTF-8 here,
     * like S_UPD_NOT_CONFIRMED and unlike the rest of this table. */
    [S_SAVED_REJECTED]  = { "%d gespeichert, %d abgelehnt: Wert außerhalb des erlaubten Bereichs "
                            "(siehe Min/Max beim Feld).",
                            "%d saved, %d rejected: value outside the allowed range "
                            "(see the field's min/max)." },
    [S_WEB_PASSWORD]    = { "Web-Passwort (Benutzer &quot;admin&quot;)",
                            "Web password (user &quot;admin&quot;)" },
    [S_WEB_PASSWORD_SET]  = { "gesetzt &ndash; leer lassen = unver&auml;ndert",
                              "set &ndash; leave empty to keep unchanged" },
    /* Names what check_update_auth() really gates -- naming only /update and
     * /settings hid that without a password the whole card, the internal
     * filesystem and the exports are readable by anyone on the network. */
    [S_WEB_PASSWORD_NONE] = { "kein Passwort &ndash; sch&uuml;tzt Einstellungen, Firmware-Update "
                              "und alle Datei-Zugriffe (SD, Flash, Logs, Export)",
                              "no password &ndash; protects settings, firmware update "
                              "and all file access (SD, flash, logs, export)" },
    [S_WEB_PASSWORD_CLEAR] = { "Passwortschutz entfernen",
                               "Remove password protection" },
    [S_REFRESH_SEC]     = { "Auto-Refresh (Sek., 0=aus)", "Auto-refresh (sec, 0=off)" },
    [S_ETH_DHCP]        = { "DHCP (IP automatisch)",     "DHCP (automatic IP)" },
    [S_ETH_IP]          = { "IP-Adresse",               "IP address" },
    [S_ETH_NETMASK]     = { "Subnetzmaske",             "Subnet mask" },
    [S_ETH_GATEWAY]     = { "Gateway",                  "Gateway" },
    [S_ETH_DNS]         = { "DNS-Server (1/2/3)",       "DNS servers (1/2/3)" },
    [S_ETH_NET_NOTE]    = { "Netzwerk-&Auml;nderungen wirken erst nach einem Neustart. "
                           "DHCP aus = feste IP, dann IP/Maske/Gateway ausf&uuml;llen. "
                           "DNS optional, gilt auch bei DHCP.",
                           "Network changes take effect after a reboot. "
                           "DHCP off = static IP, then fill in IP/mask/gateway. "
                           "DNS is optional and also applies with DHCP." },
    [S_ETH_CURRENT]     = { "Aktuell bezogen",           "Currently in use" },
    [S_ETH_CUR_NOT_UP]  = { "(keine IP &ndash; Kabel/Link pr&uuml;fen)",
                           "(no IP yet &ndash; check cable/link)" },
    [S_NTP_SERVER]      = { "NTP-Server",                "NTP server" },
    [S_COL_TYPE]        = { "Typ",                       "Type" },
    [S_ACTIVITY_TITLE]  = { "Aktivit&auml;t",            "Activity" },
    [S_ACTIVITY_SPARK]  = { "Letzte Minute",            "Last minute" },
    [S_HIST_HOUR]       = { "Letzte Stunde",            "Last hour" },
    [S_HIST_TEMP]       = { "Temperatur, letzte Stunde",
                            "Temperature, last hour" },
    /* Not S_ACTIVITY_NONE: an empty ring right after a boot is not the same
     * statement as an hour in which nothing arrived. */
    [S_HIST_WAIT]       = { "noch keine volle Minute",
                            "less than a minute of history" },
    /* Not "none yet": the hour is empty, the counter above it is not.
     * Goes to textContent, so plain UTF-8 and no entities. */
    [S_HIST_IDLE]       = { "in dieser Stunde nichts empfangen",
                            "nothing received this hour" },
    /* Two sinks: an HTML chunk AND a single-quoted JS literal set via
     * textContent -- so no apostrophes, no umlauts, no entities. */
    [S_ACTIVITY_SCALE]  = { "Skala bis",                "scale to" },
    [S_ACTIVITY_TYPES]  = { "Nachrichtentypen seit dem Einschalten",
                            "Message types since power-on" },
    /* Detail line under the message counter; a substring of S_ACTIVITY_TYPES
     * on purpose, so both name the same period in the same words. */
    [S_SINCE_BOOT]      = { "seit dem Einschalten",      "since power-on" },
    [S_ACTIVITY_NONE]   = { "(noch keine Nachrichten)",  "(no messages yet)" },
    [S_TYPE_HINT]       = { "Typ = Absender + Nachricht. Absender: Car, Bus, Ped, Tram, "
                            "RSU (Stra&szlig;enrand-Einheit, z.B. Ampel). Nachricht: CAM=Fahrzeug-Status, "
                            "DENM=Warnung, SPATEM=Ampelphase, MAPEM=Kreuzungskarte, IVIM=Verkehrszeichen, "
                            "CPM=Umfeldwahrnehmung. &bdquo;Signed&ldquo;=signiert, Inhalt nicht ausgepackt. "
                            "&bdquo;?&ldquo;=kein ETSI-Inhalt.",
                            "Type = sender + message. Sender: Car, Bus, Ped, Tram, RSU (roadside unit, "
                            "e.g. a traffic light). Message: CAM=vehicle status, DENM=hazard warning, "
                            "SPATEM=signal phase/timing, MAPEM=intersection map, IVIM=road signs, "
                            "CPM=perceived objects. \"Signed\"=signed, content not unwrapped. "
                            "\"?\"=no ETSI payload." },
    [S_LOG_SYS]         = { "System-Log auf SD",        "System log to SD" },
    [S_LOG_BUDGET]      = { "Log-Speicher-Budget (MB)", "Log storage budget (MB)" },
    [S_LOG_HINT]        = { "Logs unter /sdcard/logs/, rotierend. Braucht eine eingebundene SD-Karte.",
                            "Logs in /sdcard/logs/, rotating. Requires a mounted SD card." },
    [S_PCAP_ENABLE]       = { "Rollierende PCAP-Aufzeichnung auf SD", "Rolling PCAP capture to SD" },
    [S_PCAP_RETAIN_HOURS] = { "PCAP-Aufbewahrung (Std.)",             "PCAP retention (hours)" },
    [S_PCAP_MAX_MB]       = { "PCAP-Speicher-Obergrenze (MB)",        "PCAP storage ceiling (MB)" },
    [S_PCAP_HINT]         = { "Rohe 802.11-Frames unter /sdcard/pcap/, stündlich rotierend, mit tshark/Wireshark lesbar. Braucht eine eingebundene SD-Karte.",
                              "Raw 802.11 frames in /sdcard/pcap/, rotating hourly, readable with tshark/Wireshark. Requires a mounted SD card." },
    [S_PCAP_BUF_MB]       = { "PCAP-RAM-Puffer (MB)",                "PCAP RAM buffer (MB)" },
    [S_PCAP_BUF_HINT] = { "Frames sammeln sich erst im PSRAM und gehen dann in einem Rutsch "
                          "auf die Karte, statt einzeln &uuml;ber den (mit Ethernet geteilten) "
                          "SD-Bus. Wirkt erst nach einem Neustart.",
                          "Frames gather in PSRAM first and then go to the card in one go, "
                          "instead of one at a time over the (Ethernet-shared) SD bus. Takes "
                          "effect after a reboot." },
    [S_PCAP_FLUSH_SEC]    = { "Sp&auml;testens schreiben nach (Sek.)", "Flush to SD at least every (sec)" },
    [S_PLAYBACK_FROM]   = { "Von",                       "From" },
    [S_PLAYBACK_TO]     = { "bis",                       "to" },
    [S_PLAYBACK_LOAD]   = { "Laden",                     "Load" },
    [S_PLAYBACK_LIVE]   = { "Live",                      "Live" },
    [S_PLAYBACK_NONE]   = { "Keine Positionsdaten (CAM) in diesem Zeitraum gefunden.",
                            "No position data (CAM) found in this time range." },
    [S_PLAYBACK_ERROR]  = { "Fehler beim Laden.", "Error loading." },
    /* Rendered via textContent, so no HTML entities here -- they would show
     * up literally as "&hellip;" instead of an ellipsis. */
    [S_PLAYBACK_BUSY]   = { "Lese von SD-Karte ...", "Reading from SD card ..." },
    [S_PLAYBACK_PARTIAL] = { "Zeitraum nur teilweise gelesen (SD-Karte war belegt).",
                             "Period only partly read (SD card was busy)." },
    [S_PLAYBACK_STEP]   = { "Schritt",                   "Step" },
    [S_MAP_LAYER_DARK]  = { "Dunkel",                    "Dark" },
    [S_MAP_LAYER_LIGHT] = { "Hell",                      "Light" },
    [S_MAP_LAYER_TRACKS]= { "Fahrspuren",                "Vehicle tracks" },
    /* Only offered when other receivers are configured -- see MAP_SCRIPT. */
    [S_MAP_LAYER_TRACKS_P]= { "Fahrspuren anderer Empf&auml;nger",
                                                         "Other receivers' tracks" },
    [S_MAP_TRACK_PTS]   = { "Punkte",                    "points" },
    /* Goes to the map via textContent, which does NOT decode HTML entities --
     * plain UTF-8 here, unlike every other entry in this table. */
    [S_MAP_TRACK_CAP]   = { "Spuren gekürzt – die ältesten Punkte des Zeitraums fehlen",
                            "tracks shortened – the oldest points of the period are missing" },
    [S_MAP_SEEN_BY]     = { "empfangen von",             "received by" },
    [S_MAP_TRACK_DUR]   = { "Dauer",                     "duration" },
    /* Shown via alert(), which does NOT decode entities -- plain UTF-8, and no
     * apostrophe, because it travels as a JS string literal. */
    [S_MAP_BUSY]        = { "Ein anderer Abruf läuft gerade. Bitte gleich noch einmal einschalten.",
                            "Another transfer is running. Switch the layer on again in a moment." },
    [S_PEERS]           = { "Weitere Empf&auml;nger",    "Other receivers" },
    [S_PEERS_HINT]  = { "Hostnamen oder IP-Adressen weiterer Empf&auml;nger, mit Komma "
                        "getrennt &ndash; z.&nbsp;B. <code>its-node344.local, "
                        "192.168.178.40</code>. Deren Fahrzeuge erscheinen zus&auml;tzlich auf "
                        "dieser Karte; jedes Ger&auml;t zeigt genau die, die bei ihm "
                        "eingetragen sind. Abgefragt wird vom Browser, nicht vom Ger&auml;t "
                        "&ndash; dein Browser muss die anderen also erreichen k&ouml;nnen.",
                        "Host names or IP addresses of other receivers, comma-separated "
                        "&ndash; e.g. <code>its-node344.local, 192.168.178.40</code>. Their "
                        "vehicles also appear on this map; every device shows exactly the ones "
                        "listed on it. The browser does the fetching, not the device &ndash; "
                        "so your browser has to be able to reach the others." },
    /* Set via innerText -- plain text, no HTML entities. */
    [S_UPD_WAIT]        = { "warte auf Neustart",        "waiting for reboot" },
    /* innerText/textContent -- plain text, no HTML entities. */
    [S_UPD_FLASHING]    = { "Geraet schreibt die Firmware ...",
                            "Device is writing the firmware ..." },
    /* Each option states what is recorded IN FULL, not just what gets
     * thinned -- named only after its exception, the middle one read as if
     * it might drop everything else too. */
    [S_PCAP_FILTER]     = { "Umfang der Aufzeichnung",   "What gets recorded" },
    [S_PCAP_FILT_ALL]   = { "alles, ungek&uuml;rzt",     "everything, in full" },
    [S_PCAP_FILT_THIN]  = { "alles &ndash; Ampelmeldungen h&ouml;chstens 1&times;/s <b>insgesamt</b>",
                            "everything &ndash; traffic-light messages at most once a second "
                            "<b>in total</b>" },
    [S_PCAP_FILT_VEH]   = { "alles au&szlig;er Ampelphasen und Kreuzungskarten",
                            "everything except signal phases and intersection maps" },
    [S_PCAP_FILT_HINT] = { "Eine einzige Ampel macht 85&nbsp;% der Aufzeichnung aus, sie "
                           "wiederholt sich zehnmal pro Sekunde. Gemessen: 14,3 / 3,4 / "
                           "0,04&nbsp;MB/h. Die Frames bleiben unver&auml;ndert und "
                           "vollst&auml;ndig, nur Wiederholungen fallen weg. <b>Wichtig:</b> "
                           "die Grenze gilt je Nachrichtenart &uuml;ber ALLE Ampeln zusammen "
                           "&ndash; bei zwei Kreuzungen in Reichweite steht pro Sekunde nur "
                           "eine im Archiv. Wer jede l&uuml;ckenlos braucht, nimmt "
                           "&bdquo;alles, ungek&uuml;rzt&ldquo;.",
                           "A single traffic light makes up 85% of the recording, repeating "
                           "itself ten times a second. Measured: 14.3 / 3.4 / 0.04&nbsp;MB/h. "
                           "Frames stay unaltered and complete, only repeats are skipped. "
                           "<b>Note:</b> the limit applies per message kind across ALL traffic "
                           "lights &ndash; with two intersections in range only one makes it "
                           "into the archive each second. Pick \"everything, in "
                           "full\" if you need every light without gaps." },
    [S_TRACKS_ENABLE]   = { "Fahrspuren aufzeichnen",    "Record vehicle tracks" },
    [S_TRACKS_DAYS]     = { "Fahrspuren aufbewahren (Tage)", "Keep tracks for (days)" },
    [S_TRACKS_HINT]     = { "Zeichnet auf, wo Fahrzeuge tats&auml;chlich gefahren sind, und blendet "
                            "es auf der Karte als zuschaltbare Ebene ein. Sehr sparsam &ndash; rund "
                            "150 Punkte pro Stunde, gut 150 KB am Tag. Beginnt bei null: "
                            "&auml;ltere Fahrten aus der PCAP-Aufzeichnung fehlen. Die Karte "
                            "zeichnet h&ouml;chstens 26.000 Punkte je Abfrage.",
                            "Records where vehicles actually drove and shows it on the map as a "
                            "switchable layer. Light &ndash; about 150 points an hour, some 150 KB a day. "
                            "Starts empty: earlier journeys from the PCAP recordings are missing. "
                            "The map draws at most 26,000 points per request." },
    [S_ETH_LEDS]        = { "Netzwerk-LEDs",             "Network LEDs" },
    [S_ETH_LEDS_HINT] = { "Die zwei LEDs an der Netzwerkbuchse zeigen Verbindung und "
                          "Datenverkehr. Abschalten st&ouml;rt den Betrieb nicht, nur die "
                          "Verbindung ist dann am Ger&auml;t nicht mehr ablesbar. Wirkt "
                          "sofort.",
                          "The two LEDs on the network socket show link and traffic. Switching "
                          "them off does not affect operation, it only makes the link state "
                          "unreadable on the device. Applies at once." },
    [S_BT_ENABLE]       = { "Bluetooth",                 "Bluetooth" },
    /* The two percentages are duty cycles -- recompute from s_cycle_ms and the
     * slicing constants in bt_stream.c. Loss starts at BT on, not at connect. */
    [S_BT_HINT]         = { "Wirkt erst nach einem Neustart. BLE teilt sich das Funkteil mit dem "
                            "5,9-GHz-Empfang: ab dem Einschalten gehen rund 25&nbsp;% der Frames "
                            "verloren, w&auml;hrend ein Handy verbunden ist rund 48&nbsp;%. Die "
                            "Aufzeichnung auf SD und MQTT l&auml;uft weiter, nur mit L&uuml;cken.",
                            "Takes effect only after a restart. BLE shares the radio with the "
                            "5.9 GHz reception: from the moment it is on about 25&nbsp;% of frames "
                            "are lost, and about 48&nbsp;% while a phone is connected. Recording "
                            "to SD and MQTT keeps running, just with gaps." },
    [S_UPD_INTRO]   = { "Firmware-Datei (.bin) w&auml;hlen und hochladen. Das Ger&auml;t "
                        "flasht sie auf die inaktive OTA-Partition und startet neu. Danach im "
                        "Status best&auml;tigen, sonst wird zur&uuml;ckgerollt.",
                        "Pick a firmware file (.bin) and upload it. The device flashes it to "
                        "the inactive OTA partition and reboots. Confirm it on the status page "
                        "afterwards, or it is rolled back." },
    /* Deliberately says "flash" not just "upload" -- the button triggers an
     * immediate flash + reboot in one step, no separate "apply" step, and
     * that's easy to miss if it only said "Upload" (people click buttons
     * without reading the paragraph above them). */
    [S_UPLOAD]          = { "Hochladen &amp; flashen",   "Upload &amp; flash" },
    /* S_UPLOADING is injected into JS and shown via innerText, which does NOT
     * decode HTML entities. Use a JS \u escape (not &auml;) so it renders. */
    [S_UPLOADING]       = { "L\\u00e4dt hoch...",       "Uploading..." },
    /* Same JS \u-escape reasoning as S_UPLOADING (this one is shown via
     * alert(), which also doesn't decode HTML entities). Was hardcoded
     * English before, showing "choose a file first" even in German. */
    [S_UPD_CHOOSE_FILE] = { "Bitte zuerst eine Datei w\\u00e4hlen",
                            "Please choose a file first" },
    [S_UPLOAD_OK]       = { "OK, erfolgreich geflasht. Neustart...",
                            "OK, flashed successfully. Rebooting..." },
    [S_UPLOAD_FAIL]     = { "Upload fehlgeschlagen (Verbindungsfehler)",
                            "Upload failed (connection error)" },
    /* Hit when a new OTA is attempted while the running app is still
     * unconfirmed (ESP-IDF refuses by design). Shown via .innerText, so
     * literal UTF-8 umlauts, not &auml;-style entities. */
    [S_UPD_NOT_CONFIRMED] = { "Update nicht möglich: Die aktuell laufende Firmware ist noch nicht "
                              "bestätigt. Bitte zuerst auf der Status-Seite bestätigen (oder "
                              "zurückrollen), bevor ein neues Update gemacht wird.",
                              "Update not possible: the currently running firmware hasn't been confirmed "
                              "yet. Please confirm it (or roll it back) on the status page before "
                              "attempting another update." },
    [S_NAV_SD]          = { "Dateiverwaltung",          "Files" },
    [S_TITLE_SD]        = { "Dateiverwaltung",          "File management" },
    [S_FS_PARTITIONS]   = { "Flash-Partitionen",        "Flash partitions" },
    [S_FS_SDCARD]       = { "SD-Karte",                 "SD card" },
    [S_FS_USED]         = { "belegt",                   "used" },
    [S_FS_MOUNT_AT]     = { "eingebunden unter",        "mounted at" },
    [S_FS_INTERNAL]     = { "Interner Speicher",        "Internal storage" },
    [S_FS_NOTE]     = { "Nur &bdquo;storage&ldquo; (/data) und die SD-Karte sind Dateisysteme "
                        "mit Ordnern. Die &uuml;brigen Partitionen sind Rohbereiche (nvs = "
                        "Einstellungen, ota_* = Firmware) und nur als Roh-Abbild ladbar.",
                        "Only \"storage\" (/data) and the SD card are file systems "
                        "with folders. The other partitions are raw areas (nvs = settings, "
                        "ota_* = firmware) and can only be downloaded as a raw image." },
    [S_TAR_SELECTED]    = { "Auswahl (.tar)",           "Selection (.tar)" },
    [S_TAR_NONE]        = { "Nichts markiert.",         "Nothing selected." },
    [S_TAR_HINT]        = { "Gr&ouml;&szlig;ere Downloads dauern mehrere Minuten. Die Oberfl&auml;che "
                             "bleibt bedienbar; weitere Downloads laufen nacheinander, bei "
                             "Andrang kommt eine Absage.",
                             "Larger downloads take several minutes. The UI stays usable; further "
                             "downloads run one after another, and are refused when too many pile up." },
    [S_SD_NOT_MOUNTED]  = { "Keine SD-Karte eingebunden.", "No SD card mounted." },
    [S_SD_UNMOUNTED_HINT] = { "L&auml;sst sich eine steckende Karte nicht einbinden, ist sie "
                              "vermutlich nicht FAT (fabrikneue &uuml;ber 32&nbsp;GB kommen "
                              "als exFAT) &ndash; einmal formatieren richtet sie ein.",
                              "If a card is inserted but cannot be mounted, it is probably not "
                              "FAT (factory-fresh cards above 32&nbsp;GB come as exFAT) "
                              "&ndash; formatting once sets it up." },
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
    [S_SD_DELETE_SELECTED] = { "Auswahl l&ouml;schen",  "Delete selection" },
    /* Used inside a JS confirm() call, not HTML text -- raw UTF-8, not HTML
     * entities (script-tag content isn't HTML-entity-decoded by the
     * browser), same as the existing S_SD_DELETE_CONFIRM right above. */
    [S_SD_DELETE_SEL_CONFIRM] = { "Ausgewählte Dateien/Ordner löschen?",
                                  "Delete selected files/folders?" },
    [S_RSU_UP_TITLE]    = { "Standortfeste Sender nachliefern", "Re-send stationary transmitters" },
    [S_RSU_UP_HINT] = { "Sendet Ampeln und RSUs aus der PCAP-Aufzeichnung des gew&auml;hlten "
                        "Zeitraums (h&ouml;chstens 24&nbsp;h) nachtr&auml;glich an "
                        "opentrafficmap &ndash; z.&nbsp;B. was w&auml;hrend eines Ausfalls "
                        "ankam. Fahrzeuge nie. Die Ausd&uuml;nnung gilt je Station und "
                        "Nachrichtentyp; f&uuml;r den Karteneintrag reicht die Voreinstellung.",
                        "Re-sends traffic lights and RSUs from the PCAP recording of the "
                        "chosen period (24&nbsp;h at most) to opentrafficmap &ndash; e.g. what "
                        "arrived during an outage. Never vehicles. The thinning applies per "
                        "station and message kind; the default is enough for the map entry." },
    [S_RSU_UP_THIN]     = { "Ausd&uuml;nnung",           "Thinning" },
    [S_RSU_UP_ONCE]     = { "1 Frame je Station u. Typ", "1 frame per station &amp; type" },
    [S_RSU_UP_BTN]      = { "An opentrafficmap senden",  "Send to opentrafficmap" },
    [S_RSU_UP_NOMQTT]   = { "MQTT ist nicht verbunden – nichts gesendet.",
                            "MQTT is not connected – nothing sent." },
    [S_RSU_UP_RUN]      = { "Sende…",               "Sending…" },
    [S_RSU_UP_BUSY]     = { "Läuft bereits.",        "Already running." },
    [S_SRCH_TITLE]      = { "Suche in der Aufzeichnung", "Search the recording" },
    [S_SRCH_HINT]       = { "Durchsucht die PCAP-Aufzeichnung des Zeitraums (h&ouml;chstens 24 h). "
                            "Der Filter wirkt auf Typ, Absender-Adresse und Stations-Nummer. "
                            "RSSI steht nicht in der Aufzeichnung, die Spalte bleibt ein Strich.",
                            "Searches the PCAP recording of the chosen period (24 h at most). "
                            "The filter matches type, sender address and station id. "
                            "RSSI is not part of the recording, the column stays a dash." },
    [S_SRCH_FILTER]     = { "Filter",                   "Filter" },
    [S_SRCH_BTN]        = { "Suchen",                   "Search" },
    [S_SRCH_RUN]        = { "Suche…",                   "Searching…" },
    [S_SRCH_NONE]       = { "Keine Treffer.",           "No matches." },
    [S_SRCH_LIMIT]      = { "Limit von 200 Treffern erreicht &ndash; Zeitraum oder Filter eingrenzen.",
                            "Hit the 200-match limit &ndash; narrow the period or filter." },
    [S_SRCH_PARTIAL]    = { "Zeitraum nur teilweise gelesen.", "Period only partly read." },
    [S_SRCH_EXPORT]     = { "Als PCAP laden",              "Download as PCAP" },
    [S_SRCH_EXPORT_HINT] = { "H&ouml;chstens 4&nbsp;MB; reicht das nicht, steht "
                             "&bdquo;GEKUERZT&ldquo; im Dateinamen, bei l&uuml;ckenhaftem "
                             "Lesen &bdquo;teilweise&ldquo;. Ganze Stunden liegen ohnehin "
                             "unter /sdcard/pcap/. Braucht das Web-Passwort.",
                             "4&nbsp;MB at most; beyond that the file name says "
                             "\"GEKUERZT\", and \"teilweise\" if the read "
                             "had gaps. Whole hours are under /sdcard/pcap/ anyway. Needs the "
                             "web password." },
    [S_SD_FORMAT]       = { "Karte formatieren",        "Format card" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SD_FORMAT_CONFIRM] = { "Karte wirklich formatieren? Alle Daten gehen verloren!",
                              "Really format the card? All data will be lost!" },
    /* Set via JS innerText -> JS \u escape, no HTML entity. */
    [S_SD_FORMATTING]   = { "Formatiere\\u2026",        "Formatting\\u2026" },
    [S_SD_UP_HERE]      = { "Datei hierher hochladen",  "Upload a file here" },
    [S_SD_UP_BTN]       = { "Hochladen",                "Upload" },
    [S_PEER_TITLE]      = { "Andere Empf&auml;nger",    "Other receivers" },
    [S_PEER_NODE]       = { "Knoten",                   "Node" },
    [S_PEER_RATE]       = { "Rate (letzte 60s)",        "Rate (last 60s)" },
    [S_PEER_UPTIME]     = { "Laufzeit",                 "Uptime" },
    [S_PEER_MQTT]       = { "MQTT",                     "MQTT" },
    [S_PEER_OFFLINE]    = { "nicht erreichbar",         "unreachable" },
    /* Single-quoted JS literal concatenated into innerHTML: no apostrophes. */
    [S_PEER_NODATA]     = { "keine Daten seit",         "no data for" },
    [S_PEER_OLDFW]      = { "antwortet, aber nicht mit Statusdaten &ndash; alte Firmware, "
                            "Passwortschutz oder ein fremder Server",
                            "answers, but not with status data &ndash; old firmware, password "
                            "protection or some other server" },
    [S_LOSS_TITLE]      = { "Verluste seit dem Start",  "Losses since boot" },
    [S_LOSS_SNIFFER]    = { "Empfangspuffer voll oder kein Speicher",
                            "Receive queue full or out of memory" },
    [S_LOSS_MQTT]       = { "MQTT-Warteschlange voll",  "MQTT queue full" },
    [S_LOSS_TRACKS]     = { "Fahrspur-Punkte verworfen",
                            "Track points discarded" },
    /* "(gesch&auml;tzt)": of sdpcap's drop sources only the hour-boundary give-up
     * is byte-derived (buffered BYTES / measured average record size); oversize
     * and starved-ring drops are exact frame counts like the rows above. */
    [S_LOSS_PCAP]       = { "Aufzeichnung verloren (gesch&auml;tzt)",
                            "Recording lost (estimated)" },
    [S_LOSS_THINNED]    = { "Bewusst ausged&uuml;nnt",  "Thinned on purpose" },
    /* Sits in the loss table but is a duration, not a count -- said in the row
     * label AND in the hint, because the table around it counts frames. */
    [S_LOSS_BT_PAUSED]  = { "Empfang pausiert (Dauer)", "Reception paused (duration)" },
    [S_LOSS_BT_NOTIFY]  = { "BLE-Meldungen verworfen",  "BLE notifications dropped" },
    [S_LOSS_BT_QUEUE]   = { "BLE-Warteschlange voll",   "BLE queue full" },
    [S_LOSS_PASSAGES]   = { "Durchfahrtszeilen verloren", "Passage rows lost" },
    [S_LOSS_EVENTS]     = { "Warnungen verdr&auml;ngt", "Warnings displaced" },
    [S_LOSS_SD_FAILS]   = { "SD: l&auml;ngste Fehlserie", "SD: longest failure run" },
    [S_LOSS_SD_HELD]    = { "SD: l&auml;ngste Haltezeit", "SD: longest hold" },
    [S_LOSS_HINT]       = { "Die Werte z&auml;hlen Frames seit dem Einschalten, nur die Pausenzeile "
                            "ist eine Dauer (Empfang angehalten, w&auml;hrend Bluetooth funkte); "
                            "bei der Aufzeichnung "
                            "ist der Wert gesch&auml;tzt, weil dort ganze Puffer auf einmal verworfen "
                            "werden. Ausged&uuml;nnte sind "
                            "kein Fehler, sondern die eingestellte Filterung. Steigen die &uuml;brigen, "
                            "kommt das Ger&auml;t nicht nach &ndash; SD-Karte, Netzwerk oder Speicher. "
                            "Die beiden SD-Zeilen sind H&ouml;chstst&auml;nde seit dem Einschalten, "
                            "keine Momentanwerte: der laufende Wert ist fast immer 0, weil jeder "
                            "gegl&uuml;ckte Zugriff ihn zur&uuml;cksetzt.",
                            "The values count frames since power-on, only the pause row is a duration "
                            "(reception halted while Bluetooth was on air); "
                            "the recording row is an estimate, "
                            "because whole buffers are discarded there at once. "
                            "Thinned ones are not an error but "
                            "the configured filtering. If the others keep rising, the device is not "
                            "keeping up &ndash; SD card, network or memory. "
                            "The two SD rows are peaks since power-on, not current values: the "
                            "live figure is almost always 0 because every successful access "
                            "clears it." },
    /* Names both halves on purpose: a bare "Details" would hide that the
     * legend for the "thinned" row is what sits inside. */
    [S_LOSS_SUM]        = { "Was die Zahlen bedeuten und welche Zeilen keine Fehler sind",
                            "What the figures mean, and which rows are not faults" },
    [S_NAV_SYSTEM]      = { "System",                   "System" },
    [S_TITLE_SYSTEM]    = { "System-Info",              "System info" },
    [S_SYS_CHIP]        = { "Chip",                     "Chip" },
    [S_SYS_CORES]       = { "Kerne",                    "Cores" },
    [S_SYS_CPU_FREQ]    = { "CPU-Takt",                 "CPU clock" },
    [S_SYS_IDF]         = { "ESP-IDF",                  "ESP-IDF" },
    [S_SYS_RESET]       = { "Letzter Reset",            "Last reset" },
    [S_SYS_FLASH]       = { "Flash",                    "Flash" },
    [S_SYS_RAM_INT]     = { "RAM intern",              "RAM internal" },
    [S_SYS_RAM_PSRAM]   = { "PSRAM",                    "PSRAM" },
    [S_SYS_TRIPLE]      = { "frei / min / gesamt",      "free / min / total" },
    [S_SYS_TASKS]       = { "Tasks",                    "Tasks" },
    [S_SYS_COL_STATE]   = { "Status",                   "State" },
    [S_SYS_COL_PRIO]    = { "Prio",                     "Prio" },
    [S_SYS_COL_CPU]     = { "CPU %",                    "CPU %" },
    [S_SYS_COL_STACK]   = { "Stack frei (min)",         "Stack free (min)" },
    [S_SYS_GRP_DEVICE]  = { "Ger&auml;t",               "Device" },
    [S_SYS_GRP_STABILITY] = { "Stabilit&auml;t",        "Stability" },
    [S_SYS_GRP_LOAD]    = { "Auslastung",               "Load" },
    [S_SYS_LOAD]        = { "CPU-Last",                 "CPU load" },
    /* Without this the crash count reads as "crashing right now". */
    [S_SYS_CRASH_HINT]  = { "Die Z&auml;hler laufen seit dem letzten Zur&uuml;cksetzen, "
                            "nicht seit dem letzten Neustart &ndash; ein alter Absturz "
                            "bleibt in der Zahl stehen. Das Datum daneben sagt, wann er war.",
                            "The counters run since the last reset, not since the last "
                            "reboot &ndash; an old crash stays in the number. The date "
                            "beside it says when it happened." },
    /* Both go into title='...' -- must stay free of apostrophes. */
    [S_TH_WARN]         = { "Warnschwelle erreicht",    "Warning threshold reached" },
    [S_TH_ALARM]        = { "Kritischer Wert",          "Critical value" },
    [S_STAT_BOOTS]      = { "Neustarts gesamt",         "Reboots total" },
    [S_STAT_CRASHES]    = { "Abst&uuml;rze",            "Crashes" },
    [S_STAT_LASTCRASH]  = { "Letzter Absturz",          "Last crash" },
    [S_STAT_MAXUP]      = { "L&auml;ngste Laufzeit",    "Longest uptime" },
    [S_STAT_NEVER]      = { "noch keiner",              "none yet" },
    [S_STAT_RESET]      = { "Z&auml;hler zur&uuml;cksetzen", "Reset counters" },
    [S_STAT_RESET_CONFIRM] = { "Alle Stabilit&auml;ts-Z&auml;hler wirklich auf null setzen?",
                               "Really reset all stability counters to zero?" },
    [S_NAV_LOGS]        = { "Logs",                     "Logs" },
    [S_TITLE_LOGS]      = { "Logs",                     "Logs" },
    [S_LOGS_SYS]        = { "System-Log",               "System log" },
    [S_LOGS_REFRESH]    = { "Aktualisieren",            "Refresh" },
    [S_LOGS_NONE]       = { "Keine Log-Datei vorhanden (Logging aktiviert? SD eingebunden?).",
                            "No log file yet (logging enabled? SD mounted?)." },
    [S_LOGS_TAIL]       = { "Letzte %d KB, neueste Zeilen unten.",
                            "Last %d KB, newest lines at the bottom." },
    [S_LOGS_OLD]        = { "Vorheriges Log",           "Previous log" },
    [S_LOGS_DOWNLOAD]   = { "Ganze Datei",              "Full file" },
    [S_LOGS_F_ALL]      = { "Alle",                     "All" },
    [S_LOGS_F_PROB]     = { "Nur Warnungen und Fehler", "Warnings and errors only" },
    /* Goes into placeholder='...' -- must stay free of apostrophes. */
    [S_LOGS_SEARCH]     = { "Suchen",                   "Search" },
    /* "Meldungen", not "Zeilen": the counter keys off the "W (05:12:44)"
     * prefix, so day markers and backtrace continuations show but never count. */
    [S_LOGS_LINES]      = { "Meldungen (gefiltert / gesamt)",
                            "messages (filtered / total)" },
    /* Holds the counter slot until the tail is in and lgf() exists. */
    [S_LOGS_LOADING]    = { "l&auml;dt &hellip;",         "loading &hellip;" },
    /* Without this the empty filter result reads as "no errors on this device". */
    [S_LOGS_FILTER_HINT] = { "Filter und Suche arbeiten nur auf den hier geladenen "
                             "letzten %d KB &ndash; &auml;ltere Zeilen stehen nur in "
                             "der ganzen Datei.",
                             "Filter and search only work on the last %d KB loaded "
                             "here &ndash; older lines are only in the full file." },
    [S_NAV_SENDERS]     = { "Sender",                   "Senders" },
    [S_TITLE_SENDERS]   = { "Ortsfeste Sender, die geh&ouml;rt wurden",
                            "Stationary senders heard" },
    [S_SND_INTRO]   = { "Ampeln und RSU, die dieses Ger&auml;t geh&ouml;rt hat &ndash; mit "
                        "SD-Karte auch &uuml;ber Neustarts. Fahrzeuge fehlen: sie wechseln "
                        "laufend ihre Kennung.",
                        "Traffic lights and RSUs this device has heard &ndash; across reboots "
                        "too, with an SD card. Vehicles are missing: they keep changing their "
                        "identifier." },
    [S_SND_NONE]        = { "Noch kein ortsfester Sender geh&ouml;rt.",
                            "No stationary sender heard yet." },
    [S_SND_ID]          = { "Kennung",                  "ID" },
    [S_SND_NAME]        = { "Kreuzung",                 "Intersection" },
    [S_SND_TYPES]       = { "Sendet",                   "Sends" },
    [S_SND_FRAMES]      = { "Frames",                   "Frames" },
    [S_SND_FIRST]       = { "Zuerst",                   "First" },
    [S_SND_LAST]        = { "Zuletzt",                  "Last" },
    [S_SND_POS]         = { "Position",                 "Position" },
    [S_SND_RSSI]        = { "Pegel dBm",                "Level dBm" },
    /* One column now holds name, id and MAC -- "Kennung" would be a lie. */
    [S_SND_STATION]     = { "Sender",                   "Sender" },
    [S_SND_SINCE]       = { "seit",                     "since" },
    [S_SND_VEHICLES]    = { "Dazu %lu Frames von Fahrzeugen <b>seit dem letzten Neustart</b> "
                            "&ndash; die Tabelle oben z&auml;hlt mit SD-Karte &uuml;ber Neustarts weiter. "
                            "Wie viele Fahrzeuge das waren, l&auml;sst sich nicht sagen: die "
                            "Kennungen wechseln unterwegs.",
                            "Plus %lu frames from vehicles <b>since the last restart</b> &ndash; the table "
                            "above keeps counting across restarts when a card is present. How many "
                            "vehicles that was cannot be said: identifiers change on the move." },
    [S_SND_FULL]        = { "Tabelle voll &ndash; weitere Sender werden nicht mehr erfasst.",
                            "Table full &ndash; further senders are no longer recorded." },
    [S_SND_CLEAR]       = { "Liste zur&uuml;cksetzen",  "Reset list" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SND_CLEAR_CONFIRM] = { "Senderliste wirklich zurücksetzen?",
                              "Really reset the sender list?" },
    [S_NAV_TRANSIT]     = { "&Ouml;ffis",                  "Transit" },
    [S_TITLE_TRANSIT]   = { "Stra&szlig;enbahn und Bus", "Tram and bus" },
    [S_PT_INTRO]        = { "Aus den VDV-R09-Telegrammen der vorbeifahrenden Fahrzeuge. "
                            "Eine Vorbeifahrt = eine Sichtung &ndash; solange die Kennung nicht wechselt und sie unter 15 Minuten bleibt.",
                            "From the VDV R09 telegrams of passing vehicles. One passage counts "
                            "as one sighting &ndash; as long as the identifier holds and it stays under 15 minutes." },
    [S_PT_NONE]         = { "Noch keine Linie erfasst.", "No line recorded yet." },
    [S_PT_LINE]         = { "Linie",                     "Line" },
    [S_PT_SIGHTINGS]    = { "Sichtungen",                "Sightings" },
    [S_PT_AVG]          = { "&Oslash; Abweichung",       "Avg. deviation" },
    [S_PT_LATE]         = { "max. Versp&auml;tung",      "Worst late" },
    [S_PT_EARLY]        = { "max. zu fr&uuml;h",         "Worst early" },
    /* Not "Null": the value 0 means on time OR not transmitted, and the
     * heading is what a reader of the table actually sees. */
    [S_PT_UNKNOWN]      = { "ohne Wert",                 "no value" },
    [S_PT_LAST]         = { "Zuletzt",                   "Last" },
    /* The wire format cannot express more, and a reader would otherwise take
     * the numbers for a precise measurement. */
    [S_PT_LIMIT]    = { "Das Funkformat kennt nur &plusmn;7&nbsp;Minuten; Werte am Anschlag "
                        "sind mit &ge; markiert. &bdquo;ohne Wert&ldquo; z&auml;hlt die "
                        "Vorbeifahrten, deren zuletzt gesendete Abweichung&nbsp;0 war &ndash; das "
                        "hei&szlig;t <em>p&uuml;nktlich "
                        "oder gar nicht mitgesendet</em> und ist nicht unterscheidbar, daher eigene "
                        "Spalte statt Mittelwert. Landen alle Sichtungen einer Linie in "
                        "dieser Spalte, sendet sie die Abweichung gar nicht mit.",
                        "The radio format only carries &plusmn;7&nbsp;minutes; values at that "
                        "limit are marked &ge;. &ldquo;no value&rdquo; counts the passages whose "
                        "last transmitted deviation was&nbsp;0 &ndash; meaning <em>on time or not sent at "
                        "all</em>, which cannot be told apart, hence its own column instead of the "
                        "average. If every sighting of a line ends up in this column, it does "
                        "not transmit the deviation at all." },
    [S_PT_ACTIVE]       = { "Offene Vorbeifahrten: %d (eine gilt bis 90 s nach der letzten Nachricht).",
                            "Open passages: %d (one stays open until 90 s after the last message)." },
    [S_PT_PASSAGES]     = { "Letzte Vorbeifahrten",     "Recent passages" },
    [S_PT_WHEN]         = { "Wann",                     "When" },
    [S_PT_COURSE]       = { "Kurs",                     "Course" },
    [S_PT_DEST]         = { "Ziel",                     "Destination" },
    [S_PT_DEV]          = { "Abweichung",               "Deviation" },
    [S_PT_INRANGE]      = { "in Reichweite",            "In range" },
    [S_PT_HEADWAY]      = { "Takt",                     "Headway" },
    [S_PT_HEADWAY_NONE] = { "kein regelm&auml;&szlig;iger Takt", "no regular service" },
    /* "Ziel", not "Richtung": the field is the VDV destination number, and some
     * of those numbers turn up across many lines as depot runs. */
    [S_PT_DIR]          = { "Ziel",                     "Destination" },
    [S_PT_OPS_FIRST]    = { "erste Fahrt",              "first trip" },
    [S_PT_OPS_HINT]     = { "Takt, Betriebszeiten und Ziele sind aus den gespeicherten "
                            "Durchfahrten gerechnet, nicht aus einem Fahrplan &ndash; sie zeigen, "
                            "was hier vorbeigekommen ist. Der Betriebstag beginnt um 03:00 Uhr, "
                            "damit eine Fahrt nach Mitternacht nicht zum Betriebsbeginn des "
                            "n&auml;chsten Tages wird. Der Takt ist der Median &uuml;ber beide "
                            "Richtungen an diesem Punkt, auf ganze Minuten abgerundet: "
                            "einzelne sehr kurze Abst&auml;nde entstehen, wenn ein "
                            "Fahrzeug seine Kennung wechselt oder eine Vorbeifahrt zerschnitten "
                            "wird.",
                            "Headway, operating hours and destinations are computed from the stored "
                            "passages, not from a timetable &ndash; they show what actually came "
                            "past. The operating day starts at 03:00 so that a trip after midnight "
                            "is not counted as the next day's first. The headway is the median over "
                            "both directions at this point, rounded down to whole minutes: "
                            "single very short gaps appear when a vehicle "
                            "changes its pseudonym or a passage is cut in two." },
    /* Destinations are named here too: the table shows a "Ziel" column whose
     * bracketed count is explained nowhere else. */
    [S_PT_OPS_SUM]      = { "Woher Takt, Betriebszeiten und Ziele kommen",
                            "Where headway, operating hours and destinations come from" },
    [S_PT_CLEAR]        = { "Statistik zur&uuml;cksetzen", "Reset statistics" },
    [S_PT_CLEAR_CONFIRM] = { "Öffi-Statistik wirklich zurücksetzen?",
                             "Really reset the transit statistics?" },
    [S_NAV_TRAFFIC]     = { "Verkehr",                  "Traffic" },
    [S_TRF_BUSY]        = { "SD-Karte war besch&auml;ftigt &ndash; die gespeicherte Historie "
                            "fehlt in dieser Ansicht. Gleich nochmal laden.",
                            "The SD card was busy &ndash; the stored history is missing from this "
                            "view. Reload in a moment." },
    [S_TRF_DAY]         = { "Tag",                      "Day" },
    [S_TRF_SG]          = { "Signalgruppe",             "Signal group" },
    [S_TRF_PH_WAIT]     = { "Phasendauern erscheinen, sobald hier eine Gr&uuml;n- oder Rotphase "
                            "einmal zu Ende ist &ndash; nachts h&auml;lt eine verkehrsabh&auml;ngige "
                            "Anlage lange dieselbe.",
                            "Phase durations appear once a green or red phase has ended here "
                            "&ndash; at night a traffic-actuated installation holds one for a "
                            "long time." },
    [S_TRF_CYCLES]      = { "Gr&uuml;nphasen",          "Green phases" },
    [S_TRF_SENDERS]     = { "Kennungen",                "Identifiers" },
    [S_TRF_SENDERS_NOTE] = { "Die Fahrzeugspalten z&auml;hlen verschiedene Funkkennungen, "
                             "nicht Nachrichten &ndash; an einer Durchfahrtsstelle also grob "
                             "die Fahrzeugzahl, genau ist sie nicht: nach der ETSI-Norm k&ouml;nnen "
                             "Fahrzeuge ihre Kennung wechseln. &ge; hei&szlig;t, der Wert ist eine "
                             "Untergrenze: die Z&auml;hltabelle der Stunde war voll, oder ein "
                             "Neustart hat die Stunde geteilt.",
                             "The vehicle columns count distinct radio identifiers, not messages "
                             "&ndash; at a through road roughly the vehicle count, but not "
                             "exact: the ETSI standard lets vehicles change their identifier. &ge; "
                             "means the value is a lower bound: the hour's counting table was "
                             "full, or a restart split the hour." },
    [S_TRF_IDENT_NOTE]  = { "Nicht zu verwechseln mit der Seite &bdquo;Sender&ldquo;: die listet "
                            "ortsfeste Anlagen, diese Spalte z&auml;hlt alle Funkkennungen der Stunde.",
                            "Not to be confused with the \"Senders\" page: that lists "
                            "stationary installations, this column counts every radio identifier "
                            "seen in the hour." },
    [S_TRF_SENDERS_DAY] = { "Im Tagesmodus z&auml;hlt je Klasse die st&auml;rkste Stunde, nicht die Tagessumme "
                            "&ndash; sonst z&auml;hlte jede Ampel 24-mal.",
                            "In daily mode each class contributes its busiest hour, not the day's total "
                            "&ndash; otherwise every traffic light would count 24 times." },
    [S_TITLE_TRAFFIC]   = { "Verkehr",                  "Traffic" },
    [S_TRF_INTRO]       = { "Empfangene Nachrichten pro Stunde, nach Verkehrsteilnehmer. Wird st&uuml;ndlich auf die SD-Karte geschrieben und &uuml;berlebt Neustarts.",
                            "Received messages per hour, by road user. Written hourly to the SD card, survives reboots." },
    [S_TRF_WINDOW]      = { "Zeitraum",                 "Window" },
    [S_TRF_W_24H]       = { "24 Stunden",               "24 hours" },
    [S_TRF_W_7D]        = { "7 Tage",                   "7 days" },
    [S_TRF_W_30D]       = { "30 Tage",                  "30 days" },
    [S_TRF_STATS]       = { "Verkehrsstatistik",        "Traffic statistics" },
    [S_TRF_TOTAL]       = { "Gesamt",                   "Total" },
    [S_TRF_HOUR]        = { "Stunde",                   "Hour" },
    [S_TRF_SPEED]       = { "&Oslash;/max km/h (Fahrzeuge)", "avg/max km/h (vehicles)" },
    [S_TRF_NODATA]      = { "Noch keine Daten &ndash; die laufende Stunde erscheint ab dem ersten Frame, "
                            "sobald die Uhr steht.",
                            "No data yet &ndash; the current hour appears with the first frame, once "
                            "the clock is set." },
    [S_CAT_CAR]         = { "Auto",                     "Car" },
    [S_CAT_BUS]         = { "Bus",                      "Bus" },
    [S_CAT_TRUCK]       = { "Lkw",                      "Truck" },
    [S_CAT_TWOWHEEL]    = { "Zweirad",                  "Two-wheeler" },
    [S_CAT_PED]         = { "Fu&szlig;g&auml;nger",     "Pedestrian" },
    [S_CAT_RSU]         = { "Ampel/RSU",                "Traffic light/RSU" },
    [S_CAT_OTHER]       = { "Sonstige",                 "Other" },
    [S_EVT_TITLE]       = { "Warnmeldungen (DENM)",     "Warnings (DENM)" },
    [S_EVT_NONE]        = { "Keine Warnmeldungen im gew&auml;hlten Zeitraum.",
                            "No warnings in the selected window." },
    [S_EVT_TIME]        = { "Zeit",                     "Time" },
    [S_EVT_SENDER]      = { "Absender",                 "Sender" },
    [S_EVT_WARNING]     = { "Warnung",                  "Warning" },
    [S_EVT_DENM]        = { "Gefahrenmeldung",          "Hazard notification" },
    [S_EVT_MULTI]       = { "auch von anderen Sendern", "also from other senders" },
    [S_EVT_RELAYED]     = { "weitergereicht",           "relayed" },
    [S_EVT_RELAY_VIA]   = { "&uuml;ber",                "via" },
    [S_EVT_RELAY_UNKNOWN] = { "eine andere Funkquelle", "another radio source" },
    [S_EVT_RELAY_AFTER] = { "Abstand",                  "gap" },
    [S_EVT_RELAY_HINT]  = { "Zwei verschiedene Funkadressen auf dieselbe Warnung hei&szlig;t: "
                            "jemand hat sie weitergereicht. Die Kennung im Datensatz bleibt dabei "
                            "die des Urhebers, deshalb ist das an der Kennung allein nicht zu sehen. "
                            "Wer weitergereicht hat, steht nur da, wenn die Funkadresse in der "
                            "Senderliste gef&uuml;hrt wird. Der Bruch x/y z&auml;hlt, wie viele der "
                            "Aussendungen &uuml;ber diese Quelle kamen.",
                            "Two different radio addresses for one warning mean somebody "
                            "re-broadcast it. The station id stays the originator's, which is why "
                            "the id alone never shows this. Who relayed it is named only when that "
                            "radio address is in the sender list. The x/y ratio counts how many "
                            "broadcasts came via that source." },
    [S_EVT_BYHOUR]      = { "Warnungen je Tagesstunde", "Warnings by hour of day" },
    [S_EVT_BYWDAY]      = { "Warnungen je Wochentag",   "Warnings by weekday" },
    [S_EVT_PERHOUR]     = { "je beobachteter Stunde",   "per observed hour" },
    [S_EVT_PROFILE_HINT] = { "Die Balken sind auf die tats&auml;chlich beobachteten Stunden "
                            "normiert &ndash; ein Wochentag, der im Fenster h&auml;ufiger vorkommt, "
                            "bekommt sonst allein deshalb den l&auml;ngeren Balken. In Klammern "
                            "stehen die gez&auml;hlten Warnungen und die Zahl der beobachteten "
                            "Stunden. Gez&auml;hlt werden gemeldete Warnungen, nicht Ereignisse: "
                            "derselbe Stau kann von mehreren Fahrzeugen gemeldet werden. Der "
                            "Zeitraum ist der, den die gespeicherten Warnungen abdecken; er kann "
                            "k&uuml;rzer sein als das gew&auml;hlte Fenster.",
                            "Bars are normalised to the hours actually observed &ndash; otherwise a "
                            "weekday that occurs more often in the window gets the longer bar for "
                            "that reason alone. In brackets: the warnings counted and the number of "
                            "observed hours. What is counted are reported warnings, not incidents: "
                            "one jam can be reported by several vehicles. The period is the one the "
                            "stored warnings cover; it can be shorter than the selected window." },
    /* One entry, not seven: the labels are only ever needed together. tm_wday
     * order, Sunday first, comma-separated. */
    [S_TRF_WDAYS]       = { "So,Mo,Di,Mi,Do,Fr,Sa",     "Sun,Mon,Tue,Wed,Thu,Fri,Sat" },
    [S_EVT_TRAFFIC]     = { "Verkehrslage / Stau",      "Traffic condition / queue" },
    [S_EVT_CAPPED]      = { "Nur die neuesten 256 Warnungen &ndash; im Zeitraum waren es mehr.",
                            "Only the newest 256 warnings &ndash; the period held more." },
    [S_TRF_SPEED_MIXED] = { "Ein Teil dieses Zeitraums stammt noch aus einer anderen Regel f&uuml;r stehende "
                            "Fahrzeuge &ndash; der Durchschnitt ist dort nicht direkt vergleichbar.",
                            "Part of this period follows a different rule for standing vehicles &ndash; "
                            "the average is not directly comparable there." },
    [S_TRF_SPEED_BY_TYPE] = { "Geschwindigkeit nach Typ (&Oslash;/max km/h)",
                              "Speed by type (avg/max km/h)" },
    [S_TRF_JUMP]        = { "Springe zu",                "Jump to" },
    [S_TRF_SILENT]      = { "Stunden ohne Empfang",      "Hours with no reception" },
    [S_TRF_WEAKHOURS]   = { "Stunden weit unter dem Schnitt", "Hours far below average" },
    [S_TRF_AVAIL_HINT]  = { "Gemessen wird, ob DIESES Ger&auml;t aufgezeichnet hat &ndash; nicht, ob der "
                            "Empfang gest&ouml;rt war: eigene Neustarts und Updates sehen hier aus wie ein "
                            "Ausfall, und eine Stunde ohne jeden Empfang schreibt gar keine Zeile. "
                            "Verglichen wird mit dem Median dieses Zeitraums; schwankt die Stundensumme "
                            "von Natur aus stark, entf&auml;llt die zweite Zahl.",
                            "This measures whether THIS device recorded &ndash; not whether reception was "
                            "disturbed: your own reboots and updates look like an outage here, and an hour "
                            "with no reception at all writes no row. The yardstick is the median of this "
                            "window; where the hourly total varies by itself, the second figure is left out." },
    [S_EVT_SHOWPOS]     = { "Ort auf der Karte zeigen",  "Show location on the map" },
    [S_TRF_LIGHTS]      = { "Ampeln (live)",            "Traffic lights (live)" },
    [S_TRF_LIGHTS_NONE] = { "Keine Ampeldaten (SPATEM) empfangen.",
                            "No traffic-light data (SPATEM) received." },
    [S_TRF_INTERSECTION] = { "Kreuzung",               "Intersection" },
    [S_TRF_LIGHTS_INTRO] = {
        "Aktueller Schaltzustand je Signalgruppe der empfangenen Kreuzungen. "
        "Angezeigt wird, was die Gruppe steuert (aus der Kartennachricht "
        "MAPEM), mit ihrer Signalgruppen-Nummer in Klammern. "
        "&ge;x s ist die fr&uuml;heste Umschaltzeit, nicht die genaue &ndash; "
        "und nur da, wo die Ampel sie mitsendet. Farbe = aktuelle Phase:",
        "Current phase per signal group of the received intersections, named after "
        "what they control (from the MAPEM), with the signal group number in "
        "brackets. &ge;x s is the EARLIEST switching time, not the exact one &ndash; "
        "and only where the light transmits it. Colour = current phase:" },
    [S_TRF_PH_GREEN]    = { "Gr&uuml;n (frei)",        "Green (go)" },
    [S_TRF_PH_AMBER]    = { "Gelb (&Uuml;bergang)",    "Amber (change)" },
    [S_TRF_PH_REDAMBER] = { "Rot-Gelb",                "Red-amber" },
    [S_TRF_PH_SINCE]    = { "l&auml;uft seit",         "running for" },
    [S_TRF_PH_RED]      = { "Rot (Halt)",              "Red (stop)" },
    [S_TRF_PH_OTHER]    = { "Aus/unbekannt",           "Off/unknown" },
    [S_DIR_STRAIGHT]    = { "geradeaus",               "straight" },
    [S_DIR_LEFT]        = { "links",                   "left" },
    [S_DIR_RIGHT]       = { "rechts",                  "right" },
    [S_DIR_UTURN]       = { "wenden",                  "U-turn" },
    [S_DIR_PED]         = { "Fu&szlig;g&auml;nger",    "pedestrian" },
    [S_NAV_MAP]         = { "Karte",                    "Map" },
    [S_TITLE_MAP]       = { "Live-Karte",               "Live map" },
    [S_MAP_HINT]        = { "Positionen aus empfangenen V2X-Nachrichten: Fahrzeuge (CAM) und ortsfeste Sender wie Ampeln/RSUs (Position aus der GeoNetworking-Schicht). Symbol je Stationstyp; Anklicken zeigt Details (Typ, Zeit, RSSI, bei Fahrzeugen auch km/h). Ein Marker verschwindet nach der eingestellten Marker-Standzeit ohne neue Nachricht. Die Kartenkacheln holt der Browser aus dem Internet, das Ger&auml;t selbst nicht.<br><br>Verlauf: Zeitbereich unten w&auml;hlen, Laden, dann mit Regler und Play abspielen &ndash; Quelle ist die rollierende PCAP-Aufzeichnung auf der SD-Karte.",
                            "Positions from received V2X messages: vehicles (CAM) and stationary senders such as traffic lights/RSUs (position from the GeoNetworking layer). Icon per station type; click for details (type, time, RSSI, and km/h for vehicles). A marker disappears after the configured marker hold time without a new message. The browser fetches the map tiles from the internet, the device does not.<br><br>History: pick a time range below, click Load, then replay with the slider and Play &ndash; the source is the rolling PCAP recording on the SD card." },
    [S_MAP_HELP]        = { "Info &amp; Hilfe",           "Info &amp; help" },
    [S_MAP_LAYER_STREETS] = { "Karte",                  "Map" },
    [S_MAP_LAYER_SATELLITE] = { "Satellit",             "Satellite" },
    [S_MAP_DENM]        = { "Gefahrenmeldung aktiv",   "Hazard warning active" },
    [S_MAP_LINE]        = { "Linie",                   "Line" },
    [S_MAP_COURSE]      = { "Kurs",                    "Course" },
    [S_MAP_DEST]        = { "Ziel",                    "Destination" },
    [S_MAP_LATE]        = { "Versp&auml;tung",         "delay" },
    [S_MAP_EARLY]       = { "Vorsprung",               "ahead" },
    [S_MAP_ONTIME]      = { "keine Abweichung gemeldet", "no deviation reported" },
    [S_SYS_COREDUMP]      = { "&#9888; Crash-Dump verf&uuml;gbar", "&#9888; Crash dump available" },
    [S_SYS_COREDUMP_DOWNLOAD] = { "Herunterladen",      "Download" },
    [S_SYS_COREDUMP_CLEAR] = { "L&ouml;schen",          "Delete" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SYS_COREDUMP_CLEAR_CONFIRM] = { "Crash-Dump löschen?", "Delete crash dump?" },
};

/* Per-request language, one slot per serving task (httpd + slow worker) --
 * a streaming search must not flip a concurrently rendered page's language. */
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

/* Both sniffer paths stamp gettimeofday, which without a synced clock counts
 * seconds since boot -- so wall-clock times need this SNTP client first. */

/* Europe/Berlin with automatic CET/CEST daylight-saving switch. */
#define LOCAL_TZ   "CET-1CEST,M3.5.0,M10.5.0/3"

static bool sntp_started;

/* ESP_NETIF_SNTP_DEFAULT_CONFIG stores the hostname pointer, not a copy, and
 * esp_netif_sntp_init() is only ever called once (see sntp_started below), so
 * this buffer must stay alive for the SNTP client's whole lifetime. Configured
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
    uint8_t  pt_request;   /* HA 0=keine, 1=gerade, 2=links, 3=rechts */
    uint8_t  pt_priority;  /* PR */
    int16_t  pt_deviation; /* ZW signiert: + = Verspätung */
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

/* Recent-DENM tracker so /map can flag senders for ~60 s. Lockless: 32-bit
 * words, cosmetic data, torn reads harmless. */
#define DENM_TRACK_N 32
#define DENM_RECENT_SEC 60
/* Also remembers WHAT the warning was: the map popup used to show only a
 * generic "warning" marker, so a driver could see that a car had reported
 * something but not what. */
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
            /* Keep the last cause that actually decoded; a later message
             * failing to decode shouldn't blank a known warning. */
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

/* Message-type breakdown (its_decode labels, e.g. "CAM"/"DENM"/"Signed"/"?")
 * for the small stats block on the status page. Fixed-size, linear-scan
 * table: only a handful of distinct labels occur in practice, so this stays
 * O(1) in effect despite the O(n) scan, and needs no dynamic allocation. */
/* Now that labels combine station type + message type (e.g. "Bus CAM", "RSU
 * GeoNet:2004"), more distinct combinations can occur than with the plain
 * message-type-only label, hence more slots than before. */
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
    /* All slots taken by distinct labels (shouldn't happen in practice) --
     * silently drop rather than grow unbounded. */
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

/* Minute history behind the two hour sparklines: one writer (hist_tick, on the
 * esp_timer task), one reader (httpd) -- ordering is spelled out at both ends. */
#define HIST_MINUTES    60
#define HIST_RATE_MIN   60          /* msgs/min floor, so a quiet hour stays flat */
#define HIST_TEMP_SPAN  5           /* K, narrowest band -- else noise fills the box */
#define HIST_TEMP_NONE  INT16_MIN
/* Compiler-only barrier -- unicore, so no CPU fence is needed. Not
 * __atomic_signal_fence: that orders atomics, and clang sinks plain loads past it. */
#define HIST_BARRIER()  __asm__ __volatile__("" ::: "memory")

typedef struct {
    uint32_t stamp;     /* sample number held here; 0 = empty or being written */
    uint32_t rate;      /* frames counted in that minute */
    int16_t  temp_dc;   /* 0.1 C, HIST_TEMP_NONE if the sensor did not answer */
    int16_t  pad;
} hist_slot_t;

/* PSRAM: 720 bytes of internal RAM buy more elsewhere. Every field is 32 or
 * 16 bit and aligned, so no single field can tear on this RV32 part. */
static EXT_RAM_BSS_ATTR hist_slot_t hist_ring[HIST_MINUTES];
static uint32_t hist_count;     /* samples taken; newest sits at (hist_count-1)%60 */

/* Once a minute from its own timer. Reads only counters the packet path already
 * keeps, so webserver_handle_packet is not touched and takes no extra lock. */
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

/* One place maps a decode result onto a message entry -- the live ring and
 * the archive search share it, so their columns can never drift apart. */
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
    /* Decoded from the full frame, not from any short prefix -- CAM/DENM's
     * BTP header sits hundreds of bytes in. */
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
    /* station_id is only set with a position; without one the ActionID carries
     * the originator -- otherwise 0 would land in the row and fold alien levels. */
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

/* Threshold -> CSS class (see .v-* in s.css). One place, so two pages
 * showing the same value cannot end up disagreeing about its colour. */
static const char *lvl_class(unsigned v, unsigned warn, unsigned alarm)
{
    if (v >= alarm) return "v-bad";
    if (v >= warn)  return "v-warn";
    return "";
}

/* Free internal RAM as a share of the total: the byte count alone says
 * nothing, and the total differs per chip variant. */
static const char *ram_int_class(void)
{
    size_t tot = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
    size_t fre = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (!tot || fre > tot) return "";
    return lvl_class((unsigned)(((uint64_t)(tot - fre) * 100) / tot), 85, 92);
}

#ifdef CONFIG_ENABLE_TEMPERATURE
/* Enclosure temperature, not a chip limit: the LM75 sits on the board next
 * to it, so these are the values at which the operator should look. */
static const char *temp_class(float tc)
{
    if (tc != tc) return "v-off"; /* NaN = sensor not answering */
    if (tc < 0.0f) return "";
    return lvl_class((unsigned)tc, 60, 75);
}
#endif

/* Format a byte count as KiB or MiB for readability. */
static void format_bytes64(uint64_t bytes, char *out, size_t out_size);

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
    /* ?v= busts the browser's aggressive per-origin favicon cache so the tower
     * icon replaces the old satellite from early versions. Bump on icon change. */
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
    /* Context line above the nav: weekday, date, clock, node. On a page with
     * auto-refresh the clock follows; on one without it names the load time,
     * which is exactly how old the figures below are. */
    "%s"
    /* .navlinks is a separate flex item from .lang (see CSS) so the page
     * links can wrap onto multiple rows on narrow screens while the flag
     * switch stays anchored top-right instead of dropping onto its own,
     * disconnected-looking full-width row. */
    "<nav>"
    /* Logo (Tokyo-tower app icon), top-left. Plain image, not a link -- as a
     * nav <a> to '/' it would get the amber "active" highlight on the status
     * page, which looked wrong. */
    "<span class='logo'><img src='/icon-192.png' alt='ITS G5' height='26' width='26'></span>"
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
    /* Flag toggle (Austria/UK), current language highlighted -- replaces the
     * old plain-text "other language" link. Flags are HTML numeric entities
     * (regional indicator symbols), not raw UTF-8 in the C source. */
    "<span class='lang'>"
    "<a href='?lang=de' class='%s' title='Deutsch'>&#127462;&#127481;</a>"
    "<a href='?lang=en' class='%s' title='English'>&#127468;&#127463;</a>"
    "</span></nav>"
    /* In the head, not the footer: the flags are clickable long before the
     * page finishes streaming, and until this runs they drop the query. */
    "<script>var lq=location.search.replace(/^\\?/,'').split('&').filter(function(s){"
    "return s&&s.indexOf('=')>0&&s.slice(0,5).toLowerCase()!=='lang=';});"
    "document.querySelectorAll('nav .lang a').forEach(function(a){"
    /* lang= first, not last: resolve_language reads only the first 511 bytes
     * of the query, and a long one would push it out of reach. */
    "a.setAttribute('href','?'+['lang='+a.getAttribute('href').slice(-2)]"
    ".concat(lq).join('&')+location.hash);});</script>"
    "<h1>%s</h1>";

static const char PAGE_FOOTER[] =
    /* Deliberately no (c): the tree carries third-party parts (see NOTICE),
     * a blanket claim would overreach. Name and source link only. */
    "<div class='foot'><a href='https://codeberg.org/datom/its-g5-receiver-firmware-webinterface'"
    " target='_blank' rel='noopener'>datom &middot; Codeberg</a></div>"
    "<script>document.querySelectorAll('nav a').forEach(function(a){"
    "var h=(a.getAttribute('href')||'').split('?')[0];"
    "if(h&&h===location.pathname)a.className='active';});"
    /* Shared reboot: poll until the device answers, then reload. First poll
     * delayed so a not-yet-rebooted device cannot "succeed". */
    /* (ask, msg, slow) -- the order the callers already pass them in. */
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
    /* The POST carries no query string of its own; without ?lang= here,
     * resolve_language() on that request defaults to German. */
    const char *lc = current_lang == LANG_DE ? "de" : "en";
    static EXT_RAM_BSS_ATTR char banner[1280];
    snprintf(banner, sizeof(banner),
        "<div class='warn'><p>%s</p>"
        /* The banner now sits on /settings too, where a reload would drop
         * unsaved edits; the guard tolerates pages without that variable. */
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
/* "FR, 21.08.2026 <sep> 14:02 <sep> " from the device clock, or empty if it was
 * never set -- a 1970 date would read as a fault, not as a missing sync. */
static void format_clockline(char *out, size_t cap, const char *sep)
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

static void send_page_header_refresh(httpd_req_t *req, const char *heading, const char *json_url)
{
    /* static EXT_RAM_BSS_ATTR, not a stack buffer -- the httpd task's stack
     * is only 16384 bytes total (see webserver_init), and header[] growing
     * on-stack is exactly what caused a real crash once. */
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
                /* Mobile browsers freeze setInterval while the screen is off. Guard
                 * lives here, not in tick(), which must stay free to run at ri=1. */
                "function wake(){if(document.hidden||Date.now()-lt<1000)return;"
                "if(localStorage.getItem('ar')!=='0')tick();}"
                "document.addEventListener('visibilitychange',wake);"
                /* e.persisted separates a bfcache return from a normal load, whose
                 * tick the load handler above already fires. */
                "window.addEventListener('pageshow',function(e){if(e.persisted)wake();});"
                "});})();</script>",
                (unsigned long)ri, json_url);
    }

    const char *lc = current_lang == LANG_DE ? "de" : "en";
    const char *lang_de_active = (current_lang == LANG_DE) ? "active" : "";
    const char *lang_en_active = (current_lang == LANG_EN) ? "active" : "";

    /* Tab/home-screen title carries the node id so several receivers stay
     * distinguishable; nodeid is user-editable, hence HTML-escaped. */
    char nodeid_raw[CONFIG_NODEID_BUFFER_SIZE] = {0};
    size_t nodeid_raw_size = sizeof(nodeid_raw);
    config_get_str(CONFIG_INDEX_NODEID, nodeid_raw, &nodeid_raw_size);
    /* Capped at 24 chars before escaping (a tab title has no use for the
     * full 64-byte nodeid budget, and this keeps header[]'s worst case --
     * an adversarial nodeid of nothing but '&' -- bounded to a few hundred
     * bytes instead of a few thousand). */
    char nodeid_disp[25];
    /* Deliberate truncation to a fixed display width -- done as a plain
     * bounded copy, not snprintf("%s", ...), because -Werror=format-
     * truncation can't tell "shortening on purpose" from "buffer too small"
     * and errors out on the latter shape either way. */
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

    /* /s.css cache key. The ELF hash, not ->version: a test build that edits
     * s.css without bumping version.txt must still reach the browser. */
    char css_ver[9];
    esp_app_get_elf_sha256(css_ver, sizeof(css_ver));

    char clk[80];
    format_clockline(clk, sizeof(clk), "&middot;");
    static EXT_RAM_BSS_ATTR char ctxline[sizeof(nodeid_esc) + 160];
    /* Clock in its own span so a poll can replace just that part. */
    HTML_PRINTF(ctxline, "<div class='ctx'><span id='st-clk'>%s</span>%s</div>",
                clk, nodeid_esc);

    /* With the CSS gone from the format string -Wformat-truncation can no
     * longer bound this call; the assert does it instead (200 = nav+heading). */
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

static void send_page_header(httpd_req_t *req, const char *heading)
{
    send_page_header_refresh(req, heading, NULL);
}

/* One sample per completed second; the 60th ring slot is the second still
 * being counted, so only 59 of them can ever be shown. */
#define SPARK_POINTS    (RATE_WINDOW_SECS - 1)
#define SPARK_PEAK_MIN  10  /* msgs/s floor, so a quiet minute stays flat */
#define SPARK_DECAY_SEC 30

/* Fixed y-scale: rescaling to the window maximum made 58 of 60 samples equal
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
        /* h stays in 1..36 so the 2 px stroke never clips at the viewBox edge;
         * a silent second drops to the baseline, which is the honest reading. */
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
        /* Second look, and it is not belt and braces: a reader preempted right
         * here comes back to the values of a minute an hour younger. */
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
/* Two sinks: the page needs entities, /status.json literal UTF-8 because
 * arApply writes it with textContent -- so the caller passes the pieces. */
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

    /* The two halves below cover DIFFERENT periods, so each says so itself --
     * one heading for both had the type totals read as a 60 s snapshot. */
    char scaletxt[48];
    snprintf(scaletxt, sizeof(scaletxt), "%s %lu/s", T(S_ACTIVITY_SCALE),
             (unsigned long)peak);
    /* Opens the section; the matching </div> rides on hintblock at the end of
     * this function, so everything in between belongs to the group. */
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
    /* Memory details live on /system now (single source of truth); the status
     * page just shows operational state. */

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
        /* Three charts stand between the top of the page and the device group,
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

    /* SD usage instead of the static hardware variant that stood here: it
     * answers "is the card filling up" at a glance. */
    /* Text and class kept apart: T(S_SD_USED_OF) is itself the format
     * string, so the wrapping span cannot be appended to it. */
    /* The share is the cell's value now, the byte text its detail line; both
     * default to the same dash the old single-line variant showed. */
    char sdval[48] = "&ndash;";
    /* Empty, not a dash: the detail line then renders blank instead of putting
     * a second dash under the one in the value. */
    char sdtxt[128] = "";
    const char *sdcls = "";
#if CONFIG_ENABLE_SD
    {
        uint64_t sd_total = 0, sd_free = 0;
        if (sdcard_usage(&sd_total, &sd_free) == ESP_OK && sd_total)
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
            snprintf(sdtxt, sizeof(sdtxt), "%s", T(S_SD_NOT_MOUNTED));
            /* Grey, not red: running without a card is a normal setup for
             * someone else, not a fault of this one. */
            sdcls = "v-off";
        }
    }
#endif
    /* Threshold colour and its tooltip sit on the label, which is where the
     * state dot is in the new grid. */
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

    /* The SD value gets no state class: /status.json carries no SD field, so a
     * coloured 36px number would keep asserting the share from page load. */
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
        /* .btnrow makes these three quiet like the mockup without touching the
         * global amber button, which /settings' own savebar still relies on. */
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
        /* setAttribute, not innerHTML: the polyline is one SVG element now. */
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
        /* Defined by the neighbour block below, absent on /system. */
        "if(window.peerPoll)window.peerPoll();"
        "};})();</script>",
        T(S_RUNNING), T(S_STOPPED), T(S_CONNECTED), T(S_DISCONNECTED),
        T(S_SNIFF_START), T(S_SNIFF_STOP), T(S_ACTIVITY_SCALE));
    httpd_resp_send_chunk(req, applyscript, HTTPD_RESP_USE_STRLEN);

    /* Neighbours at a glance: three receivers meant three browser tabs, and
     * the comparison between them is the actual information. */
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
                 * catch(); a no-cors probe tells them apart, so an older peer
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
        "}",
        (unsigned long)msg_total_count, (unsigned long)rate, uptime_str,
        running ? "true" : "false", chan_str,
        mqtt_connected_state ? "true" : "false",
        spark, (unsigned long)peak, idle,
        typeline[0] ? typeline : T(S_ACTIVITY_NONE),
        clkj, hourr, hscale
#ifdef CONFIG_ENABLE_TEMPERATURE
        , tval, temp_class(tc), hourt, hband
#endif
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

/* Compact JSON for the browser to turn into table rows; single-letter field
 * names (t/r/l/y/h, a/o/i for lat/lon/stationId) to keep the payload small.
 * a/o/i only present when a position was decoded. */
/* Defined further down, next to their tables; needed here to name the warning
 * in the map popup rather than just flagging that there was one. */
static const char *denm_cause_text(uint8_t code);
static const char *denm_sub_text(uint8_t cause, uint8_t sub);

/* Emits the warning keys for a station: `d` that it warned recently, and `dt`
 * what about. The text carries HTML entities for umlauts, which is fine --
 * the popup is built as HTML. */
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

/* Optional CAM-detail keys shared by live feed and map seed. Single-letter
 * keys are crowded -- check for collisions before adding one (`h` is the hex dump!). */
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

/* One-line human summary replacing the hex preview -- 25 of those 32 bytes
 * were identical boilerplate on every real frame; raw bytes stay in the PCAP. */
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
    /* -1 cm/s is the GN "not available" pattern; printing it yielded "-0 km/h"
     * next to the popup key that already suppresses it. */
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
        /* Measure first and stop while the closing `]` still fits -- overrunning
         * silently dropped it and the client's JSON.parse threw. Newest first, oldest drop. */
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
/* Sockets whose last send failed are skipped for a while (a dirty-closed tab
 * stays "live" for minutes and spammed warnings); entries expire so reused fds recover. */
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

    /* Formatted output is ~300 bytes -- at 256 this truncated inside the open
     * <script>, and the browser swallowed the whole table as script text. */
    char fbar[512];
    HTML_PRINTF(fbar,
        /* Colon inside the span: as its own text node it would become a flex
         * item of .tools and sit a gap away from the word. */
        "<p class='tools'><span class='cap'>%s:</span>"
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
        /* Vehicle size, when the CAM carried it, rides along in the type
         * cell rather than costing the table another mostly-empty column. */
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
    /* Archive tools live here with the messages they operate on: search the
     * PCAP recording, and the manual re-send of stationary senders. */
    {
        /* 2.6 KB of literal plus 15 substituted strings; sized with room and
         * checked, because a cut here swallows the rest of the page. */
        static EXT_RAM_BSS_ATTR char arch[6144];
        HTML_PRINTF(arch,
            "<div class='grp' id='m-srch'><h2>%s</h2><p class='note'>%s</p>"
            "<p class='tools'><input type='datetime-local' id='sf'> &ndash; "
            "<input type='datetime-local' id='st'> <span class='cap'>%s:</span> "
            "<input id='sq' size='14' maxlength='32'> "
            "<button onclick='srch()'>%s</button> "
            "<button onclick='expp()'>%s</button></p>"
            "<p class='note'>%s</p>"
            "<div id='sr'></div></div>"
            "<div class='grp' id='m-rsu'><h2>%s</h2><p class='note'>%s</p>"
            "<p class='tools'><input type='datetime-local' id='rf'> &ndash; "
            "<input type='datetime-local' id='rt'> <span class='cap'>%s:</span> "
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
            T(S_SRCH_TITLE), T(S_SRCH_HINT), T(S_SRCH_FILTER), T(S_SRCH_BTN),
            T(S_SRCH_EXPORT), T(S_SRCH_EXPORT_HINT),
            T(S_RSU_UP_TITLE), T(S_RSU_UP_HINT), T(S_RSU_UP_THIN), T(S_RSU_UP_ONCE),
            T(S_RSU_UP_BTN),
            /* The fetches carry the page's language along -- without it the
             * search table and upload status came back German on ?lang=en. */
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
/*  GET /map -- live positions decoded from CAM frames                */
/* ================================================================== */

static esp_err_t map_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    send_page_header(req, T(S_TITLE_MAP));

    /* Collapsible (native <details>, no JS) and collapsed by default -- the
     * full explanation is long and eats a lot of vertical space on a phone,
     * where it pushed the map itself below the fold; the summary is one line. */
    /* Measured: 1606 bytes in German (the hint text alone is 716). Sized
     * with real headroom -- at 1536 this truncated mid-markup and took the
     * map container with it, leaving a blank page and CSS shown as text. */
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

    /* Layer-control labels, the only two localized strings the client script
     * needs -- passed in as JS vars so MAP_SCRIPT below can stay one fixed
     * static string, not a per-request snprintf. */
    uint32_t stale = 60;
    config_get_u32(CONFIG_INDEX_MAP_STALE_SEC, &stale);
    uint32_t trkdays = 2;
    config_get_u32(CONFIG_INDEX_TRACKS_DAYS, &trkdays);

    /* Peer list -> a JS array literal. Host names are restricted to the
     * characters a host name may contain, so nothing from the setting can
     * break out of the quotes into the surrounding script. */
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

    /* Labels for the CAM detail in the popup. Emitted as one JS object rather
     * than ~25 more string-table entries, the same shortcut spat_status_text()
     * takes -- these are leaf words that appear in exactly one place.
     * Order in `l` and `e` is the standard's bit order, MSB first. */
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
     * waiting for the next /ws tick. msgtype/hex only ever contain
     * digits/letters/spaces/':'/'-'/'.', safe to embed unescaped. */
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
        /* 320 was already close with the msgtype and clock inline; the CAM
         * detail adds up to ~40 more. */
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
    /* Reuses the /ws feed keys. Emoji divIcon markers keyed by station_id, evicted
     * after 60 s; initial view guessed from the browser timezone (plain HTTP = no geolocation). */
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
         * colours that carry meaning. Leaflet 1.1.1 has no className option. */
        "function paintDark(on){var c=map.getContainer();"
        "L.DomUtil[on?'addClass':'removeClass'](c,'mapdark');}"
        "paintDark(true);"
        "map.on('baselayerchange',function(e){paintDark(e.layer===dark);});"
        /* Listed with the default first, so the checked entry is the one at
         * the top rather than somewhere in the middle. */
        "var baseLayers={};baseLayers[ITS_MAP_L_DARK]=dark;"
        "baseLayers[ITS_MAP_L_STREETS]=streets;baseLayers[ITS_MAP_L_LIGHT]=light;"
        "baseLayers[ITS_MAP_L_SAT]=sat;"
        /* collapsed:false -- the collapsed state's toggle icon references a
         * Leaflet default image (images/layers.png) we didn't vendor (kept
         * to just the emoji markers, no image assets at all), which would
         * otherwise show as a blank white box until clicked/hovered. */
        /* Vehicle tracks as a switchable overlay, loaded only when actually
         * switched on -- it is a separate request against the SD card, and
         * most visits to the map do not want it. */
        /* ONE shared canvas renderer for all track polylines -- per-line L.canvas()
         * cost megabytes each on retina, and mobile Safari killed the tab. */
        "var trackRenderer=L.canvas();"
        "var trackLayer=L.layerGroup(),tracksLoaded=false;"
        /* The point cap is a real omission, not a rounding -- the overlay says
         * so rather than drawing a short day that looks complete. */
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
        /* /tracks.json used to be a bare array and became {"t":[...],"c":n}.
         * A peer still on the old firmware answers with the array, and without
         * this its tracks vanish into the peer .catch -- indistinguishable
         * from "receiver offline", which is exactly what that catch hides. */
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
        /* Removes a marker and, if it has one, its path trail -- four call
         * sites used to drop only the marker, which would have left the
         * trail behind on the map forever. */
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
        /* Sparse attributes held OUTSIDE `markers`: playback seeks rebuild markers
         * and used to wipe them, making line numbers flicker. */
        /* Remember the last value seen per station -- not every CAM carries every
         * field, and the popup used to blink them in and out. */
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
        /* Named (not anonymous) so playback can pause/resume it -- it uses
         * real Date.now(), meaningless against historical/scrubbed
         * timestamps, so it must not run while replaying the past. */
        "var sweepTimer;"
        /* VMEM holds the last known line, destination and deviation per station
         * so a CAM that omits them does not blank the popup. It outlived the
         * marker, so a new pseudonym reusing that id inherited a stale line and
         * delay -- and the object grew for the lifetime of the page. */
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
        /* Lane geometry: fetched once (the layout is static), then just
         * recoloured whenever new phases arrive. Ingress lanes take their
         * signal group's colour; lanes without a group stay neutral grey. */
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
        /* Playback: {e:[...],p:1?}; entries share the /ws {t,i,a,o,y} shape,
         * so scrubbing re-derives per-station state and feeds apply(). */
        "var pbData=null,pbTimer=null,pbPlaying=false;"
        "function pbSeek(t){t=+t;document.getElementById('pbslider').value=t;"
        "document.getElementById('pbtime').textContent=new Date(t*1000).toLocaleTimeString();"
        "var latest={};"
        "for(var i=0;i<pbData.length;i++){var e=pbData[i];if(e.t>t)break;latest[e.i]=e;}"
        /* Same 60s staleness rule as the live sweep, but measured in
         * playback time (t - entry.t) rather than real Date.now() -- a
         * station's last-known position shouldn't keep showing forever
         * just because it's the most recent entry found so far. */
        "for(var k in latest){if(t-latest[k].t>ITS_MAP_STALE)delete latest[k];}"
        /* Remove markers for stations not yet present at time t -- apply()
         * only ever adds/moves markers for what's in the array it's given,
         * it never removes ones that are absent, so without this, seeking
         * backward left every "future" station's marker stuck in place. */
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
        /* Always reframe on the loaded window's own coverage -- apply()'s
         * own auto-zoom-on-first-fix (haveView) only fires once, whenever
         * the very first position (live or seed) ever arrived, so relying
         * on that here would only zoom to playback data by accident. */
        "map.fitBounds(L.latLngBounds(pbData.map(function(e){return [e.a/1e7,e.o/1e7];})),"
        "{padding:[30,30],maxZoom:16});"
        "haveView=true;"
        /* Start at the beginning, not the end -- seeking to sl.max meant
         * every station's *final* position for the whole window was
         * already showing on load, so pressing Play had nothing left to
         * play: the slider was already at its own stop condition. */
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
        /* Default to "the last hour"; built from getFullYear()/etc rather
         * than toISOString() since datetime-local needs local time, not UTC. */
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
 * [{"i":stationId,"rg":region,"id":id,"rev":n,"age":secs,
 *   "g":[[sg,phase,secsLeft,"movement text"],...]}] */
/* Defined further down with the rest of the traffic-page helpers. */
static void spat_movement_text(const spatem_intersection_t *e, uint8_t sg,
                               char *out, size_t out_size);

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
            /* [signalGroup, phase, secondsUntilChange] -- -1 = no timing.
             * That is minEndTime: the EARLIEST the phase may end, so every
             * renderer of this field has to show it as a lower bound. */
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
 * Fetched once by /map (the layout doesn't change), then recoloured live
 * from the phases in /spatem.json. Shape:
 * [{"rg":N,"id":N,"nm":"...","lanes":[{"l":11,"t":0,"sg":1,"p":[[lat,lon],..]}]}] */
static esp_err_t lanes_json_handler(httpd_req_t *req)
{
    static spatem_intersection_t ints[SPATEM_MAX_INT];
    int ni = spatem_snapshot(ints, SPATEM_MAX_INT);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, "[", HTTPD_RESP_USE_STRLEN);
    bool first = true;
    /* One intersection at a time, copied under the lock and sent outside it.
     * Holding the lock across the chunked send was a stall of the WHOLE
     * receiver: the packet path takes this same lock (untimed) while holding
     * msg_ring_mutex, so a browser that stopped reading froze reception. */
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
     * walk kept fopen'ing and decoding whole hours of PCAP into a dead socket
     * -- the same trap tracks_get_handler was already fixed for, and worse
     * here because every frame goes through its_decode_frame(). */
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
    /* Live mode flags a station that warned recently; in playback the frame
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
        /* No flush under the SD writer lock -- stop the walk; the handler
         * flushes lock-free and resumes from this second. */
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
/*  GET /traffic  -- per-hour traffic statistics + warning list       */
/* ================================================================== */


#endif /* CONFIG_ENABLE_SD -- the cause-code texts below are shared with the
        * always-present map/messages JSON, so they stay outside the guard. */

/* DENM cause code -> plain text. The numbering is the ETSI CauseCodeChoice
 * index, which the ASN.1 keeps equal to the classic cause code by way of
 * `reserved` placeholders. Anything not listed falls back to its number, so
 * an unfamiliar warning is still reported honestly rather than mislabelled. */
typedef struct { uint8_t code; const char *de; const char *en; } denm_cause_name_t;
static const denm_cause_name_t DENM_CAUSES[] = {
    /* ETSI calls cause 1 "trafficCondition", but on its own that says nothing
     * to a reader -- in practice it is always congestion, so name it that. */
    {   1, "Stau / stockender Verkehr",   "Congestion / slow traffic" },
    {   2, "Unfall",                       "Accident" },
    {   3, "Baustelle",                    "Roadworks" },
    {   5, "Unpassierbar",                 "Impassability" },
    {   6, "Schlechte Fahrbahnhaftung",    "Slippery road" },
    {   7, "Aquaplaning",                  "Aquaplaning" },
    {   9, "Fahrbahnzustand",              "Surface condition" },
    {  10, "Hindernis auf der Fahrbahn",   "Obstacle on the road" },
    {  11, "Tier auf der Fahrbahn",        "Animal on the road" },
    {  12, "Person auf der Fahrbahn",      "Person on the road" },
    {  14, "Geisterfahrer",                "Wrong-way driving" },
    {  15, "Bergungsarbeiten",             "Rescue and recovery work" },
    {  17, "Extremwetter",                 "Extreme weather" },
    {  18, "Schlechte Sicht",              "Poor visibility" },
    {  19, "Niederschlag",                 "Precipitation" },
    {  20, "Gewalttat",                    "Violence" },
    {  26, "Langsames Fahrzeug",           "Slow vehicle" },
    {  27, "Stauende",                     "Dangerous end of queue" },
    {  91, "Fahrzeugpanne",                "Vehicle breakdown" },
    {  92, "Nach einem Unfall",            "Post crash" },
    {  93, "Medizinischer Notfall",        "Human problem" },
    {  94, "Liegengebliebenes Fahrzeug",   "Stationary vehicle" },
    {  95, "Einsatzfahrzeug im Anmarsch",  "Emergency vehicle approaching" },
    {  96, "Gefaehrliche Kurve",           "Dangerous curve" },
    {  97, "Kollisionsgefahr",             "Collision risk" },
    {  98, "Rotlichtverstoss",             "Signal violation" },
    {  99, "Gefaehrliche Situation",       "Dangerous situation" },
    { 100, "Bahnuebergang",                "Railway level crossing" },
};

static const char *denm_cause_text(uint8_t code)
{
    for (size_t i = 0; i < sizeof(DENM_CAUSES) / sizeof(DENM_CAUSES[0]); i++)
        if (DENM_CAUSES[i].code == code)
            return current_lang == LANG_DE ? DENM_CAUSES[i].de : DENM_CAUSES[i].en;
    return NULL;
}


/* Sub-cause detail, per ETSI CDD. Each cause has its own enumeration, so the
 * table is keyed by (cause, sub). Only the causes likely to turn up here are
 * filled in; anything else falls back to showing the bare number, which is
 * still honest. Sub-cause 0 always means "unavailable" and is not shown. */
typedef struct { uint8_t cause, sub; const char *de, *en; } denm_sub_name_t;
static const denm_sub_name_t DENM_SUBCAUSES[] = {
    /* 1 trafficCondition */
    { 1, 1, "mehr Verkehr",                  "increased volume of traffic" },
    { 1, 2, "Stau bildet sich langsam",      "traffic jam slowly increasing" },
    { 1, 3, "Stau bildet sich",              "traffic jam increasing" },
    { 1, 4, "Stau bildet sich schnell",      "traffic jam strongly increasing" },
    { 1, 5, "stehender Verkehr",             "traffic stationary" },
    { 1, 6, "Stau loest sich leicht auf",    "traffic jam slightly decreasing" },
    { 1, 7, "Stau loest sich auf",           "traffic jam decreasing" },
    { 1, 8, "Stau loest sich schnell auf",   "traffic jam strongly decreasing" },
    /* 2 accident */
    { 2, 1, "mehrere Fahrzeuge",             "multi-vehicle accident" },
    { 2, 2, "schwerer Unfall",               "heavy accident" },
    { 2, 3, "mit LKW",                       "involving lorry" },
    { 2, 4, "mit Bus",                       "involving bus" },
    { 2, 5, "mit Gefahrgut",                 "involving hazardous materials" },
    { 2, 6, "auf der Gegenfahrbahn",         "on opposite lane" },
    { 2, 7, "ungesicherte Unfallstelle",     "unsecured accident" },
    { 2, 8, "Hilfe angefordert",             "assistance requested" },
    /* 3 roadworks */
    { 3, 1, "Grossbaustelle",                "major roadworks" },
    { 3, 2, "Markierungsarbeiten",           "road marking work" },
    { 3, 3, "langsames Arbeitsfahrzeug",     "slow moving road maintenance" },
    { 3, 4, "kurzzeitige Baustelle",         "short-term stationary roadworks" },
    { 3, 5, "Strassenreinigung",             "street cleaning" },
    { 3, 6, "Winterdienst",                  "winter service" },
    /* 26 slowVehicle */
    { 26, 1, "Wartungsfahrzeug",             "maintenance vehicle" },
    { 26, 2, "Gaffer",                       "vehicles slowing to look at accident" },
    { 26, 3, "Schwertransport",              "abnormal load" },
    { 26, 4, "Ueberbreite",                  "abnormal wide load" },
    { 26, 5, "Konvoi",                       "convoy" },
    { 26, 6, "Schneepflug",                  "snowplough" },
    { 26, 7, "Enteisung",                    "de-icing" },
    { 26, 8, "Streufahrzeug",                "salting vehicle" },
    /* 94 stationaryVehicle */
    { 94, 1, "medizinischer Notfall",        "human problem" },
    { 94, 2, "Panne",                        "vehicle breakdown" },
    { 94, 3, "nach Unfall",                  "post crash" },
    { 94, 4, "Haltestelle",                  "public transport stop" },
    { 94, 5, "Gefahrgut an Bord",            "carrying dangerous goods" },
    { 94, 6, "Fahrzeugbrand",                "vehicle on fire" },
};

static const char *denm_sub_text(uint8_t cause, uint8_t sub)
{
    if (sub == 0)
        return NULL;                 /* "unavailable" -- nothing to add */
    for (size_t i = 0; i < sizeof(DENM_SUBCAUSES) / sizeof(DENM_SUBCAUSES[0]); i++)
        if (DENM_SUBCAUSES[i].cause == cause && DENM_SUBCAUSES[i].sub == sub)
            return current_lang == LANG_DE ? DENM_SUBCAUSES[i].de : DENM_SUBCAUSES[i].en;
    return NULL;
}

/* What a signal group controls, as short text ("geradeaus", "links, rechts",
 * "Fussgaenger"), from the MAPEM lane geometry. Empty when no MAPEM for that
 * intersection has been decoded yet. Outside the SD guard: /spatem.json
 * needs it too. */
static void spat_movement_text(const spatem_intersection_t *e, uint8_t sg,
                               char *out, size_t out_size)
{
    out[0] = '\0';
    uint16_t man = 0;
    bool ped = false;
    if (!spatem_movement(e, sg, &man, &ped))
        return;
    if (ped)
    {
        snprintf(out, out_size, "%s", T(S_DIR_PED));
        return;
    }
    size_t o = 0;
    const struct { uint16_t bit; str_id_t id; } D[] = {
        { ITS_MAN_STRAIGHT, S_DIR_STRAIGHT }, { ITS_MAN_LEFT, S_DIR_LEFT },
        { ITS_MAN_RIGHT, S_DIR_RIGHT },       { ITS_MAN_UTURN, S_DIR_UTURN },
    };
    for (size_t i = 0; i < sizeof(D) / sizeof(D[0]); i++)
        if ((man & D[i].bit) && o < out_size)
            o += snprintf(out + o, out_size - o, "%s%s", o ? ", " : "", T(D[i].id));
}

#if CONFIG_ENABLE_SD  /* traffic statistics + playback continue */

/* ETSI station type -> localized road-user category label. */
static const char *trf_cat_label(uint8_t st)
{
    switch (st)
    {
    case 5:                 return T(S_CAT_CAR);
    case 6:                 return T(S_CAT_BUS);
    case 7: case 8: case 9: return T(S_CAT_TRUCK);
    case 2: case 3: case 4: return T(S_CAT_TWOWHEEL);
    case 1:                 return T(S_CAT_PED);
    case 15:                return T(S_CAT_RSU);
    default:                return T(S_CAT_OTHER);
    }
}

/* SAE J2735 MovementPhaseState -> indicator colour. */
static const char *spat_phase_color(uint8_t phase)
{
    switch (phase)
    {
    case 5: case 6:          return "#2ecc40";  /* movement allowed -> green */
    case 7: case 8: case 9:  return "#f2b134";  /* clearance / caution -> amber */
    case 2: case 3:          return "#e74c3c";  /* stop / remain -> red */
    case 4:                  return "#e67e22";  /* pre-movement -> red+amber */
    default:                 return "#888";     /* unavailable / dark */
    }
}

/* MovementPhaseState -> short localized phase name (chip hover title). */
static const char *spat_phase_name(uint8_t phase)
{
    switch (phase)
    {
    case 5: case 6:          return T(S_TRF_PH_GREEN);
    case 4:                  return T(S_TRF_PH_REDAMBER);
    case 7: case 8: case 9:  return T(S_TRF_PH_AMBER);
    case 2: case 3:          return T(S_TRF_PH_RED);
    default:                 return T(S_TRF_PH_OTHER);
    }
}

/* Live traffic-light snapshot: one block per intersection, a coloured dot per
 * signal group. Emitted at the top of #trf-body so it refreshes with the page.
 * No-op (nothing rendered) when no SPATEM has been received. */
/* IntersectionStatusObject as a short sentence, most-notable first; `alert`
 * lets the caller colour abnormal states. Returns length (0 = nothing to show). */
static size_t spat_status_text(uint16_t st, bool *alert, char *out, size_t cap)
{
    static const struct { uint16_t bit; bool warn; const char *de, *en; } F[] = {
        { ITS_ISTAT_OFF,          true,  "abgeschaltet",       "switched off"       },
        { ITS_ISTAT_FAILURE,      true,  "St&ouml;rung",       "fault"              },
        { ITS_ISTAT_FAILURE_FLASH,true,  "Gelbblinken",        "flashing amber"     },
        { ITS_ISTAT_STANDBY,      true,  "Bereitschaft",       "standby"            },
        { ITS_ISTAT_MANUAL,       true,  "Handsteuerung",      "manual control"     },
        { ITS_ISTAT_NO_MAP,       true,  "keine MAP",          "no MAP"             },
        { ITS_ISTAT_NO_SPAT,      true,  "keine SPAT",         "no SPAT"            },
        { ITS_ISTAT_PREEMPT,      true,  "Einsatzfahrt-Vorrang","emergency preempt" },
        { ITS_ISTAT_PRIORITY,     false, "&Ouml;V-Bevorrangung","transit priority"  },
        { ITS_ISTAT_STOPTIME,     false, "Haltezeit",          "stop time"          },
        { ITS_ISTAT_FIXED_TIME,   false, "Festzeitprogramm",   "fixed-time"         },
        { ITS_ISTAT_TRAFFIC_DEP,  false, "verkehrsabh&auml;ngig","traffic-actuated" },
    };
    size_t n = 0;
    if (alert) *alert = false;
    for (size_t i = 0; i < sizeof(F) / sizeof(F[0]); i++)
    {
        if (!(st & F[i].bit))
            continue;
        const char *w = current_lang == LANG_DE ? F[i].de : F[i].en;
        int k = snprintf(out + n, cap - n, "%s%s", n ? ", " : "", w);
        if (k < 0 || (size_t)k >= cap - n)
            break;
        n += (size_t)k;
        if (F[i].warn && alert) *alert = true;
    }
    return n;
}

static void emit_traffic_lights(httpd_req_t *req)
{
    static spatem_intersection_t ints[SPATEM_MAX_INT];
    int ni = spatem_snapshot(ints, SPATEM_MAX_INT);

    char h[160];
    snprintf(h, sizeof(h), "<div class='grp' id='lights'><h2 class='ico'>&#128678; %s</h2>",
             T(S_TRF_LIGHTS));
    httpd_resp_send_chunk(req, h, HTTPD_RESP_USE_STRLEN);

    if (ni == 0)
    {
        /* The section div is open -- every exit below must close it. */
        char none[192];
        snprintf(none, sizeof(none), "<p class='note'>%s</p></div>", T(S_TRF_LIGHTS_NONE));
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
        return;
    }

    /* Explanation + colour legend, so the bare signal-group numbers below
     * aren't cryptic. */
    char legend[1280];
    #define LG_DOT(col) "<span class='dot' style='background:" col ";margin:0 4px 0 10px'></span>"
    snprintf(legend, sizeof(legend),
        "<p class='note'>%s" LG_DOT("#2ecc40") "%s" LG_DOT("#e67e22") "%s"
        LG_DOT("#f2b134") "%s" LG_DOT("#e74c3c") "%s</p>",
        T(S_TRF_LIGHTS_INTRO), T(S_TRF_PH_GREEN), T(S_TRF_PH_REDAMBER),
        T(S_TRF_PH_AMBER), T(S_TRF_PH_RED));
    #undef LG_DOT
    httpd_resp_send_chunk(req, legend, HTTPD_RESP_USE_STRLEN);

    uint32_t now = (uint32_t)time(NULL);
    for (int i = 0; i < ni; i++)
    {
        spatem_intersection_t *e = &ints[i];
        /* phase_seen, not last_seen: this number sits beside the phase dots and
         * must say how old THEY are, not when a MAPEM last arrived. An entry
         * seeded by a MAPEM alone has no phases yet (phase_seen 0 = never) --
         * fall back to last_seen, else its age froze at 0 = "just now". */
        uint32_t seen = e->phase_seen ? e->phase_seen : e->last_seen;
        unsigned long age = (seen && now > seen) ? (unsigned long)(now - seen) : 0;
        char agebuf[24];
        if (current_lang == LANG_DE) snprintf(agebuf, sizeof(agebuf), "vor %lus", age);
        else                         snprintf(agebuf, sizeof(agebuf), "%lus ago", age);

        /* Prefer the MAPEM name when the intersection sends one; the numeric
         * id stays visible next to it, just demoted to the detail line. */
        char nameesc[ITS_MAP_NAME_LEN * 6];
        html_escape(e->name, nameesc, sizeof(nameesc));
        /* Sized for the escaped name (up to ITS_MAP_NAME_LEN*6) plus the
         * surrounding markup -- a truncated closing tag here would break the
         * page layout, see the chip-buffer note above. */
        char head[512];
        if (e->name[0])
            snprintf(head, sizeof(head),
                "<div class='isec'><div class='t'>%s %s "
                "<small>(%u/%u &middot; Rev %u &middot; %s)</small></div>"
                "<div class='chips'>",
                T(S_TRF_INTERSECTION), nameesc, (unsigned)e->region,
                (unsigned)e->id, (unsigned)e->revision, agebuf);
        else
            snprintf(head, sizeof(head),
                "<div class='isec'><div class='t'>%s %u/%u "
                "<small>(Rev %u &middot; %s)</small></div><div class='chips'>",
                T(S_TRF_INTERSECTION), (unsigned)e->region, (unsigned)e->id,
                (unsigned)e->revision, agebuf);
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

        /* Controller mode / fault line. 256 covers every flag name set at
         * once (the German strings are the longer ones, ~186 bytes). */
        bool st_alert = false;
        char stbuf[256];
        if (spat_status_text(e->status, &st_alert, stbuf, sizeof(stbuf)))
        {
            char stline[448];
            snprintf(stline, sizeof(stline),
                "<p class='m' style='color:%s'>%s%s</p>",
                st_alert ? "#e74c3c" : "var(--mute)", st_alert ? "&#9888; " : "", stbuf);
            httpd_resp_send_chunk(req, stline, HTTPD_RESP_USE_STRLEN);
        }

        /* Speed limit and reference lane width, when the MAPEM carried them. */
        if (e->speed_max_kmh || e->lane_width_cm)
        {
            char geo[192], *g = geo;
            size_t left = sizeof(geo);
            int k = snprintf(g, left, "<p class='m'>");
            g += k; left -= (size_t)k;
            if (e->speed_max_kmh)
            {
                k = snprintf(g, left, "%s %u km/h",
                             current_lang == LANG_DE ? "Tempolimit" : "Speed limit",
                             (unsigned)e->speed_max_kmh);
                g += k; left -= (size_t)k;
            }
            if (e->lane_width_cm)
                snprintf(g, left, "%s%s %u,%02u m",
                         e->speed_max_kmh ? " &middot; " : "",
                         current_lang == LANG_DE ? "Spurbreite" : "Lane width",
                         (unsigned)(e->lane_width_cm / 100),
                         (unsigned)(e->lane_width_cm % 100));
            strlcat(geo, "</p>", sizeof(geo));
            httpd_resp_send_chunk(req, geo, HTTPD_RESP_USE_STRLEN);
        }

        /* Read before the chips, not after: the running-phase clock below sits
         * on the chip, and the tallies are the only place that start is kept. */
        static EXT_RAM_BSS_ATTR spatem_phases_t phbuf;
        const spatem_phases_t *ph = spatem_phases(e->region, e->id, &phbuf) ? &phbuf : NULL;

        for (int s = 0; s < e->n; s++)
        {
            /* Generous buffer: the styled chip alone is ~224 bytes, plus the
             * title text -- undersizing this once dropped the closing '>' of
             * </span>, leaving an unclosed span that collapsed the page width. */
            /* minEndTime is the EARLIEST the phase may end, not a promise --
             * the leading sign says so instead of reading like a countdown. */
            char cd[64] = "";
            if (e->change_at[s] > now && e->change_at[s] - now <= 600)
                snprintf(cd, sizeof(cd), " <small>&ge;%lus</small>",
                         (unsigned long)(e->change_at[s] - now));

            /* Prefer what the group actually controls over its bare number;
             * the number stays as a small suffix so it can still be matched
             * against the raw SPATEM data. */
            char mv[64];
            spat_movement_text(e, e->sg[s], mv, sizeof(mv));
            char label[160];
            if (mv[0])
                snprintf(label, sizeof(label), "%s <small>(%u)</small>",
                         mv, (unsigned)e->sg[s]);
            else
                snprintf(label, sizeof(label), "%u", (unsigned)e->sg[s]);

            /* Rows are keyed by group id, e->sg[] is message order -- indexing
             * the tallies by s would print one group's clock under another's dot. */
            char run[128] = "";
            for (uint8_t r = 0; ph && r < ph->n_rows; r++)
                if (ph->sg[r] == e->sg[s])
                {
                    /* Only with the flip actually watched AND the group still
                     * being heard: otherwise the number just counts silence. */
                    if (((ph->armed >> r) & 1u) && ph->now_mono > ph->since[r] &&
                        ph->now_mono - ph->last_mono[r] <= SPAT_GAP_SEC)
                    {
                        /* Formatted, not raw seconds: this junction rests in one
                         * phase for hours, and "23412 s" reads as noise. */
                        char rd[40];
                        format_uptime(ph->now_mono - ph->since[r], rd, sizeof(rd));
                        snprintf(run, sizeof(run),
                                 " <small>%s %s</small>",
                                 T(S_TRF_PH_SINCE), rd);
                    }
                    break;
                }

            char chip[768];
            snprintf(chip, sizeof(chip),
                "<span class='chip' title='%s'><i class='dot' style='background:%s'></i>"
                "%s%s%s</span>",
                spat_phase_name(e->phase[s]), spat_phase_color(e->phase[s]),
                label, cd, run);
            httpd_resp_send_chunk(req, chip, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);

        /* Measured phase durations. The controller never states these; they
         * come from watching each group flip, so they only appear once a few
         * full phases have been seen. */
        bool any = false;
        for (uint8_t r = 0; ph && r < ph->n_rows && !any; r++)
            if (ph->cnt[r][0] || ph->cnt[r][3]) any = true;
        if (any)
        {
            char dh[320];
            HTML_PRINTF(dh,
                "<div class='scroll'><table><thead><tr><th>%s</th><th>%s</th>"
                "<th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
                T(S_TRF_SG), T(S_TRF_PH_GREEN), T(S_TRF_PH_REDAMBER),
                T(S_TRF_PH_AMBER), T(S_TRF_PH_RED), T(S_TRF_CYCLES));
            httpd_resp_send_chunk(req, dh, HTTPD_RESP_USE_STRLEN);
            /* Walk the TALLY ROWS, not the message's group order: rows are
             * keyed by signal group id, so indexing them with the position in
             * e->sg[] would print one group's numbers under another's name. */
            for (uint8_t r = 0; r < ph->n_rows; r++)
            {
                if (!ph->cnt[r][0] && !ph->cnt[r][3])
                    continue;
                char cell[4][48];
                for (int c = 0; c < 4; c++)
                {
                    if (ph->cnt[r][c])
                        snprintf(cell[c], sizeof(cell[c]), "%lu s <small>(max %lu)</small>",
                                 (unsigned long)(ph->secs[r][c] / ph->cnt[r][c]),
                                 (unsigned long)ph->max[r][c]);
                    else
                        snprintf(cell[c], sizeof(cell[c]), "-");
                }
                char drow[320];
                HTML_PRINTF(drow,
                            "<tr><td>%u</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                            "<td>%lu</td></tr>",
                            (unsigned)ph->sg[r], cell[0], cell[1], cell[2], cell[3],
                            (unsigned long)ph->cnt[r][0]);
                httpd_resp_send_chunk(req, drow, HTTPD_RESP_USE_STRLEN);
            }
            httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
        }
        else
        {
            /* Nothing measured yet is not the same as broken -- a traffic-
             * actuated light can hold one phase for a long time at night. */
            char waitmsg[320];
            HTML_PRINTF(waitmsg, "<p class='note'>%s</p>", T(S_TRF_PH_WAIT));
            httpd_resp_send_chunk(req, waitmsg, HTTPD_RESP_USE_STRLEN);
        }
        /* closes this intersection's .isec */
        httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    }
    /* closes the traffic-lights .sect */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
}

/* Closes #trf-body and emits the auto-refresh script + footer. Unlike the
 * generic JSON-poll refresh, this re-fetches the page and swaps just the
 * #trf-body fragment in place (no full reload, so the background animation
 * keeps running), with the same floating pause/resume button. */
static void traffic_refresh_footer(httpd_req_t *req, uint32_t ri)
{
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    if (ri > 0 && ri < 0xFFFFFFFF)
    {
        char script[1024];
        snprintf(script, sizeof(script),
            "<script>(function(){var ri=%lu,t=null;"
            "function tick(){fetch(location.href,{cache:'no-store'}).then(function(r){return r.text();})"
            ".then(function(h){var d=new DOMParser().parseFromString(h,'text/html');"
            "var nb=d.getElementById('trf-body');"
            "if(nb)document.getElementById('trf-body').innerHTML=nb.innerHTML;}).catch(function(){});}"
            "window.addEventListener('load',function(){"
            "var b=document.createElement('button');"
            "b.style.cssText='position:fixed;bottom:12px;right:12px;z-index:99;opacity:.9;border-radius:4px;box-shadow:0 1px 4px #000';"
            "function u(){b.textContent=(localStorage.getItem('ar')!=='0'?'\\u23f8 ':'\\u25b6 ')+ri+'s';}"
            "b.onclick=function(){var on=localStorage.getItem('ar')==='0';localStorage.setItem('ar',on?'1':'0');"
            "if(on){tick();t=setInterval(tick,ri*1000);}else{if(t)clearInterval(t);}u();};"
            "u();document.body.appendChild(b);"
            "if(localStorage.getItem('ar')!=='0'){t=setInterval(tick,ri*1000);}"
            "});})();</script>",
            (unsigned long)ri);
        httpd_resp_send_chunk(req, script, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
}

/* Groups the hourly rows: the hour itself, or a local calendar day. */
static uint32_t trf_bucket_key(const stat_hour_t *h, bool daily)
{
    if (!daily)
        return h->hour;
    time_t t = (time_t)h->hour * 3600;
    struct tm lt;
    localtime_r(&t, &lt);
    return (uint32_t)((lt.tm_year + 1900) * 512 + lt.tm_yday);
}

/* The sender-list lookup takes a lock; several warning rows ask about the
 * same addresses, so memo the answers -- but never a busy list. */
typedef struct { uint8_t mac[6]; char name[INV_NAME_LEN]; uint32_t id; int8_t hit; } relay_memo_t;
#define RELAY_MEMO_N 4

static int relay_lookup(relay_memo_t *m, int *n, const uint8_t *mac,
                        char *out, size_t cap, uint32_t *id_out)
{
    for (int i = 0; i < *n; i++)
        if (memcmp(m[i].mac, mac, 6) == 0)
        {
            snprintf(out, cap, "%s", m[i].name);
            if (id_out) *id_out = m[i].id;
            return m[i].hit;
        }
    int r = inventory_lookup_mac(mac, out, cap, id_out);
    /* A busy list is not an answer -- memoing it would let one timeout decide
     * every remaining row of the page. */
    if (r >= 0 && *n < RELAY_MEMO_N)
    {
        memcpy(m[*n].mac, mac, 6);
        snprintf(m[*n].name, sizeof(m[*n].name), "%s", out);
        m[*n].id = id_out ? *id_out : 0;
        m[*n].hit = (int8_t)r;
        (*n)++;
    }
    return r;
}

/* Warnings per OBSERVED hour, scaled to the strongest bucket. A bucket that was
 * never observed is left out entirely -- a zero there would read as "quiet". */
static void emit_profile(httpd_req_t *req, const char *title, const char *colhdr,
                         const char *const *labels,
                         const uint32_t *ev, const uint32_t *obs, int nb)
{
    uint32_t peak = 1;
    for (int b = 0; b < nb; b++)
        if (obs[b])
        {
            uint32_t v = (uint32_t)((uint64_t)ev[b] * 100 / obs[b]);
            if (v > peak) peak = v;
        }
    char h[256];
    snprintf(h, sizeof(h),
             "<h3>%s</h3><div class='scroll'><table><thead><tr><th>%s</th>"
             "<th>%s</th></tr></thead><tbody>",
             title, colhdr, T(S_EVT_PERHOUR));
    httpd_resp_send_chunk(req, h, HTTPD_RESP_USE_STRLEN);
    for (int b = 0; b < nb; b++)
    {
        if (!obs[b])
            continue;
        uint32_t v = (uint32_t)((uint64_t)ev[b] * 100 / obs[b]);
        unsigned pct = (unsigned)((uint64_t)v * 100 / peak);
        char r[256];
        snprintf(r, sizeof(r),
            "<tr><td>%s</td><td>%lu.%02lu <small>(%lu / %lu)</small>"
            "<div class='bar' style='width:%u%%'></div></td></tr>",
            labels[b], (unsigned long)(v / 100), (unsigned long)(v % 100),
            (unsigned long)ev[b], (unsigned long)obs[b], pct);
        httpd_resp_send_chunk(req, r, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
}

static esp_err_t traffic_get_handler(httpd_req_t *req)
{
    resolve_language(req);

    uint32_t ri = 5;
    config_get_u32(CONFIG_INDEX_REFRESH_SEC, &ri);

    uint32_t hours = 24;
    char query[48], val[16];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
        httpd_query_key_value(query, "hours", val, sizeof(val)) == ESP_OK)
    {
        uint32_t h = (uint32_t)strtoul(val, NULL, 10);
        hours = (h == 168 || h == 720) ? h : 24;
    }
    /* Only the 24 h view changes fast enough to be worth a 5 s poll -- the
     * 30 d page is ~99 KB and would be refetched whole every interval. */
    if (hours != 24) ri = 0;

    static EXT_RAM_BSS_ATTR stat_hour_t rows[720];
    bool hist_ok = true;
    int n = tstat_read(hours, rows, 720, &hist_ok);   /* oldest-first */

    send_page_header(req, T(S_TITLE_TRAFFIC));

    const char *lc = current_lang == LANG_DE ? "de" : "en";
    char head[768];
    snprintf(head, sizeof(head),
        "<p class='note'>%s</p>"
        "<p class='jump'>%s: <a href='/traffic?hours=24&lang=%s'>%s</a> &middot; "
        "<a href='/traffic?hours=168&lang=%s'>%s</a> &middot; "
        "<a href='/traffic?hours=720&lang=%s'>%s</a></p>",
        T(S_TRF_INTRO), T(S_TRF_WINDOW),
        lc, T(S_TRF_W_24H), lc, T(S_TRF_W_7D), lc, T(S_TRF_W_30D));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

    /* Outside #trf-body on purpose: inside, the 5 s swap would rebuild it.
     * The warnings section is only emitted when there are hourly rows. */
    char jump[320];
    /* Clamped: snprintf returns the length it WANTED, so an unchecked sum
     * would step past the buffer instead of merely truncating. */
    int jr = snprintf(jump, sizeof(jump),
        "<p class='jump'>%s: <a href='#lights'>%s</a> &middot; <a href='#stats'>%s</a>",
        T(S_TRF_JUMP), T(S_TRF_LIGHTS), T(S_TRF_STATS));
    size_t jo = (jr < 0 || (size_t)jr >= sizeof(jump)) ? sizeof(jump) - 1 : (size_t)jr;
    if (n > 0)
    {
        jr = snprintf(jump + jo, sizeof(jump) - jo,
                      " &middot; <a href='#denm'>%s</a>", T(S_EVT_TITLE));
        jo += (jr < 0 || (size_t)jr >= sizeof(jump) - jo) ? sizeof(jump) - jo - 1 : (size_t)jr;
    }
    snprintf(jump + jo, sizeof(jump) - jo, "</p>");
    httpd_resp_send_chunk(req, jump, HTTPD_RESP_USE_STRLEN);

    /* Everything below the intro/selector is the auto-refreshed fragment. */
    httpd_resp_send_chunk(req, "<div id='trf-body'>", HTTPD_RESP_USE_STRLEN);
    if (!hist_ok)
    {
        /* Inside the fragment: the page swaps only this part on refresh, so
         * the note must appear and disappear with the data it describes. */
        char warn[384];
        HTML_PRINTF(warn, "<p class='note'>&#9888; %s</p>", T(S_TRF_BUSY));
        httpd_resp_send_chunk(req, warn, HTTPD_RESP_USE_STRLEN);
    }

    /* Live traffic-light phases first -- independent of the hourly stats, so
     * it shows even right after boot before any hour has accumulated. */
    emit_traffic_lights(req);

    if (n == 0)
    {
        char nd[384];
        snprintf(nd, sizeof(nd),
                 "<div class='grp' id='stats'><h2 class='ico'>&#128202; %s</h2>"
                 "<div class='warn'>%s</div></div>",
                 T(S_TRF_STATS), T(S_TRF_NODATA));
        httpd_resp_send_chunk(req, nd, HTTPD_RESP_USE_STRLEN);
        traffic_refresh_footer(req, ri);
        return ESP_OK;
    }

    /* Window totals + per-category speed. */
    uint64_t tot = 0;
    /* Every speed number on this page averages exactly these four: all other
     * categories carry a GN speed field too and report 0 km/h when parked. */
    static const int spcats[] = { STAT_CAT_CAR, STAT_CAT_BUS, STAT_CAT_TRUCK, STAT_CAT_TWOWHEEL };
    const unsigned SPCATS_N = sizeof(spcats) / sizeof(spcats[0]);
    bool speed_mixed = false;   /* window spans the 0.27.0 speed-rule change */
    uint64_t wsp_sum[STAT_NCAT] = {0}, wsp_cnt[STAT_NCAT] = {0};
    uint32_t wsp_max[STAT_NCAT] = {0};
    for (int i = 0; i < n; i++)
    {
        tot += rows[i].total;
        for (int c = 0; c < STAT_NCAT; c++)
        {
            wsp_sum[c] += rows[i].sp_sum[c];
            wsp_cnt[c] += rows[i].sp_cnt[c];
            if (rows[i].sp_max[c] > wsp_max[c]) wsp_max[c] = rows[i].sp_max[c];
        }
    }
    /* Overall speed -- vehicle categories only, same set as the cards below. */
    uint64_t osp_sum = 0, osp_cnt = 0; uint32_t osp_max = 0;
    for (unsigned k = 0; k < SPCATS_N; k++)
    {
        int c = spcats[k];
        osp_sum += wsp_sum[c]; osp_cnt += wsp_cnt[c];
        if (wsp_max[c] > osp_max) osp_max = wsp_max[c];
        for (int i = 0; i < n; i++)
            if (rows[i].speed_legacy && rows[i].sp_cnt[c]) speed_mixed = true;
    }

    /* --- Availability. The newest row is the hour still RUNNING and would
     * always read as a drop, so all of this stops at the last finished hour. */
    uint32_t now_h = (uint32_t)(time(NULL) / 3600);
    int nc = n;
    while (nc > 0 && rows[nc - 1].hour >= now_h) nc--;
    uint32_t med = 0, silent = 0, weak = 0;
    bool steady = false;
    if (nc > 0)
    {
        /* Median by binary search on the value instead of a sorted copy:
         * exact, and it needs no 2.8 KB of scratch. */
        uint32_t lo = 0, hi = 0;
        for (int k = 0; k < nc; k++)
            if (rows[k].total > hi) hi = rows[k].total;
        while (lo < hi)
        {
            uint32_t mid = lo + (hi - lo + 1) / 2;
            int cnt = 0;
            for (int k = 0; k < nc; k++)
                if (rows[k].total >= mid) cnt++;
            if (cnt * 2 >= nc) lo = mid; else hi = mid - 1;
        }
        med = lo;
        /* An hour in which nothing arrived writes no row at all, so this counts
         * silence -- it is not proof that the receiver was down. */
        /* Anchored at the window start, not at the oldest row found: a gap at
         * the old edge would shrink the denominator and read as no gap. */
        uint32_t from_h = now_h > hours - 1 ? now_h - (hours - 1) : 0;
        uint64_t up_s = esp_timer_get_time() / 1000000ull;
        time_t nowt = time(NULL);
        if (nowt > (time_t)up_s)
        {
            uint32_t boot_h = (uint32_t)((nowt - (time_t)up_s) / 3600);
            if (boot_h > from_h) from_h = boot_h;
        }
        uint32_t span = now_h > from_h ? now_h - from_h : 0;
        silent = span > (uint32_t)nc ? span - (uint32_t)nc : 0;
        int near = 0;
        for (int k = 0; k < nc; k++)
        {
            uint64_t d = rows[k].total > med ? rows[k].total - med : med - rows[k].total;
            if (d * 10 <= (uint64_t)med) near++;
            if (med && (uint64_t)rows[k].total * 4 < med) weak++;
        }
        /* Only where a permanent transmitter dominates is a low hour a gap:
         * with traffic-only reception the total drops every night by itself. */
        steady = hist_ok && med && nc >= 6 && near * 3 >= nc * 2;
    }
    /* An incomplete read would make the counts look worse than reality. */
    bool av_ok = hist_ok && nc > 0;

    char summary[640];
    snprintf(summary, sizeof(summary),
        "<div class='grp' id='stats'><h2 class='ico'>&#128202; %s</h2>"
        "<div class='grid'>"
        "<div class='cell'><div class='l'>%s</div><div class='v'>%llu</div></div>"
        "<div class='cell'><div class='l'>%s</div><div class='v'>%lu / %lu</div></div>",
        T(S_TRF_STATS),
        T(S_TRF_TOTAL), (unsigned long long)tot,
        T(S_TRF_SPEED), (unsigned long)(osp_cnt ? osp_sum / osp_cnt : 0), (unsigned long)osp_max);
    httpd_resp_send_chunk(req, summary, HTTPD_RESP_USE_STRLEN);

    /* Own chunk so these two can join the same card row; it closes .cards. */
    char avcards[288];
    size_t ao = 0;
    if (av_ok)
    {
        /* Clamped, same reason as `jump` above. */
        int ar = snprintf(avcards, sizeof(avcards),
            "<div class='cell'><div class='l'>%s</div><div class='v'>%lu</div></div>",
            T(S_TRF_SILENT), (unsigned long)silent);
        ao = (ar < 0 || (size_t)ar >= sizeof(avcards)) ? sizeof(avcards) - 1 : (size_t)ar;
        if (steady)
        {
            ar = snprintf(avcards + ao, sizeof(avcards) - ao,
                "<div class='cell'><div class='l'>%s</div><div class='v'>%lu</div></div>",
                T(S_TRF_WEAKHOURS), (unsigned long)weak);
            ao += (ar < 0 || (size_t)ar >= sizeof(avcards) - ao)
                  ? sizeof(avcards) - ao - 1 : (size_t)ar;
        }
    }
    snprintf(avcards + ao, sizeof(avcards) - ao, "</div>");
    httpd_resp_send_chunk(req, avcards, HTTPD_RESP_USE_STRLEN);
    if (av_ok)
    {
        /* Mandatory, not decoration: without it the page shows its own reboots
         * as a fault of the transmitter. */
        char avnote[448];
        HTML_PRINTF(avnote, "<p class='note'>%s</p>", T(S_TRF_AVAIL_HINT));
        httpd_resp_send_chunk(req, avnote, HTTPD_RESP_USE_STRLEN);
    }
    /* Next to the overall card, not just the per-type ones: the overall card
     * is always rendered, the per-type block only when a vehicle reported. */
    if (speed_mixed)
    {
        char note[352];
        snprintf(note, sizeof(note), "<p class='note'>%s</p>", T(S_TRF_SPEED_MIXED));
        httpd_resp_send_chunk(req, note, HTTPD_RESP_USE_STRLEN);
    }

    /* Speed by vehicle type (only categories that actually reported speed). */
    bool any_speed = false;
    for (unsigned k = 0; k < SPCATS_N; k++)
        if (wsp_cnt[spcats[k]] > 0) { any_speed = true; break; }
    if (any_speed)
    {
        char sh[128];
        snprintf(sh, sizeof(sh), "<h3>%s</h3><div class='grid'>", T(S_TRF_SPEED_BY_TYPE));
        httpd_resp_send_chunk(req, sh, HTTPD_RESP_USE_STRLEN);
        for (unsigned k = 0; k < SPCATS_N; k++)
        {
            int c = spcats[k];
            if (wsp_cnt[c] == 0) continue;
            char card[192];
            snprintf(card, sizeof(card),
                "<div class='cell'><div class='l'>%s</div><div class='v'>%lu / %lu</div></div>",
                trf_cat_label((uint8_t)(c == STAT_CAT_CAR ? 5 : c == STAT_CAT_BUS ? 6 :
                                        c == STAT_CAT_TRUCK ? 7 : 2)),
                (unsigned long)(wsp_sum[c] / wsp_cnt[c]), (unsigned long)wsp_max[c]);
            httpd_resp_send_chunk(req, card, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Beyond a day, hourly rows are unreadable and the old 72-row cap simply
     * hid the rest -- roll up per calendar day instead. */
    bool daily = (hours > 48);

    httpd_resp_send_chunk(req, "<div class='scroll'><table><thead><tr><th>",
                          HTTPD_RESP_USE_STRLEN);
    char thead[448];
    snprintf(thead, sizeof(thead),
        "%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
        "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
        daily ? T(S_TRF_DAY) : T(S_TRF_HOUR), T(S_TRF_TOTAL),
        T(S_CAT_CAR), T(S_CAT_BUS), T(S_CAT_TRUCK),
        T(S_CAT_TWOWHEEL), T(S_CAT_PED), T(S_CAT_RSU), T(S_CAT_OTHER), T(S_TRF_SPEED));
    httpd_resp_send_chunk(req, thead, HTTPD_RESP_USE_STRLEN);

    /* One bucket = one hour, or one calendar day in daily mode. Key is an
     * integer so grouping needs no string compare, and so the bar can be
     * scaled against the largest BUCKET rather than the largest hour. */
    uint32_t bar_max = 1;
    for (int k = n - 1; k >= 0; )
    {
        uint32_t key = trf_bucket_key(&rows[k], daily), sum = 0;
        while (k >= 0 && trf_bucket_key(&rows[k], daily) == key)
            sum += rows[k--].total;
        if (sum > bar_max) bar_max = sum;
    }

    int i = n - 1, shown = 0;
    while (i >= 0 && shown < 96)
    {
        stat_hour_t acc = { 0 };
        bool capped = false;
        uint32_t key = trf_bucket_key(&rows[i], daily);
        char when[24];
        time_t t0 = (time_t)rows[i].hour * 3600;
        struct tm lt0;
        localtime_r(&t0, &lt0);
        strftime(when, sizeof(when), daily ? "%Y-%m-%d" : "%m-%d %H:00", &lt0);

        while (i >= 0)
        {
            if (trf_bucket_key(&rows[i], daily) != key)
                break;
            acc.total += rows[i].total;
            for (int c = 0; c < STAT_NCAT; c++)
            {
                acc.cat[c]     += rows[i].cat[c];
                /* Summing hours would count a traffic light once per hour;
                 * the busiest hour is an honest lower bound for the day. */
                if (daily)
                {
                    if (rows[i].senders[c] > acc.senders[c])
                        acc.senders[c] = rows[i].senders[c];
                }
                else
                    acc.senders[c] += rows[i].senders[c];
                acc.sp_sum[c]  += rows[i].sp_sum[c];
                acc.sp_cnt[c]  += rows[i].sp_cnt[c];
                if (rows[i].sp_max[c] > acc.sp_max[c]) acc.sp_max[c] = rows[i].sp_max[c];
            }
            capped = capped || rows[i].senders_capped;
            i--;
        }
        shown++;

        uint64_t hsp_sum = 0, hsp_cnt = 0; uint32_t hsp_max = 0, senders = 0;
        for (int c = 0; c < STAT_NCAT; c++)
            senders += acc.senders[c];
        for (unsigned k = 0; k < SPCATS_N; k++)   /* same vehicle-only set */
        {
            int c = spcats[k];
            hsp_sum += acc.sp_sum[c]; hsp_cnt += acc.sp_cnt[c];
            if (acc.sp_max[c] > hsp_max) hsp_max = acc.sp_max[c];
        }
        unsigned pct = (unsigned)((uint64_t)acc.total * 100 / bar_max);

        /* Hours before 0.27.0 carry no identifier count -- a dash, not a zero
         * that would read as "nothing was there". &ge; when it is a lower bound. */
        const char *pre = senders ? (capped ? "&ge;" : "") : NULL;
        char cls[STAT_NCAT][16];
        for (int c = 0; c < STAT_NCAT; c++)
            if (pre)
                snprintf(cls[c], sizeof(cls[c]), "%s%lu", pre, (unsigned long)acc.senders[c]);
            else
                snprintf(cls[c], sizeof(cls[c]), "&ndash;");

        /* Per-category speed for this bucket, naming only what actually
         * measured. Hourly only: a daily mean answers a different question. */
        char spd2[288] = "";
        if (!daily)
        {
            char cats[224];
            size_t so = 0;
            unsigned ncat = 0;
            for (unsigned k = 0; k < SPCATS_N && so + 56 < sizeof(cats); k++)
            {
                int c = spcats[k];
                if (!acc.sp_cnt[c]) continue;
                ncat++;
                so += snprintf(cats + so, sizeof(cats) - so, "%s%s %lu/%lu",
                               so ? " &middot; " : "",
                               T(c == STAT_CAT_CAR   ? S_CAT_CAR :
                                 c == STAT_CAT_BUS   ? S_CAT_BUS :
                                 c == STAT_CAT_TRUCK ? S_CAT_TRUCK : S_CAT_TWOWHEEL),
                               (unsigned long)(acc.sp_sum[c] / acc.sp_cnt[c]),
                               (unsigned long)acc.sp_max[c]);
            }
            /* A single category would only repeat the cell above it. */
            if (ncat >= 2)
                snprintf(spd2, sizeof(spd2), "<div class='sub'>%s</div>", cats);
        }

        /* Same threshold as the "far below average" card: never the running
         * hour, and never a daily sum against an hourly median. */
        const char *rowcls = (!daily && steady && key < now_h &&
                              (uint64_t)acc.total * 4 < med) ? " class='v-bad'" : "";

        /* Number first, thin bar on its own line below -- the bar can span the
         * full cell without ever colliding with the count. */
        /* Per class the number of distinct identifiers, not messages: one car
         * at the light sends hundreds and would dwarf a whole bus route. */
        char row[768];
        snprintf(row, sizeof(row),
            "<tr><td>%s</td>"
            "<td%s>%lu<div class='bar' style='width:%u%%'></div></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%lu / %lu%s</td></tr>",
            when, rowcls, (unsigned long)acc.total, pct,
            cls[STAT_CAT_CAR], cls[STAT_CAT_BUS], cls[STAT_CAT_TRUCK],
            cls[STAT_CAT_TWOWHEEL], cls[STAT_CAT_PED], cls[STAT_CAT_RSU],
            cls[STAT_CAT_OTHER],
            (unsigned long)(hsp_cnt ? hsp_sum / hsp_cnt : 0), (unsigned long)hsp_max, spd2);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

    char snote[1024];
    HTML_PRINTF(snote, "<p class='note'>%s%s%s %s</p></div>", T(S_TRF_SENDERS_NOTE),
                daily ? " " : "", daily ? T(S_TRF_SENDERS_DAY) : "", T(S_TRF_IDENT_NOTE));
    httpd_resp_send_chunk(req, snote, HTTPD_RESP_USE_STRLEN);

    /* --- Warning events (DENM) for the same window, newest first. --- */
    char etitle[128];
    snprintf(etitle, sizeof(etitle),
             "<div class='grp' id='denm'><h2 class='ico'>&#9888;&#65039; %s</h2>",
             T(S_EVT_TITLE));
    httpd_resp_send_chunk(req, etitle, HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR event_rec_t evs[256];
    bool ev_ok = true, ev_capped = false;
    int en = events_read(hours, evs, 256, &ev_ok, &ev_capped);
    if (en == 0)
    {
        /* "None" is only true if the stored events were actually read. */
        char none[256];
        snprintf(none, sizeof(none), "<p class='note'>%s</p>",
                 ev_ok ? T(S_EVT_NONE) : T(S_TRF_BUSY));
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        /* Caveat first, then the table -- a busy card or a full array means the
         * rows below are a selection, not the window. */
        const char *cav = !ev_ok ? T(S_TRF_BUSY) : (ev_capped ? T(S_EVT_CAPPED) : NULL);
        if (cav)
        {
            char note[256];
            snprintf(note, sizeof(note), "<p class='note'>%s</p>", cav);
            httpd_resp_send_chunk(req, note, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "<div class='scroll'><table><thead><tr><th>",
                              HTTPD_RESP_USE_STRLEN);
        /* Same heading as /senders on purpose, so both pages read alike; the
         * unit appears in the header only. */
        char eh[192];
        snprintf(eh, sizeof(eh),
                 "%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
                 T(S_EVT_TIME), T(S_EVT_SENDER), T(S_SND_RSSI), T(S_EVT_WARNING));
        httpd_resp_send_chunk(req, eh, HTTPD_RESP_USE_STRLEN);
        relay_memo_t memo[RELAY_MEMO_N];
        int memo_n = 0;
        bool any_relay = false;
        for (int i = 0; i < en; i++)
        {
            time_t t = (time_t)evs[i].seconds;
            struct tm lt;
            localtime_r(&t, &lt);
            char when[64];
            strftime(when, sizeof(when), "%m-%d %H:%M:%S", &lt);
            /* One row is one event; show how long it went on and how many
             * broadcasts it took, rather than a row per broadcast. */
            if (evs[i].count > 1 && evs[i].last_seen > evs[i].seconds)
            {
                time_t t2 = (time_t)evs[i].last_seen;
                struct tm lt2;
                localtime_r(&t2, &lt2);
                char until[16];
                strftime(until, sizeof(until), "%H:%M:%S", &lt2);
                size_t w = strlen(when);
                snprintf(when + w, sizeof(when) - w,
                         " &ndash; %s <small>(%u&times;)</small>",
                         until, (unsigned)evs[i].count);
            }
            /* Class says WHAT warned, the id says WHO -- both in one cell so the
             * table does not grow five columns wide on a phone. */
            char sender[160];
            snprintf(sender, sizeof(sender), "%s", trf_cat_label(evs[i].station_type));
            if (evs[i].sender_id)
            {
                size_t o = strlen(sender);
                snprintf(sender + o, sizeof(sender) - o, " <span class='mono'>%lu</span>",
                         (unsigned long)evs[i].sender_id);
            }
            /* Its own test, not an else: the marker belongs on a row whose first
             * sender arrived without an id too. */
            if (evs[i].multi_sender)
            {
                size_t o = strlen(sender);
                snprintf(sender + o, sizeof(sender) - o, " <small>(%s)</small>", T(S_EVT_MULTI));
            }
            if (evs[i].n_macs > 1)
            {
                size_t o = strlen(sender);
                snprintf(sender + o, sizeof(sender) - o, " <small>(%s)</small>", T(S_EVT_RELAYED));
            }

            /* Which address relayed comes from the sender list, not from the
             * order heard -- the fixed RSU is often heard before the vehicle. */
            char relay[352] = "";
            if (evs[i].n_macs > 1)
            {
                any_relay = true;
                char nm_a[INV_NAME_LEN] = "", nm_b[INV_NAME_LEN] = "";
                char nmesc[INV_NAME_LEN * 6] = "";
                uint32_t id_a = 0, id_b = 0;
                relay_lookup(memo, &memo_n, evs[i].mac_a, nm_a, sizeof(nm_a), &id_a);
                relay_lookup(memo, &memo_n, evs[i].mac_b, nm_b, sizeof(nm_b), &id_b);
                /* The originator is the address carrying the message's own
                 * station id; an empty name cannot tell the two apart. */
                const char *nm = nm_b;
                unsigned via = evs[i].count_b;
                if (id_b && id_b == evs[i].sender_id)
                {
                    nm = nm_a;
                    via = evs[i].count > evs[i].count_b
                            ? (unsigned)(evs[i].count - evs[i].count_b) : 0u;
                }
                /* The name came off the air (MAPEM) -- escape it, exactly like
                 * the intersection name on this page. */
                if (nm[0])
                    html_escape(nm, nmesc, sizeof(nmesc));
                /* Only with exactly two sources does the remainder belong to
                 * the other one; a third makes the split unknowable. */
                char share[32] = "";
                if (evs[i].n_macs == 2)
                    snprintf(share, sizeof(share), " &middot; %u/%u",
                             via, (unsigned)evs[i].count);
                snprintf(relay, sizeof(relay),
                         "<div class='sub'>%s %s &middot; %s %u s%s</div>",
                         T(S_EVT_RELAY_VIA), nmesc[0] ? nmesc : T(S_EVT_RELAY_UNKNOWN),
                         T(S_EVT_RELAY_AFTER), (unsigned)evs[i].b_after_s, share);
            }

            /* A span, not one value: with 60 repeats the last frame says nothing.
             * It covers this row, not the whole warning. */
            char lvl[40] = "-";
            if (evs[i].rssi_min || evs[i].rssi_max)
            {
                if (evs[i].rssi_min == evs[i].rssi_max)
                    snprintf(lvl, sizeof(lvl), "%d", evs[i].rssi_min);
                else
                    snprintf(lvl, sizeof(lvl), "%d&hellip;%d", evs[i].rssi_min, evs[i].rssi_max);
            }

            /* Every stored event carries a position that the table used to
             * throw away. Both coordinates, like /map's own test. */
            char poslink[128] = "";
            if (evs[i].lat_e7 && evs[i].lon_e7)
                snprintf(poslink, sizeof(poslink),
                         " <a class='pin' href='/map?lang=%s&amp;lat=%ld&amp;lon=%ld' title='%s'>"
                         "&#128205;</a>",
                         current_lang == LANG_EN ? "en" : "de",
                         (long)evs[i].lat_e7, (long)evs[i].lon_e7, T(S_EVT_SHOWPOS));

            /* 66 bytes of markup + when[64] + poslink[128] + sender[160] +
             * relay[352] + lvl[40] + cause[160]; sub-causes pushed `cause` past 256. */
            char erow[1024];
            /* Only cause 1 has been seen in real traffic and confirmed
             * against tshark, so anything else shows its raw code rather
             * than a guessed description. */
            char cause[160];
            const char *ct = denm_cause_text(evs[i].cause);
            const char *st2 = denm_sub_text(evs[i].cause, evs[i].subcause);
            if (ct && st2)
                snprintf(cause, sizeof(cause), "%s <small>(%s)</small>", ct, st2);
            else if (ct && evs[i].subcause)
                snprintf(cause, sizeof(cause), "%s <small>(Detail %u)</small>",
                         ct, (unsigned)evs[i].subcause);
            else if (ct)
                /* Sub-cause 0 is the sender saying "unavailable" -- say so,
                 * otherwise it reads as a missing feature of this page. */
                snprintf(cause, sizeof(cause), "%s <small>(%s)</small>", ct,
                         current_lang == LANG_DE ? "ohne n&auml;here Angabe"
                                                 : "no detail given");
            else if (evs[i].cause == 0)
                snprintf(cause, sizeof(cause), "%s", T(S_EVT_DENM));
            else if (current_lang == LANG_DE)
                snprintf(cause, sizeof(cause), "Gefahrenmeldung (Code %u)", (unsigned)evs[i].cause);
            else
                snprintf(cause, sizeof(cause), "Hazard notification (code %u)", (unsigned)evs[i].cause);
            snprintf(erow, sizeof(erow),
                "<tr><td>%s%s</td><td>%s%s</td><td class='mono'>%s</td><td>&#9888; %s</td></tr>",
                when, poslink, sender, relay, lvl, cause);
            httpd_resp_send_chunk(req, erow, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
        /* Only when a row actually carries the marker -- everywhere else the
         * paragraph would explain something the reader cannot see. */
        if (any_relay)
        {
            char rh[512];
            HTML_PRINTF(rh, "<p class='note'>%s</p>", T(S_EVT_RELAY_HINT));
            httpd_resp_send_chunk(req, rh, HTTPD_RESP_USE_STRLEN);
        }

        /* Past 24 h only -- in one day each hour occurs once. A partial hourly
         * read would leave the denominator short and overstate every bar. */
        /* ev_ok too: hist_ok covers only the hourly read. Without the stored
         * warnings the numerator is a handful of open RAM events. */
        if (hours > 24 && hist_ok && ev_ok)
        {
            uint32_t ev_h[24] = {0}, obs_h[24] = {0};
            uint32_t ev_w[7]  = {0}, obs_w[7]  = {0};
            /* Same span for numerator and denominator: warnings keep their own
             * retention, and a capped list starts at its oldest row. */
            uint32_t ev_days = 30;
            config_get_u32(CONFIG_INDEX_EVENT_RETAIN_DAYS, &ev_days);
            if (ev_days == 0 || ev_days > 30) ev_days = 30;
            uint32_t nw = (uint32_t)time(NULL);
            uint32_t pf = nw > ev_days * 86400u ? nw - ev_days * 86400u : 0;
            if (ev_capped && evs[en - 1].seconds > pf) pf = evs[en - 1].seconds;
            for (int k = 0; k < n; k++)
            {
                if ((uint32_t)rows[k].hour < pf / 3600u) continue;
                time_t th = (time_t)rows[k].hour * 3600;
                struct tm lh;
                localtime_r(&th, &lh);
                obs_h[lh.tm_hour]++;
                obs_w[lh.tm_wday]++;
            }
            for (int k = 0; k < en; k++)
            {
                if (evs[k].seconds < pf) continue;
                time_t te = (time_t)evs[k].seconds;
                struct tm le;
                localtime_r(&te, &le);
                ev_h[le.tm_hour]++;
                ev_w[le.tm_wday]++;
            }
            char hl[24][3];
            const char *hp[24];
            for (int b = 0; b < 24; b++)
            {
                snprintf(hl[b], sizeof(hl[b]), "%02d", b);
                hp[b] = hl[b];
            }
            emit_profile(req, T(S_EVT_BYHOUR), T(S_TRF_HOUR), hp, ev_h, obs_h, 24);
            /* Split in place; a short table simply leaves the tail empty. */
            char wdbuf[64];
            const char *wd[7];
            snprintf(wdbuf, sizeof(wdbuf), "%s", T(S_TRF_WDAYS));
            char *wp = wdbuf;
            for (int d = 0; d < 7; d++)
            {
                wd[d] = wp;
                char *c = strchr(wp, ',');
                if (!c) { for (int e = d + 1; e < 7; e++) wd[e] = ""; break; }
                *c = '\0';
                wp = c + 1;
            }
            emit_profile(req, T(S_EVT_BYWDAY), T(S_TRF_DAY), wd, ev_w, obs_w, 7);
            char pfh[768];
            HTML_PRINTF(pfh, "<p class='note'>%s</p>", T(S_EVT_PROFILE_HINT));
            httpd_resp_send_chunk(req, pfh, HTTPD_RESP_USE_STRLEN);
        }
    }
    /* closes the warnings .sect (both branches above end here) */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);

    traffic_refresh_footer(req, ri);
    return ESP_OK;
}

/* GET /tracks.json?days=N -- vehicle tracks for the map overlay, grouped by
 * station so each vehicle becomes one polyline. Points come from the small
 * running log, NOT from the PCAP archive: see tracklog.h for why. */
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

    /* Sized for MAX retention (~25k points), not typical: a smaller cap dropped
     * the NEWEST tracks, same flaw as the old prune. Transient 520 KB PSRAM. */
    const int MAXPT = 26000;
    track_pt_t *pts = heap_caps_malloc(sizeof(track_pt_t) * MAXPT, MALLOC_CAP_SPIRAM);
    if (!pts)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
        return ESP_FAIL;
    }
    bool tracks_wrapped = false;
    int n = tracklog_read(days, pts, MAXPT, &tracks_wrapped);
    /* A full array means the read hit its cap and the OLDEST points of the
     * window were left out. Flagged in the reply so the overlay can say so
     * instead of drawing a short day and looking complete. */
    /* Only a real wrap loses points. Exactly MAXPT rows fits without loss, so
     * equality with the cap must not raise the flag. */
    bool capped = tracks_wrapped;

    httpd_resp_set_type(req, "application/json");
    /* Same reasoning as /markers.json: another receiver's map page reads this
     * cross-origin to draw all receivers' tracks on one map. Read-only, no
     * credential involved. */
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    /* {"t":[tracks],"c":1} -- "c" marks a reply that hit the point cap. All
     * receivers on a map are expected to run the same firmware, so this reads
     * the same shape from a peer as from itself. */
    httpd_resp_send_chunk(req, "{\"t\":[", HTTPD_RESP_USE_STRLEN);

    /* The log is in time order, so a station's points are scattered through
     * it. Walk it once per distinct station rather than sorting 12,000
     * records in place -- station counts are small (tens), and this keeps
     * peak memory to the one array. */
    bool first_track = true;
    bool client_gone = false;
    for (int i = 0; i < n && !client_gone; i++)
    {
        if (pts[i].station_id == 0)
            continue;                      /* already emitted below */
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
         * locked). Without this check the handler kept marching through all
         * 26,000 points, formatting and "sending" into a dead socket. */
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
    /* Ring-empty and `landed` are separate questions; the byte count answers
     * neither -- it is 0 for an empty ring and for a failed write alike. */
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
    /* Only whether the write landed. Testing the ring for emptiness as well
     * looked stricter but was simply always false with a live sniffer, so
     * every export got stamped "-teilweise" on a perfectly complete archive. */
    return landed;
}

/* Same question, but only asked where the ring can still hold part of the
 * answer -- a false "partial" invites an RSU re-send, and a re-send ADDS. */
static bool pcap_window_on_card(uint32_t to_sec)
{
    /* Bound by the CONFIGURED flush interval, never a fixed guess: the writer
     * empties the ring only on that interval. Doubled for the write itself. */
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

    /* Explicit from/to (unix seconds) rather than "last N minutes from now",
     * so any stored window is reachable -- not just a recent one -- now that
     * retention can span a full day or more. */
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
        /* This IDF's httpd only defines 500/501/505, so 500 it is -- the
         * point is that the page sees an error instead of an empty array. */
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
    /* ~1.6 KB struct on the worker stack; kept off `static` so an inline-served
     * request can't corrupt a deferred one's state. */
    playback_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.req = req;
    ctx.first = true;
    ctx.buf = pbuf;
    ctx.cap = PB_BUF_CAP;

    /* The newest minutes live in the ring, not in the files -- only relevant
     * for a window that runs up to "now", see pcap_window_on_card(). */
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
         * forever and wedge the worker -- full twice in a row: skip, say so. */
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
 *  GET /senders -- stationary senders (RSU/traffic light) heard since
 *  boot. Pure RAM, no SD access, so it runs on the httpd task.
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

            /* The MAPEM name IS the identity where there is one; id, MAC and the
             * mostly empty intersection become detail under it. */
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
             * line -- a dash there would claim something was measured. */
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
            /* 1024, not 640: the collapsed wrapper plus the summary leaves only
             * 27 bytes there, and a cut-off </details> eats the rest of the page. */
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
            /* The array feeds the headway maths above; the table stays at 120
             * rows, because 2000 would be hundreds of kilobytes of markup. */
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

/* Defined further down with the update handlers; declared here because the
 * two clear endpoints above it need the same gate -- including the 401 reply,
 * without which the handler returns having sent nothing at all and the
 * browser's fetch() just hangs instead of asking for the password. */
static bool check_update_auth(httpd_req_t *req);
static esp_err_t send_auth_required(httpd_req_t *req);

static esp_err_t transit_clear_post_handler(httpd_req_t *req)
{
    /* Destroys persisted user data, so it belongs behind the same gate as the
     * firmware update and the raw downloads. It was reachable by anyone on the
     * network with a single POST. */
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
     * firmware update and the raw downloads. It was reachable by anyone on the
     * network with a single POST. */
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

static bool check_update_auth(httpd_req_t *req)
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
    /* Reading the page is gated too, not just saving: it renders the MQTT URI
     * (which carries broker credentials when one is configured), the network
     * setup and the peer list -- and the settings page itself advertises the
     * password as protecting /settings. */
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* The save() POST carries no query string of its own; without ?lang=
     * here, resolve_language() on that request defaults to German
     * regardless of the page's actual language (same bug class as /update
     * and /confirm), so "X setting(s) saved." would always show German. */
    const char *lc = current_lang == LANG_DE ? "de" : "en";

    char nodeid[CONFIG_NODEID_BUFFER_SIZE * 6] = {0};
    char mqtt_uri[CONFIG_MQTT_URI_BUFFER_SIZE * 6] = {0};
    char ntp_server[CONFIG_NTP_SERVER_BUFFER_SIZE * 6] = {0};
    settings_get_str(CONFIG_INDEX_NODEID, nodeid, sizeof(nodeid));
    settings_get_str(CONFIG_INDEX_MQTT_URI, mqtt_uri, sizeof(mqtt_uri));
    settings_get_str(CONFIG_INDEX_NTP_SERVER, ntp_server, sizeof(ntp_server));

    uint32_t chan = 0;
    config_get_u32(CONFIG_INDEX_AUTOSTART_CHAN, &chan);
    uint8_t broadcast_only = 1;
    config_get_u8(CONFIG_INDEX_BROADCAST_ONLY, &broadcast_only);
    uint8_t brightness = 0;
    config_get_u8(CONFIG_INDEX_LED_BRIGHTNESS, &brightness);
    uint32_t led_override = 0;
    config_get_u32(CONFIG_INDEX_LED_OVERRIDE_COLOR, &led_override);
    uint32_t refresh_sec = 5;
    config_get_u32(CONFIG_INDEX_REFRESH_SEC, &refresh_sec);
    uint32_t map_stale_sec = 60;
    config_get_u32(CONFIG_INDEX_MAP_STALE_SEC, &map_stale_sec);
    char peers_esc[CONFIG_PEERS_BUFFER_SIZE * 6];
    settings_get_str(CONFIG_INDEX_PEERS, peers_esc, sizeof(peers_esc));
    uint8_t bt_en = 0;
    config_get_u8(CONFIG_INDEX_BT_ENABLE, &bt_en);

    /* Whether a web password is currently set. We never echo the password
     * itself back into the page, only whether one exists. */
    char cur_pw[CONFIG_WEB_PASSWORD_BUFFER_SIZE] = {0};
    size_t cur_pw_size = sizeof(cur_pw);
    bool pw_set = config_get_str(CONFIG_INDEX_WEB_PASSWORD, cur_pw, &cur_pw_size) == ESP_OK
                  && cur_pw_size > 1;

#if CONFIG_ENABLE_SD
    uint8_t log_sys = 0;
    uint32_t log_mb = 50;
    config_get_u8(CONFIG_INDEX_LOG_SYS, &log_sys);
    config_get_u32(CONFIG_INDEX_LOG_MAX_MB, &log_mb);

    uint8_t pcap_en = 0;
    uint32_t pcap_hours = 24, pcap_mb = 300, pcap_buf_mb = 1, pcap_flush_sec = 300;
    config_get_u8(CONFIG_INDEX_PCAP_ENABLE, &pcap_en);
    config_get_u32(CONFIG_INDEX_PCAP_RETAIN_HOURS, &pcap_hours);
    config_get_u32(CONFIG_INDEX_PCAP_MAX_MB, &pcap_mb);
    config_get_u32(CONFIG_INDEX_PCAP_BUF_MB, &pcap_buf_mb);
    config_get_u32(CONFIG_INDEX_PCAP_FLUSH_SEC, &pcap_flush_sec);
    uint8_t trk_on = 0, pcap_filt = 0;
    uint32_t trk_days = 2;
    config_get_u8(CONFIG_INDEX_TRACKS_ENABLE, &trk_on);
    config_get_u8(CONFIG_INDEX_PCAP_FILTER, &pcap_filt);
    config_get_u32(CONFIG_INDEX_TRACKS_DAYS, &trk_days);

    uint32_t stats_days = 30, event_days = 30;
    config_get_u32(CONFIG_INDEX_STATS_RETAIN_DAYS, &stats_days);
    config_get_u32(CONFIG_INDEX_EVENT_RETAIN_DAYS, &event_days);
#endif

    /* Ethernet: no static IP stored → DHCP. DNS applies in either mode. */
    char ethip[64] = {0}, ethnm[64] = {0}, ethgw[64] = {0};
    char ethdns0[64] = {0}, ethdns1[64] = {0}, ethdns2[64] = {0};
    settings_get_str(CONFIG_INDEX_ETH_IP, ethip, sizeof(ethip));
    settings_get_str(CONFIG_INDEX_ETH_NETMASK, ethnm, sizeof(ethnm));
    settings_get_str(CONFIG_INDEX_ETH_GATEWAY, ethgw, sizeof(ethgw));
    settings_get_str(CONFIG_INDEX_ETH_DNS0, ethdns0, sizeof(ethdns0));
    settings_get_str(CONFIG_INDEX_ETH_DNS1, ethdns1, sizeof(ethdns1));
    settings_get_str(CONFIG_INDEX_ETH_DNS2, ethdns2, sizeof(ethdns2));
    bool dhcp = (ethip[0] == '\0');

#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
    uint8_t eth_leds = 1;
    config_get_u8(CONFIG_INDEX_ETH_LEDS, &eth_leds);
#endif

    /* Live status (what's actually bound right now, e.g. the DHCP-obtained
     * IP), as opposed to the ethip/... above which is only ever set for a
     * static config. Shown read-only above the editable fields. */
    ethernet_status_t eth_now;
    ethernet_get_status(&eth_now);
    char cur_line[256];
    if (eth_now.up)
    {
        char dns_join[64];
        snprintf(dns_join, sizeof(dns_join), "%s%s%s%s%s",
            eth_now.dns[0], eth_now.dns[1][0] ? ", " : "", eth_now.dns[1],
            eth_now.dns[2][0] ? ", " : "", eth_now.dns[2]);
        snprintf(cur_line, sizeof(cur_line), "%s: %s / %s / %s%s%s",
            T(S_ETH_CURRENT), eth_now.ip, eth_now.netmask, eth_now.gateway,
            dns_join[0] ? " &middot; DNS " : "", dns_join);
    }
    else
    {
        snprintf(cur_line, sizeof(cur_line), "%s: %s", T(S_ETH_CURRENT), T(S_ETH_CUR_NOT_UP));
    }

    /* LED override is stored as a plain 24-bit RGB value (see led.c); render
     * it as a #rrggbb string for the <input type=color> picker. */
    char led_color[8];
    snprintf(led_color, sizeof(led_color), "#%06lx", (unsigned long)(led_override & 0xFFFFFFUL));

    send_page_header(req, T(S_TITLE_SETTINGS));

    char intro[256];
    snprintf(intro, sizeof(intro), "<p class='note'>%s</p>", T(S_SET_INTRO));
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);

    /* Six form groups of up to eleven rows each. Storage/Traffic are SD-only
     * below, so their links carry the same #if -- else they point at nothing. */
    char setjump[384];
    HTML_PRINTF(setjump,
        "<p class='jump'>%s: <a href='#g-gen'>%s</a> &middot; <a href='#g-net'>%s</a>"
        " &middot; <a href='#g-mqtt'>%s</a>"
#if CONFIG_ENABLE_SD
        " &middot; <a href='#g-sto'>%s</a> &middot; <a href='#g-trf'>%s</a>"
#endif
        " &middot; <a href='#g-sec'>%s</a></p>",
        T(S_TRF_JUMP), T(S_SET_GROUP_GENERAL), T(S_SET_GROUP_NETWORK),
        T(S_SET_GROUP_MQTT),
#if CONFIG_ENABLE_SD
        T(S_SET_GROUP_STORAGE), T(S_SET_GROUP_TRAFFIC),
#endif
        T(S_SET_GROUP_SECURITY));
    httpd_resp_send_chunk(req, setjump, HTTPD_RESP_USE_STRLEN);

    /* Each section is its own chunk, same multi-chunk pattern as
     * render_activity_stats; EXT_RAM_BSS_ATTR/static keeps them off the
     * httpd task's stack. */

    /* --- General: identity, sniffer filtering, LED, UI refresh --- */
    /* 6144 against a measured worst case of 3658 B (escaped peer list 954,
     * node ID 378); HTML_PRINTF only logs a truncation, so headroom is cheap. */
    static EXT_RAM_BSS_ATTR char general[6144];
    HTML_PRINTF(general,
        "<div class='grp top' id='g-gen'><h2>%s</h2><table class='kv set'>"
        /* size='16', not the field's full width: the HTML size attribute
         * skews auto-layout column width even under a CSS width:100% rule
         * (size=40 alone pushed the table wider than a phone screen). */
        "<tr><th>%s</th><td><input id='nodeid' value='%s' size='16'></td></tr>"
        "<tr><th>%s</th><td><select id='chan'>"
        "<option value='0'%s>%s</option>"
        "<option value='5900'%s>G5CC (5900)</option>"
        "<option value='5890'%s>G5SC2 (5890)</option>"
        "<option value='5880'%s>G5SC1 (5880)</option>"
        "<option value='5870'%s>G5SC3 (5870)</option>"
        "<option value='5860'%s>G5SC4 (5860)</option>"
        "</select></td></tr>"
        "<tr><th>%s</th><td><input type='checkbox' id='broadcastonly'%s>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td>"
        "<input type='range' id='led' min='0' max='255' value='%u' "
        "oninput=\"document.getElementById('ledval').innerText=this.value\">"
        "<span id='ledval'>%u</span></td></tr>"
        "<tr><th>%s</th><td><input type='color' id='ledoverride' value='%s'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td><input id='refreshsec' type='number' min='0' max='3600' value='%lu' size='6'></td></tr>"
        "<tr><th>%s</th><td><input id='mapstale' type='number' min='10' max='3600' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td><input id='peers' value='%s' maxlength='159' placeholder='its-node344.local, 192.168.178.40'>"
        "<br><small>%s</small></td></tr>"
        /* Size new rows against general[] at its declaration, not from here. */
        "<tr><th>%s</th><td><input type='checkbox' id='bten'%s>"
        "<br><small>%s</small></td></tr>"
        "</table></div>",
        T(S_SET_GROUP_GENERAL),
        T(S_NODEID), nodeid,
        T(S_AUTOSTART_CHAN),
        chan == 0 ? " selected" : "", T(S_CHAN_NONE),
        chan == 5900 ? " selected" : "",
        chan == 5890 ? " selected" : "",
        chan == 5880 ? " selected" : "",
        chan == 5870 ? " selected" : "",
        chan == 5860 ? " selected" : "",
        T(S_BROADCAST_ONLY), broadcast_only ? " checked" : "", T(S_BROADCAST_ONLY_HINT),
        T(S_LED_BRIGHTNESS), brightness, brightness,
        T(S_LED_OVERRIDE), led_color, T(S_LED_OVERRIDE_HINT),
        T(S_REFRESH_SEC), (unsigned long)refresh_sec,
        T(S_MAP_STALE_SEC), (unsigned long)map_stale_sec, T(S_MAP_STALE_HINT),
        T(S_PEERS), peers_esc, T(S_PEERS_HINT),
        T(S_BT_ENABLE), bt_en ? " checked" : "", T(S_BT_HINT));
    httpd_resp_send_chunk(req, general, HTTPD_RESP_USE_STRLEN);

    /* --- Network --- */
    static EXT_RAM_BSS_ATTR char network[4096];
    snprintf(network, sizeof(network),
        "<div class='grp' id='g-net'><h2>%s</h2><table class='kv set'>"
        "<tr><th></th><td>%s</td></tr>"
        "<tr><th>%s</th><td><input type='checkbox' id='dhcp'%s onchange='dhcpToggle()'></td></tr>"
        "<tr><th>%s</th><td><input class='ipfield' id='ethip' value='%s' size='16' maxlength='15'></td></tr>"
        "<tr><th>%s</th><td><input class='ipfield' id='ethnm' value='%s' size='16' maxlength='15'></td></tr>"
        "<tr><th>%s</th><td><input class='ipfield' id='ethgw' value='%s' size='16' maxlength='15'></td></tr>"
        "<tr><th>%s</th><td><input class='ipfield' id='ethdns0' value='%s' size='16' maxlength='15'> "
        "<input class='ipfield' id='ethdns1' value='%s' size='16' maxlength='15'> "
        "<input class='ipfield' id='ethdns2' value='%s' size='16' maxlength='15'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td><input id='ntpserver' value='%s' size='16'></td></tr>"
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
        /* LED control exists only on the KSZ8851SNL; on other chips the row
         * is omitted entirely (see ethernet_apply_led_setting). */
        "<tr><th>%s</th><td><input type='checkbox' id='ethleds'%s>"
        "<br><small>%s</small></td></tr>"
#endif
        "</table></div>",
        T(S_SET_GROUP_NETWORK),
        cur_line,
        T(S_ETH_DHCP), dhcp ? " checked" : "",
        T(S_ETH_IP), ethip,
        T(S_ETH_NETMASK), ethnm,
        T(S_ETH_GATEWAY), ethgw,
        T(S_ETH_DNS), ethdns0, ethdns1, ethdns2,
        T(S_ETH_NET_NOTE),
        T(S_NTP_SERVER), ntp_server
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
        , T(S_ETH_LEDS), eth_leds ? " checked" : "", T(S_ETH_LEDS_HINT)
#endif
        );
    httpd_resp_send_chunk(req, network, HTTPD_RESP_USE_STRLEN);

    /* --- MQTT --- */
    static EXT_RAM_BSS_ATTR char mqtt_block[2048];
    snprintf(mqtt_block, sizeof(mqtt_block),
        "<div class='grp' id='g-mqtt'><h2>%s</h2><table class='kv set'>"
        "<tr><th>%s</th><td><input id='mqtturi' value='%s' size='16'></td></tr>"
        "</table></div>",
        T(S_SET_GROUP_MQTT), T(S_MQTT_URI), mqtt_uri);
    httpd_resp_send_chunk(req, mqtt_block, HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD
    /* --- Storage (SD): logging + PCAP capture --- */
    static EXT_RAM_BSS_ATTR char storage[3072];
    HTML_PRINTF(storage,
        "<div class='grp' id='g-sto'><h2>%s</h2><table class='kv set'>"
        "<tr><th>%s</th><td><input type='checkbox' id='logsys'%s></td></tr>"
        "<tr><th>%s</th><td><input id='logmaxmb' type='number' min='1' max='512' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td><input type='checkbox' id='pcapen'%s></td></tr>"
        "<tr><th>%s</th><td><input id='pcaphours' type='number' min='1' max='720' value='%lu' size='6'></td></tr>"
        "<tr><th>%s</th><td><input id='pcapmaxmb' type='number' min='1' max='100000' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td><input id='pcapbufmb' type='number' min='1' max='4' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td><input id='pcapflushsec' type='number' min='8' max='3600' value='%lu' size='6'></td></tr>"
        "<tr><th>%s</th><td><select id='pcapfilt'>"
        "<option value='0'%s>%s</option>"
        "<option value='1'%s>%s</option>"
        "<option value='2'%s>%s</option></select>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td><input type='checkbox' id='trkon'%s>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td><input id='trkdays' type='number' min='1' max='7' value='%lu' size='6'></td></tr>"
        "</table></div>",
        T(S_SET_GROUP_STORAGE),
        T(S_LOG_SYS), log_sys ? " checked" : "",
        T(S_LOG_BUDGET), (unsigned long)log_mb, T(S_LOG_HINT),
        T(S_PCAP_ENABLE), pcap_en ? " checked" : "",
        T(S_PCAP_RETAIN_HOURS), (unsigned long)pcap_hours,
        T(S_PCAP_MAX_MB), (unsigned long)pcap_mb, T(S_PCAP_HINT),
        T(S_PCAP_BUF_MB), (unsigned long)pcap_buf_mb, T(S_PCAP_BUF_HINT),
        T(S_PCAP_FLUSH_SEC), (unsigned long)pcap_flush_sec,
        T(S_PCAP_FILTER),
        pcap_filt == 0 ? " selected" : "", T(S_PCAP_FILT_ALL),
        pcap_filt == 1 ? " selected" : "", T(S_PCAP_FILT_THIN),
        pcap_filt == 2 ? " selected" : "", T(S_PCAP_FILT_VEH),
        T(S_PCAP_FILT_HINT),
        T(S_TRACKS_ENABLE), trk_on ? " checked" : "", T(S_TRACKS_HINT),
        T(S_TRACKS_DAYS), (unsigned long)trk_days);
    httpd_resp_send_chunk(req, storage, HTTPD_RESP_USE_STRLEN);

    /* --- Traffic page retention --- */
    char trfset[768];
    snprintf(trfset, sizeof(trfset),
        "<div class='grp' id='g-trf'><h2>%s</h2><table class='kv set'>"
        "<tr><th>%s</th><td><input id='statsdays' type='number' min='1' max='30' value='%lu' size='6'></td></tr>"
        "<tr><th>%s</th><td><input id='eventdays' type='number' min='1' max='30' value='%lu' size='6'></td></tr>"
        "</table></div>",
        T(S_SET_GROUP_TRAFFIC),
        T(S_STATS_RETAIN_DAYS), (unsigned long)stats_days,
        T(S_EVENT_RETAIN_DAYS), (unsigned long)event_days);
    httpd_resp_send_chunk(req, trfset, HTTPD_RESP_USE_STRLEN);
#endif

    /* --- Security --- */
    static EXT_RAM_BSS_ATTR char security[1024];
    snprintf(security, sizeof(security),
        "<div class='grp' id='g-sec'><h2>%s</h2><table class='kv set'>"
        "<tr><th>%s</th><td>"
        "<input type='password' id='webpasswd' size='16' autocomplete='new-password'>"
        "<br><small>%s</small>"
        "<br><label><input type='checkbox' id='webpwclear'> %s</label>"
        "</td></tr>"
        "</table></div>",
        T(S_SET_GROUP_SECURITY),
        T(S_WEB_PASSWORD),
        pw_set ? T(S_WEB_PASSWORD_SET) : T(S_WEB_PASSWORD_NONE),
        T(S_WEB_PASSWORD_CLEAR));
    httpd_resp_send_chunk(req, security, HTTPD_RESP_USE_STRLEN);

    /* Grew with the client-side range pre-check and the range hints. PSRAM,
     * so the size is cheap; -Wformat-truncation is what caught the last bump. */
    static EXT_RAM_BSS_ATTR char save_block[6144];
    HTML_PRINTF(save_block,
        /* Several settings only take effect after a reboot (network,
         * Bluetooth); itsReboot() lives in PAGE_FOOTER. */
        "<p><button onclick=\"save()\">%s</button> "
        /* Dirty asks about the lost edits, clean asks the plain question --
         * never both, so itsReboot gets null once we already confirmed. */
        "<button class='pwr' onclick=\"var d=document.body.classList.contains('dirty');"
        "if(d&&!confirm(ITS_UNSAVED_WARN))return;"
        "itsReboot(d?null:'%s','%s','%s','%s')\">%s</button> "
        "<span id='result'></span></p>"
        /* Floating save bar: appears once anything is edited and doubles as the
         * unsaved-changes indicator; the top button stays. */
        "<style>#savebar{position:fixed;left:0;right:0;bottom:0;z-index:900;"
        "display:none;padding:10px clamp(14px,4vw,32px);"
        /* Own colour, not inherited: if /s.css fails to load, the default
         * text colour would be black on this dark bar. */
        "background:rgba(21,25,29,.96);color:#edf0f2;border-top:1px solid #2a2f34;"
        "box-shadow:0 -4px 20px rgba(0,0,0,.45)}"
        "#savebar .in{max-width:1400px;margin:0 auto;display:flex;"
        "align-items:center;gap:12px;flex-wrap:wrap}"
        "#savebar small{color:#f2b134}"
        "body.dirty{padding-bottom:64px}</style>"
        /* No confirm: the click IS the intent. Reboots only on success --
         * answered is not succeeded. */
        "<div id='savebar'><div class='in'><button onclick=\"save()\">%s</button>"
        "<button class='pwr' onclick=\"var b=this;if(b.disabled)return;b.disabled=true;"
        "var pr=save();if(!pr){b.disabled=false;return;}"
        "pr.then(function(res){if(!res||!res.ok){b.disabled=false;return;}"
        "itsReboot(null,'%s','%s','%s').then(function(go){if(!go)b.disabled=false;});"
        "});\">%s</button>"
        "<small>%s</small> <span id='result2'></span></div></div>"
        "<script>var ITS_SET_BAD=\"%s\",ITS_UNSAVED_WARN=\"%s\",ITS_SAVE_NOCONN=\"%s\";"
        /* Show every number field's allowed range, read from the field's OWN
         * min/max so the hint can never drift from what the device enforces.
         * Without it a value outside the range was simply refused and the
         * setting looked like it had reset itself. */
        "document.querySelectorAll('input[type=number]').forEach(function(i){"
        "if(!i.min&&!i.max)return;"
        "i.insertAdjacentHTML('afterend',\" <small style='color:#94a0a8'>\"+"
        "(i.min||'0')+'\\u2013'+(i.max||'\\u221e')+'</small>');});"
        "function save(){"
        /* Check before sending: an empty or out-of-range number field used to
         * be discarded by the device without naming itself, and an emptied one
         * silently meant "0" for the fields where 0 is legal. */
        "var bad=[];"
        "document.querySelectorAll('input[type=number]').forEach(function(i){"
        "var v=i.value.trim();var n=Number(v);"
        "if(v===''||!isFinite(n)||(i.min!==''&&n<Number(i.min))||(i.max!==''&&n>Number(i.max))){"
        /* Name the field the way the page labels it. Every setting sits in a
         * <tr><th>label</th><td><input></td></tr>, so the row's header IS the
         * human name; the element id ('trkdays') means nothing to a reader. */
        "var r=i.closest('tr'),h=r?r.querySelector('th'):null;"
        "bad.push(h?h.textContent.trim():i.id);}});"
        "if(bad.length){document.getElementById('result2').textContent="
        "ITS_SET_BAD+' '+bad.join(', ');return null;}"
        "var p=new URLSearchParams();"
        "p.append('nodeid',document.getElementById('nodeid').value);"
        "p.append('mqtturi',document.getElementById('mqtturi').value);"
        "p.append('chan',document.getElementById('chan').value);"
        "p.append('broadcastonly',document.getElementById('broadcastonly').checked?'1':'0');"
        "p.append('led',document.getElementById('led').value);"
        "p.append('ledoverride',parseInt(document.getElementById('ledoverride').value.substring(1),16));"
        "p.append('refreshsec',document.getElementById('refreshsec').value);"
        "p.append('mapstale',document.getElementById('mapstale').value);"
        "p.append('peers',document.getElementById('peers').value);"
        "p.append('bten',document.getElementById('bten').checked?'1':'0');"
        "p.append('ntpserver',document.getElementById('ntpserver').value);"
        "p.append('webpasswd',document.getElementById('webpasswd').value);"
        "if(document.getElementById('webpwclear').checked)p.append('webpwclear','1');"
#if CONFIG_ENABLE_SD
        "p.append('logsys',document.getElementById('logsys').checked?'1':'0');"
            "p.append('logmaxmb',document.getElementById('logmaxmb').value);"
        "p.append('pcapen',document.getElementById('pcapen').checked?'1':'0');"
        "p.append('pcaphours',document.getElementById('pcaphours').value);"
        "p.append('pcapmaxmb',document.getElementById('pcapmaxmb').value);"
        "p.append('pcapbufmb',document.getElementById('pcapbufmb').value);"
        "p.append('pcapflushsec',document.getElementById('pcapflushsec').value);"
        "p.append('pcapfilt',document.getElementById('pcapfilt').value);"
        "p.append('trkon',document.getElementById('trkon').checked?'1':'0');"
        "p.append('trkdays',document.getElementById('trkdays').value);"
        "p.append('statsdays',document.getElementById('statsdays').value);"
        "p.append('eventdays',document.getElementById('eventdays').value);"
#endif
        "p.append('dhcp',document.getElementById('dhcp').checked?'1':'0');"
        "p.append('ethip',document.getElementById('ethip').value);"
        "p.append('ethnm',document.getElementById('ethnm').value);"
        "p.append('ethgw',document.getElementById('ethgw').value);"
        "p.append('ethdns0',document.getElementById('ethdns0').value);"
        "p.append('ethdns1',document.getElementById('ethdns1').value);"
        "p.append('ethdns2',document.getElementById('ethdns2').value);"
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
        "p.append('ethleds',document.getElementById('ethleds').checked?'1':'0');"
#endif
        /* Resolves {ok,t}: a fetch fulfils on 401 and on the 422 a rejection
         * returns, so only r.ok may clear the bar or trigger a reboot. */
        "return fetch('/settings?lang=%s',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:p.toString()})"
        ".then(function(r){return r.text().then(function(t){return {ok:r.ok,t:t};});})"
        ".then(function(res){document.getElementById('result').innerText=res.t;"
        "var r2=document.getElementById('result2');if(r2)r2.innerText=res.t;"
        "if(res.ok)markClean();return res;})"
        ".catch(function(e){var m=ITS_SAVE_NOCONN+' '+e;"
        "document.getElementById('result').innerText=m;"
        "var r2=document.getElementById('result2');if(r2)r2.innerText=m;"
        "return {ok:false,t:m};});"
        "}"
        /* Any edit anywhere in the page arms the bar. Bound with capture on
         * the document so fields added later are covered too, and so this
         * needs no per-field wiring. */
        "function markDirty(){document.getElementById('savebar').style.display='block';"
        "document.body.classList.add('dirty');}"
        "function markClean(){document.getElementById('savebar').style.display='none';"
        "document.body.classList.remove('dirty');}"
        /* The mobile nav's burger toggle is itself a checkbox (.nvt), and a
         * document-level listener hears it too -- opening the menu on a phone
         * showed "unsaved changes" with nothing edited. Anything inside <nav>
         * is chrome, not a setting. */
        "function editEvt(e){if(e.target&&e.target.closest&&e.target.closest('nav'))return;"
        "markDirty();}"
        "document.addEventListener('input',editEvt,true);"
        "document.addEventListener('change',editEvt,true);"
        "function dhcpToggle(){var d=document.getElementById('dhcp').checked;"
        "['ethip','ethnm','ethgw'].forEach(function(i){document.getElementById(i).disabled=d;});}"
        "dhcpToggle();"
        "</script>",
        T(S_SAVE), T(S_REBOOT_CONFIRM), T(S_REBOOTING), T(S_REBOOT_SLOW), T(S_REBOOT_DENIED),
        T(S_REBOOT), T(S_SAVE), T(S_REBOOTING), T(S_REBOOT_SLOW), T(S_REBOOT_DENIED),
        T(S_SAVE_REBOOT), T(S_UNSAVED), T(S_SET_BAD), T(S_UNSAVED_WARN), T(S_SAVE_NOCONN), lc);
    httpd_resp_send_chunk(req, save_block, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* Loose IPv4 dotted-quad check (4 octets, each 0-255). Empty string is NOT
 * valid here; callers treat empty separately (clear/DHCP). */
static bool is_ipv4(const char *s)
{
    int parts = 0, val = 0, digits = 0;
    for (const char *p = s; ; p++)
    {
        if (*p >= '0' && *p <= '9') { val = val * 10 + (*p - '0'); if (++digits > 3 || val > 255) return false; }
        else if (*p == '.' || *p == '\0') { if (digits == 0) return false; parts++; if (*p == '\0') break; val = 0; digits = 0; }
        else return false;
    }
    return parts == 4;
}

static esp_err_t settings_post_handler(httpd_req_t *req)
{
    resolve_language(req);

    if (!check_update_auth(req))
        return send_auth_required(req);

    char buf[2048];
    if (req->content_len == 0 || req->content_len > sizeof(buf) - 1)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
        return ESP_FAIL;
    }

    /* Loop until the whole declared body arrived -- a single recv may return
     * only part of it (TCP segmentation), and parsing a truncated form would
     * silently drop whatever settings came after the cut. Same retry pattern
     * as update_post_handler/sdcard_upload_handler. */
    size_t got = 0;
    int retries = 0;
    while (got < req->content_len)
    {
        int received = httpd_req_recv(req, buf + got, req->content_len - got);
        if (received == HTTPD_SOCK_ERR_TIMEOUT)
        {
            if (++retries > 5) break;
            continue;
        }
        if (received <= 0) break;
        retries = 0;
        got += received;
    }
    if (got < req->content_len)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "recv failed");
        return ESP_FAIL;
    }
    buf[got] = '\0';

    char value[256];
    int saved = 0, rejected = 0;

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
    if (httpd_query_key_value(buf, "broadcastonly", value, sizeof(value)) == ESP_OK)
    {
        if (config_set_u8(CONFIG_INDEX_BROADCAST_ONLY, strcmp(value, "1") == 0 ? 1 : 0) == ESP_OK) saved++;
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
    if (httpd_query_key_value(buf, "ledoverride", value, sizeof(value)) == ESP_OK)
    {
        /* Decimal (converted client-side from the color picker's hex); 24-bit RGB. */
        unsigned long v = strtoul(value, NULL, 10);
        if (config_set_u32(CONFIG_INDEX_LED_OVERRIDE_COLOR, (uint32_t)(v & 0xFFFFFFUL)) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "refreshsec", value, sizeof(value)) == ESP_OK)
    {
        unsigned long s = strtoul(value, NULL, 10);
        if (s > 3600)
            rejected++;
        else if (config_set_u32(CONFIG_INDEX_REFRESH_SEC, (uint32_t)s) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapfilt", value, sizeof(value)) == ESP_OK)
    {
        unsigned long m = strtoul(value, NULL, 10);
        if (m > 2)
            rejected++;
        else if (config_set_u8(CONFIG_INDEX_PCAP_FILTER, (uint8_t)m) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "trkon", value, sizeof(value)) == ESP_OK)
    {
        if (config_set_u8(CONFIG_INDEX_TRACKS_ENABLE,
                          value[0] == '1' ? 1 : 0) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "trkdays", value, sizeof(value)) == ESP_OK)
    {
        unsigned long d = strtoul(value, NULL, 10);
        if (d < 1 || d > 7)
                rejected++;
        else if (config_set_u32(CONFIG_INDEX_TRACKS_DAYS, (uint32_t)d) == ESP_OK) saved++;
    }
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
    if (httpd_query_key_value(buf, "ethleds", value, sizeof(value)) == ESP_OK)
    {
        if (config_set_u8(CONFIG_INDEX_ETH_LEDS, value[0] == '1' ? 1 : 0) == ESP_OK)
        {
            saved++;
            /* Unlike the other network settings this one needs no restart --
             * push it to the chip straight away. */
            ethernet_apply_led_setting();
        }
    }
#endif
    /* No 'rejected' branch: a checkbox only ever sends "1" or "0", so unlike the
     * number fields there is no out-of-range case to report. */
    if (httpd_query_key_value(buf, "bten", value, sizeof(value)) == ESP_OK)
    {
        if (config_set_u8(CONFIG_INDEX_BT_ENABLE, value[0] == '1' ? 1 : 0) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "peers", value, sizeof(value)) == ESP_OK)
    {
        url_decode(value);
        if (config_set_str(CONFIG_INDEX_PEERS, value) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "mapstale", value, sizeof(value)) == ESP_OK)
    {
        unsigned long s = strtoul(value, NULL, 10);
        if (s < 10 || s > 3600)
                rejected++;
        else if (config_set_u32(CONFIG_INDEX_MAP_STALE_SEC, (uint32_t)s) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "ntpserver", value, sizeof(value)) == ESP_OK)
    {
        url_decode(value);
        if (value[0] && config_set_str(CONFIG_INDEX_NTP_SERVER, value) == ESP_OK) saved++;
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
        /* config_set_str hashes it (see config_set_web_password) -- same
         * path the console's `config_set webpasswd` command also goes
         * through, so both ways of setting it end up consistent. */
        if (value[0] && config_set_str(CONFIG_INDEX_WEB_PASSWORD, value) == ESP_OK) saved++;
    }
#if CONFIG_ENABLE_SD
    /* SD logging: checkboxes send 0/1; config_set fires a config event so sdlog
     * picks up the change live. */
    if (httpd_query_key_value(buf, "logsys", value, sizeof(value)) == ESP_OK)
    {
        if (config_set_u8(CONFIG_INDEX_LOG_SYS, strcmp(value, "1") == 0 ? 1 : 0) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "logmaxmb", value, sizeof(value)) == ESP_OK)
    {
        unsigned long mb = strtoul(value, NULL, 10);
        /* The same bound sdlog actually enforces. Accepting 100000 here and
         * silently using 512 meant the page echoed back a number the device
         * was not honouring. */
        if (mb < 1 || mb > SDLOG_MAX_MB)
                rejected++;
        else if (config_set_u32(CONFIG_INDEX_LOG_MAX_MB, (uint32_t)mb) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapen", value, sizeof(value)) == ESP_OK)
    {
        if (config_set_u8(CONFIG_INDEX_PCAP_ENABLE, strcmp(value, "1") == 0 ? 1 : 0) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcaphours", value, sizeof(value)) == ESP_OK)
    {
        unsigned long h = strtoul(value, NULL, 10);
        if (h < 1 || h > 720)
                rejected++;
        else if (config_set_u32(CONFIG_INDEX_PCAP_RETAIN_HOURS, (uint32_t)h) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapbufmb", value, sizeof(value)) == ESP_OK)
    {
        unsigned long mb = strtoul(value, NULL, 10);
        if (mb < 1 || mb > 4)
                rejected++;
        else if (config_set_u32(CONFIG_INDEX_PCAP_BUF_MB, (uint32_t)mb) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapflushsec", value, sizeof(value)) == ESP_OK)
    {
        unsigned long s = strtoul(value, NULL, 10);
        if (s < 8 || s > 3600)
                rejected++;
        else if (config_set_u32(CONFIG_INDEX_PCAP_FLUSH_SEC, (uint32_t)s) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapmaxmb", value, sizeof(value)) == ESP_OK)
    {
        unsigned long mb = strtoul(value, NULL, 10);
        if (mb < 1 || mb > 100000)
                rejected++;
        else if (config_set_u32(CONFIG_INDEX_PCAP_MAX_MB, (uint32_t)mb) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "statsdays", value, sizeof(value)) == ESP_OK)
    {
        unsigned long d = strtoul(value, NULL, 10);
        if (d < 1 || d > 30)
                rejected++;
        else if (config_set_u32(CONFIG_INDEX_STATS_RETAIN_DAYS, (uint32_t)d) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "eventdays", value, sizeof(value)) == ESP_OK)
    {
        unsigned long d = strtoul(value, NULL, 10);
        if (d < 1 || d > 30)
                rejected++;
        else if (config_set_u32(CONFIG_INDEX_EVENT_RETAIN_DAYS, (uint32_t)d) == ESP_OK) saved++;
    }
#endif
    /* Ethernet / network — only touched when the form submitted the block, so a
     * partial POST never wipes it. Takes effect on the next reboot. */
    if (httpd_query_key_value(buf, "dhcp", value, sizeof(value)) == ESP_OK)
    {
        if (strcmp(value, "1") == 0)
        {
            /* DHCP: clear the static trio so the boot code runs a DHCP client. */
            config_set_str(CONFIG_INDEX_ETH_IP, "");
            config_set_str(CONFIG_INDEX_ETH_NETMASK, "");
            config_set_str(CONFIG_INDEX_ETH_GATEWAY, "");
            saved++;
        }
        else
        {
            char ip[64] = "", nm[64] = "", gw[64] = "";
            if (httpd_query_key_value(buf, "ethip", ip, sizeof(ip)) == ESP_OK) url_decode(ip);
            if (httpd_query_key_value(buf, "ethnm", nm, sizeof(nm)) == ESP_OK) url_decode(nm);
            if (httpd_query_key_value(buf, "ethgw", gw, sizeof(gw)) == ESP_OK) url_decode(gw);
            /* Static needs all three valid together, else the boot code falls back
             * to DHCP — store them atomically to avoid a half-configured state. */
            if (is_ipv4(ip) && is_ipv4(nm) && is_ipv4(gw))
            {
                config_set_str(CONFIG_INDEX_ETH_IP, ip);
                config_set_str(CONFIG_INDEX_ETH_NETMASK, nm);
                config_set_str(CONFIG_INDEX_ETH_GATEWAY, gw);
                saved++;
            }
            else
                rejected++;   /* was dropped in silence, and a wrong static IP
                               * is the one setting you cannot fix remotely */
        }
        /* DNS 1/2/3: empty clears, a valid address is stored. Applies in both
         * DHCP and static mode. */
        static const struct { const char *key; config_index_t idx; } dnsf[3] = {
            { "ethdns0", CONFIG_INDEX_ETH_DNS0 },
            { "ethdns1", CONFIG_INDEX_ETH_DNS1 },
            { "ethdns2", CONFIG_INDEX_ETH_DNS2 },
        };
        for (size_t i = 0; i < 3; i++)
        {
            char d[64] = "";
            if (httpd_query_key_value(buf, dnsf[i].key, d, sizeof(d)) == ESP_OK)
            {
                url_decode(d);
                if (d[0] == '\0')      { if (config_set_str(dnsf[i].idx, "") == ESP_OK) saved++; }
                else if (is_ipv4(d))   { if (config_set_str(dnsf[i].idx, d)  == ESP_OK) saved++; }
                else                   rejected++;
            }
        }
    }

    char msg[160];
    if (rejected)
        snprintf(msg, sizeof(msg), T(S_SAVED_REJECTED), saved, rejected);
    else
        snprintf(msg, sizeof(msg), T(S_SAVED), saved);
    /* Lets the browser tell "saved" from "partly rejected" without parsing a
     * translated sentence. Text unchanged either way. */
    if (rejected)
        httpd_resp_set_status(req, "422 Unprocessable Entity");
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, msg);
    return ESP_OK;
}

/* ================================================================== */
/*  /sniffer, /reboot, /confirm                                       */
/* ================================================================== */

static esp_err_t sniffer_post_handler(httpd_req_t *req)
{
    /* Stopping reception destroys data that was never recorded, so it belongs
     * behind the same gate as the clear endpoints and the downloads -- the
     * password protected taking data OUT but not switching the intake off. */
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
    /* Same gate as /poweroff and /sniffer: one unauthenticated POST used to be
     * enough to restart a mounted receiver from anywhere on the network. */
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

/* POST /poweroff: flushes every buffer and unmounts -- the reply IS the "safe
 * to unplug" signal, so it runs inline. Recording stays off until restart, by design. */
#if CONFIG_ENABLE_SD
static esp_err_t poweroff_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* Leaves the card unmounted with auto-remount inhibited: one unauthenticated
     * POST stopped recording, tracks, transit log and pcap until someone mounts
     * again or reboots. Same gate as /sdcard/mount, which undoes it. */
    if (!check_update_auth(req))
        return send_auth_required(req);

    /* Same flush the restart paths use, plus the unmount that only makes
     * sense when nothing is going to run afterwards. */
    sysmon_flush_persistent();

    /* Before the unmount: sysmon would otherwise mount the card straight
     * back after 30 s, undoing the safe state while the user walks over. */
    sdcard_inhibit_auto_remount();

    esp_err_t err = sdcard_unmount();
    bool ok = (err == ESP_OK);
    ESP_LOGW(TAG, "prepare-for-power-off: unmount %s",
             ok ? "ok" : esp_err_to_name(err));
    if (!ok)
        sdcard_allow_auto_remount();  /* power-off didn't happen -- normal operation resumes */

    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    /* ESP_ERR_TIMEOUT = a worker-side download still streams from the card
     * (sdcard_read_begin) -- unmounting would free FATFS under its open FILE. */
    httpd_resp_sendstr(req, ok ? T(S_POWEROFF_OK)
                       : err == ESP_ERR_TIMEOUT ? T(S_POWEROFF_DOWNLOAD)
                                                : T(S_POWEROFF_FAIL));
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

static esp_err_t send_png(httpd_req_t *req, const uint8_t *start, const uint8_t *end)
{
    return send_asset(req, start, end, "image/png", "max-age=86400");
}

/* Vendored Leaflet -- see the extern decls above. 1-year "immutable" cache is
 * safe: the file only changes when the whole device gets reflashed with a
 * new firmware, which is a brand new binary regardless of any URL. */
static esp_err_t leaflet_js_get_handler(httpd_req_t *req)
{
    return send_asset(req, leaflet_js_start, leaflet_js_end,
                       "application/javascript", "max-age=31536000, immutable");
}

/* Shared page stylesheet. Immutable is safe because the page links it with
 * ?v=<ELF hash>: every new build is a new URL, so no stale sheet survives. */
static esp_err_t s_css_get_handler(httpd_req_t *req)
{
    return send_asset(req, s_css_start, s_css_end,
                       "text/css", "max-age=31536000, immutable");
}

static esp_err_t leaflet_css_get_handler(httpd_req_t *req)
{
    return send_asset(req, leaflet_css_start, leaflet_css_end,
                       "text/css", "max-age=31536000, immutable");
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
/*  /system  -- chip, memory, per-task CPU load                       */
/* ================================================================== */

static const char *reset_reason_str(esp_reset_reason_t r)
{
    bool de = (current_lang == LANG_DE);
    switch (r)
    {
    case ESP_RST_POWERON:   return de ? "Kaltstart (Strom angelegt)" : "Power-on (cold boot)";
    case ESP_RST_EXT:       return de ? "Externer Reset (Pin/Taste)" : "External reset (pin/button)";
    case ESP_RST_SW:        return de ? "Software (Neustart/Update)"  : "Software (restart/update)";
    case ESP_RST_PANIC:     return de ? "Absturz (Exception)"        : "Panic / exception";
    case ESP_RST_INT_WDT:   return de ? "Interrupt-Watchdog"         : "Interrupt watchdog";
    case ESP_RST_TASK_WDT:  return de ? "Task-Watchdog"              : "Task watchdog";
    case ESP_RST_WDT:       return de ? "Watchdog"                   : "Other watchdog";
    case ESP_RST_DEEPSLEEP: return de ? "Deep-Sleep-Aufwachen"       : "Deep-sleep wake";
    case ESP_RST_BROWNOUT:  return de ? "Unterspannung (Brownout)"   : "Brownout (undervoltage)";
    case ESP_RST_SDIO:      return "SDIO";
    case ESP_RST_USB:       return de ? "USB-Reset"                  : "USB reset";
    case ESP_RST_JTAG:      return de ? "JTAG-Reset"                 : "JTAG reset";
    case ESP_RST_EFUSE:     return de ? "eFuse-Fehler"               : "eFuse error";
    case ESP_RST_PWR_GLITCH:return de ? "Spannungs-Glitch"          : "Power glitch";
    case ESP_RST_CPU_LOCKUP:return de ? "CPU-Lockup (Doppelfehler)"  : "CPU lockup (double fault)";
    default:                return de ? "Unbekannt"                  : "Unknown";
    }
}

/* Open like the other /system POSTs -- the page itself is unauthenticated,
 * and this only discards diagnostic data, not user data. */
static esp_err_t coredump_clear_post_handler(httpd_req_t *req)
{
    esp_err_t e = esp_core_dump_image_erase();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, e == ESP_OK ? "OK" : "Error");
    return e == ESP_OK ? ESP_OK : ESP_FAIL;
}

/* Zeroes the /system stability counters. Same open model as the other
 * /system POST actions -- no user data, just diagnostic counters. */
static esp_err_t stats_clear_post_handler(httpd_req_t *req)
{
    sysstat_reset();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static const char *task_state_str(eTaskState s)
{
    switch (s)
    {
    case eRunning:   return "run";
    case eReady:     return "ready";
    case eBlocked:   return "blocked";
    case eSuspended: return "susp";
    case eDeleted:   return "deleted";
    default:         return "?";
    }
}

/* Per-task CPU rows shared by /system and /system.json; two snapshots ~300 ms
 * apart give current load, wrap-safe. html_escape keeps it JSON-safe too. */
static void build_task_rows_html(char *out, size_t out_size, int *idle_x10_out)
{
    out[0] = '\0';
    size_t o = 0;
    /* Idle share in tenths of a percent, -1 until measured: a failed
     * snapshot must not read as "no idle left" and show 100 % load. */
    if (idle_x10_out) *idle_x10_out = -1;

    UBaseType_t n1 = uxTaskGetNumberOfTasks();
    if (n1 > 64) n1 = 64;
    TaskStatus_t *a1 = malloc(n1 * sizeof(TaskStatus_t));
    TaskStatus_t *a2 = malloc(n1 * sizeof(TaskStatus_t));
    if (a1 && a2)
    {
        uint32_t rt1 = 0, rt2 = 0;
        UBaseType_t c1 = uxTaskGetSystemState(a1, n1, &rt1);
        vTaskDelay(pdMS_TO_TICKS(300));
        UBaseType_t c2 = uxTaskGetSystemState(a2, n1, &rt2);
        uint32_t total_delta = rt2 - rt1;
        if (idle_x10_out) *idle_x10_out = 0;

        for (UBaseType_t i = 0; i < c2 && o < out_size; i++)
        {
            uint32_t prev = 0;
            for (UBaseType_t j = 0; j < c1; j++)
                if (a1[j].xHandle == a2[i].xHandle) { prev = a1[j].ulRunTimeCounter; break; }
            uint32_t delta = a2[i].ulRunTimeCounter - prev;
            unsigned cpu_x10 = total_delta ? (unsigned)(((uint64_t)delta * 1000) / total_delta) : 0;

            /* Every IDLE* task counts: a multi-core part has one per core. */
            if (idle_x10_out && strncmp(a2[i].pcTaskName, "IDLE", 4) == 0)
                *idle_x10_out += (int)cpu_x10;

            char nameesc[48];
            html_escape(a2[i].pcTaskName, nameesc, sizeof(nameesc));
            /* Single quotes only: this fragment is embedded unescaped in
             * /system.json, where a double quote would break the response. */
            /* Bytes on this port, not words -- measured against the running tasks. */
            const char *scls = a2[i].usStackHighWaterMark < 512  ? "v-bad"
                             : a2[i].usStackHighWaterMark < 1024 ? "v-warn" : "";
            o += snprintf(out + o, out_size - o,
                "<tr><td>%s</td><td>%s</td><td>%u</td><td>%u.%u</td><td class='%s'>%u</td></tr>",
                nameesc, task_state_str(a2[i].eCurrentState),
                (unsigned)a2[i].uxCurrentPriority,
                cpu_x10 / 10, cpu_x10 % 10, scls,
                (unsigned)a2[i].usStackHighWaterMark);
        }
    }
    else
        ESP_LOGE(TAG, "task snapshot alloc failed, table stays empty");
    free(a1);
    free(a2);
}

/* Load = what the idle tasks did not take. Rendered here (not in the
 * caller) so page and JSON cannot disagree about the wording. */
static void format_cpu_load(int idle_x10, int cores, char *out, size_t out_size)
{
    if (idle_x10 < 0 || cores < 1)
    {
        snprintf(out, out_size, "&ndash;");
        return;
    }
    int busy = 1000 * cores - idle_x10;
    if (busy < 0) busy = 0;
    busy /= cores;
    /* Single quotes: cpu_str is also embedded in /system.json. */
    snprintf(out, out_size, "%d%s%d<span class='e'>%%</span>", busy / 10,
             current_lang == LANG_DE ? "," : ".", busy % 10);
}

static esp_err_t system_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* With the language: the JSON handler resolves it per request, so without
     * it an English page flips to German formatting on the first poll. */
    send_page_header_refresh(req, T(S_TITLE_SYSTEM),
                             current_lang == LANG_EN ? "/system.json?lang=en"
                                                     : "/system.json?lang=de");

    /* image_check validates the SHA256, so this can't false-positive on
     * stale flash content. Reuses the generic partition download below
     * (/fs/part?label=coredump) rather than a new route. */
    if (esp_core_dump_image_check() == ESP_OK)
    {
        esp_core_dump_summary_t *sum = malloc(sizeof(esp_core_dump_summary_t));
        char detail[96] = "";
        if (sum && esp_core_dump_get_summary(sum) == ESP_OK)
            snprintf(detail, sizeof(detail), "<br><small>Task %s &middot; PC 0x%08lx</small>",
                     sum->exc_task, (unsigned long)sum->exc_pc);
        free(sum);

        char banner[640];
        snprintf(banner, sizeof(banner),
            "<div class='warn'><p>%s%s</p>"
            "<a href='/fs/part?label=coredump'>&#8595; %s</a> "
            "<button class='dngr' onclick=\"if(confirm('%s'))fetch('/system/coredump/clear',{method:'POST'}).then(()=>location.reload());\">%s</button>"
            "</div>",
            T(S_SYS_COREDUMP), detail, T(S_SYS_COREDUMP_DOWNLOAD),
            T(S_SYS_COREDUMP_CLEAR_CONFIRM), T(S_SYS_COREDUMP_CLEAR));
        httpd_resp_send_chunk(req, banner, HTTPD_RESP_USE_STRLEN);
    }

    /* Below the crash banner on purpose: a crash report must stay the first
     * thing on the page. Eighteen task rows and twelve loss rows sit far down. */
    char sysjump[320];
    HTML_PRINTF(sysjump,
        "<p class='jump'>%s: <a href='#s-dev'>%s</a> &middot; <a href='#s-stab'>%s</a>"
        " &middot; <a href='#s-load'>%s</a> &middot; <a href='#s-loss'>%s</a></p>",
        T(S_TRF_JUMP), T(S_SYS_GRP_DEVICE), T(S_SYS_GRP_STABILITY),
        T(S_SYS_GRP_LOAD), T(S_LOSS_TITLE));
    httpd_resp_send_chunk(req, sysjump, HTTPD_RESP_USE_STRLEN);

    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const esp_app_desc_t *app = esp_app_get_description();

    char feat[64] = "";
    if (chip.features & CHIP_FEATURE_WIFI_BGN) strlcat(feat, "WiFi ", sizeof(feat));
    if (chip.features & CHIP_FEATURE_BT)       strlcat(feat, "BT ", sizeof(feat));
    if (chip.features & CHIP_FEATURE_BLE)      strlcat(feat, "BLE ", sizeof(feat));
    if (chip.features & CHIP_FEATURE_EMB_PSRAM) strlcat(feat, "PSRAM ", sizeof(feat));

    uint32_t flash_sz = 0;
    esp_flash_get_size(NULL, &flash_sz);
    char flash_str[24];
    format_bytes(flash_sz, flash_str, sizeof(flash_str));

    char uptime_str[48];
    format_uptime(esp_timer_get_time() / 1000000ull, uptime_str, sizeof(uptime_str));

    /* Live IP + link speed. Same source (ethernet_get_status) already used
     * for /settings' read-only "currently in effect" line, just formatted
     * as its own row here instead of a full sentence. */
    ethernet_status_t eth_now;
    ethernet_get_status(&eth_now);
    char eth_line[128];
    if (eth_now.up)
    {
        eth_speed_t spd = ethernet_get_mgmt_if_link_speed();
        snprintf(eth_line, sizeof(eth_line), "%s &middot; %s",
                 eth_now.ip, spd == ETH_SPEED_100M ? "100 MBit/s" : "10 MBit/s");
    }
    else
    {
        snprintf(eth_line, sizeof(eth_line), "%s", T(S_ETH_CUR_NOT_UP));
    }

    char ri_f[24], ri_m[24], ri_t[24], rp_f[24], rp_m[24], rp_t[24];
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_INTERNAL), ri_f, sizeof(ri_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL), ri_m, sizeof(ri_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_INTERNAL), ri_t, sizeof(ri_t));
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_SPIRAM), rp_f, sizeof(rp_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM), rp_m, sizeof(rp_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_SPIRAM), rp_t, sizeof(rp_t));

    /* Everything that only changes with a reboot. The separate ESP-IDF row
     * is gone: app->idf_ver in the firmware row is the same string. */
    char devblk[1024];
    HTML_PRINTF(devblk,
        "<div class='grp top' id='s-dev'><h2>%s</h2><table class='kv'>"
        "<tr><th>%s</th><td>%s rev %d, %s</td></tr>"
        "<tr><th>%s</th><td>%d</td></tr>"
        "<tr><th>%s</th><td>%d MHz</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s <small>(IDF %s &middot; %s %s)</small></td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "</table></div>",
        T(S_SYS_GRP_DEVICE),
        T(S_SYS_CHIP), CONFIG_IDF_TARGET, chip.revision, feat,
        T(S_SYS_CORES), chip.cores,
        T(S_SYS_CPU_FREQ), CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        T(S_SYS_FLASH), flash_str,
        T(S_FW_VERSION), app->version, app->idf_ver, app->date, app->time,
        T(S_SYS_RESET), reset_reason_str(esp_reset_reason()),
        T(S_ETH_IP), eth_line);
    httpd_resp_send_chunk(req, devblk, HTTPD_RESP_USE_STRLEN);

    /* Stability counters (NVS-persisted, survive crash + power loss). */
    char maxup_str[48];
    format_uptime(sysstat_max_uptime_sec(), maxup_str, sizeof(maxup_str));
    char lastcrash_str[64];
    bool crash_recent = false;
    int64_t lc = sysstat_last_crash_time();
    if (lc > 0)
    {
        struct timeval now;
        gettimeofday(&now, NULL);
        int64_t ago = now.tv_sec - lc;
        char ago_str[48];
        format_uptime(ago > 0 ? (uint64_t)ago : 0, ago_str, sizeof(ago_str));
        /* A lifetime counter whose newest entry is weeks old is history, and
         * the hint under this card says so -- do not colour it as a warning. */
        crash_recent = ago > 0 && ago < 7 * 24 * 3600;
        snprintf(lastcrash_str, sizeof(lastcrash_str), "%s %s",
                 current_lang == LANG_DE ? "vor" : "", ago_str);
    }
    else
    {
        snprintf(lastcrash_str, sizeof(lastcrash_str), "%s", T(S_STAT_NEVER));
    }

    /* Total and date sit in the card's own sub-line: a bare crash count above
     * the number it refers to read as if something were missing. */
    uint32_t crashes = sysstat_crash_count();
    char stabblk[1152];
    HTML_PRINTF(stabblk,
        "<div class='grp' id='s-stab'><h2>%s</h2><div class='grid'>"
        "<div class='cell'><div class='l %s'>%s</div><div class='v'>%lu</div>"
        "<div class='d'>%s: %lu &middot; %s: %s</div></div>"
        "<div class='cell'><div class='l'>%s</div><div class='v'>%s</div></div>"
        "<div class='cell'><div class='l'>%s</div><div class='v' id='sys-uptime'>%s</div></div>"
        "</div><p class='note'>%s</p>",
        T(S_SYS_GRP_STABILITY),
        crash_recent ? "v-warn" : "", T(S_STAT_CRASHES), (unsigned long)crashes,
        T(S_STAT_BOOTS), (unsigned long)sysstat_boot_count(),
        T(S_STAT_LASTCRASH), lastcrash_str,
        T(S_STAT_MAXUP), maxup_str,
        T(S_UPTIME), uptime_str,
        T(S_SYS_CRASH_HINT));
    httpd_resp_send_chunk(req, stabblk, HTTPD_RESP_USE_STRLEN);

    char statsbtn[384];
    snprintf(statsbtn, sizeof(statsbtn),
        "<p class='btnrow'><button class='dngr' onclick=\"if(confirm('%s'))fetch('/system/stats/clear',{method:'POST'}).then(()=>location.reload());\">%s</button></p>",
        T(S_STAT_RESET_CONFIRM), T(S_STAT_RESET));
    httpd_resp_send_chunk(req, statsbtn, HTTPD_RESP_USE_STRLEN);
    /* Closes the stability section opened above. */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);

    /* Load group: the task table is built first because its idle share is
     * the CPU figure shown above it. */
    static EXT_RAM_BSS_ATTR char task_rows[16384];
    int idle_x10 = -1;
    build_task_rows_html(task_rows, sizeof(task_rows), &idle_x10);
    char cpu_str[48];
    format_cpu_load(idle_x10, chip.cores, cpu_str, sizeof(cpu_str));

    char loadblk[1024];
    HTML_PRINTF(loadblk,
        "<div class='grp' id='s-load'><h2>%s</h2><div class='grid'>"
        "<div class='cell'><div class='l'>%s</div><div class='v' id='sys-cpu'>%s</div></div>"
        "</div><table class='kv'>"
        "<tr><th>%s (%s)</th><td class='%s' id='sys-ram-i'>%s / %s / %s</td></tr>"
        "<tr><th>%s (%s)</th><td id='sys-ram-p'>%s / %s / %s</td></tr>"
        "</table>",
        T(S_SYS_GRP_LOAD),
        T(S_SYS_LOAD), cpu_str,
        T(S_SYS_RAM_INT), T(S_SYS_TRIPLE), ram_int_class(), ri_f, ri_m, ri_t,
        T(S_SYS_RAM_PSRAM), T(S_SYS_TRIPLE), rp_f, rp_m, rp_t);
    httpd_resp_send_chunk(req, loadblk, HTTPD_RESP_USE_STRLEN);

    char taskhdr[64];
    snprintf(taskhdr, sizeof(taskhdr), "<h3>%s</h3>", T(S_SYS_TASKS));
    httpd_resp_send_chunk(req, taskhdr, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req,
        "<div class='scroll'><table><thead><tr><th>Task</th><th>", HTTPD_RESP_USE_STRLEN);
    char hdr[192];
    snprintf(hdr, sizeof(hdr), "%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody id='sys-tasks'>",
             T(S_SYS_COL_STATE), T(S_SYS_COL_PRIO), T(S_SYS_COL_CPU), T(S_SYS_COL_STACK));
    httpd_resp_send_chunk(req, hdr, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, task_rows, HTTPD_RESP_USE_STRLEN);
    /* Last </div> closes the load section opened above. */
    httpd_resp_send_chunk(req, "</tbody></table></div></div>", HTTPD_RESP_USE_STRLEN);

    /* Recorder health: every one of these was already counted internally
     * and shown nowhere, so a degraded device looked perfectly fine. */
    {
        /* Write failures are deliberately NOT added: those batches stay queued
         * and are retried, so counting them here would report a loss that did
         * not happen. Only points that really left are shown. */
        uint32_t trk_evicted = 0, trk_dropped = 0;
#if CONFIG_ENABLE_SD
        tracklog_losses(&trk_evicted, &trk_dropped, NULL);
#endif
        /* Rendered as seconds with three decimals and a unit, because every
         * other row in this table is a frame count and would be misread. */
        uint64_t paused_ms = (uint64_t)sniffer_paused_ms();
        char paused_str[32];
        snprintf(paused_str, sizeof(paused_str), "%llu%s%03llu s",
                 (unsigned long long)(paused_ms / 1000),
                 current_lang == LANG_DE ? "," : ".",
                 (unsigned long long)(paused_ms % 1000));
        /* 2048: 1396 measured in German, plus the jump anchor and the collapsed
         * wrapper. HTML_PRINTF only logs a truncation, so headroom is cheap. */
        char loss[2048];
        HTML_PRINTF(loss,
            "<div class='grp' id='s-loss'><h2>%s</h2><div class='scroll'><table class='kv'>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%s</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
#if CONFIG_ENABLE_SD
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu ms</td></tr>"
#endif
            "</table></div><details class='dtl'><summary>%s</summary>"
            "<p class='note'>%s</p></details></div>",
            T(S_LOSS_TITLE),
            T(S_LOSS_SNIFFER), (unsigned long)sniffer_dropped(),
            T(S_LOSS_MQTT), (unsigned long)mqtt_tx_dropped(),
            T(S_LOSS_BT_PAUSED), paused_str,
            T(S_LOSS_BT_NOTIFY), (unsigned long)bt_stream_dropped_notify(),
            T(S_LOSS_BT_QUEUE), (unsigned long)bt_stream_dropped_enqueue(),
#if CONFIG_ENABLE_SD
            T(S_LOSS_PCAP), (unsigned long)sdpcap_dropped(),
            T(S_LOSS_THINNED), (unsigned long)sdpcap_filtered(),
            T(S_LOSS_TRACKS), (unsigned long)(trk_evicted + trk_dropped),
            T(S_LOSS_PASSAGES), (unsigned long)ptlog_passages_dropped(),
            T(S_LOSS_EVENTS), (unsigned long)events_evicted(),
            T(S_LOSS_SD_FAILS), (unsigned long)sdcard_io_fail_max(),
            T(S_LOSS_SD_HELD), (unsigned long)sdcard_io_held_max_ms(),
#endif
            T(S_LOSS_SUM), T(S_LOSS_HINT));
        httpd_resp_send_chunk(req, loss, HTTPD_RESP_USE_STRLEN);
    }

    /* Applies a /system.json response -- uptime/RAM as plain text, the task
     * table as a pre-rendered HTML fragment (same rows build_task_rows_html
     * already produces for the initial page, just re-sent via innerHTML so
     * the row set can grow/shrink too, not just the numbers in place). */
    /* Every lookup guarded: one missing id used to throw on the first poll
     * and kill every later line of this function, the task table included. */
    httpd_resp_send_chunk(req,
        "<script>window.arApply=function(d){"
        "var e;"
        "var ck=document.getElementById('st-clk');"
        "if(ck&&d.clk!==undefined)ck.textContent=d.clk;"
        "if((e=document.getElementById('sys-uptime')))e.textContent=d.uptime;"
        "if((e=document.getElementById('sys-cpu'))&&d.cpu!==undefined)e.innerHTML=d.cpu;"
        "if((e=document.getElementById('sys-ram-i'))){e.textContent=d.ram_i;"
        "if(d.ram_icl!==undefined)e.className=d.ram_icl;}"
        "if((e=document.getElementById('sys-ram-p')))e.textContent=d.ram_p;"
        "if((e=document.getElementById('sys-tasks')))e.innerHTML=d.tasks_html;"
        "};</script>", HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* GET /system.json -- the dynamic subset of /system, polled by the script
 * send_page_header_refresh() injects. Chip info, reset reason and the
 * coredump banner never change without a reboot (which reloads the page
 * anyway), so only uptime/RAM/tasks are here. */
static esp_err_t system_json_get_handler(httpd_req_t *req)
{
    resolve_language(req);

    char uptime_str[48];
    format_uptime(esp_timer_get_time() / 1000000ull, uptime_str, sizeof(uptime_str));

    char ri_f[24], ri_m[24], ri_t[24], rp_f[24], rp_m[24], rp_t[24];
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_INTERNAL), ri_f, sizeof(ri_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL), ri_m, sizeof(ri_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_INTERNAL), ri_t, sizeof(ri_t));
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_SPIRAM), rp_f, sizeof(rp_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM), rp_m, sizeof(rp_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_SPIRAM), rp_t, sizeof(rp_t));

    static EXT_RAM_BSS_ATTR char task_rows[16384];
    int idle_x10 = -1;
    build_task_rows_html(task_rows, sizeof(task_rows), &idle_x10);
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    char cpu_str[48];
    format_cpu_load(idle_x10, chip.cores, cpu_str, sizeof(cpu_str));

    char clkj[80];
    format_clockline(clkj, sizeof(clkj), "\u00b7");

    static EXT_RAM_BSS_ATTR char json[17408];
    snprintf(json, sizeof(json),
        "{\"uptime\":\"%s\",\"cpu\":\"%s\",\"ram_i\":\"%s / %s / %s\",\"ram_icl\":\"%s\","
        /* Literal UTF-8: it is written with textContent, which shows an
         * entity verbatim. */
        "\"ram_p\":\"%s / %s / %s\",\"clk\":\"%s\",\"tasks_html\":\"%s\"}",
        uptime_str, cpu_str, ri_f, ri_m, ri_t, ram_int_class(),
        rp_f, rp_m, rp_t, clkj, task_rows);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

/* ================================================================== */
/*  GET/POST /update                                                  */
/* ================================================================== */

/* Unlike the playback bar, this one shows a real percentage: XMLHttpRequest
 * reports upload progress, so there is an honest number to display. The
 * button is disabled while it runs -- a second upload mid-flash would be
 * genuinely harmful, not merely wasteful. */
static const char UPDATE_FORM_FMT[] =
    "<div class='grp top'><p class='note'>%s</p>"
    "<input type='file' id='fw'><button id='upbtn' onclick='upload()'>%s</button>"
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
     * page; the first poll is delayed so the not-yet-rebooted device can't "succeed". */
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
     * the current language explicitly here -- otherwise resolve_language()
     * on that request defaults to German regardless of what's displayed
     * (this was the "OTA error always shows German" bug). */
    const char *lc = current_lang == LANG_DE ? "de" : "en";

    /* Measured 2518 in German; 2560 left only 42 bytes of slack, and a
     * truncated <script> here would silently disable the whole upload. */
    char form[3072];
    HTML_PRINTF(form, UPDATE_FORM_FMT,
             T(S_UPD_INTRO), T(S_UPLOAD), T(S_UPD_CHOOSE_FILE), lc,
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

/* Replaces '"' with '_' so a filename can't break out of a quoted
 * Content-Disposition value -- defense-in-depth for files that reached the
 * card some other way than our own upload check. */
static void sanitize_disp_filename(const char *name, char *out, size_t out_size)
{
    size_t o = 0;
    for (; *name && o + 1 < out_size; name++)
        out[o++] = (*name == '"') ? '_' : *name;
    out[o] = '\0';
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

/* Overview of the flash partition layout (what's stored where), at the top of
 * the file-management page. */
static void send_fs_overview(httpd_req_t *req)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    static EXT_RAM_BSS_ATTR char hdr[768];
    /* thead/tbody, not the implicit one: only a real thead gets the group's
     * underline from .grp thead th. */
    snprintf(hdr, sizeof(hdr),
        "<div class='grp top'><h2>%s</h2><p class='note'>%s</p>"
        "<div class='scroll'><table><thead><tr><th>%s</th><th>Typ</th><th>%s</th><th></th></tr></thead><tbody>",
        T(S_FS_PARTITIONS), T(S_FS_NOTE), T(S_SD_NAME), T(S_SD_SIZE));
    httpd_resp_send_chunk(req, hdr, HTTPD_RESP_USE_STRLEN);

    esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, NULL);
    while (it != NULL)
    {
        const esp_partition_t *p = esp_partition_get(it);
        char sz[24];
        format_bytes(p->size, sz, sizeof(sz));
        char info[128] = "";
        char namecell[96];
        snprintf(namecell, sizeof(namecell), "%s", p->label);
        if (running && p->address == running->address)
        {
            snprintf(info, sizeof(info), "<span class='ok'>aktiv</span>");
        }
        else if (p->type == ESP_PARTITION_TYPE_DATA && p->subtype == ESP_PARTITION_SUBTYPE_DATA_FAT)
        {
            uint64_t tot = 0, freeb = 0;
            if (esp_vfs_fat_info("/data", &tot, &freeb) == ESP_OK)
            {
                /* The internal FAT filesystem is browsable → link the label to
                 * the read-only /fs browser, just like the SD card below. */
                const char *lq = current_lang == LANG_EN ? "en" : "de";
                char u[24], t[24];
                format_bytes((uint32_t)(tot - freeb), u, sizeof(u));
                format_bytes((uint32_t)tot, t, sizeof(t));
                snprintf(namecell, sizeof(namecell), "<a href='/fs?lang=%s'>%s</a>", lq, p->label);
                snprintf(info, sizeof(info), "%s /data (%s / %s)", T(S_FS_MOUNT_AT), u, t);
            }
        }
        /* Action cell: any status/mount info, plus a raw-image download of the
         * partition bytes (esp_partition_read). */
        char dl[96];
        snprintf(dl, sizeof(dl), "<a href='/fs/part?label=%s'>&#8595; .img</a>", p->label);
        char act[256];
        if (info[0]) snprintf(act, sizeof(act), "%s &middot; %s", info, dl);
        else         snprintf(act, sizeof(act), "%s", dl);
        char row[512];
        snprintf(row, sizeof(row),
            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>",
            namecell, p->type == ESP_PARTITION_TYPE_APP ? "app" : "data", sz, act);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        it = esp_partition_next(it);
    }
    httpd_resp_send_chunk(req, "</tbody></table></div></div>", HTTPD_RESP_USE_STRLEN);
}

/* Path as clickable steps, one chunk per step: a single buffer for the whole
 * line grows with the square of the path depth. lq == NULL: links carry no lang=. */
static void send_path_crumbs(httpd_req_t *req, const char *base,
                             const char *lq, const char *rel)
{
    static EXT_RAM_BSS_ATTR char crumb[SD_PATH_MAX * 9 + 192];
    static EXT_RAM_BSS_ATTR char segesc[SD_PATH_MAX * 6], prefenc[SD_PATH_MAX * 3];
    char prefix[SD_PATH_MAX];

    HTML_PRINTF(crumb, "<p class='crumbs'><a href='%s%s%s'>/</a>",
                base, lq ? "?lang=" : "", lq ? lq : "");
    httpd_resp_send_chunk(req, crumb, HTTPD_RESP_USE_STRLEN);

    size_t pl = 0;
    const char *seg = rel;
    while (*seg)
    {
        const char *end = strchr(seg, '/');
        size_t sl = end ? (size_t)(end - seg) : strlen(seg);
        if (pl && pl + 1 < sizeof(prefix)) prefix[pl++] = '/';
        for (size_t k = 0; k < sl && pl + 1 < sizeof(prefix); k++) prefix[pl++] = seg[k];
        prefix[pl] = '\0';
        char segbuf[SD_PATH_MAX];
        strlcpy(segbuf, seg, sl + 1 < sizeof(segbuf) ? sl + 1 : sizeof(segbuf));
        html_escape(segbuf, segesc, sizeof(segesc));
        url_encode(prefix, prefenc, sizeof(prefenc));
        /* The last step stays unlinked -- that is where the listing already is. */
        if (end)
            HTML_PRINTF(crumb, "<a href='%s?p=%s%s%s'>%s</a>/", base, prefenc,
                        lq ? "&amp;lang=" : "", lq ? lq : "", segesc);
        else
            HTML_PRINTF(crumb, "%s", segesc);
        httpd_resp_send_chunk(req, crumb, HTTPD_RESP_USE_STRLEN);
        seg = end ? end + 1 : seg + sl;
    }
    httpd_resp_send_chunk(req, "</p>", HTTPD_RESP_USE_STRLEN);
}

/* Sorting in the browser -- readdir hands rows over in creation order. Shared
 * contract: <tbody id='dbody'>, data-c on sortable <th>, data-fix on fixed rows. */
static void send_dir_sort_script(httpd_req_t *req)
{
    httpd_resp_send_chunk(req,
        "<script>(function(){var tb=document.getElementById('dbody');if(!tb)return;var dir={};"
        "function srt(c){dir[c]=!dir[c];var s=dir[c]?1:-1;"
        /* data-fix, not a class: .pin in s.css is an unrelated glyph rule. */
        "var r=[].slice.call(tb.rows).filter(function(x){return !x.hasAttribute('data-fix');});"
        "r.sort(function(a,b){"
        /* Directories stay on top in both directions. */
        "var da=+(a.getAttribute('data-d')||0),db=+(b.getAttribute('data-d')||0);"
        "if(da!==db)return db-da;"
        "if(c===2)return s*((+a.getAttribute('data-sz'))-(+b.getAttribute('data-sz')));"
        /* numeric:true is what puts 20260820-06 before -10. */
        "return s*a.cells[1].textContent.localeCompare(b.cells[1].textContent,"
        "undefined,{numeric:true,sensitivity:'base'});});"
        "r.forEach(function(x){tb.appendChild(x);});}"
        /* The heads turn clickable only here, once the last row has arrived --
         * offering the affordance mid-stream promises what cannot work yet. */
        "document.querySelectorAll('th[data-c]').forEach(function(h){"
        "h.className='srt';h.tabIndex=0;"
        "h.onclick=function(){srt(+h.getAttribute('data-c'));};"
        "h.onkeydown=function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();h.onclick();}};"
        "});})();</script>", HTTPD_RESP_USE_STRLEN);
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

    /* Flash partition layout first, then the SD-card section below it. */
    send_fs_overview(req);
    char sdhdr[96];
    snprintf(sdhdr, sizeof(sdhdr), "<div class='grp'><h2>%s</h2>", T(S_FS_SDCARD));
    httpd_resp_send_chunk(req, sdhdr, HTTPD_RESP_USE_STRLEN);

    if (!sdcard_is_mounted())
    {
        /* The format button must be reachable HERE: an unreadable card never
         * mounts, and since 0.22.7 nothing formats it automatically. */
        char buf[1024];
        snprintf(buf, sizeof(buf),
            /* Closes the SD group opened above: this branch returns early. */
            "<p>%s</p><p class='note'>%s</p>"
            /* A div, not a p: a <form> inside a <p> makes the parser close the
             * paragraph early, and the row would fall apart. */
            "<div class='btnrow tools'>"
            "<form method='post' action='/sdcard/mount' style='display:inline-block'>"
            /* .act: mounting is what this branch is for, so it keeps the amber
             * fill the quiet .btnrow would otherwise take away from it. */
            "<button class='act'>%s</button></form>"
            "<button class='dngr' onclick=\"if(confirm('%s')){"
            "var x=new XMLHttpRequest();x.open('POST','/sdcard/format');"
            "x.onload=function(){location.reload();};"
            "this.innerText='%s';x.send();}\">%s</button></div></div>",
            T(S_SD_NOT_MOUNTED), T(S_SD_UNMOUNTED_HINT),
            T(S_SD_MOUNT),
            T(S_SD_FORMAT_CONFIRM), T(S_SD_FORMATTING), T(S_SD_FORMAT));
        httpd_resp_send_chunk(req, buf, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, NULL, 0);
        return ESP_OK;
    }

    /* Usage + upload form + format button */
    uint64_t total = 0, freeb = 0;
    char usage[384] = "";
    /* total != 0 guards the percentage below against a divide by zero. */
    if (sdcard_usage(&total, &freeb) == ESP_OK && total)
    {
        char t[24], u[24], f[24];
        unsigned pct = (unsigned)(((total - freeb) * 100ull) / total);
        format_bytes64(total, t, sizeof(t));
        format_bytes64(total - freeb, u, sizeof(u));
        format_bytes64(freeb, f, sizeof(f));
        char used_of[128];
        snprintf(used_of, sizeof(used_of), T(S_SD_USED_OF), u, t, f);
        /* Same thresholds and the same tile as the SD figure on '/'. %% is a
         * literal percent sign in the value, not a conversion. */
        snprintf(usage, sizeof(usage),
                 "<div class='grid'><div class='cell'><div class='l %s'>%s</div>"
                 "<div class='v'>%u<span class='e'>%%</span></div>"
                 "<div class='d'>%s</div></div></div>",
                 lvl_class(pct, 80, 92), T(S_SD_USAGE), pct, used_of);
    }

    /* These scratch buffers are large; keeping them on the stack overflowed the
     * single httpd task. esp_http_server handles requests sequentially in one
     * task, so 'static' (off-stack, one instance) is safe here. EXT_RAM_BSS_ATTR
     * places them in PSRAM .bss to spare the scarce internal SRAM. */
    static EXT_RAM_BSS_ATTR char relenc[SD_PATH_MAX * 3];
    url_encode(rel, relenc, sizeof(relenc));

    static EXT_RAM_BSS_ATTR char top[4096];
    snprintf(top, sizeof(top),
        "%s"
        /* Colon inside the span: on its own it would become a flex item of
         * .tools and sit a gap away from the word. */
        "<p class='tools'><span class='cap'>%s:</span><input type='file' id='fw'>"
        "<button onclick='up()'>%s</button> "
        "<span id='ur'></span></p>"
        "<p class='btnrow tools'><button class='dngr' onclick='fmt()'>%s</button> <span id='fr'></span></p>"
        "<p class='btnrow tools'><button onclick='seltar()'>&#8595; %s</button> "
        "<button class='dngr' onclick='seldel()'>%s</button></p>"
        "<p class='note'>%s</p>"
        "<script>"
        "var P='%s';var ITS_SD_FAIL='%s';"
        /* All three buttons used to reload no matter what came back, so a 414
         * from a long selection or a 500 looked exactly like success. */
        "function sdreq(u,go){var x=new XMLHttpRequest();x.open('POST',u);"
        "x.onload=function(){if(x.status!==200||x.responseText==='Error')"
        "alert(ITS_SD_FAIL+' ('+x.status+')');location.reload();};"
        "x.onerror=function(){alert(ITS_SD_FAIL);};x.send(go);}"
        /* P and del() paths are ALREADY url-encoded server-side -- encoding again
         * made %2520 out of a space. Only raw DOM values still need encoding. */
        "function up(){var f=document.getElementById('fw').files[0];if(!f){return;}"
        "var x=new XMLHttpRequest();"
        "x.open('POST','/sdcard/upload?p='+P+'&name='+encodeURIComponent(f.name));"
        "x.onload=function(){location.reload();};"
        "document.getElementById('ur').innerText='%s';x.send(f);}"
        "function fmt(){if(!confirm('%s'))return;"
        "document.getElementById('fr').innerText='%s';sdreq('/sdcard/format');}"
        "function del(p){if(!confirm('%s'))return;"
        "sdreq('/sdcard/delete?p='+p);}"
        "function selall(c){document.querySelectorAll('.sel').forEach(function(x){x.checked=c.checked;});}"
        "function seltar(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}location.href='/sdcard/tar?sel='+s.join('|');}"
        "function seldel(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}if(!confirm('%s'))return;"
        "sdreq('/sdcard/delete?sel='+s.join('|'));}"
        "</script>",
        usage,
        T(S_SD_UP_HERE), T(S_SD_UP_BTN),
        T(S_SD_FORMAT),
        T(S_TAR_SELECTED), T(S_SD_DELETE_SELECTED),
        T(S_TAR_HINT),
        relenc, T(S_SD_ACTION_FAILED),
        T(S_UPLOADING),
        T(S_SD_FORMAT_CONFIRM), T(S_SD_FORMATTING),
        T(S_SD_DELETE_CONFIRM),
        T(S_TAR_NONE), T(S_TAR_NONE), T(S_SD_DELETE_SEL_CONFIRM));
    httpd_resp_send_chunk(req, top, HTTPD_RESP_USE_STRLEN);


    /* NULL: the /sdcard listing links carry no lang= either, so the crumbs
     * keep the page consistent instead of half-fixing it. */
    /* Same language as /fs: resolve_language has no cookie and no default
     * beyond German, so a link without lang= silently switches back. */
    const char *lq = current_lang == LANG_EN ? "en" : "de";
    send_path_crumbs(req, "/sdcard", lq, rel);

    /* thead/tbody is not cosmetics: without it the header row sits in the
     * implicit tbody and the client-side sorter would shuffle it in. */
    char tblopen[512];
    HTML_PRINTF(tblopen,
        "<div class='scroll'><table><thead><tr>"
        "<th><input type='checkbox' onclick='selall(this)'></th>"
        "<th data-c='1'>%s</th>"
        "<th data-c='2'>%s</th>"
        "<th></th></tr></thead><tbody id='dbody'>",
        T(S_SD_NAME), T(S_SD_SIZE));
    httpd_resp_send_chunk(req, tblopen, HTTPD_RESP_USE_STRLEN);

    /* Parent-directory link */
    if (rel[0])
    {
        char parent[SD_PATH_MAX];
        strlcpy(parent, rel, sizeof(parent));
        char *slash = strrchr(parent, '/');
        if (slash) *slash = '\0'; else parent[0] = '\0';
        char penc[SD_PATH_MAX * 3];
        url_encode(parent, penc, sizeof(penc));
        /* data-fix keeps this row out of the sort, hence always on top; the
         * 14 bytes it costs go on top of an already thin percent-encoding margin. */
        char row[SD_PATH_MAX * 3 + 192];
        snprintf(row, sizeof(row),
            "<tr data-fix='1'><td></td><td><a href='/sdcard?p=%s&amp;lang=%s'>%s</a></td>"
            "<td></td><td></td></tr>",
            penc, lq, T(S_SD_PARENT));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Directory entries */
    char full[SD_PATH_MAX];
    sd_full_path(rel, full, sizeof(full));
    /* Counted reader: the DIR handle stays open across client-paced chunk
     * sends, and a console/MQTT "unmount sd" must not free FATFS under it. */
    bool rd = sdcard_read_begin();
    DIR *dir = rd ? opendir(full) : NULL;
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

            /* nameesc = display name (escaped); relenc2 = url-encoded path for
             * hrefs; relhtml = escaped raw path for the checkbox value (JS reads
             * it back and url-encodes it for the tar selection). */
            static EXT_RAM_BSS_ATTR char nameesc[256], relenc2[SD_PATH_MAX * 3];
            static EXT_RAM_BSS_ATTR char relhtml[SD_PATH_MAX * 6];
            html_escape(de->d_name, nameesc, sizeof(nameesc));
            url_encode(childrel, relenc2, sizeof(relenc2));
            html_escape(childrel, relhtml, sizeof(relhtml));

            /* data-d/data-sz feed the client-side sorter: the displayed size is
             * already formatted ("1.0 MiB") and cannot be compared numerically. */
            static EXT_RAM_BSS_ATTR char row[SD_PATH_MAX * 14];
            if (is_dir)
            {
                snprintf(row, sizeof(row),
                    "<tr data-d='1' data-sz='0'><td><input type='checkbox' class='sel' value='%s'></td>"
                    "<td><a href='/sdcard?p=%s&amp;lang=%s'>%s/</a></td><td></td><td></td></tr>",
                    relhtml, relenc2, lq, nameesc);
            }
            else
            {
                char sz[32];
                format_bytes64((uint64_t)st.st_size, sz, sizeof(sz));
                snprintf(row, sizeof(row),
                    "<tr data-d='0' data-sz='%llu'><td><input type='checkbox' class='sel' value='%s'></td>"
                    "<td><a href='/sdcard/download?p=%s'>%s</a></td><td>%s</td>"
                    "<td><button class='dngr' onclick=\"del('%s')\">%s</button></td></tr>",
                    (unsigned long long)st.st_size,
                    relhtml, relenc2, nameesc, sz, relenc2, T(S_SD_DELETE));
            }
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        closedir(dir);
    }
    if (rd)
        sdcard_read_end();

    if (entries == 0)
    {
        char row[128];
        snprintf(row, sizeof(row), "<tr data-fix='1'><td colspan='4'>%s</td></tr>", T(S_SD_EMPTY));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
    send_dir_sort_script(req);
    /* Own chunk so the closing tag of the SD group is findable when reading. */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
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
    /* Counted reader: without it, a concurrent unmount/format freed the
     * FATFS under the open FILE (use-after-free in the next fread). */
    if (!sdcard_read_begin())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    FILE *f = fopen(full, "rb");
    if (!f)
    {
        sdcard_read_end();
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
        return ESP_FAIL;
    }
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    char basesafe[SD_PATH_MAX];
    sanitize_disp_filename(base, basesafe, sizeof(basesafe));
    char disp[SD_PATH_MAX + 64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", basesafe);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        if (httpd_resp_send_chunk(req, buf, n) != ESP_OK)
        {
            fclose(f);
            sdcard_read_end();
            return ESP_FAIL;
        }
    }
    fclose(f);
    sdcard_read_end();
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
    /* A single path component only; '"' is also rejected because the name is
     * later spliced into a quoted Content-Disposition value. */
    if (name[0] == '\0' || strchr(name, '/') || strstr(name, "..") ||
        strchr(name, '"') || has_control_char(name))
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

    /* Counted "reader" (= streaming FS user): the FILE stays open across a
     * client-paced recv loop; a console/MQTT unmount must not free FATFS. */
    if (!sdcard_read_begin())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    FILE *f = fopen(full, "wb");
    if (!f)
    {
        sdcard_read_end();
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
        sdcard_read_end();
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "write failed");
        return ESP_FAIL;
    }
    sdcard_read_end();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* Unlink under the SD WRITER lock (FS_LOCK=0: removing a file a writer has
 * open corrupts its handle). Per entry -- around the whole walk it starves. */
static bool sd_rm_locked(const char *path, bool is_dir, bool *lock_busy)
{
    /* Foreign streaming readers hold a FILE open under no lock (sdcard.h); 1 is
     * our own guard. NOT *lock_busy -- a bulk walk must go on, not abandon. */
    if (sdcard_read_active() > 1)
        return false;
    if (!sdcard_io_begin_timeout(2000))
    {
        /* Transient, not a bad entry -- re-attempting costs another 2 s on the
         * httpd task, so the caller abandons the walk rather than retrying. */
        *lock_busy = true;
        return false;
    }
    bool ok = is_dir ? (rmdir(path) == 0) : (remove(path) == 0);
    sdcard_io_end();
    return ok;
}

/* Recursive delete on ONE caller-owned buffer (append, recurse, truncate) --
 * the 16 KB httpd stack can't afford per-level buffers; `depth` bounds corrupt cards. */
static bool sd_rm_tree(char *path, size_t size, int depth, bool *lock_busy)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    if (!S_ISDIR(st.st_mode))
        return sd_rm_locked(path, false, lock_busy);
    if (depth <= 0)
        return false;

    size_t len = strlen(path);
    /* Deleting entries while readdir() walks the same directory can make
     * FATFS skip some, so repeat passes until one makes no more progress. */
    for (;;)
    {
        DIR *d = opendir(path);
        if (!d)
            return false;
        int removed = 0, left = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL)
        {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            int n = snprintf(path + len, size - len, "/%s", e->d_name);
            if (n <= 0 || (size_t)n >= size - len)
                left++;
            else if (sd_rm_tree(path, size, depth - 1, lock_busy))
                removed++;
            else
                left++;
            path[len] = '\0';
            /* Writer lock busy: every further entry would wait its own 2 s. */
            if (*lock_busy)
                break;
        }
        closedir(d);
        if (*lock_busy)
            return false;
        if (left == 0)
            break;
        if (removed == 0)
            return false;
    }
    return sd_rm_locked(path, true, lock_busy);
}

static esp_err_t sdcard_delete_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* Counted reader for the whole (possibly deep) delete walk -- a console/
     * MQTT unmount must not free FATFS under sd_rm_tree's open DIR handles. */
    if (!sdcard_read_begin())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }

    /* Bulk path: ?sel=a|b|c, same encoding as /sdcard/tar's ?sel= (percent-
     * encoded '|' folded back first). Directories are removed recursively
     * (see sd_rm_tree); bad paths are silently skipped, best-effort. */
    /* Static, not stack: 8 KB of scratch would halve the httpd task's stack.
     * Own copies -- tar_download has its own and runs on the worker task. */
    static EXT_RAM_BSS_ATTR char query[4096];
    static EXT_RAM_BSS_ATTR char sel[4096];
    sel[0] = '\0';
    bool have_sel = false;
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
        have_sel = httpd_query_key_value(query, "sel", sel, sizeof(sel)) == ESP_OK;

    httpd_resp_set_type(req, "text/plain; charset=utf-8");

    if (have_sel)
    {
        char *r = sel, *w = sel;
        while (*r)
        {
            if (r[0] == '%' && r[1] == '7' && (r[2] == 'C' || r[2] == 'c'))
            {
                *w++ = '|';
                r += 3;
            }
            else
                *w++ = *r++;
        }
        *w = '\0';

        int failed = 0;
        bool lock_busy = false;
        char *save = NULL;
        for (char *tok = strtok_r(sel, "|", &save); tok; tok = strtok_r(NULL, "|", &save))
        {
            url_decode(tok);
            if (tok[0] == '\0' || strstr(tok, "..") || has_control_char(tok)) { failed++; continue; }
            char full[SD_PATH_MAX];
            sd_full_path(tok, full, sizeof(full));
            if (!sd_rm_tree(full, sizeof(full), 8, &lock_busy)) failed++;
            /* The entry that set this already counted as failed; stop here so a
             * whole selection cannot pile up 2 s waits on the httpd task. */
            if (lock_busy) break;
        }
        sdcard_read_end();
        if (failed)
            httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, failed == 0 ? "OK" : "Error");
        return failed == 0 ? ESP_OK : ESP_FAIL;
    }

    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)) || rel[0] == '\0')
    {
        sdcard_read_end();
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }
    char full[SD_PATH_MAX];
    sd_full_path(rel, full, sizeof(full));
    bool lock_busy = false;
    bool removed = sd_rm_tree(full, sizeof(full), 8, &lock_busy);
    sdcard_read_end();
    if (removed)
    {
        httpd_resp_sendstr(req, "OK");
        return ESP_OK;
    }
    httpd_resp_set_status(req, "500 Internal Server Error");
    httpd_resp_sendstr(req, "Error");
    return ESP_FAIL;
}

/* POST /sdcard/upload_rsu -- re-sends only positively-identified RSU frames.
 * Own task; frames are COLLECTED under the SD lock and sent after releasing it. */

#define RSU_BATCH_BYTES (256 * 1024)
#define RSU_BATCH_MAX   256

typedef struct {
    volatile bool running;
    volatile uint32_t sent;
    uint32_t thinned, stations;
    bool pairs_overflow;
    bool de;                     /* language captured at request time */
    uint32_t from, to, thin;     /* thin 0 = one frame per station+type, total */
    char result[256];            /* final line for the status poll */
} rsu_job_t;
static rsu_job_t rsu_job;

typedef struct {
    uint8_t *buf;
    size_t used, n;
    struct { uint32_t off; uint16_t len; } items[RSU_BATCH_MAX];
    bool full;
    /* Thinning table, persistent across the whole run. */
    struct { uint32_t station; uint8_t msgid; uint32_t last_sec; } seen[64];
    size_t n_seen;
} rsu_batch_t;

/* Runs under the SD writer lock: filter + copy ONLY, no sleeping, no I/O. */
static bool rsu_collect_cb(uint32_t sec, uint32_t usec, const uint8_t *frame,
                           size_t frame_len, const its_decoded_t *d, void *vctx)
{
    (void)usec;
    rsu_batch_t *b = (rsu_batch_t *)vctx;

    if (d->station_type != 15 || d->message_id == 0)
        return true;                    /* not a stationary sender -- skip */

    for (size_t i = 0; i < b->n_seen; i++)
    {
        if (b->seen[i].station != d->station_id || b->seen[i].msgid != d->message_id)
            continue;
        if (rsu_job.thin == 0 || sec - b->seen[i].last_sec < rsu_job.thin)
        {
            rsu_job.thinned++;
            return true;
        }
        b->seen[i].last_sec = sec;
        goto keep;
    }
    if (b->n_seen >= sizeof(b->seen) / sizeof(b->seen[0]))
    {
        /* Table full: skip and SAY so, rather than flooding or lying. */
        rsu_job.pairs_overflow = true;
        rsu_job.thinned++;
        return true;
    }
    {
        bool station_known = false;
        for (size_t i = 0; i < b->n_seen; i++)
            if (b->seen[i].station == d->station_id) { station_known = true; break; }
        if (!station_known)
            rsu_job.stations++;
    }
    b->seen[b->n_seen].station = d->station_id;
    b->seen[b->n_seen].msgid = d->message_id;
    b->seen[b->n_seen].last_sec = sec;
    b->n_seen++;

keep:
    if (b->n >= RSU_BATCH_MAX || b->used + frame_len > RSU_BATCH_BYTES ||
        frame_len > UINT16_MAX)
    {
        b->full = true;                 /* capacity hit -- reported as partial */
        return false;
    }
    memcpy(b->buf + b->used, frame, frame_len);
    b->items[b->n].off = (uint32_t)b->used;
    b->items[b->n].len = (uint16_t)frame_len;
    b->n++;
    b->used += frame_len;
    return true;
}

/* Task context, NO lock held: paced sending with retries and honest errors. */
static bool rsu_drain_batch(rsu_batch_t *b)
{
    for (size_t i = 0; i < b->n; i++)
    {
        bool ok = false;
        for (int attempt = 0; attempt < 3 && !ok; attempt++)
        {
            ok = mqtt_replay_frame(b->buf + b->items[i].off, b->items[i].len);
            if (!ok && !mqtt_connected_state)
                break;                  /* gone -- retrying won't help */
            if (!ok)
                vTaskDelay(pdMS_TO_TICKS(150));
        }
        if (!ok)
        {
            snprintf(rsu_job.result, sizeof(rsu_job.result), "%s",
                     mqtt_connected_state
                         ? (rsu_job.de ? "Fehler: MQTT-Warteschlange dauerhaft voll."
                                       : "Error: MQTT queue stayed full.")
                         : (rsu_job.de ? "Fehler: MQTT-Verbindung verloren."
                                       : "Error: MQTT connection lost."));
            return false;
        }
        rsu_job.sent++;
        vTaskDelay(pdMS_TO_TICKS(40)); /* pace: live feed keeps priority */
    }
    b->n = 0;
    b->used = 0;
    return true;
}

static void rsu_upload_task(void *arg)
{
    (void)arg;
    bool truncated = false, failed = false;
    uint32_t replay_drop0 = mqtt_replay_dropped();

    rsu_batch_t *b = heap_caps_calloc(1, sizeof(*b), MALLOC_CAP_SPIRAM);
    uint8_t *buf = b ? heap_caps_malloc(RSU_BATCH_BYTES, MALLOC_CAP_SPIRAM) : NULL;
    if (!b || !buf)
    {
        snprintf(rsu_job.result, sizeof(rsu_job.result), "%s",
                 rsu_job.de ? "Fehler: kein Speicher." : "Error: out of memory.");
        goto out;
    }
    b->buf = buf;

    /* The newest minutes are still in the PSRAM ring; without this the last
     * window before "now" is re-sent short and reported as complete -- same
     * reason as in the search and the export. A window that ended earlier is
     * complete on the card, and a false alarm here invites a SECOND re-send. */
    if (!pcap_window_on_card(rsu_job.to))
        truncated = true;

    /* Hour by hour: each walk covers exactly one file, the batch is drained
     * BETWEEN walks -- i.e. with the SD lock released. */
    for (uint32_t h = rsu_job.from - rsu_job.from % 3600;
         h <= rsu_job.to && !failed; h += 3600)
    {
        uint32_t f = h > rsu_job.from ? h : rsu_job.from;
        uint32_t t = (h + 3599 < rsu_job.to) ? h + 3599 : rsu_job.to;
        b->full = false;
        bool complete = sdpcap_read_frames(f, t, rsu_collect_cb, b);
        if (!rsu_drain_batch(b))
            failed = true;
        if (!complete || b->full)
            truncated = true;
    }

    if (!failed)
    {
        /* "sent" only means queued; wait for OUR frames to leave the shared
         * queue, then report unpublished ones exactly. */
        for (int w = 0; mqtt_replay_pending() > 0 && w < 5000; w += 100)
            vTaskDelay(pdMS_TO_TICKS(100));
        uint32_t undelivered = (mqtt_replay_dropped() - replay_drop0)
                             + mqtt_replay_pending();
        char und[80] = "";
        if (undelivered)
            snprintf(und, sizeof(und),
                     rsu_job.de ? " %lu davon nicht zugestellt (Verbindung)!"
                                : " %lu of them not delivered (connection)!",
                     (unsigned long)undelivered);

        snprintf(rsu_job.result, sizeof(rsu_job.result),
                 rsu_job.de
                     ? "Fertig: %lu Frames von %lu Station(en) gesendet, %lu ausgedünnt.%s%s%s"
                     : "Done: %lu frames from %lu station(s) sent, %lu thinned.%s%s%s",
                 (unsigned long)rsu_job.sent, (unsigned long)rsu_job.stations,
                 (unsigned long)rsu_job.thinned,
                 truncated ? (rsu_job.de ? " Zeitraum nur teilweise gelesen!"
                                         : " Period only partly read!") : "",
                 rsu_job.pairs_overflow
                     ? (rsu_job.de ? " Mehr als 64 Sender-Typ-Paare, Rest übersprungen."
                                   : " More than 64 station-type pairs, rest skipped.") : "",
                 und);
    }

out:
    free(buf);
    free(b);
    rsu_job.running = false;
    vTaskDelete(NULL);
}

static esp_err_t rsu_upload_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    if (rsu_job.running)
    {
        httpd_resp_sendstr(req, T(S_RSU_UP_BUSY));
        return ESP_OK;
    }
    if (!mqtt_connected_state)
    {
        httpd_resp_sendstr(req, T(S_RSU_UP_NOMQTT));
        return ESP_OK;
    }

    time_t now = time(NULL);
    long from = (long)now - 24 * 3600, to = (long)now, thin = 0;
    char query[96];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char val[16];
        if (httpd_query_key_value(query, "from", val, sizeof(val)) == ESP_OK)
            from = strtol(val, NULL, 10);
        if (httpd_query_key_value(query, "to", val, sizeof(val)) == ESP_OK)
            to = strtol(val, NULL, 10);
        if (httpd_query_key_value(query, "thin", val, sizeof(val)) == ESP_OK)
            thin = strtol(val, NULL, 10);
    }
    if (to > (long)now) to = (long)now;
    if (from < 0)       from = 0;
    if (to <= from)     to = from + 3600;
    if (to - from > 24L * 3600)         /* hard cap: one day per upload */
        from = to - 24L * 3600;
    if (thin < 0) thin = 0;
    if (thin > 0 && thin < 600) thin = 600;  /* finer thinning starves the SD lock */

    memset(&rsu_job, 0, sizeof(rsu_job));
    rsu_job.from = (uint32_t)from;
    rsu_job.to = (uint32_t)to;
    rsu_job.thin = (uint32_t)thin;
    rsu_job.de = current_lang == LANG_DE;
    rsu_job.running = true;
    if (xTaskCreate(rsu_upload_task, "rsuup", 12288, NULL, 2, NULL) != pdPASS)
    {
        rsu_job.running = false;
        httpd_resp_sendstr(req, "Error");
        return ESP_OK;
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* GET /sdcard/upload_rsu/status -- progress for the page's poll. Read-only. */
static esp_err_t rsu_upload_status_handler(httpd_req_t *req)
{
    char out[320];
    if (rsu_job.running)
        snprintf(out, sizeof(out), "{\"run\":1,\"sent\":%lu}",
                 (unsigned long)rsu_job.sent);
    else
        /* result carries only our own fixed texts and numbers -- no quotes,
         * safe to embed unescaped. */
        snprintf(out, sizeof(out), "{\"run\":0,\"msg\":\"%s\"}", rsu_job.result);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req, out);
}

static esp_err_t sdcard_format_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* Formatting means the card is meant to be in use again. */
    sdcard_allow_auto_remount();
    esp_err_t e = sdcard_format();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, e == ESP_OK ? "OK" : "Error");
    return e == ESP_OK ? ESP_OK : ESP_FAIL;
}

static esp_err_t sdcard_mount_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* Mounting by hand takes the device out of the prepared-for-power-off
     * state, so let sysmon look after the card again. */
    sdcard_allow_auto_remount();
    sdcard_mount();
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/sdcard");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  /fs  -- read-only browser for the internal FAT storage (/data)    */
/*  Reached from the "storage" partition row on the file-management    */
/*  page. Deliberately view+download only: /data is system storage,   */
/*  no upload/delete/format like the removable SD card.               */
/* ================================================================== */

#define DATA_MOUNT "/data"

static void data_full_path(const char *rel, char *out, size_t out_size)
{
    if (rel && rel[0])
        snprintf(out, out_size, "%s/%s", DATA_MOUNT, rel);
    else
        snprintf(out, out_size, "%s", DATA_MOUNT);
}

static esp_err_t internal_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)))
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }

    const char *lq = current_lang == LANG_EN ? "en" : "de";
    send_page_header(req, T(S_TITLE_SD));

    /* No path in here any more (send_path_crumbs escapes it per step), so a
     * small stack buffer replaces the 3840-byte PSRAM static. */
    char head[1024];
    HTML_PRINTF(head,
        /* Path in a span: the heading is uppercased, and a mount point is
         * case-sensitive -- "/DATA" names something that does not exist. */
        "<div class='grp top'><h2>%s &middot; <span class='path'>/data</span></h2>"
        "<p class='jump'><a href='/sdcard?lang=%s'>&larr; %s</a></p>"
        "<p class='btnrow tools'><button onclick='seltar()'>&#8595; %s</button></p>"
        "<p class='note'>%s</p>"
        "<script>function selall(c){document.querySelectorAll('.sel').forEach(function(x){x.checked=c.checked;});}"
        "function seltar(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}location.href='/fs/tar?sel='+s.join('|');}</script>",
        T(S_FS_INTERNAL), lq, T(S_TITLE_SD),
        T(S_TAR_SELECTED),
        T(S_TAR_HINT),
        T(S_TAR_NONE));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

    send_path_crumbs(req, "/fs", lq, rel);

    /* thead/tbody is not cosmetics: without it the header row sits in the
     * implicit tbody and the client-side sorter would shuffle it in. */
    char tblopen[512];
    HTML_PRINTF(tblopen,
        "<div class='scroll'><table><thead><tr>"
        "<th><input type='checkbox' onclick='selall(this)'></th>"
        "<th data-c='1'>%s</th>"
        "<th data-c='2'>%s</th></tr></thead><tbody id='dbody'>",
        T(S_SD_NAME), T(S_SD_SIZE));
    httpd_resp_send_chunk(req, tblopen, HTTPD_RESP_USE_STRLEN);

    /* Parent-directory link */
    if (rel[0])
    {
        char parent[SD_PATH_MAX];
        strlcpy(parent, rel, sizeof(parent));
        char *slash = strrchr(parent, '/');
        if (slash) *slash = '\0'; else parent[0] = '\0';
        char penc[SD_PATH_MAX * 3];
        url_encode(parent, penc, sizeof(penc));
        /* data-fix keeps this row out of the sort, hence always on top. */
        char row[SD_PATH_MAX * 3 + 192];
        snprintf(row, sizeof(row),
            "<tr data-fix='1'><td></td><td><a href='/fs?p=%s&amp;lang=%s'>%s</a></td><td></td></tr>",
            penc, lq, T(S_SD_PARENT));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    char full[SD_PATH_MAX];
    data_full_path(rel, full, sizeof(full));
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
            data_full_path(childrel, childfull, sizeof(childfull));
            struct stat st;
            bool is_dir = (stat(childfull, &st) == 0) && S_ISDIR(st.st_mode);

            static EXT_RAM_BSS_ATTR char nameesc[256], relenc2[SD_PATH_MAX * 3];
            static EXT_RAM_BSS_ATTR char relhtml[SD_PATH_MAX * 6];
            html_escape(de->d_name, nameesc, sizeof(nameesc));
            url_encode(childrel, relenc2, sizeof(relenc2));
            html_escape(childrel, relhtml, sizeof(relhtml));

            static EXT_RAM_BSS_ATTR char row[SD_PATH_MAX * 14];
            if (is_dir)
            {
                snprintf(row, sizeof(row),
                    "<tr data-d='1' data-sz='0'><td><input type='checkbox' class='sel' value='%s'></td>"
                    "<td><a href='/fs?p=%s&amp;lang=%s'>%s/</a></td><td></td></tr>",
                    relhtml, relenc2, lq, nameesc);
            }
            else
            {
                char sz[32];
                format_bytes64((uint64_t)st.st_size, sz, sizeof(sz));
                /* data-d/data-sz feed the sorter: the displayed size is already
                 * formatted ("1.0 MiB") and cannot be compared numerically. */
                snprintf(row, sizeof(row),
                    "<tr data-d='0' data-sz='%llu'><td><input type='checkbox' class='sel' value='%s'></td>"
                    "<td><a href='/fs/download?p=%s'>%s</a></td><td>%s</td></tr>",
                    (unsigned long long)st.st_size,
                    relhtml, relenc2, nameesc, sz);
            }
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        closedir(dir);
    }

    if (entries == 0)
    {
        char row[128];
        snprintf(row, sizeof(row), "<tr data-fix='1'><td colspan='3'>%s</td></tr>", T(S_SD_EMPTY));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
    send_dir_sort_script(req);
    /* Own chunk so the closing tag of the page's group is findable. */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t internal_download_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)) || rel[0] == '\0')
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }
    char full[SD_PATH_MAX];
    data_full_path(rel, full, sizeof(full));
    FILE *f = fopen(full, "rb");
    if (!f)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
        return ESP_FAIL;
    }
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    char basesafe[SD_PATH_MAX];
    sanitize_disp_filename(base, basesafe, sizeof(basesafe));
    char disp[SD_PATH_MAX + 64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", basesafe);
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

/* ================================================================== */
/*  Raw partition image download  (/fs/part?label=...)                */
/* ================================================================== */

static esp_err_t partimg_download_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    char query[128], label[24] = "";
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
        httpd_query_key_value(query, "label", label, sizeof(label));
    url_decode(label);
    if (label[0] == '\0')
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no label");
        return ESP_FAIL;
    }
    /* Look the label up in the partition table; only a real partition can ever
     * match, so this can't be used to read arbitrary flash. */
    const esp_partition_t *p =
        esp_partition_find_first(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, label);
    if (!p)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no partition");
        return ESP_FAIL;
    }
    char disp[64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s.img\"", p->label);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    static EXT_RAM_BSS_ATTR uint8_t partbuf[4096];
    for (size_t off = 0; off < p->size; off += sizeof(partbuf))
    {
        size_t n = (p->size - off) < sizeof(partbuf) ? (p->size - off) : sizeof(partbuf);
        if (esp_partition_read(p, off, partbuf, n) != ESP_OK)
            return ESP_FAIL;
        if (httpd_resp_send_chunk(req, (const char *)partbuf, n) != ESP_OK)
            return ESP_FAIL;
    }
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  Streaming tar (ustar) writer -- download a whole folder or a       */
/*  multi-file selection as one .tar. No compression, no external lib. */
/*  Used by both /sdcard/tar and /fs/tar.                              */
/* ================================================================== */

#define TAR_BLOCK     512
#define TAR_MAX_DEPTH 12

static EXT_RAM_BSS_ATTR char tar_hdr[TAR_BLOCK];
static EXT_RAM_BSS_ATTR char tar_full[SD_PATH_MAX * 2];

/* Write `val` as a NUL-terminated, zero-padded octal string into a header
 * field of the given width (tar numeric fields). */
static void tar_num(char *field, size_t width, uint64_t val)
{
    for (int i = (int)width - 2; i >= 0; i--) { field[i] = '0' + (char)(val & 7); val >>= 3; }
    field[width - 1] = '\0';
}

/* Place the archive member name into the 100-byte name field, using the
 * 155-byte prefix field for long paths (ustar). Best-effort for very long
 * paths (keeps the tail). */
static void tar_put_name(char *hdr, const char *arc)
{
    size_t len = strlen(arc);
    if (len <= 100) { memcpy(hdr, arc, len); return; }
    size_t split = 0;
    for (size_t i = 0; i < len; i++)
        if (arc[i] == '/' && i <= 155 && (len - i - 1) <= 100) { split = i; break; }
    if (split > 0)
    {
        memcpy(hdr + 345, arc, split);
        memcpy(hdr, arc + split + 1, len - split - 1);
    }
    else
    {
        memcpy(hdr, arc + (len - 100), 100);
    }
}

/* Emit one regular file (header + data + padding). Opens first so a failed
 * open never leaves a dangling header in the stream. Returns false only on a
 * transport error (abort the whole archive). */
static bool tar_send_file(httpd_req_t *req, const char *full, const char *arc, uint64_t size)
{
    FILE *f = fopen(full, "rb");
    if (!f) return true;   /* skip unreadable entry, archive stays valid */

    memset(tar_hdr, 0, TAR_BLOCK);
    tar_put_name(tar_hdr, arc);
    tar_num(tar_hdr + 100, 8, 0644);   /* mode */
    tar_num(tar_hdr + 108, 8, 0);      /* uid  */
    tar_num(tar_hdr + 116, 8, 0);      /* gid  */
    tar_num(tar_hdr + 124, 12, size);  /* size */
    tar_num(tar_hdr + 136, 12, 0);     /* mtime (unknown) */
    tar_hdr[156] = '0';                /* typeflag: regular file */
    memcpy(tar_hdr + 257, "ustar", 5); /* magic "ustar\0" */
    tar_hdr[263] = '0'; tar_hdr[264] = '0';  /* version "00" */
    memset(tar_hdr + 148, ' ', 8);     /* checksum field = spaces while summing */
    unsigned sum = 0;
    for (int i = 0; i < TAR_BLOCK; i++) sum += (unsigned char)tar_hdr[i];
    char cs[8];
    snprintf(cs, sizeof(cs), "%06o", sum & 0777777);
    memcpy(tar_hdr + 148, cs, 6);
    tar_hdr[154] = '\0';
    tar_hdr[155] = ' ';

    if (httpd_resp_send_chunk(req, tar_hdr, TAR_BLOCK) != ESP_OK) { fclose(f); return false; }

    uint64_t remaining = size;
    char buf[TAR_BLOCK];
    while (remaining > 0)
    {
        size_t want = remaining < TAR_BLOCK ? (size_t)remaining : TAR_BLOCK;
        size_t n = fread(buf, 1, want, f);
        if (n < want) memset(buf + n, 0, want - n);  /* honour declared size */
        if (httpd_resp_send_chunk(req, buf, want) != ESP_OK) { fclose(f); return false; }
        remaining -= want;
    }
    fclose(f);

    size_t pad = (size_t)(size % TAR_BLOCK);
    if (pad)
    {
        pad = TAR_BLOCK - pad;
        memset(buf, 0, pad);
        if (httpd_resp_send_chunk(req, buf, pad) != ESP_OK) return false;
    }
    return true;
}

/* Recurse the directory whose absolute path currently occupies tar_full[0..len).
 * `skip` bytes are stripped to form the archive-relative member name. */
static bool tar_walk(httpd_req_t *req, size_t len, size_t skip, int depth)
{
    DIR *d = opendir(tar_full);
    if (!d) return true;
    struct dirent *de;
    bool ok = true;
    while (ok && (de = readdir(d)) != NULL)
    {
        if (de->d_name[0] == '.') continue;
        int add = snprintf(tar_full + len, sizeof(tar_full) - len, "/%s", de->d_name);
        if (add < 0 || (size_t)add >= sizeof(tar_full) - len) { tar_full[len] = '\0'; continue; }
        struct stat st;
        if (stat(tar_full, &st) == 0)
        {
            if (S_ISDIR(st.st_mode))
            {
                if (depth > 0) ok = tar_walk(req, len + (size_t)add, skip, depth - 1);
            }
            else if (S_ISREG(st.st_mode))
            {
                ok = tar_send_file(req, tar_full, tar_full + skip, (uint64_t)st.st_size);
            }
        }
        tar_full[len] = '\0';
    }
    closedir(d);
    return ok;
}

/* Shared handler body: ?sel=a|b|c (pipe-separated, url-encoded members) OR
 * ?p=<dir> (a single directory, default = mount root). */
static esp_err_t tar_download(httpd_req_t *req, const char *mount)
{
    size_t skip = strlen(mount) + 1;
    httpd_resp_set_type(req, "application/x-tar");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"download.tar\"");

    /* Own statics, see sdcard_delete_handler: this one serves on the worker. */
    static EXT_RAM_BSS_ATTR char query[4096];
    static EXT_RAM_BSS_ATTR char sel[4096];
    sel[0] = '\0';
    char pdir[SD_PATH_MAX] = "";
    bool have_sel = false;
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        if (httpd_query_key_value(query, "sel", sel, sizeof(sel)) == ESP_OK)
            have_sel = true;
        else
            httpd_query_key_value(query, "p", pdir, sizeof(pdir));
    }

    bool ok = true;
    if (have_sel)
    {
        /* Some browsers/proxies percent-encode the '|' separator in query
         * strings (the URL spec says leave it raw, but not everyone does).
         * FAT filenames can never contain '|' (illegal char), so folding
         * %7C/%7c back into '|' before splitting is unambiguous. */
        char *r = sel, *w = sel;
        while (*r)
        {
            if (r[0] == '%' && r[1] == '7' && (r[2] == 'C' || r[2] == 'c'))
            {
                *w++ = '|';
                r += 3;
            }
            else
                *w++ = *r++;
        }
        *w = '\0';

        char *save = NULL;
        for (char *tok = strtok_r(sel, "|", &save); tok && ok; tok = strtok_r(NULL, "|", &save))
        {
            url_decode(tok);
            if (tok[0] == '\0' || strstr(tok, "..") || has_control_char(tok)) continue;
            int fl = snprintf(tar_full, sizeof(tar_full), "%s/%s", mount, tok);
            if (fl < 0 || (size_t)fl >= sizeof(tar_full)) continue;
            struct stat st;
            if (stat(tar_full, &st) != 0) continue;
            if (S_ISDIR(st.st_mode))       ok = tar_walk(req, (size_t)fl, skip, TAR_MAX_DEPTH);
            else if (S_ISREG(st.st_mode))  ok = tar_send_file(req, tar_full, tar_full + skip, (uint64_t)st.st_size);
        }
    }
    else
    {
        url_decode(pdir);
        if (strstr(pdir, "..") || has_control_char(pdir))
        {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
            return ESP_FAIL;
        }
        int fl = pdir[0] ? snprintf(tar_full, sizeof(tar_full), "%s/%s", mount, pdir)
                         : snprintf(tar_full, sizeof(tar_full), "%s", mount);
        if (fl > 0 && (size_t)fl < sizeof(tar_full))
            ok = tar_walk(req, (size_t)fl, skip, TAR_MAX_DEPTH);
    }

    if (ok)  /* two zero blocks terminate the archive */
    {
        memset(tar_hdr, 0, TAR_BLOCK);
        httpd_resp_send_chunk(req, tar_hdr, TAR_BLOCK);
        httpd_resp_send_chunk(req, tar_hdr, TAR_BLOCK);
    }
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t sdcard_tar_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* Counted reader for the whole archive walk -- see sdcard_download_handler. */
    if (!sdcard_read_begin())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    esp_err_t r = tar_download(req, sdcard_mount_point());
    sdcard_read_end();
    return r;
}

static esp_err_t internal_tar_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    return tar_download(req, DATA_MOUNT);
}

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
    /* Rows collect here (PSRAM), sent only AFTER the walk -- a send in the
     * callback ran under the SD writer lock, paced by the client. */
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

    /* Sized for the worst legal input -- too-small buffers made IDF's query
     * parsers fail SILENTLY and the search ran with defaults instead. */
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
                /* Longer than any searched field can be -- a truncated copy
                 * could half-match, so use a needle that never matches. */
                ctx.q[0] = '\x01';
                ctx.q[1] = '\0';
            }
            for (char *p = ctx.q; *p; p++)
                *p = (char)tolower((unsigned char)*p);
        }
        else if (qe == ESP_ERR_HTTPD_RESULT_TRUNC)
        {
            /* Needle blew past val[] (3-byte UTF-8 = 9 encoded bytes each);
             * running UNFILTERED would fake matches -- never-match instead. */
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

    /* Rows go out AFTER the walk -- capped at 200, this is at most ~166 KB
     * and the send no longer runs under the SD writer lock. */
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
/* 7.5 s at days=7, all of it on the one httpd task before this. */
static esp_err_t tracks_get_async(httpd_req_t *req)       { return defer_to_worker(req, tracks_get_handler); }

/* ================================================================== */
/*  /logs  -- view the SD log files inline in the browser             */
/* ================================================================== */

#define LOGS_TAIL_KB 24   /* how much of the file tail to show */

/* Stream the last `tail` bytes of an open file into a <pre>, HTML-escaping
 * '<', '>' and '&'. Skips the first (partial) line when not starting at 0. */
/* True if `s` starts with an ESP-IDF log prefix carrying a millisecond
 * timestamp -- "I (05:12:44.623) ". Only that exact shape, so the frame CSV
 * (different columns entirely) is never touched. */
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

/* Streams the log tail HTML-escaped, line-based so the millisecond trim always
 * sees a whole timestamp; dates come from the log's own daily marker lines. */
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
        /* Only at a real line start, and only for the log's own prefix: drop
         * the ".623" from "(05:12:44.623)". Milliseconds stay in the file on
         * the card -- they are worth having when reading the lines right
         * before a crash, just not on screen. */
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
        httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, NULL, 0);
        return ESP_OK;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    long start = size > (LOGS_TAIL_KB * 1024) ? size - (LOGS_TAIL_KB * 1024) : 0;

    /* Only now that the file is open: on the error path above there is no
     * <pre> and no filter script, so live controls there would be dead. */
    /* disabled until that script defines lgf(): a live-looking dead button is
     * worse than one that visibly is not ready yet (CSS: #lgb0:disabled). */
    char tools[640];
    HTML_PRINTF(tools,
        "<p class='btnrow tools'><button id='lgb0' disabled onclick='lgf(0)'>%s</button> "
        "<button id='lgb1' disabled onclick='lgf(1)'>%s</button> "
        "<input id='lgq' disabled oninput='lgf()' placeholder='%s' size='16'> "
        "<span id='lgcnt' class='cap'>%s</span> <small>%s</small></p>",
        T(S_LOGS_F_ALL), T(S_LOGS_F_PROB), T(S_LOGS_SEARCH),
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
    /* Browsers abort keep-alive connections all the time (page reloads via
     * auto-refresh, navigating away) which logs a harmless
     * "httpd_sock_err: error in recv : 104" (ECONNRESET) warning on every
     * occurrence — pure noise, especially in the SD log. Only real errors. */
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
     * is open -- 8 proved too tight once /map existed (accept() failures as
     * dead WS sessions piled up, see the reaping in ws_broadcast_work). */
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
