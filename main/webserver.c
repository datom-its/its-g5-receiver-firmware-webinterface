#include "sdkconfig.h"

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
#include "cmd_sniffer.h"
#include "ethernet.h"
#include "events.h"
#include "its_decode.h"
#include "ota.h"
#include "sysmon.h"
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
#include "spatem.h"

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

static const char TAG[] = "WEBSERVER";

/* snprintf for page markup that says so when it had to truncate.
 * -Wformat-truncation cannot catch these: the arguments are runtime strings
 * (translated UI text), so the compiler has no length to reason about. Cut
 * markup does not fail quietly -- it drops closing tags, and the browser then
 * swallows the rest of the page. That has cost three debugging sessions now:
 * a chip buffer collapsed the traffic page layout, a table row broke the
 * warning list, and an undersized map header removed the map container
 * itself. One log line at the moment of truncation replaces all of that. */
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
    S_NODEID, S_MAC, S_FW_VERSION, S_HW_VARIANT, S_UPTIME, S_SNIFFER,
    S_CHANNEL, S_MQTT, S_MSGS_RECEIVED, S_RATE, S_FREE_HEAP, S_FREE_PSRAM, S_TEMPERATURE,
    S_RUNNING, S_STOPPED, S_CONNECTED, S_DISCONNECTED,
    S_START, S_STOP, S_REBOOT, S_REBOOT_CONFIRM, S_REBOOTING,
    S_POWEROFF, S_POWEROFF_CONFIRM, S_POWEROFF_BUSY, S_POWEROFF_OK, S_POWEROFF_FAIL,
    S_SNIFFER_LABEL, S_SNIFF_START, S_SNIFF_STOP, S_AUTO_REFRESH,
    S_CONFIRM_NEEDED, S_CONFIRM_BTN, S_CONFIRMED, S_CONFIRM_ERROR,
    S_MSG_INTRO, S_COL_NUM, S_COL_TIME, S_COL_RSSI, S_COL_LENGTH, S_COL_PREVIEW,
    S_SET_INTRO, S_MQTT_URI, S_AUTOSTART_CHAN, S_CHAN_NONE,
    S_SET_GROUP_GENERAL, S_SET_GROUP_NETWORK, S_SET_GROUP_MQTT,
    S_SET_GROUP_STORAGE, S_SET_GROUP_SECURITY, S_SET_GROUP_TRAFFIC,
    S_STATS_RETAIN_DAYS, S_EVENT_RETAIN_DAYS,
    S_MAP_STALE_SEC, S_MAP_STALE_HINT, S_MAP_LINE, S_EVT_TRAFFIC,
    S_BROADCAST_ONLY, S_BROADCAST_ONLY_HINT,
    S_LED_OVERRIDE, S_LED_OVERRIDE_HINT,
    S_LED_BRIGHTNESS, S_SAVE, S_SAVED,
    S_WEB_PASSWORD, S_WEB_PASSWORD_SET, S_WEB_PASSWORD_NONE, S_WEB_PASSWORD_CLEAR,
    S_REFRESH_SEC,
    S_ETH_DHCP, S_ETH_IP, S_ETH_NETMASK, S_ETH_GATEWAY, S_ETH_DNS, S_ETH_NET_NOTE,
    S_ETH_CURRENT, S_ETH_CUR_NOT_UP,
    S_NTP_SERVER, S_COL_TYPE, S_ACTIVITY_TITLE, S_ACTIVITY_NONE, S_TYPE_HINT,
    S_LOG_SYS, S_LOG_FRAMES, S_LOG_BUDGET, S_LOG_HINT,
    S_PCAP_ENABLE, S_PCAP_RETAIN_HOURS, S_PCAP_MAX_MB, S_PCAP_HINT,
    S_PCAP_BUF_MB, S_PCAP_BUF_HINT, S_PCAP_FLUSH_SEC,
    S_PLAYBACK_FROM, S_PLAYBACK_TO, S_PLAYBACK_LOAD, S_PLAYBACK_LIVE, S_PLAYBACK_NONE, S_PLAYBACK_ERROR,
    S_PLAYBACK_BUSY, S_PLAYBACK_STEP, S_MAP_LAYER_DARK, S_MAP_LAYER_LIGHT, S_MAP_LAYER_TRACKS, S_MAP_LAYER_TRACKS_P, S_MAP_TRACK_PTS, S_UPD_WAIT, S_UPD_FLASHING,
    S_PEERS, S_PEERS_HINT, S_MAP_SEEN_BY, S_UNSAVED,
    S_TRACKS_ENABLE, S_TRACKS_DAYS, S_TRACKS_HINT,
    S_ETH_LEDS, S_ETH_LEDS_HINT,
    S_PCAP_FILTER, S_PCAP_FILT_ALL, S_PCAP_FILT_THIN, S_PCAP_FILT_VEH, S_PCAP_FILT_HINT,
    S_UPD_INTRO, S_UPLOAD, S_UPLOADING, S_UPLOAD_OK, S_UPLOAD_FAIL, S_UPD_CHOOSE_FILE,
    S_UPD_NOT_CONFIRMED,
    S_NAV_SD, S_TITLE_SD, S_FS_PARTITIONS, S_FS_SDCARD, S_FS_USED, S_FS_MOUNT_AT,
    S_FS_INTERNAL, S_FS_NOTE, S_TAR_SELECTED, S_TAR_NONE, S_TAR_HINT,
    S_SD_DELETE_SELECTED, S_SD_DELETE_SEL_CONFIRM,
    S_SD_NOT_MOUNTED, S_SD_MOUNT, S_SD_USAGE, S_SD_USED_OF,
    S_SD_NAME, S_SD_SIZE, S_SD_EMPTY, S_SD_PARENT, S_SD_DELETE, S_SD_DELETE_CONFIRM,
    S_SD_FORMAT, S_SD_FORMAT_CONFIRM, S_SD_FORMATTING, S_SD_UP_HERE, S_SD_UP_BTN,
    S_NAV_SYSTEM, S_TITLE_SYSTEM, S_SYS_CHIP, S_SYS_CORES, S_SYS_CPU_FREQ,
    S_SYS_IDF, S_SYS_RESET, S_SYS_FLASH, S_SYS_RAM_INT, S_SYS_RAM_PSRAM,
    S_SYS_TRIPLE, S_SYS_TASKS, S_SYS_COL_STATE, S_SYS_COL_PRIO, S_SYS_COL_CPU,
    S_SYS_COL_STACK,
    S_STAT_BOOTS, S_STAT_CRASHES, S_STAT_LASTCRASH, S_STAT_MAXUP, S_STAT_NEVER,
    S_STAT_RESET, S_STAT_RESET_CONFIRM,
    S_NAV_LOGS, S_TITLE_LOGS, S_LOGS_SYS, S_LOGS_FRAMES, S_LOGS_REFRESH,
    S_LOGS_NONE, S_LOGS_TAIL,
    S_NAV_TRAFFIC, S_TITLE_TRAFFIC, S_TRF_INTRO, S_TRF_WINDOW, S_TRF_W_24H, S_TRF_W_7D,
    S_TRF_W_30D, S_TRF_TOTAL, S_TRF_HOUR, S_TRF_SPEED, S_TRF_NODATA,
    S_CAT_CAR, S_CAT_BUS, S_CAT_TRUCK, S_CAT_TWOWHEEL, S_CAT_PED, S_CAT_RSU, S_CAT_OTHER,
    S_EVT_TITLE, S_EVT_NONE, S_EVT_TIME, S_EVT_SENDER, S_EVT_WARNING, S_EVT_DENM,
    S_TRF_SPEED_BY_TYPE,
    S_TRF_LIGHTS, S_TRF_LIGHTS_NONE, S_TRF_INTERSECTION,
    S_TRF_LIGHTS_INTRO, S_TRF_PH_GREEN, S_TRF_PH_AMBER, S_TRF_PH_RED, S_TRF_PH_OTHER,
    S_DIR_STRAIGHT, S_DIR_LEFT, S_DIR_RIGHT, S_DIR_UTURN, S_DIR_PED,
    S_NAV_MAP, S_TITLE_MAP, S_MAP_HINT, S_MAP_HELP, S_MAP_LAYER_STREETS, S_MAP_LAYER_SATELLITE,
    S_MAP_DENM,
    S_SYS_COREDUMP, S_SYS_COREDUMP_DOWNLOAD, S_SYS_COREDUMP_CLEAR, S_SYS_COREDUMP_CLEAR_CONFIRM,
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
    [S_SNIFFER_LABEL]   = { "Sniffer",                  "sniffer" },
    [S_SNIFF_START]     = { "Sniffer starten",          "Start sniffer" },
    [S_SNIFF_STOP]      = { "Sniffer stoppen",          "Stop sniffer" },
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
    /* Shown via alert(t) after fetch('/confirm').then(r=>r.text()) if
     * ota_confirm() itself fails (very rare -- was hardcoded English before). */
    [S_CONFIRM_ERROR]   = { "Fehler beim Bestätigen.", "Error confirming." },
    [S_MSG_INTRO]       = { "Die letzten %d empfangenen Frames, neueste zuerst, mit dem was sich "
                            "aus jedem dekodieren lie&szlig;.",
                            "Last %d received frames, newest first, with whatever could be decoded "
                            "from each." },
    [S_COL_NUM]         = { "#",                        "#" },
    [S_COL_TIME]        = { "Zeit",                     "Time" },
    [S_COL_RSSI]        = { "RSSI",                     "RSSI" },
    [S_COL_LENGTH]      = { "L&auml;nge",               "Length" },
    [S_COL_PREVIEW]     = { "Details",                  "Details" },
    [S_SET_INTRO]       = { "&Auml;nderungen werden im NVS gespeichert. Die meisten wirken nach einem Neustart.",
                            "Changes are saved to NVS. Most take effect after a reboot." },
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
    [S_UNSAVED]         = { "Nicht gespeicherte &Auml;nderungen",
                            "Unsaved changes" },
    [S_SAVED]           = { "%d Einstellung(en) gespeichert.", "Saved %d setting(s)." },
    [S_WEB_PASSWORD]    = { "Web-Passwort (Benutzer &quot;admin&quot;)",
                            "Web password (user &quot;admin&quot;)" },
    [S_WEB_PASSWORD_SET]  = { "gesetzt &ndash; leer lassen = unver&auml;ndert",
                              "set &ndash; leave empty to keep unchanged" },
    [S_WEB_PASSWORD_NONE] = { "kein Passwort &ndash; sch&uuml;tzt /update und /settings",
                              "no password &ndash; protects /update and /settings" },
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
    [S_ACTIVITY_TITLE]  = { "Aktivit&auml;t (60s)",      "Activity (60s)" },
    [S_ACTIVITY_NONE]   = { "(noch keine Nachrichten)",  "(no messages yet)" },
    [S_TYPE_HINT]       = { "Typ = Absender + Nachricht. Absender: Auto, Bus, Fu&szlig;g&auml;nger, "
                            "RSU (Stra&szlig;enrand-Einheit, z.B. Ampel). Nachricht: CAM=Fahrzeug-Status, "
                            "DENM=Warnung, SPATEM=Ampelphase, MAPEM=Kreuzungskarte, IVIM=Verkehrszeichen, "
                            "CPM=Umfeldwahrnehmung. &bdquo;Signed&ldquo;=signiert, nicht entschl&uuml;sselbar. "
                            "&bdquo;?&ldquo;=kein GeoNetworking-Paket.",
                            "Type = sender + message. Sender: car, bus, pedestrian, RSU (roadside unit, "
                            "e.g. a traffic light). Message: CAM=vehicle status, DENM=hazard warning, "
                            "SPATEM=signal phase/timing, MAPEM=intersection map, IVIM=road signs, "
                            "CPM=perceived objects. \"Signed\"=signed, not unwrapped. "
                            "\"?\"=not a GeoNetworking packet." },
    [S_LOG_SYS]         = { "System-Log auf SD",        "System log to SD" },
    [S_LOG_FRAMES]      = { "Frame-Log auf SD (CSV)",   "Frame log to SD (CSV)" },
    [S_LOG_BUDGET]      = { "Log-Speicher-Budget (MB)", "Log storage budget (MB)" },
    [S_LOG_HINT]        = { "Logs unter /sdcard/logs/, rotierend. Braucht eine eingebundene SD-Karte.",
                            "Logs in /sdcard/logs/, rotating. Requires a mounted SD card." },
    [S_PCAP_ENABLE]       = { "Rollierende PCAP-Aufzeichnung auf SD", "Rolling PCAP capture to SD" },
    [S_PCAP_RETAIN_HOURS] = { "PCAP-Aufbewahrung (Std.)",             "PCAP retention (hours)" },
    [S_PCAP_MAX_MB]       = { "PCAP-Speicher-Obergrenze (MB)",        "PCAP storage ceiling (MB)" },
    [S_PCAP_HINT]         = { "Rohe 802.11-Frames unter /sdcard/pcap/, stündlich rotierend, mit tshark/Wireshark lesbar. Braucht eine eingebundene SD-Karte.",
                              "Raw 802.11 frames in /sdcard/pcap/, rotating hourly, readable with tshark/Wireshark. Requires a mounted SD card." },
    [S_PCAP_BUF_MB]       = { "PCAP-RAM-Puffer (MB)",                "PCAP RAM buffer (MB)" },
    [S_PCAP_BUF_HINT]     = { "Frames werden erst im PSRAM gesammelt und dann in einem Rutsch geschrieben, statt bei jedem Frame einzeln auf die (mit Ethernet geteilte) SD-Bus zuzugreifen. Wirkt erst nach einem Neustart.",
                              "Frames are collected in PSRAM first and written in one batch, instead of touching the SD bus (shared with Ethernet) for every single frame. Takes effect after a reboot." },
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
    [S_PLAYBACK_STEP]   = { "Schritt",                   "Step" },
    [S_MAP_LAYER_DARK]  = { "Dunkel",                    "Dark" },
    [S_MAP_LAYER_LIGHT] = { "Hell",                      "Light" },
    [S_MAP_LAYER_TRACKS]= { "Fahrspuren",                "Vehicle tracks" },
    /* Only offered when other receivers are configured -- see MAP_SCRIPT. */
    [S_MAP_LAYER_TRACKS_P]= { "Fahrspuren anderer Empf&auml;nger",
                                                         "Other receivers' tracks" },
    [S_MAP_TRACK_PTS]   = { "Punkte",                    "points" },
    [S_MAP_SEEN_BY]     = { "empfangen von",             "received by" },
    [S_PEERS]           = { "Weitere Empf&auml;nger",    "Other receivers" },
    [S_PEERS_HINT]      = { "Hostnamen oder IP-Adressen weiterer Empf&auml;nger, mit Komma getrennt "
                            "&ndash; z.&nbsp;B. <code>its-node344.local, 192.168.178.40</code>. Deren "
                            "Fahrzeuge erscheinen dann zus&auml;tzlich auf dieser Karte. Es gibt keine "
                            "Haupt- oder Nebenger&auml;te: jedes Ger&auml;t zeigt genau die an, die hier "
                            "eingetragen sind. Abgefragt wird vom Browser aus, das Ger&auml;t selbst "
                            "wird dadurch nicht belastet &ndash; dein Browser muss die anderen "
                            "Empf&auml;nger also erreichen k&ouml;nnen (gleiches Netz).",
                            "Host names or IP addresses of other receivers, comma-separated &ndash; e.g. "
                            "<code>its-node344.local, 192.168.178.40</code>. Their vehicles then also "
                            "appear on this map. There are no primary or secondary devices: each one "
                            "shows exactly those listed here. The browser does the fetching, so the "
                            "device itself carries no extra load &ndash; which means your browser must "
                            "be able to reach the other receivers (same network)." },
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
    [S_PCAP_FILT_THIN]  = { "alles &ndash; nur Ampelmeldungen h&ouml;chstens 1&times;/s",
                            "everything &ndash; but traffic-light messages at most once a second" },
    [S_PCAP_FILT_VEH]   = { "nur Fahrzeuge und Warnungen, keine Ampelmeldungen",
                            "vehicles and warnings only, no traffic-light messages" },
    [S_PCAP_FILT_HINT]  = { "Eine einzige Ampel macht 85&nbsp;% der Aufzeichnung aus &ndash; sie "
                            "wiederholt sich zehnmal pro Sekunde. Gemessen: 14,3&nbsp;MB/h ungek&uuml;rzt, "
                            "3,4&nbsp;MB/h bei 1&times;/s, 0,04&nbsp;MB/h nur mit Fahrzeugen. Die Frames "
                            "selbst bleiben unver&auml;ndert und vollst&auml;ndig, es werden nur "
                            "Wiederholungen weggelassen.",
                            "A single traffic light makes up 85% of the recording &ndash; it repeats "
                            "itself ten times a second. Measured: 14.3&nbsp;MB/h unfiltered, "
                            "3.4&nbsp;MB/h at 1/s, 0.04&nbsp;MB/h with vehicles only. The frames "
                            "themselves stay complete and unaltered; only repeats are skipped." },
    [S_TRACKS_ENABLE]   = { "Fahrspuren aufzeichnen",    "Record vehicle tracks" },
    [S_TRACKS_DAYS]     = { "Fahrspuren aufbewahren (Tage)", "Keep tracks for (days)" },
    [S_TRACKS_HINT]     = { "Zeichnet auf, wo Fahrzeuge tats&auml;chlich gefahren sind, und blendet "
                            "es auf der Karte als zuschaltbare Ebene ein. Sehr sparsam &ndash; rund "
                            "150 Punkte pro Stunde, etwa 150 KB f&uuml;r drei Tage. Beginnt bei null: "
                            "&auml;ltere Fahrten aus der PCAP-Aufzeichnung sind nicht enthalten.",
                            "Records where vehicles actually drove and shows it on the map as a "
                            "switchable layer. Very light &ndash; about 150 points an hour, roughly "
                            "150 KB for three days. Starts empty: earlier journeys from the PCAP "
                            "recordings are not included." },
    [S_ETH_LEDS]        = { "Netzwerk-LEDs",             "Network LEDs" },
    [S_ETH_LEDS_HINT]   = { "Die zwei LEDs an der Netzwerkbuchse zeigen Verbindung und Datenverkehr. "
                            "Abschalten st&ouml;rt den Betrieb nicht &ndash; nur die Verbindung ist "
                            "dann am Ger&auml;t selbst nicht mehr ablesbar. Wirkt sofort.",
                            "The two LEDs on the network socket show link and traffic. Turning them "
                            "off does not affect operation &ndash; it just means the link can no "
                            "longer be checked on the device itself. Takes effect immediately." },
    [S_UPD_INTRO]       = { "W&auml;hle eine Firmware-Datei (.bin) und klicke Hochladen. Das Ger&auml;t "
                            "flasht sie auf die inaktive OTA-Partition und startet neu. Danach musst du "
                            "das Update im Status best&auml;tigen, sonst wird es zur&uuml;ckgerollt.",
                            "Select a firmware (.bin) file and click Upload. The device flashes it to the "
                            "inactive OTA partition and reboots. Afterwards you must confirm the update on "
                            "the status page, otherwise it will be rolled back." },
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
    [S_FS_NOTE]         = { "Nur &bdquo;storage&ldquo; (/data) und die SD-Karte sind Dateisysteme mit Ordnern. "
                            "Die &uuml;brigen Partitionen sind Rohbereiche ohne Dateien "
                            "(nvs = Einstellungs-Datenbank, ota_* = Firmware-Images) &ndash; nur als Roh-Abbild ladbar.",
                            "Only \"storage\" (/data) and the SD card are file systems with folders. "
                            "The other partitions are raw regions without files "
                            "(nvs = settings database, ota_* = firmware images) &ndash; downloadable only as a raw image." },
    [S_TAR_SELECTED]    = { "Auswahl (.tar)",           "Selection (.tar)" },
    [S_TAR_NONE]        = { "Nichts markiert.",         "Nothing selected." },
    [S_TAR_HINT]        = { "Hinweis: Gr&ouml;&szlig;ere Downloads k&ouml;nnen wegen der "
                             "Ger&auml;te-Architektur mehrere Minuten dauern &ndash; die "
                             "Weboberfl&auml;che ist w&auml;hrenddessen nicht bedienbar.",
                             "Note: larger downloads can take several minutes due to the "
                             "device architecture &ndash; the web UI is unresponsive meanwhile." },
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
    [S_SD_DELETE_SELECTED] = { "Auswahl l&ouml;schen",  "Delete selection" },
    /* Used inside a JS confirm() call, not HTML text -- raw UTF-8, not HTML
     * entities (script-tag content isn't HTML-entity-decoded by the
     * browser), same as the existing S_SD_DELETE_CONFIRM right above. */
    [S_SD_DELETE_SEL_CONFIRM] = { "Ausgewählte Dateien/Ordner löschen?",
                                  "Delete selected files/folders?" },
    [S_SD_FORMAT]       = { "Karte formatieren",        "Format card" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SD_FORMAT_CONFIRM] = { "Karte wirklich formatieren? Alle Daten gehen verloren!",
                              "Really format the card? All data will be lost!" },
    /* Set via JS innerText -> JS \u escape, no HTML entity. */
    [S_SD_FORMATTING]   = { "Formatiere\\u2026",        "Formatting\\u2026" },
    [S_SD_UP_HERE]      = { "Datei hierher hochladen",  "Upload a file here" },
    [S_SD_UP_BTN]       = { "Hochladen",                "Upload" },
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
    [S_STAT_BOOTS]      = { "Neustarts gesamt",         "Reboots total" },
    [S_STAT_CRASHES]    = { "davon Abst&uuml;rze",      "of which crashes" },
    [S_STAT_LASTCRASH]  = { "Letzter Absturz",          "Last crash" },
    [S_STAT_MAXUP]      = { "L&auml;ngste Laufzeit",    "Longest uptime" },
    [S_STAT_NEVER]      = { "noch keiner",              "none yet" },
    [S_STAT_RESET]      = { "Z&auml;hler zur&uuml;cksetzen", "Reset counters" },
    [S_STAT_RESET_CONFIRM] = { "Alle Stabilit&auml;ts-Z&auml;hler wirklich auf null setzen?",
                               "Really reset all stability counters to zero?" },
    [S_NAV_LOGS]        = { "Logs",                     "Logs" },
    [S_TITLE_LOGS]      = { "Logs",                     "Logs" },
    [S_LOGS_SYS]        = { "System-Log",               "System log" },
    [S_LOGS_FRAMES]     = { "Frame-Log",                "Frame log" },
    [S_LOGS_REFRESH]    = { "Aktualisieren",            "Refresh" },
    [S_LOGS_NONE]       = { "Keine Log-Datei vorhanden (Logging aktiviert? SD eingebunden?).",
                            "No log file yet (logging enabled? SD mounted?)." },
    [S_LOGS_TAIL]       = { "Letzte %d KB, neueste Zeilen unten.",
                            "Last %d KB, newest lines at the bottom." },
    [S_NAV_TRAFFIC]     = { "Verkehr",                  "Traffic" },
    [S_TITLE_TRAFFIC]   = { "Verkehr",                  "Traffic" },
    [S_TRF_INTRO]       = { "Empfangene Nachrichten pro Stunde, nach Verkehrsteilnehmer. Wird st&uuml;ndlich auf die SD-Karte geschrieben und &uuml;berlebt Neustarts.",
                            "Received messages per hour, by road user. Written hourly to the SD card, survives reboots." },
    [S_TRF_WINDOW]      = { "Zeitraum",                 "Window" },
    [S_TRF_W_24H]       = { "24 Stunden",               "24 hours" },
    [S_TRF_W_7D]        = { "7 Tage",                   "7 days" },
    [S_TRF_W_30D]       = { "30 Tage",                  "30 days" },
    [S_TRF_TOTAL]       = { "Gesamt",                   "Total" },
    [S_TRF_HOUR]        = { "Stunde",                   "Hour" },
    [S_TRF_SPEED]       = { "&Oslash;/max km/h",        "avg/max km/h" },
    [S_TRF_NODATA]      = { "Noch keine Daten (SD-Karte n&ouml;tig, sammelt ab der ersten vollen Stunde).",
                            "No data yet (needs an SD card; collects from the first full hour)." },
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
    [S_EVT_TRAFFIC]     = { "Verkehrslage / Stau",      "Traffic condition / queue" },
    [S_TRF_SPEED_BY_TYPE] = { "Geschwindigkeit nach Typ (&Oslash;/max km/h)",
                              "Speed by type (avg/max km/h)" },
    [S_TRF_LIGHTS]      = { "Ampeln (live)",            "Traffic lights (live)" },
    [S_TRF_LIGHTS_NONE] = { "Keine Ampeldaten (SPATEM) empfangen.",
                            "No traffic-light data (SPATEM) received." },
    [S_TRF_INTERSECTION] = { "Kreuzung",               "Intersection" },
    [S_TRF_LIGHTS_INTRO] = {
        "Aktueller Schaltzustand je Signalgruppe der empfangenen Kreuzungen. "
        "Angezeigt wird, was die Gruppe steuert (aus der Kartennachricht "
        "MAPEM), mit ihrer Signalgruppen-Nummer in Klammern. "
        "Die Sekundenzahl daneben ist die Restzeit bis zum "
        "Umschalten &ndash; sie erscheint nur, wenn die Ampel diese Angabe "
        "mitsendet (meist kurz vor einem Wechsel). Farbe = aktuelle Phase:",
        "Current phase per signal group of the received intersections. Shown is "
        "what each group controls (from the MAPEM map message), with its "
        "signal-group number in brackets. The seconds "
        "next to it are the time left until the phase changes &ndash; shown "
        "only when the light broadcasts it (usually shortly before a change). "
        "Colour = current phase:" },
    [S_TRF_PH_GREEN]    = { "Gr&uuml;n (frei)",        "Green (go)" },
    [S_TRF_PH_AMBER]    = { "Gelb (&Uuml;bergang)",    "Amber (change)" },
    [S_TRF_PH_RED]      = { "Rot (Halt)",              "Red (stop)" },
    [S_TRF_PH_OTHER]    = { "Aus/unbekannt",           "Off/unknown" },
    [S_DIR_STRAIGHT]    = { "geradeaus",               "straight" },
    [S_DIR_LEFT]        = { "links",                   "left" },
    [S_DIR_RIGHT]       = { "rechts",                  "right" },
    [S_DIR_UTURN]       = { "wenden",                  "U-turn" },
    [S_DIR_PED]         = { "Fu&szlig;g&auml;nger",    "pedestrian" },
    [S_NAV_MAP]         = { "Karte",                    "Map" },
    [S_TITLE_MAP]       = { "Live-Karte",               "Live map" },
    [S_MAP_HINT]        = { "Positionen aus empfangenen V2X-Nachrichten: Fahrzeuge (CAM) und ortsfeste Sender wie Ampeln/RSUs (Position aus der GeoNetworking-Schicht). Symbol je Stationstyp; Anklicken zeigt Details (Typ, Zeit, RSSI, bei Fahrzeugen auch km/h). Marker verschwinden, wenn 60 Sekunden lang nichts mehr von diesem Sender empfangen wurde. Zum Laden der Kartenkacheln braucht der Browser Internetzugang (OpenStreetMap) &ndash; das Ger&auml;t selbst nicht.<br><br>Verlauf/Wiedergabe: W&auml;hle unten einen Zeitbereich (Von/bis) und klicke Laden, dann kannst du mit dem Regler und der Play-Taste die Positionen aus diesem Zeitraum abspielen. Diese Daten stammen aus der rollierenden PCAP-Aufzeichnung auf der SD-Karte (falls aktiviert).",
                            "Positions from received V2X messages: vehicles (CAM) and stationary senders such as traffic lights/RSUs (position from the GeoNetworking layer). Icon per station type; click for details (type, time, RSSI, and km/h for vehicles). Markers disappear after 60 seconds without a new message from that sender. Loading the map tiles needs the browser to have internet access (OpenStreetMap) &ndash; the device itself doesn't.<br><br>History/playback: pick a time range (from/to) below and click Load, then use the slider and Play button to replay positions from that period. This data comes from the rolling PCAP recording on the SD card (if enabled)." },
    [S_MAP_HELP]        = { "Info &amp; Hilfe",           "Info &amp; help" },
    [S_MAP_LAYER_STREETS] = { "Karte",                  "Map" },
    [S_MAP_LAYER_SATELLITE] = { "Satellit",             "Satellite" },
    [S_MAP_DENM]        = { "Gefahrenmeldung aktiv",   "Hazard warning active" },
    [S_MAP_LINE]        = { "Linie",                   "Line" },
    [S_SYS_COREDUMP]      = { "&#9888; Crash-Dump verf&uuml;gbar", "&#9888; Crash dump available" },
    [S_SYS_COREDUMP_DOWNLOAD] = { "Herunterladen",      "Download" },
    [S_SYS_COREDUMP_CLEAR] = { "L&ouml;schen",          "Delete" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SYS_COREDUMP_CLEAR_CONFIRM] = { "Crash-Dump löschen?", "Delete crash dump?" },
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
    uint8_t  pt_line;      /* public-transport line number, 0 = none */
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
static SemaphoreHandle_t msg_ring_mutex;

/* Recent-DENM tracker: remembers the wall-clock second each station last sent
 * a hazard warning (DENM), so /map can flag that sender's marker with a
 * warning for ~60 s. Lockless -- all fields are 32-bit words (atomic
 * read/write on the RISC-V core) and the data is purely cosmetic, so a torn
 * read between the two words is harmless. Uses time(NULL) at both note and
 * read time, so it stays self-consistent whether or not NTP has synced. */
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
    /* Decoded from the full frame, not from any short prefix -- CAM/DENM's
     * BTP header sits hundreds of bytes in. */
    its_decoded_t d;
    its_decode_frame(packet->payload, packet->length, &d);
    snprintf(e->msgtype, sizeof(e->msgtype), "%s", d.label);
    e->has_position = d.has_position;
    e->lat_e7 = d.lat_e7;
    e->lon_e7 = d.lon_e7;
    e->station_id = d.station_id;
    e->has_speed = d.has_speed;
    e->speed_cmps = d.speed_cmps;
    e->length_dm = d.veh.valid ? d.veh.length_dm : 0;
    e->width_dm = d.veh.valid ? d.veh.width_dm : 0;
    e->pt_line = d.pt_line;
    e->heading_ddeg = d.cam.has_heading ? d.cam.heading_ddeg : 0xFFFF;
    e->has_accel_ctrl = d.cam.has_accel_ctrl;
    e->accel_ctrl = d.cam.accel_ctrl;
    e->has_lights = d.cam.has_lights;
    e->ext_lights = d.cam.ext_lights;
    e->role = d.cam.role;
    e->embarking = d.pt_embarking;
    e->n_path = d.cam.n_path;
    memcpy(e->path_lat_e7, d.cam.path_lat_e7, sizeof(e->path_lat_e7));
    memcpy(e->path_lon_e7, d.cam.path_lon_e7, sizeof(e->path_lon_e7));
    uint8_t st_code = d.station_type, msg_id = d.message_id;
    msg_type_stats_record(e->msgtype);
    tstat_note(st_code, msg_id, e->has_speed, e->speed_cmps);
    /* Log the hazard where it IS, not where the sender is -- the DENM's own
     * eventPosition when it carried one, the sender's position otherwise. */
    events_note(e->seconds, st_code, msg_id, d.denm_cause, d.denm_subcause,
                d.denm_station, d.denm_seq,
                d.has_denm_pos || e->has_position,
                d.has_denm_pos ? d.denm_lat_e7 : e->lat_e7,
                d.has_denm_pos ? d.denm_lon_e7 : e->lon_e7);
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
    "<style>"
    "*{box-sizing:border-box;accent-color:#f2b134}"
    /* Amber accent (device's subject is vehicles/traffic lights), signal-
     * blue kept distinct for links so they're never mistaken for buttons. */
    /* min-height:100vh: on a page shorter than the viewport (e.g. /update),
     * body's own background otherwise stops at its content height, showing
     * bare layers underneath as visible horizontal bands. Deliberately no
     * explicit html{background} here -- that disables the CSS canvas-
     * background-propagation rule (body's background becomes the viewport's
     * own canvas paint, body's own box then paints transparent), which is
     * what let body::before's radar sweep (z-index:-1, otherwise stacked
     * BEHIND body's own now-opaque background) show through at all. */
    "body{min-height:100vh;font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;margin:0;color:#edf0f2;line-height:1.5;position:relative;"
    "background:"
    "radial-gradient(circle at 12%% -8%%,rgba(242,177,52,.13),transparent 42%%),"
    "radial-gradient(circle at 100%% 12%%,rgba(79,184,224,.11),transparent 40%%),"
    "repeating-linear-gradient(0deg,rgba(255,255,255,.018) 0 1px,transparent 1px 34px),"
    "repeating-linear-gradient(90deg,rgba(255,255,255,.012) 0 1px,transparent 1px 34px),"
    "#0c1013}"
    "body::before{content:'';position:fixed;top:50%%;left:50%%;width:220vmax;height:220vmax;"
    "margin:-110vmax 0 0 -110vmax;z-index:-1;pointer-events:none;"
    "background:conic-gradient(from 0deg,transparent 0deg,rgba(242,177,52,.12) 8deg,transparent 30deg,transparent 360deg);"
    "mix-blend-mode:screen;animation:sweep 22s linear infinite}"
    "@keyframes sweep{to{transform:rotate(360deg)}}"
    "@media(prefers-reduced-motion:reduce){body::before{animation:none;display:none}}"
    ".wrap{width:100%%;max-width:1400px;margin:0 auto;padding:18px clamp(14px,4vw,32px) 48px}"
    "a{color:#4fb8e0;text-decoration:none}a:hover{text-decoration:underline}"
    "h1{font-size:20px;font-weight:600;margin:6px 0 16px}"
    "h2{font-size:16px;font-weight:600;margin:22px 0 10px}"
    "h3{font-size:14px;font-weight:600;margin:18px 0 8px;color:#c7d2e0}"
    /* nav itself doesn't wrap -- .navlinks wraps internally instead, while
     * .lang stays a fixed sibling anchored top-right (else it drops onto
     * its own orphaned row once the links need more than one line). */
    "nav{display:flex;align-items:flex-start;gap:8px;padding:5px;background:#15191d;border:1px solid #2a2f34;border-radius:10px;margin-bottom:18px;font-size:13px}"
    ".navlinks{display:flex;flex-wrap:wrap;gap:4px;flex:1;min-width:0;align-items:center}"
    "nav a{color:#94a0a8;padding:6px 12px;border-radius:7px;transition:background .12s,color .12s}"
    "nav a:hover{background:#1d2227;color:#edf0f2;text-decoration:none}"
    "nav a.active{background:linear-gradient(160deg,#f2b134,#d99a1f);color:#1a1204;font-weight:600;"
    "box-shadow:0 0 0 1px rgba(242,177,52,.35),0 2px 10px -2px rgba(242,177,52,.5)}"
    /* Hamburger toggle: hidden on desktop (the full link row fits), shown
     * only on narrow screens via the media query below. Pure CSS -- a hidden
     * checkbox (.nvt) whose :checked state reveals .navlinks, toggled by the
     * <label> button, so no JS is needed and it degrades gracefully. */
    "nav .logo{display:flex;align-items:center;align-self:center;padding:0 8px 0 4px;flex-shrink:0}"
    "nav .logo img{display:block;border-radius:5px}"
    "nav .brgr{display:none;color:#94a0a8;padding:6px 12px;border-radius:7px;cursor:pointer;font-size:18px;line-height:1;user-select:none}"
    "nav .brgr:hover{background:#1d2227}"
    "nav .nvt{display:none}"
    /* Flag toggle: a small pill holding both flags, current language
     * highlighted -- replaces the old plain text link (just the other
     * language's name), which looked like a stray, unstyled afterthought
     * next to the nav pill. */
    "nav .lang{flex-shrink:0;display:flex;gap:2px;background:#0c1013;border-radius:20px;padding:2px;border:1px solid #2a2f34}"
    "nav .lang a{padding:3px 8px;border-radius:16px;font-size:15px;line-height:1.3;opacity:.5}"
    "nav .lang a:hover{background:#1d2227;text-decoration:none;opacity:.8}"
    "nav .lang a.active{background:linear-gradient(160deg,#f2b134,#d99a1f);opacity:1}"
    /* border-collapse:separate (not collapse!) -- browsers ignore
     * border-radius on a <table> when its borders are collapsed, which made
     * plain (non-.scroll) tables look square-cornered despite this rule.
     * border-spacing:0 keeps cells touching, same look as collapse. */
    "table{width:100%%;border-collapse:separate;border-spacing:0;background:#15191d;border:1px solid #2a2f34;border-radius:10px;margin:10px 0;overflow:hidden}"
    "th,td{text-align:left;padding:10px 14px;font-size:13.5px;border-bottom:1px solid #20252a}"
    "tr:last-child>*{border-bottom:none}"
    "tr:hover>td{background:#1a1f24}"
    "th{color:#94a0a8;font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}"
    "td{font-variant-numeric:tabular-nums}"
    ".kv th{width:1px;white-space:nowrap;padding-right:32px}.kv td{overflow-wrap:anywhere}"
    ".scroll{overflow-x:auto;border:1px solid #2a2f34;border-radius:10px;margin:10px 0}"
    ".scroll table{border:none;border-radius:0;margin:0;width:auto;min-width:100%%}"
    ".scroll td,.scroll th{white-space:nowrap}"
    /* Detail/Type cells wrap at ANY width -- the detail text alone can
     * be ~100 chars, wide enough to force scroll even on desktop. */
    ".scroll td.wrapcell{white-space:normal;word-break:break-word}"
    /* Narrow screens: tighter padding, #mtbl drops its redundant "#" column. */
    "@media(max-width:640px){"
    /* Collapse nav to a hamburger: burger+flags row, links drop into a
     * dropdown on tap (.nvt:checked). Sticky so the dropdown stays reachable
     * while scrolling. z-index:1000, not lower -- Leaflet's own panes
     * (/map only) go up to 700 and would otherwise render on top of an
     * open dropdown. */
    "nav{flex-wrap:wrap;align-items:center;position:sticky;top:0;z-index:1000}"
    "nav .brgr{display:block;order:1}"
    "nav .lang{order:2;margin-left:auto}"
    "nav .navlinks{display:none;order:3;flex-basis:100%%;flex-direction:column;gap:2px;margin-top:6px;"
    "max-height:calc(100vh - 60px);overflow-y:auto}"
    "nav .nvt:checked~.navlinks{display:flex}"
    "nav .navlinks a{padding:9px 12px}"
    ".scroll th,.scroll td{padding:8px 6px}"
    "#mtbl th:first-child,#mtbl td:first-child{display:none}"
    /* .kv th is nowrap+shrink-to-fit, but that shrinks to the WIDEST label
     * in the WHOLE table (shared column width) -- one long label (e.g.
     * "Web-Passwort (Benutzer ...)") was enough to push that column, and so
     * the whole table, wider than the screen on every row, not just its
     * own. Wrapping it onto 2 lines above this width caps the damage. */
    ".kv th{white-space:normal;max-width:38vw}"
    "}"
    "button{background:linear-gradient(160deg,#f2b134,#d99a1f);color:#1a1204;font-weight:600;border:none;font-size:13.5px;padding:9px 15px;border-radius:8px;margin:3px 5px 3px 0;cursor:pointer;"
    "box-shadow:0 2px 12px -3px rgba(242,177,52,.5);transition:box-shadow .15s,transform .08s}"
    "button:hover{background:linear-gradient(160deg,#ffc861,#e2a52b);box-shadow:0 3px 16px -2px rgba(242,177,52,.65)}"
    "button:active{transform:translateY(1px)}"
    "input,select{background:#0c1013;color:#edf0f2;border:1px solid #333a41;border-radius:7px;padding:7px 9px;font-size:13.5px;max-width:100%%}"
    "input:focus,select:focus{outline:none;border-color:#4fb8e0;box-shadow:0 0 0 3px rgba(79,184,224,.18)}"
    /* File inputs sit directly before an upload button (/update, file
     * management); on narrow screens where they don't fit on one line, the
     * button wrapped to its own line with NO gap above it, looking stuck to
     * the field. margin-bottom gives that wrapped line some breathing room;
     * harmless when they DO fit side by side (just a little extra space). */
    "input[type=file]{margin:4px 8px 8px 0}"
    ".kv input:not([type=checkbox]):not([type=range]){width:100%%;max-width:360px}"
    /* Range inputs were excluded above and need their own width cap, else
     * the browser's intrinsic width widens the whole table column. */
    ".kv input[type=range]{width:100%%;max-width:280px}"
    /* IPv4 fields only need "255.255.255.255" (15 chars); !important since
     * the generic 360px rule above is otherwise more specific. */
    ".ipfield{max-width:140px!important}"
    /* ::before dot gives each badge a small "status light" even where the
     * colour alone might be hard to tell apart (colour-blindness, a dim
     * screen) -- purely CSS, no change needed anywhere the .ok/.bad spans
     * themselves get built. */
    ".ok{display:inline-block;color:#5fd88a;background:#122019;padding:2px 10px;border-radius:20px;font-size:12px}"
    ".bad{display:inline-block;color:#ff6b6b;background:#241315;padding:2px 10px;border-radius:20px;font-size:12px}"
    ".ok::before,.bad::before{content:'';display:inline-block;width:5px;height:5px;border-radius:50%%;"
    "background:currentColor;margin-right:5px;vertical-align:middle}"
    ".warn{background:#241c0d;border:1px solid #7a5c12;color:#f2b134;padding:12px 14px;border-radius:10px;margin:14px 0}"
    "small{color:#94a0a8}"
    ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:6px 0 4px}"
    ".card{background:#15191d;border:1px solid #2a2f34;border-radius:10px;padding:12px 14px}"
    ".card .l{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#94a0a8;margin-bottom:5px}"
    ".card .v{font-size:22px;font-weight:600;font-variant-numeric:tabular-nums}"
    "pre{background:#0a0d0f;border:1px solid #2a2f34;border-radius:9px;color:#cfe8f0}"
    "</style><title>%s</title></head><body><div class='wrap'>"
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
    "<a href='/traffic?lang=%s'>%s</a>"
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
    "<h1>%s</h1>";

static const char PAGE_FOOTER[] =
    "<script>document.querySelectorAll('nav a').forEach(function(a){"
    "var h=(a.getAttribute('href')||'').split('?')[0];"
    "if(h&&h===location.pathname)a.className='active';});</script>"
    "</div></body></html>";

/* `json_url` != NULL enables the floating pause/resume button + polling
 * loop: it fetches that URL every `CONFIG_INDEX_REFRESH_SEC` seconds and
 * hands the parsed JSON to `window.arApply` (defined by the page's own
 * inline script, further down in the same HTML stream -- already parsed
 * by the time this runs, since it only fires on the `load` event). No
 * full-page reload, so CSS animations (the radar sweep) never restart. */
static void send_page_header_refresh(httpd_req_t *req, const char *heading, const char *json_url)
{
    /* static EXT_RAM_BSS_ATTR, not a stack buffer -- the httpd task's stack
     * is only 16384 bytes total (see webserver_init), and header[] growing
     * on-stack is exactly what caused a real crash once. */
    static EXT_RAM_BSS_ATTR char refresh_tag[1024];
    /* Static doesn't auto-reset between calls; clear explicitly so a page
     * with json_url==NULL can't inherit a previous request's script. */
    refresh_tag[0] = '\0';
    if (json_url)
    {
        uint32_t ri = 5;
        config_get_u32(CONFIG_INDEX_REFRESH_SEC, &ri);
        if (ri > 0 && ri < 0xFFFFFFFF)
            snprintf(refresh_tag, sizeof(refresh_tag),
                "<script>(function(){var ri=%lu,url='%s',t=null;"
                "function tick(){fetch(url).then(function(r){return r.json();})"
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
                "});})();</script>",
                (unsigned long)ri, json_url);
    }

    const char *lc = current_lang == LANG_DE ? "de" : "en";
    const char *lang_de_active = (current_lang == LANG_DE) ? "active" : "";
    const char *lang_en_active = (current_lang == LANG_EN) ? "active" : "";

    /* Browser-tab / home-screen title: append the node id so it's still
     * distinguishable with several receivers open at once -- "ITS G5 Node"
     * alone (the old fixed text) looked identical in every tab. Nodeid is
     * free text from NVS (user-editable on /settings), so it must be
     * HTML-escaped same as everywhere else it's rendered (see the
     * /settings page's own nodeid_esc). */
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

    static EXT_RAM_BSS_ATTR char header[9216];
    snprintf(header, sizeof(header), PAGE_HEADER_FMT,
             lc, page_title, refresh_tag, page_title,
             lc, T(S_NAV_STATUS),
             lc, T(S_NAV_MESSAGES),
             lc, T(S_NAV_SETTINGS),
             lc, T(S_NAV_UPDATE),
             lc, T(S_NAV_MAP),
             lc, T(S_NAV_TRAFFIC),
             lc, T(S_NAV_SYSTEM),
#if CONFIG_ENABLE_SD
             lc, T(S_NAV_SD),
             lc, T(S_NAV_LOGS),
#endif
             lang_de_active, lang_en_active,
             heading);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send_chunk(req, header, HTTPD_RESP_USE_STRLEN);
}

static void send_page_header(httpd_req_t *req, const char *heading)
{
    send_page_header_refresh(req, heading, NULL);
}

/* Renders the status page's "Activity" sparkline + message-type breakdown,
 * from counters rate_record_packet/msg_type_stats_record already fill in
 * webserver_handle_packet. */
/* Builds just the sparkline's <rect> bars (no <svg> wrapper -- that's
 * emitted once, id='st-spark', and only its innerHTML gets swapped on
 * later polls since the viewBox/size never change). Shared between the
 * initial /  render and /status.json. */
static void build_spark_bars_html(char *out, size_t out_size)
{
    uint64_t now_sec = esp_timer_get_time() / 1000000ull;
    uint32_t counts[RATE_WINDOW_SECS];
    uint32_t maxcount = 1;
    if (msg_ring_mutex && xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
    {
        for (size_t i = 0; i < RATE_WINDOW_SECS; i++)
        {
            uint64_t sec = now_sec - (RATE_WINDOW_SECS - 1 - i);
            rate_bucket_t *b = &rate_buckets[sec % RATE_WINDOW_SECS];
            counts[i] = (b->sec == sec) ? b->count : 0;
        }
        xSemaphoreGive(msg_ring_mutex);
    }
    else
    {
        memset(counts, 0, sizeof(counts));
    }
    for (size_t i = 0; i < RATE_WINDOW_SECS; i++)
        if (counts[i] > maxcount) maxcount = counts[i];

    size_t o = 0;
    for (size_t i = 0; i < RATE_WINDOW_SECS && o < out_size; i++)
    {
        int h = counts[i] ? (int)(4 + (counts[i] * 32) / maxcount) : 1;
        o += snprintf(out + o, out_size - o,
            "<rect x='%d' y='%d' width='3' height='%d' rx='1' fill='#f2b134'/>",
            (int)i * 4, 40 - h, h);
    }
}

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

static void render_activity_stats(httpd_req_t *req)
{
    /* Sent as separate chunks (title / svg / breakdown) rather than composed
     * into one buffer: the sparkline alone can approach its 6 KiB capacity,
     * and gcc's -Werror=format-truncation assumes that worst case for any
     * %s of a fixed-size array -- concatenating it into another snprintf
     * would need an implausibly large destination just to satisfy the
     * compiler. */
    char title[128];
    snprintf(title, sizeof(title), "<h3>%s</h3>", T(S_ACTIVITY_TITLE));
    httpd_resp_send_chunk(req, title, HTTPD_RESP_USE_STRLEN);

    char svgopen[160];
    snprintf(svgopen, sizeof(svgopen),
        "<svg id='st-spark' viewBox='0 0 %d 40' width='100%%' height='40' preserveAspectRatio='none'>",
        RATE_WINDOW_SECS * 4);
    httpd_resp_send_chunk(req, svgopen, HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR char bars[6144];
    build_spark_bars_html(bars, sizeof(bars));
    httpd_resp_send_chunk(req, bars, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "</svg>", HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR char typeline[1024];
    build_typeline_html(typeline, sizeof(typeline));
    char typeblock[1152];
    snprintf(typeblock, sizeof(typeblock), "<p id='st-type'>%s</p>",
        typeline[0] ? typeline : T(S_ACTIVITY_NONE));
    httpd_resp_send_chunk(req, typeblock, HTTPD_RESP_USE_STRLEN);

    char hintblock[768];
    snprintf(hintblock, sizeof(hintblock), "<p><small>%s</small></p>", T(S_TYPE_HINT));
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

    send_page_header_refresh(req, T(S_TITLE_STATUS), "/status.json");

    /* Confirm banner if this firmware is pending verification */
    if (ota_is_pending_verify())
    {
        /* The POST carries no query string of its own; without ?lang= here,
         * resolve_language() on that request defaults to German regardless
         * of the page's actual language (same class of bug as /update). */
        const char *lc = current_lang == LANG_DE ? "de" : "en";
        char banner[512];
        snprintf(banner, sizeof(banner),
            "<div class='warn'><p>%s</p>"
            "<button onclick=\"fetch('/confirm?lang=%s',{method:'POST'}).then(r=>r.text()).then(t=>{alert(t);location.reload();})\">%s</button>"
            "</div>",
            T(S_CONFIRM_NEEDED), lc, T(S_CONFIRM_BTN));
        httpd_resp_send_chunk(req, banner, HTTPD_RESP_USE_STRLEN);
    }

    /* id='st-*' on every cell that /status.json can update -- see arApply
     * below. Node ID/MAC/firmware/hardware never change without a reboot
     * (a full page load already happens then), so those stay static. */
    char body[3584];
    snprintf(body, sizeof(body),
        "<div class='cards'>"
        "<div class='card'><div class='l'>%s</div><div class='v' id='st-msgs'>%lu</div></div>"
        "<div class='card'><div class='l'>%s</div><div class='v' id='st-rate'>%lu</div></div>"
        "<div class='card'><div class='l'>%s</div><div class='v' id='st-uptime'>%s</div></div>"
        "</div>"
        "<table class='kv'>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%02x:%02x:%02x:%02x:%02x:%02x</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td><span class='%s' id='st-sniff'>%s</span></td></tr>"
        "<tr><th>%s</th><td id='st-chan'>%s</td></tr>"
        "<tr><th>%s</th><td><span class='%s' id='st-mqtt'>%s</span></td></tr>"
#ifdef CONFIG_ENABLE_TEMPERATURE
        "<tr><th>%s</th><td id='st-temp'>%.1f &deg;C</td></tr>"
#endif
        "</table>",
        T(S_MSGS_RECEIVED), (unsigned long)msg_total_count,
        T(S_RATE), (unsigned long)rate,
        T(S_UPTIME), uptime_str,
        T(S_NODEID), nodeid_esc,
        T(S_MAC), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        T(S_FW_VERSION), app_desc->version,
        T(S_HW_VARIANT), CONFIG_HW_VARIANT,
        T(S_SNIFFER), running ? "ok" : "bad", running ? T(S_RUNNING) : T(S_STOPPED),
        T(S_CHANNEL), chan_str,
        T(S_MQTT), mqtt_connected_state ? "ok" : "bad",
        mqtt_connected_state ? T(S_CONNECTED) : T(S_DISCONNECTED)
#ifdef CONFIG_ENABLE_TEMPERATURE
        , T(S_TEMPERATURE), (double)temperature_get()
#endif
    );
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);

    render_activity_stats(req);

    /* No reload on click -- fetch the toggle, then let window.stSetSniff
     * (defined in applyscript below) update the button + status span from
     * the action just taken, same as a poll would. */
    /* 1024, not 512: the power-off button plus its confirm/busy strings add
     * ~330 bytes in German, and a truncated onclick would silently produce a
     * dead button rather than an error. */
    char buttons[1024];
    snprintf(buttons, sizeof(buttons),
        "<p>"
        "<button id='st-sniffbtn' data-action='%s' onclick=\"var a=this.getAttribute('data-action');"
        "fetch('/sniffer?action='+a,{method:'POST'}).then(function(){if(window.stSetSniff)window.stSetSniff(a==='start');})\">%s</button> "
        "<button onclick=\"if(confirm('%s'))fetch('/reboot',{method:'POST'}).then(()=>{document.body.innerHTML='<p>%s</p>';})\">%s</button>"
#if CONFIG_ENABLE_SD
        /* Result goes into its own span rather than replacing the page: if the
         * unmount fails the operator has to stay on the page and see why. */
        " <button onclick=\"if(!confirm('%s'))return;"
        "var s=document.getElementById('po-res');s.innerText='%s';"
        "fetch('/poweroff',{method:'POST'}).then(function(r){return r.text();})"
        ".then(function(t){s.innerText=t;}).catch(function(){s.innerText='%s';})\">%s</button>"
        " <span id='po-res'></span>"
#endif
        "</p>",
        running ? "stop" : "start",
        running ? T(S_SNIFF_STOP) : T(S_SNIFF_START),
        T(S_REBOOT_CONFIRM), T(S_REBOOTING), T(S_REBOOT)
#if CONFIG_ENABLE_SD
        , T(S_POWEROFF_CONFIRM), T(S_POWEROFF_BUSY), T(S_POWEROFF_FAIL), T(S_POWEROFF)
#endif
        );
    httpd_resp_send_chunk(req, buttons, HTTPD_RESP_USE_STRLEN);

    /* Applies a /status.json response to the cells above. Sniffer/MQTT
     * labels are embedded here (not re-sent every poll) since they're
     * fixed for the page's lifetime; innerHTML (not textContent) because
     * they may contain an HTML entity (e.g. "l&auml;uft"). Also swaps the
     * Start/Stop button's label + action so it stays correct without a
     * reload after a start/stop triggered from elsewhere. */
    char applyscript[1536];
    snprintf(applyscript, sizeof(applyscript),
        "<script>(function(){"
        "var RUN='%s',STOP='%s',CONN='%s',DISC='%s',BSTART='%s',BSTOP='%s';"
        "window.stSetSniff=function(r){"
        "var sn=document.getElementById('st-sniff');sn.className=r?'ok':'bad';sn.innerHTML=r?RUN:STOP;"
        "var sb=document.getElementById('st-sniffbtn');"
        "if(sb){sb.textContent=r?BSTOP:BSTART;sb.setAttribute('data-action',r?'stop':'start');}"
        "};"
        "window.arApply=function(d){"
        "document.getElementById('st-msgs').textContent=d.msgs;"
        "document.getElementById('st-rate').textContent=d.rate;"
        "document.getElementById('st-uptime').textContent=d.uptime;"
        "document.getElementById('st-chan').textContent=d.chan;"
        "document.getElementById('st-spark').innerHTML=d.spark;"
        "document.getElementById('st-type').innerHTML=d.types;"
        "window.stSetSniff(d.sniff);"
        "var mq=document.getElementById('st-mqtt');"
        "mq.className=d.mqtt?'ok':'bad';mq.innerHTML=d.mqtt?CONN:DISC;"
        "var te=document.getElementById('st-temp');if(te&&d.temp!==undefined)te.textContent=d.temp.toFixed(1)+' \\u00b0C';"
        "};})();</script>",
        T(S_RUNNING), T(S_STOPPED), T(S_CONNECTED), T(S_DISCONNECTED),
        T(S_SNIFF_START), T(S_SNIFF_STOP));
    httpd_resp_send_chunk(req, applyscript, HTTPD_RESP_USE_STRLEN);

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

    static EXT_RAM_BSS_ATTR char bars[6144];
    build_spark_bars_html(bars, sizeof(bars));
    static EXT_RAM_BSS_ATTR char typeline[1024];
    build_typeline_html(typeline, sizeof(typeline));

    static EXT_RAM_BSS_ATTR char json[8192];
    snprintf(json, sizeof(json),
        "{\"msgs\":%lu,\"rate\":%lu,\"uptime\":\"%s\",\"sniff\":%s,\"chan\":\"%s\",\"mqtt\":%s,"
        "\"spark\":\"%s\",\"types\":\"%s\""
#ifdef CONFIG_ENABLE_TEMPERATURE
        ",\"temp\":%.1f"
#endif
        "}",
        (unsigned long)msg_total_count, (unsigned long)rate, uptime_str,
        running ? "true" : "false", chan_str,
        mqtt_connected_state ? "true" : "false",
        bars, typeline[0] ? typeline : T(S_ACTIVITY_NONE)
#ifdef CONFIG_ENABLE_TEMPERATURE
        , (double)temperature_get()
#endif
    );
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

/* Appends the optional CAM-detail keys shared by the live feed and the map
 * seed. Kept in one place so the two can't drift apart -- they already
 * carried two separate copies of the speed/size/line block.
 *
 * KEYS ALREADY TAKEN in this message object, check before adding one:
 *   i station id   a lat        o lon         y label      t time
 *   r rssi         l length     h HEX PREVIEW s speed      d denm flag
 *   vl length      vw width     pl pt line
 *   hd heading     ac pedals    el lights     vr role      eb embarking
 *   ph path
 * `h` is the frame hex dump and predates all of this -- naming the heading
 * `h` made every popup read "heading NaN", because m.h was that string.
 *
 * Returns the number of bytes written (0 if the entry carries none). */
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

/* One-line human summary of a message for the /messages table, replacing the
 * 32-byte hex preview that used to sit there. Measured over 3965 real frames,
 * 25 of those 32 bytes were identical in every single one: the preview showed
 * the 802.11 header, the sender MAC (already a column) and a sequence
 * counter. Everything a reader cares about begins well past byte 32. Raw
 * bytes remain available in full via the PCAP download. */
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
    if (e->has_speed && n < cap)
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

        char detail[320];
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
            if (e->has_speed && po < sizeof(possuffix))
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

        /* msgtype/clock/rssi_str hold only digits, letters, spaces, ':',
         * '-', '.' (see its_decode_frame/format_clock), and `detail` is
         * assembled from our own tables and formatted numbers -- none of it
         * is frame-controlled, so no JSON escaping is needed. It does carry
         * HTML entities and a <span>, which is fine: the row is built with
         * innerHTML on the client. */
        /* Measure first and stop while the closing bracket still fits. The
         * old form let `o` run past the buffer, and then the final `]` was
         * silently skipped -- the client received malformed JSON, its parse
         * threw, and the live table and map quietly stopped updating. With
         * a fully decoded detail line per entry the worst case is around
         * 20 KB against a 6 KB buffer, so this is reachable, not theoretical.
         * Entries are walked newest-first, so what gets dropped is the
         * oldest -- the right end to lose. */
        static const char ENTRY_FMT[] =
            "%s{\"t\":\"%s\",\"r\":\"%s\",\"l\":%lu,\"y\":\"%s\",\"h\":\"%s\"%s}";
        int need = snprintf(NULL, 0, ENTRY_FMT,
            n == 0 ? "" : ",", clock, rssi_str, (unsigned long)e->length,
            e->msgtype, detail, possuffix);
        if (need < 0 || o + (size_t)need + 2 > out_size)
            break;
        o += snprintf(out + o, out_size - o, ENTRY_FMT,
            n == 0 ? "" : ",", clock, rssi_str, (unsigned long)e->length,
            e->msgtype, detail, possuffix);
    }
    /* Always closes: the loop above never consumes the two bytes kept back. */
    out[o++] = ']';
    out[o] = '\0';
    return o;
}

/* Sockets whose last send failed, so the next ticks skip them instead of
 * retrying once a second. A browser tab closed without a clean WebSocket
 * close leaves esp_http_server still reporting the socket as a live
 * websocket for many minutes; every tick then tried again, failed again and
 * logged again -- 816 warnings in one day of testing, in bursts of twelve a
 * minute lasting a quarter hour each. The entry expires so a reused file
 * descriptor is not shut out permanently. */
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

    char intro[256];
    snprintf(intro, sizeof(intro), "<p>");
    size_t l = strlen(intro);
    snprintf(intro + l, sizeof(intro) - l, T(S_MSG_INTRO), WEB_MSG_RING_SIZE);
    l = strlen(intro);
    snprintf(intro + l, sizeof(intro) - l, "</p>");
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);

    /* Own chunk (not concatenated into intro above): T(S_TYPE_HINT) alone can
     * approach several hundred bytes, which intro's small fixed buffer isn't
     * sized for. */
    char typehint[768];
    snprintf(typehint, sizeof(typehint), "<p><small>%s</small></p>", T(S_TYPE_HINT));
    httpd_resp_send_chunk(req, typehint, HTTPD_RESP_USE_STRLEN);

    char thead[384];
    snprintf(thead, sizeof(thead),
        "<div class='scroll'><table id='mtbl'><thead><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead>"
        "<tbody id='msgtbody'>",
        T(S_COL_NUM), T(S_COL_TIME), T(S_COL_RSSI), T(S_COL_LENGTH), T(S_COL_TYPE), T(S_COL_PREVIEW));
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

        char detail[320];
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

        char row[768];
        HTML_PRINTF(row,
            "<tr><td>%zu</td><td>%s</td><td>%s</td><td>%lu</td>"
            "<td class='wrapcell'>%s</td><td class='wrapcell'>%s</td></tr>",
            n + 1, clock, rssi_str, (unsigned long)e->length, typeesc, detail);
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
        "h+='<tr><td>'+(i+1)+'</td><td>'+m.t+'</td><td>'+m.r+'</td><td>'+m.l+'</td><td class=\"wrapcell\">'+ty+'</td><td class=\"wrapcell\">'+m.h+'</td></tr>';}"
        "document.getElementById('msgtbody').innerHTML=h;delay=1000;};"
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
        "<details style='margin:6px 0'>"
        "<summary style='cursor:pointer'><small>%s</small></summary>"
        "<p><small>%s</small></p></details>"
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
        "<div style='margin:8px 0'>"
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
    char labels[1152];
    HTML_PRINTF(labels,
             "<script>var ITS_MAP_L_STREETS=\"%s\",ITS_MAP_L_SAT=\"%s\","
             "ITS_MAP_L_DARK=\"%s\",ITS_MAP_L_LIGHT=\"%s\","
             "ITS_MAP_L_TRACKS=\"%s\",ITS_MAP_L_TRACKS_P=\"%s\","
             "ITS_MAP_TRACK_PTS=\"%s\",ITS_MAP_TRACK_DAYS=%lu,"
             "ITS_MAP_SEEN_BY=\"%s\",ITS_MAP_PEERS=[%s],ITS_MAP_SELF=\"%s\","
             "ITS_PB_NONE=\"%s\",ITS_PB_ERROR=\"%s\",ITS_PB_BUSY=\"%s\","
             "ITS_MAP_DENM=\"%s\","
             "ITS_MAP_STALE=%lu,ITS_MAP_LINE=\"%s\";</script>",
             T(S_MAP_LAYER_STREETS), T(S_MAP_LAYER_SATELLITE),
             T(S_MAP_LAYER_DARK), T(S_MAP_LAYER_LIGHT),
             T(S_MAP_LAYER_TRACKS), T(S_MAP_LAYER_TRACKS_P),
             T(S_MAP_TRACK_PTS), (unsigned long)trkdays,
             T(S_MAP_SEEN_BY), peerjs, selfname,
             T(S_PLAYBACK_NONE), T(S_PLAYBACK_ERROR), T(S_PLAYBACK_BUSY),
             T(S_MAP_DENM),
             (unsigned long)stale, T(S_MAP_LINE));
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
        if (e->has_speed)
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
        char camsuffix[256] = "";
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
    /* Reuses the /ws feed from /messages, also reading its a/o/i keys.
     * Markers are emoji divIcons (no image asset needed), keyed by
     * station_id, evicted after 60s without an update. Initial view guessed
     * from the browser's IANA timezone (Geolocation API needs HTTPS, which
     * this plain-HTTP device doesn't have) -- overridden on first real fix. */
    static const char MAP_SCRIPT[] =
        "<script>(function(){"
        "var TZVIEW={'Europe/Vienna':[47.6,14.5,7],'Europe/Berlin':[51,10.3,6],"
        "'Europe/Zurich':[46.9,8.2,7],'Europe':[50,10,4],'Africa':[2,20,3],"
        "'America':[40,-95,3],'Asia':[30,100,3],'Australia':[-25,135,4],'Pacific':[-20,-140,3]};"
        "var tz='';try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'';}catch(e){}"
        "var g=TZVIEW[tz]||TZVIEW[tz.split('/')[0]]||[20,0,2];"
        "var map=L.map('map').setView([g[0],g[1]],g[2]);"
        "var streets=L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',"
        "{maxZoom:19,attribution:'&copy; OpenStreetMap contributors'});"
        "var sat=L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/"
        "World_Imagery/MapServer/tile/{z}/{y}/{x}',"
        "{maxZoom:19,attribution:'Tiles &copy; Esri'});"
        /* Two CARTO layers alongside OSM and the satellite view. The dark
         * one is what loads by default: the rest of the interface is dark,
         * and the coloured lane and track overlays read far better on it
         * than on the bright street map. Its light, low-contrast sibling is
         * there for daylight. Same external-tile arrangement as the other
         * two already use. */
        "var dark=L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png',"
        "{maxZoom:20,subdomains:'abcd',"
        "attribution:'&copy; OpenStreetMap contributors, &copy; CARTO'}).addTo(map);"
        "var light=L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',"
        "{maxZoom:20,subdomains:'abcd',"
        "attribution:'&copy; OpenStreetMap contributors, &copy; CARTO'});"
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
        /* One shared canvas renderer for every track polyline. The first
         * version created a fresh L.canvas() per line, and Leaflet backs each
         * one with its own <canvas> element sized to the map viewport times
         * device pixel ratio -- a few MB EACH on a retina phone. With a few
         * hundred vehicle tracks that piled up past a gigabyte and mobile
         * Safari killed the tab ("page was reset because it used too much
         * memory"). One renderer shared across all of them uses one canvas
         * no matter how many tracks there are. */
        "var trackRenderer=L.canvas();"
        "var trackLayer=L.layerGroup(),tracksLoaded=false;"
        /* Second overlay for the other receivers' tracks, offered only when
         * any are configured. Deliberately a SEPARATE layer rather than
         * folding them into the one above: both can then be on at once (which
         * is the "all three together" view) or either on its own, with no
         * mutually-exclusive-checkbox trickery. Tracks are drawn per receiver
         * and never merged into one line per vehicle -- /tracks.json carries
         * no timestamps, so points from two receivers could not be ordered
         * against each other, and interleaving them by guess would draw a
         * zigzag that no vehicle ever drove. Two lines for one vehicle is
         * also the more informative picture: it shows where the receivers'
         * ranges overlap. */
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
        "function drawTracks(a,layer,color,who){"
        "for(var i=0;i<a.length;i++){var t=a[i];if(!t.p||t.p.length<2)continue;"
        "var pts=t.p.map(function(q){return [q[0]/1e7,q[1]/1e7];});"
        "var pl=L.polyline(pts,{color:color,weight:2,opacity:0.35,"
        "renderer:trackRenderer});"
        "pl.bindPopup('#'+t.i+' \\u00b7 '+pts.length+' '+ITS_MAP_TRACK_PTS"
        "+(who?'<br><small>'+ITS_MAP_SEEN_BY+' '+htxt(who)+'</small>':''));"
        "pl.addTo(layer);}}"
        "function loadTracks(){tracksLoaded=true;"
        "fetch('/tracks.json?days='+ITS_MAP_TRACK_DAYS,{cache:'no-store'})"
        ".then(function(r){return r.json();}).then(function(a){"
        "trackLayer.clearLayers();drawTracks(a,trackLayer,'#4fb8e0',ITS_MAP_SELF);"
        "}).catch(function(){tracksLoaded=false;});}"
        /* One colour per peer, in the order they are configured, so the same
         * receiver keeps the same colour across reloads. Chosen to stay apart
         * from the local blue and from the amber UI accent. */
        "var PEER_COLORS=['#e07a4f','#7ad07a','#c07ae0','#e0c04f','#4fe0c0'];"
        "function loadPeerTracks(){peerTracksLoaded=true;"
        "peerTrackLayer.clearLayers();"
        "ITS_MAP_PEERS.forEach(function(hp,idx){"
        "fetch('http://'+hp+'/tracks.json?days='+ITS_MAP_TRACK_DAYS,{cache:'no-store'})"
        ".then(function(r){return r.json();}).then(function(a){"
        "drawTracks(a,peerTrackLayer,PEER_COLORS[idx%PEER_COLORS.length],hp);"
        /* A peer that is off or unreachable is skipped silently, exactly like
         * the live marker poll -- one missing receiver must not cost the
         * others their tracks. */
        "}).catch(function(){});});}"
        "var markers={};var VMEM={};var haveView=false;var liveMode=true;"
        "var EMOJI={Ped:'\\ud83d\\udeb6',Cyclist:'\\ud83d\\udeb4',Moped:'\\ud83d\\udef5',"
        "Motorcycle:'\\ud83c\\udfcd',Car:'\\ud83d\\ude97',Bus:'\\ud83d\\ude8c',"
        "LTruck:'\\ud83d\\ude9a',HTruck:'\\ud83d\\ude9b',Trailer:'\\ud83d\\ude9b',"
        "Special:'\\ud83d\\udea7',Tram:'\\ud83d\\ude8a',RSU:'\\ud83d\\udea6'};"
        "function emojiFor(y){for(var k in EMOJI){if(y===k||y.indexOf(k+' ')===0)return EMOJI[k];}return '\\ud83d\\udccd';}"
        /* Heading is drawn as a needle sweeping around the emoji, not by
         * rotating the emoji itself -- a tilted car glyph reads as a
         * rendering fault. A CSS border triangle, deliberately NOT a text
         * arrow: the first attempt used an arrow character sitting at a
         * negative offset outside the icon box, and it never became visible
         * on the device. A triangle inside the box depends on no font and
         * cannot be clipped. `transform-origin` is the box centre, so the
         * needle orbits the marker; 0 deg points north, as headings do. */
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
        "+(d.g[j][3]?d.g[j][3]+' <small>('+d.g[j][0]+')</small>':d.g[j][0])+(d.g[j][2]>=0?' <small>'+d.g[j][2]+'s</small>':'')+'</span>';}return h;}"
        /* Renders the set bits of a BIT STRING as a comma-separated line.
         * Bit 0 is the MSB, hence 1<<(w-1-i). */
        "function bits(v,names,w){if(!v)return '';var o=[];"
        "for(var i=0;i<w;i++)if(v&(1<<(w-1-i)))o.push(names[i]);"
        "return o.length?'<br>'+o.join(', '):'';}"
        "function popupHtml(m){var h='<b>'+(m.y||'?')+'</b><br>'+(m.t||'-')+' &middot; '"
        "+(m.r||'-')+' &middot; '+(m.l||'-')+' B<br>#'+m.i;"
        "if(m.s!==undefined)h+='<br>'+(m.s*0.036).toFixed(1)+' km/h';"
        "if(m.pl)h+='<br><b>'+ITS_MAP_LINE+' '+m.pl+'</b>';"
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
        /* Sparse per-vehicle attributes: only ~40% of a bus's CAMs carry the
         * public-transport container, so without a memory the line number
         * flickers. Held OUTSIDE `markers` on purpose -- seeking backwards in
         * playback destroys and rebuilds markers, which used to wipe it and
         * left the replay showing a line only on the odd frame. `vr` (role)
         * is just as sparse and gets the same treatment. */
        /* Not every CAM carries every field: a car sends its lights in ~75%
         * of messages and its line/role only occasionally, so the popup used
         * to blink them in and out. Remember the last value SEEN per station
         * and fill it back in when a message omits it -- a field only ever
         * changes when the vehicle actually sends a new value for it. */
        "var mem=VMEM[key]||(VMEM[key]={});"
        "['pl','vr','ac','el','hd','vl','vw','dt'].forEach(function(f){"
        "if(m[f]!==undefined)mem[f]=m[f]; else if(mem[f]!==undefined)m[f]=mem[f];});"
        /* Which receivers heard this station, as a set with timestamps. The
         * local feed and each peer arrive as separate updates, so a single
         * field would just be overwritten by whichever landed last -- the
         * local one, once a second. Sources age out on the same staleness
         * rule as the markers themselves. */
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
        "apply(window.ITS_MAP_SEED||[]);"
        /* Named (not anonymous) so playback can pause/resume it -- it uses
         * real Date.now(), meaningless against historical/scrubbed
         * timestamps, so it must not run while replaying the past. */
        "var sweepTimer;"
        "function startSweep(){sweepTimer=setInterval(function(){var now=Date.now();"
        "for(var k in markers){if(now-markers[k].lastSeen>ITS_MAP_STALE*1000){"
        "dropMarker(k);}}},5000);}"
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
        /* Other receivers, merged in from the browser. Markers are keyed by
         * station id, so a vehicle two receivers both hear collapses into one
         * marker on its own -- and where their ranges overlap becomes
         * visible. Failures are ignored silently: a peer being rebooted or
         * off must not disturb the local map. */
        /* One request per peer in flight, never more: against a host that
         * drops packets instead of refusing them, a browser fetch can hang
         * for minutes -- fired again every two seconds, those pile up (and
         * mobile Safari is the first to mind). A peer is simply skipped
         * until its previous request has finished either way. */
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
        "var k=a[i].rg+'/'+a[i].id;PHASE[k]={};"
        "for(var j=0;j<a[i].g.length;j++)PHASE[k][a[i].g[j][0]]=a[i].g[j][1];}"
        "SPAT=m;paintLanes();}).catch(function(){});}"
        "fetchSpat();setInterval(fetchSpat,3000);"
        /* Lane geometry: fetched once (the layout is static), then just
         * recoloured whenever new phases arrive. Ingress lanes take their
         * signal group's colour; lanes without a group stay neutral grey. */
        "var LANES=[],PHASE={};"
        "function paintLanes(){for(var i=0;i<LANES.length;i++){var o=LANES[i];"
        "var ph=(PHASE[o.k]||{})[o.sg];"
        "o.line.setStyle({color:(o.sg<0?'#7a848c':spatColor(ph)),"
        "weight:(o.t==1?3:4),opacity:(o.sg<0?0.5:0.9),dashArray:(o.t==1?'4,4':null)});}}"
        "function loadLanes(){fetch('/lanes.json',{cache:'no-store'})"
        ".then(function(r){return r.json();}).then(function(a){"
        "for(var i=0;i<LANES.length;i++)map.removeLayer(LANES[i].line);LANES=[];"
        "for(var i=0;i<a.length;i++){var X=a[i],k=X.rg+'/'+X.id;"
        /* `ln` deliberately not named L -- that is Leaflet's own global. */
        "for(var j=0;j<X.lanes.length;j++){var ln=X.lanes[j];"
        "var pts=ln.p.map(function(p){return [p[0]/1e7,p[1]/1e7];});"
        "var pl=L.polyline(pts,{color:'#7a848c',weight:4,opacity:0.8}).addTo(map);"
        "pl.bindPopup('Spur '+ln.l+(ln.sg>=0?' \\u00b7 SG '+ln.sg:'')"
        "+(ln.t==1?' \\u00b7 \\u00dcbergang':''));"
        "LANES.push({line:pl,sg:ln.sg,t:ln.t,k:k});}}"
        "paintLanes();}).catch(function(){});}"
        "loadLanes();setInterval(loadLanes,120000);"
        "window.addEventListener('pagehide',function(){closing=true;if(ws)ws.close();});"
        /* Playback: /map/playback returns the same {t,i,a,o,y} shape (plus
         * t=unix seconds) as /ws, so scrubbing just re-derives "current state
         * per station at time T" from the loaded dataset and feeds it
         * through the exact same apply(). */
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
        "fetch('/map/playback?from='+from+'&to='+to).then(function(r){"
        "if(!r.ok)throw new Error('http '+r.status);return r.json();"
        "}).then(function(data){"
        "pbBusy(false);"
        "pbData=data;"
        "if(!pbData.length){msg.textContent=ITS_PB_NONE;return;}"
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
        /* Wired up here (not inline HTML onclick=/oninput=) because those
         * run in the *global* scope, not inside this IIFE -- an inline
         * onclick='pbLoad()' can't see pbLoad at all, since it's private to
         * this closure. This is exactly why nothing happened when clicking
         * Load: a silent "pbLoad is not defined" in the console. */
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
 * [{"i":stationId,"rg":region,"id":id,"rev":n,"age":secs,"g":[[sg,phase],...]}] */
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
        unsigned long age = now > e->last_seen ? (unsigned long)(now - e->last_seen) : 0;
        /* Name is IA5 from the MAPEM and further filtered to printable ASCII
         * by the decoder, but '"' and '\' would still break the JSON string.
         * '<' '>' '&' are dropped too: this string comes off the air from an
         * unauthenticated sender and the map popup renders it as markup
         * (Leaflet bindPopup -> innerHTML). The client escapes it as well
         * (htxt() in MAP_SCRIPT) -- both, because either alone would leave a
         * script-injection path open for any future consumer of this field. */
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
            /* [signalGroup, phase, secondsUntilChange] -- -1 = no timing. */
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
 * [{"rg":43,"id":840,"nm":"...","lanes":[{"l":11,"t":0,"sg":1,"p":[[lat,lon],..]}]}] */
static esp_err_t lanes_json_handler(httpd_req_t *req)
{
    static spatem_intersection_t ints[SPATEM_MAX_INT];
    int ni = spatem_snapshot(ints, SPATEM_MAX_INT);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, "[", HTTPD_RESP_USE_STRLEN);
    bool first = true;
    /* Held for the whole walk: the pointers below aim into buffers the packet
     * path re-decodes in place on a new MAPEM revision. */
    spatem_geometry_lock();
    for (int i = 0; i < ni; i++)
    {
        const its_map_geom_t *g = spatem_geometry(ints[i].region, ints[i].id);
        if (!g)
            continue;
        char head[64];
        snprintf(head, sizeof(head), "%s{\"rg\":%u,\"id\":%u,\"lanes\":[",
                 first ? "" : ",", (unsigned)g->region, (unsigned)g->id);
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);
        first = false;

        /* Separator keys off what was actually emitted, not off the loop
         * index: lanes with fewer than two nodes are skipped, and a skipped
         * lane 0 would otherwise put a leading comma into the array --
         * malformed JSON that kills the lane overlay for ALL intersections,
         * silently (the client's fetch has a bare .catch). */
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
    spatem_geometry_unlock();
    httpd_resp_send_chunk(req, "]", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  GET /map/playback -- historical positions from stored PCAP files  */
/* ================================================================== */

#if CONFIG_ENABLE_SD
/* A stationary RSU broadcasts SPATEM ~10x a second from an unchanging
 * position, so replaying every frame verbatim produced ~9000 identical
 * entries per quarter hour -- megabytes of JSON, each entry its own chunked
 * write, and the browser gave up long before the end. Playback only needs
 * "where was this station at time T", so a station is re-emitted when it has
 * actually moved, and otherwise only occasionally to keep the marker alive. */
#define PB_MAX_STATIONS  96   /* distinct senders tracked; beyond that, no dedup */
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
    /* Entries are accumulated here and flushed in blocks; one chunked write
     * per entry was itself a large part of the 45+ seconds. */
    char buf[2048];
    size_t len;
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

    /* A DENM is an event, not a position sample -- never suppress one. */
    if (d->message_id != 1 && !playback_want(ctx, sec, d))
    {
        ctx->skipped++;
        return true;
    }

    /* Same optional keys as the live /ws feed, so the map's popupHtml renders
     * a replayed marker exactly like a live one. */
    /* MUST be initialised: when a frame carries none of these optional keys
     * (every RSU message, for one), nothing below writes to it, and the
     * uninitialised stack bytes were being printed straight into the JSON.
     * That produced invalid UTF-8 mid-response and made the browser's
     * JSON.parse throw -- i.e. "error loading" on an otherwise fine reply.
     * Worst case with every key set is ~92 bytes. */
    char extra[320] = "";
    size_t eo = 0;
    if (d->has_speed)
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"s\":%ld", (long)d->speed_cmps);
    if (d->veh.valid && d->veh.length_dm && d->veh.width_dm && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"vl\":%u,\"vw\":%u",
                       (unsigned)d->veh.length_dm, (unsigned)d->veh.width_dm);
    if (d->pt_line && eo < sizeof(extra))
        eo += snprintf(extra + eo, sizeof(extra) - eo, ",\"pl\":%u", (unsigned)d->pt_line);
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
    if (ctx->len + (size_t)n >= sizeof(ctx->buf))
    {
        playback_flush(ctx);
        if (ctx->client_gone)
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

/* What a signal group controls, as short text ("geradeaus", "links, rechts",
 * "Fussgaenger"), from the MAPEM lane geometry. Empty when no MAPEM for that
 * intersection has been decoded yet. */
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

/* MovementPhaseState -> short localized phase name (chip hover title). */
static const char *spat_phase_name(uint8_t phase)
{
    switch (phase)
    {
    case 5: case 6:          return T(S_TRF_PH_GREEN);
    case 4: case 7: case 8: case 9: return T(S_TRF_PH_AMBER);
    case 2: case 3:          return T(S_TRF_PH_RED);
    default:                 return T(S_TRF_PH_OTHER);
    }
}

/* Live traffic-light snapshot: one block per intersection, a coloured dot per
 * signal group. Emitted at the top of #trf-body so it refreshes with the page.
 * No-op (nothing rendered) when no SPATEM has been received. */
/* Renders IntersectionStatusObject into a short human sentence. Only the
 * flags a bystander can actually observe are listed, ordered most-notable
 * first: faults, then who is being given priority, then the base operating
 * mode. `alert` reports whether anything abnormal is set, so the caller can
 * colour it. Returns the length written (0 = nothing worth showing). */
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

    char h[96];
    snprintf(h, sizeof(h), "<h2>&#128678; %s</h2>", T(S_TRF_LIGHTS));
    httpd_resp_send_chunk(req, h, HTTPD_RESP_USE_STRLEN);

    if (ni == 0)
    {
        char none[160];
        snprintf(none, sizeof(none), "<p><small>%s</small></p>", T(S_TRF_LIGHTS_NONE));
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
        return;
    }

    /* Explanation + colour legend, so the bare signal-group numbers below
     * aren't cryptic. */
    char legend[1280];
    #define LG_DOT(col) "<span style='display:inline-block;width:11px;height:11px;" \
        "border-radius:50%%;background:" col ";vertical-align:middle;margin:0 4px 0 10px'></span>"
    snprintf(legend, sizeof(legend),
        "<p><small>%s" LG_DOT("#2ecc40") "%s" LG_DOT("#f2b134") "%s"
        LG_DOT("#e74c3c") "%s</small></p>",
        T(S_TRF_LIGHTS_INTRO), T(S_TRF_PH_GREEN), T(S_TRF_PH_AMBER), T(S_TRF_PH_RED));
    #undef LG_DOT
    httpd_resp_send_chunk(req, legend, HTTPD_RESP_USE_STRLEN);

    uint32_t now = (uint32_t)time(NULL);
    for (int i = 0; i < ni; i++)
    {
        spatem_intersection_t *e = &ints[i];
        unsigned long age = now > e->last_seen ? (unsigned long)(now - e->last_seen) : 0;
        char agebuf[24];
        if (current_lang == LANG_DE) snprintf(agebuf, sizeof(agebuf), "vor %lus", age);
        else                         snprintf(agebuf, sizeof(agebuf), "%lus ago", age);

        /* Prefer the MAPEM name ("Kaerntner Strasse - Busgarage"); the numeric
         * id stays visible next to it, just demoted to the detail line. */
        char nameesc[ITS_MAP_NAME_LEN * 6];
        html_escape(e->name, nameesc, sizeof(nameesc));
        /* Sized for the escaped name (up to ITS_MAP_NAME_LEN*6) plus the
         * surrounding markup -- a truncated closing tag here would break the
         * page layout, see the chip-buffer note above. */
        char head[512];
        if (e->name[0])
            snprintf(head, sizeof(head),
                "<p style='margin-bottom:4px'><b>%s %s</b> "
                "<small>(%u/%u &middot; Rev %u &middot; %s)</small></p>"
                "<div style='margin-bottom:10px'>",
                T(S_TRF_INTERSECTION), nameesc, (unsigned)e->region,
                (unsigned)e->id, (unsigned)e->revision, agebuf);
        else
            snprintf(head, sizeof(head),
                "<p style='margin-bottom:4px'><b>%s %u/%u</b> "
                "<small>(Rev %u &middot; %s)</small></p><div style='margin-bottom:10px'>",
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
                "<p style='margin:0 0 6px'><small style='color:%s'>%s%s</small></p>",
                st_alert ? "#e74c3c" : "#94a0a8", st_alert ? "&#9888; " : "", stbuf);
            httpd_resp_send_chunk(req, stline, HTTPD_RESP_USE_STRLEN);
        }

        /* Speed limit and reference lane width, when the MAPEM carried them. */
        if (e->speed_max_kmh || e->lane_width_cm)
        {
            char geo[192], *g = geo;
            size_t left = sizeof(geo);
            int k = snprintf(g, left, "<p style='margin:0 0 6px'><small style='color:#94a0a8'>");
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
            strlcat(geo, "</small></p>", sizeof(geo));
            httpd_resp_send_chunk(req, geo, HTTPD_RESP_USE_STRLEN);
        }

        for (int s = 0; s < e->n; s++)
        {
            /* Generous buffer: the styled chip alone is ~224 bytes, plus the
             * title text -- undersizing this once dropped the closing '>' of
             * </span>, leaving an unclosed span that collapsed the page width. */
            /* Countdown only when the RSU actually sent timing for this
             * group and the deadline hasn't passed. */
            char cd[64] = "";
            if (e->change_at[s] > now && e->change_at[s] - now <= 600)
                snprintf(cd, sizeof(cd), " <small style='color:#94a0a8'>%lus</small>",
                         (unsigned long)(e->change_at[s] - now));

            /* Prefer what the group actually controls over its bare number;
             * the number stays as a small suffix so it can still be matched
             * against the raw SPATEM data. */
            char mv[64];
            spat_movement_text(e, e->sg[s], mv, sizeof(mv));
            char label[160];
            if (mv[0])
                snprintf(label, sizeof(label), "%s <small style='color:#94a0a8'>(%u)</small>",
                         mv, (unsigned)e->sg[s]);
            else
                snprintf(label, sizeof(label), "%u", (unsigned)e->sg[s]);

            char chip[512];
            snprintf(chip, sizeof(chip),
                "<span title='%s' style='display:inline-block;margin:2px 10px 2px 0;white-space:nowrap'>"
                "<span style='display:inline-block;width:13px;height:13px;border-radius:50%%;"
                "background:%s;vertical-align:middle;margin-right:4px'></span>%s%s</span>",
                spat_phase_name(e->phase[s]), spat_phase_color(e->phase[s]),
                label, cd);
            httpd_resp_send_chunk(req, chip, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    }
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

    static EXT_RAM_BSS_ATTR stat_hour_t rows[720];
    int n = tstat_read(hours, rows, 720);   /* oldest-first */

    send_page_header(req, T(S_TITLE_TRAFFIC));

    const char *lc = current_lang == LANG_DE ? "de" : "en";
    char head[768];
    snprintf(head, sizeof(head),
        "<p><small>%s</small></p>"
        "<p>%s: <a href='/traffic?hours=24&lang=%s'>%s</a> &middot; "
        "<a href='/traffic?hours=168&lang=%s'>%s</a> &middot; "
        "<a href='/traffic?hours=720&lang=%s'>%s</a></p>",
        T(S_TRF_INTRO), T(S_TRF_WINDOW),
        lc, T(S_TRF_W_24H), lc, T(S_TRF_W_7D), lc, T(S_TRF_W_30D));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

    /* Everything below the intro/selector is the auto-refreshed fragment. */
    httpd_resp_send_chunk(req, "<div id='trf-body'>", HTTPD_RESP_USE_STRLEN);

    /* Live traffic-light phases first -- independent of the hourly stats, so
     * it shows even right after boot before any hour has accumulated. */
    emit_traffic_lights(req);

    if (n == 0)
    {
        char nd[256];
        snprintf(nd, sizeof(nd), "<div class='warn'>%s</div>", T(S_TRF_NODATA));
        httpd_resp_send_chunk(req, nd, HTTPD_RESP_USE_STRLEN);
        traffic_refresh_footer(req, ri);
        return ESP_OK;
    }

    /* Window totals + per-category speed. */
    uint64_t tot = 0;
    uint64_t wsp_sum[STAT_NCAT] = {0}, wsp_cnt[STAT_NCAT] = {0};
    uint32_t wsp_max[STAT_NCAT] = {0};
    uint32_t max_total = 1;
    for (int i = 0; i < n; i++)
    {
        tot += rows[i].total;
        for (int c = 0; c < STAT_NCAT; c++)
        {
            wsp_sum[c] += rows[i].sp_sum[c];
            wsp_cnt[c] += rows[i].sp_cnt[c];
            if (rows[i].sp_max[c] > wsp_max[c]) wsp_max[c] = rows[i].sp_max[c];
        }
        if (rows[i].total > max_total) max_total = rows[i].total;
    }
    /* Overall speed across all vehicle categories. */
    uint64_t osp_sum = 0, osp_cnt = 0; uint32_t osp_max = 0;
    for (int c = 0; c < STAT_NCAT; c++)
    {
        osp_sum += wsp_sum[c]; osp_cnt += wsp_cnt[c];
        if (wsp_max[c] > osp_max) osp_max = wsp_max[c];
    }

    char summary[512];
    snprintf(summary, sizeof(summary),
        "<div class='cards'>"
        "<div class='card'><div class='l'>%s</div><div class='v'>%llu</div></div>"
        "<div class='card'><div class='l'>%s</div><div class='v'>%lu / %lu</div></div>"
        "</div>",
        T(S_TRF_TOTAL), (unsigned long long)tot,
        T(S_TRF_SPEED), (unsigned long)(osp_cnt ? osp_sum / osp_cnt : 0), (unsigned long)osp_max);
    httpd_resp_send_chunk(req, summary, HTTPD_RESP_USE_STRLEN);

    /* Speed by vehicle type (only categories that actually reported speed). */
    static const int spcats[] = { STAT_CAT_CAR, STAT_CAT_BUS, STAT_CAT_TRUCK, STAT_CAT_TWOWHEEL };
    bool any_speed = false;
    for (unsigned k = 0; k < sizeof(spcats)/sizeof(spcats[0]); k++)
        if (wsp_cnt[spcats[k]] > 0) { any_speed = true; break; }
    if (any_speed)
    {
        char sh[128];
        snprintf(sh, sizeof(sh), "<h3>%s</h3><div class='cards'>", T(S_TRF_SPEED_BY_TYPE));
        httpd_resp_send_chunk(req, sh, HTTPD_RESP_USE_STRLEN);
        for (unsigned k = 0; k < sizeof(spcats)/sizeof(spcats[0]); k++)
        {
            int c = spcats[k];
            if (wsp_cnt[c] == 0) continue;
            char card[192];
            snprintf(card, sizeof(card),
                "<div class='card'><div class='l'>%s</div><div class='v'>%lu / %lu</div></div>",
                trf_cat_label((uint8_t)(c == STAT_CAT_CAR ? 5 : c == STAT_CAT_BUS ? 6 :
                                        c == STAT_CAT_TRUCK ? 7 : 2)),
                (unsigned long)(wsp_sum[c] / wsp_cnt[c]), (unsigned long)wsp_max[c]);
            httpd_resp_send_chunk(req, card, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    }

    /* Per-hour table, newest first, capped for readability (summary above
     * still covers the whole window). */
    httpd_resp_send_chunk(req, "<div class='scroll'><table><tr><th>", HTTPD_RESP_USE_STRLEN);
    char thead[384];
    snprintf(thead, sizeof(thead),
        "%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
        "<th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr>",
        T(S_TRF_HOUR), T(S_TRF_TOTAL), T(S_CAT_CAR), T(S_CAT_BUS), T(S_CAT_TRUCK),
        T(S_CAT_TWOWHEEL), T(S_CAT_PED), T(S_CAT_RSU), T(S_CAT_OTHER), T(S_TRF_SPEED));
    httpd_resp_send_chunk(req, thead, HTTPD_RESP_USE_STRLEN);

    int shown = 0;
    for (int i = n - 1; i >= 0 && shown < 72; i--, shown++)
    {
        stat_hour_t *h = &rows[i];
        time_t t = (time_t)h->hour * 3600;
        struct tm lt;
        localtime_r(&t, &lt);
        char when[24];
        strftime(when, sizeof(when), "%m-%d %H:00", &lt);
        unsigned pct = (unsigned)((uint64_t)h->total * 100 / max_total);

        /* Overall speed for the hour, derived from the per-category fields. */
        uint64_t hsp_sum = 0, hsp_cnt = 0; uint32_t hsp_max = 0;
        for (int c = 0; c < STAT_NCAT; c++)
        {
            hsp_sum += h->sp_sum[c]; hsp_cnt += h->sp_cnt[c];
            if (h->sp_max[c] > hsp_max) hsp_max = h->sp_max[c];
        }

        /* Number first, thin bar on its own line below -- the bar can span the
         * full cell without ever colliding with the count. */
        char row[512];
        snprintf(row, sizeof(row),
            "<tr><td>%s</td>"
            "<td>%lu<div style='height:4px;background:#f2b134;border-radius:2px;"
            "width:%u%%;min-width:2px;margin-top:3px'></div></td>"
            "<td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td><td>%lu</td>"
            "<td>%lu / %lu</td></tr>",
            when, (unsigned long)h->total, pct,
            (unsigned long)h->cat[STAT_CAT_CAR], (unsigned long)h->cat[STAT_CAT_BUS],
            (unsigned long)h->cat[STAT_CAT_TRUCK], (unsigned long)h->cat[STAT_CAT_TWOWHEEL],
            (unsigned long)h->cat[STAT_CAT_PED], (unsigned long)h->cat[STAT_CAT_RSU],
            (unsigned long)h->cat[STAT_CAT_OTHER],
            (unsigned long)(hsp_cnt ? hsp_sum / hsp_cnt : 0), (unsigned long)hsp_max);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "</table></div>", HTTPD_RESP_USE_STRLEN);

    /* --- Warning events (DENM) for the same window, newest first. --- */
    char etitle[64];
    snprintf(etitle, sizeof(etitle), "<h2>%s</h2>", T(S_EVT_TITLE));
    httpd_resp_send_chunk(req, etitle, HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR event_rec_t evs[256];
    int en = events_read(hours, evs, 256);
    if (en == 0)
    {
        char none[192];
        snprintf(none, sizeof(none), "<p><small>%s</small></p>", T(S_EVT_NONE));
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        httpd_resp_send_chunk(req, "<div class='scroll'><table><tr><th>", HTTPD_RESP_USE_STRLEN);
        char eh[160];
        snprintf(eh, sizeof(eh), "%s</th><th>%s</th><th>%s</th></tr>",
                 T(S_EVT_TIME), T(S_EVT_SENDER), T(S_EVT_WARNING));
        httpd_resp_send_chunk(req, eh, HTTPD_RESP_USE_STRLEN);
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
            /* 44 bytes of markup + when[64] + the category label + cause[160];
             * sub-causes pushed `cause` past what 256 could hold. */
            char erow[384];
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
                /* Sub-cause 0 means the sender explicitly said "unavailable".
                 * Showing nothing made that look like a missing feature, so
                 * say it plainly instead -- verified on real traffic: all 25
                 * warnings in one recording carried cause 1, sub-cause 0. */
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
                "<tr><td>%s</td><td>%s</td><td>&#9888; %s</td></tr>",
                when, trf_cat_label(evs[i].station_type), cause);
            httpd_resp_send_chunk(req, erow, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</table></div>", HTTPD_RESP_USE_STRLEN);
    }

    traffic_refresh_footer(req, ri);
    return ESP_OK;
}

/* GET /tracks.json?days=N -- vehicle tracks for the map overlay, grouped by
 * station so each vehicle becomes one polyline. Points come from the small
 * running log, NOT from the PCAP archive: see tracklog.h for why. */
/* GET /markers.json -- the same array the live feed pushes, but as a plain
 * request so ANOTHER receiver's map page can fetch and merge it. Deliberately
 * read by the browser rather than by the peer device: an ESP32 polling its
 * neighbours would need an HTTP client on the box that is already decoding
 * traffic-light messages ten times a second, for no gain when the person
 * looking at the map can reach all of them anyway. */
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

    /* Sized for the MAXIMUM retention (7 days at the measured ~150 points an
     * hour is ~25,000), not the typical case -- at 12,000 this had the same
     * flaw just fixed in the prune: the read stops at the cap, and since the
     * file is chronological, it is the newest tracks that would silently
     * vanish from the map. 26,000 x 20 bytes is 520 KB of PSRAM, transient. */
    const int MAXPT = 26000;
    track_pt_t *pts = heap_caps_malloc(sizeof(track_pt_t) * MAXPT, MALLOC_CAP_SPIRAM);
    if (!pts)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
        return ESP_FAIL;
    }
    int n = tracklog_read(days, pts, MAXPT);

    httpd_resp_set_type(req, "application/json");
    /* Same reasoning as /markers.json: another receiver's map page reads this
     * cross-origin to draw all receivers' tracks on one map. Read-only, no
     * credential involved. */
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_send_chunk(req, "[", HTTPD_RESP_USE_STRLEN);

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
        for (int j = i; j < n && !client_gone; j++)
        {
            if (pts[j].station_id != sid)
                continue;
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
            pts[j].station_id = 0;         /* consumed */
        }
        if (bl && httpd_resp_send_chunk(req, buf, bl) != ESP_OK)
            client_gone = true;
        if (!client_gone &&
            httpd_resp_send_chunk(req, "]}", HTTPD_RESP_USE_STRLEN) != ESP_OK)
            client_gone = true;
    }

    if (!client_gone)
    {
        httpd_resp_send_chunk(req, "]", HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, NULL, 0);
    }
    heap_caps_free(pts);
    return client_gone ? ESP_FAIL : ESP_OK;
}

static esp_err_t playback_get_handler(httpd_req_t *req)
{
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

    /* An unmounted card would otherwise yield an empty array, which the page
     * shows as "no data in this range" -- indistinguishable from a genuinely
     * empty window. This actually misled a diagnosis: queried a minute after
     * a reboot, playback looked broken when the card simply wasn't up yet. */
    if (!sdcard_is_mounted())
    {
        /* This IDF's httpd only defines 500/501/505, so 500 it is -- the
         * point is that the page sees an error instead of an empty array. */
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "SD card not mounted");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, "[", HTTPD_RESP_USE_STRLEN);
    /* ~2.5 KB on the httpd task's 16 KB stack; kept off `static` so two
     * concurrent playback requests can't corrupt each other's state. */
    playback_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.req = req;
    ctx.first = true;
    sdpcap_read_positions(from_sec, to_sec, playback_emit, &ctx);
    playback_flush(&ctx);
    ESP_LOGI(TAG, "playback %lu..%lu: %lu entries, %lu duplicates dropped%s",
             (unsigned long)from_sec, (unsigned long)to_sec,
             (unsigned long)ctx.emitted, (unsigned long)ctx.skipped,
             ctx.client_gone ? " (client gone, aborted)" : "");
    if (ctx.client_gone)
        return ESP_FAIL;   /* socket is dead; closing the chunked reply would only error again */
    httpd_resp_send_chunk(req, "]", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}
#endif

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

    /* Whether a web password is currently set. We never echo the password
     * itself back into the page, only whether one exists. */
    char cur_pw[CONFIG_WEB_PASSWORD_BUFFER_SIZE] = {0};
    size_t cur_pw_size = sizeof(cur_pw);
    bool pw_set = config_get_str(CONFIG_INDEX_WEB_PASSWORD, cur_pw, &cur_pw_size) == ESP_OK
                  && cur_pw_size > 1;

#if CONFIG_ENABLE_SD
    uint8_t log_sys = 0, log_frames = 0;
    uint32_t log_mb = 50;
    config_get_u8(CONFIG_INDEX_LOG_SYS, &log_sys);
    config_get_u8(CONFIG_INDEX_LOG_FRAMES, &log_frames);
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

    uint8_t eth_leds = 1;
    config_get_u8(CONFIG_INDEX_ETH_LEDS, &eth_leds);

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
    snprintf(intro, sizeof(intro), "<p>%s</p>", T(S_SET_INTRO));
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);

    /* Each section is its own chunk, same multi-chunk pattern as
     * render_activity_stats; EXT_RAM_BSS_ATTR/static keeps them off the
     * httpd task's stack. */

    /* --- General: identity, sniffer filtering, LED, UI refresh --- */
    static EXT_RAM_BSS_ATTR char general[4096];
    HTML_PRINTF(general,
        "<h2>%s</h2><table class='kv'>"
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
        "</table>",
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
        T(S_PEERS), peers_esc, T(S_PEERS_HINT));
    httpd_resp_send_chunk(req, general, HTTPD_RESP_USE_STRLEN);

    /* --- Network --- */
    static EXT_RAM_BSS_ATTR char network[4096];
    snprintf(network, sizeof(network),
        "<h2>%s</h2><table class='kv'>"
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
        "<tr><th>%s</th><td><input type='checkbox' id='ethleds'%s>"
        "<br><small>%s</small></td></tr>"
        "</table>",
        T(S_SET_GROUP_NETWORK),
        cur_line,
        T(S_ETH_DHCP), dhcp ? " checked" : "",
        T(S_ETH_IP), ethip,
        T(S_ETH_NETMASK), ethnm,
        T(S_ETH_GATEWAY), ethgw,
        T(S_ETH_DNS), ethdns0, ethdns1, ethdns2,
        T(S_ETH_NET_NOTE),
        T(S_NTP_SERVER), ntp_server,
        T(S_ETH_LEDS), eth_leds ? " checked" : "", T(S_ETH_LEDS_HINT));
    httpd_resp_send_chunk(req, network, HTTPD_RESP_USE_STRLEN);

    /* --- MQTT --- */
    static EXT_RAM_BSS_ATTR char mqtt_block[2048];
    snprintf(mqtt_block, sizeof(mqtt_block),
        "<h2>%s</h2><table class='kv'>"
        "<tr><th>%s</th><td><input id='mqtturi' value='%s' size='16'></td></tr>"
        "</table>",
        T(S_SET_GROUP_MQTT), T(S_MQTT_URI), mqtt_uri);
    httpd_resp_send_chunk(req, mqtt_block, HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD
    /* --- Storage (SD): logging + PCAP capture --- */
    static EXT_RAM_BSS_ATTR char storage[3072];
    HTML_PRINTF(storage,
        "<h2>%s</h2><table class='kv'>"
        "<tr><th>%s</th><td><input type='checkbox' id='logsys'%s></td></tr>"
        "<tr><th>%s</th><td><input type='checkbox' id='logframes'%s></td></tr>"
        "<tr><th>%s</th><td><input id='logmaxmb' type='number' min='1' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th>%s</th><td><input type='checkbox' id='pcapen'%s></td></tr>"
        "<tr><th>%s</th><td><input id='pcaphours' type='number' min='1' max='720' value='%lu' size='6'></td></tr>"
        "<tr><th>%s</th><td><input id='pcapmaxmb' type='number' min='1' value='%lu' size='6'>"
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
        "</table>",
        T(S_SET_GROUP_STORAGE),
        T(S_LOG_SYS), log_sys ? " checked" : "",
        T(S_LOG_FRAMES), log_frames ? " checked" : "",
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
        "<h2>%s</h2><table class='kv'>"
        "<tr><th>%s</th><td><input id='statsdays' type='number' min='1' max='30' value='%lu' size='6'></td></tr>"
        "<tr><th>%s</th><td><input id='eventdays' type='number' min='1' max='30' value='%lu' size='6'></td></tr>"
        "</table>",
        T(S_SET_GROUP_TRAFFIC),
        T(S_STATS_RETAIN_DAYS), (unsigned long)stats_days,
        T(S_EVENT_RETAIN_DAYS), (unsigned long)event_days);
    httpd_resp_send_chunk(req, trfset, HTTPD_RESP_USE_STRLEN);
#endif

    /* --- Security --- */
    static EXT_RAM_BSS_ATTR char security[1024];
    snprintf(security, sizeof(security),
        "<h2>%s</h2><table class='kv'>"
        "<tr><th>%s</th><td>"
        "<input type='password' id='webpasswd' size='16' autocomplete='new-password'>"
        "<br><small>%s</small>"
        "<br><label><input type='checkbox' id='webpwclear'> %s</label>"
        "</td></tr>"
        "</table>",
        T(S_SET_GROUP_SECURITY),
        T(S_WEB_PASSWORD),
        pw_set ? T(S_WEB_PASSWORD_SET) : T(S_WEB_PASSWORD_NONE),
        T(S_WEB_PASSWORD_CLEAR));
    httpd_resp_send_chunk(req, security, HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR char save_block[4096];
    HTML_PRINTF(save_block,
        "<p><button onclick=\"save()\">%s</button> <span id='result'></span></p>"
        /* The page is long enough that changing one field near the top meant
         * scrolling all the way down to save. This bar appears as soon as
         * anything is edited and stays within reach; it also doubles as the
         * "you have unsaved changes" indicator, which the page had no way of
         * showing before. The button at the top of this block stays, so the
         * familiar way still works. */
        "<style>#savebar{position:fixed;left:0;right:0;bottom:0;z-index:900;"
        "display:none;padding:10px clamp(14px,4vw,32px);"
        "background:rgba(21,25,29,.96);border-top:1px solid #2a2f34;"
        "box-shadow:0 -4px 20px rgba(0,0,0,.45)}"
        "#savebar .in{max-width:1400px;margin:0 auto;display:flex;"
        "align-items:center;gap:12px;flex-wrap:wrap}"
        "#savebar small{color:#f2b134}"
        "body.dirty{padding-bottom:64px}</style>"
        "<div id='savebar'><div class='in'><button onclick=\"save()\">%s</button>"
        "<small>%s</small> <span id='result2'></span></div></div>"
        "<script>"
        "function save(){"
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
        "p.append('ntpserver',document.getElementById('ntpserver').value);"
        "p.append('webpasswd',document.getElementById('webpasswd').value);"
        "if(document.getElementById('webpwclear').checked)p.append('webpwclear','1');"
#if CONFIG_ENABLE_SD
        "p.append('logsys',document.getElementById('logsys').checked?'1':'0');"
        "p.append('logframes',document.getElementById('logframes').checked?'1':'0');"
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
        "p.append('ethleds',document.getElementById('ethleds').checked?'1':'0');"
        "fetch('/settings?lang=%s',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:p.toString()})"
        ".then(r=>r.text()).then(t=>{document.getElementById('result').innerText=t;"
        "var r2=document.getElementById('result2');if(r2)r2.innerText=t;"
        "markClean();});"
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
        T(S_SAVE), T(S_SAVE), T(S_UNSAVED), lc);
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
        if (s <= 3600 && config_set_u32(CONFIG_INDEX_REFRESH_SEC, (uint32_t)s) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapfilt", value, sizeof(value)) == ESP_OK)
    {
        unsigned long m = strtoul(value, NULL, 10);
        if (m <= 2 && config_set_u8(CONFIG_INDEX_PCAP_FILTER, (uint8_t)m) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "trkon", value, sizeof(value)) == ESP_OK)
    {
        if (config_set_u8(CONFIG_INDEX_TRACKS_ENABLE,
                          value[0] == '1' ? 1 : 0) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "trkdays", value, sizeof(value)) == ESP_OK)
    {
        unsigned long d = strtoul(value, NULL, 10);
        if (d >= 1 && d <= 7 &&
            config_set_u32(CONFIG_INDEX_TRACKS_DAYS, (uint32_t)d) == ESP_OK) saved++;
    }
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
    if (httpd_query_key_value(buf, "peers", value, sizeof(value)) == ESP_OK)
    {
        url_decode(value);
        if (config_set_str(CONFIG_INDEX_PEERS, value) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "mapstale", value, sizeof(value)) == ESP_OK)
    {
        unsigned long s = strtoul(value, NULL, 10);
        if (s >= 10 && s <= 3600 &&
            config_set_u32(CONFIG_INDEX_MAP_STALE_SEC, (uint32_t)s) == ESP_OK) saved++;
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
    if (httpd_query_key_value(buf, "logframes", value, sizeof(value)) == ESP_OK)
    {
        if (config_set_u8(CONFIG_INDEX_LOG_FRAMES, strcmp(value, "1") == 0 ? 1 : 0) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "logmaxmb", value, sizeof(value)) == ESP_OK)
    {
        unsigned long mb = strtoul(value, NULL, 10);
        if (mb >= 1 && mb <= 100000 &&
            config_set_u32(CONFIG_INDEX_LOG_MAX_MB, (uint32_t)mb) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapen", value, sizeof(value)) == ESP_OK)
    {
        if (config_set_u8(CONFIG_INDEX_PCAP_ENABLE, strcmp(value, "1") == 0 ? 1 : 0) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcaphours", value, sizeof(value)) == ESP_OK)
    {
        unsigned long h = strtoul(value, NULL, 10);
        if (h >= 1 && h <= 720 &&
            config_set_u32(CONFIG_INDEX_PCAP_RETAIN_HOURS, (uint32_t)h) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapbufmb", value, sizeof(value)) == ESP_OK)
    {
        unsigned long mb = strtoul(value, NULL, 10);
        if (mb >= 1 && mb <= 4 &&
            config_set_u32(CONFIG_INDEX_PCAP_BUF_MB, (uint32_t)mb) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapflushsec", value, sizeof(value)) == ESP_OK)
    {
        unsigned long s = strtoul(value, NULL, 10);
        if (s >= 8 && s <= 3600 &&
            config_set_u32(CONFIG_INDEX_PCAP_FLUSH_SEC, (uint32_t)s) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "pcapmaxmb", value, sizeof(value)) == ESP_OK)
    {
        unsigned long mb = strtoul(value, NULL, 10);
        if (mb >= 1 && mb <= 100000 &&
            config_set_u32(CONFIG_INDEX_PCAP_MAX_MB, (uint32_t)mb) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "statsdays", value, sizeof(value)) == ESP_OK)
    {
        unsigned long d = strtoul(value, NULL, 10);
        if (d >= 1 && d <= 30 &&
            config_set_u32(CONFIG_INDEX_STATS_RETAIN_DAYS, (uint32_t)d) == ESP_OK) saved++;
    }
    if (httpd_query_key_value(buf, "eventdays", value, sizeof(value)) == ESP_OK)
    {
        unsigned long d = strtoul(value, NULL, 10);
        if (d >= 1 && d <= 30 &&
            config_set_u32(CONFIG_INDEX_EVENT_RETAIN_DAYS, (uint32_t)d) == ESP_OK) saved++;
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
            }
        }
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
    /* Before the restart, not after the reply: esp_restart() is as abrupt for
     * the SD card as pulling the plug, so without this a reboot silently
     * discards whatever the PCAP ring had not written yet (minutes of it). */
    sysmon_flush_persistent();
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "Rebooting...");
    esp_timer_start_once(reboot_timer_handle, 1000000);
    return ESP_OK;
}

/* POST /poweroff -- makes pulling the plug safe. There is no real "shutdown"
 * on this hardware: /reboot just calls esp_restart(), which is exactly as
 * abrupt for the card as cutting power. What actually costs data is the
 * buffering -- the PCAP ring holds minutes of capture in PSRAM between
 * scheduled flushes -- and a power cut landing inside an SD write.
 *
 * So this writes every buffer out and unmounts the card, after which nothing
 * touches the SD bus again until the device is restarted. Runs inline rather
 * than on a timer: the reply is the operator's signal that it is safe to
 * unplug, so it must not come back before the work is actually done.
 * Recording does NOT resume by itself afterwards -- that is the point, and
 * the confirm dialog says so. */
#if CONFIG_ENABLE_SD
static esp_err_t poweroff_post_handler(httpd_req_t *req)
{
    resolve_language(req);

    /* Same flush the restart paths use, plus the unmount that only makes
     * sense when nothing is going to run afterwards. */
    sysmon_flush_persistent();

    esp_err_t err = sdcard_unmount();
    bool ok = (err == ESP_OK);
    ESP_LOGW(TAG, "prepare-for-power-off: unmount %s",
             ok ? "ok" : esp_err_to_name(err));

    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, ok ? T(S_POWEROFF_OK) : T(S_POWEROFF_FAIL));
    return ok ? ESP_OK : ESP_FAIL;
}
#endif

static esp_err_t confirm_post_handler(httpd_req_t *req)
{
    resolve_language(req);
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
        "\"display\":\"standalone\",\"background_color\":\"#0c1013\","
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

/* Same auth model as reboot_post_handler -- /system itself is unauthenticated,
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

/* Builds the per-task CPU-load rows (no <table>/header wrapper) shared by
 * the initial /system render and /system.json. Two snapshots ~300 ms apart
 * give the *current* load (delta), which is wrap-safe unlike a cumulative
 * since-boot counter. Task names come from our own FreeRTOS task creation
 * calls, not attacker input, but html_escape() still strips quotes so the
 * result is also safe to embed as a JSON string value with no extra
 * escaping (same reasoning as build_msg_json). */
static void build_task_rows_html(char *out, size_t out_size)
{
    out[0] = '\0';
    size_t o = 0;

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

        for (UBaseType_t i = 0; i < c2 && o < out_size; i++)
        {
            uint32_t prev = 0;
            for (UBaseType_t j = 0; j < c1; j++)
                if (a1[j].xHandle == a2[i].xHandle) { prev = a1[j].ulRunTimeCounter; break; }
            uint32_t delta = a2[i].ulRunTimeCounter - prev;
            unsigned cpu_x10 = total_delta ? (unsigned)(((uint64_t)delta * 1000) / total_delta) : 0;

            char nameesc[48];
            html_escape(a2[i].pcTaskName, nameesc, sizeof(nameesc));
            o += snprintf(out + o, out_size - o,
                "<tr><td>%s</td><td>%s</td><td>%u</td><td>%u.%u</td><td>%u</td></tr>",
                nameesc, task_state_str(a2[i].eCurrentState),
                (unsigned)a2[i].uxCurrentPriority,
                cpu_x10 / 10, cpu_x10 % 10,
                (unsigned)a2[i].usStackHighWaterMark);
        }
    }
    free(a1);
    free(a2);
}

static esp_err_t system_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    send_page_header_refresh(req, T(S_TITLE_SYSTEM), "/system.json");

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
            "<button onclick=\"if(confirm('%s'))fetch('/system/coredump/clear',{method:'POST'}).then(()=>location.reload());\">%s</button>"
            "</div>",
            T(S_SYS_COREDUMP), detail, T(S_SYS_COREDUMP_DOWNLOAD),
            T(S_SYS_COREDUMP_CLEAR_CONFIRM), T(S_SYS_COREDUMP_CLEAR));
        httpd_resp_send_chunk(req, banner, HTTPD_RESP_USE_STRLEN);
    }

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

    char info[1792];
    snprintf(info, sizeof(info),
        "<table class='kv'>"
        "<tr><th>%s</th><td>%s rev %d, %s</td></tr>"
        "<tr><th>%s</th><td>%d</td></tr>"
        "<tr><th>%s</th><td>%d MHz</td></tr>"
        "<tr><th>%s</th><td>%s (IDF %s, %s %s)</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td id='sys-uptime'>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s (%s)</th><td id='sys-ram-i'>%s / %s / %s</td></tr>"
        "<tr><th>%s (%s)</th><td id='sys-ram-p'>%s / %s / %s</td></tr>"
        "</table>",
        T(S_SYS_CHIP), CONFIG_IDF_TARGET, chip.revision, feat,
        T(S_SYS_CORES), chip.cores,
        T(S_SYS_CPU_FREQ), CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        T(S_FW_VERSION), app->version, app->idf_ver, app->date, app->time,
        T(S_SYS_IDF), esp_get_idf_version(),
        T(S_SYS_RESET), reset_reason_str(esp_reset_reason()),
        T(S_UPTIME), uptime_str,
        T(S_ETH_IP), eth_line,
        T(S_SYS_RAM_INT), T(S_SYS_TRIPLE), ri_f, ri_m, ri_t,
        T(S_SYS_RAM_PSRAM), T(S_SYS_TRIPLE), rp_f, rp_m, rp_t);
    httpd_resp_send_chunk(req, info, HTTPD_RESP_USE_STRLEN);

    /* Stability counters (NVS-persisted, survive crash + power loss). */
    char maxup_str[48];
    format_uptime(sysstat_max_uptime_sec(), maxup_str, sizeof(maxup_str));
    char lastcrash_str[64];
    int64_t lc = sysstat_last_crash_time();
    if (lc > 0)
    {
        struct timeval now;
        gettimeofday(&now, NULL);
        int64_t ago = now.tv_sec - lc;
        char ago_str[48];
        format_uptime(ago > 0 ? (uint64_t)ago : 0, ago_str, sizeof(ago_str));
        snprintf(lastcrash_str, sizeof(lastcrash_str), "%s %s",
                 current_lang == LANG_DE ? "vor" : "", ago_str);
    }
    else
    {
        snprintf(lastcrash_str, sizeof(lastcrash_str), "%s", T(S_STAT_NEVER));
    }

    char stats[512];
    snprintf(stats, sizeof(stats),
        "<table class='kv'>"
        "<tr><th>%s</th><td>%lu</td></tr>"
        "<tr><th>%s</th><td>%lu</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "</table>",
        T(S_STAT_BOOTS),    (unsigned long)sysstat_boot_count(),
        T(S_STAT_CRASHES),  (unsigned long)sysstat_crash_count(),
        T(S_STAT_LASTCRASH), lastcrash_str,
        T(S_STAT_MAXUP),    maxup_str);
    httpd_resp_send_chunk(req, stats, HTTPD_RESP_USE_STRLEN);

    char statsbtn[384];
    snprintf(statsbtn, sizeof(statsbtn),
        "<p><button onclick=\"if(confirm('%s'))fetch('/system/stats/clear',{method:'POST'}).then(()=>location.reload());\">%s</button></p>",
        T(S_STAT_RESET_CONFIRM), T(S_STAT_RESET));
    httpd_resp_send_chunk(req, statsbtn, HTTPD_RESP_USE_STRLEN);

    char taskhdr[64];
    snprintf(taskhdr, sizeof(taskhdr), "<h2>%s</h2>", T(S_SYS_TASKS));
    httpd_resp_send_chunk(req, taskhdr, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req,
        "<div class='scroll'><table><tr><th>Task</th><th>", HTTPD_RESP_USE_STRLEN);
    char hdr[128];
    snprintf(hdr, sizeof(hdr), "%s</th><th>%s</th><th>%s</th><th>%s</th></tr><tbody id='sys-tasks'>",
             T(S_SYS_COL_STATE), T(S_SYS_COL_PRIO), T(S_SYS_COL_CPU), T(S_SYS_COL_STACK));
    httpd_resp_send_chunk(req, hdr, HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR char task_rows[16384];
    build_task_rows_html(task_rows, sizeof(task_rows));
    httpd_resp_send_chunk(req, task_rows, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

    /* Applies a /system.json response -- uptime/RAM as plain text, the task
     * table as a pre-rendered HTML fragment (same rows build_task_rows_html
     * already produces for the initial page, just re-sent via innerHTML so
     * the row set can grow/shrink too, not just the numbers in place). */
    httpd_resp_send_chunk(req,
        "<script>window.arApply=function(d){"
        "document.getElementById('sys-uptime').textContent=d.uptime;"
        "document.getElementById('sys-ram-i').textContent=d.ram_i;"
        "document.getElementById('sys-ram-p').textContent=d.ram_p;"
        "document.getElementById('sys-tasks').innerHTML=d.tasks_html;"
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
    build_task_rows_html(task_rows, sizeof(task_rows));

    static EXT_RAM_BSS_ATTR char json[17408];
    snprintf(json, sizeof(json),
        "{\"uptime\":\"%s\",\"ram_i\":\"%s / %s / %s\",\"ram_p\":\"%s / %s / %s\",\"tasks_html\":\"%s\"}",
        uptime_str, ri_f, ri_m, ri_t, rp_f, rp_m, rp_t, task_rows);
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
    "<p>%s</p>"
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
    /* Upload done, device now writing flash -- and this is where nearly all
     * the waiting happens. onprogress measures what the browser handed to
     * the network stack, not what the device has processed, so over a LAN it
     * reaches 100%% almost at once and then falls silent. The bar therefore
     * switches to an indeterminate stripe and says what is going on; an
     * earlier version left this phase blank, which read as a freeze. */
    "xhr.upload.onload=function(){bar.style.width='100%%';bar.className='busy';"
    "pct.textContent='%s';};"
    "xhr.onload=function(){b.disabled=false;b.style.opacity=1;"
    "bar.className='';pct.textContent='';"
    "document.getElementById('result').innerText=xhr.responseText;"
    "if(xhr.status===200)waitBack();};"
    /* The device reboots a moment after answering, and the page used to sit
     * there unchanged forever -- nothing told the reader when it was safe to
     * carry on. Poll a tiny static asset until it answers again, then go
     * back to the status page. The first poll is delayed: right after the
     * reply the device is still up, and an immediate success would "detect"
     * a reboot that has not happened yet. */
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
    "</script>";

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
    snprintf(hdr, sizeof(hdr),
        "<h2>%s</h2><p>%s</p><div class='scroll'><table><tr><th>%s</th><th>Typ</th><th>%s</th><th></th></tr>",
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
    httpd_resp_send_chunk(req, "</table></div>", HTTPD_RESP_USE_STRLEN);
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
    char sdhdr[64];
    snprintf(sdhdr, sizeof(sdhdr), "<h2>%s</h2>", T(S_FS_SDCARD));
    httpd_resp_send_chunk(req, sdhdr, HTTPD_RESP_USE_STRLEN);

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

    /* These scratch buffers are large; keeping them on the stack overflowed the
     * single httpd task. esp_http_server handles requests sequentially in one
     * task, so 'static' (off-stack, one instance) is safe here. EXT_RAM_BSS_ATTR
     * places them in PSRAM .bss to spare the scarce internal SRAM. */
    static EXT_RAM_BSS_ATTR char relenc[SD_PATH_MAX * 3];
    url_encode(rel, relenc, sizeof(relenc));
    /* rel is attacker-controlled (from ?p=) and gets displayed as a path
     * breadcrumb below; escape it so it can't inject HTML/JS. */
    static EXT_RAM_BSS_ATTR char relesc[SD_PATH_MAX * 6];
    html_escape(rel, relesc, sizeof(relesc));

    static EXT_RAM_BSS_ATTR char top[3584];
    snprintf(top, sizeof(top),
        "%s"
        "<p>%s: <input type='file' id='fw'><button onclick='up()'>%s</button> "
        "<span id='ur'></span></p>"
        "<p><button onclick='fmt()'>%s</button> <span id='fr'></span></p>"
        "<p><button onclick='seltar()'>&#8595; %s</button> "
        "<button onclick='seldel()'>%s</button></p>"
        "<p><small>%s</small></p>"
        "<script>"
        "var P='%s';"
        /* P and the paths handed to del() are ALREADY url-encoded server-side
         * (url_encode); running encodeURIComponent over them again turned a
         * space into %2520, and the server -- which decodes exactly once --
         * then looked for a file literally named "my%20file.txt". Only values
         * read raw out of the DOM (the checkbox values in seltar/seldel) still
         * need encoding here. */
        "function up(){var f=document.getElementById('fw').files[0];if(!f){return;}"
        "var x=new XMLHttpRequest();"
        "x.open('POST','/sdcard/upload?p='+P+'&name='+encodeURIComponent(f.name));"
        "x.onload=function(){location.reload();};"
        "document.getElementById('ur').innerText='%s';x.send(f);}"
        "function fmt(){if(!confirm('%s'))return;"
        "var x=new XMLHttpRequest();x.open('POST','/sdcard/format');"
        "x.onload=function(){location.reload();};"
        "document.getElementById('fr').innerText='%s';x.send();}"
        "function del(p){if(!confirm('%s'))return;"
        "var x=new XMLHttpRequest();x.open('POST','/sdcard/delete?p='+p);"
        "x.onload=function(){location.reload();};x.send();}"
        "function selall(c){document.querySelectorAll('.sel').forEach(function(x){x.checked=c.checked;});}"
        "function seltar(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}location.href='/sdcard/tar?sel='+s.join('|');}"
        "function seldel(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}if(!confirm('%s'))return;"
        "var x=new XMLHttpRequest();x.open('POST','/sdcard/delete?sel='+s.join('|'));"
        "x.onload=function(){location.reload();};x.send();}"
        "</script>",
        usage,
        T(S_SD_UP_HERE), T(S_SD_UP_BTN),
        T(S_SD_FORMAT),
        T(S_TAR_SELECTED), T(S_SD_DELETE_SELECTED),
        T(S_TAR_HINT),
        relenc,
        T(S_UPLOADING),
        T(S_SD_FORMAT_CONFIRM), T(S_SD_FORMATTING),
        T(S_SD_DELETE_CONFIRM),
        T(S_TAR_NONE), T(S_TAR_NONE), T(S_SD_DELETE_SEL_CONFIRM));
    httpd_resp_send_chunk(req, top, HTTPD_RESP_USE_STRLEN);

    /* Own (small) chunk: the path breadcrumb is attacker-controlled (?p=), so
     * it is kept separate from the buffer above and always HTML-escaped. */
    static EXT_RAM_BSS_ATTR char breadcrumb[SD_PATH_MAX * 6 + 256];
    snprintf(breadcrumb, sizeof(breadcrumb),
        "<p><b>/%s</b></p><div class='scroll'><table>"
        "<tr><th><input type='checkbox' onclick='selall(this)'></th>"
        "<th>%s</th><th>%s</th><th></th></tr>",
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
            "<tr><td></td><td><a href='/sdcard?p=%s'>%s</a></td><td></td><td></td></tr>",
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

            /* nameesc = display name (escaped); relenc2 = url-encoded path for
             * hrefs; relhtml = escaped raw path for the checkbox value (JS reads
             * it back and url-encodes it for the tar selection). */
            static EXT_RAM_BSS_ATTR char nameesc[256], relenc2[SD_PATH_MAX * 3];
            static EXT_RAM_BSS_ATTR char relhtml[SD_PATH_MAX * 6];
            html_escape(de->d_name, nameesc, sizeof(nameesc));
            url_encode(childrel, relenc2, sizeof(relenc2));
            html_escape(childrel, relhtml, sizeof(relhtml));

            static EXT_RAM_BSS_ATTR char row[SD_PATH_MAX * 14];
            if (is_dir)
            {
                snprintf(row, sizeof(row),
                    "<tr><td><input type='checkbox' class='sel' value='%s'></td>"
                    "<td><a href='/sdcard?p=%s'>%s/</a></td><td></td><td></td></tr>",
                    relhtml, relenc2, nameesc);
            }
            else
            {
                char sz[32];
                format_bytes64((uint64_t)st.st_size, sz, sizeof(sz));
                snprintf(row, sizeof(row),
                    "<tr><td><input type='checkbox' class='sel' value='%s'></td>"
                    "<td><a href='/sdcard/download?p=%s'>%s</a></td><td>%s</td>"
                    "<td><button onclick=\"del('%s')\">%s</button></td></tr>",
                    relhtml, relenc2, nameesc, sz, relenc2, T(S_SD_DELETE));
            }
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        closedir(dir);
    }

    if (entries == 0)
    {
        char row[128];
        snprintf(row, sizeof(row), "<tr><td colspan='4'>%s</td></tr>", T(S_SD_EMPTY));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</table></div>", HTTPD_RESP_USE_STRLEN);
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
    /* A filename must be a single path component. Also reject '"': it's later
     * spliced unescaped into the download's Content-Disposition header value
     * (filename="..."), so a name containing one could break out of that
     * quoted value. FatFs's own name validation likely already rejects '"'
     * at fopen() time, but don't rely solely on that. */
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

/* Deletes `path`, recursing into directories -- plain remove() only does
 * rmdir() on a directory, which fails on any non-empty one (that silently
 * left folders like a reused card's old dashcam directory undeletable).
 *
 * Works on ONE caller-owned buffer (append child name, recurse, truncate):
 * the httpd task's stack is only 16 KB, so a per-level SD_PATH_MAX buffer
 * would be far too expensive. `depth` bounds recursion on a corrupt card. */
static bool sd_rm_tree(char *path, size_t size, int depth)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    if (!S_ISDIR(st.st_mode))
        return remove(path) == 0;
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
            else if (sd_rm_tree(path, size, depth - 1))
                removed++;
            else
                left++;
            path[len] = '\0';
        }
        closedir(d);
        if (left == 0)
            break;
        if (removed == 0)
            return false;
    }
    return rmdir(path) == 0;
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

    /* Bulk path: ?sel=a|b|c, same encoding as /sdcard/tar's ?sel= (percent-
     * encoded '|' folded back first). Directories are removed recursively
     * (see sd_rm_tree); bad paths are silently skipped, best-effort. */
    char query[1024];
    char sel[1024] = "";
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
        char *save = NULL;
        for (char *tok = strtok_r(sel, "|", &save); tok; tok = strtok_r(NULL, "|", &save))
        {
            url_decode(tok);
            if (tok[0] == '\0' || strstr(tok, "..") || has_control_char(tok)) { failed++; continue; }
            char full[SD_PATH_MAX];
            sd_full_path(tok, full, sizeof(full));
            if (!sd_rm_tree(full, sizeof(full), 8)) failed++;
        }
        httpd_resp_sendstr(req, failed == 0 ? "OK" : "Error");
        return failed == 0 ? ESP_OK : ESP_FAIL;
    }

    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)) || rel[0] == '\0')
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }
    char full[SD_PATH_MAX];
    sd_full_path(rel, full, sizeof(full));
    if (sd_rm_tree(full, sizeof(full), 8))
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

    /* Heading, back-link to the overview, and the current-path breadcrumb.
     * rel comes from ?p= (attacker-controlled) → always HTML-escaped. */
    static EXT_RAM_BSS_ATTR char relesc[SD_PATH_MAX * 6];
    html_escape(rel, relesc, sizeof(relesc));
    static EXT_RAM_BSS_ATTR char head[SD_PATH_MAX * 12];
    snprintf(head, sizeof(head),
        "<h2>%s &middot; /data</h2>"
        "<p><a href='/sdcard?lang=%s'>&larr; %s</a></p>"
        "<p><button onclick='seltar()'>&#8595; %s</button></p>"
        "<p><small>%s</small></p>"
        "<script>function selall(c){document.querySelectorAll('.sel').forEach(function(x){x.checked=c.checked;});}"
        "function seltar(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}location.href='/fs/tar?sel='+s.join('|');}</script>"
        "<p><b>/%s</b></p><div class='scroll'><table>"
        "<tr><th><input type='checkbox' onclick='selall(this)'></th>"
        "<th>%s</th><th>%s</th></tr>",
        T(S_FS_INTERNAL), lq, T(S_TITLE_SD),
        T(S_TAR_SELECTED),
        T(S_TAR_HINT),
        T(S_TAR_NONE),
        relesc, T(S_SD_NAME), T(S_SD_SIZE));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

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
            "<tr><td></td><td><a href='/fs?p=%s&amp;lang=%s'>%s</a></td><td></td></tr>",
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
                    "<tr><td><input type='checkbox' class='sel' value='%s'></td>"
                    "<td><a href='/fs?p=%s&amp;lang=%s'>%s/</a></td><td></td></tr>",
                    relhtml, relenc2, lq, nameesc);
            }
            else
            {
                char sz[32];
                format_bytes64((uint64_t)st.st_size, sz, sizeof(sz));
                snprintf(row, sizeof(row),
                    "<tr><td><input type='checkbox' class='sel' value='%s'></td>"
                    "<td><a href='/fs/download?p=%s'>%s</a></td><td>%s</td></tr>",
                    relhtml, relenc2, nameesc, sz);
            }
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        closedir(dir);
    }

    if (entries == 0)
    {
        char row[128];
        snprintf(row, sizeof(row), "<tr><td colspan='3'>%s</td></tr>", T(S_SD_EMPTY));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</table></div>", HTTPD_RESP_USE_STRLEN);
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

    char query[1024];
    char sel[1024] = "";
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
    if (!sdcard_is_mounted())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    return tar_download(req, sdcard_mount_point());
}

static esp_err_t internal_tar_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    return tar_download(req, DATA_MOUNT);
}

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

/* Streams the tail of a log file into the page, HTML-escaped.
 *
 * Line-based rather than fixed-size chunks: the millisecond trim below has to
 * see a whole timestamp, and a 512-byte read boundary can fall right inside
 * one. The date is not added per line on purpose -- the system log already
 * carries "===== YYYY-MM-DD (Day) =====" markers at each session start and
 * midnight rollover, which pin a multi-day log to a calendar day without
 * repeating the date on every single line. */
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

    /* Which log: ?file=frames selects the frame CSV, otherwise the system log. */
    bool frames = false;
    char query[64];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char v[16];
        if (httpd_query_key_value(query, "file", v, sizeof(v)) == ESP_OK && strcmp(v, "frames") == 0)
            frames = true;
    }
    const char *path = frames ? CONFIG_SNIFFER_MOUNT_POINT "/logs/frames.csv"
                              : CONFIG_SNIFFER_MOUNT_POINT "/logs/system.log";
    const char *lc = current_lang == LANG_DE ? "de" : "en";

    send_page_header(req, T(S_TITLE_LOGS));

    /* Switcher + refresh links. */
    char nav[512];
    snprintf(nav, sizeof(nav),
        "<p><a href='/logs?file=system&lang=%s'>%s%s%s</a> | "
        "<a href='/logs?file=frames&lang=%s'>%s%s%s</a> | "
        "<a href='/logs?file=%s&lang=%s'>%s</a></p>",
        lc, frames ? "" : "<b>", T(S_LOGS_SYS), frames ? "" : "</b>",
        lc, frames ? "<b>" : "", T(S_LOGS_FRAMES), frames ? "</b>" : "",
        frames ? "frames" : "system", lc, T(S_LOGS_REFRESH));
    httpd_resp_send_chunk(req, nav, HTTPD_RESP_USE_STRLEN);

    FILE *f = fopen(path, "rb");
    if (!f)
    {
        char msg[128];
        snprintf(msg, sizeof(msg), "<p>%s</p>", T(S_LOGS_NONE));
        httpd_resp_send_chunk(req, msg, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, NULL, 0);
        return ESP_OK;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    long start = size > (LOGS_TAIL_KB * 1024) ? size - (LOGS_TAIL_KB * 1024) : 0;

    char note[128];
    httpd_resp_send_chunk(req, "<p><small>", HTTPD_RESP_USE_STRLEN);
    snprintf(note, sizeof(note), T(S_LOGS_TAIL), LOGS_TAIL_KB);
    httpd_resp_send_chunk(req, note, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "</small></p><pre style='white-space:pre-wrap;word-break:break-all;background:#000;padding:1em;border:1px solid #444;max-height:70vh;overflow:auto'>",
                          HTTPD_RESP_USE_STRLEN);

    stream_tail_escaped(req, f, start);
    fclose(f);

    httpd_resp_send_chunk(req, "</pre>", HTTPD_RESP_USE_STRLEN);
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
    /* Same story one layer up: a tab closed without a clean WebSocket close
     * makes every broadcast to that socket warn ("Failed to send WS header").
     * Measured on a day of testing: 823 such lines, all of them describing a
     * browser that had simply gone away -- nothing the device can act on,
     * while crowding real entries out of the SD log. The skip-list in
     * ws_broadcast_work already cuts the retries; this silences the rest.
     * Genuine WebSocket faults still surface, they are logged at E. */
    esp_log_level_set("httpd_ws", ESP_LOG_ERROR);

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
    config.max_uri_handlers = 46; /* 41 routes today, plus a little headroom */
    /* /messages and /map each hold a /ws socket open for as long as the tab
     * is open -- 8 proved too tight once /map existed (accept() failures as
     * dead WS sessions piled up, see the reaping in ws_broadcast_work). */
    config.max_open_sockets = 11;
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
        { .uri = "/spatem.json", .method = HTTP_GET, .handler = spatem_json_handler },
        { .uri = "/lanes.json",  .method = HTTP_GET, .handler = lanes_json_handler },
        { .uri = "/traffic",     .method = HTTP_GET, .handler = traffic_get_handler },
        { .uri = "/leaflet.js",  .method = HTTP_GET, .handler = leaflet_js_get_handler },
        { .uri = "/leaflet.css", .method = HTTP_GET, .handler = leaflet_css_get_handler },
        { .uri = "/favicon*",          .method = HTTP_GET, .handler = favicon_get_handler },
        { .uri = "/apple-touch-icon*", .method = HTTP_GET, .handler = apple_icon_get_handler },
        { .uri = "/icon-192.png",      .method = HTTP_GET, .handler = icon192_get_handler },
        { .uri = "/icon-512.png",      .method = HTTP_GET, .handler = icon512_get_handler },
        { .uri = "/manifest.webmanifest", .method = HTTP_GET, .handler = manifest_get_handler },
#if CONFIG_HTTPD_WS_SUPPORT
        { .uri = "/ws", .method = HTTP_GET, .handler = ws_get_handler, .is_websocket = true },
#endif
#if CONFIG_ENABLE_SD
        { .uri = "/map/playback",    .method = HTTP_GET,  .handler = playback_get_handler },
        { .uri = "/tracks.json",     .method = HTTP_GET,  .handler = tracks_get_handler },
        { .uri = "/markers.json",    .method = HTTP_GET,  .handler = markers_json_handler },
        { .uri = "/sdcard",          .method = HTTP_GET,  .handler = sdcard_get_handler },
        { .uri = "/sdcard/download", .method = HTTP_GET,  .handler = sdcard_download_handler },
        { .uri = "/sdcard/upload",   .method = HTTP_POST, .handler = sdcard_upload_handler },
        { .uri = "/sdcard/delete",   .method = HTTP_POST, .handler = sdcard_delete_handler },
        { .uri = "/sdcard/format",   .method = HTTP_POST, .handler = sdcard_format_handler },
        { .uri = "/sdcard/mount",    .method = HTTP_POST, .handler = sdcard_mount_handler },
        { .uri = "/fs",              .method = HTTP_GET,  .handler = internal_get_handler },
        { .uri = "/fs/download",     .method = HTTP_GET,  .handler = internal_download_handler },
        { .uri = "/fs/part",         .method = HTTP_GET,  .handler = partimg_download_handler },
        { .uri = "/fs/tar",          .method = HTTP_GET,  .handler = internal_tar_handler },
        { .uri = "/sdcard/tar",      .method = HTTP_GET,  .handler = sdcard_tar_handler },
        { .uri = "/logs",            .method = HTTP_GET,  .handler = logs_get_handler },
#endif
    };
    for (size_t i = 0; i < sizeof(uris) / sizeof(uris[0]); i++)
        httpd_register_uri_handler(server, &uris[i]);

    ESP_LOGI(TAG, "Web server started on port %d", config.server_port);
}
