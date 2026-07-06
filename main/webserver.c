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
#if CONFIG_ENABLE_SD
#include "sdcard.h"
#endif
#ifdef CONFIG_ENABLE_TEMPERATURE
#include "temperature.h"
#endif

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
    S_SNIFFER_LABEL, S_SNIFF_START, S_SNIFF_STOP, S_AUTO_REFRESH,
    S_CONFIRM_NEEDED, S_CONFIRM_BTN, S_CONFIRMED, S_CONFIRM_ERROR,
    S_MSG_INTRO, S_COL_NUM, S_COL_TIME, S_COL_RSSI, S_COL_LENGTH, S_COL_PREVIEW,
    S_SET_INTRO, S_MQTT_URI, S_AUTOSTART_CHAN, S_CHAN_NONE,
    S_LED_BRIGHTNESS, S_SAVE, S_SAVED,
    S_WEB_PASSWORD, S_WEB_PASSWORD_SET, S_WEB_PASSWORD_NONE, S_WEB_PASSWORD_CLEAR,
    S_REFRESH_SEC,
    S_ETH_DHCP, S_ETH_IP, S_ETH_NETMASK, S_ETH_GATEWAY, S_ETH_DNS, S_ETH_NET_NOTE,
    S_ETH_CURRENT, S_ETH_CUR_NOT_UP,
    S_NTP_SERVER, S_COL_TYPE, S_ACTIVITY_TITLE, S_ACTIVITY_NONE, S_TYPE_HINT,
    S_LOG_SYS, S_LOG_FRAMES, S_LOG_BUDGET, S_LOG_HINT,
    S_UPD_INTRO, S_UPLOAD, S_UPLOADING, S_UPLOAD_OK, S_UPLOAD_FAIL, S_UPD_CHOOSE_FILE,
    S_UPD_NOT_CONFIRMED,
    S_NAV_SD, S_TITLE_SD, S_FS_PARTITIONS, S_FS_SDCARD, S_FS_USED, S_FS_MOUNT_AT,
    S_FS_INTERNAL, S_FS_NOTE, S_TAR_SELECTED, S_TAR_NONE,
    S_SD_NOT_MOUNTED, S_SD_MOUNT, S_SD_USAGE, S_SD_USED_OF,
    S_SD_NAME, S_SD_SIZE, S_SD_EMPTY, S_SD_PARENT, S_SD_DELETE, S_SD_DELETE_CONFIRM,
    S_SD_FORMAT, S_SD_FORMAT_CONFIRM, S_SD_FORMATTING, S_SD_UP_HERE, S_SD_UP_BTN,
    S_NAV_SYSTEM, S_TITLE_SYSTEM, S_SYS_CHIP, S_SYS_CORES, S_SYS_CPU_FREQ,
    S_SYS_IDF, S_SYS_RESET, S_SYS_FLASH, S_SYS_RAM_INT, S_SYS_RAM_PSRAM,
    S_SYS_TRIPLE, S_SYS_TASKS, S_SYS_COL_STATE, S_SYS_COL_PRIO, S_SYS_COL_CPU,
    S_SYS_COL_STACK,
    S_NAV_LOGS, S_TITLE_LOGS, S_LOGS_SYS, S_LOGS_FRAMES, S_LOGS_REFRESH,
    S_LOGS_NONE, S_LOGS_TAIL,
    S_NAV_MAP, S_TITLE_MAP, S_MAP_HINT, S_MAP_LAYER_STREETS, S_MAP_LAYER_SATELLITE,
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
    /* ESP-IDF refuses to start a new OTA while the running app is still
     * unconfirmed (ESP_ERR_OTA_ROLLBACK_INVALID_STATE) -- by design, so you
     * can't stack unconfirmed updates. Common right after flashing when the
     * confirm step on the status page hasn't happened yet.
     * This string is sent as a plain XHR response body and shown via
     * .innerText (see update_post_handler / UPDATE_FORM_FMT's xhr.onload) --
     * NOT parsed as HTML, so literal UTF-8 umlauts are used here, not
     * &auml;-style entities (those would show up as literal garbage). */
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
    [S_NAV_LOGS]        = { "Logs",                     "Logs" },
    [S_TITLE_LOGS]      = { "Logs",                     "Logs" },
    [S_LOGS_SYS]        = { "System-Log",               "System log" },
    [S_LOGS_FRAMES]     = { "Frame-Log",                "Frame log" },
    [S_LOGS_REFRESH]    = { "Aktualisieren",            "Refresh" },
    [S_LOGS_NONE]       = { "Keine Log-Datei vorhanden (Logging aktiviert? SD eingebunden?).",
                            "No log file yet (logging enabled? SD mounted?)." },
    [S_LOGS_TAIL]       = { "Letzte %d KB, neueste Zeilen unten.",
                            "Last %d KB, newest lines at the bottom." },
    [S_NAV_MAP]         = { "Karte",                    "Map" },
    [S_TITLE_MAP]       = { "Live-Karte",               "Live map" },
    [S_MAP_HINT]        = { "Positionen aus empfangenen CAM-Nachrichten (Fahrzeuge/RSUs), als Symbol je Stationstyp. Anklicken zeigt Details. Marker verschwinden, wenn 60 Sekunden lang nichts mehr von diesem Sender empfangen wurde. Zum Laden der Kartenkacheln braucht der Browser Internetzugang (OpenStreetMap) -- das Gerät selbst nicht.",
                            "Positions from received CAM messages (vehicles/RSUs), shown as an icon per station type. Click a marker for details. Markers disappear after 60 seconds without a new message from that sender. Loading the map tiles needs the browser to have internet access (OpenStreetMap) -- the device itself doesn't." },
    [S_MAP_LAYER_STREETS] = { "Karte",                  "Map" },
    [S_MAP_LAYER_SATELLITE] = { "Satellit",             "Satellite" },
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
#define WEB_MSG_PREVIEW_LEN 32

#define WEB_MSG_TYPE_LEN 32

typedef struct {
    uint32_t seconds;
    uint32_t microseconds;
    uint32_t length;
    uint32_t preview_len;
    int      rssi;
    uint8_t  preview[WEB_MSG_PREVIEW_LEN];
    char     msgtype[WEB_MSG_TYPE_LEN];
    bool     has_position; /* true if lat_e7/lon_e7/station_id below are valid (CAM only) */
    int32_t  lat_e7;       /* WGS84 latitude,  1e-7 degree units */
    int32_t  lon_e7;       /* WGS84 longitude, 1e-7 degree units */
    uint32_t station_id;   /* ItsPduHeader.stationId; stable per sender, only meaningful if has_position */
} web_msg_entry_t;

static web_msg_entry_t msg_ring[WEB_MSG_RING_SIZE];
static size_t msg_ring_head;
static size_t msg_ring_count;
static uint32_t msg_total_count;
static SemaphoreHandle_t msg_ring_mutex;

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
    e->preview_len = packet->length < WEB_MSG_PREVIEW_LEN ? packet->length : WEB_MSG_PREVIEW_LEN;
    memcpy(e->preview, packet->payload, e->preview_len);
    /* Decoded from the full frame (not just the short preview above) -- CAM/
     * DENM's BTP header sits well past WEB_MSG_PREVIEW_LEN bytes in. */
    its_decode_frame(packet->payload, packet->length, e->msgtype, sizeof(e->msgtype),
                      &e->has_position, &e->lat_e7, &e->lon_e7, &e->station_id);
    msg_type_stats_record(e->msgtype);

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
    "<meta name='theme-color' content='#1c56be'>"
    "<meta name='apple-mobile-web-app-capable' content='yes'>"
    "<meta name='apple-mobile-web-app-status-bar-style' content='black-translucent'>"
    "<meta name='apple-mobile-web-app-title' content='ITS G5 Node'>"
    "%s"  /* optional auto-refresh script */
    "<style>"
    "*{box-sizing:border-box}"
    "body{font-family:system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;margin:0;background:#0e1725;color:#e6ebf2;line-height:1.5}"
    ".wrap{width:100%%;max-width:1040px;margin:0 auto;padding:18px clamp(14px,4vw,32px) 48px}"
    "a{color:#5f9bff;text-decoration:none}a:hover{text-decoration:underline}"
    "h1{font-size:20px;font-weight:600;margin:6px 0 16px}"
    "h2{font-size:16px;font-weight:600;margin:22px 0 10px}"
    "h3{font-size:14px;font-weight:600;margin:18px 0 8px;color:#c7d2e0}"
    /* nav itself does NOT wrap -- .navlinks (the page links) wraps onto
     * multiple rows internally instead, while .lang (the flag switch) stays
     * a fixed sibling anchored top-right at all times. Without this split,
     * .lang used to be just another wrappable flex item and would drop onto
     * its own orphaned-looking full-width row on narrow screens once the
     * page links needed more than one row. align-items:flex-start so .lang
     * sits at the TOP of .navlinks' box even when that box grows taller
     * (wrapped to several rows), rather than centering into its middle. */
    "nav{display:flex;align-items:flex-start;gap:8px;padding:5px;background:#131c2a;border:1px solid #26303f;border-radius:11px;margin-bottom:18px;font-size:13px}"
    ".navlinks{display:flex;flex-wrap:wrap;gap:4px;flex:1;min-width:0;align-items:center}"
    "nav a{color:#aeb9c9;padding:6px 12px;border-radius:8px}"
    "nav a:hover{background:#1c2636;text-decoration:none}"
    "nav a.active{background:#2f6fd0;color:#fff}"
    /* Flag toggle: a small pill holding both flags, current language
     * highlighted -- replaces the old plain text link (just the other
     * language's name), which looked like a stray, unstyled afterthought
     * next to the nav pill. */
    "nav .lang{flex-shrink:0;display:flex;gap:2px;background:#0e1725;border-radius:20px;padding:2px;border:1px solid #26303f}"
    "nav .lang a{padding:3px 8px;border-radius:16px;font-size:15px;line-height:1.3;opacity:.5}"
    "nav .lang a:hover{background:#1c2636;text-decoration:none;opacity:.8}"
    "nav .lang a.active{background:#2f6fd0;opacity:1}"
    /* border-collapse:separate (not collapse!) -- browsers ignore
     * border-radius on a <table> when its borders are collapsed, which made
     * plain (non-.scroll) tables look square-cornered despite this rule.
     * border-spacing:0 keeps cells touching, same look as collapse. */
    "table{width:100%%;border-collapse:separate;border-spacing:0;background:#16202e;border:1px solid #26303f;border-radius:12px;margin:10px 0;overflow:hidden}"
    "th,td{text-align:left;padding:10px 14px;font-size:13.5px;border-bottom:1px solid #222c3a}"
    "tr:last-child>*{border-bottom:none}"
    "th{color:#8b98ab;font-weight:400}"
    ".kv th{width:1px;white-space:nowrap;padding-right:32px}.kv td{overflow-wrap:anywhere}"
    ".scroll{overflow-x:auto;border:1px solid #26303f;border-radius:12px;margin:10px 0}"
    ".scroll table{border:none;border-radius:0;margin:0;width:auto;min-width:100%%}"
    ".scroll td,.scroll th{white-space:nowrap}"
    /* Wrappable cells (hex preview, Type -- both can be long, both already
     * break cleanly at spaces/colons) flow onto multiple lines at ANY width:
     * the hex preview alone can be ~100 characters, wide enough to force
     * horizontal scroll even inside the 1040px desktop content column, not
     * just on phones. .scroll's own horizontal scroll remains as a fallback
     * for genuinely wide tables that don't opt into wrapping (system/SD). */
    ".scroll td.wrapcell{white-space:normal;word-break:break-word}"
    /* On narrow screens only: tighten padding, and on the /messages table
     * specifically (#mtbl) drop the "#" column -- it's just the row's
     * position, redundant with reading top-to-bottom, and every column adds
     * its own padding on top of its content width. */
    "@media(max-width:640px){"
    ".scroll th,.scroll td{padding:8px 6px}"
    "#mtbl th:first-child,#mtbl td:first-child{display:none}"
    /* .kv th is nowrap+shrink-to-fit, but that shrinks to the WIDEST label
     * in the WHOLE table (shared column width) -- one long label (e.g.
     * "Web-Passwort (Benutzer ...)") was enough to push that column, and so
     * the whole table, wider than the screen on every row, not just its
     * own. Wrapping it onto 2 lines above this width caps the damage. */
    ".kv th{white-space:normal;max-width:38vw}"
    "}"
    "button{background:#2f6fd0;color:#fff;border:none;font-size:13.5px;padding:9px 15px;border-radius:9px;margin:3px 5px 3px 0;cursor:pointer}"
    "button:hover{background:#3b7de0}"
    "input,select{background:#0e1725;color:#e6ebf2;border:1px solid #38455a;border-radius:8px;padding:7px 9px;font-size:13.5px;max-width:100%%}"
    /* File inputs sit directly before an upload button (/update, file
     * management); on narrow screens where they don't fit on one line, the
     * button wrapped to its own line with NO gap above it, looking stuck to
     * the field. margin-bottom gives that wrapped line some breathing room;
     * harmless when they DO fit side by side (just a little extra space). */
    "input[type=file]{margin:4px 8px 8px 0}"
    ".kv input:not([type=checkbox]):not([type=range]){width:100%%;max-width:360px}"
    /* Range (the LED-brightness slider) was excluded from the rule above and
     * so had NO width constraint at all -- left to the browser's own
     * default intrinsic width, which contributed to the table being wider
     * than necessary in auto layout (every column shares one width across
     * all rows, so an oversized cell in any single row widens the whole
     * column, and the whole table). */
    ".kv input[type=range]{width:100%%;max-width:280px}"
    /* IPv4 fields only ever hold up to "255.255.255.255" (15 chars) -- the
     * generic 360px above is sized for long free-text fields (Node-ID,
     * MQTT-URI) and was too wide for three of these side by side (the DNS
     * row), overflowing the page especially with the wider German labels
     * next to them. !important because the generic rule above is otherwise
     * more specific (two :not() clauses). */
    ".ipfield{max-width:140px!important}"
    ".ok{display:inline-block;color:#5fe0a0;background:#123726;padding:2px 10px;border-radius:20px;font-size:12px}"
    ".bad{display:inline-block;color:#ff8a8a;background:#3a1720;padding:2px 10px;border-radius:20px;font-size:12px}"
    ".warn{background:#3a2e0c;border:1px solid #7a5c12;color:#ffd77a;padding:12px 14px;border-radius:11px;margin:14px 0}"
    "small{color:#8b98ab}"
    ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin:6px 0 4px}"
    ".card{background:#141d2b;border:1px solid #26303f;border-radius:11px;padding:12px 14px}"
    ".card .l{font-size:12px;color:#8b98ab;margin-bottom:3px}.card .v{font-size:22px;font-weight:600}"
    "pre{background:#0b1220;border:1px solid #26303f;border-radius:11px;color:#cfe3ff}"
    "</style><title>ITS G5 Node</title></head><body><div class='wrap'>"
    /* .navlinks is a separate flex item from .lang (see CSS) so the page
     * links can wrap onto multiple rows on narrow screens while the flag
     * switch stays anchored top-right instead of dropping onto its own,
     * disconnected-looking full-width row. */
    "<nav><div class='navlinks'>"
    "<a href='/?lang=%s'>%s</a><a href='/messages?lang=%s'>%s</a>"
    "<a href='/settings?lang=%s'>%s</a><a href='/update?lang=%s'>%s</a>"
    "<a href='/map?lang=%s'>%s</a>"
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

static void send_page_header_refresh(httpd_req_t *req, const char *heading, int refresh_secs)
{
    /* Auto-refresh is JS-based (not a <meta> tag) so a floating button can
     * pause/resume it (persisted per-browser in localStorage) and the interval
     * is configurable (0 = off). ⏸ = pause, ▶ = play. */
    char refresh_tag[768] = "";
    if (refresh_secs > 0)
    {
        uint32_t ri = 5;
        config_get_u32(CONFIG_INDEX_REFRESH_SEC, &ri);
        if (ri > 0 && ri < 0xFFFFFFFF)
            snprintf(refresh_tag, sizeof(refresh_tag),
                "<script>(function(){var ri=%lu;"
                "window.addEventListener('load',function(){"
                "var b=document.createElement('button');"
                "b.style.cssText='position:fixed;bottom:12px;right:12px;z-index:99;opacity:.9;border-radius:4px;box-shadow:0 1px 4px #000';"
                "function u(){b.textContent=(localStorage.getItem('ar')!=='0'?'\\u23f8 ':'\\u25b6 ')+ri+'s';}"
                "b.onclick=function(){var on=localStorage.getItem('ar')==='0';"
                "localStorage.setItem('ar',on?'1':'0');"
                "if(on){location.reload();}else{if(window._t)clearTimeout(window._t);u();}};"
                "u();document.body.appendChild(b);"
                "if(localStorage.getItem('ar')!=='0'){window._t=setTimeout(function(){location.reload();},ri*1000);}"
                "});})();</script>",
                (unsigned long)ri);
    }

    const char *lc = current_lang == LANG_DE ? "de" : "en";
    const char *lang_de_active = (current_lang == LANG_DE) ? "active" : "";
    const char *lang_en_active = (current_lang == LANG_EN) ? "active" : "";

    char header[5120];
    snprintf(header, sizeof(header), PAGE_HEADER_FMT,
             lc, refresh_tag,
             lc, T(S_NAV_STATUS),
             lc, T(S_NAV_MESSAGES),
             lc, T(S_NAV_SETTINGS),
             lc, T(S_NAV_UPDATE),
             lc, T(S_NAV_MAP),
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
    send_page_header_refresh(req, heading, 0);
}

/* Renders the 60-second packet-rate sparkline + per-message-type breakdown
 * shown on the status page under "Activity". Reuses state that already
 * exists (rate_buckets fed by rate_record_packet, msg_type_stats fed by
 * msg_type_stats_record -- both in webserver_handle_packet) rather than
 * adding new counters. Only one channel is ever active at a time (see
 * sniffer_get_channel), so this is framed as activity/signal over time
 * rather than a per-channel breakdown. */
static void render_activity_stats(httpd_req_t *req)
{
    uint64_t now_sec = esp_timer_get_time() / 1000000ull;
    uint32_t counts[RATE_WINDOW_SECS];
    uint32_t maxcount = 1;
    /* rate_buckets[]/msg_type_stats[] are written under msg_ring_mutex (see
     * webserver_handle_packet -> rate_record_packet/msg_type_stats_record),
     * but were previously read here without it -- a label could be observed
     * mid-strlcpy, torn between old and new bytes (harmless since both sides
     * use fixed-size arrays, just a cosmetically wrong/flickering label, but
     * worth doing correctly). Snapshot both under the same lock, then render
     * from the snapshot so the lock isn't held during the (slower) chunked
     * HTTP writes below. */
    static msg_type_stat_t type_snapshot[MSG_TYPE_STATS_SLOTS];
    if (msg_ring_mutex && xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
    {
        for (size_t i = 0; i < RATE_WINDOW_SECS; i++)
        {
            uint64_t sec = now_sec - (RATE_WINDOW_SECS - 1 - i);
            rate_bucket_t *b = &rate_buckets[sec % RATE_WINDOW_SECS];
            counts[i] = (b->sec == sec) ? b->count : 0;
        }
        memcpy(type_snapshot, msg_type_stats, sizeof(type_snapshot));
        xSemaphoreGive(msg_ring_mutex);
    }
    else
    {
        memset(counts, 0, sizeof(counts));
        memset(type_snapshot, 0, sizeof(type_snapshot));
    }
    for (size_t i = 0; i < RATE_WINDOW_SECS; i++)
        if (counts[i] > maxcount) maxcount = counts[i];

    static EXT_RAM_BSS_ATTR char svg[6144];
    size_t o = 0;
    o += snprintf(svg + o, sizeof(svg) - o,
        "<svg viewBox='0 0 %d 40' width='100%%' height='40' preserveAspectRatio='none'>",
        RATE_WINDOW_SECS * 4);
    for (size_t i = 0; i < RATE_WINDOW_SECS && o < sizeof(svg); i++)
    {
        int h = counts[i] ? (int)(4 + (counts[i] * 32) / maxcount) : 1;
        o += snprintf(svg + o, sizeof(svg) - o,
            "<rect x='%d' y='%d' width='3' height='%d' rx='1' fill='#2f6fd0'/>",
            (int)i * 4, 40 - h, h);
    }
    o += snprintf(svg + o, sizeof(svg) - o, "</svg>");

    char typeline[1024] = {0};
    size_t tl = 0;
    for (size_t i = 0; i < MSG_TYPE_STATS_SLOTS; i++)
    {
        if (type_snapshot[i].label[0] == '\0')
            continue;
        char typeesc[WEB_MSG_TYPE_LEN * 6];
        html_escape(type_snapshot[i].label, typeesc, sizeof(typeesc));
        int n = snprintf(typeline + tl, sizeof(typeline) - tl, "%s%s %lu",
            tl ? " &middot; " : "", typeesc, (unsigned long)type_snapshot[i].count);
        if (n > 0 && (size_t)n < sizeof(typeline) - tl)
            tl += (size_t)n;
    }

    /* Sent as separate chunks (title / svg / breakdown) rather than composed
     * into one buffer: svg alone can approach its 6 KiB capacity, and gcc's
     * -Werror=format-truncation assumes that worst case for any %s of a
     * fixed-size array -- concatenating it into another snprintf would need
     * a implausibly large destination just to satisfy the compiler. */
    char title[128];
    snprintf(title, sizeof(title), "<h3>%s</h3>", T(S_ACTIVITY_TITLE));
    httpd_resp_send_chunk(req, title, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, svg, HTTPD_RESP_USE_STRLEN);

    /* typeline (the per-type counts) and the hint are sent as separate chunks
     * so a long breakdown can't crowd out the hint in one fixed buffer. */
    char typeblock[1152];
    snprintf(typeblock, sizeof(typeblock), "<p>%s</p>",
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

    send_page_header_refresh(req, T(S_TITLE_STATUS), 5);

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

    char body[3584];
    snprintf(body, sizeof(body),
        "<div class='cards'>"
        "<div class='card'><div class='l'>%s</div><div class='v'>%lu</div></div>"
        "<div class='card'><div class='l'>%s</div><div class='v'>%lu</div></div>"
        "<div class='card'><div class='l'>%s</div><div class='v'>%s</div></div>"
        "</div>"
        "<table class='kv'>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%02x:%02x:%02x:%02x:%02x:%02x</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td><span class='%s'>%s</span></td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td><span class='%s'>%s</span></td></tr>"
#ifdef CONFIG_ENABLE_TEMPERATURE
        "<tr><th>%s</th><td>%.1f &deg;C</td></tr>"
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

    char buttons[512];
    snprintf(buttons, sizeof(buttons),
        "<p>"
        "<button onclick=\"fetch('/sniffer?action=%s',{method:'POST'}).then(()=>location.reload())\">%s</button> "
        "<button onclick=\"if(confirm('%s'))fetch('/reboot',{method:'POST'}).then(()=>{document.body.innerHTML='<p>%s</p>';})\">%s</button>"
        "</p>",
        running ? "stop" : "start",
        running ? T(S_SNIFF_STOP) : T(S_SNIFF_START),
        T(S_REBOOT_CONFIRM), T(S_REBOOTING), T(S_REBOOT));
    httpd_resp_send_chunk(req, buttons, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
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

/* Same snapshot-then-render shape as messages_get_handler, but as compact
 * JSON for the browser to turn into table rows. Field names are single
 * letters (t/r/l/y/h, plus a/o/i for CAM position -- lAtitude e7, lOngitude
 * e7, station Id) purely to keep the payload small on a 10 Mbit link. a/o/i
 * are only present when a message actually has a decoded position (CAM
 * only), so the common case (no position) costs nothing extra on the wire. */
static size_t build_msg_json(char *out, size_t out_size)
{
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

    size_t o = 0;
    o += snprintf(out + o, out_size - o, "[");
    for (size_t n = 0; n < count && o < out_size; n++)
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

        char possuffix[96] = "";
        if (e->has_position)
            snprintf(possuffix, sizeof(possuffix), ",\"a\":%ld,\"o\":%ld,\"i\":%lu",
                     (long)e->lat_e7, (long)e->lon_e7, (unsigned long)e->station_id);

        /* msgtype/clock/rssi_str/hex only ever contain digits, letters,
         * spaces, ':', '-', '.' (see its_decode_frame/format_clock) --
         * never attacker- or frame-controlled bytes, so no JSON escaping is
         * needed for them. */
        o += snprintf(out + o, o < out_size ? out_size - o : 0,
            "%s{\"t\":\"%s\",\"r\":\"%s\",\"l\":%lu,\"y\":\"%s\",\"h\":\"%s\"%s}",
            n == 0 ? "" : ",", clock, rssi_str, (unsigned long)e->length, e->msgtype, hex, possuffix);
    }
    if (o + 2 <= out_size)
    {
        out[o++] = ']';
        out[o] = '\0';
    }
    return o;
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

    httpd_ws_frame_t frame = { .type = HTTPD_WS_TYPE_TEXT, .payload = (uint8_t *)json, .len = len };
    for (size_t i = 0; i < max_fds; i++)
        if (httpd_ws_get_fd_info(g_httpd_server, client_fds[i]) == HTTPD_WS_CLIENT_WEBSOCKET)
            httpd_ws_send_frame_async(g_httpd_server, client_fds[i], &frame);
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
    snprintf(intro + l, sizeof(intro) - l, T(S_MSG_INTRO), WEB_MSG_RING_SIZE, WEB_MSG_PREVIEW_LEN);
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

        char typeesc[WEB_MSG_TYPE_LEN * 6];
        html_escape(e->msgtype, typeesc, sizeof(typeesc));

        char row[640];
        snprintf(row, sizeof(row),
            "<tr><td>%zu</td><td>%s</td><td>%s</td><td>%lu</td><td class='wrapcell'>%s</td><td class='wrapcell'><code>%s</code></td></tr>",
            n + 1, clock, rssi_str, (unsigned long)e->length, typeesc, hex);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

#if CONFIG_HTTPD_WS_SUPPORT
    /* Reconnects with backoff if the socket drops (e.g. Wi-Fi hiccup on the
     * client, or the device rebooting) -- the static rows above still work
     * without JS/WebSocket, just without the live updates. */
    static const char ws_script[] =
        "<script>(function(){"
        "var delay=1000;"
        "function connect(){"
        "var proto=location.protocol==='https:'?'wss://':'ws://';"
        "var ws=new WebSocket(proto+location.host+'/ws');"
        "ws.onmessage=function(ev){"
        "var d=JSON.parse(ev.data);var h='';"
        "for(var i=0;i<d.length;i++){var m=d[i];"
        "h+='<tr><td>'+(i+1)+'</td><td>'+m.t+'</td><td>'+m.r+'</td><td>'+m.l+'</td><td class=\"wrapcell\">'+m.y+'</td><td class=\"wrapcell\"><code>'+m.h+'</code></td></tr>';}"
        "document.getElementById('msgtbody').innerHTML=h;delay=1000;};"
        "ws.onclose=function(){setTimeout(connect,delay);delay=Math.min(delay*2,30000);};"
        "}"
        "connect();"
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

    char hint[1024];
    snprintf(hint, sizeof(hint),
        "<p><small>%s</small></p>"
        "<link rel='stylesheet' href='/leaflet.css'>"
        "<script src='/leaflet.js'></script>"
        "<style>.its-emoji-icon{font-size:20px;line-height:26px;text-align:center}</style>"
        "<div id='map' style='height:70vh;border-radius:12px;overflow:hidden'></div>",
        T(S_MAP_HINT));
    httpd_resp_send_chunk(req, hint, HTTPD_RESP_USE_STRLEN);

    /* Layer-control labels, the only two localized strings the client script
     * needs -- passed in as JS vars so MAP_SCRIPT below can stay one fixed
     * static string, not a per-request snprintf. */
    char labels[192];
    snprintf(labels, sizeof(labels), "<script>var ITS_MAP_L_STREETS=\"%s\",ITS_MAP_L_SAT=\"%s\";</script>",
             T(S_MAP_LAYER_STREETS), T(S_MAP_LAYER_SATELLITE));
    httpd_resp_send_chunk(req, labels, HTTPD_RESP_USE_STRLEN);

    /* Seed the map from whatever's already in the ring buffer, same
     * snapshot-then-render pattern as messages_get_handler above, so the map
     * isn't empty for up to ~1s waiting for the next /ws tick. msgtype/hex
     * only ever contain digits/letters/spaces/':'/'-'/'.' (see
     * its_decode_frame/format_clock), so it's safe to embed directly in this
     * JS string literal, same as the existing build_msg_json (no
     * attacker-controlled bytes to escape). */
    httpd_resp_send_chunk(req, "<script>var ITS_MAP_SEED=[", HTTPD_RESP_USE_STRLEN);

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
        char entry[224];
        snprintf(entry, sizeof(entry),
                 "%s{\"i\":%lu,\"a\":%ld,\"o\":%ld,\"y\":\"%s\",\"t\":\"%s\",\"r\":\"%s\",\"l\":%lu}",
                 first ? "" : ",", (unsigned long)e->station_id,
                 (long)e->lat_e7, (long)e->lon_e7, e->msgtype, clock, rssi_str,
                 (unsigned long)e->length);
        httpd_resp_send_chunk(req, entry, HTTPD_RESP_USE_STRLEN);
        first = false;
    }
    httpd_resp_send_chunk(req, "];</script>", HTTPD_RESP_USE_STRLEN);

#if CONFIG_HTTPD_WS_SUPPORT
    /* Reuses the exact same /ws feed and JSON shape as /messages -- this
     * script just also reads the a/o/i keys that /messages ignores. Markers
     * are L.marker with a divIcon (an emoji glyph, per station type) rather
     * than an image -- no marker-icon asset needed, and richer than a plain
     * dot. bindPopup() makes them clickable, showing whatever fields exist.
     * Keyed by station_id so a given vehicle's marker moves rather than
     * accumulating; swept every 5s, evicted after 60s without an update.
     * Initial view is guessed from the browser's IANA timezone (works over
     * plain HTTP; the Geolocation API needs HTTPS/localhost, which this
     * device's plain-HTTP LAN address doesn't satisfy) -- overridden as soon
     * as a real position arrives (first fix recenters once, see haveView). */
    static const char MAP_SCRIPT[] =
        "<script>(function(){"
        "var TZVIEW={'Europe/Vienna':[47.6,14.5,7],'Europe/Berlin':[51,10.3,6],"
        "'Europe/Zurich':[46.9,8.2,7],'Europe':[50,10,4],'Africa':[2,20,3],"
        "'America':[40,-95,3],'Asia':[30,100,3],'Australia':[-25,135,4],'Pacific':[-20,-140,3]};"
        "var tz='';try{tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'';}catch(e){}"
        "var g=TZVIEW[tz]||TZVIEW[tz.split('/')[0]]||[20,0,2];"
        "var map=L.map('map').setView([g[0],g[1]],g[2]);"
        "var streets=L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png',"
        "{maxZoom:19,attribution:'&copy; OpenStreetMap contributors'}).addTo(map);"
        "var sat=L.tileLayer('https://server.arcgisonline.com/ArcGIS/rest/services/"
        "World_Imagery/MapServer/tile/{z}/{y}/{x}',"
        "{maxZoom:19,attribution:'Tiles &copy; Esri'});"
        "var baseLayers={};baseLayers[ITS_MAP_L_STREETS]=streets;baseLayers[ITS_MAP_L_SAT]=sat;"
        /* collapsed:false -- the collapsed state's toggle icon references a
         * Leaflet default image (images/layers.png) we didn't vendor (kept
         * to just the emoji markers, no image assets at all), which would
         * otherwise show as a blank white box until clicked/hovered. */
        "L.control.layers(baseLayers,null,{collapsed:false}).addTo(map);"
        "var markers={};var haveView=false;"
        "var EMOJI={Ped:'\\ud83d\\udeb6',Cyclist:'\\ud83d\\udeb4',Moped:'\\ud83d\\udef5',"
        "Motorcycle:'\\ud83c\\udfcd',Car:'\\ud83d\\ude97',Bus:'\\ud83d\\ude8c',"
        "LTruck:'\\ud83d\\ude9a',HTruck:'\\ud83d\\ude9b',Trailer:'\\ud83d\\ude9b',"
        "Special:'\\ud83d\\udea7',Tram:'\\ud83d\\ude8a',RSU:'\\ud83d\\udce1'};"
        "function emojiFor(y){for(var k in EMOJI){if(y===k||y.indexOf(k+' ')===0)return EMOJI[k];}return '\\ud83d\\udccd';}"
        "function iconFor(y){return L.divIcon({html:emojiFor(y),className:'its-emoji-icon',"
        "iconSize:[26,26],iconAnchor:[13,13]});}"
        "function popupHtml(m){return '<b>'+(m.y||'?')+'</b><br>'+(m.t||'-')+' &middot; '"
        "+(m.r||'-')+' &middot; '+(m.l||'-')+' B<br>#'+m.i;}"
        "function apply(arr){var now=Date.now();"
        "for(var i=0;i<arr.length;i++){var m=arr[i];if(m.a===undefined)continue;"
        "var lat=m.a/1e7,lon=m.o/1e7,key=String(m.i);"
        "if(markers[key]){markers[key].marker.setLatLng([lat,lon]);}"
        "else{markers[key]={marker:L.marker([lat,lon],{icon:iconFor(m.y||'')}).addTo(map)};}"
        "markers[key].marker.bindPopup(popupHtml(m));"
        "markers[key].lastSeen=now;"
        "if(!haveView){map.setView([lat,lon],15);haveView=true;}}}"
        "apply(window.ITS_MAP_SEED||[]);"
        "setInterval(function(){var now=Date.now();for(var k in markers){"
        "if(now-markers[k].lastSeen>60000){map.removeLayer(markers[k].marker);delete markers[k];}}},5000);"
        "var delay=1000;"
        "function connect(){"
        "var proto=location.protocol==='https:'?'wss://':'ws://';"
        "var ws=new WebSocket(proto+location.host+'/ws');"
        "ws.onmessage=function(ev){apply(JSON.parse(ev.data));delay=1000;};"
        "ws.onclose=function(){setTimeout(connect,delay);delay=Math.min(delay*2,30000);};"
        "}"
        "connect();"
        "})();</script>";
    httpd_resp_send_chunk(req, MAP_SCRIPT, HTTPD_RESP_USE_STRLEN);
#endif

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
    uint8_t brightness = 0;
    config_get_u8(CONFIG_INDEX_LED_BRIGHTNESS, &brightness);
    uint32_t refresh_sec = 5;
    config_get_u32(CONFIG_INDEX_REFRESH_SEC, &refresh_sec);

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

    /* Large; keep off the httpd task stack (single-task, sequential handlers). */
    static EXT_RAM_BSS_ATTR char body[8192];
    snprintf(body, sizeof(body),
        "<p>%s</p>"
        "<table class='kv'>"
        /* size='16' (not the field's natural full width) on purpose: on a
         * table with auto layout, the HTML size attribute skews the
         * browser's column-width computation even under a CSS width:100%
         * rule, reserving far more column width than necessary (size=40 on
         * mqtturi alone was enough to push the whole table wider than a
         * phone screen). The input still shows/edits the full value
         * (scrollable within the box); only the initial rendered width hint
         * changes, and the CSS width/max-width rule still governs the
         * actual size on wider screens. */
        "<tr><th>%s</th><td><input id='nodeid' value='%s' size='16'></td></tr>"
        "<tr><th>%s</th><td><input id='mqtturi' value='%s' size='16'></td></tr>"
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
        "<tr><th>%s</th><td><input id='refreshsec' type='number' min='0' max='3600' value='%lu' size='6'></td></tr>"
        "<tr><th>%s</th><td>"
        "<input type='password' id='webpasswd' size='16' autocomplete='new-password'>"
        "<br><small>%s</small>"
        "<br><label><input type='checkbox' id='webpwclear'> %s</label>"
        "</td></tr>"
#if CONFIG_ENABLE_SD
        "<tr><th>%s</th><td><input type='checkbox' id='logsys'%s></td></tr>"
        "<tr><th>%s</th><td><input type='checkbox' id='logframes'%s></td></tr>"
        "<tr><th>%s</th><td><input id='logmaxmb' type='number' min='1' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
#endif
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
        "</table>"
        "<p><button onclick=\"save()\">%s</button> <span id='result'></span></p>"
        "<script>"
        "function save(){"
        "var p=new URLSearchParams();"
        "p.append('nodeid',document.getElementById('nodeid').value);"
        "p.append('mqtturi',document.getElementById('mqtturi').value);"
        "p.append('chan',document.getElementById('chan').value);"
        "p.append('led',document.getElementById('led').value);"
        "p.append('refreshsec',document.getElementById('refreshsec').value);"
        "p.append('ntpserver',document.getElementById('ntpserver').value);"
        "p.append('webpasswd',document.getElementById('webpasswd').value);"
        "if(document.getElementById('webpwclear').checked)p.append('webpwclear','1');"
#if CONFIG_ENABLE_SD
        "p.append('logsys',document.getElementById('logsys').checked?'1':'0');"
        "p.append('logframes',document.getElementById('logframes').checked?'1':'0');"
        "p.append('logmaxmb',document.getElementById('logmaxmb').value);"
#endif
        "p.append('dhcp',document.getElementById('dhcp').checked?'1':'0');"
        "p.append('ethip',document.getElementById('ethip').value);"
        "p.append('ethnm',document.getElementById('ethnm').value);"
        "p.append('ethgw',document.getElementById('ethgw').value);"
        "p.append('ethdns0',document.getElementById('ethdns0').value);"
        "p.append('ethdns1',document.getElementById('ethdns1').value);"
        "p.append('ethdns2',document.getElementById('ethdns2').value);"
        "fetch('/settings?lang=%s',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:p.toString()})"
        ".then(r=>r.text()).then(t=>{document.getElementById('result').innerText=t;});"
        "}"
        "function dhcpToggle(){var d=document.getElementById('dhcp').checked;"
        "['ethip','ethnm','ethgw'].forEach(function(i){document.getElementById(i).disabled=d;});}"
        "dhcpToggle();"
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
        T(S_REFRESH_SEC), (unsigned long)refresh_sec,
        T(S_WEB_PASSWORD),
        pw_set ? T(S_WEB_PASSWORD_SET) : T(S_WEB_PASSWORD_NONE),
        T(S_WEB_PASSWORD_CLEAR),
#if CONFIG_ENABLE_SD
        T(S_LOG_SYS), log_sys ? " checked" : "",
        T(S_LOG_FRAMES), log_frames ? " checked" : "",
        T(S_LOG_BUDGET), (unsigned long)log_mb, T(S_LOG_HINT),
#endif
        cur_line,
        T(S_ETH_DHCP), dhcp ? " checked" : "",
        T(S_ETH_IP), ethip,
        T(S_ETH_NETMASK), ethnm,
        T(S_ETH_GATEWAY), ethgw,
        T(S_ETH_DNS), ethdns0, ethdns1, ethdns2,
        T(S_ETH_NET_NOTE),
        T(S_NTP_SERVER), ntp_server,
        T(S_SAVE),
        lc
    );

    send_page_header(req, T(S_TITLE_SETTINGS));
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);
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

    if (req->content_len == 0 || req->content_len > 2048)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
        return ESP_FAIL;
    }

    char buf[2048] = {0};
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
    if (httpd_query_key_value(buf, "refreshsec", value, sizeof(value)) == ESP_OK)
    {
        unsigned long s = strtoul(value, NULL, 10);
        if (s <= 3600 && config_set_u32(CONFIG_INDEX_REFRESH_SEC, (uint32_t)s) == ESP_OK) saved++;
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
        "\"display\":\"standalone\",\"background_color\":\"#0a1c3a\","
        "\"theme_color\":\"#1c56be\",\"icons\":["
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

static esp_err_t system_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    send_page_header(req, T(S_TITLE_SYSTEM));

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

    char ri_f[24], ri_m[24], ri_t[24], rp_f[24], rp_m[24], rp_t[24];
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_INTERNAL), ri_f, sizeof(ri_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL), ri_m, sizeof(ri_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_INTERNAL), ri_t, sizeof(ri_t));
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_SPIRAM), rp_f, sizeof(rp_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM), rp_m, sizeof(rp_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_SPIRAM), rp_t, sizeof(rp_t));

    char info[1400];
    snprintf(info, sizeof(info),
        "<table class='kv'>"
        "<tr><th>%s</th><td>%s rev %d, %s</td></tr>"
        "<tr><th>%s</th><td>%d</td></tr>"
        "<tr><th>%s</th><td>%d MHz</td></tr>"
        "<tr><th>%s</th><td>%s (IDF %s, %s %s)</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s (%s)</th><td>%s / %s / %s</td></tr>"
        "<tr><th>%s (%s)</th><td>%s / %s / %s</td></tr>"
        "</table><h2>%s</h2>",
        T(S_SYS_CHIP), CONFIG_IDF_TARGET, chip.revision, feat,
        T(S_SYS_CORES), chip.cores,
        T(S_SYS_CPU_FREQ), CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        T(S_FW_VERSION), app->version, app->idf_ver, app->date, app->time,
        T(S_SYS_IDF), esp_get_idf_version(),
        T(S_SYS_RESET), reset_reason_str(esp_reset_reason()),
        T(S_UPTIME), uptime_str,
        T(S_SYS_RAM_INT), T(S_SYS_TRIPLE), ri_f, ri_m, ri_t,
        T(S_SYS_RAM_PSRAM), T(S_SYS_TRIPLE), rp_f, rp_m, rp_t,
        T(S_SYS_TASKS));
    httpd_resp_send_chunk(req, info, HTTPD_RESP_USE_STRLEN);

    /* Two snapshots ~300 ms apart give the *current* per-task CPU load (delta),
     * which is wrap-safe unlike cumulative-since-boot counters. */
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

        httpd_resp_send_chunk(req,
            "<div class='scroll'><table><tr><th>Task</th><th>", HTTPD_RESP_USE_STRLEN);
        char hdr[128];
        snprintf(hdr, sizeof(hdr), "%s</th><th>%s</th><th>%s</th><th>%s</th></tr>",
                 T(S_SYS_COL_STATE), T(S_SYS_COL_PRIO), T(S_SYS_COL_CPU), T(S_SYS_COL_STACK));
        httpd_resp_send_chunk(req, hdr, HTTPD_RESP_USE_STRLEN);

        for (UBaseType_t i = 0; i < c2; i++)
        {
            uint32_t prev = 0;
            for (UBaseType_t j = 0; j < c1; j++)
                if (a1[j].xHandle == a2[i].xHandle) { prev = a1[j].ulRunTimeCounter; break; }
            uint32_t delta = a2[i].ulRunTimeCounter - prev;
            unsigned cpu_x10 = total_delta ? (unsigned)(((uint64_t)delta * 1000) / total_delta) : 0;

            char nameesc[48];
            html_escape(a2[i].pcTaskName, nameesc, sizeof(nameesc));
            char row[256];
            snprintf(row, sizeof(row),
                "<tr><td>%s</td><td>%s</td><td>%u</td><td>%u.%u</td><td>%u</td></tr>",
                nameesc, task_state_str(a2[i].eCurrentState),
                (unsigned)a2[i].uxCurrentPriority,
                cpu_x10 / 10, cpu_x10 % 10,
                (unsigned)a2[i].usStackHighWaterMark);
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</table></div>", HTTPD_RESP_USE_STRLEN);
    }
    free(a1);
    free(a2);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
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
    "if(!f){alert('%s');return;}"
    "var xhr=new XMLHttpRequest();"
    "xhr.open('POST','/update?lang=%s');"
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

    /* The upload POST carries no query string of its own, so it must be told
     * the current language explicitly here -- otherwise resolve_language()
     * on that request defaults to German regardless of what's displayed
     * (this was the "OTA error always shows German" bug). */
    const char *lc = current_lang == LANG_DE ? "de" : "en";

    char form[1024];
    snprintf(form, sizeof(form), UPDATE_FORM_FMT,
             T(S_UPD_INTRO), T(S_UPLOAD), T(S_UPD_CHOOSE_FILE), lc, T(S_UPLOAD_FAIL), T(S_UPLOADING));

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

/* Copies `name` into `out`, replacing '"' with '_'. Used to build the
 * filename value of a Content-Disposition header: a bare '"' in the source
 * filename would otherwise break out of the quoted value. Belt-and-braces
 * defense-in-depth -- upload rejects '"' in new filenames already, but this
 * also covers files that reached the card some other way (e.g. copied onto
 * it directly with a card reader, bypassing that check entirely). */
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
        "<p><button onclick='seltar()'>&#8595; %s</button></p>"
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
        "function selall(c){document.querySelectorAll('.sel').forEach(function(x){x.checked=c.checked;});}"
        "function seltar(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}location.href='/sdcard/tar?sel='+s.join('|');}"
        "</script>",
        usage,
        T(S_SD_UP_HERE), T(S_SD_UP_BTN),
        T(S_SD_FORMAT),
        T(S_TAR_SELECTED),
        relenc,
        T(S_UPLOADING),
        T(S_SD_FORMAT_CONFIRM), T(S_SD_FORMATTING),
        T(S_SD_DELETE_CONFIRM),
        T(S_TAR_NONE));
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
        "<script>function selall(c){document.querySelectorAll('.sel').forEach(function(x){x.checked=c.checked;});}"
        "function seltar(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}location.href='/fs/tar?sel='+s.join('|');}</script>"
        "<p><b>/%s</b></p><div class='scroll'><table>"
        "<tr><th><input type='checkbox' onclick='selall(this)'></th>"
        "<th>%s</th><th>%s</th></tr>",
        T(S_FS_INTERNAL), lq, T(S_TITLE_SD),
        T(S_TAR_SELECTED), T(S_TAR_NONE),
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
static void stream_tail_escaped(httpd_req_t *req, FILE *f, long start)
{
    fseek(f, start, SEEK_SET);
    char in[512];
    char out[512 * 5];
    bool skip_partial = (start > 0);
    size_t n;
    while ((n = fread(in, 1, sizeof(in), f)) > 0)
    {
        size_t i = 0;
        if (skip_partial)
        {
            while (i < n && in[i] != '\n') i++;
            if (i < n) { i++; skip_partial = false; }
            else continue;  /* whole chunk was the partial first line */
        }
        size_t o = 0;
        for (; i < n; i++)
        {
            const char *rep;
            switch (in[i])
            {
            case '<': rep = "&lt;";  break;
            case '>': rep = "&gt;";  break;
            case '&': rep = "&amp;"; break;
            default:  out[o++] = in[i]; continue;
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
    config.max_uri_handlers = 34; /* 28 routes today + /map, /leaflet.js, /leaflet.css, plus a little headroom */
    /* One extra over the default 7: the /ws live feed holds a socket open for
     * as long as /messages is open in a browser tab, on top of normal
     * requests. */
    config.max_open_sockets = 8;
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
        { .uri = "/messages", .method = HTTP_GET,  .handler = messages_get_handler },
        { .uri = "/settings", .method = HTTP_GET,  .handler = settings_get_handler },
        { .uri = "/settings", .method = HTTP_POST, .handler = settings_post_handler },
        { .uri = "/update",   .method = HTTP_GET,  .handler = update_get_handler },
        { .uri = "/update",   .method = HTTP_POST, .handler = update_post_handler },
        { .uri = "/sniffer",  .method = HTTP_POST, .handler = sniffer_post_handler },
        { .uri = "/reboot",   .method = HTTP_POST, .handler = reboot_post_handler },
        { .uri = "/confirm",  .method = HTTP_POST, .handler = confirm_post_handler },
        { .uri = "/system",   .method = HTTP_GET,  .handler = system_get_handler },
        { .uri = "/map",         .method = HTTP_GET, .handler = map_get_handler },
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
