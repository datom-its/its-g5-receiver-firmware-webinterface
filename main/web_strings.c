#include "web_strings.h"

#include <time.h>

/* The pair count is written out in the comment at the top of web_strings.h. This holds the
 * two together: a new text fails the build until that number is corrected. */
_Static_assert(S_COUNT == 1232, "update the pair count in the header comment of web_strings.h");

static const char *STR[S_COUNT][2] = {
    /*                        DE                          EN                     */
    /* States have three levels in s.css. An info is a whole sentence without brackets in
     * p.note, a warning goes in .warn and an alarm in .alarm. s.css sets the sign in front of
     * a warning or an alarm, so no text has one. */
    [S_NAV_STATUS]      = { "Status",                   "Status" },
    [S_NAV_MESSAGES]    = { "Nachrichten",              "Messages" },
    [S_NAV_SETTINGS]    = { "Einstellungen",            "Settings" },
    [S_NAV_UPDATE]      = { "Firmware",                 "Firmware" },
    [S_TITLE_STATUS]    = { "Status",                   "Status" },
    [S_TITLE_MESSAGES]  = { "Nachrichten",              "Messages" },
    [S_TITLE_SETTINGS]  = { "Einstellungen",            "Settings" },
    [S_TITLE_UPDATE]    = { "Firmware-Update",          "Firmware update" },
    [S_NODEID]          = { "Node-ID",                  "Node ID" },
    /* Shown without hlp at every field with .reboot in SET_DEFS. The network fields say it with
     * S_ETH_NET_REBOOT. Without it, the user saves and then waits for an effect that only comes
     * later. */
    [S_NEEDS_REBOOT]    = { "Wirkt erst nach einem Neustart.",
                            "Takes effect only after a restart." },
    [S_MAC]             = { "MAC-Adresse",              "MAC" },
    [S_FW_VERSION]      = { "Firmware-Version",         "Firmware version" },
    [S_SD_CARD]         = { "SD-Karte",                 "SD card" },
    [S_UPTIME]          = { "Laufzeit",                 "Uptime" },
    [S_SNIFFER]         = { "Empfang",                  "Reception" },
    [S_CHANNEL]         = { "Kanal",                    "Channel" },
    [S_MQTT]            = { "MQTT",                     "MQTT" },
    [S_MSGS_RECEIVED]   = { "Empfangene Nachrichten",   "Messages received" },
    [S_RATE]            = { "Nachrichten pro Minute",   "Messages per minute" },
    [S_TEMPERATURE]     = { "Temperatur",               "Temperature" },
    [S_RUNNING]         = { "l&auml;uft",               "running" },
    [S_STOPPED]         = { "angehalten",               "stopped" },
    [S_CONNECTED]       = { "verbunden",                "connected" },
    [S_DISCONNECTED]    = { "getrennt",                 "disconnected" },
    [S_REBOOT]          = { "Neustart",                 "Restart" },
    /* Shown in a JS confirm() dialog, which does not decode HTML entities, so
     * this uses a JS \u escape instead of &auml;. */
    [S_REBOOT_CONFIRM]  = { "Ger\\u00e4t neu starten?", "Restart the device?" },
    [S_REBOOTING]       = { "Neustart l&auml;uft&hellip;", "Restarting&hellip;" },
    /* &quot;, never an apostrophe: this goes into a single-quoted JS string
     * inside a double-quoted onclick attribute. A bare ' ends the string. */
    [S_REBOOT_SLOW]     = { "Das Ger&auml;t meldet sich nicht. "
                            "<a href=&quot;/&quot;>Seite neu laden</a>",
                            "The device is not answering. "
                            "<a href=&quot;/&quot;>Reload the page</a>" },
    /* These two go into alert()/confirm(): plain text, no entities. */
    [S_REBOOT_DENIED]   = { "Neustart abgelehnt \u2013 Web-Passwort n\u00f6tig.",
                            "Restart refused - web password required." },
    [S_UNSAVED_WARN] = {
        "Es gibt ungespeicherte \u00c4nderungen, die beim Neustart verloren gehen. Trotzdem neu "
        "starten?",
        "There are unsaved changes that a restart discards. Restart anyway?" },
    /* Asked before a page change drops unsaved fields. The one above keeps the restart wording.
     * Goes to confirm() through a JS literal: real UTF-8, no apostrophe, no double quote. */
    [S_UNSAVED_LEAVE] = {
        "Es gibt ungespeicherte Änderungen, die beim Wechsel der Seite verloren gehen. Trotzdem "
        "weiter?",
        "There are unsaved changes that are lost when the page changes. Continue anyway?" },
    /* innerText, so literal UTF-8. A transport failure is not a bad value. */
    /* The httpd answers a 401 with its own English default text, so the page shows this one
     * instead. It goes to innerText. */
    [S_SAVE_DENIED]     = { "Nicht gespeichert \u2013 Web-Passwort n\u00f6tig.",
                            "Not saved - web password required." },
    [S_SAVE_NOCONN]     = { "Nicht gespeichert \u2013 keine Verbindung zum Ger\u00e4t:",
                            "Not saved - no connection to the device:" },
    [S_POWEROFF]        = { "Zum Ausschalten vorbereiten",
                                                        "Prepare for power-off" },
    /* Shown in a JS confirm() dialog -> JS \u escape, no HTML entity. */
    [S_POWEROFF_CONFIRM]= { "Aufzeichnung sichern und SD-Karte aush\\u00e4ngen? Neben dem Knopf "
                            "steht dann, wann der Strom weg darf. Der Empfang l\\u00e4uft ohne "
                            "SD-Karte weiter, bis sie auf der Seite \\u201eDateien\\u201c wieder "
                            "eingebunden wird oder das Ger\\u00e4t neu startet.",
                            "Save the recording and unmount the SD card? Next to the button it "
                            "then says when the power may go off. Reception goes on without the "
                            "SD card until it is mounted again on the \\u201cFiles\\u201d page or "
                            "the device restarts." },
    /* These five are shown via .innerText, which does NOT interpret escapes
     * -- literal UTF-8 here, unlike the confirm() string above. */
    [S_POWEROFF_BUSY]   = { "Daten werden gesichert… Strom erst nach der Meldung trennen.",
                            "Saving data… Unplug only after the message." },
    [S_POWEROFF_OK]     = { "Fertig. Das Gerät kann jetzt vom Strom getrennt werden.",
                            "Done. The device can now be disconnected from power." },
    /* Its own refusal, because the button is S_POWEROFF and S_REBOOT_DENIED would speak of a
     * restart. It goes out through innerText, so real umlauts. */
    [S_POWEROFF_DENIED] = { "Nicht vorbereitet – Web-Passwort nötig.",
                            "Not prepared – web password required." },
    [S_POWEROFF_FAIL]   = { "Die SD-Karte ließ sich nicht sauber aushängen.",
                            "The SD card could not be unmounted cleanly." },
    [S_POWEROFF_DOWNLOAD] = { "Nicht ausgehängt – es wird noch eine Datei heruntergeladen. "
                              "Danach erneut versuchen.",
                              "Not unmounted – a download is still running. Try again "
                              "afterwards." },
    [S_POWEROFF_BLOCKED] = { "Nicht ausgehängt – die SD-Karte ist blockiert. Später erneut versuchen.",
                             "Not unmounted – the SD card is blocked. Try again later." },
    /* Appended to the answer above, %s is a size. The status stays what the
     * unmount decided. */
    [S_POWEROFF_UNSAVED] = { "%s der Aufzeichnung konnten nicht geschrieben werden.",
                             "%s of the recording could not be written." },
    /* Also set with textContent by the start page script: plain ASCII, no entities. */
    [S_SNIFF_START]     = { "Empfang starten",          "Start reception" },
    [S_SNIFF_STOP]      = { "Empfang anhalten",         "Stop reception" },
    /* One %s: the element <b id=otamin> with the minutes left. A value takes the unit
     * symbol, and "min" fits 1 and 30 alike. The quote is S_CONFIRM_BTN. */
    [S_CONFIRM_NEEDED] = {
        "Diese Firmware kam per Update und ist noch nicht best&auml;tigt. Ohne Best&auml;tigung "
        "startet das Ger&auml;t in %s&nbsp;min wieder die vorige Firmware, bei einem Neustart "
        "schon fr&uuml;her. Das sch&uuml;tzt vor einem Update, das nicht l&auml;uft.<br><br>Wenn "
        "alles l&auml;uft: &bdquo;Update jetzt best&auml;tigen&ldquo; dr&uuml;cken.",
        "This firmware came by update and is not confirmed yet. Without confirmation, the device "
        "starts the previous firmware again in %s&nbsp;min, or earlier at a restart. This guards "
        "against an update that does not work.<br><br>If everything works, press &ldquo;Confirm "
        "update now&rdquo;." },
    /* No rollback timer running: promising "30 minutes" would be untrue. */
    [S_CONFIRM_NEEDED_NT] = {
        "Diese Firmware kam per Update und ist noch nicht best&auml;tigt. Bis dahin nimmt das "
        "Ger&auml;t kein weiteres Update an.<br><br>Eine Frist von 30 Minuten gibt es diesmal "
        "nicht, weil das Ger&auml;t keine best&auml;tigte vorige Firmware findet, zu der es "
        "zur&uuml;ckkehren k&ouml;nnte.<br><br>Wenn alles l&auml;uft: &bdquo;Update jetzt "
        "best&auml;tigen&ldquo; dr&uuml;cken.",
        "This firmware came by update and is not confirmed yet. Until then, the device takes no "
        "further update.<br><br>There is no 30-minute deadline this time, because the device "
        "finds no confirmed older firmware to go back to.<br><br>If everything works, press "
        "&ldquo;Confirm update now&rdquo;." },
    [S_CONFIRM_BTN]     = { "Update jetzt best&auml;tigen", "Confirm update now" },
    /* Sent as a plain-text response and shown via JS alert(); it is not parsed
     * as HTML, so this uses a literal UTF-8 "ä" (served with charset=utf-8)
     * rather than the &auml; entity. */
    [S_CONFIRMED]       = { "Bestätigt. Das Gerät bleibt bei dieser Firmware.",
                            "Confirmed. The device stays on this firmware." },
    /* Shown via alert(t) after fetch('/confirm').then(r=>r.text()) if
     * ota_confirm() itself fails. */
    [S_CONFIRM_ERROR]   = { "Fehler beim Bestätigen.", "Error confirming." },
    /* alert() texts: literal UTF-8, no apostrophes (they sit in a JS string).
     * No URL is named, because the browser may ask for the password itself. */
    [S_CONFIRM_AUTH]    = { "Anmeldung nötig. Bitte mit dem Web-Passwort anmelden "
                            "und erneut bestätigen.",
                            "Sign-in required. Please sign in with the web password "
                            "and confirm again." },
    [S_CONFIRM_NOCONN] = {
        "Keine Antwort vom Gerät, die Bestätigung kam vielleicht nicht an. Bitte die Seite neu "
        "laden. Wenn der Hinweis noch da ist, erneut bestätigen. Wenn die Seite nicht lädt, ist "
        "das Gerät gerade nicht erreichbar, dann später neu laden.",
        "No answer from the device; the confirmation may not have arrived. Please reload the "
        "page. If the notice is still there, confirm again. If the page does not load, the "
        "device is not reachable right now, so reload later." },
    /* Only on pages that poll or stream. %s is the element <b id=stlt>, into which the page
     * script writes the clock time. */
    [S_LINK_LOST]       = { "Seit %s keine Verbindung zum Ger&auml;t. Die Werte sind veraltet.",
                            "No connection to the device since %s. The values are out of date." },
    /* Faults of the whole device, bar under every page heading (web_faults.c) and probs_html in
     * /status.json and /system.json: entities are fine, never a double quote or backslash. */
    /* Appended to every SD line of the bar, because each of them means the same loss. */
    [S_FLT_SD_LOST]     = { "Neue Daten werden nicht gespeichert.",
                            "New data is not being saved." },
    [S_FLT_SD_NOFS]     = { "Die SD-Karte hat kein brauchbares Dateisystem.",
                            "The SD card has no usable filesystem." },
    [S_FLT_SD_FULL]     = { "Die SD-Karte ist voll.",   "The SD card is full." },
    /* %s here and in the two below is a duration such as 14 min 3 s. */
    [S_FLT_SD_WRITE]    = { "Die SD-Karte nimmt seit %s keine Daten mehr an.",
                            "The SD card has refused data for %s." },
    [S_FLT_RX]          = { "Seit %s kommt keine Nachricht mehr an. Vorher kamen sie laufend. "
                            "Antenne und Kanal pr&uuml;fen.",
                            "No message for %s. Before that they came in steadily. Check the "
                            "antenna and the channel." },
    [S_FLT_CLOCK]       = { "Die Uhr ist nicht gestellt. Darum fehlen das Datum, die "
                            "Verkehrsstatistik und die Pr&uuml;fung, ob Zertifikate noch gelten.",
                            "The clock is not set. So the date, the traffic statistics and the "
                            "check whether certificates are still valid are missing." },
    [S_FLT_CRASH_DUMP]  = { "Das Ger&auml;t ist abgest&uuml;rzt und hat Absturzdaten gespeichert.",
                            "The device crashed and saved a crash dump." },
    [S_FLT_CRASH]       = { "Das Ger&auml;t ist in den letzten 24 Stunden abgest&uuml;rzt und neu "
                            "gestartet.",
                            "The device crashed and restarted within the last 24 hours." },
    [S_FLT_MQTT]        = { "MQTT ist seit %s getrennt. Die Nachrichten kommen nicht beim Server "
                            "an.",
                            "MQTT has been disconnected for %s. Messages are not reaching the "
                            "server." },
    /* Sent by httpd_resp_send_err as text/html WITHOUT a charset, so entities here,
     * unlike the plain-text reasons above. */
    [S_SD_NEEDS_RESTART] = {
        "Die SD-Karte l&auml;sst sich gerade nicht einbinden, weil sie nach dem letzten "
        "Formatieren nicht zur&uuml;ckkam. Darum sperrt das Ger&auml;t Einbinden und Formatieren "
        "bis zum n&auml;chsten Neustart. Kaputt ist die SD-Karte deshalb nicht "
        "unbedingt.<br><br>N&auml;chster Schritt: das Ger&auml;t neu starten, zum Beispiel mit "
        "&bdquo;<a href='/?lang=de#sec-ctl'>Neustart</a>&ldquo; auf der Seite "
        "&bdquo;Status&ldquo;. Danach zeigt die Seite "
        "&bdquo;<a href='/sdcard?lang=de'>Dateien</a>&ldquo;, ob die SD-Karte l&auml;uft oder "
        "noch formatiert werden muss.",
        "The SD card cannot be mounted right now, because it did not come back after the last "
        "format. So the device blocks mounting and formatting until the next restart. This does "
        "not necessarily mean the SD card is broken.<br><br>Next step: restart the device, for "
        "example with &ldquo;<a href='/?lang=en#sec-ctl'>Restart</a>&rdquo; on the "
        "&ldquo;Status&rdquo; page. After that, the "
        "&ldquo;<a href='/sdcard?lang=en'>Files</a>&rdquo; page shows whether the SD card works "
        "or still needs formatting." },
    /* Two catch branches on /messages and one on /senders set this with textContent, so no
     * entities and no apostrophe. */
    [S_ERR_GENERIC] = { "Fehler", "Error" },
    /* aria-label of the menu button, in a single-quoted HTML attribute: entities yes,
     * apostrophe no. */
    [S_NAV_MENU] = { "Men&uuml;", "Menu" },
    /* The three group names of the menu (web_nav.c): HTML text and the single-quoted
     * data-pg attribute, so entities yes, apostrophe no. The Status group uses S_NAV_STATUS. */
    /* "Umgebung" rather than "Straße", because the group holds what the device hears around it. */
    [S_NAV_G_ROAD]   = { "Umgebung",     "Nearby" },
    [S_NAV_G_RADIO]  = { "Funk",         "Radio" },
    [S_NAV_G_DEVICE] = { "Ger&auml;t",   "Device" },
    /* The button in the page header that shows and hides all explanations. It shows the state,
     * not the action. Its title says what a click does. */
    [S_HELP_ON]  = { "Erkl&auml;rungen: an", "Explanations: on" },
    [S_HELP_OFF] = { "Erkl&auml;rungen: aus", "Explanations: off" },
    [S_HELP_TIP] = { "Erkl&auml;rungen auf allen Seiten ein- oder ausblenden",
                     "Show or hide the explanations on all pages" },
    /* The meta description in the page head. Like the title above, it is a single-quoted
     * attribute, so no apostrophe. */
    [S_META_DESC] = { "ITS-G5-Empf&auml;nger an der Stra&szlig;e: Live-Status, dekodierte "
                      "Nachrichten, Karte, Verkehrsstatistik und Logs.",
                      "ITS-G5 roadside receiver: live status, decoded messages, map, traffic "
                      "statistics and logs." },
    /* Added to the lane popup for lane type 1, which its_decode.h names a crosswalk. The German
     * Übergang means a crossing here, not a change. Goes out as a JS string literal: no
     * entities, no quote, no backslash. */
    [S_MAP_XWALK] = { "Fußgängerübergang", "Pedestrian crossing" },
    /* Four items from the CAM in the map popup. JS literal: real umlauts, no apostrophe. */
    [S_MAP_ALT] = { "Höhe", "Altitude" },
    [S_MAP_ACCEL] = { "Beschleunigung", "Acceleration" },
    [S_MAP_REVERSE] = { "rückwärts", "reversing" },
    [S_MAP_LANEPOS] = { "Spur", "Lane" },
    /* The words for the special values of LanePosition: 0 and 14 are hard shoulders, -1 is off
     * the road. They go into the map popup and the detail line, hence real umlauts and no
     * apostrophe. */
    [S_LANE_SHOULDER] = { "Seitenstreifen", "hard shoulder" },
    [S_LANE_OFFROAD] = { "abseits der Straße", "off the road" },
    /* Alert on the map when the tracks cannot be read because the SD card is not mounted.
     * JS literal: real umlauts and typographic quotes, no entity, no apostrophe, no straight
     * double quote. */
    [S_MAP_TRACKS_NOSD] = {
        "Die gefahrenen Wege liegen auf der SD-Karte, und die ist gerade nicht eingebunden. "
        "Warum, zeigt die Seite „Dateien“.",
        "The vehicle tracks are stored on the SD card, which is not mounted right now. The "
        "“Files” page shows why." },
    [S_SD_ACTION_FAILED] = { "Der Vorgang ist fehlgeschlagen.",
                             "The operation failed." },
    [S_MSG_INTRO] = {
        "Die letzten %d empfangenen Frames, die neuesten oben.",
        "The last %d frames received, newest on top." },
    [S_COL_NUM]         = { "#",                        "#" },
    [S_COL_TIME]        = { "Zeit",                     "Time" },
    [S_COL_RSSI]        = { "Pegel (dBm)",              "Signal (dBm)" },
    [S_COL_SENDER]      = { "Absender",                 "Sender" },
    [S_COL_LENGTH]      = { "L&auml;nge (B)",           "Length (B)" },
    [S_COL_PREVIEW]     = { "Details",                  "Details" },
    [S_SET_INTRO] = {
        "Die Einstellungen bleiben auch nach dem Ausschalten erhalten. Die meisten wirken "
        "sofort, einzelne erst nach einem Neustart.",
        "Settings are kept when the device is switched off. Most take effect at once, a few only "
        "after a restart." },
    [S_MQTT_URI]        = { "MQTT-URI",                 "MQTT URI" },
    /* One text for the page and for /status.json textContent: no umlaut, no entity, no double
     * quote, backslash, < or &. %s is the host in the first, a duration in the second. */
    [S_MQTT_TO]         = { "mit %s",                   "to %s" },
    [S_MQTT_SINCE]      = { "seit %s",                  "for %s" },
    [S_MQTT_NEVER]      = { "seit dem Start noch nie verbunden",
                            "not connected once since start-up" },
    [S_MQTT_WHY_DNS]    = { "Servername nicht gefunden", "server name not found" },
    [S_MQTT_WHY_UNREACH] = { "Server nicht erreichbar", "server not reachable" },
    [S_MQTT_WHY_TLS]    = { "sichere Verbindung gescheitert (TLS)",
                            "secure connection failed (TLS)" },
    [S_MQTT_WHY_AUTH]   = { "Anmeldung abgelehnt (Benutzer oder Passwort)",
                            "login refused (user or password)" },
    [S_MQTT_WHY_REFUSED] = { "Server lehnt die Verbindung ab",
                             "server refuses the connection" },
    [S_MQTT_WHY_LOST]   = { "Verbindung abgerissen",    "connection lost" },
    [S_MQTT_WHY_NONET]  = { "kein Netzwerk",            "no network" },
    /* Row label on /settings. A state, so it stays visible with the explanations off. */
    [S_MQTT_NOW]        = { "MQTT-Zustand jetzt",       "MQTT state now" },
    /* hlp. Named _HINT like the other explanations, whose paragraphs stay within 240 visible
     * characters. */
    [S_MQTT_PW_HINT] = {
        "Das Passwort steht hier als &bull;&bull;&bull;&bull;, damit es auf keinem "
        "Bildschirmfoto zu sehen ist. Wenn man das so l&auml;sst, bleibt das gespeicherte "
        "Passwort. F&uuml;r ein neues einfach die Punkte &uuml;berschreiben.",
        "The password shows here as &bull;&bull;&bull;&bull;, so it never appears on a "
        "screenshot. Leave it that way and the saved password stays. For a new one, just type "
        "over the dots." },
    [S_AUTOSTART_CHAN]  = { "Autostart-Kanal",          "Autostart channel" },
    [S_CHAN_NONE]       = { "(keiner)",                 "(none)" },
    /* The group heads of /settings. SUB are the small heads inside the SD card group. HTML. */
    [S_SET_GROUP_DEVICE]  = { "Ger&auml;t",             "Device" },
    [S_SET_GROUP_RX]      = { "Empfang",                "Reception" },
    [S_SET_GROUP_NETWORK] = { "Netzwerk",               "Network" },
    [S_SET_GROUP_LINKS]   = { "Verbindungen",           "Connections" },
    [S_SET_GROUP_STORAGE] = { "SD-Karte",               "SD card" },
    [S_SET_SUB_PCAP]      = { "Aufzeichnung (PCAP)",    "Recording (PCAP)" },
    [S_SET_SUB_TRAFFIC]   = { "Verkehrsstatistik und Warnungen",
                              "Traffic statistics and warnings" },
    [S_SET_GROUP_WEB]     = { "Weboberfl&auml;che",     "Web interface" },
    [S_STATS_RETAIN_DAYS] = { "Statistik aufbewahren (Tage)",   "Keep statistics for (days)" },
    [S_EVENT_RETAIN_DAYS] = { "Warnungen aufbewahren (Tage)",   "Keep warnings for (days)" },
    [S_MAP_STALE_SEC]   = { "Karte: Marker-Standzeit (s)", "Map: marker hold time (s)" },
    [S_MAP_STALE_HINT]  = { "Wie lange ein Sender ohne neue Nachricht auf der Karte bleibt.",
                            "How long a sender stays on the map without a new message." },
    [S_SET_GROUP_SECURITY]= { "Sicherheit",             "Security" },
    [S_BROADCAST_ONLY]  = { "Nur Broadcast erfassen",   "Capture broadcast only" },
    [S_BROADCAST_ONLY_HINT] = {
        "Ausgeschaltet nimmt das Ger&auml;t auch Unicast-Frames auf, das sind deutlich mehr "
        "Daten.",
        "When off, the device also captures unicast frames, which is significantly more data." },
    [S_LED_OVERRIDE]     = { "Feste LED-Farbe",          "Fixed LED color" },
    [S_LED_OVERRIDE_HINT] = { "Mit H&auml;kchen leuchtet die LED immer in der gew&auml;hlten "
                              "Farbe. Ohne H&auml;kchen zeigt sie wie sonst den Status des "
                              "Ger&auml;ts.",
                              "When checked, the LED always shows the chosen color. Otherwise it "
                              "shows the device status as usual." },
    [S_LED_BRIGHTNESS]  = { "LED-Helligkeit",           "LED brightness" },
    [S_SAVE]            = { "Speichern",                "Save" },
    [S_SAVE_REBOOT]     = { "Speichern &amp; Neustart",  "Save &amp; restart" },
    [S_UNSAVED]         = { "Nicht gespeicherte &Auml;nderungen",
                            "Unsaved changes" },
    [S_SAVED]           = { "%d Einstellung(en) gespeichert.", "Saved %d setting(s)." },
    /* Rendered via textContent, so plain UTF-8 -- no entities. */
    [S_SET_BAD]         = { "Nicht gespeichert, Wert außerhalb des Bereichs:",
                            "Not saved, value out of range:" },
    /* Its own sentence for an empty or unreadable number field, where the out-of-range text
     * would be wrong. The wording follows S_IMP_WHY_TYPE_NUM. */
    [S_SET_BAD_NUM]     = { "Nicht gespeichert, ganze Zahl erwartet:",
                            "Not saved, whole number expected:" },
    /* Silently dropping an out-of-range value while reporting success is how a
     * setting appears to "reset itself" -- the page has to say it refused. */
    /* Goes out as text/plain, which decodes NO entities. Literal UTF-8 here,
     * like S_SET_BAD above. */
    [S_SAVED_REJECTED]  = { "%d gespeichert, %d abgelehnt.", "%d saved, %d rejected." },
    /* Same words as S_IMP_REBOOT, but this goes out as text/plain and is shown via innerText:
     * real umlauts, no entities. */
    [S_SAVED_REBOOT]    = { "Einige geänderte Einstellungen wirken erst nach einem Neustart.",
                            "Some changed settings take effect only after a restart." },
    [S_WEB_PASSWORD]    = { "Web-Passwort (Benutzer <code>admin</code>)",
                            "Web password (user <code>admin</code>)" },
    [S_WEB_PASSWORD_SET] = {
        "gesetzt &ndash; leer lassen, dann bleibt das bisherige",
        "set &ndash; leave empty to keep the current one" },
    /* Names the main things check_update_auth() gates, hence "unter anderem": without a
     * password the whole card, the internal filesystem and the exports are open to the network. */
    [S_WEB_PASSWORD_NONE] = {
        "kein Passwort gesetzt &ndash; ein Passwort sch&uuml;tzt unter anderem Einstellungen, "
        "Firmware-Update, Neustart und alle Datei-Zugriffe (SD-Karte, Flash, Logs, Export)",
        "no password set &ndash; a password protects, among other things, settings, firmware "
        "update, restart and all file access (SD card, flash, logs, export)" },
    [S_WEB_PASSWORD_CLEAR] = { "Passwortschutz entfernen",
                               "Remove password protection" },
    /* The page a refused page load gets (web_auth.c). */
    [S_AUTH_TITLE]      = { "Anmeldung n&ouml;tig",     "Sign-in required" },
    [S_AUTH_TEXT]       = { "Diese Seite ist mit dem Web-Passwort gesch&uuml;tzt. Der Browser "
                            "fragt beim Anmelden nach Benutzername und Passwort. Der Benutzername "
                            "ist <code>admin</code>.",
                            "This page is protected by the web password. When signing in, the "
                            "browser asks for a username and a password. The username is "
                            "<code>admin</code>." },
    /* config.c registers the console command config_clear, and the key is webpasswd. */
    [S_AUTH_FORGOT]     = { "Passwort vergessen? An der seriellen Konsole hebt "
                            "<code>config_clear webpasswd</code> den Schutz auf. Danach "
                            "l&auml;sst sich auf der Seite "
                            "&bdquo;<a href='/settings?lang=de#webpasswd'>Einstellungen</a>&ldquo; "
                            "ein neues Passwort setzen.",
                            "Forgot the password? On the serial console, <code>config_clear "
                            "webpasswd</code> removes the protection. A new password can then be "
                            "set on the "
                            "&ldquo;<a href='/settings?lang=en#webpasswd'>Settings</a>&rdquo; "
                            "page." },
    [S_AUTH_RETRY]      = { "Erneut anmelden",          "Sign in again" },
    [S_REFRESH_SEC]     = { "Seite selbst aktualisieren (s, 0=aus)",
                            "Update the page by itself (s, 0=off)" },
    [S_ETH_DHCP]        = { "DHCP (IP automatisch)",     "DHCP (automatic IP)" },
    [S_ETH_IP]          = { "IP-Adresse",               "IP address" },
    [S_ETH_NETMASK]     = { "Subnetzmaske",             "Subnet mask" },
    [S_ETH_GATEWAY]     = { "Gateway",                  "Gateway" },
    [S_ETH_DNS]         = { "DNS-Server (1/2/3)",       "DNS servers (1/2/3)" },
    /* Always visible under the address fields; the rest of S_ETH_NET_NOTE is explanation. */
    [S_ETH_NET_REBOOT]  = { "Netzwerk-&Auml;nderungen wirken erst nach einem Neustart.",
                           "Network changes take effect only after a restart." },
    [S_ETH_NET_NOTE] = {
        "Ohne DHCP gilt eine feste Adresse, dann IP-Adresse, Maske und Gateway ausf&uuml;llen. "
        "DNS ist freiwillig und gilt auch mit DHCP.",
        "Without DHCP a static address applies, so fill in IP address, mask and gateway. DNS is "
        "optional and also applies with DHCP." },
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
    [S_HIST_WAIT]       = { "noch zu wenig Daten",
                            "not enough data yet" },
    /* Not "none yet": the hour is empty, the counter above it is not.
     * Goes to textContent, so plain UTF-8 and no entities. */
    [S_HIST_IDLE]       = { "in dieser Stunde nichts empfangen",
                            "nothing received this hour" },
    /* Two sinks: an HTML chunk AND a single-quoted JS literal set via
     * textContent -- so no apostrophes, no umlauts, no entities. */
    [S_ACTIVITY_SCALE]  = { "Skala bis",                "scale to" },
    [S_ACTIVITY_TYPES]  = { "Nachrichtentypen seit dem letzten Neustart",
                            "Message types since the last restart" },
    /* Detail line under the message counter. In both languages it is a substring of
     * S_ACTIVITY_TYPES on purpose, so both name the same period in the same words. */
    [S_SINCE_BOOT]      = { "seit dem letzten Neustart",
                            "since the last restart" },
    /* Also the types value of /status.json before the first message: no double quote. */
    [S_ACTIVITY_NONE]   = { "Noch keine Nachrichten empfangen.", "No messages received yet." },
    [S_TYPE_HINT]       = { "Typ = Absender + Nachricht, zum Beispiel <code>Car CAM</code>. "
                            "Einige Absender: Car (Auto), Bus, Ped (Fu&szlig;g&auml;nger), Tram "
                            "(Stra&szlig;enbahn), RSU (Anlage am Stra&szlig;enrand, etwa eine "
                            "Ampel).<br><br>Einige Nachrichten: CAM = Fahrzeug-Status, DENM = "
                            "Warnung, SPATEM = Ampelphase, MAPEM = Kreuzungskarte, SREM = "
                            "Ampelanforderung, IVIM = Verkehrszeichen, CPM = erkannte "
                            "Objekte.<br><br><code>Signed</code>: gesicherte Nachricht, die das "
                            "Ger&auml;t nicht lesen kann, etwa weil sie verschl&uuml;sselt "
                            "ist.<br><br><code>IPv6</code>, "
                            "<code>WSMP</code>: andere Protokolle. <code>?</code>: unbekanntes "
                            "Format oder Frame zu kurz.",
                            "Type = sender + message, for example <code>Car CAM</code>. Some "
                            "senders: Car, Bus, Ped (pedestrian), Tram, RSU (roadside unit, such "
                            "as a traffic light).<br><br>Some messages: CAM = vehicle status, "
                            "DENM = hazard warning, SPATEM = signal phase and timing, MAPEM = "
                            "intersection map, SREM = signal request, IVIM = road signs, CPM = "
                            "detected objects.<br><br><code>Signed</code>: a secured message the "
                            "device cannot read, for example because it is "
                            "encrypted.<br><br><code>IPv6</code>, <code>WSMP</code>: other protocols. "
                            "<code>?</code>: unknown format or frame too short." },
    [S_LOG_SYS]         = { "System-Log schreiben",     "Write the system log" },
    [S_LOG_BUDGET]      = { "System-Log: h&ouml;chstens (MB)", "System log: at most (MB)" },
    [S_LOG_HINT] = {
        "Das System-Log liegt in /sdcard/logs/system.log, zwei Dateien im Wechsel. Die "
        "Gr&ouml;&szlig;e hier gilt nur f&uuml;r diese beiden Dateien. Daf&uuml;r muss eine "
        "SD-Karte eingebunden sein.",
        "The system log is in /sdcard/logs/system.log, two files in rotation. The size set here "
        "applies to these two files only. It needs a mounted SD card." },
    [S_PCAP_ENABLE]       = { "Frames aufzeichnen",                   "Record frames" },
    [S_PCAP_RETAIN_HOURS] = { "Aufzeichnung aufbewahren (h)",
                              "Keep the recording for (h)" },
    [S_PCAP_MAX_MB]       = { "Aufzeichnung: h&ouml;chstens (MB)",    "Recording: at most (MB)" },
    [S_PCAP_HINT] = {
        "Speichert die rohen Funk-Frames in /sdcard/pcap/, eine Datei je Stunde. Wireshark und "
        "tshark k&ouml;nnen sie &ouml;ffnen. Daf&uuml;r muss eine SD-Karte eingebunden sein.",
        "Stores the raw radio frames in /sdcard/pcap/, one file per hour. Wireshark and tshark "
        "can open them. It needs a mounted SD card." },
    [S_PCAP_BUF_MB]       = { "PCAP-RAM-Puffer (MB)",                "PCAP RAM buffer (MB)" },
    [S_PCAP_BUF_HINT] = {
        "Das Ger&auml;t sammelt empfangene Frames zuerst im Zusatzspeicher (PSRAM) und schreibt "
        "sie dann gesammelt auf die SD-Karte. Ethernet h&auml;ngt an derselben Leitung, und "
        "wenige gro&szlig;e Schreibvorg&auml;nge unterbrechen das Netz seltener als viele "
        "kleine.<br><br>M&ouml;glich sind 1 bis 4&nbsp;MB, voreingestellt ist 1&nbsp;MB. Ein "
        "gr&ouml;&szlig;erer Puffer hilft, wenn die SD-Karte kurz langsam ist, denn Frames gehen "
        "erst verloren, wenn er voll ist. Bei einem Stromausfall fehlt, was seit dem letzten "
        "Schreiben ankam.",
        "The device first collects received frames in the extra memory (PSRAM) and then writes "
        "them to the SD card together. Ethernet shares the same line, and a few large writes "
        "interrupt the network less often than many small ones.<br><br>Possible are 1 to "
        "4&nbsp;MB, the default is 1&nbsp;MB. A larger buffer helps when the SD card is slow for "
        "a while, because frames are only lost when it is full. On a power cut, whatever arrived "
        "since the last write is missing." },
    [S_PCAP_FLUSH_SEC]    = { "Sp&auml;testens schreiben nach (s)",
                              "Write to the SD card at least every (s)" },
    [S_PLAYBACK_FROM]   = { "Von",                       "From" },
    [S_PLAYBACK_TO]     = { "bis",                       "to" },
    [S_PLAYBACK_LOAD]   = { "Laden",                     "Load" },
    [S_PLAYBACK_LIVE]   = { "Live",                      "Live" },
    [S_PLAYBACK_NONE]   = { "In diesem Zeitraum wurde nichts mit Position aufgezeichnet.",
                            "Nothing with a position was recorded in this period." },
    [S_PLAYBACK_ERROR]  = { "Fehler beim Laden.", "Error loading." },
    /* Its own sentence for an input that makes no sense. The text of a failed query would send
     * the user looking for a fault in the device. JS literal: real UTF-8, no entity, no
     * apostrophe, no straight double quote. */
    [S_PLAYBACK_RANGE]  = { "Bitte beide Felder bei „Zeitraum“ ausfüllen. Das zweite muss "
                            "später liegen.",
                            "Please fill in both “Period” fields. The second one has to be "
                            "later." },
    /* Rendered via textContent, so no HTML entities here -- they would show
     * up literally as "&hellip;" instead of an ellipsis. */
    [S_PLAYBACK_BUSY]   = { "Liest die SD-Karte…",
                            "Reading the SD card…" },
    /* Two causes: the period was cut to four hours, or the SD card was busy. The text names
     * both, each with its condition. The same JS sink as S_PLAYBACK_RANGE. */
    [S_PLAYBACK_PARTIAL] = {
        "Nur ein Teil des Zeitraums ist zu sehen. Bei mehr als vier Stunden sind es die ersten "
        "vier, den Rest zeigt ein neues „Laden“ mit späterem Beginn. Bei kürzerem Zeitraum war "
        "die SD-Karte belegt oder gestört, dann hilft oft ein neues „Laden“.",
        "Only part of the period is shown. For more than four hours it is the first four, and a "
        "new “Load” with a later start shows the rest. For shorter periods the SD card was busy "
        "or had an error, and another “Load” often helps." },
    [S_PLAYBACK_STEP]   = { "Schritt",                   "Step" },
    /* Name of the layer button on /map, where Leaflet only has the English "Layers". Goes into
     * a JS variable and is set with .title, so no entities. */
    [S_MAP_LAYERS]      = { "Kartenebenen",              "Map layers" },
    [S_MAP_LAYER_DARK]  = { "Dunkel",                    "Dark" },
    [S_MAP_LAYER_LIGHT] = { "Hell",                      "Light" },
    [S_MAP_LAYER_TRACKS]= { "Gefahrene Wege",            "Vehicle tracks" },
    /* Only offered when other receivers are configured -- see MAP_SCRIPT. */
    [S_MAP_LAYER_TRACKS_P]= { "Gefahrene Wege anderer Empf&auml;nger",
                              "Vehicle tracks of other receivers" },
    [S_MAP_TRACK_PTS]   = { "Punkte",                    "points" },
    /* Goes to the map via textContent, which does NOT decode HTML entities,
     * so this entry is plain UTF-8. */
    [S_MAP_TRACK_CAP]   = { "Gefahrene Wege gekürzt – die ältesten Punkte des Zeitraums fehlen",
                            "vehicle tracks shortened – the oldest points of the period are "
                            "missing" },
    [S_MAP_SEEN_BY]     = { "empfangen von",             "received by" },
    [S_MAP_TRACK_DUR]   = { "Dauer",                     "duration" },
    /* Shown via alert(), which does NOT decode entities -- plain UTF-8, and no
     * apostrophe, because it travels as a JS string literal. */
    [S_MAP_BUSY]        = { "Ein anderer Abruf läuft gerade. Bitte gleich noch einmal einschalten.",
                            "Another transfer is running. Switch the layer on again in a moment." },
    [S_PEERS]           = { "Andere Empf&auml;nger",     "Other receivers" },
    [S_PEERS_HINT]  = { "Hostnamen oder IP-Adressen weiterer Empf&auml;nger mit dieser Firmware, "
                        "mit Komma getrennt, zum Beispiel <code>its-node344.local, "
                        "192.168.178.40</code>.<br><br>Die Seite "
                        "&bdquo;<a href='/map?lang=de'>Karte</a>&ldquo; zeigt dann auch deren "
                        "Sender, und die Ebene &bdquo;Gefahrene Wege anderer "
                        "Empf&auml;nger&ldquo; deren Wege. Die Seite "
                        "&bdquo;<a href='/?lang=de#sec-peer'>Status</a>&ldquo; zeigt je "
                        "Empf&auml;nger Laufzeit, MQTT, Nachrichten pro Minute und Zustand. Die "
                        "Liste gilt nur f&uuml;r dieses Ger&auml;t.<br><br>Der Browser fragt die "
                        "anderen Empf&auml;nger direkt ab, nicht &uuml;ber dieses Ger&auml;t. "
                        "Darum muss der Browser sie erreichen k&ouml;nnen.",
                        "Host names or IP addresses of other receivers running this firmware, "
                        "comma-separated, for example <code>its-node344.local, "
                        "192.168.178.40</code>.<br><br>The "
                        "&ldquo;<a href='/map?lang=en'>Map</a>&rdquo; page then shows their "
                        "senders too, and the &ldquo;Vehicle tracks of other receivers&rdquo; "
                        "layer shows their tracks. The "
                        "&ldquo;<a href='/?lang=en#sec-peer'>Status</a>&rdquo; page shows "
                        "uptime, MQTT, messages per minute and state for each receiver. The list "
                        "applies to this device only.<br><br>The browser queries the other "
                        "receivers directly, not through this device. So the browser must be "
                        "able to reach them." },
    /* Set via innerText -- plain text, no HTML entities. */
    [S_UPD_WAIT]        = { "warte auf Neustart",        "waiting for restart" },
    /* innerText/textContent -- plain text, no HTML entities. */
    [S_UPD_FLASHING]    = { "Ger\\u00e4t schreibt die Firmware\\u2026 Bitte warten.",
                            "Device is writing the firmware\\u2026 Please wait." },
    /* Each option states what is recorded IN FULL, not just what gets thinned:
     * otherwise the middle one reads as if it dropped everything else. */
    [S_PCAP_FILTER]     = { "Umfang der Aufzeichnung",   "What gets recorded" },
    [S_PCAP_FILT_ALL]   = { "alles, ungek&uuml;rzt",     "everything, in full" },
    [S_PCAP_FILT_THIN]  = { "alles, aber je Sekunde nur eine Ampelphase und eine Kreuzungskarte",
                            "everything, but only one signal phase and one intersection map per "
                            "second" },
    [S_PCAP_FILT_VEH]   = { "alles au&szlig;er Ampelphasen und Kreuzungskarten",
                            "everything except signal phases and intersection maps" },
    [S_PCAP_FILT_HINT] = {
        "Ampeln senden ihre Phasen und ihre Kreuzungskarte immer wieder. Das f&uuml;llt oft den "
        "gr&ouml;&szlig;ten Teil der Aufzeichnung. Die Auswahl k&uuml;rzt nur diese zwei "
        "Nachrichtenarten. Jeder aufgezeichnete Frame bleibt vollst&auml;ndig und "
        "unver&auml;ndert.<br><br><b>Wichtig:</b> Die Grenze je Sekunde gilt f&uuml;r alle "
        "Ampeln zusammen. Aufgezeichnet wird die Nachricht, die in der Sekunde zuerst ankommt. "
        "Bei zwei Kreuzungen in Reichweite kann darum eine ganz fehlen. L&uuml;ckenlos ist nur "
        "&bdquo;alles, ungek&uuml;rzt&ldquo;.",
        "Traffic lights send their phases and their intersection map over and over. That often "
        "fills most of the recording. This choice only cuts these two message kinds. Each "
        "recorded frame stays complete and unchanged.<br><br><b>Note:</b> The per-second limit "
        "holds for all traffic lights together. The message that arrives first in each second is "
        "recorded. With two intersections in range, one can be missing entirely. Only "
        "&ldquo;everything, in full&rdquo; has no gaps." },
    [S_TRACKS_ENABLE]   = { "Gefahrene Wege aufzeichnen", "Record vehicle tracks" },
    [S_TRACKS_DAYS]     = { "Gefahrene Wege aufbewahren (Tage)", "Keep vehicle tracks for (days)" },
    [S_TRACKS_HINT] = {
        "Zeichnet auf, wo Fahrzeuge gefahren sind, und zeigt es auf der Seite "
        "&bdquo;<a href='/map?lang=de'>Karte</a>&ldquo; als Ebene &bdquo;Gefahrene Wege&ldquo; "
        "zum Zuschalten. Ein Fahrzeug bekommt einen neuen Punkt erst nach mindestens 2 Sekunden "
        "und einigen Metern Weg.<br><br>An einer Kreuzung kamen so rund 150 Punkte pro Stunde "
        "zusammen, f&uuml;r alle Fahrzeuge, gut 150 KB am Tag. Die Aufzeichnung beginnt, sobald "
        "die Einstellung gespeichert ist. Fr&uuml;here Fahrten holt das Ger&auml;t nicht aus der "
        "PCAP-Aufzeichnung nach.<br><br>Die Karte l&auml;dt h&ouml;chstens 26000 Punkte. Wenn es "
        "mehr sind, fehlen die &auml;ltesten, und die Karte zeigt einen Hinweis.",
        "Records where vehicles drove and shows it on the "
        "&ldquo;<a href='/map?lang=en'>Map</a>&rdquo; page as the &ldquo;Vehicle tracks&rdquo; "
        "layer, which can be switched on. A new point needs at least 2 seconds and a short move "
        "since the last one.<br><br>At one intersection that came to about 150 points an hour "
        "for all vehicles together, some 150 KB a day. Recording starts once the setting is "
        "saved. The device does not fetch earlier journeys from the PCAP recording.<br><br>The "
        "map loads at most 26000 points. If there are more, the oldest are missing, and the map "
        "shows a notice." },
    [S_ETH_LEDS]        = { "Netzwerk-LEDs",             "Network LEDs" },
    [S_ETH_LEDS_HINT] = {
        "Die zwei LEDs an der Netzwerkbuchse zeigen Verbindung und Datenverkehr. Ohne die LEDs "
        "l&auml;uft das Ger&auml;t genauso, man sieht die Verbindung dann nur nicht mehr an der "
        "Buchse. Die &Auml;nderung wirkt sofort.",
        "The two LEDs on the network socket show link and traffic. Without them the device works "
        "the same, you just no longer see the link at the socket. The change applies at once." },
    [S_BT_ENABLE]       = { "Bluetooth",                 "Bluetooth" },
    /* The two percentages are duty cycles -- recompute from s_cycle_ms and the
     * slicing constants in bt_stream.c. Loss starts at BT on, not at connect. */
    [S_BT_HINT] = {
        "Bluetooth teilt sich das Funkteil mit dem Empfang auf 5,9 GHz. Sobald es eingeschaltet "
        "ist, gehen rund 25&nbsp;% der Frames verloren, solange ein Handy verbunden ist rund "
        "48&nbsp;%.<br><br>Die Aufzeichnung auf der SD-Karte und die Weitergabe per MQTT laufen "
        "weiter, nur mit L&uuml;cken.",
        "Bluetooth shares the radio with the reception on 5.9 GHz. As soon as it is on, about "
        "25&nbsp;% of frames are lost, and about 48&nbsp;% while a phone is "
        "connected.<br><br>Recording to the SD card and forwarding over MQTT keep running, just "
        "with gaps." },
    /* Stays visible with the explanations off: which file, and the step after it. The quote
     * is S_CONFIRM_BTN. */
    [S_UPD_FILE]    = { "Die Datei <code>its-g5-receiver-firmware.bin</code> w&auml;hlen und "
                        "hochladen.<br>Nach dem Neustart oben &bdquo;Update jetzt "
                        "best&auml;tigen&ldquo; dr&uuml;cken.",
                        "Pick <code>its-g5-receiver-firmware.bin</code> and upload it.<br>After "
                        "the restart, press &ldquo;Confirm update now&rdquo; at the top." },
    /* Only the background, as an explanation. The notice after the restart is the one with the
     * button that S_UPD_FILE names right above. */
    [S_UPD_INTRO] = {
        "Das Ger&auml;t schreibt die Datei neben die bisherige Firmware und startet neu. Nach "
        "dem Neustart sagt ein Hinweis, ob es ohne Best&auml;tigung nach 30 Minuten wieder die "
        "vorige Firmware startet.",
        "The device writes the file next to the old firmware and restarts. After the restart a "
        "notice says whether it goes back to the old one when nobody confirms within 30 minutes." },
    /* Says "flash", not just "upload": the button starts the flash and the
     * reboot in one step, with no separate "apply". */
    [S_UPLOAD]          = { "Hochladen &amp; flashen",   "Upload &amp; flash" },
    /* S_UPLOADING is injected into JS and shown via innerText, which does NOT
     * decode HTML entities. Use a JS \u escape (not &auml;) so it renders. */
    [S_UPLOADING]       = { "L\\u00e4dt hoch\\u2026",
                            "Uploading\\u2026" },
    /* Same JS \u-escape reasoning as S_UPLOADING (this one is shown via
     * alert(), which also doesn't decode HTML entities). */
    [S_UPD_CHOOSE_FILE] = { "Bitte zuerst eine Datei w\\u00e4hlen",
                            "Please choose a file first" },
    /* Goes into the aria-label, so HTML. A JS escape would show there as it is. */
    [S_UPD_FILE_LABEL]  = { "Firmware-Datei w&auml;hlen", "Choose firmware file" },
    /* Goes to innerText: real umlauts, no entities. The httpd answers a 401 with its English
     * default text, which does not belong here. */
    [S_UPD_DENIED]      = { "Hochladen abgelehnt \u2013 Web-Passwort n\u00f6tig.",
                            "Upload refused - web password required." },
    [S_UPLOAD_OK] = {
        "Firmware erfolgreich geschrieben. Nach dem Neustart die neue Firmware bestätigen. "
        "Neustart…",
        "Firmware written successfully. Confirm the new firmware after the restart. Restarting…" },
    /* innerText, real UTF-8. The connection can break after the boot slot was switched, so
     * this must not claim the old firmware still runs. */
    [S_UPLOAD_FAIL]     = { "Hochladen abgebrochen: keine Antwort vom Gerät. Bitte die Seite neu "
                            "laden und nachsehen, welche Version läuft.",
                            "Upload stopped: no answer from the device. Please reload the page "
                            "and check which version is running." },
    /* Hit when a new OTA is attempted while the running app is still
     * unconfirmed (ESP-IDF refuses by design). Shown via .innerText, so
     * literal UTF-8 umlauts, not &auml;-style entities. */
    [S_UPD_NOT_CONFIRMED] = {
        "Kein neues Update möglich: Die laufende Firmware ist noch nicht bestätigt. Bitte zuerst "
        "oben auf „Update jetzt bestätigen“ klicken. Wenn der Knopf fehlt, die Seite neu laden.",
        "No new update possible: the running firmware is not confirmed yet. Please click "
        "“Confirm update now” above first. If the button is missing, reload the page." },
    /* The state lines of the update page and the notice after an update that did not start.
     * HTML. */
    [S_UPD_RUNNING]     = { "L&auml;uft jetzt:",        "Running now:" },
    [S_UPD_ST_OK]       = { "best&auml;tigt",           "confirmed" },
    [S_UPD_ST_PENDING]  = { "noch nicht best&auml;tigt", "not confirmed yet" },
    [S_UPD_LAST_FAILED] = { "Zuletzt nicht angelaufen:", "Last failed update:" },
    /* Two %s: the version that did not start, then the one running now. */
    [S_UPD_FAILED_ABORT] = { "Das Update auf %s ist nicht angelaufen. Das Ger&auml;t ist neu "
                             "gestartet, bevor das Update best&auml;tigt war: nach einem Absturz, "
                             "einem Stromausfall oder einem Neustart. Jetzt l&auml;uft wieder %s.",
                             "The update to %s did not work. The device restarted before the "
                             "update was confirmed: after a crash, a power cut or a restart. It "
                             "now runs %s again." },
    [S_UPD_FAILED_INVALID] = { "Das Update auf %s ist nicht angelaufen. Niemand hat es innerhalb "
                               "von 30 Minuten best&auml;tigt, oder es wurde von Hand "
                               "zur&uuml;ckgenommen. Jetzt l&auml;uft wieder %s.",
                               "The update to %s did not work. Nobody confirmed it within 30 "
                               "minutes, or it was undone by hand. It now runs %s again." },
    [S_UPD_FAILED_HIDE] = { "Hinweis ausblenden",       "Hide notice" },
    /* JS literals, alert, innerText and HTTP text bodies: real UTF-8, no apostrophe, no <,
     * no entity. */
    [S_UPD_HIDE_DENIED] = { "Nicht ausgeblendet – Web-Passwort nötig.",
                            "Not hidden - web password required." },
    [S_UPD_HIDE_NOCONN] = { "Keine Antwort vom Gerät. Bitte die Seite neu laden und nochmal "
                            "versuchen.",
                            "No answer from the device. Please reload the page and try again." },
    [S_UPD_ERR_NOFW]    = { "Das ist keine Firmware-Datei für dieses Gerät, oder sie ist "
                            "beschädigt. Richtig ist its-g5-receiver-firmware.bin.",
                            "This is not a firmware file for this device, or it is damaged. The "
                            "right one is its-g5-receiver-firmware.bin." },
    [S_UPD_ERR_CHIP]    = { "Diese Firmware ist für einen anderen Chip gebaut. Auf diesem Gerät "
                            "läuft sie nicht.",
                            "This firmware is built for another chip. It does not run on this "
                            "device." },
    [S_UPD_ERR_SIZE]    = { "Die Datei ist zu groß für den Platz auf dem Gerät. Richtig ist "
                            "its-g5-receiver-firmware.bin.",
                            "The file is too big for the space on the device. The right one is "
                            "its-g5-receiver-firmware.bin." },
    [S_UPD_ERR_CUT]     = { "Hochladen abgebrochen, die Verbindung ist abgerissen. Die alte "
                            "Firmware läuft weiter. Bitte nochmal versuchen.",
                            "Upload stopped, the connection broke. The old firmware keeps "
                            "running. Please try again." },
    /* One %s: the esp_err_to_name code, kept for bug reports. */
    [S_UPD_ERR_FLASH]   = { "Das Gerät konnte die Datei nicht übernehmen (%s). Die alte Firmware "
                            "läuft weiter. Bitte nochmal versuchen, sonst das Gerät neu starten.",
                            "The device could not take the file (%s). The old firmware keeps "
                            "running. Please try again, or restart the device." },
    [S_UPD_FILEVER]     = { "Version in der Datei:",    "Version in the file:" },
    [S_UPD_SAMEVER]     = { "diese Version läuft schon", "this version is already running" },
    [S_UPD_OTHER_PROJ]  = { "Diese Datei enthält eine andere Firmware, nicht die für diesen "
                            "Empfänger. Trotzdem hochladen?",
                            "This file holds a different firmware, not the one for this receiver. "
                            "Upload anyway?" },
    /* The page appends the version in brackets when it knows it. */
    [S_UPD_BACK_OLD]    = { "Das Update ist nicht angelaufen. Das Gerät läuft wieder mit der "
                            "vorigen Firmware.",
                            "The update did not work. The device is back on its previous "
                            "firmware." },
    [S_UPD_SLOW]        = { "Das Gerät meldet sich nicht mehr. Bitte die Seite später neu laden.",
                            "The device is not answering. Please reload the page later." },
    [S_NAV_SD]          = { "Dateien",                  "Files" },
    [S_TITLE_SD]        = { "Dateien",                  "Files" },
    /* Heading of the last group on /sdcard: the chip's own storage, as opposed to the card. */
    [S_FS_FLASH]        = { "Flash des Ger&auml;ts",    "Device flash memory" },
    [S_FS_PARTITIONS]   = { "Flash-Partitionen",        "Flash partitions" },
    [S_FS_SDCARD]       = { "SD-Karte",                 "SD card" },
    [S_FS_MOUNT_AT]     = { "eingebunden unter",        "mounted at" },
    [S_FS_INTERNAL]     = { "Interner Speicher",        "Internal storage" },
    [S_FS_NOTE] = {
        "Die Tabelle zeigt die Bereiche des Flash-Speichers. Nur <code>storage</code> hat "
        "Ordner, ein Klick auf den Namen &ouml;ffnet sie. Die &uuml;brigen Bereiche haben keine "
        "Ordner, zum Beispiel <code>nvs</code> mit den Einstellungen und "
        "<code>ota_0</code>/<code>ota_1</code> mit der Firmware.<br><br><code>&darr; .img</code> "
        "l&auml;dt einen Bereich als Ganzes herunter, Byte f&uuml;r Byte.",
        "The table shows the areas of the flash memory. Only <code>storage</code> has folders; a "
        "click on its name opens them. The other areas have no folders, for example "
        "<code>nvs</code> with the settings and <code>ota_0</code>/<code>ota_1</code> with the "
        "firmware.<br><br><code>&darr; .img</code> downloads an area as a whole, byte for byte." },
    [S_TAR_SELECTED]    = { "Auswahl (.tar)",           "Selection (.tar)" },
    [S_TAR_NONE]        = { "Nichts markiert.",         "Nothing selected." },
    [S_TAR_HINT]        = { "Gro&szlig;e Dateien brauchen zum Herunterladen mehrere Minuten. Die "
                            "Seiten lassen sich derweil weiter bedienen.<br><br>Das Ger&auml;t "
                            "arbeitet Dateiabrufe, Suchen und Kartenabrufe nacheinander ab, bis "
                            "zu zwei warten. Ein weiterer bekommt statt der Datei nur "
                            "<code>Besch&auml;ftigt</code>.",
                            "Larger downloads take several minutes. The pages stay usable "
                            "meanwhile.<br><br>The device handles downloads, searches and map "
                            "requests one by one, and up to two wait. One more gets only "
                            "<code>Busy</code> instead of the file." },
    [S_SD_NOT_MOUNTED]  = { "Keine SD-Karte eingebunden.", "No SD card mounted." },
    /* Four different situations, and only the first is worth formatting for. */
    [S_SD_ERR_NOFS] = {
        "Die SD-Karte antwortet, hat aber kein lesbares FAT-Dateisystem. Formatieren richtet sie "
        "ein und l&ouml;scht dabei den vorhandenen Inhalt.",
        "The SD card answers but has no readable FAT filesystem. Formatting sets it up and "
        "erases what is on it." },
    [S_SD_ERR_NOCARD] = {
        "Die SD-Karte antwortet nicht. Steckt sie richtig? Formatieren hilft in diesem Fall "
        "nicht.",
        "The SD card does not answer. Is it seated properly? Formatting does not help here." },
    [S_SD_ERR_UNMOUNTED] = { "Die SD-Karte wurde absichtlich ausgeh&auml;ngt, zum Beispiel mit "
                             "&bdquo;Zum Ausschalten vorbereiten&ldquo;. Der Knopf "
                             "&bdquo;Einbinden&ldquo; holt sie zur&uuml;ck. Formatieren ist nicht "
                             "n&ouml;tig.",
                             "The SD card was unmounted on purpose, for example by &ldquo;Prepare "
                             "for power-off&rdquo;. The &ldquo;Mount&rdquo; button brings it "
                             "back. Formatting is not needed." },
    [S_SD_ERR_WRITEFAIL] = {
        "Die SD-Karte lie&szlig; sich nicht mehr beschreiben, auch ein Testschreibvorgang schlug "
        "fehl. Darum wurde sie ausgeh&auml;ngt.<br><br>Das Ger&auml;t versucht alle 30 Sekunden, "
        "sie wieder einzubinden. Wenn danach wieder kein Schreibvorgang klappt, bleibt sie "
        "ausgeh&auml;ngt, bis man sie hier einbindet oder das Ger&auml;t neu startet.",
        "The SD card could no longer be written, a test write failed too. So it was "
        "unmounted.<br><br>The device tries to mount it again every 30 seconds. If no write "
        "works after that, it stays unmounted until it is mounted here or the device restarts." },
    [S_SD_ERR_WRITEFAIL_OUT] = {
        "Die SD-Karte lie&szlig; sich nicht mehr beschreiben, auch ein Testschreibvorgang schlug "
        "fehl. Darum wurde sie ausgeh&auml;ngt. Das Ger&auml;t versucht nicht mehr, sie "
        "einzubinden. Zur&uuml;ck kommt sie mit &bdquo;Einbinden&ldquo; oder einem Neustart.",
        "The SD card could no longer be written, a test write failed too. So it was unmounted. "
        "The device no longer tries to mount it. &ldquo;Mount&rdquo; or a restart brings it back." },
    [S_SD_TAKEN_OUT]    = { "SD-Karte nach Schreibfehlern ausgeh&auml;ngt.",
                            "SD card taken out after failed writes." },
    /* Short lines for the SD tile on the start page, also in sdui of /status.json: no double
     * quote, no backslash. /sdcard keeps the long S_SD_ERR_* texts. */
    [S_SD_TILE_UNMOUNTED] = { "Die SD-Karte wurde absichtlich ausgeh&auml;ngt. Mit "
                              "&bdquo;Einbinden&ldquo; auf der Seite &bdquo;Dateien&ldquo; kommt "
                              "sie zur&uuml;ck.",
                              "The SD card was unmounted on purpose. &ldquo;Mount&rdquo; on the "
                              "&ldquo;Files&rdquo; page brings it back." },
    [S_SD_TILE_NOFS]    = { "Die SD-Karte hat kein lesbares Dateisystem. Mehr dazu auf der Seite "
                            "&bdquo;Dateien&ldquo;.",
                            "The SD card has no readable filesystem. More on the "
                            "&ldquo;Files&rdquo; page." },
    /* Label before ": N". It is the same counter as S_LOSS_FLUSHFAIL on /system. */
    [S_SD_FAILS_BOOT]   = { "Schreibfehler seit dem letzten Neustart",
                            "Write errors since the last restart" },
    [S_SD_ERR_USAGE]    = { "Die SD-Karte ist eingebunden, aber das Ger&auml;t kann nicht ablesen, "
                            "wie voll sie ist. Wenn das so bleibt, die Karte pr&uuml;fen.",
                            "The SD card is mounted, but the device cannot tell how full it is. If "
                            "this persists, check the card." },
    [S_LOGS_CONSOLE]    = { "Konsole", "Console" },
    [S_LOGS_CONSOLE_HINT] = {
        "Die letzten 64 Meldungen des Ger&auml;ts, gehalten im Arbeitsspeicher. Ein Neustart "
        "l&ouml;scht sie, daf&uuml;r gibt es sie auch ohne SD-Karte. Das System-Log oben braucht "
        "dagegen die SD-Karte.",
        "The device's last 64 messages, kept in RAM. A restart clears them, but they are there "
        "even without an SD card. The system log above needs the SD card." },
    [S_SD_MOUNT]        = { "Einbinden",               "Mount" },
    [S_SD_USAGE]        = { "Belegung",                 "Usage" },
    [S_SD_USED_OF]      = { "%s von %s belegt (%s frei)", "%s of %s used (%s free)" },
    [S_SD_NAME]         = { "Name",                     "Name" },
    [S_SD_SIZE]         = { "Gr&ouml;&szlig;e",         "Size" },
    [S_SD_EMPTY]        = { "Der Ordner ist leer.",     "The folder is empty." },
    [S_A11Y_SELECT_ALL] = { "Alle ausw&auml;hlen",        "Select all" },
    [S_A11Y_SELECT_ROW] = { "Ausw&auml;hlen",             "Select" },
    [S_A11Y_ACTIONS]    = { "Aktionen",                   "Actions" },
    [S_SD_PARENT]       = { ".. (h&ouml;her)",          ".. (up)" },
    [S_SD_DELETE]       = { "L&ouml;schen",             "Delete" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SD_DELETE_CONFIRM] = { "Datei löschen?",         "Delete file?" },
    [S_SD_DELETE_SELECTED] = { "Auswahl l&ouml;schen",  "Delete selection" },
    /* Used inside a JS confirm() call in a <script> block, whose content the
     * browser does not entity-decode: raw UTF-8, no HTML entities. */
    [S_SD_DELETE_SEL_CONFIRM] = { "Ausgewählte Dateien/Ordner löschen?",
                                  "Delete selected files/folders?" },
    [S_RSU_UP_TITLE]    = { "Anlagen am Stra&szlig;enrand nachliefern",
                            "Re-send roadside unit frames" },
    [S_RSU_UP_HINT] = {
        "Das Ger&auml;t schickt jeden empfangenen Frame laufend per MQTT weiter, ab Werk an "
        "opentrafficmap.<br><br>Wenn die Verbindung unterbrochen war, fehlen opentrafficmap "
        "diese Frames. F&uuml;r Ampeln und andere Anlagen am Stra&szlig;enrand kann man sie hier "
        "nachschicken.<br><br>Die Frames kommen aus der Aufzeichnung auf der SD-Karte, "
        "h&ouml;chstens 24&nbsp;Stunden auf einmal. Fahrzeuge sind nie "
        "dabei.<br><br>&bdquo;Ausd&uuml;nnung&ldquo; legt fest, wie viele Frames geschickt "
        "werden: ab Werk einer je Anlage und Nachrichtentyp f&uuml;r den ganzen Zeitraum, sonst "
        "einer je Stunde oder je 10 Minuten.<br><br>F&uuml;r den Eintrag auf der Karte von "
        "opentrafficmap reicht die Voreinstellung.",
        "The device forwards every received frame over MQTT as it arrives, to opentrafficmap by "
        "default.<br><br>While the connection was down, opentrafficmap misses those frames. For "
        "traffic lights and other roadside units they can be re-sent here.<br><br>The frames "
        "come from the recording on the SD card, 24&nbsp;hours at most per run. Vehicles are "
        "never included.<br><br>&ldquo;Thinning&rdquo; sets how many frames are sent: by default "
        "one per unit and message type for the whole period, otherwise one per hour or per 10 "
        "minutes.<br><br>The default is enough for the entry on the opentrafficmap map." },
    [S_RSU_UP_THIN]     = { "Ausd&uuml;nnung",           "Thinning" },
    [S_RSU_UP_ONCE]     = { "1 Frame je Anlage und Typ", "1 frame per unit and type" },
    [S_RSU_UP_BTN]      = { "An opentrafficmap senden",  "Send to opentrafficmap" },
    [S_RSU_UP_NOMQTT] = {
        "MQTT ist nicht verbunden, es wurde nichts gesendet.",
        "MQTT is not connected, nothing was sent." },
    [S_RSU_UP_RUN]      = { "Sende…",               "Sending…" },
    [S_RSU_UP_BUSY]     = { "Läuft bereits.",        "Already running." },
    [S_SRCH_TITLE]      = { "Suche in der Aufzeichnung", "Search the recording" },
    [S_SRCH_HINT] = {
        "Durchsucht die PCAP-Aufzeichnung, h&ouml;chstens 24&nbsp;Stunden auf einmal. Der Filter "
        "sucht in Typ, MAC-Adresse und Stations-Nummer. Die Treffer zeigen keinen Pegel, weil "
        "die Aufzeichnung ihn nicht enth&auml;lt.",
        "Searches the PCAP recording, 24&nbsp;hours at most at a time. The filter looks at type, "
        "MAC address and station ID. The matches show no signal level, because the recording "
        "does not contain it." },
    [S_SRCH_FILTER]     = { "Filter",                   "Filter" },
    [S_SRCH_BTN]        = { "Suchen",                   "Search" },
    [S_SRCH_RUN]        = { "Suche…",                   "Searching…" },
    [S_SRCH_NONE]       = { "Keine Treffer.",           "No matches." },
    [S_SRCH_LIMIT] = {
        "Die Suche zeigt h&ouml;chstens 200 Treffer. Zeitraum oder Filter eingrenzen.",
        "The search shows 200 matches at most. Narrow the period or the filter." },
    [S_SRCH_PARTIAL]    = { "Zeitraum nur teilweise gelesen.", "Period only partly read." },
    /* Goes to text/plain and into a JS literal: real UTF-8, no apostrophe, no double quote. */
    [S_ARCH_BUSY]       = { "Das Gerät ist mit einem anderen Abruf beschäftigt. Bitte gleich "
                            "noch einmal versuchen.",
                            "The device is busy with another transfer. Try again in a moment." },
    [S_SRCH_EXPORT]     = { "Als PCAP herunterladen",      "Download as PCAP" },
    [S_SRCH_EXPORT_HINT] = {
        "&bdquo;Als PCAP herunterladen&ldquo; speichert die Frames des Zeitraums als Datei, mit "
        "&bdquo;Filter&ldquo; nur die passenden. Wenn ein Web-Passwort gesetzt ist, fragt der "
        "Browser danach.<br><br>Die Datei umfasst h&ouml;chstens 24&nbsp;Stunden, bei einem "
        "l&auml;ngeren Zeitraum die letzten 24. Beginn und Ende stehen im Dateinamen.<br><br>Sie "
        "ist h&ouml;chstens 4&nbsp;MB gro&szlig;. Dar&uuml;ber fehlt das Ende, und im Dateinamen "
        "steht <code>cut</code>.<br><br>Wenn das Ger&auml;t nicht alles lesen konnte, etwa weil "
        "die SD-Karte belegt war, steht im Dateinamen <code>partial</code>. Ganze Stunden ohne "
        "diese Grenzen liegen unter <code>/sdcard/pcap/</code> auf der Seite "
        "&bdquo;<a href='/sdcard?lang=de&amp;p=pcap'>Dateien</a>&ldquo;.",
        "&ldquo;Download as PCAP&rdquo; saves the frames of the period as a file, with a "
        "&ldquo;Filter&rdquo; only the matching ones. If a web password is set, the browser asks "
        "for it.<br><br>The file covers 24&nbsp;hours at most, for a longer period the last 24. "
        "The file name gives the start and end.<br><br>It is 4&nbsp;MB at most. Beyond that the "
        "end is missing, and the file name says <code>cut</code>.<br><br>If the device could not "
        "read everything, for example because the SD card was busy, the file name says "
        "<code>partial</code>. Whole hours without these limits are under "
        "<code>/sdcard/pcap/</code> on the "
        "&ldquo;<a href='/sdcard?lang=en&amp;p=pcap'>Files</a>&rdquo; page." },
    [S_SD_FORMAT]       = { "SD-Karte formatieren",        "Format SD card" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SD_FORMAT_CONFIRM] = { "SD-Karte wirklich formatieren? Alle Daten gehen verloren!",
                              "Really format the SD card? All data will be lost!" },
    /* Set via JS innerText -> JS \u escape, no HTML entity. */
    [S_SD_FORMATTING]   = { "Formatiere\\u2026",        "Formatting\\u2026" },
    [S_SD_UP_HERE]      = { "Datei hierher hochladen",  "Upload a file here" },
    [S_SD_UP_BTN]       = { "Hochladen",                "Upload" },
    [S_PEER_TITLE]      = { "Andere Empf&auml;nger",    "Other receivers" },
    [S_PEER_NODE]       = { "Ger&auml;t",                  "Device" },
    [S_PEER_UPTIME]     = { "Laufzeit",                 "Uptime" },
    [S_PEER_MQTT]       = { "MQTT",                     "MQTT" },
    /* A single-quoted JS literal, which the street row of the start page also writes with
     * textContent: no entities, no apostrophe, no backslash. */
    [S_PEER_OFFLINE]    = { "von diesem Browser aus nicht erreichbar",
                            "not reachable from this browser" },
    /* Single-quoted JS literal concatenated into innerHTML: no apostrophes. */
    [S_PEER_NODATA]     = { "keine Daten seit",         "no data for" },
    /* These go into single-quoted JS literals and innerHTML: no apostrophe, no backslash. */
    [S_PEER_LASTOK]     = { "letzte Antwort",           "last answer" },
    [S_PEER_SELF]       = { "dieses Ger&auml;t",        "this device" },
    [S_PEER_OLDFW]      = { "antwortet, liefert aber keine Statusdaten (alte Firmware, Passwort "
                            "oder ein anderer Server)",
                            "answers, but sends no status data (old firmware, a password or a "
                            "different server)" },
    [S_LOSS_TITLE]      = { "Verluste",                 "Losses" },
    [S_LOSS_SNIFFER]    = { "Empfangspuffer voll oder kein Speicher",
                            "Receive queue full or out of memory" },
    [S_LOSS_MQTT]       = { "MQTT-Warteschlange voll",  "MQTT queue full" },
    [S_LOSS_TRACKS]     = { "Punkte gefahrener Wege verworfen", "Vehicle track points discarded" },
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
    [S_LOSS_SD_FAILS]   = { "SD-Karte: l&auml;ngste Fehlserie", "SD card: longest failure run" },
    [S_LOSS_SD_HELD]    = { "SD-Karte: l&auml;ngste Haltezeit", "SD card: longest hold" },
    [S_LOSS_FLUSHFAIL]  = { "SD-Karte: Schreibvorg&auml;nge fehlgeschlagen",
                            "SD card: writes failed" },
    /* The table above counts this session. These three carry over restarts, so
     * they need their own label or they read as more of the same. */
    [S_LOSS_LIFETIME]   = { "&Uuml;ber alle Neustarts (verloren / Schreibfehler / "
                            "SD-Karte ausgeh&auml;ngt)",
                            "Across all restarts (lost / writes failed / SD card taken out)" },
    /* Several paragraphs in one text: web_system.c prints it into a single <p>, and
     * <br><br> separates them without a second id. */
    /* What each row counts was checked against the tile in web_system.c. Six rows count
     * frames, the other eight count pieces, operations or a duration. */
    [S_LOSS_HINT] = {
        "Die Tabelle &bdquo;Verluste&ldquo; z&auml;hlt seit dem letzten Neustart, au&szlig;er in "
        "ihrer letzten Zeile. Jede Zahl &uuml;ber 0 ist farbig markiert.<br><br>Wenn eine Zahl "
        "laufend w&auml;chst, kommt das Ger&auml;t nicht nach: SD-Karte, Netz oder "
        "Arbeitsspeicher sind zu langsam oder voll.<br><br>Die Zeilen unter &bdquo;Zur "
        "Information&ldquo; sind keine Verluste. &bdquo;Bewusst ausged&uuml;nnt&ldquo; "
        "z&auml;hlt, was der eingestellte &bdquo;<a href='/settings?lang=de#pcapfilt'>Umfang der "
        "Aufzeichnung</a>&ldquo; wegl&auml;sst. &bdquo;Empfang pausiert (Dauer)&ldquo; ist die "
        "Zeit, in der Bluetooth das Funkteil nutzt.<br><br>&bdquo;Aufzeichnung verloren "
        "(gesch&auml;tzt)&ldquo;: Bei der Aufzeichnung gehen Frames manchmal blockweise "
        "verloren. Dann ist nur die Zahl der Bytes bekannt, und das Ger&auml;t rechnet sie mit "
        "der mittleren Frame-Gr&ouml;&szlig;e in Frames um.<br><br>Wenn diese Zahl steigt, kann "
        "ein gr&ouml;&szlig;erer &bdquo;<a href='/settings?lang=de#pcapbufmb'>PCAP-RAM-Puffer "
        "(MB)</a>&ldquo; auf der Seite &bdquo;Einstellungen&ldquo; helfen.<br><br>Drei Zeilen "
        "z&auml;hlen Eintr&auml;ge, die nicht in die Warteschlange zur SD-Karte kamen: Punkte "
        "gefahrener Wege, Durchfahrten und Warnungen.<br><br>Sie fehlen dann bei der Ebene "
        "&bdquo;Gefahrene Wege&ldquo; auf der Seite "
        "&bdquo;<a href='/map?lang=de'>Karte</a>&ldquo;, bei den Durchfahrten auf der Seite "
        "&bdquo;<a href='/transit?lang=de'>&Ouml;ffis</a>&ldquo; und bei den "
        "&bdquo;<a href='/traffic?lang=de#denm'>Warnungen (DENM)</a>&ldquo; auf der Seite "
        "&bdquo;Verkehr&ldquo;.<br><br>Auf die SD-Karte darf immer nur ein Teil der Firmware "
        "zugleich schreiben. Die meisten anderen warten bis zu 2&nbsp;Sekunden und versuchen es "
        "sp&auml;ter noch einmal.<br><br>Ihre Daten bleiben so lange im Arbeitsspeicher. "
        "Verloren geht erst etwas, wenn er voll ist.<br><br>Aufzeichnung und System-Log warten "
        "ohne Zeitgrenze. &bdquo;SD-Karte: l&auml;ngste Fehlserie&ldquo; z&auml;hlt, wie oft das "
        "Warten hintereinander gescheitert ist, meist 0.<br><br>&bdquo;SD-Karte: l&auml;ngste "
        "Haltezeit&ldquo; ist die l&auml;ngste Zeit, die ein Teil die SD-Karte belegt hat. "
        "Einige hundert Millisekunden sind normal.<br><br>Die letzte Zeile der Tabelle "
        "&bdquo;Verluste&ldquo; z&auml;hlt &uuml;ber alle Neustarts hinweg: Verluste und "
        "Schreibfehler der Aufzeichnung und wie oft das Ger&auml;t die SD-Karte nach "
        "Schreibfehlern ausgeh&auml;ngt hat.<br><br>Von dieser Tabelle setzt &bdquo;Z&auml;hler "
        "zur&uuml;cksetzen&ldquo; weiter oben nur diese Zeile auf 0.",
        "The table &ldquo;Losses&rdquo; counts since the last restart, except in its last row. "
        "Every number above 0 is marked in color.<br><br>If a number keeps growing, the device "
        "is not keeping up: the SD card, the network or the RAM is too slow or full.<br><br>The "
        "rows under &ldquo;For information&rdquo; are not losses. &ldquo;Thinned on "
        "purpose&rdquo; counts what the chosen &ldquo;<a href='/settings?lang=en#pcapfilt'>What "
        "gets recorded</a>&rdquo; leaves out. &ldquo;Reception paused (duration)&rdquo; is the "
        "time Bluetooth uses the radio.<br><br>&ldquo;Recording lost (estimated)&rdquo;: the "
        "recording sometimes loses frames a whole block at a time. Then only the number of bytes "
        "is known, and the device converts it into frames with the average frame size.<br><br>If "
        "this number grows, a larger &ldquo;<a href='/settings?lang=en#pcapbufmb'>PCAP RAM "
        "buffer (MB)</a>&rdquo; on the &ldquo;Settings&rdquo; page can help.<br><br>Three rows "
        "count entries that missed the queue to the SD card: vehicle track points, passages and "
        "warnings.<br><br>They are then missing from the &ldquo;Vehicle tracks&rdquo; layer on "
        "the &ldquo;<a href='/map?lang=en'>Map</a>&rdquo; page, from the passages on the "
        "&ldquo;<a href='/transit?lang=en'>Transit</a>&rdquo; page and from the "
        "&ldquo;<a href='/traffic?lang=en#denm'>Warnings (DENM)</a>&rdquo; on the "
        "&ldquo;Traffic&rdquo; page.<br><br>Only one part of the firmware may write to the SD "
        "card at a time. Most others wait up to 2&nbsp;seconds and try again later.<br><br>Their "
        "data stays in RAM until then. Nothing is lost unless the RAM fills up.<br><br>The "
        "recording and the system log wait without a time limit. &ldquo;SD card: longest failure "
        "run&rdquo; counts how often waiting failed in a row, mostly 0.<br><br>&ldquo;SD card: "
        "longest hold&rdquo; is the longest time one part kept the SD card busy. A few hundred "
        "milliseconds are normal.<br><br>The last row of &ldquo;Losses&rdquo; counts across all "
        "restarts: losses and failed writes of the recording, and how often the device took the "
        "SD card out after failed writes.<br><br>Of this table, &ldquo;Reset counters&rdquo; "
        "further up sets only this row to 0." },
    /* Not a bare "Details": the fold says what the figures mean, the "thinned" row included. */
    [S_LOSS_SUM] = { "Was die Zahlen bedeuten", "What the figures mean" },
    /* Heading of the second table, whose rows are no losses. Visible with the explanations
     * off; S_LOSS_HINT quotes it. */
    [S_LOSS_INFO]       = { "Zur Information",          "For information" },
    [S_NAV_SYSTEM]      = { "System",                   "System" },
    [S_TITLE_SYSTEM]    = { "System",                   "System" },
    [S_SYS_CHIP]        = { "Chip",                     "Chip" },
    [S_SYS_CORES]       = { "Kerne",                    "Cores" },
    [S_SYS_CPU_FREQ]    = { "CPU-Takt",                 "CPU clock" },
    [S_SYS_RESET]       = { "Grund des letzten Neustarts", "Reason for the last restart" },
    [S_SYS_FLASH]       = { "Flash",                    "Flash" },
    [S_SYS_RAM_INT]     = { "RAM intern",              "RAM internal" },
    [S_SYS_RAM_PSRAM]   = { "PSRAM",                    "PSRAM" },
    [S_SYS_TRIPLE]      = { "frei / kleinster / gesamt", "free / lowest / total" },
    [S_SYS_TASKS]       = { "Tasks",                    "Tasks" },
    [S_SYS_COL_STATE]   = { "Zustand",                  "State" },
    [S_SYS_COL_PRIO]    = { "Prio",                     "Prio" },
    [S_SYS_COL_CPU]     = { "CPU %",                    "CPU %" },
    /* Exact bytes, not KB: a few hundred bytes of stack decide. */
    [S_SYS_COL_STACK]   = { "Stack frei, kleinster (B)", "Stack free, lowest (B)" },
    /* The summary group on the start page. /system names its first group S_SYS_GRP_CHIP,
     * because that group only shows chip and firmware. */
    [S_SYS_GRP_DEVICE]  = { "Ger&auml;t",               "Device" },
    [S_SYS_GRP_CHIP]    = { "Chip und Firmware",        "Chip and firmware" },
    [S_SYS_GRP_STABILITY] = { "Stabilit&auml;t",        "Stability" },
    [S_SYS_GRP_LOAD]    = { "Auslastung",               "Load" },
    [S_SYS_LOAD]        = { "CPU-Last",                 "CPU load" },
    /* Without this the crash count reads as "crashing right now". */
    [S_SYS_CRASH_HINT] = {
        "Die Z&auml;hler laufen seit dem letzten Zur&uuml;cksetzen, nicht seit dem letzten "
        "Neustart. Ein alter Absturz bleibt darum in der Zahl stehen. Daneben steht, wie lange "
        "der letzte Absturz her ist.",
        "The counters run since the last reset, not since the last restart. An old crash "
        "therefore stays in the number. Beside it is how long ago the last crash was." },
    /* Both go into title='...' -- must stay free of apostrophes. */
    [S_TH_WARN]         = { "Warnschwelle erreicht",    "Warning threshold reached" },
    [S_TH_ALARM]        = { "Kritischer Wert",          "Critical value" },
    [S_STAT_BOOTS]      = { "Neustarts gesamt",         "Restarts total" },
    [S_STAT_CRASHES]    = { "Abst&uuml;rze",            "Crashes" },
    [S_STAT_LASTCRASH]  = { "Letzter Absturz",          "Last crash" },
    [S_STAT_MAXUP]      = { "L&auml;ngste Laufzeit",    "Longest uptime" },
    [S_STAT_NEVER]      = { "noch keiner",              "none yet" },
    [S_STAT_RESET]      = { "Z&auml;hler zur&uuml;cksetzen", "Reset counters" },
    [S_STAT_RESET_CONFIRM] = { "Alle Stabilit\u00e4ts-Z\u00e4hler und die Verluste der SD-Karte "
                               "\u00fcber alle Neustarts wirklich auf null setzen?",
                               "Really reset all stability counters and the SD card losses across "
                               "restarts to zero?" },
    [S_NAV_LOGS]        = { "Logs",                     "Logs" },
    [S_TITLE_LOGS]      = { "Logs",                     "Logs" },
    [S_LOGS_SYS]        = { "System-Log",               "System log" },
    [S_LOGS_REFRESH]    = { "Aktualisieren",            "Refresh" },
    /* For the previous log, a missing file is the normal case. system.1.log only appears when
     * system.log reaches half the set size and is renamed. */
    [S_LOGS_NONE_OLD] = {
        "Noch kein vorheriges Log. Es entsteht erst, wenn die laufende Datei die halbe "
        "eingestellte Gr&ouml;&szlig;e erreicht und umbenannt wird.",
        "No previous log yet. It appears once the running file reaches half the set size and is "
        "renamed." },
    [S_LOGS_NONE]       = { "Noch kein System-Log. Ist "
                            "&bdquo;<a href='/settings?lang=de#logsys'>System-Log "
                            "schreiben</a>&ldquo; eingeschaltet und die SD-Karte eingebunden?",
                            "No system log yet. Is "
                            "&ldquo;<a href='/settings?lang=en#logsys'>Write the system "
                            "log</a>&rdquo; switched on and the SD card mounted?" },
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
    /* The line under the filter that hides the temperature messages. "Meldungen" like the
     * counter above, so both numbers add up. HTML spans; the script only switches a class. */
    [S_LOGS_TEMP_HID]   = { "Temperaturmeldungen ausgeblendet", "temperature messages hidden" },
    [S_LOGS_TEMP_SHOWN] = { "Temperaturmeldungen sichtbar", "temperature messages shown" },
    [S_LOGS_SHOW]       = { "zeigen",                   "show" },
    [S_LOGS_HIDE]       = { "ausblenden",               "hide" },
    [S_LOGS_READ_ERR] = {
        "Die SD-Karte hat beim Lesen einen Fehler gemeldet, darum fehlen die neueren Zeilen.",
        "The SD card reported an error while reading, so the newer lines are missing." },
    /* Without this the empty filter result reads as "no errors on this device". */
    [S_LOGS_FILTER_HINT] = {
        "Filter und Suche durchsuchen nur die letzten %d KB, die hier geladen sind. &Auml;ltere "
        "Zeilen stehen nur in der ganzen Datei.",
        "Filter and search only cover the last %d KB loaded here. Older lines are only in the "
        "full file." },
    [S_NAV_SENDERS]     = { "Anlagen",                  "Roadside units" },
    [S_TITLE_SENDERS]   = { "Anlagen am Stra&szlig;enrand, etwa Ampeln",
                            "Roadside units, such as traffic lights" },
    [S_SND_INTRO] = {
        "Ampeln und andere Anlagen am Stra&szlig;enrand, die das Ger&auml;t empfangen hat. Mit "
        "SD-Karte bleibt die Tabelle &uuml;ber einen Neustart erhalten. Fahrzeuge stehen nicht "
        "drin, weil sie laufend ihre Stations-Nummer wechseln.<br><br>In der Spalte "
        "&bdquo;Signatur&ldquo; steht oben das Zertifikat, etwa <code>Kurzkennung "
        "1a2b3c4d&hellip;</code>, darunter das Pr&uuml;fergebnis, etwa "
        "<code>vertrauensw&uuml;rdig &middot; Liste L2 &middot; Kette 2</code>.<br><br>Kette 2 "
        "hei&szlig;t: 2 Signaturen f&uuml;hren bis zu einer obersten Stelle auf der EU-Liste L2, "
        "und alle stimmen. Die EU f&uuml;hrt drei solche Listen: L2 f&uuml;r den echten Betrieb, "
        "L1 f&uuml;r den Probebetrieb, L0 f&uuml;r den Testbetrieb.<br><br>Andere Ergebnisse: "
        "&bdquo;nicht pr&uuml;fbar&ldquo; (dem Ger&auml;t fehlt etwas), "
        "&bdquo;ung&uuml;ltig&ldquo; (Fehler gefunden), &bdquo;zur&uuml;ckgezogen&ldquo; (steht "
        "auf einer Sperrliste).",
        "Traffic lights and other roadside units the device has received. With an SD card the "
        "table survives a restart. Vehicles are not listed, because they keep changing their "
        "station ID.<br><br>The &ldquo;Signature&rdquo; column shows the certificate on top, "
        "such as <code>short identifier 1a2b3c4d&hellip;</code>, and the check result below it, "
        "such as <code>trustworthy &middot; list L2 &middot; chain 2</code>.<br><br>Chain 2 "
        "means: 2 signatures lead up to a root on the EU list L2, and all of them match. The EU "
        "keeps three such lists: L2 for live operation, L1 for pre-production, L0 for "
        "testing.<br><br>Other results: &ldquo;cannot be checked&rdquo; (the device lacks "
        "something), &ldquo;invalid&rdquo; (a fault was found), &ldquo;withdrawn&rdquo; (on a "
        "revocation list)." },
    [S_SND_NONE] = {
        "Noch keine Anlage am Stra&szlig;enrand empfangen.",
        "No roadside unit received yet." },
    [S_SND_TYPES]       = { "Sendet",                   "Sends" },
    [S_SND_FRAMES]      = { "Frames",                   "Frames" },
    [S_SND_LAST]        = { "Zuletzt",                  "Last" },
    [S_SND_POS]         = { "Position",                 "Position" },
    /* One column now holds name, id and MAC -- "Kennung" would be a lie. */
    [S_SND_STATION]     = { "Anlage",                   "Unit" },
    [S_SND_SINCE]       = { "seit",                     "since" },
    [S_SND_VEHICLES]    = { "Dazu kamen %lu Frames von Fahrzeugen, gez&auml;hlt <b>seit dem "
                            "letzten Neustart</b>.",
                            "Plus %lu frames from vehicles, counted <b>since the last "
                            "restart</b>." },
    /* Its own entry, so the switch for the explanations hides it while the number stays. */
    [S_SND_VEH_HINT] = {
        "Ein Fahrzeug sendet viele Frames, darum ist das keine Zahl der Fahrzeuge. Ungef&auml;hr "
        "wie viele Fahrzeuge je Stunde vorbeikamen, zeigt die Seite "
        "&bdquo;<a href='/traffic?lang=de#stats'>Verkehr</a>&ldquo;.",
        "One vehicle sends many frames, so this is not the number of vehicles. The "
        "&ldquo;<a href='/traffic?lang=en#stats'>Traffic</a>&rdquo; page shows roughly how many "
        "vehicles came past per hour." },
    [S_SND_FULL] = {
        "Die Tabelle ist voll, weitere Anlagen kommen nicht mehr dazu.",
        "The table is full, no further roadside units are added." },
    [S_SND_CLEAR]       = { "Liste zur&uuml;cksetzen",  "Reset list" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity, no apostrophe, no
     * straight double quote. */
    [S_SND_CLEAR_CONFIRM] = { "Liste der Anlagen wirklich zurücksetzen?",
                              "Really reset the list of roadside units?" },
    [S_NAV_TRANSIT]     = { "&Ouml;ffis",                  "Transit" },
    [S_TITLE_TRANSIT]   = { "&Ouml;ffis &ndash; Stra&szlig;enbahn und Bus",
                            "Transit &ndash; tram and bus" },
    [S_PT_INTRO] = {
        "Busse und Stra&szlig;enbahnen schicken in ihrer Statusnachricht eine kurze Meldung nach "
        "VDV R09 mit. Darin stehen etwa Linie, Ziel und Abweichung vom Fahrplan. Mit dieser "
        "Meldung melden sie sich auch bei Ampeln an.<br><br>Die Spalte &bdquo;Sichtungen&ldquo; "
        "z&auml;hlt Vorbeifahrten: Ein Fahrzeug, das vorbeif&auml;hrt, z&auml;hlt einmal. Wenn "
        "es l&auml;nger als 15 Minuten in Reichweite bleibt, z&auml;hlt es alle 15 Minuten neu, "
        "ebenso wenn es seine Stations-Nummer wechselt.",
        "Buses and trams send a short VDV R09 report inside their status message. It carries, "
        "for example, line, destination and deviation from the timetable. They also use this "
        "report to register with traffic lights.<br><br>The &ldquo;Sightings&rdquo; column "
        "counts passages: a vehicle that passes counts once. If it stays in range for more than "
        "15 minutes, it counts again every 15 minutes, and also when it changes its station ID." },
    /* Also the transit tile of the start page and /status.json: no double quote, no backslash. */
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
    [S_PT_LIMIT] = {
        "Die Fahrzeuge melden, wie viele Minuten sie vom Fahrplan abweichen: Plus hei&szlig;t zu "
        "sp&auml;t, Minus zu fr&uuml;h. Die Meldung reicht nur bis 7&nbsp;Minuten. Darum "
        "hei&szlig;t <code>&ge;7 min</code>: 7&nbsp;Minuten oder mehr.<br><br>Eine gemeldete 0 "
        "kann <em>p&uuml;nktlich</em> oder <em>nicht mitgeschickt</em> hei&szlig;en, beides "
        "sieht gleich aus. Darum z&auml;hlt &bdquo;ohne Wert&ldquo; diese Vorbeifahrten "
        "getrennt, und &bdquo;Ø Abweichung&ldquo; l&auml;sst sie weg.<br><br>Wenn alle "
        "Sichtungen einer Linie bei &bdquo;ohne Wert&ldquo; landen, schickt diese Linie die "
        "Abweichung vermutlich nicht mit.",
        "The vehicles report by how many minutes they deviate from the timetable: plus means "
        "late, minus means early. The report only goes up to 7&nbsp;minutes. So <code>&ge;7 "
        "min</code> means 7&nbsp;minutes or more.<br><br>A reported 0 can mean <em>on time</em> "
        "or <em>not sent</em>, and the two look the same. So &ldquo;no value&rdquo; counts these "
        "passages separately, and &ldquo;Avg. deviation&rdquo; leaves them out.<br><br>If all "
        "sightings of a line end up under &ldquo;no value&rdquo;, this line probably does not "
        "send the deviation." },
    /* One %d. The hlp note under it says when a passage closes. */
    [S_PT_ACTIVE]       = { "Offene Vorbeifahrten: %d.", "Open passages: %d." },
    /* Heading and chip of the full list on /transit. "Alle" although at most 120 rows
     * show: S_PT_CAPPED says so under the table when more are stored. */
    [S_PT_PASSAGES]     = { "Alle Vorbeifahrten",       "All passages" },
    /* Heading and chip of the five newest rows at the top of /transit: a short excerpt, so
     * it differs from the full list below. */
    [S_PT_NEWEST]       = { "Neueste Vorbeifahrten",    "Latest passages" },
    [S_PT_LINES]        = { "Linien",                   "Lines" },
    [S_PT_COURSE]       = { "Kurs",                     "Course" },
    [S_PT_DEST]         = { "Ziel",                     "Destination" },
    /* MP and ZL from the OCIT part of the R09 telegram. They appear in the column on /transit
     * and in the detail text on /messages, which also goes into the JSON field h. */
    [S_PT_POINT]        = { "Meldepunkt",               "Report point" },
    [S_PT_TRAINLEN]     = { "Zugl&auml;nge",            "Train length" },
    [S_PT_DEV]          = { "Abweichung",               "Deviation" },
    [S_PT_INRANGE]      = { "in Reichweite",            "In range" },
    [S_PT_HEADWAY]      = { "Takt",                     "Headway" },
    [S_PT_HEADWAY_NONE] = { "kein regelm&auml;&szlig;iger Takt", "no regular service" },
    /* "Ziel", not "Richtung": the field is the VDV destination number, and some
     * of those numbers turn up across many lines as depot runs. */
    [S_PT_DIR]          = { "Ziel",                     "Destination" },
    [S_PT_OPS_FIRST]    = { "erste Fahrt",              "first trip" },
    [S_PT_OPS_HINT] = {
        "Takt, Betriebszeiten und Ziele berechnet das Ger&auml;t aus den gespeicherten "
        "Vorbeifahrten, nicht aus einem Fahrplan.<br><br>Takt: der mittlere Abstand von einem "
        "Fahrzeug der Linie zum n&auml;chsten, beide Richtungen zusammen, abgerundet auf "
        "Minuten. Wenn die Linie hier in beide Richtungen f&auml;hrt, ist er darum k&uuml;rzer "
        "als der Takt einer Richtung im Fahrplan.<br><br>Mittel hei&szlig;t Median: der Wert in "
        "der Mitte, wenn man alle Abst&auml;nde der Gr&ouml;&szlig;e nach ordnet. Einzelne sehr "
        "kurze Abst&auml;nde, etwa nach einem Wechsel der Stations-Nummer, st&ouml;ren ihn "
        "kaum.<br><br>Betriebszeiten: die fr&uuml;heste und die sp&auml;teste Uhrzeit, zu der "
        "die Linie hier vorbeikam. F&uuml;r diese Rechnung beginnt der Tag um 03:00 Uhr, darum "
        "z&auml;hlt eine Fahrt um 00:30 als sp&auml;te Fahrt.<br><br>Ziel: die zwei "
        "h&auml;ufigsten Zielnummern, die die Fahrzeuge schicken, in Klammern wie oft.",
        "The device computes headway, operating hours and destinations from the stored passages, "
        "not from a timetable.<br><br>Headway: the typical gap from one vehicle of the line to "
        "the next, both directions together, rounded down to whole minutes. If the line runs "
        "past here in both directions, it is therefore shorter than the timetable headway of one "
        "direction.<br><br>Typical means the median: the value in the middle when all gaps are "
        "sorted by size. Single very short gaps, for example after a change of station ID, "
        "hardly affect it.<br><br>Operating hours: the earliest and the latest time the line "
        "came past here. For this, the day starts at 03:00, so a trip at 00:30 counts as a late "
        "trip.<br><br>Destination: the two most frequent destination numbers the vehicles send, "
        "with how often in parentheses." },
    /* Destinations are named here too: the table shows a "Ziel" column whose
     * bracketed count is explained nowhere else. */
    [S_PT_OPS_SUM]      = { "Woher Takt, Betriebszeiten und Ziele kommen",
                            "Where headway, operating hours and destinations come from" },
    [S_PT_CLEAR]        = { "Statistik zur&uuml;cksetzen", "Reset statistics" },
    [S_PT_CLEAR_CONFIRM] = { "Öffi-Statistik wirklich zurücksetzen?",
                             "Really reset the transit statistics?" },
    [S_NAV_TRAFFIC]     = { "Verkehr",                  "Traffic" },
    [S_TRF_BUSY] = {
        "Die SD-Karte war besch&auml;ftigt, darum fehlen in dieser Ansicht die gespeicherten "
        "Stunden. Bitte gleich noch einmal laden.",
        "The SD card was busy, so the stored hours are missing from this view. Please reload in "
        "a moment." },
    [S_TRF_DAY]         = { "Tag",                      "Day" },
    [S_TRF_SG]          = { "Signalgruppe",             "Signal group" },
    [S_TRF_PH_WAIT] = {
        "Die Phasendauern erscheinen, sobald das Ger&auml;t eine Gr&uuml;n- oder Rotphase ganz "
        "empfangen hat, von einem Umschalten bis zum n&auml;chsten. Die Phase, die beim Start "
        "des Empfangs schon lief, z&auml;hlt nicht. Nachts kann das Stunden dauern.",
        "Phase durations appear once the device has received a whole green or red phase, from "
        "one switch to the next. The phase already running when reception started does not "
        "count. At night this can take hours." },
    /* Shown above the duration table, so the table head needs no word for the numbers. The
     * cells are averages with the longest value in brackets. */
    [S_TRF_PH_TABLE_NOTE] = { "Je Signalgruppe die mittlere Dauer einer Phase, in Klammern die "
                              "l&auml;ngste gemessene. Gez&auml;hlt wird erst, wenn eine Phase "
                              "zu Ende ist.",
                              "Per signal group the average length of a phase, in brackets the "
                              "longest one measured. A phase counts only once it has ended." },
    [S_TRF_CYCLES]      = { "Gemessene Gr&uuml;nphasen", "Green phases measured" },
    [S_TRF_SENDERS_NOTE] = {
        "Die Fahrzeugspalten z&auml;hlen verschiedene Stations-Nummern, nicht Nachrichten. An "
        "einer Durchfahrtsstelle ist das ungef&auml;hr die Zahl der Fahrzeuge. Genau ist sie "
        "nicht, weil Fahrzeuge nach der ETSI-Norm ihre Stations-Nummer wechseln "
        "d&uuml;rfen.<br><br>&ge; hei&szlig;t: Der Wert ist eine Untergrenze, weil die "
        "Z&auml;hltabelle der Stunde voll war oder ein Neustart die Stunde geteilt hat.",
        "The vehicle columns count distinct station IDs, not messages. At a through road that is "
        "roughly the number of vehicles. It is not exact, because the ETSI standard lets "
        "vehicles change their station ID.<br><br>&ge; means: the value is a lower bound, "
        "because the hour's counting table was full or a restart split the hour." },
    [S_TRF_IDENT_NOTE] = {
        "Die Spalte &bdquo;Ampel/Anlage&ldquo; z&auml;hlt nur, was in dieser Stunde gesendet "
        "hat. Die Seite &bdquo;<a href='/senders?lang=de'>Anlagen</a>&ldquo; listet dagegen jede "
        "Ampel und Anlage am Stra&szlig;enrand, die das Ger&auml;t bisher empfangen hat. Darum "
        "k&ouml;nnen die beiden Zahlen verschieden sein.",
        "The &ldquo;Traffic light/roadside unit&rdquo; column counts only what transmitted in "
        "that hour. The &ldquo;<a href='/senders?lang=en'>Roadside units</a>&rdquo; page, in "
        "contrast, lists every traffic light and roadside unit the device has received so far. "
        "So the two numbers can differ." },
    [S_TRF_SENDERS_DAY] = {
        "Bei 7 und 30 Tagen steht in &bdquo;Auto&ldquo; bis &bdquo;Sonstige&ldquo; der "
        "h&ouml;chste Stundenwert des Tages. Als Summe w&auml;re jede Ampel 24-mal gez&auml;hlt.",
        "For 7 and 30 days, &ldquo;Car&rdquo; to &ldquo;Other&rdquo; show the day's highest "
        "hourly value. A sum would count every traffic light 24 times." },
    [S_TITLE_TRAFFIC]   = { "Verkehr",                  "Traffic" },
    /* The class columns count distinct station numbers, not messages. Only the total column
     * counts messages. */
    [S_TRF_INTRO] = {
        "Die &bdquo;Verkehrsstatistik&ldquo; z&auml;hlt je Stunde alle empfangenen Nachrichten. "
        "Die Spalten &bdquo;Auto&ldquo; bis &bdquo;Sonstige&ldquo; z&auml;hlen au&szlig;erdem "
        "die verschiedenen Stations-Nummern, die jeder Sender mitschickt.<br><br>Bei Fahrzeugen "
        "zeigt das ungef&auml;hr, wie viele vorbeikamen. Die Zahlen kommen jede Stunde auf die "
        "SD-Karte und bleiben &uuml;ber einen Neustart erhalten.",
        "The &ldquo;Traffic statistics&rdquo; count all received messages per hour. The columns "
        "from &ldquo;Car&rdquo; to &ldquo;Other&rdquo; also count the distinct station IDs that "
        "each sender transmits.<br><br>For vehicles this roughly shows how many came past. The "
        "counts go to the SD card every hour and survive a restart." },
    /* Also the caption of every period picker (map, archive search, re-send), so
     * S_MAP_HINT and S_PLAYBACK_RANGE can quote one word for all of them. */
    [S_TRF_WINDOW]      = { "Zeitraum",                 "Period" },
    [S_TRF_W_24H]       = { "24 Stunden",               "24 hours" },
    [S_TRF_W_7D]        = { "7 Tage",                   "7 days" },
    [S_TRF_W_30D]       = { "30 Tage",                  "30 days" },
    [S_TRF_STATS]       = { "Verkehrsstatistik",        "Traffic statistics" },
    [S_TRF_TOTAL]       = { "Gesamt",                   "Total" },
    [S_TRF_HOUR]        = { "Stunde",                   "Hour" },
    [S_TRF_SPEED]       = { "&Oslash;/max km/h (Fahrzeuge)", "avg/max km/h (vehicles)" },
    [S_TRF_NODATA] = {
        "Noch keine Daten. Die laufende Stunde erscheint mit dem ersten Frame, sobald die Uhr "
        "gestellt ist.",
        "No data yet. The current hour appears with the first frame once the clock is set." },
    [S_CAT_CAR]         = { "Auto",                     "Car" },
    [S_CAT_BUS]         = { "Bus",                      "Bus" },
    [S_CAT_TRUCK]       = { "Lkw",                      "Truck" },
    [S_CAT_TWOWHEEL]    = { "Zweirad",                  "Two-wheeler" },
    [S_CAT_PED]         = { "Fu&szlig;g&auml;nger",     "Pedestrian" },
    [S_CAT_RSU]         = { "Ampel/Anlage",             "Traffic light/roadside unit" },
    [S_CAT_OTHER]       = { "Sonstige",                 "Other" },
    /* Help under the warning list on /traffic: what the sub-lines of a warning say. */
    [S_EVT_DETAIL_HINT] = {
        "Unter der Ursache steht, was der Sender sonst noch mitschickt: etwa wo und f&uuml;r "
        "welche Fahrtrichtung die Warnung gilt, auf welcher Stra&szlig;e, und Tempo und Richtung "
        "an der Gefahrenstelle. Es gilt immer die neueste "
        "Meldung.<br><br>&bdquo;Verl&auml;sslichkeit&ldquo; reicht von 1 (gering) bis 7 (hoch). "
        "&bdquo;Weg zur Stelle&ldquo; ist die Zahl der Punkte auf der Strecke zur "
        "Gefahrenstelle. &bdquo;Ausdehnung der Stelle&ldquo; ist die Zahl der Punkte, die "
        "zeigen, wie weit die Gefahrenstelle selbst reicht.<br><br>&bdquo;gemeldet von&ldquo; "
        "steht nur da, wenn die Warnung von einer anderen Art von Sender stammt als der in der "
        "Spalte &bdquo;Absender&ldquo;. Ein Beispiel: Eine Ampel hat die Warnung eines Autos "
        "weitergesendet.",
        "Below the cause is what else the sender sends: for example where and for which "
        "direction of travel the warning applies, on which road, and speed and course at the "
        "hazard. The newest report always counts.<br><br>&ldquo;confidence&rdquo; runs from 1 "
        "(low) to 7 (high). &ldquo;path to the spot&rdquo; is the number of points on the "
        "stretch to the hazard. &ldquo;extent of the spot&rdquo; is the number of points that "
        "show how far the hazard itself reaches.<br><br>&ldquo;raised by&rdquo; only appears "
        "when the warning comes from another kind of sender than the one in the "
        "&ldquo;Sender&rdquo; column. An example: a traffic light has passed on the warning of a "
        "car." },
    [S_EVT_TITLE]       = { "Warnungen (DENM)",         "Warnings (DENM)" },
    [S_EVT_NONE]        = { "Keine Warnungen im gew&auml;hlten Zeitraum.",
                            "No warnings in the selected period." },
    /* Column head of the warnings on /traffic, and the name of a warning without a known
     * cause there and in ITS_WA of /map, a double-quoted JS string: no quote, no backslash. */
    [S_EVT_WARNING]     = { "Warnung",                  "Warning" },
    [S_EVT_MULTI]       = { "auch von anderen Sendern", "also from other senders" },
    [S_EVT_RELAYED]     = { "weitergereicht",           "relayed" },
    [S_EVT_RELAY_VIA]   = { "&uuml;ber",                "via" },
    [S_EVT_RELAY_UNKNOWN] = { "eine andere Funkquelle", "another radio source" },
    [S_EVT_RELAY_AFTER] = { "Abstand",                  "gap" },
    [S_EVT_RELAY_HINT] = {
        "&bdquo;weitergereicht&ldquo; hei&szlig;t: Eine andere Station hat dieselbe Warnung noch "
        "einmal gesendet. Erkennbar ist das an zwei MAC-Adressen oder an der Sprungzahl im "
        "Frame. Beim Absender steht weiter die Stations-Nummer des Urhebers.<br><br>Ein "
        "Beispiel: <code>&uuml;ber Hauptplatz &middot; Abstand 3&nbsp;s &middot; 4/60</code>. "
        "Die Anlage Hauptplatz hat die Warnung weitergesendet, 3&nbsp;Sekunden nach dem Urheber. "
        "4 der 60 Frames kamen &uuml;ber Hauptplatz.<br><br><code>bis 2&times; weitergereicht "
        "&middot; nur weitergereicht: 44 von 52 &middot; fehlen: 8</code>: 44 der 52 Frames "
        "kamen nur &uuml;ber eine andere Station an. 8 Frames des Urhebers fehlen ganz, das "
        "zeigt die laufende Nummer im Frame.<br><br>Der Pegel z&auml;hlt nur Frames, die direkt "
        "vom Urheber kamen. Wenn eine Warnung nur weitergereicht ankam, steht beim Pegel der "
        "Wert der Station, &uuml;ber die sie kam, etwa <code>&uuml;ber Hauptplatz "
        "-72&hellip;-70</code>. Ohne Messwert steht ein Strich.<br><br>Der Name kommt von der "
        "Seite &bdquo;<a href='/senders?lang=de'>Anlagen</a>&ldquo;.",
        "&ldquo;relayed&rdquo; means another station sent the same warning once more. Two MAC "
        "addresses show it, or the hop count in the frame. The sender keeps the station ID of "
        "the originator.<br><br>An example: <code>via Main Square &middot; gap 3&nbsp;s &middot; "
        "4/60</code>. The roadside unit Main Square relayed the warning, 3&nbsp;seconds after "
        "the originator. 4 of the 60 frames came via Main Square.<br><br><code>relayed up to "
        "2&times; &middot; only relayed: 44 of 52 &middot; missing: 8</code>: 44 of the 52 "
        "frames arrived only through another station. 8 frames of the originator are missing, as "
        "the sequence number in the frame shows.<br><br>The signal covers only frames straight "
        "from the originator. When a warning arrived only relayed, the signal shown is that of "
        "the station it came through, for example <code>via Main Square -72&hellip;-70</code>. "
        "Without a reading it shows a dash.<br><br>The name comes from the "
        "&ldquo;<a href='/senders?lang=en'>Roadside units</a>&rdquo; page." },
    [S_EVT_BYHOUR]      = { "Warnungen je Tagesstunde", "Warnings by hour of day" },
    [S_EVT_BYWDAY]      = { "Warnungen je Wochentag",   "Warnings by weekday" },
    [S_EVT_PERHOUR]     = { "je beobachteter Stunde",   "per observed hour" },
    [S_EVT_PROFILE_HINT] = {
        "Jede Zeile zeigt, wie viele Warnungen zu dieser Tageszeit oder an diesem Wochentag im "
        "Schnitt pro Stunde ankamen. Ein Beispiel: <code>0,50 (12 / 24)</code> hei&szlig;t 12 "
        "Warnungen in 24 beobachteten Stunden, also eine halbe pro Stunde.<br><br>Als beobachtet "
        "z&auml;hlt eine Stunde, in der mindestens ein Frame ankam. Die Warnungen werden durch "
        "diese Stunden geteilt. Ein Wochentag, der im Zeitraum &ouml;fter vorkommt, bekommt so "
        "nicht allein deshalb den l&auml;ngeren Balken.<br><br>Gez&auml;hlt werden Warnungen, "
        "nicht Ereignisse: Wenn f&uuml;nf Fahrzeuge denselben Stau melden, sind das f&uuml;nf. "
        "Der Zeitraum reicht nur so weit zur&uuml;ck, wie das Ger&auml;t Warnungen aufbewahrt.",
        "Each row shows how many warnings arrived per hour on average at this time of day or on "
        "this weekday. An example: <code>0.50 (12 / 24)</code> means 12 warnings in 24 observed "
        "hours, so half a warning per hour.<br><br>An hour counts as observed when at least one "
        "frame arrived. The warnings are divided by these hours. A weekday that occurs more "
        "often in the period does not get the longer bar for that alone.<br><br>Warnings are "
        "counted, not incidents: if five vehicles report the same jam, that is five. The period "
        "only reaches back as far as the device keeps warnings." },
    /* One entry, not seven: the labels are only ever needed together. tm_wday
     * order, Sunday first, comma-separated. */
    [S_TRF_WDAYS]       = { "So,Mo,Di,Mi,Do,Fr,Sa",     "Sun,Mon,Tue,Wed,Thu,Fri,Sat" },
    [S_EVT_CAPPED]      = { "Nur die neuesten 256 Warnungen &ndash; im Zeitraum waren es mehr.",
                            "Only the newest 256 warnings &ndash; the period held more." },
    /* The same note for the passages. Headway and operating hours use all stored passages.
     * The table shows only the newest. */
    [S_PT_CAPPED] = {
        "Die Tabelle zeigt nur die neuesten 120 Vorbeifahrten, gespeichert sind mehr. Takt und "
        "Betriebszeiten oben sind aus allen berechnet.",
        "The table shows only the newest 120 passages, more are stored. The headway and "
        "operating hours above are computed from all of them." },
    [S_TRF_SPEED_MIXED] = {
        "Ein Teil dieses Zeitraums wurde noch mit einer &auml;lteren Regel f&uuml;r stehende "
        "Fahrzeuge gez&auml;hlt. Der Durchschnitt ist darum nicht direkt vergleichbar.",
        "Part of this period was still counted with an older rule for standing vehicles. The "
        "average is therefore not directly comparable." },
    [S_TRF_SPEED_BY_TYPE] = { "Geschwindigkeit nach Typ (&Oslash;/max km/h)",
                              "Speed by type (avg/max km/h)" },
    [S_TRF_JUMP]        = { "Direkt zu",                 "Jump to" },
    [S_TRF_SILENT]      = { "Stunden ohne Empfang",      "Hours with no reception" },
    [S_TRF_WEAKHOURS]   = { "Stunden weit unter dem Median", "Hours far below the median" },
    [S_TRF_AVAIL_HINT] = {
        "Die K&auml;stchen z&auml;hlen Stunden mit wenig oder keiner "
        "Aufzeichnung.<br><br>&bdquo;Stunden ohne Empfang&ldquo;: Stunden im gew&auml;hlten "
        "Zeitraum seit dem letzten Neustart, f&uuml;r die keine Z&auml;hlung gespeichert ist. "
        "Meist kam nichts an, selten ging das Speichern schief.<br><br>Die Zeit vor dem Neustart "
        "z&auml;hlt nicht mit, auch nicht, wenn das Ger&auml;t aus war.<br><br>&bdquo;Stunden "
        "weit unter dem Median&ldquo;: Stunden im ganzen Zeitraum mit weniger als einem Viertel "
        "der &uuml;blichen Zahl. Als &uuml;blich gilt der Median: die mittlere Stunde, wenn man "
        "alle nach ihrer Zahl ordnet.<br><br>Das zweite K&auml;stchen gibt es nur bei "
        "gleichm&auml;&szlig;igem Empfang, etwa von einer Ampel. Wenn der Empfang vom Verkehr "
        "abh&auml;ngt, fehlt es, weil sonst nachts jede Stunde weit darunter l&auml;ge.",
        "These boxes count hours with little or no recording.<br><br>&ldquo;Hours with no "
        "reception&rdquo;: hours in the chosen period since the last restart for which no count "
        "is stored. Mostly nothing arrived, rarely saving failed.<br><br>Time before the restart "
        "does not count, not even while the device was off.<br><br>&ldquo;Hours far below the "
        "median&rdquo;: hours in the whole period with less than a quarter of the usual count. "
        "Usual means the median: the middle hour when all are sorted by their count.<br><br>The "
        "second box only appears with steady reception, for example from a traffic light. When "
        "reception depends on the traffic, it is left out, because at night every hour would "
        "fall far below." },
    [S_EVT_SHOWPOS]     = { "Ort auf der Karte zeigen",  "Show location on the map" },
    [S_TRF_LIGHTS]      = { "Ampeln (live)",            "Traffic lights (live)" },
    /* "Noch" holds: spatem.c never lowers its count after start-up, so this shows only until
     * the first traffic light is heard. Also in /status.json: no double quote, no backslash. */
    [S_TRF_LIGHTS_NONE] = { "Noch keine Ampeldaten empfangen.",
                            "No traffic-light data received yet." },
    /* Also the lights tile of the start page and /status.json: no double quote, no backslash. */
    [S_TRF_INTERSECTION] = { "Kreuzung",               "Intersection" },
    /* Labels for what the MAPEM says about an intersection on /traffic. */
    [S_TRF_SPEEDLIMIT]  = { "Tempolimit",               "Speed limit" },
    [S_TRF_SPEEDMIN]    = { "Mindesttempo",             "Minimum speed" },
    [S_TRF_LANEWIDTH]   = { "Spurbreite",               "Lane width" },
    [S_TRF_ALT]         = { "H&ouml;he",                "Altitude" },
    [S_TRF_LIGHTS_INTRO] = {
        "F&uuml;r jede Kreuzung gibt es ein Feld je Signalgruppe. Eine Signalgruppe sind alle "
        "Lichter, die immer gleich schalten. Ein Beispiel: <code>geradeaus, rechts (3) "
        "&ge;12&nbsp;s</code>.<br><br>Das hei&szlig;t: Gruppe 3 regelt geradeaus und rechts und "
        "schaltet fr&uuml;hestens in 12 Sekunden um. Die Sekunden stehen nur da, wenn die Ampel "
        "sie mitschickt und es h&ouml;chstens zehn Minuten sind.<br><br>Die Richtungen stammen "
        "aus der Kreuzungskarte der Ampel. Ohne diese Karte steht nur die Nummer da.<br><br>Die "
        "kleine Ampel vor jeder Gruppe zeigt die aktuelle Phase. Wie bei einer echten leuchtet "
        "oben Rot, in der Mitte Gelb und unten Gr&uuml;n:",
        "Each intersection has one box per signal group. A signal group is all lights that "
        "always switch together. An example: <code>straight, right (3) "
        "&ge;12&nbsp;s</code>.<br><br>This means group 3 controls straight and right and "
        "switches in 12 seconds at the earliest. The seconds only appear when the light sends "
        "them and the change is at most ten minutes away.<br><br>The directions come from the "
        "intersection map of the traffic light. Without that map only the number "
        "appears.<br><br>The small traffic light in front of each group shows the current phase. "
        "As on a real one, red is at the top, amber in the middle and green at the bottom:" },
    [S_TRF_PH_GREEN]    = { "Gr&uuml;n (frei)",        "Green (go)" },
    [S_TRF_PH_AMBER]    = { "Gelb (&Uuml;bergang)",    "Amber (change)" },
    [S_TRF_PH_REDAMBER] = { "Rot-Gelb",                "Red-amber" },
    [S_TRF_PH_SINCE]    = { "l&auml;uft seit",         "running for" },
    [S_TRF_PH_RED]      = { "Rot (Halt)",              "Red (stop)" },
    [S_TRF_PH_OTHER]    = { "Aus/unbekannt",           "Off/unknown" },
    /* Dark, with none of the three lights on, does not mean the signal is off. It means nothing
     * was heard for more than ten seconds. That is about our reception, not about the light. */
    [S_TRF_PH_STALE]    = { "keine aktuellen Daten",  "no current data" },
    [S_DIR_STRAIGHT]    = { "geradeaus",               "straight" },
    [S_DIR_LEFT]        = { "links",                   "left" },
    [S_DIR_RIGHT]       = { "rechts",                  "right" },
    [S_DIR_UTURN]       = { "wenden",                  "U-turn" },
    [S_DIR_PED]         = { "Fu&szlig;g&auml;nger",    "pedestrian" },
    [S_NAV_MAP]         = { "Karte",                    "Map" },
    [S_TITLE_MAP]       = { "Karte",                    "Map" },
    [S_MAP_HINT] = {
        "Die Karte zeigt, wo die Sender gerade sind. Ihre Position schicken sie selbst mit. Das "
        "Symbol zeigt, wer sendet: Auto, Bus, Stra&szlig;enbahn, Fu&szlig;g&auml;nger, Ampel und "
        "so weiter.<br><br>Ein Klick auf ein Symbol zeigt Typ, Uhrzeit, Pegel, L&auml;nge des "
        "Frames und Stations-Nummer. Dazu kommt, was der Sender sonst schickt: etwa Tempo und "
        "Richtung, bei &Ouml;ffis die Linie, bei Ampeln die Phasen.<br><br>Wenn das Ger&auml;t "
        "die Spuren einer Kreuzung kennt, zeichnet die Karte sie ein, jede in der Farbe ihrer "
        "Ampel. Bei Rot und Rot-Gelb ist die Linie gepunktet, das hilft bei "
        "Rot-Gr&uuml;n-Schw&auml;che. Grau hei&szlig;t: keine Ampel oder Phase "
        "unbekannt.<br><br>Wenn von einem Sender nichts Neues kommt, verschwindet sein Symbol "
        "nach der Zeit &bdquo;<a href='/settings?lang=de#mapstale'>Karte: Marker-Standzeit "
        "(s)</a>&ldquo; auf der Seite &bdquo;Einstellungen&ldquo;. Den Kartenhintergrund holt "
        "der Browser aus dem Internet, nicht das Ger&auml;t.<br><br>Verlauf: bei "
        "&bdquo;Zeitraum&ldquo; Beginn und Ende w&auml;hlen, &bdquo;Laden&ldquo; klicken, dann "
        "mit &#9654; oder dem Regler abspielen. Ein Abruf l&auml;dt h&ouml;chstens vier "
        "Stunden.<br><br>Die Daten kommen aus der Aufzeichnung auf der SD-Karte. Wie weit sie "
        "zur&uuml;ckreicht, stellt man auf der Seite "
        "&bdquo;<a href='/settings?lang=de#pcaphours'>Einstellungen</a>&ldquo; ein.",
        "The map shows where the senders are right now. They send their position themselves. The "
        "icon shows who is sending: car, bus, tram, pedestrian, traffic light and so "
        "on.<br><br>A click on an icon shows type, time, signal level, frame length and station "
        "ID. Anything else the sender transmits follows, such as speed and heading, the line for "
        "public transport and the phases for traffic lights.<br><br>When the device knows the "
        "lanes of an intersection, the map draws them, each in the colour of its light. At red "
        "and red-amber the line is dotted, which helps with red-green colour blindness. Grey "
        "means no light or phase unknown.<br><br>When nothing new comes from a sender, its icon "
        "disappears after the &ldquo;<a href='/settings?lang=en#mapstale'>Map: marker hold time "
        "(s)</a>&rdquo; on the &ldquo;Settings&rdquo; page. The browser loads the map background "
        "from the internet, not the device.<br><br>History: pick start and end under "
        "&ldquo;Period&rdquo;, click &ldquo;Load&rdquo;, then replay with &#9654; or the slider. "
        "One request loads four hours at most.<br><br>The data comes from the recording on the "
        "SD card. How far back it reaches is set on the "
        "&ldquo;<a href='/settings?lang=en#pcaphours'>Settings</a>&rdquo; page." },
    [S_MAP_HELP]        = { "Info &amp; Hilfe",           "Info &amp; help" },
    [S_MAP_LAYER_STREETS] = { "Karte",                  "Map" },
    [S_MAP_LAYER_SATELLITE] = { "Satellit",             "Satellite" },
    [S_MAP_DENM]        = { "Warnung aktiv",           "Warning active" },
    [S_MAP_LINE]        = { "Linie",                   "Line" },
    [S_MAP_COURSE]      = { "Kurs",                    "Course" },
    [S_MAP_DEST]        = { "Ziel",                    "Destination" },
    /* Unit of the timetable deviation. It appears in the detail column, also in the JSON
     * field h, and in the map popup, so no entity and no quote. */
    [S_UNIT_MIN]        = { "min",                     "min" },
    [S_MAP_LATE]        = { "Versp&auml;tung",         "delay" },
    [S_MAP_EARLY]       = { "Vorsprung",               "ahead" },
    [S_MAP_ONTIME]      = { "keine Abweichung gemeldet", "no deviation reported" },
    /* No warning sign in the text: s.css sets it in front of the line. */
    [S_SYS_COREDUMP]      = { "Absturzdaten verf&uuml;gbar", "Crash dump available" },
    [S_SYS_COREDUMP_DOWNLOAD] = { "Absturzdaten herunterladen", "Download crash dump" },
    [S_SYS_COREDUMP_CLEAR] = { "L&ouml;schen",          "Delete" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity. */
    [S_SYS_COREDUMP_CLEAR_CONFIRM] = { "Absturzdaten löschen?", "Delete crash dump?" },
    /* Visible, not hlp: without the purpose most people delete the file. The last sentence
     * warns before attaching it in public. */
    [S_SYS_COREDUMP_HINT] = { "Das Ger&auml;t ist abgest&uuml;rzt und hat Daten dazu gespeichert. "
                              "F&uuml;r einen Fehlerbericht auf Codeberg diese Datei herunterladen "
                              "und anh&auml;ngen. Die Datei ist ein Auszug aus dem Arbeitsspeicher "
                              "und kann Zugangsdaten enthalten.",
                              "The device crashed and saved data about it. For a bug report on "
                              "Codeberg, download this file and attach it. The file is an excerpt "
                              "of the device memory and can contain credentials." },
    /* Message details on /messages and /senders. HTML, also inside the JSON field h. */
    [S_SIG_UNSIGNED] = { "unsigniert", "unsigned" },
    [S_SIG_CERT] = { "Zertifikat", "certificate" },
    [S_SIG_DIGEST] = { "Kurzkennung", "short identifier" },
    [S_SIG_OTHER] = { "andere Signaturart", "other kind of signature" },
    [S_SIG_ID_UNKNOWN] = { "Kennung unbekannt", "ID unknown" },
    [S_SIG_KNOWN] = { "Zertifikat bekannt", "certificate known" },
    [S_SIG_MISSING] = { "Zertifikat des Senders fehlt", "sender certificate not received" },
    [S_SIG_ISSUER] = { "Aussteller", "issuer" },
    [S_SIG_MAC] = { "MAC passt zur Kennung", "MAC matches the ID" },
    [S_DCC_TXPOWER] = { "Sendeleistung", "transmit power" },
    [S_DCC_CBR] = { "Kanallast", "channel load" },
    [S_DCC_CBR_NEIGH] = { "bei Nachbarn bis", "at neighbours up to" },
    [S_DCC_CBR_MAX] = { "h&ouml;chste Kanallast", "highest channel load" },
    [S_DENM_CANCEL] = { "aufgehoben", "cancelled" },
    [S_DENM_NEGATE] = { "widerrufen", "revoked" },
    [S_DENM_VALID] = { "gilt", "valid for" },
    [S_DENM_DEFAULT] = { "Standardwert", "default" },
    /* The rest of the DENM, in the line on /messages. HTML. The distances are numbers and need
     * no entry. Only the open top step has one. */
    [S_DENM_AWARE] = { "Warnbereich bis", "warning range up to" },
    [S_DENM_DIST_OVER] = { "Warnbereich mehr als 10 km", "warning range more than 10 km" },
    [S_DENM_DIR] = { "gilt f&uuml;r", "applies to" },
    [S_DENM_DIR_ALL] = { "alle Richtungen", "all directions" },
    [S_DENM_DIR_UP] = { "gleiche Richtung, noch vor der Stelle",
                        "same direction, before the spot" },
    [S_DENM_DIR_DOWN] = { "gleiche Richtung, schon nach der Stelle",
                          "same direction, past the spot" },
    [S_DENM_DIR_OPP] = { "Gegenrichtung", "opposite direction" },
    [S_DENM_ROAD_UO] = { "Ortsgebiet, Richtungen nicht getrennt",
                         "built-up area, directions not separated" },
    [S_DENM_ROAD_US] = { "Ortsgebiet, Richtungen getrennt",
                         "built-up area, directions separated" },
    [S_DENM_ROAD_FO] = { "Freiland, Richtungen nicht getrennt",
                         "open road, directions not separated" },
    [S_DENM_ROAD_FS] = { "Freiland, Richtungen getrennt", "open road, directions separated" },
    [S_DENM_QUALITY] = { "Verl&auml;sslichkeit", "confidence" },
    [S_DENM_AT_SPEED] = { "Tempo an der Stelle", "speed at the spot" },
    [S_DENM_AT_DIR] = { "Richtung an der Stelle", "course at the spot" },
    [S_LBL_ALT] = { "H&ouml;he", "altitude" },
    [S_MAP_REF_ALT] = { "H&ouml;he der Kreuzung", "intersection altitude" },
    [S_DENM_REPEAT] = { "wiederholt alle", "repeated every" },
    [S_DENM_ZONE] = { "Weg zur Stelle", "path to the spot" },
    /* eventZone: how far the spot itself reaches, counted in points. */
    [S_DENM_EXTENT] = { "Ausdehnung der Stelle", "extent of the spot" },
    [S_DENM_POINT] = { "Punkt", "point" },
    [S_DENM_POINTS] = { "Punkte", "points" },
    /* The station type that raised the warning, when a unit of another type relays it. */
    [S_DENM_STATION] = { "gemeldet von", "raised by" },
    /* RTCMEM, message type 13. What the corrections SAY is not shown here, because the standard
     * leaves their numbering to the GNSS receiver in the vehicle. HTML. */
    [S_RTCM_CORR] = { "GNSS-Korrekturen", "GNSS corrections" },
    [S_RTCM_CNT] = { "Z&auml;hler", "counter" },
    [S_RTCM_ANCHOR] = { "Bezugspunkt", "reference point" },
    [S_RTCM_MINUTE] = { "Minute des Jahres", "minute of the year" },
    [S_RTCM_REV_NONE] = { "RTCM-Ausgabe nicht angegeben", "RTCM edition not stated" },
    /* The sender names an edition that has no meaning here: reserved, or a value behind the
     * extension. That is not the same as naming none. */
    [S_RTCM_REV_OTHER] = { "RTCM-Ausgabe weder 2 noch 3", "RTCM edition neither 2 nor 3" },
    /* The unit is a pair because the English word needs the plural. */
    [S_UNIT_BYTES] = { "Byte", "bytes" },
    /* The eight bits with which the GNSS receiver of the station reports on itself. The words
     * follow the explanation in DSRC.asn:2296-2303, not the bit names. The explanation calls
     * bit 6 DGPS and bit 7 RTK outright. For bits 1 and 2 the standard gives only the name,
     * hence "reports itself". Bit 4 contradicts itself in the source. Its name says below 5,
     * the explanation above it says more than 5. Claiming either would be a guess, so the
     * text says the standard leaves it open. */
    [S_GNSS_UNAVAIL] = { "Empf&auml;nger nicht verf&uuml;gbar", "receiver unavailable" },
    [S_GNSS_HEALTHY] = { "meldet sich als gesund", "reports itself healthy" },
    [S_GNSS_MONITORED] = { "meldet sich als &uuml;berwacht", "reports itself monitored" },
    [S_GNSS_BASE] = { "feste Basisstation", "fixed base station" },
    [S_GNSS_PDOP] = { "PDOP-Bit gesetzt (die Norm sagt nicht, in welche Richtung)",
                      "PDOP bit set (the standard does not say which way)" },
    [S_GNSS_INVIEW] = { "weniger als 5 Satelliten in Sicht", "fewer than 5 satellites in view" },
    [S_GNSS_LOCAL] = { "DGPS-Korrekturen benutzt", "DGPS corrections used" },
    [S_GNSS_NETWORK] = { "RTK-Korrekturen benutzt", "RTK corrections used" },
    /* CPM, message type 14. The label comes before the number, as with the RTCMEM counter, so
     * no "1 Sensoren" appears. HTML. */
    [S_CPM_OBJECTS] = { "erkannte Objekte", "detected objects" },
    [S_LBL_HERE] = { "davon in dieser Nachricht", "of them in this message" },
    [S_CPM_SENSORS] = { "Sensoren", "sensors" },
    [S_CPM_REGIONS] = { "Wahrnehmungsbereiche", "perception regions" },
    [S_CPM_PART] = { "Teil", "part" },
    [S_CPM_OF] = { "von", "of" },
    [S_CPM_FROM_VEH] = { "Absender ist ein Fahrzeug", "sent by a vehicle" },
    [S_CPM_FROM_RSU] = { "Absender ist eine Anlage am Stra&szlig;enrand",
                         "sent by a roadside unit" },
    /* orientationAngle is the way the vehicle faces, measured from north, not the direction it
     * moves in. A vehicle that stands still has an orientation but no direction of travel. */
    [S_CPM_HEADING] = { "Ausrichtung", "orientation" },
    [S_CPM_OTHER] = { "weitere Container", "other containers" },
    /* Shown only when the container list could not be read with its extension bit, but could
     * without it. The sender then follows the reading that Wireshark also uses by default. */
    [S_CPM_LIST_NOEXT] = { "Liste nach Wiresharks Lesart, ohne Erweiterungsbit",
                           "list in Wireshark's reading, without the extension bit" },
    /* The container was announced, but its bytes did not fit its shape. A number from them
     * would be made up, so only its id is shown. */
    [S_CPM_BAD] = { "Container ohne lesbaren Inhalt", "containers without readable content" },
    [S_CPM_VERSION] = { "CPM-Version", "CPM version" },
    [S_NOT_READ] = { "wird nicht gelesen", "is not read" },
    /* The CPM detail line on /messages: what the sender's sensors perceived, as in
     * 'Arten: Auto 5, Fußgänger 2'. The classes below are the kinds counted there. */
    [S_CPM_KINDS] = { "Arten", "kinds" },
    [S_CPM_CAT_CAR] = { "Auto", "car" },
    [S_CPM_CAT_BUS] = { "Bus", "bus" },
    [S_CPM_CAT_TRUCK] = { "Lkw", "truck" },
    [S_CPM_CAT_TRAM] = { "Stra&szlig;enbahn", "tram" },
    [S_CPM_CAT_TWOWHEEL] = { "Zweirad", "two-wheeler" },
    [S_CPM_CAT_PED] = { "Fu&szlig;g&auml;nger", "pedestrian" },
    [S_CPM_CAT_ANIMAL] = { "Tier", "animal" },
    [S_CPM_CAT_GROUP] = { "Gruppe", "group" },
    [S_CPM_CAT_OTHER] = { "Sonstiges", "other" },
    [S_CPM_CAT_NONE] = { "ohne Art", "no kind given" },
    /* One object: 'Objekt 4711: Auto, 80 % sicher, Güte 12 von 15, 23 m NO, 36 km/h nach O'.
     * Rate and quality are printf formats. The rest are plain words. */
    [S_CPM_OBJ] = { "Objekt", "object" },
    [S_CPM_SURE] = { "sicher", "sure" },
    [S_CPM_QUALITY] = { "G&uuml;te %u von 15", "quality %u of 15" },
    [S_CPM_TOWARD] = { "nach", "toward" },
    [S_CPM_REACH] = { "Reichweite bis", "range up to" },
    [S_CPM_MORE] = { "weitere", "more" },
    [S_CPM_RATE] = { "Takt %s bis %s pro Sekunde", "rate %s to %s per second" },
    [S_CPM_MEASURED] = { "Messzeit", "measured at" },
    [S_CPM_TRAILERS] = { "Anh&auml;nger", "trailers" },
    [S_CPM_MAP_INT] = { "Kreuzung", "intersection" },
    [S_CPM_MAP_SEG] = { "Stra&szlig;enabschnitt", "road segment" },
    [S_CPM_NEWER_EDITION] = { "Objekte nach neuerer Normfassung gelesen (wie Wireshark)",
        "objects read by the newer edition of the standard (as Wireshark does)" },
    [S_CPM_DOUBT] = { "Angaben unsicher, Container passt nicht zu seiner L&auml;nge:",
        "values uncertain, container does not match its length:" },
    /* The sensor types of the sensor information container. An unknown value prints its number. */
    [S_CPM_ST_UNDEF] = { "unbestimmt", "undefined" },
    [S_CPM_ST_RADAR] = { "Radar", "radar" },
    [S_CPM_ST_LIDAR] = { "Lidar", "lidar" },
    [S_CPM_ST_MONO] = { "Kamera", "camera" },
    [S_CPM_ST_STEREO] = { "Stereokamera", "stereo camera" },
    [S_CPM_ST_NIGHT] = { "Nachtsichtkamera", "night-vision camera" },
    [S_CPM_ST_ULTRA] = { "Ultraschall", "ultrasound" },
    [S_CPM_ST_PMD] = { "Laufzeitkamera", "time-of-flight camera" },
    [S_CPM_ST_LOOP] = { "Induktionsschleife", "induction loop" },
    [S_CPM_ST_SPHERE] = { "Rundumkamera", "360-degree camera" },
    [S_CPM_ST_UWB] = { "UWB-Funk", "UWB radio" },
    [S_CPM_ST_ACOUSTIC] = { "Mikrofon", "microphone" },
    [S_CPM_ST_LOCAL] = { "Fusion eigener Sensoren", "fusion of own sensors" },
    [S_CPM_ST_ITS] = { "Fusion mit Funkdaten", "fusion with radio data" },
    [S_CPM_ST_N] = { "Sensorart %u", "sensor type %u" },
    /* The finer class of an object, when the sender gives one: vehicles, persons, bicycles and the
     * like, motorcycles, animals, a group, other objects. A class of a newer edition says so. */
    [S_CPM_V_UNKNOWN] = { "Fahrzeug unbekannter Art", "vehicle of unknown kind" },
    [S_CPM_V_LTRUCK] = { "Lieferwagen", "light truck" },
    [S_CPM_V_HTRUCK] = { "schwerer Lkw", "heavy truck" },
    [S_CPM_V_TRAILER] = { "Anh&auml;nger", "trailer" },
    [S_CPM_V_SPECIAL] = { "Sonderfahrzeug", "special vehicle" },
    [S_CPM_V_AGRI] = { "Landmaschine", "agricultural vehicle" },
    [S_CPM_V_N] = { "Fahrzeugart %u", "vehicle type %u" },
    [S_CPM_P_WORKER] = { "Stra&szlig;enarbeiter", "road worker" },
    [S_CPM_P_RESCUE] = { "Einsatzkraft", "first responder" },
    [S_CPM_B_WHEELCHAIR] = { "Rollstuhl", "wheelchair" },
    [S_CPM_B_HORSE] = { "Reiter", "horse rider" },
    [S_CPM_B_SKATES] = { "Rollschuhe", "roller skates" },
    [S_CPM_B_SCOOTER] = { "E-Scooter", "e-scooter" },
    [S_CPM_B_PERSONAL] = { "Kleinstfahrzeug", "personal transporter" },
    [S_CPM_B_PEDELEC] = { "Pedelec", "pedelec" },
    [S_CPM_B_SPEDELEC] = { "S-Pedelec", "speed pedelec" },
    [S_CPM_B_ROADBIKE] = { "Rennrad", "road bike" },
    [S_CPM_B_KIDSBIKE] = { "Kinderrad", "child bike" },
    [S_CPM_M_MOPED] = { "Moped", "moped" },
    [S_CPM_M_SIDE_R] = { "Motorrad mit Beiwagen rechts", "motorcycle with sidecar on the right" },
    [S_CPM_M_SIDE_L] = { "Motorrad mit Beiwagen links", "motorcycle with sidecar on the left" },
    [S_CPM_A_WILD] = { "Wildtier", "wild animal" },
    [S_CPM_A_FARM] = { "Nutztier", "farm animal" },
    [S_CPM_A_SERVICE] = { "Assistenztier", "service animal" },
    [S_CPM_G_OF] = { "Gruppe von %u", "group of %u" },
    [S_CPM_O_UNKNOWN] = { "unbekannt", "unknown" },
    [S_CPM_O_SINGLE] = { "einzelnes Objekt", "single object" },
    [S_CPM_O_MULTI] = { "mehrere Objekte", "several objects" },
    [S_CPM_O_BULK] = { "Sch&uuml;ttgut", "bulk material" },
    [S_CPM_CLS_NEWER] = { "neuere Art", "newer kind" },
    /* The CPM map layer on /map: objects, sensor coverage and perception regions. The entries
     * are the layer names, the popup words, the note for when the device keeps fewer objects
     * than were sent, and the help. */
    [S_MAP_L_CPM] = { "Von Sensoren erkannt", "Seen by sensors" },
    [S_MAP_L_CPM_AREA] = { "Sichtbereiche der Sensoren", "Sensor coverage" },
    [S_MAP_CPM_BY] = { "erkannt von Station", "seen by station" },
    [S_MAP_CPM_HEIGHT] = { "H&ouml;he zum Bezugspunkt", "height above the reference point" },
    [S_MAP_CPM_AGE] = { "erfasst seit", "tracked for" },
    [S_MAP_CPM_ALONG] = { "entlang der Spur", "along the lane" },
    [S_MAP_CPM_CONN] = { "Verbindung", "connection" },
    [S_MAP_CPM_FROMREF] = { "vom Bezugspunkt", "from the reference point" },
    [S_MAP_CPMA_SENSOR] = { "Sichtbereich von Sensor", "coverage of sensor" },
    [S_MAP_CPMA_REGION] = { "Wahrnehmungsbereich", "perception region" },
    [S_MAP_CPMA_CONF] = { "Erkennung hier", "detection here" },
    [S_MAP_CPMA_UNSURE] = {
        "Lage unsicher, weil die Norm den Winkel hier nicht eindeutig festlegt",
        "position uncertain, because the standard does not define the angle clearly here" },
    [S_MAP_CPMA_CUT] = {
        "Nicht alle erkannten Objekte und Sichtbereiche sind eingezeichnet, weil der Speicher "
        "daf&uuml;r voll ist.",
        "Not every detected object and coverage area is drawn, because the memory for them is "
        "full." },
    [S_MAP_CPM_HINT] = {
        "Punkte mit gestricheltem Ring senden nicht selbst. Eine Anlage oder ein Fahrzeug hat "
        "sie mit Sensoren erkannt und gemeldet (CPM). Ohne neue Meldung verschwinden sie nach "
        "3&nbsp;Sekunden.<br><br>Die blauen Fl&auml;chen zeigen, wie weit diese Sensoren sehen. "
        "Bei einem Fahrzeug bewegt sich die Fl&auml;che mit.<br><br>Je kr&auml;ftiger das Blau, "
        "desto zuverl&auml;ssiger erkennt der Sensor Objekte in dieser Fl&auml;che. Ein Klick "
        "auf die Fl&auml;che zeigt, von wem sie stammt.<br><br>Gepunktet umrandete Fl&auml;chen "
        "sind Wahrnehmungsbereiche. F&uuml;r jede dieser Fl&auml;chen meldet der Sender, wie "
        "zuverl&auml;ssig er darin Objekte erkennt. Hinter einem Hindernis kann das zum Beispiel "
        "schlechter sein.<br><br>Auch die Fl&auml;chen verschwinden ohne neue Meldung nach "
        "3&nbsp;Sekunden.",
        "Markers with a dashed ring do not transmit themselves. A roadside unit or a vehicle saw "
        "them with its sensors and reported them (CPM). Without a new report they disappear "
        "after 3&nbsp;seconds.<br><br>The blue areas show how far these sensors see. On a "
        "vehicle the area moves with it.<br><br>The stronger the blue, the more reliably the "
        "sensor detects objects in this area. A click on the area shows who sent "
        "it.<br><br>Areas with a dotted edge are perception regions. For each of them the sender "
        "reports how reliably it detects objects in it. Behind an obstacle, for example, this "
        "can be worse.<br><br>The areas too disappear after 3&nbsp;seconds without a new report." },
    /* The section on /traffic with the newest CPM, EVCSN, POIM and RTCMEM per sender, and what
     * goes to the SD card. A charging station or car park that does not change is written once
     * an hour. */
    [S_INF_TITLE] = { "Sensoren, Ladestationen, Parkpl&auml;tze, GNSS",
        "Sensors, charging stations, parking, GNSS" },
    [S_INF_INTRO] = {
        "Was Anlagen und Fahrzeuge &uuml;ber ihre Sensoren (CPM), &uuml;ber Ladestationen "
        "(EVCSN) und &uuml;ber Parkpl&auml;tze (POIM) senden, dazu GNSS-Korrekturen (RTCMEM). "
        "Von jedem Sender steht die neueste Nachricht da.<br><br>Wenn ein Sender mehrere "
        "Parkpl&auml;tze oder Ladestationen nennt, bekommt jede eine eigene Zeile. "
        "&bdquo;Details&ldquo; zeigt dasselbe wie die Seite &bdquo;Nachrichten&ldquo;. "
        "&bdquo;Anzahl&ldquo; z&auml;hlt die Nachrichten einer Zeile, seit sie in der Liste "
        "steht.<br><br>Die Liste h&auml;lt bis zu 64 Zeilen und zeigt die neuesten 16. Sie liegt "
        "nur im Arbeitsspeicher und ist nach einem Neustart leer, bis die Sender wieder "
        "senden.<br><br>Auf die SD-Karte kommt je Zeile h&ouml;chstens ein Eintrag pro "
        "Minute.<br><br>Bei CPM und RTCMEM steht ein Eintrag f&uuml;r alle Nachrichten dieser "
        "Minute. Bei Ladestationen und Parkpl&auml;tzen gibt es einen Eintrag, wenn sich etwas "
        "&auml;ndert, sonst einmal pro Stunde.<br><br>Die Dateien sind "
        "<code>logs/cpm.csv</code>, <code>logs/evcsn.csv</code>, <code>logs/poim.csv</code> und "
        "<code>logs/rtcmem.csv</code>. Wenn eine Datei 1 MB erreicht, bekommt sie "
        "<code>.1</code> in den Namen, etwa <code>logs/cpm.1.csv</code>, und die vorige mit "
        "<code>.1</code> wird gel&ouml;scht.<br><br>Herunterladen kann man sie auf der Seite "
        "&bdquo;<a href='/sdcard?lang=de&amp;p=logs'>Dateien</a>&ldquo;.",
        "What roadside units and vehicles send about their sensors (CPM), charging stations "
        "(EVCSN) and parking (POIM), and GNSS corrections (RTCMEM). The newest message of each "
        "sender is shown.<br><br>When a sender names several car parks or charging stations, "
        "each gets its own row. &ldquo;Details&rdquo; shows the same as the "
        "&ldquo;Messages&rdquo; page. &ldquo;Count&rdquo; counts the messages of a row since it "
        "entered the list.<br><br>The list holds up to 64 rows and shows the newest 16. It lives "
        "in memory only and is empty after a restart until the senders send again.<br><br>The SD "
        "card gets at most one entry per row and minute.<br><br>For CPM and RTCMEM one entry "
        "stands for all messages of that minute. For charging stations and parking an entry is "
        "written when something changes, otherwise once an hour.<br><br>The files are "
        "<code>logs/cpm.csv</code>, <code>logs/evcsn.csv</code>, <code>logs/poim.csv</code> and "
        "<code>logs/rtcmem.csv</code>. When a file reaches 1 MB, it gets <code>.1</code> in its "
        "name, like <code>logs/cpm.1.csv</code>, and the previous one with <code>.1</code> is "
        "deleted.<br><br>They are available for download on the "
        "&ldquo;<a href='/sdcard?lang=en&amp;p=logs'>Files</a>&rdquo; page." },
    [S_INF_NONE] = { "Seit dem Neustart ist noch keine CPM, EVCSN, POIM oder RTCMEM in der Liste.",
        "No CPM, EVCSN, POIM or RTCMEM in the list since the restart." },
    /* Instead of the list while the clock is unset: frames before it are not listed. */
    [S_INF_CLOCK] = { "Die Uhr ist noch nicht gestellt. Bis dahin kommt nichts in diese Liste.",
        "The clock is not set yet. Until it is, nothing goes into this list." },
    /* Items from the signature header in the grey line of /messages, one line per unit on
     * /senders and the certificate key on /trust. The signing time shows as clock time and as
     * a gap. */
    [S_SEC_SIGNED] = { "signiert", "signed" },
    [S_SEC_BEFORE_RX] = { "vor Empfang", "before reception" },
    [S_SEC_AT_RX] = { "bei Empfang", "on reception" },
    [S_SEC_AFTER_RX] = { "nach Empfang", "after reception" },
    [S_SEC_TIME_FAR] = { "nach 2106", "after 2106" },
    [S_SEC_PLACE] = { "Ort der Signatur", "place of the signature" },
    [S_SEC_AT_SENDER] = { "beim Absender", "at the sender" },
    [S_SEC_FROM_SENDER] = { "vom Absender", "from the sender" },
    [S_SEC_LOC_RANGE] = { "au&szlig;erhalb der erlaubten Werte", "outside the allowed values" },
    [S_SEC_ALT_MSG] = { "in der Nachricht", "in the message" },
    [S_SEC_EXPIRES] = { "l&auml;uft ab", "expires" },
    [S_SEC_EXPIRED_RX] = { "bei Empfang schon abgelaufen", "already expired on reception" },
    [S_SEC_NOT_AFTER] = { "nicht nach der Signatur", "not after the signature" },
    [S_SEC_ALG] = { "Verfahren", "algorithm" },
    [S_SEC_CERT_KEY] = { "Schl&uuml;ssel des Zertifikats", "key of the certificate" },
    [S_SEC_KEY] = { "Schl&uuml;ssel", "Key" },
    [S_SEC_KEY_IMPLICIT] = { "implizit", "implicit" },
    [S_SEC_HASH_UNKNOWN] = { "Hash unbekannt", "hash unknown" },
    [S_SEC_ASKS] = { "fragt nach Zertifikaten", "asks for certificates" },
    [S_SEC_SENDS_CA] = { "legt das Zertifikat eines Ausstellers bei",
        "includes the certificate of an issuer" },
    [S_SEC_ASKS_CRL] = { "fragt nach einer Sperrliste", "asks for a revocation list" },
    [S_SEC_ASKS_CTL] = { "fragt nach einer Liste der Aussteller", "asks for an issuer list" },
    [S_SEC_ENC_KEY] = { "nennt einen Schl&uuml;ssel f&uuml;r Antworten", "names a key for replies" },
    [S_SEC_PDU] = { "f&uuml;r einen Sicherheitsdienst bestimmt", "meant for a security service" },
    [S_SEC_CONTRIB] = {
        "Zusatzfelder im Sicherheits-Header",
        "extra fields in the security header" },
    [S_SEC_EXT_HASH] = { "Inhalt nur als Hash gesendet", "content sent as a hash only" },
    /* The content came along AND its hash: TS 103 097 5.2 allows either, not both. */
    [S_SEC_EXT_HASH_TOO] = { "Hash des Inhalts zus&auml;tzlich gesendet", "hash of the content sent as well" },
    /* GeoNetworking in the grey line of /messages (how the frame travelled, position age,
     * sequence number, lifetime, traffic class), under each warning on /traffic and per unit
     * on /senders. */
    [S_GN_DIRECT] = { "direkt geh&ouml;rt", "heard directly" },
    [S_GN_RELAYED] = { "%u&times; weitergereicht", "relayed %u&times;" },
    [S_GN_MAXHOPS] = { "h&ouml;chstens %u Spr&uuml;nge", "at most %u hops" },
    [S_GN_ORIGIN] = { "zuerst gesendet von %s", "first sent by %s" },
    [S_GN_HOPS_BAD] = { "Sprungzahl passt nicht: %u &uuml;brig, %u erlaubt",
        "hop count does not fit: %u left, %u allowed" },
    [S_GN_POS] = { "Standort bestimmt", "position taken" },
    [S_GN_POS_CLOCK] = { "Zeit des Standorts passt nicht zur Uhr",
        "time of the position does not match the clock" },
    [S_GN_SN] = { "laufende Nummer %u", "sequence number %u" },
    [S_GN_SN_DUP] = { "schon geh&ouml;rt", "heard before" },
    [S_GN_SN_LATE] = { "versp&auml;tet", "late" },
    [S_GN_SN_GAP] = { "davor fehlen: %u", "missing before it: %u" },
    [S_GN_LIFETIME] = { "Lebensdauer", "lifetime" },
    [S_GN_TCLASS] = { "Verkehrsklasse %u", "traffic class %u" },
    [S_GN_PRIO_0] = { "sehr hoher Vorrang", "very high priority" },
    [S_GN_PRIO_1] = { "hoher Vorrang", "high priority" },
    [S_GN_PRIO_2] = { "normaler Vorrang", "normal priority" },
    [S_GN_PRIO_3] = { "niedriger Vorrang", "low priority" },
    [S_GN_TC_UNDEF] = { "in ITS-G5 nicht belegt", "not defined for ITS-G5" },
    [S_GN_SCF] = { "darf auf Nachbarn warten", "may wait for a station in range" },
    [S_GN_OFFLOAD] = { "Kanalwechsel erlaubt", "may change channel" },
    [S_GN_FIXED] = { "als fest montiert gemeldet", "reported as fixed in place" },
    [S_GN_MOBILE] = { "als beweglich gemeldet", "reported as mobile" },
    [S_GN_HINT] = {
        "Am Ende der grauen Zeile steht, auf welchem Weg der Frame ankam. <code>1&times; "
        "weitergereicht, h&ouml;chstens 3 Spr&uuml;nge</code>: Eine andere Station hat ihn noch "
        "einmal gesendet. Die MAC-Adresse geh&ouml;rt dann zu dieser "
        "Station.<br><br><code>Standort bestimmt 112&nbsp;ms vor Empfang</code>: So alt war die "
        "Positionsangabe im Frame beim Empfang. Bei einem weitergereichten Frame z&auml;hlt der "
        "Umweg mit. &bdquo;nach Empfang&ldquo; hei&szlig;t: Eine der beiden Uhren geht "
        "falsch.<br><br><code>laufende Nummer 812 (davor fehlen: 2)</code>: Viele Warnungen und "
        "Kreuzungskarten sind fortlaufend nummeriert. Eine fehlende Nummer ist ein Frame, der "
        "hier nie ankam. CAM und meist auch Ampelphasen haben keine Nummer.<br><br>&bdquo;schon "
        "geh&ouml;rt&ldquo; ist eine Kopie, meist &uuml;ber eine andere Station. "
        "&bdquo;versp&auml;tet&ldquo; ist nach einer h&ouml;heren Nummer angekommen und "
        "f&uuml;llt eine L&uuml;cke.<br><br><code>Lebensdauer 60&nbsp;s</code>: So lange darf "
        "der Frame im Funknetz unterwegs sein. <code>Verkehrsklasse 3 (niedriger "
        "Vorrang)</code>: die Vorrangstufe, die der Sender vergibt. 0 hat den h&ouml;chsten "
        "Vorrang.<br><br>Die Fahrtrichtung stammt bei einer CAM aus der CAM selbst, bei anderen "
        "Nachrichten eines Fahrzeugs aus der Positionsangabe im Frame.<br><br>Eine Richtung 0 "
        "zeigt die Seite bei diesen Nachrichten nicht an, weil viele Sender 0 schreiben, wenn "
        "sie keine Richtung kennen.",
        "The end of the grey line says which way the frame came. <code>relayed 1&times;, at most "
        "3 hops</code>: another station sent it once more. The MAC address then belongs to that "
        "station.<br><br><code>position taken 112&nbsp;ms before reception</code>: this is how "
        "old the position in the frame was on reception. For a relayed frame the detour counts "
        "too. &ldquo;after reception&rdquo; means: one of the two clocks is "
        "wrong.<br><br><code>sequence number 812 (missing before it: 2)</code>: many warnings "
        "and intersection maps are numbered in sequence. A missing number is a frame that never "
        "arrived here. CAM and mostly signal phases carry no number.<br><br>&ldquo;heard "
        "before&rdquo; is a copy, mostly through another station. &ldquo;late&rdquo; arrived "
        "after a higher number and fills a gap.<br><br><code>lifetime 60&nbsp;s</code>: how long "
        "the frame may travel through the radio network. <code>traffic class 3 (low "
        "priority)</code>: the priority the sender assigns. 0 is the highest.<br><br>A CAM gives "
        "its own heading. Other messages from a vehicle take it from the position in the "
        "frame.<br><br>A heading of 0 is not shown for these messages, because many senders "
        "write 0 when they know no heading." },
    [S_EVT_GN_RELAYED] = { "bis %u&times; weitergereicht", "relayed up to %u&times;" },
    [S_EVT_GN_DIRECT] = { "auch direkt geh&ouml;rt", "also heard directly" },
    [S_EVT_GN_ONLY_RELAY] = { "nur weitergereicht: %u von %u", "only relayed: %u of %u" },
    [S_EVT_GN_MISSING] = { "fehlen: %u", "missing: %u" },
    [S_SND_SN_MISS] = { "fehlen: %lu", "missing: %lu" },
    [S_SND_SN_RELAY] = { "nur weitergereicht: %lu", "only relayed: %lu" },
    [S_SND_SN_HINT] = {
        "Unter der Zahl der Frames steht, was sich aus der laufenden Nummer der Anlage ablesen "
        "l&auml;sst. <code>fehlen: 276 (0,1&nbsp;%)</code>: So viele Frames kamen nie an. Das "
        "geht nur bei nummerierten Frames, etwa Kreuzungskarten, meist nicht bei "
        "Ampelphasen.<br><br><code>nur weitergereicht: 12</code>: Diese Frames kamen nur "
        "&uuml;ber eine andere Station, nicht direkt von der Anlage. Beide Zahlen z&auml;hlen "
        "seit dem ersten Empfang. Mit SD-Karte bleiben sie &uuml;ber einen Neustart erhalten.",
        "Below the number of frames is what the unit&rsquo;s sequence number shows. "
        "<code>missing: 276 (0.1&nbsp;%)</code>: this many frames never arrived. This works only "
        "for numbered frames, such as intersection maps, mostly not for signal "
        "phases.<br><br><code>only relayed: 12</code>: these frames came only through another "
        "station, not straight from the unit. Both numbers count from the first reception. With "
        "an SD card they are kept across a restart." },
    [S_SEC_OMITTED] = { "signiert auch Daten, die nicht mitgesendet werden",
        "also signs data that is not sent along" },
    [S_SEC_EXT_OTHER] = { "weiterer Teil, den das Ger&auml;t nicht kennt",
        "a further part this device does not know" },
    [S_SEC_UNREADABLE] = { "unlesbar", "unreadable" },
    [S_SEC_NOT_ALLOWED] = { "nicht erlaubt", "not allowed" },
    [S_SEC_DEV_TIME] = { "Zeit der Signatur fehlt", "signature time missing" },
    [S_SEC_DEV_LOC] = { "Ort der Signatur fehlt", "place of the signature missing" },
    [S_SEC_DEV_SIGNER] = { "diese Signaturart ist nicht erlaubt", "this kind of signature is not allowed" },
    [S_SEC_DEV_DIGEST] = { "nur Kurzkennung, die Norm verlangt hier das Zertifikat",
        "short identifier only, the standard asks for the certificate here" },
    [S_SEC_DEV_CHAIN] = { "Zertifikate statt einem", "certificates instead of one" },
    [S_SEC_DEV_PSID] = { "PSID passt nicht zur Nachrichtenart", "PSID does not match the message type" },
    [S_SEC_PSID_WANT] = { "erwartet", "expected" },
    [S_SND_SEC_DEV] = {
        "Sicherheits-Header nicht nach Norm",
        "security header not to the standard" },
    [S_DETAIL_HINT_SEC] = {
        "Am Ende der grauen Zeile stehen Angaben aus dem Sicherheits-Header, etwa <code>signiert "
        "14:03:11 (85 ms vor Empfang) &middot; Ort der Signatur: beim Absender, H&ouml;he 414,0 "
        "m</code>. Diese Angaben macht der Sender selbst, das Ger&auml;t pr&uuml;ft sie nicht "
        "nach.<br><br>Hinter der Uhrzeit steht, wie lange vor dem Empfang signiert wurde. "
        "&bdquo;nach Empfang&ldquo; hei&szlig;t: Die Uhr des Senders geht vor.<br><br>Die "
        "H&ouml;he berechnet das Ger&auml;t nach der Norm. Wenn die Nachricht selbst auch eine "
        "H&ouml;he nennt, steht diese in Klammern daneben.<br><br>Bei einer CAM geh&ouml;ren "
        "beide H&ouml;hen zum Sender. Wenn sie Hunderte Meter auseinanderliegen, ist die "
        "H&ouml;he im Sicherheits-Header falsch.<br><br>Bei einer Warnung geh&ouml;rt die "
        "H&ouml;he in Klammern zum Ort des Ereignisses, bei einer Kreuzungskarte zur "
        "Kreuzung.<br><br><code>Verfahren</code> nennt die Art der Signatur, etwa ECDSA NIST "
        "P-256. Ob die Signatur stimmt, steht weiter vorne in der Zeile.<br><br>&#9888; "
        "hei&szlig;t: Diese Angabe im Sicherheits-Header weicht von der Norm ab. &bdquo;nicht "
        "erlaubt&ldquo; steht bei einer Angabe, die die Norm f&uuml;r diese Nachricht nicht "
        "vorsieht.",
        "The grey line ends with details from the security header, such as <code>signed 14:03:11 "
        "(85 ms before reception) &middot; place of the signature: at the sender, altitude 414.0 "
        "m</code>. The sender provides them itself, the device does not check them.<br><br>After "
        "the clock time comes how long before reception the message was signed. &ldquo;after "
        "reception&rdquo; means: the sender&rsquo;s clock is fast.<br><br>The device computes "
        "the altitude as the standard prescribes. If the message itself also gives an altitude, "
        "it follows in brackets.<br><br>In a CAM both altitudes belong to the sender. If they "
        "lie hundreds of metres apart, the altitude in the security header is wrong.<br><br>In a "
        "warning the altitude in brackets belongs to the place of the event, in an intersection "
        "map to the intersection.<br><br><code>algorithm</code> names the kind of signature, "
        "such as ECDSA NIST P-256. Whether the signature is right is said earlier in the "
        "line.<br><br>&#9888; means: this entry in the security header does not follow the "
        "standard. &ldquo;not allowed&rdquo; marks an entry the standard does not provide for in "
        "this message." },
    [S_TRUST_KEY_NOTE] = {
        "Unter jeder Kennung steht der Schl&uuml;ssel des Zertifikats, etwa "
        "<code>Schl&uuml;ssel: ECDSA NIST P-256</code>. <code>implizit</code> hei&szlig;t: Das "
        "Zertifikat enth&auml;lt keinen fertigen Schl&uuml;ssel. Er wird erst aus dem "
        "Zertifikat und seinem Aussteller berechnet.",
        "Below each identifier is the key of the certificate, such as <code>Key: ECDSA NIST "
        "P-256</code>. <code>implicit</code> means: the certificate holds no finished key. It "
        "is computed from the certificate and its issuer." },
    [S_SND_SEC_HINT] = {
        "Unter dem Pr&uuml;fergebnis stehen Verfahren und H&ouml;he aus dem Sicherheits-Header, "
        "so wie der Sender sie zuletzt geschickt hat.<br><br>&#9888; z&auml;hlt die Nachrichten, "
        "deren Sicherheits-Header von der Norm abweicht. Was genau abweicht, zeigt die Seite "
        "Nachrichten.",
        "Below the check result are the algorithm and altitude from the security header, as the "
        "sender last sent them.<br><br>&#9888; counts the messages whose security header does "
        "not follow the standard. What exactly differs is shown on the Messages page." },
    [S_INF_MSGS] = { "Anzahl", "Count" },
    [S_INF_LOST] = { "Zeilen seit dem Neustart vielleicht nicht auf die SD-Karte gekommen.",
        "rows may not have reached the SD card since the restart." },
    /* Two numbers of the sender do not fit together, such as part 5 of 3. Both are shown, with
     * this word behind them. */
    [S_CONTRADICTS] = { "widerspr&uuml;chlich", "contradictory" },
    /* EVCSN, message type 11 (and 3 in version 0). Charging modes 1 to 3 are the terms of the
     * standard for charging from the grid, so they are shown in brackets. HTML. */
    [S_EVCSN_STATIONS] = { "Ladestationen", "charging stations" },
    [S_EVCSN_STATION] = { "Station", "station" },
    [S_EVCSN_POS] = { "Standort", "location" },
    [S_EVCSN_ACCESS] = { "Zugang", "access" },
    [S_EVCSN_HOURS] = { "&Ouml;ffnungszeiten", "opening hours" },
    [S_EVCSN_PRICE] = { "Preis", "price" },
    [S_EVCSN_SPOTS] = { "Ladepunkte", "charging spots" },
    /* relayCapable says that the sender can pass on reservation messages, not that this
     * message may be passed on (TS 101 556-1, table A.2). */
    [S_EVCSN_RELAY] = { "kann Reservierungen weiterleiten", "can relay reservation messages" },
    [S_EVCS_MODE1] = { "Normalladen (Mode 1)", "standard charging (mode 1)" },
    [S_EVCS_MODE2] = { "Normalladen (Mode 2)", "standard charging (mode 2)" },
    [S_EVCS_MODE3] = { "Normal- oder Schnellladen (Mode 3)", "standard or fast charging (mode 3)" },
    [S_EVCS_FAST_EXT] = { "Schnellladen mit externem Ladeger&auml;t",
                          "fast charging with an external charger" },
    [S_EVCS_QUICKDROP] = { "Akkutausch", "battery swap" },
    [S_EVCS_INDUCT_STAND] = { "induktiv im Stand", "inductive while standing" },
    [S_EVCS_INDUCT_DRIVE] = { "induktiv w&auml;hrend der Fahrt", "inductive while driving" },
    /* POIM, messageId 3. German says Parkplatz for the facility and for one space, so the
     * facility is Parkplatz and one space always Stellplatz. HTML. */
    [S_POIM_PLACES] = { "Parkpl&auml;tze", "parking facilities" },
    [S_POIM_FREE] = { "freie Stellpl&auml;tze", "free spaces" },
    [S_POIM_SPACES] = { "Stellpl&auml;tze", "spaces" },
    /* Behind the number 101. The standard names 101 "unavailable", but its comment gives 16383
     * for that, so 101 may also be a plain count. */
    [S_POIM_OR_NA] = { "oder keine Angabe", "or not stated" },
    [S_POIM_OCC] = { "Belegungsgrad", "occupancy" },
    [S_POIM_ST_CLOSED] = { "geschlossen", "closed" },
    [S_POIM_ST_OPEN] = { "ge&ouml;ffnet", "open" },
    [S_POIM_ST_SUBSCR] = { "nur f&uuml;r Dauerparker", "subscribers only" },
    [S_POIM_ST_FULL] = { "ge&ouml;ffnet, aber voll", "open but full" },
    /* The trend of the occupancy, always behind that word: rising means it fills up. */
    [S_POIM_TR_DOWN] = { "sinkt", "falling" },
    [S_POIM_TR_DOWN_FAST] = { "sinkt schnell", "falling quickly" },
    [S_POIM_TR_DOWN_SLOW] = { "sinkt langsam", "falling slowly" },
    [S_POIM_TR_UP] = { "steigt", "rising" },
    [S_POIM_TR_UP_FAST] = { "steigt schnell", "rising quickly" },
    [S_POIM_TR_UP_SLOW] = { "steigt langsam", "rising slowly" },
    [S_POIM_TR_STABLE] = { "bleibt gleich", "steady" },
    [S_POIM_TR_VARIES] = { "schwankt", "varies" },
    [S_POIM_DAILY] = { "t&auml;glich", "daily" },
    /* No day bit set: without the words the times would read like every day. */
    [S_POIM_NODAYS] = { "an keinem Tag", "on no day" },
    [S_POIM_AREAS] = { "Parkbereiche", "parking areas" },
    [S_POIM_AREA] = { "Bereich", "area" },
    [S_POIM_ATLEAST] = { "mindestens", "at least" },
    [S_POIM_LEVEL] = { "Ebene", "level" },
    /* Never Hoehe alone: that word is the altitude of the facility on the same line. Both name
     * a limit, not a vehicle: 126..128 allow every vehicle up to 6,25 m. */
    [S_POIM_HEIGHT] = { "Fahrzeugh&ouml;he bis", "vehicle height up to" },
    [S_POIM_HEIGHT_OPEN] = { "H&ouml;hengrenze &uuml;ber 6,25 m oder keine Angabe",
                             "height limit above 6.25 m or not stated" },
    /* In front of the first count for a kind of space, like the areas: how many counts came. */
    [S_POIM_COUNTS] = { "Z&auml;hlungen", "counts" },
    /* Behind the word of that count when more filter lists came: all of them hold at once,
     * so the count covers fewer spaces than the word alone. */
    [S_POIM_MORE_COND] = { "mit Auflagen", "with conditions" },
    /* The EU vehicle categories L, M, N, O, T, G. Klasse alone reads like a driving licence. */
    [S_POIM_CLASS_FOR] = { "f&uuml;r EU-Fahrzeugklasse", "for EU vehicle category" },
    [S_POIM_LOAD] = { "Ladung", "load" },
    /* The kinds of reserved space. Each carries its own for/with/only, since 9 to 11 name no
     * group of people. */
    [S_POIM_RES_DISABLED] = { "f&uuml;r Menschen mit Behinderung", "for disabled persons" },
    [S_POIM_RES_PREGNANT] = { "f&uuml;r Schwangere", "for pregnant women" },
    [S_POIM_RES_WOMEN] = { "f&uuml;r Frauen", "for women" },
    [S_POIM_RES_PARENTS] = { "f&uuml;r Eltern mit Kleinkind", "for parents with small children" },
    [S_POIM_RES_LOADING] = { "zum Be- und Entladen", "for loading and unloading" },
    [S_POIM_RES_EV_MANUAL] = { "zum Laden von E-Fahrzeugen von Hand",
                               "for charging electric vehicles by hand" },
    [S_POIM_RES_EV_AUTO] = { "zum automatischen Laden von E-Fahrzeugen",
                             "for automated charging of electric vehicles" },
    [S_POIM_RES_REEFER] = { "f&uuml;r K&uuml;hltransporte", "for refrigerated transport" },
    [S_POIM_RES_VIP] = { "f&uuml;r VIP", "for VIPs" },
    [S_POIM_RES_PREBOOK] = { "nur mit Vorab-Buchung", "pre-booked only" },
    [S_POIM_RES_BOOKABLE] = { "noch reservierbar", "can still be reserved" },
    [S_POIM_RES_NOBOOK] = { "nicht reservierbar", "cannot be reserved" },
    [S_POIM_RES_VALET] = { "zur Abgabe f&uuml;r automatisches Parken",
                           "for drop-off for automated valet parking" },
    /* Not Berechtigung: that word belongs to the certificates. */
    [S_POIM_RES_PERMIT] = { "mit Parkausweis", "with a permit" },
    [S_POIM_FEE_TIME] = { "mit Zeittarif", "time-based fee" },
    [S_POIM_FEE_FLAT] = { "mit Pauschale", "flat fee" },
    [S_POIM_FEE_SUBSCR] = { "im Abo enthalten", "included in a subscription" },
    /* The goods of a load, behind the word for load. */
    [S_POIM_GOODS_AMMO] = { "Munition", "ammunition" },
    [S_POIM_GOODS_CHEM] = { "Chemikalien", "chemicals" },
    [S_POIM_GOODS_EMPTY] = { "leer", "empty" },
    [S_POIM_GOODS_FUEL] = { "Treibstoff", "fuel" },
    [S_POIM_GOODS_GLASS] = { "Glas", "glass" },
    [S_POIM_GOODS_DANGER] = { "gef&auml;hrliche Stoffe", "dangerous materials" },
    [S_POIM_GOODS_LIQUID] = { "Fl&uuml;ssigkeiten", "liquids" },
    [S_POIM_GOODS_LIVESTOCK] = { "lebende Tiere", "livestock" },
    [S_POIM_GOODS_PEOPLE] = { "gef&auml;hrlich f&uuml;r Mensch und Tier",
                              "dangerous to people or animals" },
    [S_POIM_GOODS_ENV] = { "umweltgef&auml;hrdend", "dangerous to the environment" },
    [S_POIM_GOODS_WATER] = { "gef&auml;hrlich bei Kontakt mit Wasser",
                             "dangerous in contact with water" },
    [S_POIM_GOODS_PERISH] = { "verderbliche Waren", "perishable goods" },
    [S_POIM_GOODS_PHARMA] = { "Arzneimittel", "pharmaceuticals" },
    [S_POIM_GOODS_VEHICLES] = { "Fahrzeuge", "vehicles" },
    [S_POIM_GOODS_REEFER] = { "K&uuml;hlgut", "refrigerated goods" },
    [S_POIM_STT_HEAVY] = { "schwere Last", "heavy load" },
    [S_POIM_STT_WIDTH] = { "&Uuml;berbreite", "excess width" },
    [S_POIM_STT_LENGTH] = { "&Uuml;berl&auml;nge", "excess length" },
    [S_POIM_STT_HEIGHT] = { "&Uuml;berh&ouml;he", "excess height" },
    /* How long one may park. Each limit is followed by a number of minutes: MAX stands behind
     * the charging text, LIMIT alone. */
    [S_POIM_OT_UNKNOWN] = { "Parkdauer unbekannt", "parking time unknown" },
    [S_POIM_OT_UNLIMITED] = { "ohne Zeitlimit", "no time limit" },
    [S_POIM_OT_CHARGING] = { "nur w&auml;hrend des Ladens", "only while charging" },
    [S_POIM_OT_MAX] = { "h&ouml;chstens", "at most" },
    [S_POIM_OT_LIMIT] = { "Parkdauer h&ouml;chstens", "parking at most" },
    [S_POIM_OT_UNTIL] = { "Parken bis", "parking until" },
    [S_POIM_OT_FORCED] = { "Ausfahrt erst ab", "no exit before" },
    [S_POIM_LINK_IVIM] = { "verkn&uuml;pfte IVIM", "linked IVIM" },
    [S_POIM_LINK_X] = { "verkn&uuml;pfte Kreuzung", "linked intersection" },
    [S_POIM_LINK_SEG] = { "verkn&uuml;pfter Stra&szlig;enabschnitt", "linked road segment" },
    [S_POIM_PROVIDER] = { "Anbieter", "provider" },
    [S_POIM_ENTRY] = { "Eintrag", "entry" },
    [S_POIM_OTHER_KIND] = { "Eintr&auml;ge der Art", "entries of kind" },
    /* The type of that list is unknown, so nothing behind it in the facility can be found. */
    [S_POIM_ENGINE] = { "verbotene Motorarten und der Rest dieses Parkplatzes nicht gelesen",
                        "barred engine types and the rest of this facility not read" },
    /* Worded like S_TRUST_WHY_PARSE. The shorter form keeps the longest line in budget. */
    [S_POIM_BROKEN] = { "Rest dieses Parkplatzes nicht lesbar",
                        "rest of this facility cannot be read" },
    /* The list of entries broke off. The facility in front of the break may be fine. */
    [S_POIM_LIST_BROKEN] = { "Rest der Nachricht nicht lesbar",
                             "rest of the message cannot be read" },
    [S_POIM_NEWER] = { "Angaben, die das Ger&auml;t noch nicht kennt",
                       "fields the device does not know yet" },
    /* A value its type does not allow, such as the hour 25, was dropped and the rest read. */
    [S_POIM_OUT_OF_RANGE] = { "ung&uuml;ltige Werte weggelassen", "invalid values left out" },
    /* The facility held more than its shape: sender and reader disagree about that shape.
     * Not "Parkplatz laenger", which reads as the size of the car park. */
    [S_POIM_TAIL_LEFT] = { "mehr Daten zum Parkplatz als erwartet, Angaben unsicher",
                           "more data on this facility than expected, values uncertain" },
    [S_POIM_VERSION] = { "POIM-Version", "POIM version" },
    /* An SAEM whose header is not version 1: 'SAEM-Version 2 wird nicht gelesen', like CPM and POIM. */
    [S_SAEM_VERSION] = { "SAEM-Version", "SAEM version" },
    /* The GeoBroadcast area on /messages and /traffic alike:
     * 'Zielgebiet: Kreis, Radius 500 m'. */
    [S_AREA_TARGET] = { "Zielgebiet", "target area" },
    [S_AREA_CIRCLE] = { "Kreis, Radius", "circle, radius" },
    [S_AREA_RECT] = { "Rechteck", "rectangle" },
    [S_AREA_ELLIPSE] = { "Ellipse", "ellipse" },
    [S_IVIM_NOTE] = { "Verkehrszeichen-Nachricht (Inhalt wird nicht dekodiert)",
        "traffic sign message (content not decoded)" },
    /* Detail line of an SAEM on /messages, the twin of the IVIM line: the device does not read its body. */
    [S_SAEM_NOTE] = { "Dienst-Ank&uuml;ndigung (Inhalt wird nicht dekodiert)",
        "service announcement (content not decoded)" },
    [S_SREM_AT] = { "Anforderung an Kreuzung", "request to intersection" },
    [S_SSEM_AT] = { "Antwort der Kreuzung", "response from intersection" },
    [S_PRT_REQUEST] = { "Vorrang anfordern", "request priority" },
    [S_PRT_UPDATE] = { "Anforderung aktualisieren", "update request" },
    [S_PRT_CANCEL] = { "Anforderung abbrechen", "cancel request" },
    [S_PRT_UNKNOWN] = { "Art unbekannt", "unknown kind" },
    [S_AP_LANE] = { "Fahrspur", "lane" },
    [S_AP_APPROACH] = { "Zufahrt", "approach" },
    [S_AP_CONNECTION] = { "Verbindung", "connection" },
    [S_AP_CENTER] = { "Kreuzungsmitte", "intersection centre" },
    [S_AP_OTHER] = { "unbekannter Zugang", "unknown access point" },
    [S_SREM_REQ_NO] = { "Nr.", "no." },
    /* The section on /traffic that records the requests and the answers. HTML. */
    [S_PRIO_TITLE] = { "Ampelanforderungen", "Priority requests" },
    [S_PRIO_SUM] = { "Was die Tabelle zeigt", "What the table shows" },
    [S_PRIO_INTRO] = {
        "Was Busse und Stra&szlig;enbahnen bei den Ampeln angefordert haben und was die Ampel "
        "geantwortet hat. Wenn eine Nachricht mehrere Anforderungen tr&auml;gt, steht jede in "
        "einer eigenen Zeile.<br><br>Die Liste steht auf der SD-Karte und bleibt &uuml;ber einen "
        "Neustart erhalten. Die SD-Karte h&auml;lt die neuesten 2000 Zeilen, die Tabelle zeigt "
        "120.",
        "What buses and trams asked the traffic lights for, and what the light answered. When "
        "one message carries several requests, each gets its own row.<br><br>The list is stored "
        "on the SD card and survives a restart. The SD card keeps the newest 2000 rows, the "
        "table shows 120." },
    [S_PRIO_NONE] = { "Noch keine Anforderung empfangen.", "No request received yet." },
    [S_PRIO_NOSD] = { "Ohne eingebundene SD-Karte wird nichts aufgezeichnet.",
                      "Without a mounted SD card nothing is recorded." },
    [S_PRIO_KIND] = { "Art", "Kind" },
    [S_PRIO_REQ] = { "Anforderung", "request" },
    [S_PRIO_ANS] = { "Antwort", "answer" },
    [S_PRIO_WHO] = { "Wer", "Who" },
    [S_PRIO_WHAT] = { "Was", "What" },
    [S_PRIO_WAY] = { "Ein &rarr; Aus", "In &rarr; out" },
    /* Printed as "%lu %s" behind the count, so English starts in lower case. The phase
     * history on /traffic uses it too. */
    [S_PRIO_LOST] = {
        "Zeilen seit dem Neustart verloren, weil die Warteschlange zur SD-Karte voll war.",
        "rows lost since the restart, because the queue to the SD card was full." },
    [S_PRIO_CLEAR] = { "Anforderungen l&ouml;schen", "Delete priority requests" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity, no apostrophe, no
     * straight double quote. */
    [S_PRIO_CLEAR_CONFIRM] = { "Alle Ampelanforderungen auf der SD-Karte löschen? Das lässt sich "
                               "nicht rückgängig machen.",
                               "Delete all priority requests on the SD card? This cannot be "
                               "undone." },
    /* The section on /traffic with the measured phases. HTML. The intro names the columns in
     * order and counts 120 phases, not rows, because groups that switch alike share a row. */
    [S_PHL_TITLE] = { "Phasenverlauf", "Phase history" },
    [S_PHL_INTRO] = {
        "Jede Zeile ist eine abgeschlossene Ampelphase: Signalgruppe, Phase, Dauer und was "
        "danach kam. Eine Signalgruppe sind alle Lichter, die immer gleich schalten.<br><br>Eine "
        "Zeile gibt es nur, wenn das Ger&auml;t die Phase ohne L&uuml;cke von Anfang bis Ende "
        "empfangen hat. Gesch&auml;tzt wird nichts.<br><br>Manche Ampeln schalten mehrere "
        "Signalgruppen genau gleich. Dann stehen sie in einer Zeile, etwa <code>1, "
        "2</code>.<br><br>Die Tabelle zeigt die neuesten 120 Phasen, die SD-Karte h&auml;lt die "
        "neuesten 2000 in <code>logs/phases.csv</code>. Herunterladen kann man sie auf der Seite "
        "&bdquo;<a href='/sdcard?lang=de&amp;p=logs'>Dateien</a>&ldquo;.",
        "Each row is a finished traffic light phase: signal group, phase, duration and what came "
        "next. A signal group is all lights that always switch together.<br><br>A row only "
        "appears when the device received the phase from start to end without a gap. Nothing is "
        "estimated.<br><br>Some lights switch several signal groups exactly alike. They then "
        "share one row, for example <code>1, 2</code>.<br><br>The table shows the newest 120 "
        "phases, the SD card keeps the newest 2000 in <code>logs/phases.csv</code>. They are "
        "available for download on the "
        "&ldquo;<a href='/sdcard?lang=en&amp;p=logs'>Files</a>&rdquo; page." },
    [S_PHL_NONE] = { "Noch keine Phase zu Ende gegangen.", "No phase has ended yet." },
    [S_PHL_PHASE] = { "Phase", "Phase" },
    [S_PHL_DUR] = { "Dauer", "Duration" },
    [S_PHL_NEXT] = { "Danach", "Then" },
    [S_PHL_CLEAR] = { "Phasenverlauf l&ouml;schen", "Delete phase history" },
    /* Shown in a JS confirm() dialog -> literal UTF-8, no HTML entity, no apostrophe, no
     * straight double quote. */
    [S_PHL_CLEAR_CONFIRM] = { "Den ganzen Phasenverlauf auf der SD-Karte löschen? Das lässt sich "
                              "nicht rückgängig machen.",
                              "Delete the whole phase history on the SD card? This cannot be "
                              "undone." },
    [S_SREM_VEHICLE] = { "Fahrzeug", "vehicle" },
    [S_SREM_ENTITY] = { "vorl&auml;ufige Kennung", "temporary ID" },
    [S_SREM_ROLE] = { "Rolle", "role" },
    [S_SREM_NAME] = { "Name", "name" },
    [S_SREM_ROUTE] = { "Linie", "route" },
    [S_MORE] = { "und weitere", "and more" },
    [S_UNKNOWN] = { "unbekannt", "unknown" },
    [S_SSEM_ST_REQUESTED] = { "angefordert", "requested" },
    [S_SSEM_ST_PROCESSING] = { "wird bearbeitet", "processing" },
    [S_SSEM_ST_WATCH] = { "eingeschr&auml;nkt, auf Verkehr achten", "limited, watch other traffic" },
    [S_SSEM_ST_GRANTED] = { "gew&auml;hrt", "granted" },
    [S_SSEM_ST_REJECTED] = { "abgelehnt", "rejected" },
    [S_SSEM_ST_MAXPRESENCE] = { "H&ouml;chstdauer &uuml;berschritten", "maximum time exceeded" },
    [S_SSEM_ST_LOCKED] = { "vor&uuml;bergehend gesperrt", "temporarily locked" },
    [S_SSEM_ST_OTHER] = { "anderer Status", "other status" },
    [S_BVR_PUBLIC] = { "&Ouml;PNV", "public transport" },
    [S_BVR_SPECIAL] = { "Schwertransport", "special transport" },
    [S_BVR_DANGEROUS] = { "Gefahrgut", "dangerous goods" },
    [S_BVR_ROADWORK] = { "Baustelle", "roadworks" },
    [S_BVR_RESCUE] = { "Bergung", "road rescue" },
    [S_BVR_EMERGENCY] = { "Einsatzfahrzeug", "emergency vehicle" },
    [S_BVR_SAFETYCAR] = { "Sicherungsfahrzeug", "safety car" },
    [S_BVR_TRUCK] = { "Lkw", "truck" },
    [S_BVR_MOTORCYCLE] = { "Motorrad", "motorcycle" },
    [S_BVR_ROADSIDE] = { "Anlage am Stra&szlig;enrand",
                         "roadside unit" },
    [S_BVR_POLICE] = { "Polizei", "police" },
    [S_BVR_FIRE] = { "Feuerwehr", "fire brigade" },
    [S_BVR_AMBULANCE] = { "Rettungswagen", "ambulance" },
    [S_BVR_DOT] = { "Stra&szlig;enverwaltung", "road authority" },
    [S_BVR_TRANSIT] = { "Linienverkehr", "transit" },
    [S_BVR_SLOW] = { "langsames Fahrzeug", "slow vehicle" },
    [S_BVR_STOPNGO] = { "h&auml;ufig haltend", "stop and go" },
    [S_BVR_CYCLIST] = { "Radfahrer", "cyclist" },
    [S_BVR_NONMOTOR] = { "ohne Motor", "non-motorised" },
    [S_BVR_MILITARY] = { "Milit&auml;r", "military" },
    [S_BVR_TRAM] = { "Stra&szlig;enbahn", "tram" },
    [S_BVR_OTHER] = { "andere Rolle", "other role" },
    [S_COL_SIG] = { "Signatur", "Signature" },
    /* Warning state and area on /traffic, /trust, /messages and /fs. HTML, but some also land
     * in the map's ITS_WA object or a single-quoted literal of the start page: no entities, no
     * quotes, no apostrophe in this group. */
    [S_WARN_ACTIVE] = { "aktiv", "active" },
    [S_WARN_EXPIRED] = { "abgelaufen", "expired" },
    [S_WARN_VALID_UNTIL] = { "gilt bis", "valid until" },
    [S_WARN_LAST_RX] = { "zuletzt empfangen",     "last received" },
    /* German puts "vor" in front and English appends "ago". The other half stays empty.
     * fmt_age (web_fmt.c) adds them with a non-breaking space. Other callers do that
     * themselves. Also in the tiles of the start page and in /status.json: no double quote. */
    [S_AGO_PRE] = { "vor", "" },
    [S_WARN_AGO] = { "", "ago" },
    [S_CLOCK_UNSET] = { "Uhr nicht gestellt", "clock not set" },
    /* Unlike S_CLOCK_UNSET these four never reach ITS_WA: the clock row on /system and its link
     * on /system and /trust. HTML only, so entities are fine. */
    [S_CLOCK] = { "Uhrzeit", "Clock" },
    /* Read with S_AGO_PRE and S_WARN_AGO: "zuletzt gestellt vor 12 min 3 s". */
    [S_CLOCK_LAST] = { "zuletzt gestellt", "last set" },
    /* Not "never set": the RTC keeps the time over a software restart. */
    [S_CLOCK_NOANSWER] = { "Der NTP-Server hat seit dem letzten Neustart nicht geantwortet.",
        "The NTP server has not answered since the last restart." },
    [S_CLOCK_FIX] = { "NTP-Server pr&uuml;fen", "Check the NTP server" },
    [S_WARN_TERM_HINT] = { "Aufgehoben: der Sender hat die Warnung selbst beendet. Widerrufen: eine andere Station meldet, dass die Gefahr nicht mehr besteht.",
        "Cancelled: the sender ended the warning itself. Revoked by another station: it reports that the hazard is gone." },
    /* Radio reception, fallback address and settings backup on /system and /settings. HTML. */
    [S_SYS_GRP_RX] = { "Funkempfang", "Radio reception" },
    [S_RX_NOISE] = { "Rauschpegel, Mittel der letzten Minute", "Noise floor, last-minute average" },
    [S_RX_NONE] = { "keine Frames in der letzten Minute", "no frames in the last minute" },
    [S_RX_OFF] = { "Funkempfang ist aus", "radio reception is off" },
    [S_RX_BROKEN] = { "Kaputte Frames", "Broken frames" },
    /* Sub-line of the tile, without hlp: the number alone reads like a fault of the device. */
    [S_RX_BROKEN_SUB] = { "gest&ouml;rt angekommen, kein Fehler des Ger&auml;ts",
        "damaged on arrival, not a fault of the device" },
    /* Format strings, placeholders: channel link, then broken count and noise floor (the second
     * has only the link). They travel inside a JSON string, so no double quote, no backslash. */
    [S_RX_QUIET_HEARS] = { "Auf %s kommen Frames an, aber keine lesbare Nachricht. Seit dem "
                           "letzten Neustart waren %lu Frames besch&auml;digt. "
                           "Rauschpegel: %s&nbsp;dBm.",
                           "Frames arrive on %s, but no readable message. %lu frames were damaged "
                           "since the last restart. Noise floor: %s&nbsp;dBm." },
    [S_RX_QUIET_DEAF] = { "Kein Empfang auf %s. Wenn in der N&auml;he Ampeln oder Fahrzeuge "
                          "senden, Antenne und Kanal pr&uuml;fen.",
                          "No reception on %s. If traffic lights or vehicles nearby are sending, "
                          "check the antenna and the channel." },
    [S_RX_HINT] = {
        "Der Rauschpegel ist das Grundrauschen am Funkkanal, gemessen bei jedem Frame. Je tiefer "
        "der Wert, desto weniger St&ouml;rungen auf dem Kanal. Je weiter ein Signal &uuml;ber "
        "dem Rauschpegel liegt, desto sicherer l&auml;sst es sich lesen.<br><br>Ein Frame kommt "
        "kaputt an, wenn zum Beispiel das Signal zu schwach war. Das Ger&auml;t z&auml;hlt diese "
        "Frames nur und wertet sie nicht aus.",
        "The noise floor is the background noise on the radio channel, measured with every "
        "frame. The lower it is, the less interference there is on the channel. The further a "
        "signal stands above it, the more reliably it can be read.<br><br>A frame arrives broken "
        "when, for example, the signal was too weak. The device only counts these frames and "
        "does not decode them." },
    [S_AUTOIP] = { "Ersatzadresse: Kein DHCP-Server gefunden.", "Fallback address: no DHCP server found." },
    [S_AUTOIP_HOST] = { "Erreichbar &uuml;ber", "Reachable at" },
    [S_AUTOIP_HINT] = { "Sobald ein DHCP-Server antwortet, bekommt das Ger&auml;t von ihm eine Adresse.",
        "As soon as a DHCP server answers, the device gets an address from it." },
    [S_BAK_GROUP] = { "Sicherung", "Backup" },
    [S_BAK_EXPORT] = { "Einstellungen exportieren (JSON)", "Export settings (JSON)" },
    [S_BAK_EXPORT_HINT] = {
        "L&auml;dt alle Einstellungen au&szlig;er dem Web-Passwort als JSON-Datei herunter. Die "
        "Datei enth&auml;lt die MQTT-Zugangsdaten, darum bitte nicht weitergeben.",
        "Downloads all settings except the web password as a JSON file. The file contains the "
        "MQTT credentials, so do not share it." },
    [S_BAK_IMPORT_H] = { "Einstellungen importieren", "Import settings" },
    [S_BAK_FILE] = { "Datei (JSON)", "File (JSON)" },
    [S_BAK_DEVICE] = { "Node-ID und feste Netzwerk-Adresse aus der Datei &uuml;bernehmen",
        "Take the node ID and the fixed network address from the file" },
    [S_BAK_DEVICE_HINT] = { "Nur beim Wiederherstellen desselben Ger&auml;ts ankreuzen. Zwei Ger&auml;te mit gleicher ID oder Adresse st&ouml;ren sich."
        "<br><br>Der Haken gilt f&uuml;r Node-ID und feste Netzwerk-Adresse. Die MQTT-Zugangsdaten werden immer &uuml;bernommen.",
        "Tick this only when restoring the same device. Two devices with the same ID or address get in each other&#39;s way."
        "<br><br>The tick covers the node ID and the fixed network address. The MQTT credentials are always imported." },
    [S_BAK_IMPORT] = { "Importieren", "Import" },
    [S_BAK_IMPORT_HINT] = {
        "Das Ger&auml;t pr&uuml;ft jeden Wert wie beim Speichern. Falsche Werte lehnt es ab, die "
        "g&uuml;ltigen &uuml;bernimmt es. Die Ergebnisseite nennt jeden abgelehnten Wert mit "
        "Grund.<br><br>Das Web-Passwort bleibt immer das bisherige, der Export schreibt es nicht "
        "in die Datei.",
        "The device checks every value as it does when saving. It rejects wrong values and "
        "applies the valid ones. The result page lists each rejected value with the "
        "reason.<br><br>The web password always stays as it is, the export does not write it "
        "into the file." },
    [S_IMP_RESULT] = { "Ergebnis", "Result" },
    [S_IMP_APPLIED] = { "&Uuml;bernommen", "Applied" },
    [S_IMP_UNCHANGED] = { "Unver&auml;ndert", "Unchanged" },
    [S_IMP_REJECTED] = { "Abgelehnt", "Rejected" },
    [S_IMP_IGNORED] = { "Ignoriert", "Ignored" },
    [S_IMP_NOTHING] = { "Die Datei enthielt keine Einstellung, die &uuml;bernommen werden konnte.",
        "The file held no setting that could be applied." },
    [S_IMP_REBOOT] = { "Einige ge&auml;nderte Einstellungen wirken erst nach einem Neustart.",
        "Some changed settings take effect only after a restart." },
    [S_IMP_BACK] = { "Zur&uuml;ck zu den Einstellungen", "Back to the settings" },
    [S_IMP_WHY_TYPE_NUM] = { "ganze Zahl erwartet", "whole number expected" },
    [S_IMP_WHY_TYPE_BOOL] = { "true oder false erwartet", "true or false expected" },
    [S_IMP_WHY_TYPE_STR] = { "Text erwartet", "text expected" },
    [S_IMP_WHY_RANGE] = { "außerhalb des erlaubten Bereichs", "outside the allowed range" },
    [S_IMP_WHY_EMPTY] = { "darf nicht leer sein", "must not be empty" },
    [S_IMP_WHY_LONG] = { "zu lang", "too long" },
    [S_IMP_WHY_CHARS] = { "enthält verbotene Zeichen", "contains forbidden characters" },
    [S_IMP_WHY_CHOICE] = { "kein Kanal aus der Auswahl", "not one of the offered channels" },
    [S_IMP_WHY_IPV4] = { "keine gültige IPv4-Adresse", "not a valid IPv4 address" },
    [S_IMP_WHY_COLOR] = { "Farbe im Format #rrggbb erwartet", "colour expected as #rrggbb" },
    [S_IMP_WHY_STATIC] = { "feste Adresse braucht gültige IP-Adresse, Subnetzmaske und Gateway",
        "a fixed address needs a valid IP address, subnet mask and gateway" },
    /* The masked password is kept only while server and user stay the same, so it never goes
     * to a new server. Text reply like its neighbours: real UTF-8. */
    [S_IMP_WHY_MASK] = {
        "Server oder Benutzer sind neu, darum das Passwort eintippen statt ••••",
        "the server or user changed, so type the password instead of ••••" },
    [S_IMP_WHY_STORE] = { "Speichern fehlgeschlagen", "saving failed" },
    [S_IMP_WHY_UNKNOWN] = { "unbekannte Einstellung", "unknown setting" },
    [S_IMP_WHY_PASSWORD] = { "das Web-Passwort wird nie importiert", "the web password is never imported" },
    [S_IMP_WHY_DEVICE] = { "gehört zu einem Gerät, nur mit Haken übernommen",
        "belongs to one device, taken only when ticked" },
    [S_IMP_WHY_NOT_BUILT] = { "gibt es in dieser Firmware nicht", "not available in this firmware" },
    [S_IMP_WHY_DHCP_UNUSED] = { "wird bei DHCP nicht verwendet", "not used with DHCP" },
    [S_IMP_WHY_NEEDS_DHCP] = { "gilt nur zusammen mit dhcp", "only valid together with dhcp" },
    [S_IMP_FILE_NONE] = { "Keine Datei empfangen, oder die Datei ist leer.",
        "No file received, or the file is empty." },
    [S_IMP_FILE_BIG] = { "Die Datei ist zu gro&szlig;, h&ouml;chstens 16&nbsp;KB.",
        "The file is too large, 16&nbsp;KB at most." },
    [S_IMP_FILE_JSON] = { "Die Datei ist kein g&uuml;ltiges JSON.", "The file is not valid JSON." },
    [S_IMP_FILE_MEM] = { "Zu wenig Speicher, um die Datei zu lesen.", "Not enough memory to read the file." },
    [S_IMP_FILE_MANY] = { "Die Datei hat zu viele Eintr&auml;ge.", "The file has too many entries." },
    [S_IMP_FILE_FORMAT] = { "Das ist keine Einstellungsdatei dieses Empf&auml;ngers.",
        "This is not a settings file of this receiver." },
    [S_IMP_FILE_NEWER] = { "Die Datei stammt aus einer neueren Firmware. Bitte zuerst die Firmware aktualisieren.",
        "The file comes from a newer firmware. Please update the firmware first." },
    /* Warning areas on /map. The layer name is a label in the layer control. */
    [S_MAP_LAYER_WARN] = { "Warnbereiche", "Warning areas" },
    /* Shown with textContent -> literal UTF-8, no HTML entity. */
    [S_MAP_WARN_CAP] = { "Es fehlen vielleicht Warnbereiche, weil der Speicher für Warnungen voll war.",
        "Some warning areas may be missing because the memory for warnings was full." },
    /* Signal requests on /transit. HTML. */
    [S_PT_REQUEST] = { "Ampelanforderung", "Signal request" },
    [S_PT_REQ_NONE] = { "keine", "none" },
    [S_PT_PRIORITY] = { "Priorit&auml;t", "priority" },
    [S_PT_REQ_COUNT] = { "Ampelanforderungen", "Signal requests" },
    [S_PT_REQ_HINT] = {
        "Die Spalte &bdquo;Ampelanforderung&ldquo; zeigt, f&uuml;r welche Richtung sich das "
        "Fahrzeug zuletzt bei der Ampel angemeldet hat: &bdquo;geradeaus&ldquo;, "
        "&bdquo;links&ldquo; oder &bdquo;rechts&ldquo;.<br><br>Dahinter steht die h&ouml;chste "
        "Priorit&auml;t w&auml;hrend der Vorbeifahrt, 1 bis 3, so wie das Fahrzeug sie "
        "schickt.<br><br>&bdquo;keine&ldquo; hei&szlig;t: keine Anmeldung. "
        "&bdquo;unbekannt&ldquo; steht bei Vorbeifahrten, die eine &auml;ltere Firmware ohne "
        "diese Angabe gespeichert hat.",
        "The &ldquo;Signal request&rdquo; column shows which direction the vehicle last "
        "registered for at the traffic light: &ldquo;straight&rdquo;, &ldquo;left&rdquo; or "
        "&ldquo;right&rdquo;.<br><br>After it comes the highest priority during the passage, 1 "
        "to 3, as the vehicle sends it.<br><br>&ldquo;none&rdquo; means no registration. "
        "&ldquo;unknown&rdquo; marks passages that an older firmware stored without this "
        "information." },
    /* Certificate cache on /system, under the heading S_TRUST_H_SEEN. HTML, also inside
     * the /system.json field cert_sub. */
    /* Both numerator and denominator count short identifiers (digests_known and
     * digests_missing in format_certcache). Messages with a whole certificate are in neither. */
    [S_CERTCACHE_SHARE] = { "Kurzkennungen zugeordnet",
        "Short identifiers matched" },
    [S_CERTCACHE_NONE] = { "noch keine Kurzkennung empfangen", "no short identifier received yet" },
    [S_CERTCACHE_HINT] = {
        "Die meisten Nachrichten nennen nur eine Kurzkennung, nicht das ganze Zertifikat. Das "
        "Ger&auml;t ordnet sie den Zertifikaten zu, die es schon empfangen hat. Das ist noch "
        "keine Pr&uuml;fung.",
        "Most messages carry only a short identifier, not the whole certificate. The device "
        "matches it against the certificates it has already received. That is not a check yet." },
    /* The chain verdict of one certificate. HTML on /messages and /senders, and the same
     * text goes into the JSON field h, which is why no quote and no angle bracket may appear. */
    [S_TRUST_YES] = { "vertrauensw&uuml;rdig", "trustworthy" },
    [S_TRUST_UNCHECKED] = { "noch nicht gepr&uuml;ft", "not checked yet" },
    [S_TRUST_NOCHECK] = { "nicht pr&uuml;fbar", "cannot be checked" },
    [S_TRUST_INVALID] = { "ung&uuml;ltig", "invalid" },
    [S_TRUST_SIG_INVALID] = { "Signatur ung&uuml;ltig", "signature invalid" },
    [S_TRUST_WHY_ISSUER] = { "Zertifikat des Ausstellers fehlt", "issuer certificate not received" },
    [S_TRUST_WHY_ROOT] = { "oberste Stelle fehlt in dieser Firmware, ein Update kann helfen",
                           "root missing from this firmware, an update may help" },
    [S_TRUST_WHY_CHAIN] = { "Aussteller nicht vertrauensw&uuml;rdig", "issuer not trustworthy" },
    [S_TRUST_WHY_EXPIRED] = { "Zertifikat abgelaufen", "certificate expired" },
    [S_TRUST_WHY_NOTYET] = { "Zertifikat noch nicht g&uuml;ltig", "certificate not valid yet" },
    [S_TRUST_WHY_NOPERIOD] = { "Zertifikat ohne Zeitraum", "certificate without a period" },
    [S_TRUST_WHY_CLOCK] = { "Uhr nicht gestellt", "clock not set" },
    [S_TRUST_WHY_CURVE] = { "Kurve nicht unterst&uuml;tzt", "curve not supported" },
    [S_TRUST_WHY_IMPLICIT] = { "implizites Zertifikat ohne Signatur", "implicit certificate without a signature" },
    [S_TRUST_WHY_PARSE] = { "Zertifikat nicht lesbar", "certificate could not be read" },
    [S_TRUST_WHY_LONG] = { "Zertifikat zu lang", "certificate too long" },
    [S_TRUST_WHY_FORM] = { "Schl&uuml;ssel in unerwarteter Form", "key in an unexpected form" },
    [S_TRUST_WHY_CRYPTO] = { "Pr&uuml;fung im Ger&auml;t fehlgeschlagen", "the check failed inside the device" },
    [S_TRUST_WHY_OTHER] = { "Grund unbekannt", "reason unknown" },
    [S_TRUST_LIST] = { "Liste", "list" },
    [S_TRUST_CHAIN] = { "Kette", "chain" },
    /* The chain check on /system, named apart from the message signatures beside it. HTML,
     * also inside the /system.json field trust_sub. */
    [S_TRUST_CHECKS] = { "Kettenpr&uuml;fungen", "Chain checks" },
    [S_TRUST_NO_CHECKS_YET] = { "noch keine Kette gepr&uuml;ft", "no chain checked yet" },
    [S_TRUST_DROPPED] = { "ausgelassen", "skipped" },
    [S_TRUST_ISSUERS] = { "bekannte Aussteller", "known issuers" },
    [S_TRUST_SLOWEST] = { "l&auml;ngste Pr&uuml;fung", "slowest check" },
    [S_TRUSTLIST_DATE] = { "Stand",
                           "as of" },
    [S_TRUSTLIST_TOTAL] = { "Eintr&auml;ge in der Tabelle", "entries in the table" },
    /* The table holds more than the roots. n_roots counts neither the list managers nor the
     * replaced predecessors, but the table lists both. */
    [S_TRUSTLIST_GAP] = { "die Differenz sind Listen-Verwalter und abgel&ouml;ste Eintr&auml;ge",
                          "the difference is list managers and replaced entries" },
    [S_TRUSTLIST_NONE] = { "keine EU-Liste eingebaut", "no EU list built in" },
    /* The summary line of the collapsed explanation, same pattern as the loss table. */
    [S_CERT_SUM] = {
        "Wie das Ger&auml;t Zertifikate pr&uuml;ft",
        "How the device checks certificates" },
    /* Heading of the certificate group on /system. */
    [S_SYS_GRP_CERT] = { "Signaturen und Berechtigungen", "Signatures and permissions" },
    [S_TRUST_MEANS] = {
        "F&uuml;r &bdquo;vertrauensw&uuml;rdig&ldquo; verfolgt das Ger&auml;t, wer das "
        "Zertifikat des Senders ausgestellt hat und wer das des Ausstellers. Ganz oben muss eine "
        "Stelle stehen, die auf einer der eingebauten Listen der EU-Kommission "
        "steht.<br><br>Ohne das Zertifikat des Ausstellers oder ohne gestellte Uhr lautet das "
        "Ergebnis &bdquo;nicht pr&uuml;fbar&ldquo;.",
        "For &ldquo;trustworthy&rdquo; the device follows the chain: the issuer of the sender's "
        "certificate, then the issuer of that issuer. At the top there has to be a body from one "
        "of the built-in lists of the European Commission.<br><br>Without the issuer "
        "certificate, or with the clock not set, the result is &ldquo;cannot be checked&rdquo;." },
    /* The summary line over the two notes under the message table. */
    [S_DETAIL_SUM] = { "Was die Spalten bedeuten", "What the columns mean" },
    /* Under the message table. HTML in one <p> of web_messages.c, so paragraphs are split by
     * <br><br>. It reads like the cell: the content first, then the grey signature line. */
    [S_DETAIL_HINT] = {
        "Die Spalte &bdquo;Details&ldquo; zeigt zuerst den Inhalt der Nachricht. "
        "<code>Zielgebiet: Kreis, Radius 500 m</code> hei&szlig;t zum Beispiel: Die Nachricht "
        "ist f&uuml;r alle in diesem Umkreis bestimmt.<br><br>Die graue Zeile darunter nennt das "
        "Zertifikat, mit dem die Nachricht signiert ist, etwa <code>Kurzkennung "
        "1a2b3c4d&hellip;</code>. Die Kennung ist auf 8 Zeichen "
        "gek&uuml;rzt.<br><br><code>vertrauensw&uuml;rdig (1_EU-ROOT-CA_L1, 1_EU-AA_L1)</code>: "
        "Die Klammer nennt zuerst die oberste Stelle aus einer EU-Liste, dann den Aussteller des "
        "Zertifikats. Alle Signaturen dazwischen stimmen.<br><br>Ein einzelner Name hei&szlig;t: "
        "Die oberste Stelle hat das Zertifikat selbst "
        "ausgestellt.<br><br>&bdquo;vertrauensw&uuml;rdig&ldquo; gilt nur f&uuml;r das "
        "Zertifikat. Ob die Nachricht selbst echt ist, steht weiter hinten in der "
        "Zeile.<br><br><code>nicht pr&uuml;fbar: Zertifikat des Ausstellers fehlt</code>: Dem "
        "Ger&auml;t fehlt etwas f&uuml;r die Pr&uuml;fung. Gegen den Sender spricht das nicht. "
        "&bdquo;ung&uuml;ltig&ldquo; hei&szlig;t: Die Pr&uuml;fung hat einen Fehler gefunden, "
        "etwa ein abgelaufenes Zertifikat.<br><br>&bdquo;zur&uuml;ckgezogen&ldquo;: Das "
        "Zertifikat oder einer seiner Aussteller steht auf einer eingebauten Sperrliste. Was "
        "erst nach dem Datum der Liste zur&uuml;ckgezogen wurde, kennt das Ger&auml;t "
        "nicht.<br><br>Das Zertifikat legt auch fest, welche Nachrichten sein Besitzer senden "
        "darf. Die Art der Nachricht hei&szlig;t hier Dienst, die PSID ist seine Nummer. 36 "
        "steht zum Beispiel f&uuml;r CAM.<br><br><code>Dienst erlaubt (PSID 36)</code>: Das "
        "Zertifikat erlaubt CAM. <code>Inhalt erlaubt (Zusatzangaben &Ouml;PNV)</code>: Ein Bus "
        "schickt Angaben f&uuml;r den &Ouml;PNV mit, und sein Zertifikat erlaubt das. Bei "
        "&bdquo;Inhalt nicht pr&uuml;fbar&ldquo; steht der Grund in der "
        "Klammer.<br><br><code>Signatur echt</code> hei&szlig;t: Das Ger&auml;t hat "
        "nachgerechnet. Die Nachricht kommt unver&auml;ndert vom Besitzer des "
        "Zertifikats.<br><br>Das macht es nur bei einem Teil der Nachrichten. Bei den anderen "
        "steht, wie es bei diesem Zertifikat bisher ausging, etwa <code>dieses Zertifikat "
        "bisher: 12 echt, 0 falsch</code>.<br><br>Bei &bdquo;Signatur nicht gepr&uuml;ft&ldquo; "
        "ist offen, ob die Nachricht echt ist. Die Zahlen in der Klammer stammen von "
        "fr&uuml;heren Nachrichten.<br><br>&bdquo;echt&ldquo; ohne "
        "&bdquo;vertrauensw&uuml;rdig&ldquo; sagt nicht, wer sendet, denn ein Zertifikat kann "
        "sich jeder selbst machen.<br><br><code>Signatur in Pr&uuml;fung</code>: Bei Brainpool "
        "dauert das einige Sekunden. Das Ergebnis steht dann bei den n&auml;chsten Nachrichten "
        "mit demselben Zertifikat und auf der Seite "
        "&bdquo;<a href='/trust?lang=de#t-msig'>Zertifikate</a>&ldquo;.",
        "The &ldquo;Details&rdquo; column first shows the content of the message. <code>target "
        "area: circle, radius 500 m</code>, for example, means: the message is meant for "
        "everyone within this range.<br><br>The grey line below names the certificate the "
        "message is signed with, such as <code>short identifier 1a2b3c4d&hellip;</code>. The "
        "identifier is cut to 8 characters.<br><br><code>trustworthy (1_EU-ROOT-CA_L1, "
        "1_EU-AA_L1)</code>: the brackets first name the root from an EU list, then the issuer "
        "of the certificate. Every signature in between matches.<br><br>A single name means the "
        "root itself is the issuer of the certificate.<br><br>&ldquo;trustworthy&rdquo; only "
        "applies to the certificate. Whether the message itself is genuine is said further on in "
        "the line.<br><br><code>cannot be checked: issuer certificate not received</code>: the "
        "device lacks something for the check. That says nothing against the sender. "
        "&ldquo;invalid&rdquo; means the check found a fault, such as an expired "
        "certificate.<br><br>&ldquo;withdrawn&rdquo;: the certificate or one of its issuers is "
        "on a built-in revocation list. Anything withdrawn after the date of the list is unknown "
        "to the device.<br><br>A certificate also sets which messages its owner may send. The "
        "kind of message is called the service here, and the PSID is its number. 36, for "
        "example, stands for CAM.<br><br><code>service allowed (PSID 36)</code>: the certificate "
        "allows CAM. <code>content allowed (extra data public transport)</code>: a bus sends "
        "public transport data along, and its certificate allows that. With &ldquo;content "
        "cannot be checked&rdquo; the brackets give the reason.<br><br><code>signature "
        "genuine</code> means: the device did the math. The message came unchanged from the "
        "owner of the certificate.<br><br>It does that for only part of the messages. The others "
        "show how this certificate fared so far, for example <code>this certificate so far: 12 "
        "genuine, 0 not matching</code>.<br><br>With &ldquo;signature not checked&rdquo; it is "
        "open whether the message is genuine. The numbers in brackets come from earlier "
        "messages.<br><br>&ldquo;genuine&rdquo; without &ldquo;trustworthy&rdquo; does not say "
        "who sent it, because anyone can make a certificate of their own.<br><br><code>signature "
        "being checked</code>: with Brainpool this takes a few seconds. The result then shows "
        "with the next messages under the same certificate and on the "
        "&ldquo;<a href='/trust?lang=en#t-msig'>Certificates</a>&rdquo; page." },
    /* The signature of the message itself (its_msgsig.c), its own item after the permission.
     * HTML inside the JSON field h, so no quote, backslash or angle bracket. */
    [S_MSIG_OK] = { "Signatur echt", "signature genuine" },
    [S_MSIG_BAD] = { "Signatur falsch", "signature does not match" },
    [S_MSIG_PENDING] = { "Signatur in Pr&uuml;fung", "signature being checked" },
    [S_MSIG_SAMPLE] = { "Signatur nicht gepr&uuml;ft", "signature not checked" },
    [S_MSIG_BUSY] = { "Signatur nicht gepr&uuml;ft, ausgelastet", "signature not checked, busy" },
    [S_MSIG_NOCHECK] = { "Signatur nicht pr&uuml;fbar", "signature cannot be checked" },
    [S_MSIG_WHY_NOCERT] = { "Zertifikat fehlt", "certificate missing" },
    [S_MSIG_WHY_FORM] = { "Form nicht unterst&uuml;tzt", "form not supported" },
    [S_MSIG_WHY_HASH] = { "Hash nicht SHA-256", "hash is not SHA-256" },
    [S_MSIG_WHY_CRYPTO] = { "Krypto-Bibliothek lehnt ab", "refused by the crypto library" },
    [S_MSIG_WHY_CURVE] = { "andere Kurve als der Schl&uuml;ssel", "other curve than the key" },
    /* What the certificate gave so far, behind a message that was not checked itself. */
    [S_MSIG_SO_FAR] = { "dieses Zertifikat bisher", "this certificate so far" },
    [S_MSIG_N_OK] = { "echt", "genuine" },
    [S_MSIG_N_BAD] = { "falsch", "not matching" },
    /* The tile on /system, the line on /senders and the table on /trust. */
    [S_MSIG_TITLE] = { "Nachrichten-Signaturen", "Message signatures" },
    [S_MSIG_CERT_TITLE] = { "Nachrichten-Signaturen (Stichprobe)", "Message signatures (sample)" },
    [S_MSIG_NONE_YET] = { "noch keine gepr&uuml;ft", "none checked yet" },
    [S_MSIG_N_NOCHECK] = { "nicht pr&uuml;fbar", "cannot be checked" },
    [S_MSIG_N_NOTCHECKED] = { "nicht gepr&uuml;ft", "not checked" },
    [S_MSIG_N_SAMPLE] = { "au&szlig;erhalb der Stichprobe", "outside the sample" },
    [S_MSIG_N_BUSY] = { "ausgelastet", "busy" },
    [S_MSIG_MAX] = { "h&ouml;chstens", "at most" },
    /* The numbers in S_MSIG_HINT2 and S_MSIG_T_HINT come from its_msgsig.c. A change there
     * has to reach both texts. */
    [S_MSIG_HINT] = {
        "Bei einem Teil der Nachrichten rechnet das Ger&auml;t die Signatur selbst nach: Kommt "
        "die Nachricht unver&auml;ndert vom Besitzer des Zertifikats? &bdquo;echt&ldquo; "
        "hei&szlig;t ja. &bdquo;vertrauensw&uuml;rdig&ldquo; gilt dagegen nur f&uuml;r das "
        "Zertifikat.<br><br>&bdquo;echt&ldquo; ohne &bdquo;vertrauensw&uuml;rdig&ldquo; sagt "
        "nicht, wer sendet, denn ein Zertifikat kann sich jeder selbst machen.",
        "For part of the messages the device recomputes the signature itself: did the message "
        "come unchanged from the owner of the certificate? &ldquo;genuine&rdquo; means yes. "
        "&ldquo;trustworthy&rdquo; only applies to the certificate.<br><br>&ldquo;genuine&rdquo; "
        "without &ldquo;trustworthy&rdquo; does not say who sent it, because anyone can make a "
        "certificate of their own." },
    [S_MSIG_HINT2] = {
        "NIST P-256 rechnet der Chip in Hardware, Brainpool viel langsamer in Software. Darum "
        "pr&uuml;ft das Ger&auml;t dasselbe Zertifikat fr&uuml;hestens nach 5 bis 15 Sekunden "
        "wieder, bei Brainpool nach 5 bis 15 Minuten.<br><br>Bei vielen Zertifikaten kommt jedes "
        "seltener dran. Alles zusammen braucht h&ouml;chstens 5 % der Rechenzeit, Zertifikate "
        "ohne vertrauensw&uuml;rdige Kette davon h&ouml;chstens die H&auml;lfte.",
        "The chip computes NIST P-256 in hardware, Brainpool far slower in software. So the "
        "device checks the same certificate again after 5 to 15 seconds at the earliest, with "
        "Brainpool after 5 to 15 minutes.<br><br>With many certificates each comes up less "
        "often. All of it takes at most 5 % of the computing time, certificates without a "
        "trustworthy chain at most half of that." },
    [S_MSIG_T_HINT] = {
        "Die neuesten 32 Pr&uuml;fungen seit dem letzten Neustart, die neueste oben. Eine "
        "falsche Signatur kommt auch ins Log: die erste je Zertifikat mit "
        "vertrauensw&uuml;rdiger Kette immer, sonst h&ouml;chstens eine Zeile alle 10 "
        "Sekunden.<br><br>Unter &bdquo;Absender&ldquo; steht der Name der Anlage von der Seite "
        "&bdquo;Anlagen&ldquo;, bei anderen Sendern ihre Art, etwa Auto oder Bus. Klein darunter "
        "steht die Stations-Nummer. Fahrzeuge haben keinen Namen, weil sie diese Nummer laufend "
        "wechseln.",
        "The newest 32 checks since the last restart, newest first. A signature that does not "
        "match also goes into the log: the first per certificate with a trustworthy chain "
        "always, the rest at most one line every 10 seconds.<br><br>Under &ldquo;Sender&rdquo; "
        "is the name of the unit from the page &ldquo;Roadside units&rdquo;, for other senders "
        "their kind, such as car or bus. Below it, in small print, is the station ID. Vehicles "
        "have no name, because they keep changing this number." },
    /* Only a build with a card records, and only there /settings has the anchor. */
    [S_MSIG_T_REC] = {
        "Wenn das Ger&auml;t aufzeichnet, beh&auml;lt es jede gepr&uuml;fte Nachricht, auch wenn "
        "der &bdquo;<a href='/settings?lang=de#pcapfilt'>Umfang der Aufzeichnung</a>&ldquo; "
        "gek&uuml;rzt ist.",
        "While recording, the device keeps every checked message, whatever "
        "&ldquo;<a href='/settings?lang=en#pcapfilt'>What gets recorded</a>&rdquo; says." },
    [S_MSIG_T_NONE] = { "Noch keine Nachricht gepr&uuml;ft.", "No message checked yet." },
    [S_MSIG_C_US] = { "Dauer", "Time taken" },
    [S_MSIG_C_MSG] = { "Nachricht", "Message" },
    [S_MSIG_CHECK] = { "Pr&uuml;fung", "check" },
    [S_MSIG_CHECKS] = { "Pr&uuml;fungen", "checks" },
    /* The two permission answers of the signing certificate, each its own item after the chain
     * verdict on /messages: the service (PSID), then the content (SSP bits). HTML, also inside
     * the JSON field h, so without a quote, a backslash or an angle bracket. */
    [S_PERM_OK] = { "Dienst erlaubt", "service allowed" },
    [S_PERM_BAD] = { "Dienst nicht erlaubt", "service not allowed" },
    [S_PERM_UNKNOWN] = { "Dienst nicht pr&uuml;fbar", "service cannot be checked" },
    [S_PERM_CONT_OK] = { "Inhalt erlaubt", "content allowed" },
    [S_PERM_CONT_BAD] = { "Inhalt nicht erlaubt", "content not allowed" },
    [S_PERM_CONT_UNKNOWN] = { "Inhalt nicht pr&uuml;fbar", "content cannot be checked" },
    /* What the content answer was held against, in the brackets behind it. Same sinks, and
     * short: the detail line of a message already carries a lot. */
    [S_PERM_WHY_UNCHECKED] = { "nicht gepr&uuml;ft", "not checked" },
    [S_PERM_WHY_SSP_NONE] = { "nicht eingeschr&auml;nkt", "not restricted" },
    [S_PERM_WHY_SSP_VER] = { "Berechtigungsversion unbekannt", "permission version unknown" },
    [S_PERM_WHY_SSP_FORM] = { "Berechtigungsform unbekannt", "permission form unknown" },
    /* The cause of a hazard notification, with the number the message carried. */
    [S_PERM_WHY_CAUSE] = { "Ursache", "cause" },
    /* Nobody wrote down whether this one is allowed: most cause codes have no bit of their
     * own, and a bitmap may also end before the bit that was wanted. */
    [S_PERM_WHY_NOBIT] = { "kein Bit daf&uuml;r", "no bit for it" },
    /* A digest names a certificate the frame did not carry. The store keeps its services, but
     * its permission bits only after a frame showed them, so here nothing finer was at hand. */
    [S_PERM_WHY_NOBITS] = { "Berechtigungsbits nicht gespeichert",
        "permission bits not stored" },
    [S_PERM_WHY_NOTREAD] = { "nicht gelesen", "not read" },
    /* Bit 0 was held against what was read. A later intersection, an extension, or the rest
     * after the walk broke off was not read. */
    [S_PERM_WHY_PART] = { "nur teilweise gelesen", "only partly read" },
    [S_PERM_WHY_ZONE] = { "Zone angek&uuml;ndigt", "zone announced" },
    /* A special container of a CAM, named after what it is for, like the vehicle roles. */
    [S_PERM_WHY_EXTRA] = { "Zusatzangaben", "extra data" },
    [S_PERM_WHY_ROLE] = { "Rolle", "role" },
    [S_PERM_WHY_SERVICE] = { "f&uuml;r diesen Dienst nichts geregelt",
        "nothing covered for this service" },
    [S_PERM_WHY_VERONLY] = { "nur die Version geregelt", "only the version is covered" },
    /* A plain CAM: its bits cover a zone and the special containers, and it carries neither.
     * The same words as the free part of the content tile. */
    [S_PERM_WHY_NOTHING] = { "nichts zu pr&uuml;fen", "nothing to check" },
    /* The two permission tiles on /system, their lines also inside the JSON fields perm_sub and
     * perm_content_sub. The three labels are read together: only the first two decided. */
    [S_PERM_TITLE] = { "Dienst-Pr&uuml;fungen", "Service checks" },
    [S_PERM_CONT_TITLE] = { "Inhalts-Pr&uuml;fungen", "Content checks" },
    [S_PERM_C_OK] = { "erlaubt", "allowed" },
    [S_PERM_C_BAD] = { "nicht erlaubt", "not allowed" },
    [S_PERM_C_OPEN] = { "nicht pr&uuml;fbar", "cannot be checked" },
    [S_PERM_C_FREE] = { "davon nichts zu pr&uuml;fen", "of those nothing to check" },
    [S_PERM_NONE_YET] = { "noch kein Dienst gepr&uuml;ft", "no service checked yet" },
    [S_PERM_CONT_NONE_YET] = { "noch kein Inhalt gepr&uuml;ft", "no content checked yet" },
    [S_PERM_HINT] = {
        "Ein Zertifikat legt fest, welche Nachrichten sein Sender schicken darf. Die Art der "
        "Nachricht hei&szlig;t hier Dienst. Die Kachel &bdquo;Dienst-Pr&uuml;fungen&ldquo; "
        "z&auml;hlt, wie oft das gepr&uuml;ft wurde.<br><br>Ein Zertifikat kann auch einzelne "
        "Inhalte erlauben. Bei einer Warnung (DENM) ist das die Ursache. Beim Fahrzeug-Status "
        "(CAM) sind es die Zusatzangaben, etwa &Ouml;PNV. Bei einer Ampelanforderung (SREM) ist "
        "es die Rolle, etwa Polizei.<br><br>Das Ger&auml;t pr&uuml;ft den Inhalt nur, wenn der "
        "Dienst erlaubt ist. Die Kachel &bdquo;Inhalts-Pr&uuml;fungen&ldquo; z&auml;hlt, wie oft "
        "das gepr&uuml;ft wurde.<br><br>Das Ger&auml;t pr&uuml;ft Zertifikat, Dienst und Inhalt "
        "getrennt. Ein Zertifikat kann &bdquo;vertrauensw&uuml;rdig&ldquo; sein und eine "
        "Nachricht trotzdem nicht erlauben. Dann steht in der Zeile der Nachricht &bdquo;Dienst "
        "nicht erlaubt&ldquo; oder &bdquo;Inhalt nicht erlaubt&ldquo;.",
        "A certificate states which messages its sender may send. The kind of message is called "
        "the service here. The tile &ldquo;Service checks&rdquo; counts how often this was "
        "checked.<br><br>A certificate can also allow individual contents. For a hazard warning "
        "(DENM) that is the cause. For a vehicle status (CAM) it is the extra data, such as "
        "public transport. For a signal request (SREM) it is the role, such as "
        "police.<br><br>The device only checks the content when the service is allowed. The tile "
        "&ldquo;Content checks&rdquo; counts how often this was checked.<br><br>The device "
        "checks certificate, service and content separately. A certificate can be "
        "&ldquo;trustworthy&rdquo; and still not allow a message. The line of the message then "
        "says &ldquo;service not allowed&rdquo; or &ldquo;content not allowed&rdquo;." },
    [S_PERM_HINT2] = {
        "Manchmal legt die Norm nicht fest, welches Bit f&uuml;r welchen Inhalt gilt. Dann steht "
        "&bdquo;Inhalt nicht pr&uuml;fbar&ldquo;, nie &bdquo;Inhalt nicht "
        "erlaubt&ldquo;.<br><br>Bei Verkehrszeichen (IVIM) und Dienst-Ank&uuml;ndigungen (SAEM) "
        "pr&uuml;ft das Ger&auml;t den Inhalt nicht.<br><br>Bei den Zusatzangaben (CAM) "
        "pr&uuml;ft es nur die Art, etwa Baustelle, nicht die Einzelheiten. Bei einer "
        "Ampelanforderung (SREM) pr&uuml;ft es die Rolle, aber keine weiteren Angaben zum "
        "Anfragenden.",
        "Sometimes the standard does not define which bit stands for which content. Then it says "
        "&ldquo;content cannot be checked&rdquo;, never &ldquo;content not "
        "allowed&rdquo;.<br><br>For traffic sign messages (IVIM) and service announcements "
        "(SAEM) the device does not check the content.<br><br>For the extra data (CAM) it only "
        "checks the kind, such as roadworks, not the details. For a signal request (SREM) it "
        "checks the role, but no further data about the requester." },
    /* Said in the certificate group on /system when no list is built in. HTML. */
    [S_CRL_NONE] = {
        "In dieser Firmware ist keine Sperrliste eingebaut. Eine Sperrliste nennt Zertifikate, "
        "die vor ihrem Ablauf zur&uuml;ckgezogen wurden. Ohne sie kann bei so einem Zertifikat "
        "&bdquo;vertrauensw&uuml;rdig&ldquo; statt &bdquo;zur&uuml;ckgezogen&ldquo; "
        "stehen.<br><br>Die ver&ouml;ffentlichten Versionen haben Sperrlisten. Ein "
        "&bdquo;<a href='/update?lang=de'>Firmware-Update</a>&ldquo; auf eine davon behebt das.",
        "No revocation list is built into this firmware. Such a list names certificates that "
        "were withdrawn before they ran out. Without one, such a certificate can show "
        "&ldquo;trustworthy&rdquo; instead of &ldquo;withdrawn&rdquo;.<br><br>The published "
        "versions have revocation lists. A &ldquo;<a href='/update?lang=en'>Firmware "
        "update</a>&rdquo; to one of them fixes this." },
    /* In the signature tile on /system. HTML. */
    [S_TRUST_SELFTEST_OK] = { "Selbsttest bestanden in", "self test passed in" },
    [S_TRUST_SELFTEST_FAIL] = { "Selbsttest fehlgeschlagen nach",
        "self test failed after" },
    /* Two more chain verdicts, beside S_TRUST_YES above. Same sinks, so no quote and no
     * angle bracket. The word stands alone, because the counters on /system reuse it. */
    [S_TRUST_REVOKED] = { "zur&uuml;ckgezogen", "withdrawn" },
    [S_TRUST_WHY_NOISSUE] = { "Aussteller darf keine Zertifikate ausstellen",
        "the issuer is not allowed to issue certificates" },
    /* In the signature tile on /system, the least free stack the verify task ever had. */
    [S_TRUST_STACK_LEFT] = { "Stack frei",  "stack free" },
    /* Said in the detail view when the authority certificate came out of the firmware,
     * because the sender never sent one. HTML. */
    [S_TRUST_FROM_STORE] = { "Aussteller aus der Firmware, nicht mitgesendet",
        "issuer taken from the firmware, not sent along" },
    /* Expired checks are part of the invalid ones, which is why the wording says so. */
    [S_TRUST_C_EXPIRED] = { "davon abgelaufen", "of those expired" },
    /* In the detail view, in front of the date of the list that names this certificate. */
    [S_CRL_DATE_PRE] = { "Sperrliste vom", "Revocation list dated" },
    /* Joins the two dates of the revocation-list line on /system, the span the built-in set
     * covers: naming only the oldest would let one abandoned list from 2020 speak for lists
     * renewed years later. HTML. */
    [S_CRL_TO] = { "bis", "to" },
    /* Its own help paragraph under the list line on /system, not inside it: an explanation,
     * no state, so the switch for the explanations hides it. HTML. */
    [S_CRL_GAP] = {
        "Was erst nach dem Datum der Sperrliste zur&uuml;ckgezogen wurde, erkennt das Ger&auml;t "
        "nicht.",
        "Anything withdrawn only after the date of the revocation list is not detected by the "
        "device." },
    [S_CRL_LISTS] = { "Listen", "lists" },
    /* The same words as S_TRUST_CRL_IDS on /trust. It is the same number, and two wordings
     * would make it look like two different measurements. */
    [S_CRL_ENTRIES] = { "gesperrte Kennungen", "withdrawn identifiers" },
    /* One abandoned list must not speak for the whole set, so a count says how many of them
     * are late, and the date belongs to the oldest of those. */
    [S_CRL_OF] = { "von", "of" },
    [S_CRL_OVERDUE] = { "Listen &uuml;berf&auml;llig, die &auml;lteste seit",
        "lists overdue, the oldest since" },
    /* Ends the overdue line: the device fetches no lists, only a newer firmware brings them. */
    [S_CRL_NEWFW] = { "eine neuere Firmware bringt neue Listen",
        "a newer firmware brings new lists" },
    /* The built-in authority store in the certificate group on /system: the count word of
     * the line that S_TRUST_H_CAS starts. HTML. */
    [S_CASTORE_CERTS] = { "Zertifikate", "certificates" },
    /* A whole grey paragraph on /system, so a sentence with a capital and a full stop. */
    [S_CASTORE_NONE] = { "Keine Aussteller-Zertifikate eingebaut.",
        "No issuer certificates built in." },
    [S_CASTORE_HINT] = {
        "Zum Pr&uuml;fen braucht das Ger&auml;t auch das Zertifikat des Ausstellers. Manche "
        "Aussteller schicken es nie mit. Darum liegen solche Zertifikate in der "
        "Firmware.<br><br>In der Zeile &bdquo;Eingebaute Aussteller&ldquo; steht hinter "
        "&bdquo;Stand&ldquo; der Tag, an dem sie geholt wurden. Ein Aussteller, der sp&auml;ter "
        "dazukam, fehlt.<br><br>Wenn er sein Zertifikat nicht mitschickt, bleiben seine Sender "
        "&bdquo;nicht pr&uuml;fbar&ldquo;, bis eine neuere Firmware es mitbringt.",
        "To check a certificate the device also needs the issuer certificate. Some issuers never "
        "send it. That is why such certificates sit in the firmware.<br><br>In the line "
        "&ldquo;Built-in issuers&rdquo;, the date after &ldquo;as of&rdquo; is the day they were "
        "collected. An issuer that came later is missing.<br><br>If it does not send its "
        "certificate, its senders stay &ldquo;cannot be checked&rdquo; until a newer firmware "
        "brings it along." },

    /* ---- /trust: the material the chain check rests on ---------------------------- */
    /* All of it is HTML in a page (the four headings also name their lines on /system), never
     * inside a JSON string, so entities are free. The texts still avoid the quote and the
     * backslash, so a later /trust.json costs nothing. */
    [S_NAV_TRUST] = { "Zertifikate", "Certificates" },
    [S_TITLE_TRUST] = { "Zertifikate", "Certificates" },
    /* What a chain and the EU lists are, and why new entries need a new firmware. */
    [S_TRUST_INTRO] = {
        "Jedes Zertifikat nennt seinen Aussteller. Der Aussteller hat selbst ein Zertifikat, und "
        "das nennt wieder dessen Aussteller. Diese Reihe hei&szlig;t Kette. Ganz oben steht die "
        "oberste Stelle.<br><br>Die EU-Kommission f&uuml;hrt drei Listen der obersten Stellen, "
        "kurz EU-Listen. Nur wenn die Kette bei einer obersten Stelle aus diesen Listen endet "
        "und jede Signatur stimmt, hei&szlig;t das Zertifikat "
        "&bdquo;vertrauensw&uuml;rdig&ldquo;.<br><br>Alle Listen auf dieser Seite sind in die "
        "Firmware eingebaut, das Ger&auml;t holt nichts aus dem Netz. Neue Eintr&auml;ge kommen "
        "darum erst mit einer neueren Firmware.",
        "Every certificate names its issuer. The issuer has a certificate of its own, and that "
        "one names its issuer in turn. This sequence is called the chain. At the top stands the "
        "root.<br><br>The European Commission keeps three lists of the roots, the EU lists for "
        "short. A certificate counts as &ldquo;trustworthy&rdquo; only if its chain ends at a "
        "root from these lists. Every signature has to match as well.<br><br>All lists on this "
        "page are built into the firmware, and the device loads nothing from the network. New "
        "entries therefore only come with a newer firmware." },
    /* And what is not checked. All three gaps are real and none may be glossed over. */
    [S_TRUST_INTRO_NOT] = {
        "Drei Dinge pr&uuml;ft das Ger&auml;t nicht. Beim Aussteller pr&uuml;ft es nur, welche "
        "Dienste er erlaubt, nicht welche Inhalte.<br><br>Eine Sperrliste enth&auml;lt nur, was "
        "bis zu ihrem Stand zur&uuml;ckgezogen wurde. Und das Gebiet, f&uuml;r das ein "
        "Zertifikat gilt, pr&uuml;ft das Ger&auml;t nicht.",
        "There are three things the device does not check. At the issuer it only checks which "
        "services the issuer allows, not which contents.<br><br>A revocation list only contains "
        "what was withdrawn as of its date. And the region a certificate is valid for is not "
        "checked by the device." },
    /* Said once at the top instead of in every row, because it holds for every date below. */
    [S_TRUST_NOCLOCK_NOTE] = {
        "Die Uhr ist nicht gestellt. Ohne Uhrzeit wei&szlig; das Ger&auml;t nicht, ob ein "
        "Eintrag noch gilt, darum steht statt eines Ergebnisses &bdquo;Uhr nicht gestellt&ldquo;.",
        "The clock is not set. Without a time the device does not know whether an entry is still "
        "valid, so instead of a result it says &ldquo;clock not set&rdquo;." },

    [S_TRUST_H_ROOTS] = { "Eingebaute oberste Stellen", "Built-in roots" },
    [S_TRUST_H_CAS] = { "Eingebaute Aussteller", "Built-in issuers" },
    [S_TRUST_H_CRLS] = { "Eingebaute Sperrlisten", "Built-in revocation lists" },
    [S_TRUST_H_SEEN] = { "Selbst gesehene Zertifikate", "Certificates seen by this device" },

    [S_TRUST_N_ROOTS] = {
        "Diese Tabelle zeigt die drei EU-Listen. Jede Kette muss bei einer der obersten Stellen "
        "darin enden. Die Spalte &bdquo;Liste&ldquo; sagt, auf welcher Liste ein Eintrag steht: "
        "L0 f&uuml;r den Testbetrieb, L1 f&uuml;r den Probebetrieb, L2 f&uuml;r den echten "
        "Betrieb.<br><br>Auch eine Kette, die bei L0 endet, gilt als "
        "&bdquo;vertrauensw&uuml;rdig&ldquo;. Die Rolle &bdquo;TLM (Listen-Verwalter)&ldquo; "
        "hei&szlig;t: dieser Eintrag hat nur seine Liste signiert. Bei ihm darf keine Kette "
        "enden.<br><br>&bdquo;Vorg&auml;nger&ldquo; unter dem Namen hei&szlig;t: Ein neuerer "
        "Eintrag hat diesen abgel&ouml;st. Oft ist er dann schon &bdquo;abgelaufen&ldquo;, und "
        "eine Kette, die bei einem abgelaufenen Eintrag endet, ist nicht mehr "
        "&bdquo;vertrauensw&uuml;rdig&ldquo;.",
        "This table shows the three EU lists. Every chain has to end at one of the roots in "
        "them. The &ldquo;List&rdquo; column says which list an entry is on: L0 for testing, L1 "
        "for pre-production, L2 for live operation.<br><br>A chain that ends at L0 also counts "
        "as &ldquo;trustworthy&rdquo;. The role &ldquo;TLM (list manager)&rdquo; means this "
        "entry only signed its list. No chain may end at it.<br><br>&ldquo;predecessor&rdquo; "
        "under the name means: a newer entry replaced this one. It is then often "
        "&ldquo;expired&rdquo; already, and a chain that ends at an expired entry is no longer "
        "&ldquo;trustworthy&rdquo;." },
    [S_TRUST_N_CAS] = {
        "Diese Zertifikate liegen in der Firmware, weil manche Aussteller ihr eigenes nie "
        "mitschicken. Die Spalte &bdquo;Liste&ldquo; nennt die EU-Liste ihrer obersten "
        "Stelle.<br><br>Die Namen sind nicht eindeutig, denselben Namen gibt es unter mehreren "
        "obersten Stellen. Welches Zertifikat gemeint ist, zeigt erst die Kennung. Die Spalte "
        "Oberste Stelle stammt aus dem Zertifikat, nicht aus dem Namen.",
        "These certificates sit in the firmware because some issuers never send their own. The "
        "&ldquo;List&rdquo; column names the EU list of their root.<br><br>The names are not "
        "unique, the same name exists under several roots. Only the identifier shows which "
        "certificate is meant. The Root column comes from the certificate, not from the name." },
    [S_TRUST_N_CRLS] = {
        "Eine Sperrliste nennt die Zertifikate, die ihre oberste Stelle zur&uuml;ckgezogen hat. "
        "Neue Listen holt das Ger&auml;t nicht. Die Spalte &bdquo;Liste&ldquo; nennt die "
        "EU-Liste dieser obersten Stelle.<br><br>Spalte Stand: bis wann die Liste reicht. Spalte "
        "N&auml;chste Erneuerung: wann die oberste Stelle die n&auml;chste Liste geplant hat. "
        "&bdquo;&uuml;berf&auml;llig&ldquo; hei&szlig;t, dieser Tag ist vorbei. Ohne gestellte "
        "Uhr kann das Ger&auml;t das nicht erkennen.",
        "A revocation list names the certificates its root withdrew. The device fetches no new "
        "lists. The &ldquo;List&rdquo; column names the EU list of that root.<br><br>Column As "
        "of: how far the list reaches. Column Next renewal: when the root planned the next list. "
        "&ldquo;overdue&rdquo; means that day has passed. Without a clock set the device cannot "
        "tell." },
    /* The grey word under a date in the list table of /trust; S_TRUST_N_CRLS quotes it. */
    [S_TRUST_CRL_LATE] = { "&uuml;berf&auml;llig", "overdue" },
    [S_TRUST_N_SEEN] = {
        "Nur diese Tabelle &auml;ndert sich laufend. Sie zeigt die Zertifikate, die das "
        "Ger&auml;t gerade im Speicher hat, und was die Pr&uuml;fung ergab.<br><br>Platz ist "
        "f&uuml;r 512. Wenn sie voll ist, f&auml;llt das Zertifikat heraus, das am l&auml;ngsten "
        "nicht mehr empfangen wurde. Nach einem Neustart ist sie leer.<br><br>&bdquo;nicht "
        "pr&uuml;fbar&ldquo; spricht nicht gegen den Sender. Meist fehlt nur das Zertifikat "
        "seines Ausstellers. Wenn es sp&auml;ter &uuml;ber Funk kommt, pr&uuml;ft das Ger&auml;t "
        "noch einmal.<br><br>Die Spalte &bdquo;woher&ldquo; sagt, woher das Zertifikat des "
        "Ausstellers kam: &bdquo;mitgesendet&ldquo; &uuml;ber Funk, &bdquo;aus der "
        "Firmware&ldquo; oder &bdquo;aus einer EU-Liste&ldquo;. Bei &bdquo;unbekannt&ldquo; hat "
        "das Ger&auml;t keinen Aussteller gefunden.",
        "Only this table changes while the device runs. It shows the certificates the device "
        "holds in memory right now, and what the check found.<br><br>There is room for 512. When "
        "it is full, the certificate not received for the longest time drops out. After a "
        "restart it is empty.<br><br>&ldquo;cannot be checked&rdquo; says nothing against the "
        "sender. Usually only the issuer certificate is missing. If it arrives over the air "
        "later, the device checks once more.<br><br>The &ldquo;source&rdquo; column says where "
        "the issuer certificate came from: &ldquo;sent along&rdquo; over the air, &ldquo;from "
        "the firmware&rdquo; or &ldquo;from an EU list&rdquo;. With &ldquo;unknown&rdquo; the "
        "device found no issuer." },

    /* Column heads. Short, because the cells beside them are wide already. */
    [S_TRUST_C_NAME] = { "Name", "Name" },
    [S_TRUST_C_ROLE] = { "Rolle", "Role" },
    /* The L0/L1/L2 column: the same word as the check result on /senders ("Liste L2"), and
     * Umgebung names only the menu group. */
    [S_TRUST_C_ENV] = { "Liste", "List" },
    [S_TRUST_C_ID] = { "Kennung", "Identifier" },
    [S_TRUST_C_VALID] = { "G&uuml;ltigkeit", "Validity" },
    [S_TRUST_C_STATE] = { "Zustand", "State" },
    [S_TRUST_C_KIND] = { "Art", "Kind" },
    [S_TRUST_C_ROOT] = { "Oberste Stelle", "Root" },
    [S_TRUST_C_SOURCE] = { "woher", "source" },
    [S_TRUST_C_THIS] = { "Stand", "As of" },
    [S_TRUST_C_NEXT] = { "N&auml;chste Erneuerung", "Next renewal" },
    [S_TRUST_C_FRAMES] = { "Frames", "Frames" },
    [S_TRUST_C_REASON] = { "Grund", "Reason" },
    [S_TRUST_C_VERDICT] = { "Urteil", "Verdict" },
    /* Its own text, not the one of the trust list: the two columns count different things
     * and must not change together. */
    [S_TRUST_C_ENTRIES] = { "Eintr&auml;ge", "Entries" },

    /* Validity states. Only the first one is the green word, see validity_words(). */
    [S_TRUST_V_VALID] = { "g&uuml;ltig", "valid" },
    [S_TRUST_V_NOTYET] = { "noch nicht g&uuml;ltig", "not valid yet" },

    [S_TRUST_ROLE_ROOT] = { "oberste Stelle", "root" },
    [S_TRUST_ROLE_TLM] = { "TLM (Listen-Verwalter)", "TLM (list manager)" },
    [S_TRUST_PRED] = { "Vorg&auml;nger", "predecessor" },
    [S_TRUST_KIND_EA] = { "EA (Anmeldung)", "EA (enrolment)" },
    [S_TRUST_KIND_AA] = { "AA (stellt Sender-Zertifikate aus)",
                          "AA (issues sender certificates)" },
    [S_TRUST_SRC_SENT] = { "mitgesendet", "sent along" },
    /* No issuer found. This is the zero value of issuer_from, so an entry without an issuer
     * never reads as S_TRUST_SRC_SENT. */
    [S_TRUST_SRC_NONE] = { "unbekannt", "unknown" },
    [S_TRUST_SRC_BUILTIN] = { "aus der Firmware", "from the firmware" },
    /* Fourth value of the source column. The issuer is a root of the built-in EU list, so
     * nothing was sent along. */
    [S_TRUST_SRC_ROOT] = { "aus einer EU-Liste", "from an EU list" },
    /* An authority whose issuer is in no built-in list. The row still appears, only without a
     * root to name. Claiming one would be worse than naming the gap. */
    [S_TRUST_ROOT_NONE] = { "keine oberste Stelle in der Liste", "no root in the list" },
    /* Not "empty" but "cannot be read right now". its_certcache_used() returns 0 while the lock
     * is taken, and that must not turn into "none yet". */
    [S_TRUST_SEEN_BUSY] = {
        "Die Tabelle wurde gerade bearbeitet und war darum nicht lesbar. Nach dem Neuladen der "
        "Seite ist sie wieder da.",
        "The table was being updated at that moment and could not be read. Reloading the page "
        "brings it back." },
    [S_TRUST_SEEN_NONE] = {
        "Noch kein Zertifikat empfangen. Sobald ein Sender eines mitschickt, erscheint es in "
        "dieser Tabelle.",
        "No certificate received yet. As soon as a sender sends one, it appears in this table." },

    [S_TRUST_CRL_IDS] = { "Gesperrte Kennungen", "Withdrawn identifiers" },
    [S_TRUST_CRL_SUM] = { "Summe der Spalte Eintr&auml;ge", "Sum of the entries column" },
    /* The two numbers differ whenever two lists name the same certificate, so the page says
     * both and why, instead of letting the table look as if it contradicted itself. */
    [S_TRUST_CRL_IDS_HINT] = {
        "Zwei Listen k&ouml;nnen dieselbe Kennung nennen, das Ger&auml;t speichert sie nur "
        "einmal. Darum ist die Summe der Spalte Eintr&auml;ge h&ouml;her als die Zahl der "
        "gesperrten Kennungen.",
        "Two lists can name the same identifier, and the device stores it only once. That is why "
        "the Entries column adds up to more than the number of withdrawn identifiers." },
    [S_TRUST_CRL_SINCE] = { "steht auf der Sperrliste vom",
                            "on the revocation list dated" },
    /* S_TRUST_REVOKED also applies when only the issuer is on a list. its_crl_list_of() then
     * does not find this identifier, and S_TRUST_CRL_SINCE would be wrong. */
    [S_TRUST_CRL_ISSUER] = { "Aussteller zur&uuml;ckgezogen", "issuer withdrawn" },

    /* The three reasons the permission check of its_verify.c added. */
    [S_TRUST_WHY_NOPERM] = { "Aussteller deckt diese Berechtigung nicht",
        "the issuer does not cover this permission" },
    [S_TRUST_WHY_DEEP] = { "Kette l&auml;nger als erlaubt", "the chain is longer than allowed" },
    [S_TRUST_WHY_PERMFORM] = { "Berechtigungsfeld nicht lesbar",
        "the permission field cannot be read" },

    /* ---- Start page, /messages, /traffic and the live switch ------------------------ */
    /* What the device is, first thing on the start page. HTML in p.note.hlp: an explanation,
     * so the switch in the header hides it. */
    [S_START_LEAD] = { "Dieses Ger&auml;t empf&auml;ngt die Funknachrichten (ITS-G5) von Ampeln, "
                       "Fahrzeugen und &Ouml;ffis in der N&auml;he.",
                       "This device receives the radio messages (ITS-G5) of traffic lights, "
                       "vehicles and public transport nearby." },
    /* First item of a SPATEM detail line, a format with two %u in both languages. HTML and
     * the JSON string h of the message feed: no double quote, no backslash. */
    [S_MSG_SPAT_GREEN] = { "Signalgruppen gr&uuml;n: %u von %u", "signal groups green: %u of %u" },
    /* The state line under an empty filtered list on /messages, a format: %d the ring size,
     * the two %s the places for the times of its oldest and newest row. HTML, no hlp. */
    [S_MSG_FILTER_EMPTY] = {
        "Keiner der letzten %d Frames passt zum Filter. Die Liste reicht nur von %s bis %s.",
        "None of the last %d frames matches the filter. The list only reaches from %s to %s." },
    /* Link text after that line, SD builds only. The quote is S_SRCH_TITLE. HTML. */
    [S_MSG_FILTER_OLDER] = { "&Auml;ltere stehen unter &bdquo;Suche in der Aufzeichnung&ldquo;.",
                             "Older ones are under &ldquo;Search the recording&rdquo;." },
    /* The sender column in the notes fold on /messages. The quote is S_COL_SENDER. HTML. */
    [S_SENDER_HINT] = {
        "In der Spalte &bdquo;Absender&ldquo; steht oben der Name oder die Stations-Nummer, "
        "darunter klein die MAC-Adresse.<br><br>Namen haben nur Anlagen am Stra&szlig;enrand, "
        "meist ist es der Name der Kreuzung. Fahrzeuge wechseln Stations-Nummer und MAC-Adresse "
        "immer wieder.",
        "The &ldquo;Sender&rdquo; column shows the name or the station ID on top and the MAC "
        "address small below it.<br><br>Only roadside units have a name, usually that of the "
        "intersection. Vehicles change station ID and MAC address again and again." },
    /* Starts the second line of the time cell of a warning on /traffic, before its end.
     * Not S_PLAYBACK_TO: until fits the end of an event, and pages stay uncoupled. HTML. */
    [S_EVT_UNTIL] = { "bis", "until" },
    /* The live switch in the page header: the title in a single-quoted attribute (entities
     * yes, apostrophe no), the two states as HTML. Live is the same word on purpose. */
    [S_LIVE_TIP] = { "Live-Anzeige anhalten oder fortsetzen. Das Ger&auml;t empf&auml;ngt weiter.",
                     "Pause or resume the live view. The device keeps receiving." },
    [S_LIVE_ON]  = { "Live",     "Live" },
    [S_LIVE_OFF] = { "Live aus", "Live off" },
    /* Under the lights on /traffic when the view does not reload: a state, so no hlp. The
     * quotes are S_TRF_W_24H, S_NAV_SETTINGS and S_REFRESH_SEC. HTML. */
    [S_TRF_NOTLIVE] = {
        "Diese Ansicht aktualisiert sich nicht. Nur die Ansicht &bdquo;24 Stunden&ldquo; ist "
        "live.",
        "This view does not update itself. Only the &ldquo;24 hours&rdquo; view is live." },
    [S_TRF_NOTLIVE_OFF] = {
        "Diese Seite aktualisiert sich nicht, weil auf der Seite &bdquo;Einstellungen&ldquo; "
        "&bdquo;<a href='/settings?lang=de#refreshsec'>Seite selbst aktualisieren (s, "
        "0=aus)</a>&ldquo; auf 0 steht.",
        "This page does not update itself, because "
        "&ldquo;<a href='/settings?lang=en#refreshsec'>Update the page by itself (s, "
        "0=off)</a>&rdquo; is set to 0 on the &ldquo;Settings&rdquo; page." },
    /* Caption of the live filter on /messages. Its own entry: the archive search keeps
     * S_SRCH_FILTER, which S_SRCH_EXPORT_HINT quotes. HTML. */
    [S_MSG_LISTFILTER] = { "Liste filtern", "Filter list" },
    /* Link under a search result that plays the same period on /map. HTML. */
    [S_SRCH_MAP] = { "Diesen Zeitraum auf der Karte abspielen", "Play this period on the map" },
    /* The question before reception stops. confirm() in a single-quoted JS literal: umlauts as
     * JS \u escapes, no entity, no apostrophe, no double quote. */
    [S_SNIFF_ASK] = {
        "Empfang anhalten? Er bleibt aus bis zum n\\u00e4chsten Start oder Neustart.",
        "Stop reception? It stays off until the next start or restart." },
    /* Heading of the button group at the end of the start page. HTML. */
    [S_CTRL_TITLE] = { "Steuerung", "Controls" },
    /* Link in the MQTT settings to the re-send form, then an arrow and S_NAV_SENDERS. HTML. */
    [S_MQTT_RESEND] = { "Verpasste Frames nachliefern", "Re-send missed frames" },

    /* The street row of the start page (web_glance.c). These two appear in its detail lines,
     * which also go to /status.json: HTML, no double quote, no backslash. */
    [S_GL_PT_SEEN] = { "zuletzt gesehen", "last seen" },
    [S_GL_SP_MORE] = { "weitere", "more" },
    /* The peers tile, written with textContent from a single-quoted JS literal: plain
     * text, no entity, no apostrophe, no backslash. */
    [S_GL_PEER_ALL]   = { "alle antworten", "all answering" },
    [S_GL_PEER_QUIET] = { "ohne Empfang",   "without reception" },
    /* ---- Time zone, reset reasons, detail items and re-send results ----------------- */
    /* The state line under the phase table on /traffic, p.note without hlp: the averages
     * start over with every restart. HTML. */
    [S_TRF_PH_BOOT] = { "Gemessen seit dem letzten Neustart.",
                        "Measured since the last restart." },
    /* The time zone field on /settings and the clock row of /system. HTML. */
    [S_TZ] = { "Zeitzone", "Time zone" },
    /* Form hint under the time zone field, small.hlp: where the zone applies, true with and
     * without SD. What a change does to the recording (S_TZ_EFFECT, SD builds only) is shown
     * above it. HTML. */
    [S_TZ_HINT] = { "Alle Uhrzeiten der Oberfl&auml;che gelten in dieser Zone. Ihr K&uuml;rzel "
                    "steht oben neben der Uhrzeit, etwa MESZ.",
                    "Every time on these pages is in this zone. Its abbreviation stands next to "
                    "the clock at the top, for example CEST." },
    /* The five zone names in the time zone select and the clock row of /system. HTML. */
    [S_TZ_N_UTC] = { "Weltzeit",     "Universal time" },
    [S_TZ_N_WET] = { "Westeuropa",   "Western Europe" },
    [S_TZ_N_CET] = { "Mitteleuropa", "Central Europe" },
    [S_TZ_N_EET] = { "Osteuropa",    "Eastern Europe" },
    [S_TZ_N_TRT] = { "T&uuml;rkei",  "Turkey" },
    /* Zone abbreviations next to the clock. They also go into clk of /status.json and
     * /system.json: ASCII only, no entity, no quote, no backslash. */
    [S_TZ_AB_WET]  = { "WEZ",  "WET" },
    [S_TZ_AB_WEST] = { "WESZ", "WEST" },
    [S_TZ_AB_CET]  = { "MEZ",  "CET" },
    [S_TZ_AB_CEST] = { "MESZ", "CEST" },
    [S_TZ_AB_EET]  = { "OEZ",  "EET" },
    [S_TZ_AB_EEST] = { "OESZ", "EEST" },

    /* Why the chip started last (web_system.c reset_reason_str), in the crash tile of / and
     * the device table of /system. HTML only, plain ASCII. */
    [S_RST_POWERON]    = { "Kaltstart (Strom angelegt)", "Power-on (cold boot)" },
    [S_RST_EXT]        = { "Externer Reset (Pin/Taste)", "External reset (pin/button)" },
    [S_RST_SW]         = { "Software (Neustart/Update)", "Software (restart/update)" },
    [S_RST_PANIC]      = { "Absturz (Exception)",        "Crash (exception)" },
    [S_RST_INT_WDT]    = { "Interrupt-Watchdog",         "Interrupt watchdog" },
    [S_RST_TASK_WDT]   = { "Task-Watchdog",              "Task watchdog" },
    [S_RST_WDT]        = { "Anderer Watchdog",           "Other watchdog" },
    [S_RST_DEEPSLEEP]  = { "Deep-Sleep-Aufwachen",       "Deep-sleep wake" },
    [S_RST_BROWNOUT]   = { "Unterspannung (Brownout)",   "Brownout (undervoltage)" },
    [S_RST_SDIO]       = { "SDIO",                       "SDIO" },
    [S_RST_USB]        = { "USB-Reset",                  "USB reset" },
    [S_RST_JTAG]       = { "JTAG-Reset",                 "JTAG reset" },
    [S_RST_EFUSE]      = { "eFuse-Fehler",               "eFuse error" },
    [S_RST_PWR_GLITCH] = { "Spannungs-Glitch",           "Power glitch" },
    [S_RST_CPU_LOCKUP] = { "CPU-Lockup (Doppelfehler)",  "CPU lockup (double fault)" },
    /* Items of the details column (webserver.c msg_detail_text): HTML rows, the JSON field h
     * of /ws and the archive search. No double quote, no backslash. */
    [S_DET_IND_LEFT]  = { "Blinker links",   "left indicator" },
    [S_DET_IND_RIGHT] = { "Blinker rechts",  "right indicator" },
    [S_DET_BOARDING]  = { "Fahrgastwechsel", "boarding" },
    /* The result line of the re-send (web_files.c): JSON msg of /sdcard/upload_rsu/status, then
     * textContent. UTF-8 as C escapes, no entity, quote or backslash. A text that starts with a
     * space is appended to the one before. */
    [S_RSU_R_QFULL]   = { "Fehler: MQTT-Warteschlange dauerhaft voll.",
                          "Error: MQTT queue stayed full." },
    [S_RSU_R_LOST]    = { "Fehler: MQTT-Verbindung verloren.", "Error: MQTT connection lost." },
    [S_RSU_R_NOMEM]   = { "Fehler: kein Speicher.",            "Error: out of memory." },
    [S_RSU_R_UNDELIV] = { " %lu davon nicht zugestellt (Verbindung)!",
                          " %lu of them not delivered (connection)!" },
    [S_RSU_R_DONE]    = { "Fertig: %lu Frames von %lu Anlage(n) gesendet, "
                          "%lu ausged\u00fcnnt.%s%s%s",
                          "Done: %lu frames from %lu unit(s) sent, %lu thinned.%s%s%s" },
    [S_RSU_R_PARTIAL] = { " Zeitraum nur teilweise gelesen!", " Period only partly read!" },
    [S_RSU_R_PAIRS]   = { " Mehr als 64 Paare aus Anlage und Typ, Rest \u00fcbersprungen.",
                          " More than 64 unit-type pairs, rest skipped." },
    /* The cause cell of the warnings table on /traffic (web_traffic.c emit_warnings). HTML. */
    [S_EVT_NODETAIL]   = { "ohne n&auml;here Angabe", "no detail given" },
    [S_EVT_SUBCODE]    = { "Detail %u",               "detail %u" },
    [S_EVT_CAUSE_CODE] = { "Warnung (Code %u)",       "Warning (code %u)" },

    /* The note on /map when the map background does not load: labels, then textContent.
     * Plain UTF-8 (C character escapes), no entity, no quote, no backslash. */
    [S_MAP_TILES_OFF] = {
        "Kartenhintergrund nicht erreichbar. Der Browser braucht daf\u00fcr Internet.",
        "Map background not reachable. The browser needs internet access for it." },
    /* Title and aria-label of the reload button of the home-screen app, both single-quoted
     * attributes: no apostrophe. The glyph is in the code. HTML. */
    [S_RELOAD_PAGE] = { "Seite neu laden", "Reload the page" },
    /* ---- Single texts for several pages -------------------------------------------- */
    /* The count word for exactly one, beside S_CASTORE_CERTS on /system and /trust. HTML. */
    [S_CASTORE_CERT] = { "Zertifikat", "certificate" },
    /* Visible under the time zone field (not hlp): what a change does to search and
     * playback. sdpcap.c names its hour files in local time. HTML. */
    [S_TZ_EFFECT] = { "Die Aufzeichnung benennt ihre Dateien nach dieser Zone. Nach einem "
                      "Wechsel finden Suche und Wiedergabe die Stunden davor nicht mehr.",
                      "The recording names its files after this zone. After a change, search "
                      "and playback no longer find the hours before it." },
    /* The hlp note under the open-passage count on /transit: PT_GAP_SEC in ptlog.c. HTML. */
    [S_PT_ACTIVE_HINT] = { "Eine Vorbeifahrt bleibt bis 90 Sekunden nach der letzten "
                           "Nachricht offen.",
                           "A passage stays open until 90 seconds after the last message." },
    /* Label before the number in the map popup. It goes into a JS string: ASCII only, no
     * quote, no entity. */
    [S_STATION_ID] = { "Stations-Nummer", "Station ID" },
    /* The 403 of web_csrf.c as text/plain: scripts show it via innerText or alert, a form as
     * the whole page. Real umlauts, no entities. */
    [S_POST_FOREIGN] = { "Abgelehnt: Diese Anfrage kam von einer anderen Webseite. Das Gerät "
                         "nimmt Änderungen nur von seinen eigenen Seiten an. Hinter einem Proxy "
                         "muss der Host-Header gleich bleiben.",
                         "Refused: this request came from another website. The device takes "
                         "changes only from its own pages. Behind a proxy, the Host header must "
                         "stay the same." },
};

const char *web_str(str_id_t id, lang_t lang)
{
    return STR[id][lang];
}

/* 2004-01-01 00:00:00 UTC as a unix time, and the leap seconds inserted since. its_verify.c
 * holds the same two numbers, because it may not depend on the web interface. */
#define TIME32_EPOCH 1072915200u
#define TIME32_LEAP  5u
/* Around 2020-09, which every clock set from the network is past. */
#define CLOCK_MIN    1600000000u

/* Wider than both arguments, so the sum of a late Time32 stays a date instead of wrapping. */
uint64_t web_time32_to_unix(uint32_t time32)
{
    return time32 ? (uint64_t)time32 + TIME32_EPOCH - TIME32_LEAP : 0;
}

uint32_t web_unix_to_time32(uint64_t unix_seconds)
{
    uint64_t base = (uint64_t)TIME32_EPOCH - TIME32_LEAP;
    return unix_seconds > base ? (uint32_t)(unix_seconds - base) : 0;
}

bool web_clock_set(uint32_t unix_seconds)
{
    return unix_seconds >= CLOCK_MIN;
}

void web_day_str(uint32_t time32, lang_t lang, char *out, size_t cap)
{
    struct tm lt;
    time_t u = (time_t)web_time32_to_unix(time32);
    if (!out || !cap)
        return;
    out[0] = '\0';
    if (!time32 || !localtime_r(&u, &lt))
        return;
    /* A day that does not fit leaves the buffer unspecified, so it is emptied again. */
    if (!strftime(out, cap, lang == LANG_DE ? "%d.%m.%Y" : "%Y-%m-%d", &lt))
        out[0] = '\0';
}
