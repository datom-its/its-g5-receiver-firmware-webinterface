#include "web_strings.h"

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
    /* Shown in a JS confirm() dialog -> JS \u escape, no HTML entity. */
    [S_POWEROFF_CONFIRM]= { "Aufzeichnung sichern und SD-Karte aush\\u00e4ngen? "
                            "Danach zeichnet das Ger\\u00e4t bis zum Neustart nicht mehr auf.",
                            "Save the recording and unmount the SD card? "
                            "The device stops recording afterwards until it is restarted." },
    /* These five are shown via .innerText, which does NOT interpret escapes
     * -- literal UTF-8 here, unlike the confirm() string above. */
    [S_POWEROFF_BUSY]   = { "Puffer werden geschrieben...",
                                                        "Writing buffers..." },
    [S_POWEROFF_OK]     = { "Fertig. Das Gerät kann jetzt vom Strom getrennt werden.",
                            "Done. The device can now be disconnected from power." },
    [S_POWEROFF_FAIL]   = { "Fehlgeschlagen – SD-Karte nicht sauber ausgehängt.",
                            "Failed – the SD card was not cleanly unmounted." },
    [S_POWEROFF_DOWNLOAD] = { "Nicht ausgehängt – ein Download läuft noch. Danach erneut versuchen.",
                              "Not unmounted – a download is still running. Try again afterwards." },
    [S_POWEROFF_BLOCKED] = { "Nicht ausgehängt – die Karte ist blockiert. Später erneut versuchen.",
                             "Not unmounted – the card is blocked. Try again later." },
    /* Appended to the answer above, %s is a size. The status stays what the
     * unmount decided. */
    [S_POWEROFF_UNSAVED] = { "%s der Aufzeichnung konnten nicht geschrieben werden.",
                             "%s of the recording could not be written." },
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
     * ota_confirm() itself fails. */
    [S_CONFIRM_ERROR]   = { "Fehler beim Bestätigen.", "Error confirming." },
    /* alert() texts: literal UTF-8, no apostrophes (they sit in a JS string).
     * No URL is named, because the browser may ask for the password itself. */
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
    /* Goes out as text/plain, which decodes NO entities. Literal UTF-8 here,
     * like S_UPD_NOT_CONFIRMED and S_SET_BAD above. */
    [S_SAVED_REJECTED]  = { "%d gespeichert, %d abgelehnt: Wert außerhalb des erlaubten Bereichs "
                            "(siehe Min/Max beim Feld).",
                            "%d saved, %d rejected: value outside the allowed range "
                            "(see the field's min/max)." },
    [S_WEB_PASSWORD]    = { "Web-Passwort (Benutzer &quot;admin&quot;)",
                            "Web password (user &quot;admin&quot;)" },
    [S_WEB_PASSWORD_SET]  = { "gesetzt &ndash; leer lassen = unver&auml;ndert",
                              "set &ndash; leave empty to keep unchanged" },
    /* Names what check_update_auth() really gates: without a password the whole
     * card, the internal filesystem and the exports are open to the network. */
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
    /* Goes to the map via textContent, which does NOT decode HTML entities,
     * so this entry is plain UTF-8. */
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
    /* Each option states what is recorded IN FULL, not just what gets thinned:
     * otherwise the middle one reads as if it dropped everything else. */
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
    /* Says "flash", not just "upload": the button starts the flash and the
     * reboot in one step, with no separate "apply". */
    [S_UPLOAD]          = { "Hochladen &amp; flashen",   "Upload &amp; flash" },
    /* S_UPLOADING is injected into JS and shown via innerText, which does NOT
     * decode HTML entities. Use a JS \u escape (not &auml;) so it renders. */
    [S_UPLOADING]       = { "L\\u00e4dt hoch...",       "Uploading..." },
    /* Same JS \u-escape reasoning as S_UPLOADING (this one is shown via
     * alert(), which also doesn't decode HTML entities). */
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
    /* Four different situations, and only the first is worth formatting for. */
    [S_SD_ERR_NOFS]     = { "Die Karte antwortet, tr&auml;gt aber kein brauchbares "
                            "FAT-Dateisystem. Einmal formatieren richtet sie ein &ndash; "
                            "dabei geht alles darauf verloren.",
                            "The card answers but carries no usable FAT filesystem. "
                            "Formatting it once sets it up, and erases everything on it." },
    [S_SD_ERR_NOCARD]   = { "Die Karte antwortet gar nicht. Steckt sie richtig? "
                            "Formatieren hilft in diesem Fall nicht.",
                            "The card does not answer at all. Is it seated properly? "
                            "Formatting does not help here." },
    [S_SD_ERR_UNMOUNTED] = { "Die Karte wurde absichtlich ausgeh&auml;ngt &ndash; etwa "
                             "mit &bdquo;Zum Ausschalten vorbereiten&ldquo;. Einbinden "
                             "holt sie zur&uuml;ck, formatieren ist nicht n&ouml;tig.",
                             "The card was unmounted on purpose, e.g. by "
                             "&ldquo;Prepare for power-off&rdquo;. Mounting brings it "
                             "back; formatting is not needed." },
    [S_SD_ERR_WRITEFAIL] = { "Die Karte hat keine Schreibvorg&auml;nge mehr angenommen, auch "
                             "keinen Testschreibvorgang, und wurde ausgeh&auml;ngt. Das Ger&auml;t "
                             "versucht alle 30 Sekunden, sie wieder einzubinden. Klappt danach "
                             "wieder kein Schreibvorgang, bleibt sie drau&szlig;en, bis sie hier "
                             "eingebunden wird oder das Ger&auml;t neu startet.",
                             "The card stopped taking writes, a test write failed too, and it was "
                             "unmounted. The device tries to mount it again every 30 seconds. If "
                             "no write lands after that, it stays out until it is mounted here or "
                             "the device restarts." },
    [S_SD_ERR_WRITEFAIL_OUT] = { "Die Karte hat keine Schreibvorg&auml;nge mehr angenommen, auch "
                                 "keinen Testschreibvorgang, und wurde ausgeh&auml;ngt. Das "
                                 "Ger&auml;t versucht nicht mehr, sie einzubinden. Einbinden holt "
                                 "sie zur&uuml;ck, ein Neustart auch.",
                                 "The card stopped taking writes, a test write failed too, and it "
                                 "was unmounted. The device no longer tries to mount it. Mounting "
                                 "it here brings it back, so does a restart." },
    [S_SD_TAKEN_OUT]    = { "Karte nach Schreibfehlern ausgeh&auml;ngt.",
                            "Card taken out after failed writes." },
    [S_SD_ERR_USAGE]    = { "Karte eingebunden, Belegung nicht lesbar.",
                            "Card mounted, usage cannot be read." },
    [S_LOGS_CONSOLE]    = { "Konsole", "Console" },
    [S_LOGS_CONSOLE_HINT] = { "Die letzten Meldungen des Ger&auml;ts, im Arbeitsspeicher "
                              "gehalten. Sie stehen auch dann hier, wenn die Karte fehlt "
                              "&ndash; das Systemlog oben braucht sie n&auml;mlich.",
                              "The device's last messages, kept in RAM. They appear here "
                              "even with no card, which the system log above needs." },
    [S_SD_MOUNT]        = { "Einbinden",               "Mount" },
    [S_SD_USAGE]        = { "Belegung",                 "Usage" },
    [S_SD_USED_OF]      = { "%s von %s belegt (%s frei)", "%s of %s used (%s free)" },
    [S_SD_NAME]         = { "Name",                     "Name" },
    [S_SD_SIZE]         = { "Gr&ouml;&szlig;e",         "Size" },
    [S_SD_EMPTY]        = { "(leer)",                   "(empty)" },
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
    [S_LOSS_TITLE]      = { "Verluste",                 "Losses" },
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
    [S_LOSS_FLUSHFAIL]  = { "SD: Schreibvorg&auml;nge fehlgeschlagen",
                            "SD: writes failed" },
    /* The table above counts this session. These three carry over restarts, so
     * they need their own label or they read as more of the same. */
    [S_LOSS_LIFETIME]   = { "&Uuml;ber alle Neustarts (verloren / Schreibfehler / "
                            "Karte ausgeh&auml;ngt)",
                            "Across all restarts (lost / writes failed / card taken out)" },
    [S_LOSS_HINT]       = { "Die Werte z&auml;hlen Frames seit dem Einschalten. Drei Zeilen weichen ab: "
                            "Die Pausenzeile ist eine Dauer (Empfang angehalten, w&auml;hrend Bluetooth "
                            "funkte). Die fehlgeschlagenen Schreibvorg&auml;nge z&auml;hlen Vorg&auml;nge, "
                            "keine Frames. Die letzte Zeile z&auml;hlt &uuml;ber alle Neustarts, bis "
                            "&bdquo;Z&auml;hler zur&uuml;cksetzen&ldquo; sie l&ouml;scht. "
                            "Bei der Aufzeichnung "
                            "ist der Wert gesch&auml;tzt, weil dort ganze Puffer auf einmal verworfen "
                            "werden. Ausged&uuml;nnte sind "
                            "kein Fehler, sondern die eingestellte Filterung. Steigen die &uuml;brigen, "
                            "kommt das Ger&auml;t nicht nach &ndash; SD-Karte, Netzwerk oder Speicher. "
                            "L&auml;ngste Fehlserie und l&auml;ngste Haltezeit sind H&ouml;chstst&auml;nde "
                            "seit dem Einschalten, "
                            "keine Momentanwerte: der laufende Wert ist fast immer 0, weil jeder "
                            "gegl&uuml;ckte Zugriff ihn zur&uuml;cksetzt.",
                            "The values count frames since power-on. Three rows differ: the pause row "
                            "is a duration (reception halted while Bluetooth was on air). The "
                            "writes-failed row counts write operations, not frames. The last row counts "
                            "across all restarts until &ldquo;Reset counters&rdquo; clears it. "
                            "The recording row is an estimate, "
                            "because whole buffers are discarded there at once. "
                            "Thinned ones are not an error but "
                            "the configured filtering. If the others keep rising, the device is not "
                            "keeping up &ndash; SD card, network or memory. "
                            "Longest failure run and longest hold are peaks since power-on, not current "
                            "values: the live figure is almost always 0 because every successful access "
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
    [S_STAT_RESET_CONFIRM] = { "Alle Stabilit&auml;ts-Z&auml;hler und die SD-Verluste &uuml;ber alle "
                               "Neustarts wirklich auf null setzen?",
                               "Really reset all stability counters and the SD losses across "
                               "restarts to zero?" },
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

const char *web_str(str_id_t id, lang_t lang)
{
    return STR[id][lang];
}
