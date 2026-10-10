#include "web_settings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"

#include "config.h"
#include "ethernet.h"
#include "mqtt_uri.h"
#include "sdcard.h"
#include "settings_apply.h"
#include "web_fmt.h"
#include "web_mqtt.h"
#include "web_system.h"
#include "webserver_priv.h"

static const char TAG[] = "WEBSERVER";

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

esp_err_t settings_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* Reading the page is gated too, not just saving: it renders the MQTT URI
     * (password masked), the network setup and the peer list. The settings page
     * itself advertises the password as protecting /settings. */
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* The POST needs a ?lang= of its own: resolve_language() defaults to
     * German for a request without a query string, so the reply counting the
     * saved settings would always come back in German. */
    const char *lc = web_lang() == LANG_DE ? "de" : "en";

    char nodeid[CONFIG_NODEID_BUFFER_SIZE * 6] = {0};
    char ntp_server[CONFIG_NTP_SERVER_BUFFER_SIZE * 6] = {0};
    settings_get_str(CONFIG_INDEX_NODEID, nodeid, sizeof(nodeid));
    settings_get_str(CONFIG_INDEX_NTP_SERVER, ntp_server, sizeof(ntp_server));

    /* The MQTT password shows as a mask, so it is on no screenshot. Static, off the httpd
     * stack; worst escaped 254 x 6 + 12 mask bytes = 1536. The mask adds up to 11 bytes. */
    static EXT_RAM_BSS_ATTR char uri_raw[CONFIG_MQTT_URI_BUFFER_SIZE],
        uri_masked[CONFIG_MQTT_URI_BUFFER_SIZE + 16], mqtt_uri[CONFIG_MQTT_URI_BUFFER_SIZE * 6 + 16];
    size_t uri_sz = sizeof(uri_raw);
    if (config_get_str(CONFIG_INDEX_MQTT_URI, uri_raw, &uri_sz) != ESP_OK)
        uri_raw[0] = '\0';
    mqtt_uri_mask(uri_raw, uri_masked, sizeof(uri_masked));
    html_escape(uri_masked, mqtt_uri, sizeof(mqtt_uri));
    bool has_pw = strcmp(uri_raw, uri_masked) != 0;
    /* uri_raw held the password. The POST buffers are wiped the same way. */
    memset(uri_raw, 0, sizeof(uri_raw));

    /* Numbers come through set_read_num(), which the settings export uses too,
     * so the page and the file show the same value and the same fallback. */
    uint32_t chan = set_read_num(SET_CHAN);
    uint32_t broadcast_only = set_read_num(SET_BROADCASTONLY);
    unsigned brightness = (unsigned)set_read_num(SET_LED);
    uint32_t led_override = set_read_num(SET_LEDOVERRIDE);
    uint32_t refresh_sec = set_read_num(SET_REFRESHSEC);
    uint32_t map_stale_sec = set_read_num(SET_MAPSTALE);
    char peers_esc[CONFIG_PEERS_BUFFER_SIZE * 6];
    settings_get_str(CONFIG_INDEX_PEERS, peers_esc, sizeof(peers_esc));
    uint32_t bt_en = set_read_num(SET_BTEN);

    /* Whether a web password is currently set. We never echo the password
     * itself back into the page, only whether one exists. */
    char cur_pw[CONFIG_WEB_PASSWORD_BUFFER_SIZE] = {0};
    size_t cur_pw_size = sizeof(cur_pw);
    bool pw_set = config_get_str(CONFIG_INDEX_WEB_PASSWORD, cur_pw, &cur_pw_size) == ESP_OK
                  && cur_pw_size > 1;

#if CONFIG_ENABLE_SD
    uint32_t log_sys = set_read_num(SET_LOGSYS);
    uint32_t log_mb = set_read_num(SET_LOGMAXMB);

    uint32_t pcap_en = set_read_num(SET_PCAPEN);
    uint32_t pcap_hours = set_read_num(SET_PCAPHOURS);
    uint32_t pcap_mb = set_read_num(SET_PCAPMAXMB);
    uint32_t pcap_buf_mb = set_read_num(SET_PCAPBUFMB);
    uint32_t pcap_flush_sec = set_read_num(SET_PCAPFLUSHSEC);
    uint32_t trk_on = set_read_num(SET_TRKON);
    uint32_t pcap_filt = set_read_num(SET_PCAPFILT);
    uint32_t trk_days = set_read_num(SET_TRKDAYS);

    uint32_t stats_days = set_read_num(SET_STATSDAYS);
    uint32_t event_days = set_read_num(SET_EVENTDAYS);
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
    uint32_t eth_leds = set_read_num(SET_ETHLEDS);
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
    /* The same fallback-address notice as on /system, under the address it explains.
     * 768 against 441 (reach at its 255). */
    static EXT_RAM_BSS_ATTR char autoip[768];
    autoip[0] = '\0';
    if (web_autoip_active())
        web_autoip_note(autoip, sizeof(autoip), false, NULL);

    /* LED override is stored as a plain 24-bit RGB value (see led.c). Render
     * it as a #rrggbb string for the <input type=color> picker. */
    char led_color[8];
    /* 0 means no fixed colour (led.c). The picker then offers white, so ticking the box gives
     * a colour you can see. */
    snprintf(led_color, sizeof(led_color), "#%06lx",
             led_override ? (unsigned long)(led_override & 0xFFFFFFUL) : 0xFFFFFFUL);

    /* A browser set to no-referrer posts the import form with Origin null, and web_csrf.c
     * refuses that. same-origin keeps the real Origin and sends no Referer to other sites. */
    httpd_resp_set_hdr(req, "Referrer-Policy", "same-origin");
    send_page_header(req, T(S_TITLE_SETTINGS));

    char intro[256];
    snprintf(intro, sizeof(intro), "<p class='note hlp'>%s</p>", T(S_SET_INTRO));
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);

    /* Seven form groups in the order a newcomer sets the device up, then the backup group.
     * The SD card link shares the #if of its group, or it would point at nothing. 354 of 512. */
    char setjump[512];
    HTML_PRINTF(setjump,
        "<p class='jump'>%s: <a href='#g-gen'>%s</a> &middot; <a href='#g-rx'>%s</a>"
        " &middot; <a href='#g-net'>%s</a> &middot; <a href='#g-mqtt'>%s</a>"
#if CONFIG_ENABLE_SD
        " &middot; <a href='#g-sto'>%s</a>"
#endif
        " &middot; <a href='#g-web'>%s</a> &middot; <a href='#g-sec'>%s</a>"
        " &middot; <a href='#g-bak'>%s</a></p>",
        T(S_TRF_JUMP), T(S_SET_GROUP_DEVICE), T(S_SET_GROUP_RX), T(S_SET_GROUP_NETWORK),
        T(S_SET_GROUP_LINKS),
#if CONFIG_ENABLE_SD
        T(S_SET_GROUP_STORAGE),
#endif
        T(S_SET_GROUP_WEB), T(S_SET_GROUP_SECURITY), T(S_BAK_GROUP));
    httpd_resp_send_chunk(req, setjump, HTTPD_RESP_USE_STRLEN);

    /* Each section is its own chunk, the same multi-chunk pattern as
     * render_activity_stats. EXT_RAM_BSS_ATTR/static keeps them off the
     * httpd task's stack. */

    /* --- Device and reception: what the device is called and shows, then what it hears.
     * Keeps the id g-gen (the Node-ID link of the start page) and the buffer name. --- */
    /* 4096 against a worst case of 2461 B (node ID escaped at its buffer size 383, the KSZ row
     * on). */
    static EXT_RAM_BSS_ATTR char general[4096];
    HTML_PRINTF(general,
        "<div class='grp top' id='g-gen'><h2>%s</h2><table class='kv set'>"
        /* size='16', not the field's full width: the HTML size attribute
         * skews auto-layout column width even under a CSS width:100% rule
         * (size=40 alone pushed the table wider than a phone screen). */
        "<tr><th><label for='nodeid'>%s</label></th><td><input id='nodeid' value='%s' size='16'>"
        /* Every field with .reboot in SET_DEFS says so without hlp, so the sentence stays
         * visible with explanations off. An explanation after it follows as a hlp small. */
        "<small><br>%s</small></td></tr>"
        "<tr><th><label for='led'>%s</label></th><td>"
        "<input type='range' id='led' min='0' max='255' value='%u' "
        "oninput=\"document.getElementById('ledval').innerText=this.value\">"
        "<span id='ledval'>%u</span></td></tr>"
        /* The tick says "fixed colour". The picker alone could not say "none". */
        "<tr><th><label for='ledovon'>%s</label></th><td><input type='checkbox' id='ledovon'%s"
        " onchange=\"document.getElementById('ledoverride').disabled=!this.checked\"> "
        "<input type='color' id='ledoverride' aria-label='%s' value='%s'%s>"
        "<small class='hlp'><br>%s</small></td></tr>"
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
        /* LED control exists only on the KSZ8851SNL; on other chips the row
         * is omitted entirely (see ethernet_apply_led_setting). */
        "<tr><th><label for='ethleds'>%s</label></th><td><input type='checkbox' id='ethleds'%s>"
        "<small class='hlp'><br>%s</small></td></tr>"
#endif
        "</table></div>"
        "<div class='grp' id='g-rx'><h2>%s</h2><table class='kv set'>"
        "<tr><th><label for='chan'>%s</label></th><td><select id='chan'>"
        /* CHANNELS in settings_apply.c lists these values and refuses any other. The unit is
         * written as in the channel tile on '/'. */
        "<option value='0'%s>%s</option>"
        "<option value='5900'%s>G5CC (5900 MHz)</option>"
        "<option value='5890'%s>G5SC2 (5890 MHz)</option>"
        "<option value='5880'%s>G5SC1 (5880 MHz)</option>"
        "<option value='5870'%s>G5SC3 (5870 MHz)</option>"
        "<option value='5860'%s>G5SC4 (5860 MHz)</option>"
        "</select><small><br>%s</small></td></tr>"
        "<tr><th><label for='broadcastonly'>%s</label></th><td><input type='checkbox' id='broadcastonly'%s>"
        "<small><br>%s</small><small class='hlp'> %s</small></td></tr>"
        /* Size new rows against general[] at its declaration, not from here. */
        "</table></div>",
        T(S_SET_GROUP_DEVICE),
        T(S_NODEID), nodeid, T(S_NEEDS_REBOOT),
        T(S_LED_BRIGHTNESS), brightness, brightness,
        T(S_LED_OVERRIDE), led_override ? " checked" : "", T(S_LED_OVERRIDE), led_color,
        led_override ? "" : " disabled", T(S_LED_OVERRIDE_HINT),
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
        T(S_ETH_LEDS), eth_leds ? " checked" : "", T(S_ETH_LEDS_HINT),
#endif
        T(S_SET_GROUP_RX),
        T(S_AUTOSTART_CHAN),
        chan == 0 ? " selected" : "", T(S_CHAN_NONE),
        chan == 5900 ? " selected" : "",
        chan == 5890 ? " selected" : "",
        chan == 5880 ? " selected" : "",
        chan == 5870 ? " selected" : "",
        chan == 5860 ? " selected" : "", T(S_NEEDS_REBOOT),
        T(S_BROADCAST_ONLY), broadcast_only ? " checked" : "", T(S_NEEDS_REBOOT),
        T(S_BROADCAST_ONLY_HINT));
    httpd_resp_send_chunk(req, general, HTTPD_RESP_USE_STRLEN);

    /* --- Network --- */
    /* What the clock does now, beside the field that fixes it. A variable, not T(): the
     * statement also holds hlp notes. 256 against 119 measured (German). */
    static EXT_RAM_BSS_ATTR char clkst[256];
    web_clock_state(clkst, sizeof(clkst), false);
    /* 4096 against a worst case of 3111 B (current line 255, fallback notice 767, escaped NTP
     * server 383, clock state 255, the six IPv4 fields at 15); 3399 with those at 63. */
    static EXT_RAM_BSS_ATTR char network[4096];
    snprintf(network, sizeof(network),
        "<div class='grp' id='g-net'><h2>%s</h2><table class='kv set'>"
        "<tr><th></th><td>%s%s</td></tr>"
        "<tr><th><label for='dhcp'>%s</label></th><td><input type='checkbox' id='dhcp'%s onchange='dhcpToggle()'></td></tr>"
        "<tr><th><label for='ethip'>%s</label></th><td><input class='ipfield' id='ethip' value='%s' size='16' maxlength='15'></td></tr>"
        "<tr><th><label for='ethnm'>%s</label></th><td><input class='ipfield' id='ethnm' value='%s' size='16' maxlength='15'></td></tr>"
        "<tr><th><label for='ethgw'>%s</label></th><td><input class='ipfield' id='ethgw' value='%s' size='16' maxlength='15'></td></tr>"
        "<tr><th><label for='ethdns0'>%s</label></th><td><input class='ipfield' id='ethdns0' value='%s' size='16' maxlength='15'> "
        "<input class='ipfield' id='ethdns1' aria-label='%s' value='%s' size='16' maxlength='15'> "
        "<input class='ipfield' id='ethdns2' aria-label='%s' value='%s' size='16' maxlength='15'>"
        /* The network fields (.net) share one visible restart sentence under the DNS row. */
        "<small><br>%s</small><small class='hlp'> %s</small></td></tr>"
        /* The literal ends with the table still open: the zone row (tzrow) closes it. */
        "<tr><th><label for='ntpserver'>%s</label></th><td><input id='ntpserver' value='%s' size='16'>"
        "<small><br>%s</small><small><br>%s</small></td></tr>",
        T(S_SET_GROUP_NETWORK),
        cur_line, autoip,
        T(S_ETH_DHCP), dhcp ? " checked" : "",
        T(S_ETH_IP), ethip,
        T(S_ETH_NETMASK), ethnm,
        T(S_ETH_GATEWAY), ethgw,
        T(S_ETH_DNS), ethdns0, T(S_ETH_DNS), ethdns1, T(S_ETH_DNS), ethdns2,
        T(S_ETH_NET_REBOOT), T(S_ETH_NET_NOTE),
        T(S_NTP_SERVER), ntp_server, clkst, T(S_NEEDS_REBOOT));
    httpd_resp_send_chunk(req, network, HTTPD_RESP_USE_STRLEN);

    /* The zone row comes under the NTP server and closes the network table. It is a chunk of
     * its own, so network[] keeps its size. 1024 against 685 measured (English, German 683). */
    static EXT_RAM_BSS_ATTR char tzrow[1024];
    int tn = web_addf(tzrow, sizeof(tzrow), 0,
        "<tr><th><label for='tz'>%s</label></th><td><select id='tz'>", T(S_TZ));
    for (uint8_t z = 0; z < FMT_ZONE_N; z++)
    {
        char lbl[32];   /* 25 at most, web_fmt.h */
        fmt_tz_label(z, web_lang(), lbl, sizeof(lbl));
        tn = web_addf(tzrow, sizeof(tzrow), tn, "<option value='%u'%s>%s</option>",
                      (unsigned)z, z == fmt_tz() ? " selected" : "", lbl);
    }
    /* What a change breaks stays visible with explanations off. The explanation follows as hlp in
     * a paragraph of its own, since together they ran to 281 characters. Without SD there is no
     * recording, search or playback a change could break. */
#if CONFIG_ENABLE_SD
    web_addf(tzrow, sizeof(tzrow), tn,
        "</select><small><br>%s</small><small class='hlp'><br><br>%s</small></td></tr></table></div>",
        T(S_TZ_EFFECT), T(S_TZ_HINT));
#else
    web_addf(tzrow, sizeof(tzrow), tn,
        "</select><small class='hlp'><br>%s</small></td></tr></table></div>", T(S_TZ_HINT));
#endif
    httpd_resp_send_chunk(req, tzrow, HTTPD_RESP_USE_STRLEN);

    /* --- Connections: MQTT, the other receivers, Bluetooth. Keeps the id g-mqtt and the
     * buffer name: the start page, the fault bar and bookmarks lead here for MQTT. --- */
    /* The state row as on the start page. 384 against 218 measured (German, host at 63). */
    char mqnow[384];
    web_mqtt_state_cell(mqnow, sizeof(mqnow));
    /* Its label as a variable, not T(): the statement also holds the hlp notes of the peers
     * and Bluetooth rows. The label stays in a th, visible with explanations off. */
    const char *mqlbl = T(S_MQTT_NOW);
    /* Explains the mask only when there is one. 256 against 216 measured (German). */
    char pwnote[256] = "";
    if (has_pw)
        HTML_PRINTF(pwnote, "<small class='hlp'> %s</small>", T(S_MQTT_PW_HINT));
    static EXT_RAM_BSS_ATTR char rsulink[192];
    rsulink[0] = '\0';
#if CONFIG_ENABLE_SD
    /* Missed frames are re-sent from the page of the roadside units, but people look for that
     * here. 192 against 109 measured (German and English alike). */
    HTML_PRINTF(rsulink, "<tr><th></th><td><a href='/senders?lang=%s#snd-rsu'>%s &rarr; %s</a></td></tr>",
                lc, T(S_MQTT_RESEND), T(S_NAV_SENDERS));
#endif
    /* 6144 against 4625 B (German: state row 263, masked URI escaped up to 1536, password hint 216,
     * link row 109, escaped peer list 954); 4937 with every part at its buffer size. */
    static EXT_RAM_BSS_ATTR char mqtt_block[6144];
    HTML_PRINTF(mqtt_block,
        "<div class='grp' id='g-mqtt'><h2>%s</h2><table class='kv set'>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th><label for='mqtturi'>%s</label></th><td><input id='mqtturi' value='%s' size='16'>"
        "<small><br>%s</small>%s</td></tr>%s"
        "<tr><th><label for='peers'>%s</label></th><td><input id='peers' value='%s' maxlength='159' placeholder='its-node344.local, 192.168.178.40'>"
        "<small class='hlp'><br>%s</small></td></tr>"
        "<tr><th><label for='bten'>%s</label></th><td><input type='checkbox' id='bten'%s>"
        "<small><br>%s</small><small class='hlp'> %s</small></td></tr>"
        "</table></div>",
        T(S_SET_GROUP_LINKS), mqlbl, mqnow, T(S_MQTT_URI), mqtt_uri, T(S_NEEDS_REBOOT),
        pwnote, rsulink,
        T(S_PEERS), peers_esc, T(S_PEERS_HINT),
        T(S_BT_ENABLE), bt_en ? " checked" : "", T(S_NEEDS_REBOOT), T(S_BT_HINT));
    httpd_resp_send_chunk(req, mqtt_block, HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD
    /* --- SD card: everything the card keeps, recording first, every retention here.
     * Each sub-table is a direct child of the div: the phone CSS uses .grp>table.set. --- */
    /* 6144 against 4470 B (worst of German and English). PSRAM, so a
     * larger buffer costs nothing that is scarce. */
    static EXT_RAM_BSS_ATTR char storage[6144];
    HTML_PRINTF(storage,
        "<div class='grp' id='g-sto'><h2>%s</h2>"
        "<h3>%s</h3><table class='kv set'>"
        "<tr><th><label for='pcapen'>%s</label></th><td><input type='checkbox' id='pcapen'%s></td></tr>"
        "<tr><th><label for='pcapfilt'>%s</label></th><td><select id='pcapfilt'>"
        "<option value='0'%s>%s</option>"
        "<option value='1'%s>%s</option>"
        "<option value='2'%s>%s</option></select>"
        "<small class='hlp'><br>%s</small></td></tr>"
        "<tr><th><label for='pcaphours'>%s</label></th><td><input id='pcaphours' type='number' min='1' max='720' value='%lu' size='6'></td></tr>"
        "<tr><th><label for='pcapmaxmb'>%s</label></th><td><input id='pcapmaxmb' type='number' min='1' max='100000' value='%lu' size='6'>"
        "<small class='hlp'><br>%s</small></td></tr>"
        "<tr><th><label for='pcapbufmb'>%s</label></th><td><input id='pcapbufmb' type='number' min='1' max='4' value='%lu' size='6'>"
        "<small><br>%s</small><small class='hlp'> %s</small></td></tr>"
        "<tr><th><label for='pcapflushsec'>%s</label></th><td><input id='pcapflushsec' type='number' min='8' max='3600' value='%lu' size='6'></td></tr>"
        "</table>"
        "<h3>%s</h3><table class='kv set'>"
        "<tr><th><label for='trkon'>%s</label></th><td><input type='checkbox' id='trkon'%s>"
        "<small class='hlp'><br>%s</small></td></tr>"
        "<tr><th><label for='trkdays'>%s</label></th><td><input id='trkdays' type='number' min='1' max='7' value='%lu' size='6'></td></tr>"
        "</table>"
        "<h3>%s</h3><table class='kv set'>"
        "<tr><th><label for='statsdays'>%s</label></th><td><input id='statsdays' type='number' min='1' max='30' value='%lu' size='6'></td></tr>"
        "<tr><th><label for='eventdays'>%s</label></th><td><input id='eventdays' type='number' min='1' max='30' value='%lu' size='6'></td></tr>"
        "</table>"
        "<h3>%s</h3><table class='kv set'>"
        "<tr><th><label for='logsys'>%s</label></th><td><input type='checkbox' id='logsys'%s></td></tr>"
        "<tr><th><label for='logmaxmb'>%s</label></th><td><input id='logmaxmb' type='number' min='1' max='512' value='%lu' size='6'>"
        "<small class='hlp'><br>%s</small></td></tr>"
        "</table></div>",
        T(S_SET_GROUP_STORAGE),
        T(S_SET_SUB_PCAP),
        T(S_PCAP_ENABLE), pcap_en ? " checked" : "",
        T(S_PCAP_FILTER),
        pcap_filt == 0 ? " selected" : "", T(S_PCAP_FILT_ALL),
        pcap_filt == 1 ? " selected" : "", T(S_PCAP_FILT_THIN),
        pcap_filt == 2 ? " selected" : "", T(S_PCAP_FILT_VEH),
        T(S_PCAP_FILT_HINT),
        T(S_PCAP_RETAIN_HOURS), (unsigned long)pcap_hours,
        T(S_PCAP_MAX_MB), (unsigned long)pcap_mb, T(S_PCAP_HINT),
        T(S_PCAP_BUF_MB), (unsigned long)pcap_buf_mb, T(S_NEEDS_REBOOT), T(S_PCAP_BUF_HINT),
        T(S_PCAP_FLUSH_SEC), (unsigned long)pcap_flush_sec,
        T(S_MAP_LAYER_TRACKS),
        T(S_TRACKS_ENABLE), trk_on ? " checked" : "", T(S_TRACKS_HINT),
        T(S_TRACKS_DAYS), (unsigned long)trk_days,
        T(S_SET_SUB_TRAFFIC),
        T(S_STATS_RETAIN_DAYS), (unsigned long)stats_days,
        T(S_EVENT_RETAIN_DAYS), (unsigned long)event_days,
        T(S_LOGS_SYS),
        T(S_LOG_SYS), log_sys ? " checked" : "",
        T(S_LOG_BUDGET), (unsigned long)log_mb, T(S_LOG_HINT));
    httpd_resp_send_chunk(req, storage, HTTPD_RESP_USE_STRLEN);
#endif

    /* --- Web interface: how the pages behave. Stored on the device, so they hold for
     * every browser. 1024 against 531. --- */
    static EXT_RAM_BSS_ATTR char webui[1024];
    HTML_PRINTF(webui,
        "<div class='grp' id='g-web'><h2>%s</h2><table class='kv set'>"
        "<tr><th><label for='refreshsec'>%s</label></th><td><input id='refreshsec' type='number' min='0' max='3600' value='%lu' size='6'></td></tr>"
        "<tr><th><label for='mapstale'>%s</label></th><td><input id='mapstale' type='number' min='10' max='3600' value='%lu' size='6'>"
        "<small class='hlp'><br>%s</small></td></tr>"
        "</table></div>",
        T(S_SET_GROUP_WEB),
        T(S_REFRESH_SEC), (unsigned long)refresh_sec,
        T(S_MAP_STALE_SEC), (unsigned long)map_stale_sec, T(S_MAP_STALE_HINT));
    httpd_resp_send_chunk(req, webui, HTTPD_RESP_USE_STRLEN);

    /* --- Security --- */
    /* 484 of 1024 with the longer texts. */
    static EXT_RAM_BSS_ATTR char security[1024];
    snprintf(security, sizeof(security),
        "<div class='grp' id='g-sec'><h2>%s</h2><table class='kv set'>"
        "<tr><th><label for='webpasswd'>%s</label></th><td>"
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

    /* 8192 against 7373 measured (each text in its longer language). PSRAM, so the size is
     * cheap. */
    static EXT_RAM_BSS_ATTR char save_block[8192];
    HTML_PRINTF(save_block,
        /* Several settings only take effect after a reboot (network,
         * Bluetooth). itsReboot() is defined in PAGE_FOOTER. */
        "<p><button onclick=\"save()\">%s</button> "
        /* Dirty asks about the lost edits, clean asks the plain question.
         * Never both, so itsReboot gets null once the user already confirmed. */
        "<button class='pwr' onclick=\"var d=document.body.classList.contains('dirty');"
        "if(d&&!confirm(ITS_UNSAVED_WARN))return;"
        "itsReboot(d?null:'%s','%s','%s','%s')\">%s</button> "
        "<span id='result'></span></p>"
        /* Floating save bar: appears once anything is edited and doubles as the
         * unsaved-changes indicator. The top button stays. */
        "<style>#savebar{position:fixed;left:0;right:0;bottom:0;z-index:900;"
        "display:none;padding:10px clamp(14px,4vw,32px);"
        /* Own colour, not inherited: if /s.css fails to load, the default
         * text colour would be black on this dark bar. */
        "background:rgba(21,25,29,.96);color:#edf0f2;border-top:1px solid #2a2f34;"
        "box-shadow:0 -4px 20px rgba(0,0,0,.45)}"
        "#savebar .in{max-width:1400px;margin:0 auto;display:flex;"
        "align-items:center;gap:12px;flex-wrap:wrap}"
        /* Unsaved edits get lost, so they get the warning colour, not the brand amber. */
        "#savebar small{color:var(--warn,#e07a4f)}"
        /* While the bar holds the reply for 4 s after a save, "unsaved" would contradict it. */
        "body:not(.dirty) #savebar small{display:none}"
        "body.sbon{padding-bottom:64px}.set [aria-invalid=true]{border-color:var(--alarm,#ff6b6b)}</style>"
        /* No confirm: the click IS the intent. Reboots only after a save that
         * succeeded, because a rejected save is answered too. */
        "<div id='savebar'><div class='in'><button onclick=\"save()\">%s</button>"
        "<button class='pwr' onclick=\"var b=this;if(b.disabled)return;b.disabled=true;"
        "var pr=save();if(!pr){b.disabled=false;return;}"
        "pr.then(function(res){if(!res||!res.ok){b.disabled=false;return;}"
        "itsReboot(null,'%s','%s','%s').then(function(go){if(!go)b.disabled=false;});"
        "});\">%s</button>"
        "<small>%s</small> <span id='result2'></span></div></div>"
        "<script>var ITS_SET_BAD=\"%s\",ITS_SET_BAD_NUM=\"%s\",ITS_UNSAVED_WARN=\"%s\","
        "ITS_UNSAVED_LEAVE=\"%s\",ITS_SAVE_NOCONN=\"%s\",ITS_SAVE_DENIED=\"%s\";"
        /* Show every number field's allowed range, read from the field's OWN
         * min/max so the hint can never drift from what the device enforces.
         * Without it a value outside the range was simply refused and the
         * setting looked like it had reset itself. */
        "document.querySelectorAll('input[type=number]').forEach(function(i){"
        "if(!i.min&&!i.max)return;"
        "i.insertAdjacentHTML('afterend',\" <small style='color:#94a0a8'>\"+"
        "(i.min||'0')+'\\u2013'+(i.max||'\\u221e')+'</small>');});"
        /* Name the field the way the page labels it. Every setting is a
         * <tr><th>label</th><td><input></td></tr> row, so the row's header IS
         * the human name. The element id ('trkdays') means nothing to a reader. */
        "function fnm(i){var r=i.closest('tr'),h=r?r.querySelector('th'):null;"
        "return h?h.textContent.trim():i.id;}"
        /* A marked field is scrolled into view. No focus(), because it opens the phone keyboard. */
        "function fgo(){var f=document.querySelector('[aria-invalid]');"
        "if(f)f.scrollIntoView({block:'center'});}"
        "function save(){"
        "document.querySelectorAll('[aria-invalid]').forEach(function(x){x.removeAttribute('aria-invalid');});"
        /* Check before sending: an empty or out-of-range number field used to
         * be discarded by the device without naming itself, and an emptied one
         * silently meant "0" for the fields where 0 is legal. */
        /* Two lists: an empty field is not a number out of range, and the message has to
         * say which of the two it is. */
        "var bad=[],badn=[];"
        "document.querySelectorAll('input[type=number]').forEach(function(i){"
        "var v=i.value.trim();var n=Number(v);"
        "var nm=fnm(i);"
        "if(v===''||!isFinite(n)){badn.push(nm);i.setAttribute('aria-invalid','true');return;}"
        "if((i.min!==''&&n<Number(i.min))||(i.max!==''&&n>Number(i.max))){"
        "bad.push(nm);i.setAttribute('aria-invalid','true');}});"
        /* Nothing was sent: a warning to fix the fields, not a refusal. */
        "if(bad.length||badn.length){var rw=document.getElementById('result2');"
        "rw.className='v-warn';rw.textContent="
        "(badn.length?ITS_SET_BAD_NUM+' '+badn.join(', '):'')"
        "+(bad.length&&badn.length?' ':'')"
        "+(bad.length?ITS_SET_BAD+' '+bad.join(', '):'');fgo();return null;}"
        "var p=new URLSearchParams();"
        "p.append('nodeid',document.getElementById('nodeid').value);"
        "p.append('mqtturi',document.getElementById('mqtturi').value);"
        "p.append('chan',document.getElementById('chan').value);"
        "p.append('broadcastonly',document.getElementById('broadcastonly').checked?'1':'0');"
        "p.append('led',document.getElementById('led').value);"
        /* ledovon is no setting and never sent: without the tick the colour goes as 0. */
        "p.append('ledoverride',document.getElementById('ledovon').checked?"
        "parseInt(document.getElementById('ledoverride').value.substring(1),16):0);"
        "p.append('refreshsec',document.getElementById('refreshsec').value);"
        "p.append('mapstale',document.getElementById('mapstale').value);"
        "p.append('peers',document.getElementById('peers').value);"
        "p.append('bten',document.getElementById('bten').checked?'1':'0');"
        "p.append('ntpserver',document.getElementById('ntpserver').value);"
        "p.append('tz',document.getElementById('tz').value);"
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
        /* Resolves {ok,t}: fetch fulfils on a 401 and on the 422 as well, so
         * only r.ok may clear the bar or trigger a reboot. */
        "return fetch('/settings?lang=%s',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:p.toString()})"
        ".then(function(r){return r.text().then(function(t){return {ok:r.ok,status:r.status,t:t,"
        "f:r.headers.get('X-Bad-Field')};});})"
        /* A 401 carries the English default text of the httpd. Every other outcome
         * already comes back translated. */
        ".then(function(res){if(res.status===401)res.t=ITS_SAVE_DENIED;"
        /* Contract with settings_post_handler: the reply ends in ' key: reason' and X-Bad-Field
         * carries the same key, so the label replaces the id and the field gets marked. */
        "var fe=res.f&&document.getElementById(res.f);if(fe){res.t=res.t.replace(' '+res.f+': ',"
        "' '+fnm(fe)+': ');fe.setAttribute('aria-invalid','true');fgo();}"
        /* A 401 and every refusal mean "not saved", the level /update uses for them. */
        "var rc=res.ok?'v-ok':'v-bad',r1=document.getElementById('result');"
        "r1.innerText=res.t;r1.className=rc;"
        "var r2=document.getElementById('result2');if(r2){r2.innerText=res.t;r2.className=rc;}"
        "if(res.ok)markClean();return res;})"
        ".catch(function(e){var m=ITS_SAVE_NOCONN+' '+e;"
        "var r1=document.getElementById('result');r1.innerText=m;r1.className='v-bad';"
        "var r2=document.getElementById('result2');if(r2){r2.innerText=m;r2.className='v-bad';}"
        "return {ok:false,t:m};});"
        "}"
        /* Leaving with edits asks first, and the browser brings its own text. sbGo marks a leave
         * already confirmed. After a restart itsReboot has replaced the page, savebar included. */
        "var sbT,sbGo=0;function sbAsk(e){if(sbGo||!document.body.classList.contains('dirty')"
        "||!document.getElementById('savebar'))return;e.preventDefault();e.returnValue=true;}"
        "addEventListener('pageshow',function(){sbGo=0;});"
        /* Any edit anywhere in the page arms the bar. Bound with capture on
         * the document so fields added later are covered too, and so this
         * needs no per-field wiring. */
        "function markDirty(){clearTimeout(sbT);addEventListener('beforeunload',sbAsk);"
        "document.getElementById('savebar').style.display='block';"
        "document.body.classList.add('dirty','sbon');}"
        /* The unsaved state ends at once, but the bar keeps the reply for 4 s. The reply may say
         * that a restart is needed, and without the delay it would vanish unread. The leave
         * question is armed only while dirty, so the back/forward cache stays usable. */
        "function markClean(){document.body.classList.remove('dirty');"
        "removeEventListener('beforeunload',sbAsk);clearTimeout(sbT);"
        "sbT=setTimeout(function(){document.getElementById('savebar').style.display='none';"
        "document.body.classList.remove('sbon');},4000);}"
        /* The nav's burger toggle and the backup group's file picker and checkbox
         * are inputs too, but no settings, so they must not arm the bar. */
        "function editEvt(e){if(e.target&&e.target.closest&&e.target.closest('nav,#g-bak'))return;"
        "markDirty();}"
        "document.addEventListener('input',editEvt,true);"
        "document.addEventListener('change',editEvt,true);"
        "function dhcpToggle(){var d=document.getElementById('dhcp').checked;"
        "['ethip','ethnm','ethgw'].forEach(function(i){document.getElementById(i).disabled=d;});}"
        "dhcpToggle();"
        "</script>",
        T(S_SAVE), T(S_REBOOT_CONFIRM), T(S_REBOOTING), T(S_REBOOT_SLOW), T(S_REBOOT_DENIED),
        T(S_REBOOT), T(S_SAVE), T(S_REBOOTING), T(S_REBOOT_SLOW), T(S_REBOOT_DENIED),
        T(S_SAVE_REBOOT), T(S_UNSAVED), T(S_SET_BAD), T(S_SET_BAD_NUM), T(S_UNSAVED_WARN),
        T(S_UNSAVED_LEAVE), T(S_SAVE_NOCONN), T(S_SAVE_DENIED), lc);
    httpd_resp_send_chunk(req, save_block, HTTPD_RESP_USE_STRLEN);

    /* --- Backup: a download link and a plain form after the save buttons, since save() does
     * not send them --- */
    /* 2048 against 1528 measured. Export is a download link (grey, arrow), so it does not count
     * as leaving. Amber stays for the import, which changes the device. */
    static EXT_RAM_BSS_ATTR char backup[2048];
    HTML_PRINTF(backup,
        "<div class='grp' id='g-bak'><h2>%s</h2>"
        "<p><a class='dlb' href='/settings/export.json' download>&#8595; %s</a></p>"
        "<p class='note hlp'>%s</p>"
        "<h3>%s</h3>"
        /* Leaving for the result page drops unsaved edits above, so it asks once. sbGo then
         * keeps the browser's own leave question from asking a second time. */
        "<form method='post' enctype='multipart/form-data' action='/settings/import?lang=%s'"
        " onsubmit=\"if(document.body.classList.contains('dirty')&&!confirm(ITS_UNSAVED_LEAVE))"
        "return false;sbGo=1;\">"
        /* The label goes above its field in one .fld, as on /sdcard. The device box below keeps
         * its sentence beside the box. */
        "<p><span class='fld'><label class='cap' for='bakfile'>%s</label>"
        "<input type='file' id='bakfile' name='file' accept='.json,application/json' required></span></p>"
        "<p><label><input type='checkbox' name='device' value='1'> %s</label>"
        "<small class='hlp'><br>%s</small></p>"
        "<p><button type='submit'>%s</button></p></form>"
        "<p class='note hlp'>%s</p></div>",
        T(S_BAK_GROUP), T(S_BAK_EXPORT), T(S_BAK_EXPORT_HINT),
        T(S_BAK_IMPORT_H), lc, T(S_BAK_FILE),
        T(S_BAK_DEVICE), T(S_BAK_DEVICE_HINT),
        T(S_BAK_IMPORT), T(S_BAK_IMPORT_HINT));
    httpd_resp_send_chunk(req, backup, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* Reads one form field and decodes it: 1 when present, 0 when absent, -1 when
 * it does not fit into out. */
static int form_field(const char *body, const char *key, char *out, size_t cap)
{
    esp_err_t r = httpd_query_key_value(body, key, out, cap);
    if (r == ESP_ERR_NOT_FOUND)
        return 0;
    if (r != ESP_OK)
        return -1;
    url_decode(out);
    return 1;
}

/* Why one value was refused, in PLAIN text: this reply goes out as text/plain
 * and the page shows it with innerText, which decodes no entities. Same
 * reasons the import page gives (reject_reason in web_backup.c). Pass
 * SET_COUNT for a field that has no set_def_t, like the web password. */
static const char *reject_why(set_id_t id, set_err_t e)
{
    const set_def_t *d = id < SET_COUNT ? &SET_DEFS[id] : NULL;
    str_id_t s = S_IMP_WHY_STORE;
    switch (e)
    {
    case SET_ERR_TYPE:
    case SET_ERR_NUMBER:
        /* COLOR counts as a number here, unlike on the import page: the form
         * sends the LED colour as a decimal, only the JSON uses #rrggbb. */
        s = !d ? S_IMP_WHY_TYPE_STR
          : (d->kind == SET_KIND_BOOL || d->kind == SET_KIND_DHCP) ? S_IMP_WHY_TYPE_BOOL
          : (d->kind == SET_KIND_UINT || d->kind == SET_KIND_CHAN
             || d->kind == SET_KIND_COLOR) ? S_IMP_WHY_TYPE_NUM
          : S_IMP_WHY_TYPE_STR;
        break;
    case SET_ERR_RANGE:     s = S_IMP_WHY_RANGE;  break;
    case SET_ERR_EMPTY:     s = S_IMP_WHY_EMPTY;  break;
    case SET_ERR_LONG:      s = S_IMP_WHY_LONG;   break;
    case SET_ERR_CHARS:     s = S_IMP_WHY_CHARS;  break;
    case SET_ERR_CHOICE:    s = S_IMP_WHY_CHOICE; break;
    case SET_ERR_IPV4:      s = S_IMP_WHY_IPV4;   break;
    case SET_ERR_COLOR:     s = S_IMP_WHY_COLOR;  break;
    case SET_ERR_STATIC_IP: s = S_IMP_WHY_STATIC; break;
    case SET_ERR_MASK:      s = S_IMP_WHY_MASK;   break;
    default:                break;   /* SET_OK and SET_ERR_STORE */
    }
    return T(s);
}

esp_err_t settings_post_handler(httpd_req_t *req)
{
    resolve_language(req);

    if (!check_update_auth(req))
        return send_auth_required(req);

    /* 4096: a full MQTT URI alone percent-encodes to 765 bytes. Static is safe, because
     * only the httpd task runs this handler. Both buffers are wiped at the end. */
    static EXT_RAM_BSS_ATTR char buf[4096];
    if (req->content_len == 0 || req->content_len > sizeof(buf) - 1)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad body");
        return ESP_FAIL;
    }

    /* Loop until the whole declared body arrived. A single recv may return
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
        memset(buf, 0, sizeof(buf));
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "recv failed");
        return ESP_FAIL;
    }
    buf[got] = '\0';

    /* Room for the longest setting percent-encoded. */
    static EXT_RAM_BSS_ATTR char value[CONFIG_MQTT_URI_BUFFER_SIZE * 3];
    int saved = 0, rejected = 0;
    /* The first refusal, so the reply can name it instead of guessing a reason.
     * Both point into static storage (SET_DEFS, the string table), never into
     * buf[], which is wiped before the reply is built. */
    const char *bad_key = NULL, *bad_why = NULL;
    /* save() always sends every field, so only a value that really changed may ask for a
     * restart. Compared with what was stored, not with what is running. */
    bool need_reboot = false;

    /* Every setting outside the network block goes through set_apply(), the
     * check the settings import uses as well. A field that does not fit is refused. */
    for (int i = 0; i < SET_COUNT; i++)
    {
        if (SET_DEFS[i].net)
            continue;
        int f = form_field(buf, SET_DEFS[i].key, value, sizeof(value));
        if (f == 0)
            continue;
        /* f < 0: longer than value[], so nothing was copied -- that is "too long". */
        bool ch = false;
        set_err_t e = f > 0 ? set_apply((set_id_t)i, value, &ch) : SET_ERR_LONG;
        if (e == SET_OK)
        {
            saved++;
            if (ch && SET_DEFS[i].reboot)
                need_reboot = true;
        }
        else
        {
            rejected++;
            if (!bad_key)
            {
                bad_key = SET_DEFS[i].key;
                bad_why = reject_why((set_id_t)i, e);
            }
        }
        /* The zone applies at once. The next hourly PCAP file gets the new name. */
        if (e == SET_OK && ch && i == SET_TZ)
            web_tz_reload();
    }

    /* Web password: an explicit "remove" checkbox clears it; otherwise a
     * non-empty value sets it. An empty value leaves the current one unchanged
     * so other settings can be saved without wiping the password. Storing an
     * empty string disables protection (check_update_auth treats it as open). */
    if (httpd_query_key_value(buf, "webpwclear", value, sizeof(value)) == ESP_OK
        && strcmp(value, "1") == 0)
    {
        if (config_set_str(CONFIG_INDEX_WEB_PASSWORD, "") == ESP_OK)
            saved++;
        else
        {
            rejected++;
            if (!bad_key)
            {
                bad_key = "webpasswd";
                bad_why = reject_why(SET_COUNT, SET_ERR_STORE);
            }
        }
    }
    else
    {
        /* form_field(), not httpd_query_key_value(): it also tells a password
         * too long for value[] apart from one that is not there at all. */
        int fp = form_field(buf, "webpasswd", value, sizeof(value));
        if (fp < 0)
        {
            rejected++;
            if (!bad_key)
            {
                bad_key = "webpasswd";
                bad_why = reject_why(SET_COUNT, SET_ERR_LONG);
            }
        }
        else if (fp > 0 && value[0])
        {
            /* config_set_str hashes it (see config_set_web_password). The
             * console's `config_set webpasswd` goes through the same path, so
             * both ways of setting it agree. */
            esp_err_t r = config_set_str(CONFIG_INDEX_WEB_PASSWORD, value);
            if (r == ESP_OK)
                saved++;
            else
            {
                /* Above 64 characters config_set_str refuses it. Counting that
                 * as saved reports a protection the device does not have. */
                rejected++;
                if (!bad_key)
                {
                    bad_key = "webpasswd";
                    bad_why = reject_why(SET_COUNT,
                                         r == ESP_ERR_INVALID_SIZE ? SET_ERR_LONG : SET_ERR_STORE);
                }
            }
        }
    }

    /* The network block is touched only when the form sent it, so a partial POST
     * never wipes it. It takes effect on the next reboot. */
    char dhcp[4];
    int f = form_field(buf, "dhcp", dhcp, sizeof(dhcp));
    if (f != 0)
    {
        /* A part too long for its buffer does not arrive at all: the query parser
         * copies nothing when it would have to cut. It stays empty, and the
         * IPv4 check refuses it. */
        char ip[64] = "", nm[64] = "", gw[64] = "";
        form_field(buf, "ethip", ip, sizeof(ip));
        form_field(buf, "ethnm", nm, sizeof(nm));
        form_field(buf, "ethgw", gw, sizeof(gw));
        bool cha = false;
        set_err_t ea = f > 0 ? set_apply_address(dhcp, ip, nm, gw, &cha) : SET_ERR_TYPE;
        if (ea == SET_OK)
        {
            saved++;
            if (cha && SET_DEFS[SET_DHCP].reboot)
                need_reboot = true;
        }
        else
        {
            rejected++;   /* a wrong static IP is the one setting you cannot fix remotely */
            if (!bad_key)
            {
                /* A dhcp flag that is neither 1 nor 0 is blamed on the dhcp field.
                 * Everything else in this block is about the static address. */
                set_id_t bid = (ea == SET_ERR_TYPE) ? SET_DHCP : SET_ETHIP;
                bad_key = SET_DEFS[bid].key;
                bad_why = reject_why(bid, ea);
            }
        }

        /* DNS 1/2/3: empty clears, a valid address is stored. Applies in both
         * DHCP and static mode. */
        static const set_id_t dns[3] = { SET_ETHDNS0, SET_ETHDNS1, SET_ETHDNS2 };
        for (size_t i = 0; i < 3; i++)
        {
            int g = form_field(buf, SET_DEFS[dns[i]].key, value, sizeof(value));
            if (g == 0)
                continue;
            bool chd = false;
            set_err_t ed = g > 0 ? set_apply(dns[i], value, &chd) : SET_ERR_LONG;
            if (ed == SET_OK)
            {
                saved++;
                if (chd && SET_DEFS[dns[i]].reboot)
                    need_reboot = true;
            }
            else
            {
                rejected++;
                if (!bad_key)
                {
                    bad_key = SET_DEFS[dns[i]].key;
                    bad_why = reject_why(dns[i], ed);
                }
            }
        }
    }
    /* The body holds the web password in clear text. */
    memset(buf, 0, sizeof(buf));
    memset(value, 0, sizeof(value));

    /* 256 against a worst case of 184 B: counting sentence 31 B (S_SAVED, DE, with a
     * two-digit number), restart sentence 1 + 64 B (S_SAVED_REBOOT, DE), field id 13 B
     * ("broadcastonly"), reason 72 B (S_IMP_WHY_MASK, DE), plus the 3 B of separators. */
    char msg[256];
    int n;
    if (rejected)
        n = snprintf(msg, sizeof(msg), T(S_SAVED_REJECTED), saved, rejected);
    else
        n = snprintf(msg, sizeof(msg), T(S_SAVED), saved);
    /* Worded like S_IMP_REBOOT on the import page. Before the refusal, so the reply
     * still ends in "key: reason". */
    if (need_reboot && n > 0 && (size_t)n < sizeof(msg))
    {
        int m = snprintf(msg + n, sizeof(msg) - (size_t)n, " %s", T(S_SAVED_REBOOT));
        if (m > 0)
            n += m;
    }
    /* Names the first refused field and the real reason. Appended instead of
     * woven into the sentence, so both texts keep the placeholders they have. */
    if (bad_key && n > 0 && (size_t)n < sizeof(msg))
        snprintf(msg + n, sizeof(msg) - (size_t)n, " %s: %s", bad_key, bad_why);
    /* Lets the browser tell "saved" from "partly rejected" without parsing a
     * translated sentence. Text unchanged either way. */
    if (rejected)
        httpd_resp_set_status(req, "422 Unprocessable Entity");
    /* Contract with save(): the page shows the field's label instead of the id and marks the
     * field. bad_key points into SET_DEFS or a literal, so it outlives the send. */
    if (bad_key)
        httpd_resp_set_hdr(req, "X-Bad-Field", bad_key);
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, msg);
    return ESP_OK;
}
