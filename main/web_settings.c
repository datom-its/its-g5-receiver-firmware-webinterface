#include "web_settings.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"

#include "config.h"
#include "ethernet.h"
#include "sdcard.h"
#include "sdlog.h"
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
     * (which carries broker credentials when one is configured), the network
     * setup and the peer list. The settings page itself advertises the
     * password as protecting /settings. */
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* The POST needs a ?lang= of its own: resolve_language() defaults to
     * German for a request without a query string, so the reply counting the
     * saved settings would always come back in German. */
    const char *lc = web_lang() == LANG_DE ? "de" : "en";

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

    /* LED override is stored as a plain 24-bit RGB value (see led.c). Render
     * it as a #rrggbb string for the <input type=color> picker. */
    char led_color[8];
    snprintf(led_color, sizeof(led_color), "#%06lx", (unsigned long)(led_override & 0xFFFFFFUL));

    send_page_header(req, T(S_TITLE_SETTINGS));

    char intro[256];
    snprintf(intro, sizeof(intro), "<p class='note'>%s</p>", T(S_SET_INTRO));
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);

    /* Six form groups of up to ten rows each. The Storage and Traffic links
     * carry the same SD #if as their sections, or else they point at nothing. */
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

    /* Each section is its own chunk, the same multi-chunk pattern as
     * render_activity_stats. EXT_RAM_BSS_ATTR/static keeps them off the
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
        "<tr><th><label for='nodeid'>%s</label></th><td><input id='nodeid' value='%s' size='16'></td></tr>"
        "<tr><th><label for='chan'>%s</label></th><td><select id='chan'>"
        "<option value='0'%s>%s</option>"
        "<option value='5900'%s>G5CC (5900)</option>"
        "<option value='5890'%s>G5SC2 (5890)</option>"
        "<option value='5880'%s>G5SC1 (5880)</option>"
        "<option value='5870'%s>G5SC3 (5870)</option>"
        "<option value='5860'%s>G5SC4 (5860)</option>"
        "</select></td></tr>"
        "<tr><th><label for='broadcastonly'>%s</label></th><td><input type='checkbox' id='broadcastonly'%s>"
        "<br><small>%s</small></td></tr>"
        "<tr><th><label for='led'>%s</label></th><td>"
        "<input type='range' id='led' min='0' max='255' value='%u' "
        "oninput=\"document.getElementById('ledval').innerText=this.value\">"
        "<span id='ledval'>%u</span></td></tr>"
        "<tr><th><label for='ledoverride'>%s</label></th><td><input type='color' id='ledoverride' value='%s'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th><label for='refreshsec'>%s</label></th><td><input id='refreshsec' type='number' min='0' max='3600' value='%lu' size='6'></td></tr>"
        "<tr><th><label for='mapstale'>%s</label></th><td><input id='mapstale' type='number' min='10' max='3600' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th><label for='peers'>%s</label></th><td><input id='peers' value='%s' maxlength='159' placeholder='its-node344.local, 192.168.178.40'>"
        "<br><small>%s</small></td></tr>"
        /* Size new rows against general[] at its declaration, not from here. */
        "<tr><th><label for='bten'>%s</label></th><td><input type='checkbox' id='bten'%s>"
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
        "<tr><th><label for='dhcp'>%s</label></th><td><input type='checkbox' id='dhcp'%s onchange='dhcpToggle()'></td></tr>"
        "<tr><th><label for='ethip'>%s</label></th><td><input class='ipfield' id='ethip' value='%s' size='16' maxlength='15'></td></tr>"
        "<tr><th><label for='ethnm'>%s</label></th><td><input class='ipfield' id='ethnm' value='%s' size='16' maxlength='15'></td></tr>"
        "<tr><th><label for='ethgw'>%s</label></th><td><input class='ipfield' id='ethgw' value='%s' size='16' maxlength='15'></td></tr>"
        "<tr><th><label for='ethdns0'>%s</label></th><td><input class='ipfield' id='ethdns0' value='%s' size='16' maxlength='15'> "
        "<input class='ipfield' id='ethdns1' aria-label='%s' value='%s' size='16' maxlength='15'> "
        "<input class='ipfield' id='ethdns2' aria-label='%s' value='%s' size='16' maxlength='15'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th><label for='ntpserver'>%s</label></th><td><input id='ntpserver' value='%s' size='16'></td></tr>"
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
        /* LED control exists only on the KSZ8851SNL; on other chips the row
         * is omitted entirely (see ethernet_apply_led_setting). */
        "<tr><th><label for='ethleds'>%s</label></th><td><input type='checkbox' id='ethleds'%s>"
        "<br><small>%s</small></td></tr>"
#endif
        "</table></div>",
        T(S_SET_GROUP_NETWORK),
        cur_line,
        T(S_ETH_DHCP), dhcp ? " checked" : "",
        T(S_ETH_IP), ethip,
        T(S_ETH_NETMASK), ethnm,
        T(S_ETH_GATEWAY), ethgw,
        T(S_ETH_DNS), ethdns0, T(S_ETH_DNS), ethdns1, T(S_ETH_DNS), ethdns2,
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
        "<tr><th><label for='mqtturi'>%s</label></th><td><input id='mqtturi' value='%s' size='16'></td></tr>"
        "</table></div>",
        T(S_SET_GROUP_MQTT), T(S_MQTT_URI), mqtt_uri);
    httpd_resp_send_chunk(req, mqtt_block, HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD
    /* --- Storage (SD): logging + PCAP capture --- */
    static EXT_RAM_BSS_ATTR char storage[3072];
    HTML_PRINTF(storage,
        "<div class='grp' id='g-sto'><h2>%s</h2><table class='kv set'>"
        "<tr><th><label for='logsys'>%s</label></th><td><input type='checkbox' id='logsys'%s></td></tr>"
        "<tr><th><label for='logmaxmb'>%s</label></th><td><input id='logmaxmb' type='number' min='1' max='512' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th><label for='pcapen'>%s</label></th><td><input type='checkbox' id='pcapen'%s></td></tr>"
        "<tr><th><label for='pcaphours'>%s</label></th><td><input id='pcaphours' type='number' min='1' max='720' value='%lu' size='6'></td></tr>"
        "<tr><th><label for='pcapmaxmb'>%s</label></th><td><input id='pcapmaxmb' type='number' min='1' max='100000' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th><label for='pcapbufmb'>%s</label></th><td><input id='pcapbufmb' type='number' min='1' max='4' value='%lu' size='6'>"
        "<br><small>%s</small></td></tr>"
        "<tr><th><label for='pcapflushsec'>%s</label></th><td><input id='pcapflushsec' type='number' min='8' max='3600' value='%lu' size='6'></td></tr>"
        "<tr><th><label for='pcapfilt'>%s</label></th><td><select id='pcapfilt'>"
        "<option value='0'%s>%s</option>"
        "<option value='1'%s>%s</option>"
        "<option value='2'%s>%s</option></select>"
        "<br><small>%s</small></td></tr>"
        "<tr><th><label for='trkon'>%s</label></th><td><input type='checkbox' id='trkon'%s>"
        "<br><small>%s</small></td></tr>"
        "<tr><th><label for='trkdays'>%s</label></th><td><input id='trkdays' type='number' min='1' max='7' value='%lu' size='6'></td></tr>"
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
        "<tr><th><label for='statsdays'>%s</label></th><td><input id='statsdays' type='number' min='1' max='30' value='%lu' size='6'></td></tr>"
        "<tr><th><label for='eventdays'>%s</label></th><td><input id='eventdays' type='number' min='1' max='30' value='%lu' size='6'></td></tr>"
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

    /* PSRAM, so the size is cheap. */
    static EXT_RAM_BSS_ATTR char save_block[6144];
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
        "#savebar small{color:#f2b134}"
        "body.dirty{padding-bottom:64px}</style>"
        /* No confirm: the click IS the intent. Reboots only after a save that
         * succeeded, because a rejected save is answered too. */
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
        /* Name the field the way the page labels it. Every setting is a
         * <tr><th>label</th><td><input></td></tr> row, so the row's header IS
         * the human name. The element id ('trkdays') means nothing to a reader. */
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
        /* Resolves {ok,t}: fetch fulfils on a 401 and on the 422 as well, so
         * only r.ok may clear the bar or trigger a reboot. */
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
         * document-level listener hears it too. Opening the menu on a phone
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

esp_err_t settings_post_handler(httpd_req_t *req)
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
            /* Unlike the other network settings this one needs no restart.
             * Push it to the chip straight away. */
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
        /* config_set_str hashes it (see config_set_web_password). The
         * console's `config_set webpasswd` goes through the same path, so
         * both ways of setting it agree. */
        if (value[0] && config_set_str(CONFIG_INDEX_WEB_PASSWORD, value) == ESP_OK) saved++;
    }
#if CONFIG_ENABLE_SD
    /* SD logging: checkboxes send 0/1. config_set fires a config event, so
     * sdlog picks up the change live. */
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
            /* Static needs all three valid together, or the boot code falls back
             * to DHCP. All three are checked before any is stored. */
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
