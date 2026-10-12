#include "sdkconfig.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_attr.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "config.h"
#include "its_decode.h"
#include "its_gn.h"
#include "spatem.h"
#include "tracklog.h"
#if CONFIG_ENABLE_SD
#include "sdcard.h"
#include "sdpcap.h"
#endif

#include "web_map.h"
#include "webserver_priv.h"
#include "webserver_ring.h"
#include "web_fmt.h"
#include "web_traffic.h"
#include "web_cpm.h"

static const char TAG[] = "WEBSERVER";

/* ================================================================== */
/*  GET /map -- live positions from CAM and GeoNetworking headers     */
/* ================================================================== */

esp_err_t map_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* The live watcher of the page header needs the /ws echo. Without WebSocket support the
     * map has no live feed. */
#if CONFIG_HTTPD_WS_SUPPORT
    send_page_header_live(req, T(S_TITLE_MAP));
#else
    send_page_header(req, T(S_TITLE_MAP));
#endif

    /* Collapsible via native <details>, no JS needed. Collapsed by default,
     * because the full explanation pushes the map below the fold on a phone.
     * The summary takes one line. */
    /* Measured at 2668 bytes with every number at its widest. The buffer has 3072, because
     * a cut here ends the markup mid-tag and takes the map container with it. */
    char hint[3072];
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
        ".leaflet-bar a:hover{background:#1d2227;color:#edf0f2}"
        /* Leaflet draws the folded toggle from images/layers.png, which is not shipped. The
         * !important also beats its retina rule, so the image is never requested. */
        ".leaflet-control-layers-toggle{background-image:none!important}"
        ".leaflet-control-layers-toggle::after{content:'\\2630';display:block;text-align:center;"
        "font-size:20px;line-height:36px;color:#edf0f2}"
        ".leaflet-touch .leaflet-control-layers-toggle::after{line-height:44px}"
        "#map{height:70vh;border-radius:12px;overflow:hidden}"
        /* On a phone the period controls go above a lower map. With them below it, the map
         * would catch the swipe meant for the page. Only the order changes. This style comes
         * before the div, so Leaflet sees the height. */
        "@media(max-width:640px){.mapbox{display:flex;flex-direction:column}"
        ".mapbox>.grp{order:-1;margin:14px 0;padding-top:0;border-top:0}#map{height:60vh}}</style>"
        /* .mapbox closes after the playback controls, in every build. */
        "<div class='mapbox'><div id='map'></div>",
        T(S_MAP_HELP), T(S_MAP_HINT));
    httpd_resp_send_chunk(req, hint, HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD && CONFIG_HTTPD_WS_SUPPORT
    /* Playback controls: hidden until pbLoad() (see MAP_SCRIPT) finds at
     * least one entry. Default from/to values are filled in by JS in the
     * device's zone (itsTz). */
    /* Reading a multi-hour window off the SD card takes seconds, and with no
     * feedback at all the page looked dead -- so an indeterminate bar runs
     * while the request is in flight. Indeterminate rather than percentage:
     * the response is streamed and its total length isn't known up front. */
    /* Measured worst case (German) is 1312 bytes. A truncated closing tag
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
        "<div class='tools'>%s "
        "<button id='pbload'>%s</button>"
        "<span id='pbbar'><i></i></span> "
        "</div><p id='pbmsg' hidden></p>"
        "<span id='pbctl' style='display:none'>"
        "<button id='pbplay'>&#9654;</button> "
        "<input id='pbslider' type='range' min='0' max='0' value='0' step='10' "
        "style='width:220px;vertical-align:middle'> "
        "<span id='pbtime'></span>"
        /* Step size drives both the slider granularity and how far each
         * play tick advances, so it doubles as the replay speed. */
        " <label class='cap' for='pbstep' style='margin-left:10px'>%s</label> "
        "<select id='pbstep'>"
        "<option value='1'>1 s</option>"
        "<option value='2'>2 s</option>"
        "<option value='5'>5 s</option>"
        "<option value='10' selected>10 s</option>"
        "<option value='30'>30 s</option>"
        "<option value='60'>60 s</option>"
        "</select>"
        /* Own row with real top margin -- on phone, Live would otherwise
         * wrap directly under Play with no gap, easy to fat-finger. */
        "<div style='margin-top:10px'><button id='pblive'>%s</button></div>"
        "</span></div>",
        web_range_html("pbfrom", "pbto"), T(S_PLAYBACK_LOAD),
        T(S_PLAYBACK_STEP), T(S_PLAYBACK_LIVE));
    httpd_resp_send_chunk(req, pbctl, HTTPD_RESP_USE_STRLEN);
#endif
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN); /* Closes .mapbox from the hint, in every build. */

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
    /* 2329 bytes in the worst case (all texts at their longest, a full peer list and a
     * long node id). 2560 leaves headroom, and the httpd stack still had 4652 bytes to spare
     * at its deepest, measured on the test receiver. */
    char labels[2560];
    HTML_PRINTF(labels,
             "<script>var ITS_MAP_L_STREETS=\"%s\",ITS_MAP_L_SAT=\"%s\","
             "ITS_MAP_L_DARK=\"%s\",ITS_MAP_L_LIGHT=\"%s\","
             "ITS_MAP_L_TRACKS=\"%s\",ITS_MAP_L_TRACKS_P=\"%s\",ITS_MAP_LAYERS=\"%s\","
             "ITS_MAP_TILES=\"%s\","
             "ITS_MAP_TRACK_PTS=\"%s\",ITS_MAP_TRACK_CAP=\"%s\",ITS_MAP_TRACK_DAYS=%lu,"
             "ITS_MAP_TRACK_DUR=\"%s\",ITS_MAP_BUSY=\"%s\","
             "ITS_MAP_SEEN_BY=\"%s\",ITS_MAP_PEERS=[%s],ITS_MAP_SELF=\"%s\","
             "ITS_PB_NONE=\"%s\",ITS_PB_ERROR=\"%s\",ITS_PB_BUSY=\"%s\","
             "ITS_PB_PART=\"%s\",ITS_PB_RANGE=\"%s\","
             "ITS_PB_NOSD=\"%s\",ITS_PB_WAIT=\"%s\","
             "ITS_MAP_DENM=\"%s\","
             "ITS_MAP_STALE=%lu,ITS_MAP_LINE=\"%s\","
             "ITS_MAP_KURS=\"%s\",ITS_MAP_ZIEL=\"%s\","
             "ITS_MAP_LATE=\"%s\",ITS_MAP_EARLY=\"%s\",ITS_MAP_ONTIME=\"%s\","
             "ITS_MAP_MIN=\"%s\","
             /* Lane popup words. The movement text beside them comes already
              * translated from /spatem.json. */
             "ITS_MAP_LANE=\"%s\",ITS_MAP_XWALK=\"%s\",ITS_MAP_NOSD=\"%s\","
             "ITS_MAP_ALT=\"%s\",ITS_MAP_ACCEL=\"%s\",ITS_MAP_REVERSE=\"%s\","
             "ITS_MAP_LANEPOS=\"%s\",ITS_LANE_SHOULDER=\"%s\",ITS_LANE_OFFROAD=\"%s\";</script>",
             T(S_MAP_LAYER_STREETS), T(S_MAP_LAYER_SATELLITE),
             T(S_MAP_LAYER_DARK), T(S_MAP_LAYER_LIGHT),
             T(S_MAP_LAYER_TRACKS), T(S_MAP_LAYER_TRACKS_P), T(S_MAP_LAYERS),
             T(S_MAP_TILES_OFF),
             T(S_MAP_TRACK_PTS), T(S_MAP_TRACK_CAP), (unsigned long)trkdays,
             T(S_MAP_TRACK_DUR), T(S_MAP_BUSY),
             T(S_MAP_SEEN_BY), peerjs, selfname,
             T(S_PLAYBACK_NONE), T(S_PLAYBACK_ERROR), T(S_PLAYBACK_BUSY),
             T(S_PLAYBACK_PARTIAL), T(S_PLAYBACK_RANGE),
             T(S_SD_NOT_MOUNTED), T(S_ARCH_BUSY),
             T(S_MAP_DENM),
             (unsigned long)stale, T(S_MAP_LINE),
             T(S_MAP_COURSE), T(S_MAP_DEST),
             T(S_MAP_LATE), T(S_MAP_EARLY), T(S_MAP_ONTIME), T(S_UNIT_MIN),
             T(S_AP_LANE), T(S_MAP_XWALK), T(S_MAP_TRACKS_NOSD),
             T(S_MAP_ALT), T(S_MAP_ACCEL), T(S_MAP_REVERSE),
             T(S_MAP_LANEPOS), T(S_LANE_SHOULDER), T(S_LANE_OFFROAD));
    httpd_resp_send_chunk(req, labels, HTTPD_RESP_USE_STRLEN);
    /* The popup's label before the station number, sent in pieces. One more argument in the
     * snprintf above cost this frame 16 bytes, and map_get_handler is the deepest call chain
     * of the httpd task. */
    web_send_parts(req, "<script>var ITS_MAP_SID=\"", T(S_STATION_ID), "\";</script>", NULL);

    /* Labels for the CAM detail in the popup. Emitted inline as JS vars rather
     * than ~40 more string-table entries, the same shortcut spat_status_text()
     * takes. These are leaf words that appear in exactly one place. Order in
     * ITS_CAM_A and ITS_CAM_L is the standard's bit order, MSB first. */
    char camlbl[1024];
    if (web_lang() == LANG_DE)
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

#if CONFIG_ENABLE_SD
    /* Texts for the warning areas from /warning_areas.json. Without this object the
     * map script leaves the layer out, which is how a build without SD support runs. */
    {
        /* Static: only the httpd task serves /map, like the snapshot below. German needs 933. */
        static EXT_RAM_BSS_ATTR char walbl[2048];
        int o = snprintf(walbl, sizeof(walbl),
            "<script>var ITS_WA={l:\"%s\",cap:\"%s\",u:\"%s\",unk:\"%s\",clk:\"%s\",d:\"%s\","
            "st:{active:\"%s\",expired:\"%s\",cancelled:\"%s\",negated:\"%s\",unknown:\"%s\"},c:{",
            T(S_MAP_LAYER_WARN), T(S_MAP_WARN_CAP), T(S_WARN_VALID_UNTIL), T(S_UNKNOWN),
            T(S_CLOCK_UNSET), T(S_EVT_WARNING), T(S_WARN_ACTIVE), T(S_WARN_EXPIRED),
            T(S_DENM_CANCEL), T(S_DENM_NEGATE), T(S_UNKNOWN));
        /* The cause names come from the table in web_traffic.c and hold no quotes. */
        bool firstc = true;
        for (unsigned c = 1; c < 256 && o > 0 && (size_t)o < sizeof(walbl); c++)
        {
            const char *ct = denm_cause_text((uint8_t)c);
            if (!ct)
                continue;
            o += snprintf(walbl + o, sizeof(walbl) - o, "%s%u:\"%s\"", firstc ? "" : ",", c, ct);
            firstc = false;
        }
        if (o > 0 && (size_t)o < sizeof(walbl))
            o += snprintf(walbl + o, sizeof(walbl) - o, "}};</script>");
        /* A cut script would break the whole map, so it is left out instead. Plain snprintf, not
         * web_addf: only its full count shows the cut, and o is checked before every write. */
        if (o > 0 && (size_t)o < sizeof(walbl))
            httpd_resp_send_chunk(req, walbl, HTTPD_RESP_USE_STRLEN);
        else
            ESP_LOGW(TAG, "map warning labels truncated");
    }
#endif

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

    /* Oldest first (unlike build_msg_json), because apply() overwrites per station
     * and the newest entry has to be the last one it sees. Keep this order. */
    bool first = true;
    for (size_t n = 0; n < count; n++)
    {
        web_msg_entry_t *e = &snapshot[n];
        if (!e->has_position)
            continue;
        char clock[24];
        fmt_clock(e->seconds, e->microseconds, web_lang(), clock, sizeof(clock));
        char rssi_str[16];
        if (e->rssi != 0) snprintf(rssi_str, sizeof(rssi_str), "%d dBm", e->rssi);
        else              snprintf(rssi_str, sizeof(rssi_str), "-");
        char speedsuffix[24] = "";
        if (e->has_speed && e->speed_cmps != -1)   /* -1 = not available */
            snprintf(speedsuffix, sizeof(speedsuffix), ",\"s\":%ld", (long)e->speed_cmps);
        char denmsuffix[160] = "";
        denm_json(e->station_id, (uint32_t)time(NULL), denmsuffix, sizeof(denmsuffix));
        char dimsuffix[40] = "";   /* two uint16 in their widest form plus the keys */
        if (e->length_dm && e->width_dm)
            snprintf(dimsuffix, sizeof(dimsuffix), ",\"vl\":%u,\"vw\":%u",
                     (unsigned)e->length_dm, (unsigned)e->width_dm);
        char ptsuffix[24] = "";
        if (e->pt_line)
            snprintf(ptsuffix, sizeof(ptsuffix), ",\"pl\":%u", (unsigned)e->pt_line);
        char camsuffix[384] = "";   /* cam_json_extra writes 338 at most */
        cam_json_extra(e, camsuffix, sizeof(camsuffix));
        /* The source MAC as "sm", as the live feed and the playback send it. Without it the
         * popup shows no MAC address until the first tick. */
        char mac_str[20];
        if (e->has_src_mac)
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     e->src_mac[0], e->src_mac[1], e->src_mac[2],
                     e->src_mac[3], e->src_mac[4], e->src_mac[5]);
        else
            snprintf(mac_str, sizeof(mac_str), "-");
        /* Sized for the two large optional parts. The CAM detail takes up to
         * 384 bytes and the DENM text up to 160, on top of ids, clock, RSSI and MAC. */
        char entry[800];
        snprintf(entry, sizeof(entry),
                 "%s{\"i\":%lu,\"a\":%ld,\"o\":%ld,\"y\":\"%s\",\"t\":\"%s\",\"r\":\"%s\","
                 "\"sm\":\"%s\",\"l\":%lu%s%s%s%s%s}",
                 first ? "" : ",", (unsigned long)e->station_id,
                 (long)e->lat_e7, (long)e->lon_e7, e->msgtype, clock, rssi_str, mac_str,
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
        /* One decimal with the page's separator, as the tables write it. */
        "var DS=document.documentElement.lang=='de'?',':'.';"
        "function dc(v){return v.toFixed(1).replace('.',DS);}"
        /* Cut to one decimal like fmt_alt_cm, then dc(): toFixed alone rounded and printed -0,0. */
        "function al(c){return dc((c-c%10)/100)+' m';}"
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
        "var dark=L.tileLayer(OSMU,{maxZoom:19,attribution:OSMA});"
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
        /* Without internet in the browser the background stays grey. tileerror comes once per
         * tile, so the note is shown only once. The first tile that loads removes it. */
        "var tileNote=null,tileOk=false;"
        "function tileBad(){if(tileNote||tileOk)return;tileNote=L.control({position:'bottomleft'});"
        /* The look of the three map notes (.tilenote, .tracknote, .wanote) is in s.css. */
        "tileNote.onAdd=function(){var d=L.DomUtil.create('div','tilenote');d.setAttribute('role','status');"
        "d.textContent=ITS_MAP_TILES;return d;};tileNote.addTo(map);}"
        "function tileGood(){tileOk=true;if(tileNote){tileNote.remove();tileNote=null;}}"
        "[streets,dark,sat].concat(light.getLayers()).forEach(function(t){"
        "t.on('tileerror',tileBad);t.on('tileload',tileGood);});"
        /* The background is kept per browser. mapb holds d, s, l or a, and dark stays the
         * default. It is put on the map before the control exists, so no event fires. */
        "var MB={d:dark,s:streets,l:light,a:sat},mb='d',mo=null;"
        "try{mb=localStorage.getItem('mapb')||'d';mo=localStorage.getItem('mapo');}catch(e){}"
        "if(!MB[mb])mb='d';MB[mb].addTo(map);paintDark(mb==='d');"
        "map.on('baselayerchange',function(e){paintDark(e.layer===dark);tileOk=false;"
        "for(var k in MB)if(MB[k]===e.layer){try{localStorage.setItem('mapb',k);}catch(x){}}});"
        /* Dark first, the default. With a remembered background the checked entry can be lower. */
        "var baseLayers={};baseLayers[ITS_MAP_L_DARK]=dark;"
        "baseLayers[ITS_MAP_L_STREETS]=streets;baseLayers[ITS_MAP_L_LIGHT]=light;"
        "baseLayers[ITS_MAP_L_SAT]=sat;"
        /* Vehicle tracks as a switchable overlay, loaded only when actually
         * switched on, or when this browser had them on last time. It is a
         * separate request against the SD card, and most visits do not want it. */
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
        "d.textContent=ITS_MAP_TRACK_CAP;return d;};"
        "trackNote.addTo(map);}"
        /* Separate overlay for peers' tracks, never merged per vehicle -- no
         * timestamps to order points across receivers, and separate lines show the overlap. */
        "var peerTrackLayer=L.layerGroup(),peerTracksLoaded=false;"
        "var overlays={};overlays[ITS_MAP_L_TRACKS]=trackLayer;"
        "if(ITS_MAP_PEERS.length)overlays[ITS_MAP_L_TRACKS_P]=peerTrackLayer;"
        /* Warning areas are on by default. An x in mapo keeps them off in this browser. ITS_WA
         * is only sent when the firmware has the route. */
        "var WA=window.ITS_WA,waLayer=L.layerGroup(),waShapes={},waOrder='',waNote=null,"
        "waBusy=false,waGone=false;"
        "if(WA){if(!mo||mo.indexOf('x')<0)waLayer.addTo(map);overlays[WA.l]=waLayer;}"
        /* Folded only at the phone width of s.css (640px). Left open, the list covers a third
         * of a phone map. The toggle is the glyph from the style block in map_get_handler. */
        "var lctl=L.control.layers(baseLayers,overlays,{collapsed:window.matchMedia('(max-width:640px)').matches}).addTo(map);"
        "var ltg=lctl.getContainer().querySelector('.leaflet-control-layers-toggle');"
        "if(ltg){ltg.title=ITS_MAP_LAYERS;ltg.setAttribute('aria-label',ITS_MAP_LAYERS);}"
        "map.on('overlayadd',function(e){"
        "if(e.layer===trackLayer&&!tracksLoaded)loadTracks();"
        "if(e.layer===peerTrackLayer&&!peerTracksLoaded)loadPeerTracks();"
        /* Re-adding the layer appends its shapes above the lanes, so they are sorted again. */
        "if(e.layer===waLayer){waOrder='';waLoad();}});"
        "map.on('overlayremove',function(e){if(e.layer===waLayer)waCap(false);});"
        /* The layers are kept per browser. mapo holds t for tracks, p for other receivers'
         * tracks and x for warning areas off. */
        "map.on('overlayadd overlayremove',function(){"
        "var s=(map.hasLayer(trackLayer)?'t':'')+(map.hasLayer(peerTrackLayer)?'p':'')"
        "+(WA&&!map.hasLayer(waLayer)?'x':'');try{localStorage.setItem('mapo',s);}catch(e){}});"
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
        /* The station number with its label, as in the vehicle popup. */
        "pl.bindPopup(trkIcon(t.t)+ITS_MAP_SID+' '+t.i+' \\u00b7 '+pts.length+' '+ITS_MAP_TRACK_PTS"
        "+(t.d!==undefined?' \\u00b7 '+ITS_MAP_TRACK_DUR+' '+itsDur(t.d,0):'')"
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
        ".then(function(r){if(r.status===503)throw 503;if(r.status===500)throw 500;"
        "return r.json();}).then(function(d){"
        "trackLayer.clearLayers();drawTracks(trkArr(d),trackLayer,null,ITS_MAP_SELF);"
        "trackCapSelf=!!(d&&d.c);trackCap=trackCapSelf||trackCapPeer;updateTrackNote();"
        /* A 503 keeps the drawing, since the worker is only busy. Every other failure means
         * we have nothing to show, and stale tracks would look like fresh ones. */
        "}).catch(function(e){tracksLoaded=false;if(e===503){alert(ITS_MAP_BUSY);return;}"
        "trackLayer.clearLayers();trackCapSelf=false;"
        "trackCap=trackCapPeer;updateTrackNote();"
        /* 500 is the device saying the card is not mounted. Without a word the empty
         * layer reads as "nobody drove". */
        "if(e===500)alert(ITS_MAP_NOSD);});}"
        /* One colour per peer, in the order they are configured, so the same
         * receiver keeps the same colour across reloads. Chosen to stay apart
         * from the local blue, the amber UI accent and the --warn orange of
         * active warning areas. */
        "var PEER_COLORS=['#f062d0','#7ad07a','#c07ae0','#e0c04f','#4fe0c0'];"
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
        /* The red here is the signal red of the lamps, as .amp.r in s.css, not the alarm level. */
        "function spatColor(p){if(p===5||p===6)return '#2ecc40';"
        "if(p===7||p===8||p===9)return '#f2b134';if(p===2||p===3)return '#e74c3c';"
        "if(p===4)return '#e67e22';return '#888';}"
        /* Which lamps of the small signal light up. The grouping is the same as in
         * spat_phase_lamp() in web_traffic.c. */
        "function spatLamp(p){if(p===5||p===6)return 'g';"
        "if(p===7||p===8||p===9)return 'y';if(p===2||p===3)return 'r';"
        "if(p===4)return 'ry';return 'off';}"
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
        "<i class=\"amp '+spatLamp(d.g[j][1])+'\" style=\"margin-right:3px\"><b></b><b></b><b></b></i>'"
        "+(d.g[j][3]?d.g[j][3]+' <small>('+d.g[j][0]+')</small>':d.g[j][0])+(d.g[j][2]>=0?' <small>\\u2265'+d.g[j][2]+'s</small>':'')+'</span>';}return h;}"
        /* Renders the set bits of a BIT STRING as a comma-separated line.
         * Bit 0 is the MSB, hence 1<<(w-1-i). */
        "function bits(v,names,w){if(!v)return '';var o=[];"
        "for(var i=0;i<w;i++)if(v&(1<<(w-1-i)))o.push(names[i]);"
        "return o.length?'<br>'+o.join(', '):'';}"
        /* An empty value shows as a dash. The feed itself keeps '-' for older peers. */
        "function nv(x){return x===undefined||x===null||x===''||x==='-'?'&ndash;':x;}"
        "function popupHtml(m){var h='<b>'+(m.y||'?')+'</b><br>'+nv(m.t)+' &middot; '"
        "+nv(m.r)+' &middot; '+nv(m.l)+(m.l?' B':'')+'<br>'+ITS_MAP_SID+' '+m.i;"
        "if(m.sm&&m.sm!=='-')h+='<br><code>'+htxt(m.sm)+'</code>';"
        "if(m.s!==undefined)h+='<br>'+dc(m.s*0.036)+' km/h';"
        "if(m.pl)h+='<br><b>'+ITS_MAP_LINE+' '+m.pl+'</b>';"
        "if(m.pk)h+=' &middot; '+ITS_MAP_KURS+' '+m.pk;"
        "if(m.pz)h+=' &middot; '+ITS_MAP_ZIEL+' '+m.pz;"
        /* pd is the schedule deviation: >0 late, <0 early. Zero is ambiguous
         * (on time OR not transmitted) -- the label says so, see S_MAP_ONTIME. */
        /* The radio carries three bits plus a sign, so 7 is the end of the scale, not a
         * measurement. The table on /transit marks it the same way. */
        "if(m.pd!==undefined)h+='<br>'+(Math.abs(m.pd)>=7?'\\u2265 ':'')"
        "+(m.pd>0?m.pd+' '+ITS_MAP_MIN+' '+ITS_MAP_LATE:"
        "(m.pd<0?(-m.pd)+' '+ITS_MAP_MIN+' '+ITS_MAP_EARLY:ITS_MAP_ONTIME));"
        "if(m.vl&&m.vw)h+='<br>'+dc(m.vl/10)+' \\u00d7 '+dc(m.vw/10)+' m';"
        /* Altitude in metres. The acceleration is signed, and negative means braking. */
        "if(m.al!==undefined)h+='<br>'+ITS_MAP_ALT+' '+al(m.al);"
        "if(m.la!==undefined&&m.la!==0)h+='<br>'+ITS_MAP_ACCEL+' '+dc(m.la/10)+' m/s\\u00b2';"
        "if(m.dd===1)h+='<br>'+ITS_MAP_REVERSE;"
        "if(m.lp!==undefined)h+='<br>'+(m.lp>0&&m.lp<14?ITS_MAP_LANEPOS+' '+m.lp:"
        "(m.lp<0?ITS_LANE_OFFROAD:ITS_LANE_SHOULDER));"
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
        /* One colour for an active warning on every page: .wact, with its sign from s.css. */
        "if(m.d)h+='<br><span class=\"wact\">'+(m.dt||ITS_MAP_DENM)+'</span>';"
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
        /* Where the vehicle has just been, as a faint trail from the marker back. The CAM lists
         * the point nearest the vehicle first (EN 302 637-2, B.38), so the marker goes in front.
         * Replaced rather than appended: each CAM carries the whole (short) history, so
         * accumulating them would draw it many times. */
        "if(m.ph&&m.ph.length){var pts=m.ph.map(function(q){return [q[0]/1e7,q[1]/1e7];});"
        "pts.unshift([lat,lon]);"
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
        /* The CPM layer of web_cpm.c needs the map, the layer control and the live state. */
        "window.itsMapApi={map:map,lctl:lctl,live:function(){return liveMode;}};"
        /* Assigned before connect() and the first fetch run, not just declared:
         * /ws, /spatem.json and a peer's /markers.json all answer translated text. */
        /* The page's own language, as on the messages page. */
        "var MLQ=document.documentElement.lang==='en'?'en':'de';"
        "var delay=1000,ws,closing=false,pt=0;"
        "function connect(){"
        "var proto=location.protocol==='https:'?'wss://':'ws://';"
        /* No ?lang= here. The handshake request never reaches the handler, so the language
         * is sent as the first frame right after it. */
        "ws=new WebSocket(proto+location.host+'/ws');"
        /* Pings every 5 s, like /messages: a socket to a device without power looks open. */
        "ws.onopen=function(){try{ws.send(MLQ);}catch(e){}itsSeen();clearInterval(pt);"
        "pt=setInterval(function(){try{ws.send('p');}catch(e){}},5000);};"
        /* Reversed to oldest-first: the feed sends newest first (build_msg_json) and
         * apply() overwrites per station, so unreversed the OLDEST entry would win. */
        "ws.onmessage=function(ev){itsSeen();if(ev.data==='p')return;"
        "if(liveMode)apply(JSON.parse(ev.data).reverse());delay=1000;};"
        "ws.onclose=function(){clearInterval(pt);if(closing)return;setTimeout(connect,delay);"
        "delay=Math.min(delay*2,30000);};"
        "}"
        /* Stale after two missing echoes plus 3 s. */
        "connect();itsWatch(13000);"
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
        "fetch('http://'+hp+'/markers.json?lang='+MLQ,{cache:'no-store'})"
        ".then(function(r){return r.json();}).then(function(a){"
        "peerBusy[hp]=false;"
        "if(!liveMode)return;"
        "for(var i=0;i<a.length;i++)a[i].src=hp;"
        /* Same newest-first order as our own /ws feed, so reversed for the same reason. */
        "apply(a.reverse());}).catch(function(){peerBusy[hp]=false;});});}"
        "if(ITS_MAP_PEERS.length){fetchPeers();setInterval(fetchPeers,2000);}"
        "function fetchSpat(){if(!liveMode)return;"
        /* Every answer is a sign of life as well. */
        "fetch('/spatem.json?lang='+MLQ,{cache:'no-store'}).then(function(r){itsSeen();return r.json();})"
        /* The guard again: an answer that arrives after the switch to playback would
         * otherwise paint the live phase back over the replay. */
        ".then(function(a){if(!liveMode)return;var m={};for(var i=0;i<a.length;i++){m[a[i].i]=a[i];"
        "var k=a[i].rg+'/'+a[i].id;PHASE[k]={};MTXT[k]={};"
        "for(var j=0;j<a[i].g.length;j++){PHASE[k][a[i].g[j][0]]=a[i].g[j][1];"
        /* Field 3 is the ready-translated movement text the server already sends. */
        "MTXT[k][a[i].g[j][0]]=a[i].g[j][3];}}"
        "SPAT=m;paintLanes();}).catch(function(){});}"
        "fetchSpat();setInterval(fetchSpat,3000);"
        /* GeoNetworking rectangle or ellipse as polygon points. Distance a runs along the
         * bearing (degrees clockwise from north), b at right angles, both from the centre. */
        /* A flat plane around the centre is enough: at 48 degrees latitude a corner 1 km out
         * lies 0.1 m from its great-circle position, and one 7 km out 5 m. */
        "function waPoly(lat,lon,a,b,ang,ell){"
        "var t=ang*Math.PI/180,s=Math.sin(t),c=Math.cos(t),kn=180/(Math.PI*6371000),"
        "ke=kn/Math.cos(lat*Math.PI/180),p=[],n=ell?64:4;"
        "for(var i=0;i<n;i++){var x,y;"
        "if(ell){x=a*Math.cos(2*Math.PI*i/n);y=b*Math.sin(2*Math.PI*i/n);}"
        "else{x=(i===0||i===3)?a:-a;y=i<2?b:-b;}"
        "p.push([lat+(x*c-y*s)*kn,lon+(x*s+y*c)*ke]);}"
        "return p;}"
        /* Active warnings stand out in the warning colour, as on '/' and /traffic. Everything
         * else is pale and dashed. '#e07a4f' is the --warn of s.css, written out because an SVG
         * stroke takes no var(). */
        "function waStyle(st){var on=st==='active',k=on?'#e07a4f':'#94a0a8';"
        "return {color:k,fillColor:k,weight:on?2:1.5,opacity:on?0.9:0.6,"
        "fillOpacity:on?0.15:0.04,dashArray:on?null:'5,5'};}"
        /* Device time, in German 23.09. 18:54 like fmt_when. */
        "function waTime(u){return itsTz.dm(u*1000)+' '+itsTz.hm(u*1000);}"
        /* The texts come from our own tables and may carry entities, so they are not escaped. */
        "function waText(w,now){"
        "var c=WA.c[w.cause]||(w.cause?WA.d+' ('+w.cause+')':WA.d);"
        "return '\\u26a0 <b>'+c+'</b><br>'+(WA.st[w.state]||WA.unk)"
        "+'<br>'+WA.u+' '+(w.until?waTime(w.until):WA.unk)"
        "+(now===null?'<br><small>'+WA.clk+'</small>':'');}"
        "function waCap(on){"
        "if(!on){if(waNote){waNote.remove();waNote=null;}return;}"
        "if(waNote)return;"
        "waNote=L.control({position:'bottomleft'});"
        "waNote.onAdd=function(){var e=L.DomUtil.create('div','wanote');"
        "e.textContent=WA.cap;return e;};"
        "waNote.addTo(map);}"
        "function waClear(){waLayer.clearLayers();waShapes={};waOrder='';waCap(false);}"
        /* Shapes are kept per ActionID and only restyled or re-texted on change, so a
         * refresh does not flicker and an open popup stays open. */
        "function waApply(d){d=d||{};var a=d.areas||[],seen={},ks=[],ord='';"
        "for(var i=0;i<a.length;i++){var w=a[i],k=w.station+'/'+w.seq;"
        "if(seen[k]||(w.shape!=='circle'&&w.shape!=='rect'&&w.shape!=='ellipse'))continue;"
        "var g=[w.shape,w.lat_e7,w.lon_e7,w.a,w.b,w.angle].join(),o=waShapes[k];"
        "if(o&&o.g!==g){waLayer.removeLayer(o.s);o=null;}"
        "if(!o){var la=w.lat_e7/1e7,lo=w.lon_e7/1e7;"
        "o=waShapes[k]={g:g,st:'',p:'',s:w.shape==='circle'?L.circle([la,lo],{radius:w.a}):"
        "L.polygon(waPoly(la,lo,w.a,w.b,w.angle,w.shape==='ellipse'))};"
        "o.s.bindPopup('').addTo(waLayer);}"
        "if(o.st!==w.state){o.st=w.state;o.s.setStyle(waStyle(w.state));}"
        "var p=waText(w,d.now);if(p!==o.p){o.p=p;o.s.setPopupContent(p);}"
        "seen[k]=1;ks.push(k);ord+=k+':'+w.state+';';}"
        "for(var k in waShapes)if(!seen[k]){waLayer.removeLayer(waShapes[k].s);delete waShapes[k];}"
        /* Behind the lanes and trails, so those stay clickable, and the first listed
         * (active, newest) in front of the other areas. */
        "if(ord!==waOrder){waOrder=ord;for(var i=0;i<ks.length;i++)waShapes[ks[i]].s.bringToBack();}"
        "waCap(!!d.capped);}"
        /* Warning areas change slowly, so every ten seconds is enough. A 404 means the route is
         * missing and ends the polling. Any other failure keeps the shapes until the next
         * answer. */
        "function waLoad(){if(!WA||waGone||waBusy||!liveMode||!map.hasLayer(waLayer))return;"
        "waBusy=true;"
        "fetch('/warning_areas.json',{cache:'no-store'}).then(function(r){"
        "if(r.status===404)waGone=true;if(!r.ok)throw r.status;return r.json();})"
        ".then(function(d){waBusy=false;if(liveMode&&map.hasLayer(waLayer))waApply(d);})"
        ".catch(function(){waBusy=false;});}"
        "if(WA){waLoad();setInterval(waLoad,10000);}"
        /* Lane geometry is reloaded every two minutes and recoloured whenever new
         * phases arrive. A lane without a signal group stays neutral grey. */
        /* MTXT shares this var statement with PHASE on purpose: fetchSpat() runs
         * before this line and only its async callback may touch either. */
        "var LANES=[],PHASE={},MTXT={};"
        "function paintLanes(){for(var i=0;i<LANES.length;i++){var o=LANES[i];"
        "var ph=(PHASE[o.k]||{})[o.sg];"
        /* Red and red-amber are dotted, so a stop can be read without telling red from green.
         * Dots, not dashes, because crosswalks are already dashed. */
        "var stop=o.sg>=0&&(ph===2||ph===3||ph===4);"
        "o.line.setStyle({color:(o.sg<0?'#7a848c':spatColor(ph)),"
        "weight:(o.t==1?3:4),opacity:(o.sg<0?0.5:0.9),dashArray:(stop?'1,8':(o.t==1?'4,4':null))});"
        /* Movement text arrives with every phase poll, the popup was bound once.
         * Not run through htxt(): it comes from the T() table and carries entities. */
        "var mv=(MTXT[o.k]||{})[o.sg];"
        "if(o.pt){var pc=o.pt+(mv?' \\u00b7 '+mv:'');"
        /* Only on change -- rewriting an open popup every 3s drops a selection. */
        "if(pc!==o.pc){o.pc=pc;o.line.setPopupContent(pc);}}}}"
        /* Playback: the last live phase would otherwise stay painted for the whole
         * replay (fetchSpat stops there). Empty PHASE repaints every lane neutral
         * grey, like waClear() drops the warning areas. Back in live mode the 3 s poll
         * fills PHASE again. */
        "function lnClear(){PHASE={};MTXT={};paintLanes();}"
        "function loadLanes(){fetch('/lanes.json',{cache:'no-store'})"
        ".then(function(r){return r.json();}).then(function(a){"
        "for(var i=0;i<LANES.length;i++)map.removeLayer(LANES[i].line);LANES=[];"
        "for(var i=0;i<a.length;i++){var X=a[i],k=X.rg+'/'+X.id;"
        /* `ln` deliberately not named L -- that is Leaflet's own global. */
        "for(var j=0;j<X.lanes.length;j++){var ln=X.lanes[j];"
        "var pts=ln.p.map(function(p){return [p[0]/1e7,p[1]/1e7];});"
        /* The popup goes through bindPopup (innerHTML), so the labels may hold
         * entities, like the movement text appended in paintLanes(). */
        "var pt=ITS_MAP_LANE+' '+ln.l+(ln.sg>=0?' \\u00b7 SG '+ln.sg:'')"
        "+(ln.t==1?' \\u00b7 '+ITS_MAP_XWALK:'');"
        "var pl=L.polyline(pts,{color:'#7a848c',weight:4,opacity:0.8}).addTo(map);"
        "pl.bindPopup(pt);"
        "LANES.push({line:pl,sg:ln.sg,t:ln.t,k:k,pt:pt});}}"
        "paintLanes();}).catch(function(){});}"
        "loadLanes();setInterval(loadLanes,120000);"
        "window.addEventListener('pagehide',function(){closing=true;if(ws)ws.close();});"
        /* Playback answers {e:[...],p:1?}. Entries carry the /ws feed's i, a, o, y and t
         * keys, plus ts as unix seconds for the slider and the staleness rule. */
        "var pbData=null,pbTimer=null,pbPlaying=false;"
        "function pbSeek(t){t=+t;document.getElementById('pbslider').value=t;"
        "document.getElementById('pbtime').textContent=itsTz.hm(t*1000,1);"
        "var latest={};"
        "for(var i=0;i<pbData.length;i++){var e=pbData[i];if(e.ts>t)break;latest[e.i]=e;}"
        /* Same staleness rule as the live sweep, measured in playback time
         * (t - entry.t) rather than real Date.now(). Without it a station's
         * last position would stay on the map for the rest of the window. */
        "for(var k in latest){if(t-latest[k].ts>ITS_MAP_STALE)delete latest[k];}"
        /* Remove markers for stations absent at time t, because apply() only
         * adds and moves markers and never drops the ones it was not given. */
        "for(var k in markers){if(!(k in latest))dropMarker(k);}"
        "apply(Object.keys(latest).map(function(k){return latest[k];}));}"
        /* Busy state: the bar plus a disabled button, so a slow SD read can't
         * be mistaken for a dead page or fired off twice by an impatient
         * second click. Cleared on every exit path, including errors. */
        /* The playback line has its own row, with the same levels as the /messages search.
         * Nothing found and no card are notes. A partial load or a busy device is a warning,
         * since trying again can help. A failed load is an alarm. */
        "function pbm(t,c){var m=document.getElementById('pbmsg');m.textContent=t||'';"
        "m.className=t?c:'';m.hidden=!t;}"
        "function pbBusy(on){document.getElementById('pbbar').style.display=on?'inline-block':'none';"
        "var b=document.getElementById('pbload');b.disabled=on;b.style.opacity=on?0.6:1;"
        "pbm(on?ITS_PB_BUSY:'','note');}"
        "function pbLoad(){"
        "var from=itsTz.parse(document.getElementById('pbfrom').value);"
        "var to=itsTz.parse(document.getElementById('pbto').value);"
        "pbm('');"
        /* An invalid period gets its own message. It is no load error, and the load error
         * text would make the reader suspect the SD card. */
        "if(!from||!to||to<=from){pbm(ITS_PB_RANGE,'warn');return;}"
        "pbBusy(true);"
        /* Response is {e:[...],p:1?} -- p flags a partly-read period (SD lock
         * contention), shown instead of silently pretending the range is empty. */
        "fetch('/map/playback?from='+from+'&to='+to+'&lang='+(document.documentElement.lang==='en'?'en':'de')).then(function(r){"
        /* 409 = no SD card, 503 = the worker is busy (defer_to_worker). Anything else, a
         * broken JSON too, shows S_PLAYBACK_ERROR. */
        "if(!r.ok)throw r.status;return r.json();"
        "}).then(function(data){"
        "pbBusy(false);"
        "pbData=data.e;"
        "if(!pbData.length){pbm(data.p?ITS_PB_PART:ITS_PB_NONE,data.p?'warn':'note');return;}"
        "if(data.p)pbm(ITS_PB_PART,'warn');"
        /* The seed is the state at page load. After a replay it would be minutes old when
         * switching back to live, yet it would be painted as fresh. */
        "liveMode=false;clearInterval(sweepTimer);VMEM={};window.ITS_MAP_SEED=[];"
        /* The areas are the current state, which would mislead during a replay. */
        "if(WA)waClear();"
        "lnClear();"
        "for(var k in markers)dropMarker(k);markers={};"
        "var sl=document.getElementById('pbslider');"
        "sl.min=pbData[0].ts;sl.max=pbData[pbData.length-1].ts;sl.step=pbStep();"
        "document.getElementById('pbctl').style.display='';"
        /* Reframe on the loaded window itself. apply() auto-zooms only on the
         * very first fix it ever sees (haveView), live or seed. */
        "map.fitBounds(L.latLngBounds(pbData.map(function(e){return [e.a/1e7,e.o/1e7];})),"
        "{padding:[30,30],maxZoom:16});"
        "haveView=true;"
        /* Start at the beginning, so Play still has something to play. */
        "pbSeek(sl.min);"
        "}).catch(function(e){pbBusy(false);"
        "e===409?pbm(ITS_PB_NOSD,'note'):e===503?pbm(ITS_PB_WAIT,'warn'):pbm(ITS_PB_ERROR,'alarm');});}"
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
        "apply(window.ITS_MAP_SEED||[]);startSweep();waLoad();}"
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
        /* Restored last, when every function and colour exists. Adding a layer fires
         * overlayadd, which loads the tracks. */
        "if(mo&&mo.indexOf('t')>=0)trackLayer.addTo(map);"
        "if(mo&&mo.indexOf('p')>=0&&ITS_MAP_PEERS.length)peerTrackLayer.addTo(map);"
        /* Default to the last hour. datetime-local holds the device's wall time (itsTz). */
        /* ?from=&to= (Unix seconds) come from the search on /messages: fill the period
         * and load it. The language flag links keep both. */
        "(function(){var q=new URLSearchParams(location.search),f=+q.get('from'),t=+q.get('to'),now=Date.now();"
        "if(f>0&&t>f){document.getElementById('pbfrom').value=itsTz.inp(f*1000);"
        "document.getElementById('pbto').value=itsTz.inp(t*1000);pbLoad();return;}"
        "document.getElementById('pbto').value=itsTz.inp(now);"
        "document.getElementById('pbfrom').value=itsTz.inp(now-36e5);})();"
        "})();</script>";
    httpd_resp_send_chunk(req, MAP_SCRIPT, HTTPD_RESP_USE_STRLEN);
    web_cpm_map_send(req);
#endif
    httpd_resp_send_chunk(req, FAULT_POLL_JS, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* GET /spatem.json -- current traffic-light phases, keyed by the RSU's
 * stationId so /map can enrich that marker's popup. RAM-only (no SD needed),
 * so it stays outside the SD guard below. Shape:
 * [{"i":stationId,"rg":region,"id":id,"rev":n,"age":secs,"nm":"name",
 *   "g":[[sg,phase,secsLeft,"movement text"],...]}]
 * "rev" is the MAPEM revision. The map script does not read it. It is kept because a
 * reader outside this firmware can tell from it that the lane geometry changed. */
/* spat_movement_text() below comes from web_traffic.c. */

esp_err_t spatem_json_handler(httpd_req_t *req)
{
    /* Like every page: the movement text below is translated, so without this
     * it would stay in the language of whatever was loaded last. */
    resolve_language(req);
    /* PSRAM, like the copies on /traffic and the start page. */
    static EXT_RAM_BSS_ATTR spatem_intersection_t ints[SPATEM_MAX_INT];
    int ni = spatem_snapshot(ints, SPATEM_MAX_INT);
    uint32_t now = (uint32_t)time(NULL);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send_chunk(req, "[", HTTPD_RESP_USE_STRLEN);
    for (int i = 0; i < ni; i++)
    {
        spatem_intersection_t *e = &ints[i];
        /* phase_seen, not last_seen: this number is shown beside the phase lamps and
         * must say how old THEY are, not when a MAPEM last arrived. An entry
         * seeded by a MAPEM alone has no phases yet (phase_seen 0 = never). It
         * falls back to last_seen, or its age would stay at 0 = "just now". */
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
esp_err_t lanes_json_handler(httpd_req_t *req)
{
    /* PSRAM, like the copies on /traffic and the start page. */
    static EXT_RAM_BSS_ATTR spatem_intersection_t ints[SPATEM_MAX_INT];
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
static bool playback_emit(uint32_t sec, uint32_t usec, const uint8_t *frame, size_t len,
                          const its_decoded_t *d, void *ctx_)
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
     * otherwise print uninitialised stack bytes into the JSON. Every key set: 231 bytes. */
    char extra[320] = "";
    int eo = 0;
    if (d->has_speed && d->speed_cmps != -1)   /* -1 = not available */
        eo = web_addf(extra, sizeof(extra), eo, ",\"s\":%ld", (long)d->speed_cmps);
    if (d->veh.valid && d->veh.length_dm && d->veh.width_dm)
        eo = web_addf(extra, sizeof(extra), eo, ",\"vl\":%u,\"vw\":%u",
                      (unsigned)d->veh.length_dm, (unsigned)d->veh.width_dm);
    if (d->has_src_mac)
        eo = web_addf(extra, sizeof(extra), eo,
                      ",\"sm\":\"%02x:%02x:%02x:%02x:%02x:%02x\"",
                      d->src_mac[0], d->src_mac[1], d->src_mac[2],
                      d->src_mac[3], d->src_mac[4], d->src_mac[5]);
    if (d->pt_line)
        eo = web_addf(extra, sizeof(extra), eo, ",\"pl\":%u", (unsigned)d->pt_line);
    if (d->pt_telegram && d->pt_course)
        eo = web_addf(extra, sizeof(extra), eo, ",\"pk\":%u", (unsigned)d->pt_course);
    if (d->pt_telegram && d->pt_dest)
        eo = web_addf(extra, sizeof(extra), eo, ",\"pz\":%u", (unsigned)d->pt_dest);
    if (d->pt_telegram)
        eo = web_addf(extra, sizeof(extra), eo, ",\"pd\":%d", (int)d->pt_deviation);
    /* The same detail the live feed sends, so replayed markers look exactly like live ones.
     * The heading comes from its_gn_heading, the same rule as the live ring. */
    its_gn_t g;
    its_gn_fill(&g, frame, len, d);
    uint16_t hd = its_gn_heading(d, &g);
    if (hd != 0xFFFF)
        eo = web_addf(extra, sizeof(extra), eo, ",\"hd\":%u", (unsigned)hd);
    if (d->cam.has_accel_ctrl)
        eo = web_addf(extra, sizeof(extra), eo, ",\"ac\":%u",
                      (unsigned)d->cam.accel_ctrl);
    if (d->cam.has_lights)
        eo = web_addf(extra, sizeof(extra), eo, ",\"el\":%u",
                      (unsigned)d->cam.ext_lights);
    if (d->cam.role != 0xFF && d->cam.role != 0)
        eo = web_addf(extra, sizeof(extra), eo, ",\"vr\":%u",
                      (unsigned)d->cam.role);
    if (d->pt_embarking)
        eo = web_addf(extra, sizeof(extra), eo, ",\"eb\":1");
    /* Live mode flags a station that warned recently. In playback the frame
     * being replayed IS the warning, so flag that one. */
    if (d->message_id == 1)
    {
        const char *ct = denm_cause_text(d->denm_cause);
        const char *st = denm_sub_text(d->denm_cause, d->denm_subcause);
        if (ct && st)
            web_addf(extra, sizeof(extra), eo, ",\"d\":1,\"dt\":\"%s (%s)\"", ct, st);
        else if (ct)
            web_addf(extra, sizeof(extra), eo, ",\"d\":1,\"dt\":\"%s\"", ct);
        else
            web_addf(extra, sizeof(extra), eo, ",\"d\":1");
    }

    /* Two time fields with one job each. ts is the second to compute with (slider,
     * staleness), and t is the formatted clock time, as in the live feed. */
    char pbclock[24];
    fmt_clock(sec, 0, web_lang(), pbclock, sizeof(pbclock));
    char entry[608];
    int n = snprintf(entry, sizeof(entry),
             "%s{\"ts\":%lu,\"t\":\"%s\",\"i\":%lu,\"a\":%ld,\"o\":%ld,\"y\":\"%s\"%s}",
             ctx->first ? "" : ",", (unsigned long)sec, pbclock, (unsigned long)d->station_id,
             (long)d->lat_e7, (long)d->lon_e7, d->label, extra);
    if (n < 0)
        return true;
    /* memcpy below copies n bytes, so a cut entry must not get there. Every key set: 354 of 608. */
    if ((size_t)n >= sizeof(entry))
    {
        ESP_LOGE(TAG, "playback entry cut: %d of %u", n, (unsigned)sizeof(entry));
        return true;
    }
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

/* The frame walk, because the GN heading needs the bytes. It keeps exactly the frames the
 * position walk hands over (d.has_position in sdpcap_walk). */
static bool playback_frame(uint32_t sec, uint32_t usec, const uint8_t *frame, size_t len,
                           const its_decoded_t *d, void *ctx)
{
    if (!d->has_position)
        return true;
    return playback_emit(sec, usec, frame, len, d, ctx);
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
esp_err_t markers_json_handler(httpd_req_t *req)
{
    /* The detail text is translated, so the reading map's ?lang= decides. That holds
     * also when the reader is another receiver's page (no lang = German, as everywhere). */
    resolve_language(req);
    /* 20 entries, each with up to MSG_DETAIL_MAX bytes of detail text and 576 bytes of
     * position data. 16 KB would silently cut the feed shorter than the table on the page.
     * When even 48 KB fill up, build_msg_json leaves the oldest entries out whole, so the
     * JSON stays valid. */
    static EXT_RAM_BSS_ATTR char json[49152];
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

esp_err_t tracks_get_handler(httpd_req_t *req)
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

    /* The cross-origin header goes out before every exit below, not just the good one:
     * a peer's map reads this, and a bare 500 without it is unreadable for the browser. */
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");

    /* Same reasoning as /map/playback: without this an unmounted card answers an
     * empty, successful list, which reads as "nobody drove". The check comes before the
     * large point buffer is allocated. It answers 500, not 409 like playback, because
     * loadTracks() in the map script reads 500 as no card. */
    if (!sdcard_is_mounted())
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "SD card not mounted");
        return ESP_FAIL;
    }

    /* Sized for MAX retention (~25k points), not typical: a smaller cap makes
     * the read drop the oldest points of the window. Allocated in PSRAM for this request
     * only. */
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

esp_err_t playback_get_handler(httpd_req_t *req)
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
    /* A shortened window is reported through the same "p" flag as a partial read.
     * Otherwise four hours answered to a twelve-hour request would look complete. */
    bool clamped = false;
    if (to - from > 240L * 60)  /* bound how many hourly files one request walks */
    {
        to = from + 240L * 60;
        clamped = true;
    }

    uint32_t from_sec = (uint32_t)from;
    uint32_t to_sec = (uint32_t)to;

    /* Without this an unmounted card yields an empty array, which the page
     * shows as "no data in this range" -- same look as a genuinely empty one. */
    if (!sdcard_is_mounted())
    {
        /* 409, not 500, so the page can tell a missing card from a failed read. 500 stays
         * for the allocation below. */
        httpd_resp_set_status(req, "409 Conflict");
        httpd_resp_set_type(req, "text/plain; charset=utf-8");
        httpd_resp_sendstr(req, T(S_SD_NOT_MOUNTED));
        return ESP_OK;
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
    /* Shortened above or unflushed frames: either way the window is incomplete. */
    bool partial = clamped || !flushed;
    uint32_t cursor = from_sec;
    uint32_t last_full_sec = 0;
    bool have_full_sec = false;
    for (;;)
    {
        ctx.full = false;
        bool complete = sdpcap_read_frames(cursor, to_sec, playback_frame, &ctx);
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
    /* No password and no gate: another site's <img> loop would push out the RAM console.
     * One line a minute, as in web_csrf.c. The one worker runs one playback at a time. */
    static uint32_t log1;    /* uptime second + 1 of the last line, 0 before the first */
    static unsigned quiet;   /* playbacks since that line */
    uint32_t now1 = (uint32_t)(esp_timer_get_time() / 1000000) + 1;
    if (log1 && now1 - log1 < 60)
        quiet++;
    else
    {
        ESP_LOGI(TAG, "playback %lu..%lu: %lu entries, %lu duplicates dropped%s%s (%u more)",
                 (unsigned long)from_sec, (unsigned long)to_sec,
                 (unsigned long)ctx.emitted, (unsigned long)ctx.skipped,
                 partial ? " (partial)" : "",
                 ctx.client_gone ? " (client gone, aborted)" : "", quiet);
        log1 = now1;
        quiet = 0;
    }
    if (ctx.client_gone)
        return ESP_FAIL;   /* socket is dead; closing the chunked reply would only error again */
    httpd_resp_send_chunk(req, partial ? "],\"p\":1}" : "]}", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}
#endif
