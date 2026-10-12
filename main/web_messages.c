#include "sdkconfig.h"

#include <ctype.h>
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

#include "its_decode.h"
#include "msg_extra.h"
#if CONFIG_ENABLE_SD
#include "sdcard.h"
#include "sdpcap.h"
#endif

#include "web_messages.h"
#include "webserver_priv.h"
#include "webserver_ring.h"
#include "web_dlname.h"
#include "web_fmt.h"
#include "web_msgdetail.h"

static const char TAG[] = "WEBSERVER";

/* The sender cell of the three message rows, laid out as on /senders. The name is on top, with
 * the station number and the address small below it. Without a name the station number moves
 * to the top. The name is escaped like the feed's sn key, and sid 0 means no station number.
 * A missing address ('' or the '-' the search hay keeps) shows as the page-wide &ndash;.
 * The dot is bound to the station number, so a narrow window wraps after it and the address
 * line never starts with it. */
static void sender_cell(const char *name, uint32_t sid, const char *mac_str, char *out, size_t cap)
{
    char ids[16] = "";
    if (sid)
        snprintf(ids, sizeof(ids), "%lu", (unsigned long)sid);
    if (!mac_str[0] || strcmp(mac_str, "-") == 0)
        mac_str = "&ndash;";
    if (name[0])
    {
        size_t k = web_msgdetail_escape(name, out, cap);
        web_addf(out, cap, (int)k, "<div class='sub mono'>%s%s%s</div>", ids,
                 ids[0] ? "&nbsp;&middot; " : "", mac_str);
    }
    else if (ids[0])
        snprintf(out, cap, "<span class='mono'>%s</span><div class='sub mono'>%s</div>", ids, mac_str);
    else
        snprintf(out, cap, "<span class='mono'>%s</span>", mac_str);
}

/* ================================================================== */
/*  GET /messages                                                     */
/* ================================================================== */

esp_err_t messages_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* Live-updated over WebSocket (see /ws) instead of a periodic full-page
     * reload, so the table refreshes without flicker or losing scroll
     * position. The switch in the header holds the list. */
#if CONFIG_HTTPD_WS_SUPPORT
    send_page_header_pausable(req, T(S_TITLE_MESSAGES), 0);
#else
    send_page_header(req, T(S_TITLE_MESSAGES));
#endif

    /* Opens the page's first group; closed once before the archive block. */
    char intro[256];
    snprintf(intro, sizeof(intro), "<div class='grp top'><p class='note hlp'>");
    size_t l = strlen(intro);
    snprintf(intro + l, sizeof(intro) - l, T(S_MSG_INTRO), WEB_MSG_RING_SIZE);
    l = strlen(intro);
    snprintf(intro + l, sizeof(intro) - l, "</p>");
    httpd_resp_send_chunk(req, intro, HTTPD_RESP_USE_STRLEN);
#if CONFIG_ENABLE_SD
    /* Phone only (.phjump in s.css): there the list is a long column of cards and the search
     * comes after it. No buffer: literal, heading text, literal. */
    web_send_parts(req, "<p class='phjump'><a href='#m-srch'>", T(S_SRCH_TITLE),
                   "&nbsp;&darr;</a></p>", NULL);
#endif

    /* The notes fold away behind one line, the way the loss table and the map do it, in the
     * order of the columns: type, sender, details. They go out in pieces, so no buffer limits
     * their length. */
    web_send_parts(req, "<details class='dtl'><summary>", T(S_DETAIL_SUM),
                   "</summary><p class='note'>", T(S_TYPE_HINT),
                   "</p><p class='note'>", T(S_SENDER_HINT),
                   "</p><p class='note'>", T(S_DETAIL_HINT),
                   "</p><p class='note'>", T(S_DETAIL_HINT_SEC),
                   "</p><p class='note'>", T(S_GN_HINT), "</p></details>", NULL);

    /* 650 of 768; a cut inside the open <script> makes the browser swallow the rest of
     * the table as script text. Static: only the httpd task serves this page. */
    static EXT_RAM_BSS_ATTR char fbar[768];
    HTML_PRINTF(fbar,
        /* The label and its field share one .fld, so a wrapping row cannot part them. */
        "<p class='tools'><span class='fld'><label class='cap' for='lf'>%s</label>"
        "<input id='lf' size='18' oninput='applyf()'></span></p>"
        "<script>window.applyf=function(){"
        "var n=document.getElementById('lf').value.toLowerCase(),k=0,"
        "rs=document.querySelectorAll('#msgtbody tr');"
        "rs.forEach(function(r){var s=!n||r.textContent.toLowerCase().indexOf(n)>=0;"
        "r.style.display=s?'':'none';if(s)k++;});"
        /* Cell 2 is the time in every row, and the rows run newest first. */
        "var e=document.getElementById('lfnone');if(!e)return;e.hidden=!n||!rs.length||k>0;"
        "if(!e.hidden){document.getElementById('lfa').textContent=rs[rs.length-1].cells[1].textContent;"
        "document.getElementById('lfb').textContent=rs[0].cells[1].textContent;}};"
        "</script>",
        T(S_MSG_LISTFILTER));
    httpd_resp_send_chunk(req, fbar, HTTPD_RESP_USE_STRLEN);

    /* Shown by applyf() when the filter hides every row. The list holds only the newest
     * frames, and an empty table must not read as nothing received. The line reports a state,
     * not help, so it has no hlp class.
     * 136 of 320 and 263 of 640. */
    char fntext[320];
    snprintf(fntext, sizeof(fntext), T(S_MSG_FILTER_EMPTY), WEB_MSG_RING_SIZE,
             "<b id='lfa'></b>", "<b id='lfb'></b>");
    char fnone[640];
#if CONFIG_ENABLE_SD
    HTML_PRINTF(fnone, "<p class='note' id='lfnone' hidden>%s <a href='#m-srch'>%s</a></p>",
                fntext, T(S_MSG_FILTER_OLDER));
#else
    HTML_PRINTF(fnone, "<p class='note' id='lfnone' hidden>%s</p>", fntext);
#endif
    httpd_resp_send_chunk(req, fnone, HTTPD_RESP_USE_STRLEN);

    /* Measured 209 of 384 with the longest texts. */
    char thead[384];
    snprintf(thead, sizeof(thead),
        "<div class='scroll'><table id='mtbl' class='mcard'><thead><tr><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead>"
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

    uint32_t now_s = (uint32_t)(esp_timer_get_time() / 1000000) + 1;
    for (size_t n = 0; n < count; n++)
    {
        web_msg_entry_t *e = &snapshot[count - 1 - n];

        /* Static like snapshot above: only the httpd task serves this page. */
        static EXT_RAM_BSS_ATTR char detail[MSG_DETAIL_MAX];
        msg_detail_text(e, (uint32_t)time(NULL), detail, sizeof(detail));

        char clock[24];
        fmt_clock(e->seconds, e->microseconds, web_lang(), clock, sizeof(clock));

        /* Bare number, because the column head names the unit. */
        char rssi_str[16];
        if (e->rssi != 0)
            snprintf(rssi_str, sizeof(rssi_str), "%d", e->rssi);
        else
            snprintf(rssi_str, sizeof(rssi_str), "&ndash;");

        char typeesc[WEB_MSG_TYPE_LEN * 6];
        html_escape(e->msgtype, typeesc, sizeof(typeesc));

        char mac_str[20];
        if (e->has_src_mac)
            snprintf(mac_str, sizeof(mac_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     e->src_mac[0], e->src_mac[1], e->src_mac[2],
                     e->src_mac[3], e->src_mac[4], e->src_mac[5]);
        else
            snprintf(mac_str, sizeof(mac_str), "-");

        /* 306 of 320: a 39-character name escaped, a 10-digit station number, mac_str full. */
        static EXT_RAM_BSS_ATTR char sndc[320];
        sender_cell(e->has_src_mac ? snd_name(s_snd_cache, SND_CACHE_N, e->src_mac, now_s) : "",
                    e->has_position ? e->station_id : 0, mac_str, sndc, sizeof(sndc));

        /* MSG_DETAIL_MAX + 700 of MSG_DETAIL_MAX + 768, detail and sender cell at their buffer
         * sizes. */
        static EXT_RAM_BSS_ATTR char row[MSG_DETAIL_MAX + 768];
        /* Same seven cells in the same order as the JS row below and the archive row:
         * the phone cards (s.css .mcard) place them by position. */
        HTML_PRINTF(row,
            "<tr><td>%zu</td><td>%s</td><td>%s</td><td>%lu</td>"
            "<td class='wrapcell'>%s</td><td class='wrapcell'>%s</td><td class='wrapcell'>%s</td></tr>",
            n + 1, clock, rssi_str, (unsigned long)e->length, typeesc, sndc, detail);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

#if CONFIG_HTTPD_WS_SUPPORT
    /* Reconnects with backoff if the socket drops (e.g. Wi-Fi hiccup on the
     * client, or the device rebooting) -- the static rows above still work
     * without JS/WebSocket, just without the live updates. */
    static const char ws_script[] =
        "<script>(function(){"
        /* Assigned before connect() runs, not just declared: the feed builds the
         * detail text per socket and defaults to German without this. */
        /* The language the server chose for this page, taken from <html lang>. Read from the
         * address, an English page opened without lang= would get a German feed. */
        "var MLQ=document.documentElement.lang==='en'?'en':'de';"
        "var delay=1000,ws,closing=false,pt=0,pend=null,ht=0;"
        /* An empty value shows as a dash. The feed keeps '-' as data for older peers. */
        "function nv(x){return x===undefined||x===null||x===''||x==='-'?'&ndash;':x;}"
        "function draw(d){var h='';for(var i=0;i<d.length;i++){var m=d[i];"
        /* Type cell exactly like the server-rendered row above: size and line
         * already stand in the detail column, and the map reads m.vl/m.pl from
         * the same feed for its popup. The phone cards need the same cell order. */
        "h+='<tr><td>'+(i+1)+'</td><td>'+m.t+'</td><td>'+String(nv(m.r)).replace(' dBm','')+'</td><td>'+m.l+'</td><td class=\"wrapcell\">'+m.y+'</td><td class=\"wrapcell\">'+(m.sn?m.sn+'<div class=\"sub mono\">'+(m.i?m.i+'&nbsp;&middot; ':'')+nv(m.sm)+'</div>':m.i?'<span class=\"mono\">'+m.i+'</span><div class=\"sub mono\">'+nv(m.sm)+'</div>':'<span class=\"mono\">'+nv(m.sm)+'</span>')+'</td><td class=\"wrapcell\">'+m.h+'</td></tr>';}"
        "document.getElementById('msgtbody').innerHTML=h;if(window.applyf)window.applyf();}"
        /* While the list is paused, or within 5 s of the reader scrolling, tapping, typing or
         * selecting, the newest frame waits in pend. Older ones are dropped. */
        "function flush(){clearTimeout(ht);if(!pend||itsLive.paused())return;"
        "var w=5000-itsLive.idle();if(w>0){ht=setTimeout(flush,w);return;}"
        "var d=pend;pend=null;draw(d);}"
        "itsLive.on(flush);"
        "function connect(){"
        "var proto=location.protocol==='https:'?'wss://':'ws://';"
        /* No ?lang= here, because the handshake request never reaches the handler. */
        "ws=new WebSocket(proto+location.host+'/ws');"
        /* The handshake carries no language to the handler, so the first frame does. Pings
         * every 5 s: a socket to a device without power looks open for minutes. */
        "ws.onopen=function(){try{ws.send(MLQ);}catch(e){}itsSeen();clearInterval(pt);"
        "pt=setInterval(function(){try{ws.send('p');}catch(e){}},5000);};"
        "ws.onmessage=function(ev){itsSeen();if(ev.data==='p')return;"
        "pend=JSON.parse(ev.data);delay=1000;flush();};"
        "ws.onclose=function(){clearInterval(pt);if(closing)return;setTimeout(connect,delay);"
        "delay=Math.min(delay*2,30000);};"
        "}"
        /* Stale after two missing echoes plus 3 s. */
        "connect();itsWatch(13000);"
        /* Navigating away/reloading without this leaves the socket to be
         * reaped later by the server-side dead-client check in
         * ws_broadcast_work instead of freeing it immediately. */
        "window.addEventListener('pagehide',function(){closing=true;if(ws)ws.close();});"
        "})();</script>";
    httpd_resp_send_chunk(req, ws_script, HTTPD_RESP_USE_STRLEN);
#endif
    httpd_resp_send_chunk(req, FAULT_POLL_JS, HTTPD_RESP_USE_STRLEN);

    /* Closes .grp top unconditionally -- the archive block below is SD-only
     * and must not be the one carrying the closing tag. */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD
    /* The recording search comes right after the messages it finds. The re-send of roadside
     * units is on /senders (web_rsu.c). */
    {
        /* 12 substituted strings: 2831 of 6144 (longer language, the period picker at its size);
         * sized with room and checked, because a cut here swallows the rest of the page. */
        static EXT_RAM_BSS_ATTR char arch[6144];
        HTML_PRINTF(arch,
            "<div class='grp' id='m-srch'><h2>%s</h2><p class='note hlp'>%s</p>"
            "<p class='tools'>%s "
            "<span class='fld'><label class='cap' for='sq'>%s</label>"
            "<input id='sq' size='14' maxlength='32'></span> "
            "<button onclick='srch()'>%s</button> "
            "<button class='dlb' onclick='expp()'>&#8595; %s</button></p>"
            "<p class='note hlp'>%s</p>"
            "<div id='sr'></div></div>"
            "<script>"
            /* The fields hold the device's wall time (itsTz), and the URLs keep Unix seconds. */
            "(function(){var n=Date.now();document.getElementById('st').value=itsTz.inp(n);"
            "document.getElementById('sf').value=itsTz.inp(n-216e5);})();"
            "function srch(){"
            "var f=itsTz.parse(document.getElementById('sf').value);"
            "var t=itsTz.parse(document.getElementById('st').value);"
            "if(!f||!t)return;"
            "var o=document.getElementById('sr');o.textContent='%s';"
            "fetch('/messages/search?from='+f+'&to='+t+'&q='+encodeURIComponent(document.getElementById('sq').value)+'&lang=%s')"
            ".then(function(r){return r.text();}).then(function(x){o.innerHTML=x;})"
            ".catch(function(){o.textContent='%s';});}"
            "function expp(){"
            "var f=itsTz.parse(document.getElementById('sf').value);"
            "var t=itsTz.parse(document.getElementById('st').value);"
            "if(!f||!t)return;"
            /* Asks first (chk=1), so a missing card or a busy device is said in #sr
             * instead of handing out an empty file. */
            "var u='from='+f+'&to='+t+'&q='+encodeURIComponent(document.getElementById('sq').value),"
            "o=document.getElementById('sr');"
            "fetch('/messages/export.pcap?chk=1&lang=%s&'+u,{cache:'no-store'}).then(function(r){"
            "if(r.ok){location.href='/messages/export.pcap?'+u;return;}"
            "return r.text().then(function(x){o.textContent=x;});})"
            ".catch(function(){o.textContent='%s';});}"
            "</script>",
            T(S_SRCH_TITLE), T(S_SRCH_HINT), web_range_html("sf", "st"),
            T(S_SRCH_FILTER), T(S_SRCH_BTN), T(S_SRCH_EXPORT), T(S_SRCH_EXPORT_HINT),
            /* The fetches carry the page's language along. Without it the
             * search table comes back German on ?lang=en. */
            /* These texts go into textContent inside a quoted string, so they must hold no
             * entities and no apostrophe. */
            T(S_SRCH_RUN), web_lang() == LANG_EN ? "en" : "de", T(S_ERR_GENERIC),
            web_lang() == LANG_EN ? "en" : "de", T(S_ERR_GENERIC));
        httpd_resp_send_chunk(req, arch, HTTPD_RESP_USE_STRLEN);
    }
#endif

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

#if CONFIG_ENABLE_SD
/* ==================================================================
 *  GET /messages/search -- searches the PCAP archive. RSSI is shown
 *  as an empty value (&ndash;): the recording carries the raw frames, not reception meta.
 * ================================================================== */

#define SRCH_LIMIT 200
#define SRCH_ROW_MAX (MSG_DETAIL_MAX + 768)
#define SRCH_OUT_CAP (SRCH_LIMIT * SRCH_ROW_MAX)

/* The sender names of one search. The table is cleared before each walk and asked only for
 * shown rows. Only one search runs at a time (defer_to_worker), so one table is enough. */
static EXT_RAM_BSS_ATTR snd_name_t s_srch_names[SND_CACHE_N];

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

    /* Static, because only one search runs at a time (see defer_to_worker). The search does
     * not ask the certificate cache (false below), so a digest signer shows no verdict. */
    static EXT_RAM_BSS_ATTR msg_extra_scratch_t xs;
    static EXT_RAM_BSS_ATTR char detail[MSG_DETAIL_MAX];
    static EXT_RAM_BSS_ATTR char row[SRCH_ROW_MAX];
    msg_extra_from_frame(&e.extra, frame, frame_len, d, false, sec, &xs);
    /* The recording's time stamp is the reception time, so the gap to the signing time and
     * the position's age show here too. The heading is taken as in webserver_handle_packet. */
    its_sechdr_note_rx(&e.extra.sechdr, sec, usec);
    its_gn_note_rx(&e.extra.gn, sec, usec);
    e.heading_ddeg = its_gn_heading(d, &e.extra.gn);
    msg_detail_text(&e, sec, detail, sizeof(detail));

    char clock[24];
    fmt_when(sec, 0, FMT_SEC, web_lang(), clock, sizeof(clock));

    char typeesc[WEB_MSG_TYPE_LEN * 6];
    html_escape(e.msgtype, typeesc, sizeof(typeesc));

    /* The name is looked up now, not at receive time: at most one question per shown MAC. */
    static EXT_RAM_BSS_ATTR char sndc[320];
    sender_cell(e.has_src_mac ? snd_name(s_srch_names, SND_CACHE_N, e.src_mac,
                                         (uint32_t)(esp_timer_get_time() / 1000000) + 1) : "",
                e.has_position ? e.station_id : 0, mac_str, sndc, sizeof(sndc));

    /* Same seven cells in the same order as the two rows in messages_get_handler:
     * the phone cards (s.css .mcard) place them by position. */
    int rl = snprintf(row, sizeof(row),
        "<tr><td>%lu</td><td>%s</td><td>&ndash;</td><td>%lu</td>"
        "<td class='wrapcell'>%s</td><td class='wrapcell'>%s</td><td class='wrapcell'>%s</td></tr>",
        (unsigned long)++c->shown, clock, (unsigned long)e.length,
        typeesc, sndc, detail);
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

/* Streams an HTML fragment. It runs on the slow worker via messages_search_async in
 * webserver.c. */
esp_err_t messages_search_stream(httpd_req_t *req)
{
    resolve_language(req);

    /* Without a card the walk reads nothing, and 'Keine Treffer.' would read like 'nothing
     * received'. The card is checked on every search, because it can come back while the page
     * is open. */
    if (!sdcard_is_mounted())
    {
        /* 96 against 47 measured (German). */
        char nosd[96];
        snprintf(nosd, sizeof(nosd), "<p class='note'>%s</p>", T(S_SD_NOT_MOUNTED));
        httpd_resp_set_type(req, "text/html; charset=utf-8");
        httpd_resp_sendstr(req, nosd);
        return ESP_OK;
    }

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
    /* Measured 185 of 512. */
    char head[512];
    snprintf(head, sizeof(head),
        "<div class='scroll'><table class='mcard'><thead><tr><th>#</th><th>%s</th><th>%s</th>"
        "<th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
        T(S_COL_TIME), T(S_COL_RSSI), T(S_COL_LENGTH), T(S_COL_TYPE),
        T(S_COL_SENDER), T(S_COL_PREVIEW));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

    /* The newest minutes are still in the PSRAM ring; without this the search
     * reports them as "nothing found". Same reason as in the export -- and,
     * for a window that already closed, the ring is not asked at all. */
    bool flushed = pcap_window_on_card((uint32_t)to);
    memset(s_srch_names, 0, sizeof(s_srch_names));
    bool complete = sdpcap_read_frames((uint32_t)from, (uint32_t)to, srch_cb, &ctx) && flushed;

    /* Rows go out AFTER the walk, so the send does not hold the SD writer
     * lock. Capped at SRCH_LIMIT rows, that is at most SRCH_OUT_CAP bytes. */
    if (ctx.out_len)
        httpd_resp_send_chunk(req, ctx.out, ctx.out_len);
    heap_caps_free(ctx.out);

    /* The map plays the same period. It loads four hours at most and says so itself. from
     * and to are the clamped values of this search. 126 of 192. */
    char mapl[192] = "";
#if CONFIG_HTTPD_WS_SUPPORT
    HTML_PRINTF(mapl, "<p class='more'><a href='/map?lang=%s&amp;from=%ld&amp;to=%ld'>%s</a></p>",
                web_lang() == LANG_EN ? "en" : "de", from, to, T(S_SRCH_MAP));
#endif
    /* An empty or capped result is a note. A partly read window is a warning, because then
     * 'no match' may be wrong. 302 of 512, 367 with mapl at its size. */
    bool part = !complete && !ctx.limit_hit;
    char foot[512];
    HTML_PRINTF(foot, "</tbody></table></div>%s%s%s%s%s%s%s",
        ctx.shown == 0 || ctx.limit_hit ? "<p class='note'>" : "",
        ctx.shown == 0 ? T(S_SRCH_NONE) : ctx.limit_hit ? T(S_SRCH_LIMIT) : "",
        ctx.shown == 0 || ctx.limit_hit ? "</p>" : "",
        part ? "<div class='warn'><p>" : "",
        part ? T(S_SRCH_PARTIAL) : "",
        part ? "</p></div>" : "",
        mapl);
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

esp_err_t messages_export_stream(httpd_req_t *req)
{
    /* On the worker: its own language slot, set per request like the search. */
    resolve_language(req);
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

    /* Checked before the name and the type go out, because without a card the file would come
     * out empty. */
    if (!sdcard_is_mounted())
    {
        httpd_resp_set_status(req, "409 Conflict");
        httpd_resp_set_type(req, "text/plain; charset=utf-8");
        httpd_resp_sendstr(req, T(S_SD_NOT_MOUNTED));
        return ESP_OK;
    }

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

    /* Nothing has been sent yet, so the name can still state the truth: the clamped period in
     * device time like the hourly files, and whether the file is cut or has gaps. The marks
     * are not translated, because the download URL carries no lang=. */
    char f0[16], t0[16], what[48], disp[WEB_DL_DISP_MAX];
    const char *mark = ctx.full ? "-cut" : (complete ? "" : "-partial");
    web_dl_stamp(f0, sizeof(f0), (time_t)from);
    web_dl_stamp(t0, sizeof(t0), (time_t)to);
    if (f0[0] && t0[0])   /* the end drops its date within one day */
        snprintf(what, sizeof(what), "%s-%s%s", f0, strncmp(f0, t0, 9) ? t0 : t0 + 9, mark);
    else
        snprintf(what, sizeof(what), "%ld-%ld%s", from, to, mark);
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    httpd_resp_set_hdr(req, "Content-Disposition", web_dl_disp(disp, sizeof(disp), what, "pcap"));

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
    /* Without a web password another site's <img> loop would push out the RAM console.
     * Log one line a minute, as web_csrf.c does. The statics need no lock, because the one
     * worker runs one export at a time. */
    static uint32_t log1;    /* uptime second + 1 of the last line, 0 before the first */
    static unsigned quiet;   /* exports since that line */
    uint32_t now1 = (uint32_t)(esp_timer_get_time() / 1000000) + 1;
    if (log1 && now1 - log1 < 60)
        quiet++;
    else
    {
        ESP_LOGI(TAG, "export %ld..%ld: %lu frames, %u bytes%s%s (%u more)", from, to,
                 (unsigned long)ctx.kept, (unsigned)ctx.len,
                 ctx.full ? " (size cap hit)" : "", complete ? "" : " (partial)", quiet);
        log1 = now1;
        quiet = 0;
    }
    if (gone)
        return ESP_FAIL;
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}
#endif /* CONFIG_ENABLE_SD */
