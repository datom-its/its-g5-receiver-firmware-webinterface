#include "sdkconfig.h"

#include "web_glance.h"

#include <string.h>
#include <time.h>

#include "esp_attr.h"

#include "ptlog.h"
#include "spatem.h"
#include "web_fmt.h"
#include "web_system.h"
#include "web_traffic.h"
#include "webserver_priv.h"

static const char TAG[] = "web_glance";

/* "vor 4 min" / "4 min ago" like the lamp age on /traffic. fmt_age's no-break spaces keep it
 * whole at 390 px. Worst 13 bytes ("vor 49710 d", 32-bit clock). */
static void gl_ago(uint32_t sec, char *out, size_t cap)
{
    fmt_age(sec, FMT_DUR_ONE, web_lang(), out, cap);
}

void web_glance_view(gl_view_t *v)
{
    uint32_t now = (uint32_t)time(NULL);

    /* Eight entries of 404 bytes: never on the httpd stack. */
    static EXT_RAM_BSS_ATTR spatem_intersection_t ints[SPATEM_MAX_INT];
    int n = spatem_snapshot(ints, SPATEM_MAX_INT);
    v->amp[0] = '\0';
    v->ampd[0] = '\0';
    if (n <= 0)
        HTML_PRINTF(v->ampd, "%s", T(S_TRF_LIGHTS_NONE));
    else
    {
        /* The newest entry that has phases, or the newest of all when none has phases. */
        int first = 0, more = 0;
        for (int i = n - 1; i >= 0; i--)
            if (ints[i].phase_seen)
                first = i;
        for (int i = 0; i < n; i++)
            more += i != first && ints[i].phase_seen;
        const spatem_intersection_t *e = &ints[first];

        /* In message order, as the chips on /traffic. Both pages use one lamp mapping. */
        int at = 0;
        for (int s = 0; s < e->n; s++)
            at = web_addf(v->amp, sizeof(v->amp), at, "%s%s", s ? " " : "",
                          web_phase_lamp(e->phase[s]));

        /* The name comes over the air: escaped here, json-escaped again for /status.json. */
        if (e->name[0])
        {
            html_escape(e->name, v->ampd, sizeof(v->ampd));
            at = (int)strlen(v->ampd);
        }
        else
            at = web_addf(v->ampd, sizeof(v->ampd), 0, "%s %u/%u", T(S_TRF_INTERSECTION),
                          (unsigned)e->region, (unsigned)e->id);
        /* The age of the lamps, as on /traffic. A MAPEM-only entry falls back to last_seen. */
        uint32_t seen = e->phase_seen ? e->phase_seen : e->last_seen;
        char ago[FMT_AGE_MAX];
        gl_ago(seen && now > seen ? now - seen : 0, ago, sizeof(ago));
        at = web_addf(v->ampd, sizeof(v->ampd), at, " &middot; %s", ago);
        if (more)
            web_addf(v->ampd, sizeof(v->ampd), at, " &middot; %d %s", more, T(S_GL_SP_MORE));
    }

    uint16_t line = 0;
    uint32_t sec = 0;
    v->pt_state = ptlog_latest(&line, &sec);
    if (v->pt_state == 1)
    {
        char ago[FMT_AGE_MAX];
        gl_ago(now > sec ? now - sec : 0, ago, sizeof(ago));
        /* The word before the number, as the line is called on the bus. */
        HTML_PRINTF(v->pt, "%s %u", T(S_PT_LINE), (unsigned)line);
        HTML_PRINTF(v->ptd, "%s %s", T(S_GL_PT_SEEN), ago);
    }
    else
    {
        HTML_PRINTF(v->pt, "%s", "&ndash;");
        HTML_PRINTF(v->ptd, "%s", v->pt_state == 0 ? T(S_PT_NONE) : "");
    }

#if CONFIG_ENABLE_SD
    v->warn = web_warn_active();
#else
    v->warn = WEB_WARN_UNKNOWN;
#endif
}

void web_glance_send(httpd_req_t *req, const gl_view_t *v, const char *lc, bool peers)
{
    /* web_addf, not HTML_PRINTF: the lamps are a loop. 2495 of 4096 (German, SD, peers,
     * 32 lamps, a name of 39 quotes, clock unset). */
    static EXT_RAM_BSS_ATTR char glblk[4096];
    const size_t cap = sizeof(glblk);
    int at = web_addf(glblk, cap, 0,
                      "<div class='grp' id='sec-road'><h2>%s</h2><div class='grid'>"
                      "<div class='cell'><div class='l'>", T(S_NAV_G_ROAD));
#if CONFIG_ENABLE_SD
    at = web_addf(glblk, cap, at, "<a href='/traffic?lang=%s#lights'>%s</a>", lc, T(S_TRF_LIGHTS));
#else
    /* Without SD there is no /traffic. The map shows the lights as well. */
    at = web_addf(glblk, cap, at, "<a href='/map?lang=%s'>%s</a>", lc, T(S_TRF_LIGHTS));
#endif
    at = web_addf(glblk, cap, at, "</div><div class='v amps' id='gl-amp'>");
    if (!v->amp[0])
        at = web_addf(glblk, cap, at, "&ndash;");
    for (const char *p = v->amp; *p;)
    {
        size_t k = strcspn(p, " ");
        at = web_addf(glblk, cap, at, "<i class='amp %.*s'><b></b><b></b><b></b></i>", (int)k, p);
        p += k;
        if (*p == ' ')
            p++;
    }
    at = web_addf(glblk, cap, at,
                  "</div><div class='d' id='gl-ampd'>%s</div></div>"
                  "<div class='cell'><div class='l'><a href='/transit?lang=%s'>%s</a></div>"
                  "<div class='v' id='gl-pt'>%s</div><div class='d' id='gl-ptd'>%s</div></div>",
                  v->ampd, lc, T(S_NAV_TRANSIT), v->pt, v->ptd);
#if CONFIG_ENABLE_SD
    /* Without SD there is no warning store and no /traffic: no tile rather than a lasting
     * dash. Amber from one active warning on, a state of the road, not of the device. */
    char wn[12] = "&ndash;";
    if (v->warn >= 0)
        snprintf(wn, sizeof(wn), "%d", v->warn);
    at = web_addf(glblk, cap, at,
                  "<div class='cell'><div class='l%s' id='gl-wnl'><a href='/traffic?lang=%s#denm'>"
                  "%s</a></div><div class='v' id='gl-wn'>%s</div><div class='d' id='gl-wnd'>%s</div>"
                  "</div>",
                  v->warn > 0 ? " v-warn" : "", lc, T(S_EVT_TITLE), wn,
                  T(v->warn == WEB_WARN_NOCLOCK ? S_CLOCK_UNSET : S_WARN_ACTIVE));
#endif
    if (peers)
        at = web_addf(glblk, cap, at,
                      "<div class='cell'><div class='l' id='gl-prl'><a href='#sec-peer'>%s</a></div>"
                      "<div class='v' id='gl-pr'>&hellip;</div><div class='d' id='gl-prd'></div></div>",
                      T(S_PEER_TITLE));
    web_addf(glblk, cap, at, "</div></div>");
    httpd_resp_send_chunk(req, glblk, HTTPD_RESP_USE_STRLEN);
}

/* The entries of the type line become links in the browser, so the field "types" of
 * /status.json stays byte-identical: outside programs and the peers read it. */
void web_glance_script(httpd_req_t *req, const char *lc)
{
#if CONFIG_ENABLE_SD
    const int sd = 1;
#else
    const int sd = 0;
#endif
    /* Only the httpd task serves the start page, so static is safe; 1600 of 2048 (German),
     * 1614 with the %d at 11 digits and each text at its longest in either language. */
    static EXT_RAM_BSS_ATTR char glscr[2048];
    HTML_PRINTF(glscr,
        "<script>(function(){var LC='%s',SD=%d,ALL='%s',QT='%s',OFF='%s',ACT='%s';"
        "function g(i){return document.getElementById(i);}"
        /* Where a type leads: lights and requests to /traffic, warnings to its list, trams
         * and buses to /transit, vehicles to the map. Without SD there is no /traffic. */
        "function tu(s){var q='?lang='+LC;"
        "if(/\\b(SPATEM|MAPEM|SSEM)\\b/.test(s))return SD?'/traffic'+q+'#lights':'/map'+q;"
        "if(/\\bSREM\\b/.test(s))return SD?'/traffic'+q+'#prio':'/messages'+q;"
        "if(/\\bDENM\\b/.test(s))return SD?'/traffic'+q+'#denm':'/messages'+q;"
        "if(/^(Bus|Tram) /.test(s))return '/transit'+q;"
        "if(/\\bCAM\\b/.test(s))return '/map'+q;"
        "return '/messages'+q;}"
        /* Only entries that end in a count become links, so the no-messages sentence stays
         * text; a line that already has links is left alone. */
        "function tl(){var e=g('st-type');if(!e||e.querySelector('a'))return;"
        "e.innerHTML=e.innerHTML.split(' \\u00b7 ').map(function(p){"
        "return / \\d+$/.test(p)?\"<a href='\"+tu(p)+\"'>\"+p+'</a>':p;}).join(' &middot; ');}"
        /* arApply calls this on every poll, after it wrote the type line anew. Lamp classes
         * must pass a whitelist. A busy line table sends no pt. A warning count of null (clock
         * unset, store busy) leaves the tile as it is. */
        "window.glApply=function(d){tl();var e,x=d.gl;if(x){"
        "if(x.amp!==undefined&&(e=g('gl-amp')))e.innerHTML=x.amp?x.amp.split(' ').map(function(c){"
        "return \"<i class='amp \"+(/^(g|y|r|ry|off)$/.test(c)?c:'off')+\"'><b></b><b></b><b></b></i>\";"
        "}).join(''):'&ndash;';"
        "if(x.ampd!==undefined&&(e=g('gl-ampd')))e.innerHTML=x.ampd;"
        "if(x.pt!==undefined&&(e=g('gl-pt')))e.innerHTML=x.pt;"
        "if(x.ptd!==undefined&&(e=g('gl-ptd')))e.innerHTML=x.ptd;}"
        "if(typeof d.warn_active==='number'&&(e=g('gl-wn'))){e.textContent=d.warn_active;"
        "g('gl-wnd').textContent=ACT;g('gl-wnl').className='l'+(d.warn_active>0?' v-warn':'');}};"
        /* The peer block calls this: n of m answer, q of them do not receive. Unreachable ones
         * turn the label amber, a warning and no alarm. Quiet ones are only named, or a device
         * at a place without traffic would stay amber for good. */
        "window.glPeer=function(n,m,q){var v=g('gl-pr'),t=g('gl-prd'),l=g('gl-prl');if(!v||!t)return;"
        "v.innerHTML=(+n)+\"<span class='e'>/\"+(+m)+'</span>';"
        "t.textContent=(n<m?(m-n)+' '+OFF:ALL)+(q?' \\u00b7 '+q+' '+QT:'');"
        "if(l)l.className='l'+(n<m?' v-warn':'');};"
        "tl();})();</script>",
        lc, sd, T(S_GL_PEER_ALL), T(S_GL_PEER_QUIET), T(S_PEER_OFFLINE), T(S_WARN_ACTIVE));
    httpd_resp_send_chunk(req, glscr, HTTPD_RESP_USE_STRLEN);
}

void web_glance_json(char *out, size_t cap)
{
    static EXT_RAM_BSS_ATTR gl_view_t v;
    /* The detail lines carry a name heard over the air: web_json_esc drops broken UTF-8 and
     * controls and escapes quote and backslash, at most twice the input (ampd 383, ptd 159). */
    static EXT_RAM_BSS_ATTR char ampdj[768], ptdj[320];
    web_glance_view(&v);
    web_json_esc(v.ampd, ampdj, sizeof(ampdj));
    web_json_esc(v.ptd, ptdj, sizeof(ptdj));
    int at = web_addf(out, cap, 0, ",\"gl\":{\"amp\":\"%s\",\"ampd\":\"%s\"", v.amp, ampdj);
    /* A busy line table sends no pt, so the tile keeps what it shows. */
    if (v.pt_state >= 0)
        at = web_addf(out, cap, at, ",\"pt\":\"%s\",\"ptd\":\"%s\"", v.pt, ptdj);
    web_addf(out, cap, at, "}");
}
