#include "web_traffic.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "its_decode.h"
#include "stats.h"
#include "events_log.h"
#include "config.h"
#include "inventory.h"
#include "sdcard.h"
#include "webserver_priv.h"

static const char TAG[] = "WEBSERVER";

#if CONFIG_ENABLE_SD

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

const char *denm_cause_text(uint8_t code)
{
    for (size_t i = 0; i < sizeof(DENM_CAUSES) / sizeof(DENM_CAUSES[0]); i++)
        if (DENM_CAUSES[i].code == code)
            return web_lang() == LANG_DE ? DENM_CAUSES[i].de : DENM_CAUSES[i].en;
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

const char *denm_sub_text(uint8_t cause, uint8_t sub)
{
    if (sub == 0)
        return NULL;                 /* "unavailable" -- nothing to add */
    for (size_t i = 0; i < sizeof(DENM_SUBCAUSES) / sizeof(DENM_SUBCAUSES[0]); i++)
        if (DENM_SUBCAUSES[i].cause == cause && DENM_SUBCAUSES[i].sub == sub)
            return web_lang() == LANG_DE ? DENM_SUBCAUSES[i].de : DENM_SUBCAUSES[i].en;
    return NULL;
}

/* What a signal group controls, as short text ("geradeaus", "links, rechts",
 * "Fussgaenger"), from the MAPEM lane geometry. Empty when no MAPEM for that
 * intersection has been decoded yet. Outside the SD guard: /spatem.json
 * needs it too. */
void spat_movement_text(const spatem_intersection_t *e, uint8_t sg,
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

#if CONFIG_ENABLE_SD  /* traffic statistics + warning list continue */

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
        const char *w = web_lang() == LANG_DE ? F[i].de : F[i].en;
        int k = snprintf(out + n, cap - n, "%s%s", n ? ", " : "", w);
        if (k < 0 || (size_t)k >= cap - n)
            break;
        n += (size_t)k;
        if (F[i].warn && alert) *alert = true;
    }
    return n;
}

/* Live traffic-light snapshot: one block per intersection, a coloured dot per
 * signal group. Emitted inside #trf-body, so it refreshes with the page. */
/* Without any SPATEM it prints a short note instead. */
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
        if (web_lang() == LANG_DE) snprintf(agebuf, sizeof(agebuf), "vor %lus", age);
        else                         snprintf(agebuf, sizeof(agebuf), "%lus ago", age);

        /* Prefer the MAPEM name when the intersection sends one; the numeric
         * id stays visible next to it, just demoted to the detail line. */
        char nameesc[ITS_MAP_NAME_LEN * 6];
        html_escape(e->name, nameesc, sizeof(nameesc));
        /* Sized for the escaped name (up to ITS_MAP_NAME_LEN*6) plus the
         * surrounding markup. A truncated closing tag would break the layout. */
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
                             web_lang() == LANG_DE ? "Tempolimit" : "Speed limit",
                             (unsigned)e->speed_max_kmh);
                g += k; left -= (size_t)k;
            }
            if (e->lane_width_cm)
                snprintf(g, left, "%s%s %u,%02u m",
                         e->speed_max_kmh ? " &middot; " : "",
                         web_lang() == LANG_DE ? "Spurbreite" : "Lane width",
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
            /* The chip buffer below is generous: the styled chip alone is about
             * 224 bytes, plus the title text. */
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
    /* closes the traffic-lights .grp */
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

esp_err_t traffic_get_handler(httpd_req_t *req)
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

    const char *lc = web_lang() == LANG_DE ? "de" : "en";
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
    bool speed_mixed = false;   /* window has rows under the older speed rule */
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

    /* Own chunk so these two can join the same card row. It closes .grid. */
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

    /* Beyond a day, hourly rows are unreadable. Roll them up per calendar
     * day instead. */
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

        /* Older hourly rows carry no identifier count. Show a dash, not a zero
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

            /* Link to the position when both coordinates are set. Not every
             * stored event has one. */
            char poslink[128] = "";
            if (evs[i].lat_e7 && evs[i].lon_e7)
                snprintf(poslink, sizeof(poslink),
                         " <a class='pin' href='/map?lang=%s&amp;lat=%ld&amp;lon=%ld' title='%s'>"
                         "&#128205;</a>",
                         web_lang() == LANG_EN ? "en" : "de",
                         (long)evs[i].lat_e7, (long)evs[i].lon_e7, T(S_EVT_SHOWPOS));

            /* 66 bytes of markup + when[64] + poslink[128] + sender[160] +
             * relay[352] + lvl[40] + cause[160]. */
            char erow[1024];
            /* Causes the table does not name show their raw code instead of a
             * guessed description. */
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
                         web_lang() == LANG_DE ? "ohne n&auml;here Angabe"
                                                 : "no detail given");
            else if (evs[i].cause == 0)
                snprintf(cause, sizeof(cause), "%s", T(S_EVT_DENM));
            else if (web_lang() == LANG_DE)
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

        /* Windows past 24 h only: in one day each hour occurs once. A partial
         * hourly read would leave the denominator short and overstate every bar. */
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
            /* Split in place. A string with too few names leaves the rest empty. */
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
    /* closes the warnings .grp (both branches above end here) */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);

    traffic_refresh_footer(req, ri);
    return ESP_OK;
}

#endif /* CONFIG_ENABLE_SD */
