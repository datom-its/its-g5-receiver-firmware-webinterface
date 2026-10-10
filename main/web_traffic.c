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
#include "priolog.h"
#include "spatlog.h"
#include "web_infolog.h"
#include "web_fmt.h"
#include "web_gn.h"
#include "web_msgdetail.h"
#include "webserver_priv.h"

#if CONFIG_ENABLE_SD

/* Inside the guard: only the SD part logs, and an unused TAG fails a build without SD. */
static const char TAG[] = "WEBSERVER";

/* ================================================================== */
/*  GET /traffic  -- per-hour traffic statistics + warning list       */
/* ================================================================== */


#endif /* CONFIG_ENABLE_SD -- the cause-code texts below are shared with the
        * always-present map/messages JSON, so they stay outside the guard. */

/* DENM cause code -> plain text. The numbering is the ETSI CauseCodeChoice
 * index, which the ASN.1 keeps equal to the classic cause code by way of
 * `reserved` placeholders. Anything not listed falls back to its number, so
 * an unfamiliar warning is still reported as unknown rather than mislabelled. */
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
    {  96, "Gefährliche Kurve",           "Dangerous curve" },
    {  97, "Kollisionsgefahr",             "Collision risk" },
    {  98, "Rotlichtverstoß",             "Signal violation" },
    {  99, "Gefährliche Situation",       "Dangerous situation" },
    { 100, "Bahnübergang",                "Railway level crossing" },
};

const char *denm_cause_text(uint8_t code)
{
    for (size_t i = 0; i < sizeof(DENM_CAUSES) / sizeof(DENM_CAUSES[0]); i++)
        if (DENM_CAUSES[i].code == code)
            return web_lang() == LANG_DE ? DENM_CAUSES[i].de : DENM_CAUSES[i].en;
    return NULL;
}


/* Sub-cause detail, per ETSI CDD. Each cause has its own enumeration, so the
 * table is keyed by (cause, sub). Only the causes likely to turn up are filled
 * in. Any other sub-cause shows as its bare number instead of a guess. Sub-cause
 * 0 always means "unavailable" and is not shown. */
typedef struct { uint8_t cause, sub; const char *de, *en; } denm_sub_name_t;
static const denm_sub_name_t DENM_SUBCAUSES[] = {
    /* 1 trafficCondition */
    { 1, 1, "mehr Verkehr",                  "increased volume of traffic" },
    { 1, 2, "Stau bildet sich langsam",      "traffic jam slowly increasing" },
    { 1, 3, "Stau bildet sich",              "traffic jam increasing" },
    { 1, 4, "Stau bildet sich schnell",      "traffic jam strongly increasing" },
    { 1, 5, "stehender Verkehr",             "traffic stationary" },
    { 1, 6, "Stau löst sich leicht auf",    "traffic jam slightly decreasing" },
    { 1, 7, "Stau löst sich auf",           "traffic jam decreasing" },
    { 1, 8, "Stau löst sich schnell auf",   "traffic jam strongly decreasing" },
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
    { 3, 1, "Großbaustelle",                "major roadworks" },
    { 3, 2, "Markierungsarbeiten",           "road marking work" },
    { 3, 3, "langsames Arbeitsfahrzeug",     "slow moving road maintenance" },
    { 3, 4, "kurzzeitige Baustelle",         "short-term stationary roadworks" },
    { 3, 5, "Straßenreinigung",             "street cleaning" },
    { 3, 6, "Winterdienst",                  "winter service" },
    /* 26 slowVehicle */
    { 26, 1, "Wartungsfahrzeug",             "maintenance vehicle" },
    { 26, 2, "Gaffer",                       "vehicles slowing to look at accident" },
    { 26, 3, "Schwertransport",              "abnormal load" },
    { 26, 4, "Überbreite",                  "abnormal wide load" },
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
        if (man & D[i].bit)
            o = (size_t)web_addf(out, out_size, (int)o, "%s%s", o ? ", " : "", T(D[i].id));
}

/* MovementPhaseState -> lit lamps of the small signal (.amp in s.css). The position of the lit
 * lamps tells the phase, so nobody has to tell red from green. The grouping is the same as in
 * spatLamp() and spatColor() on /map. */
static const char *spat_phase_lamp(uint8_t phase)
{
    switch (phase)
    {
    case 5: case 6:          return "g";    /* movement allowed */
    case 7: case 8: case 9:  return "y";    /* clearance / caution */
    case 2: case 3:          return "r";    /* stop / remain */
    case 4:                  return "ry";   /* pre-movement: red and amber */
    default:                 return "off";  /* unavailable / dark / stale */
    }
}

/* The same lamps for the start page (web_glance.c), which exists without SD support. */
const char *web_phase_lamp(uint8_t phase) { return spat_phase_lamp(phase); }

#if CONFIG_ENABLE_SD  /* traffic statistics + warning list continue */

/* ETSI station type -> localized road-user category label, from the table of /messages. */
static const char *trf_cat_label(uint8_t st)
{
    return T(web_msgdetail_station_cat(st));
}

/* MovementPhaseState -> short localized phase name (chip hover title).
 * `stale` tells the two dark states apart: phases blanked because we hear nothing
 * (a statement about OUR reception) vs. a light reporting itself off/unknown. */
static const char *spat_phase_name(uint8_t phase, bool stale)
{
    switch (phase)
    {
    case 5: case 6:          return T(S_TRF_PH_GREEN);
    case 4:                  return T(S_TRF_PH_REDAMBER);
    case 7: case 8: case 9:  return T(S_TRF_PH_AMBER);
    case 2: case 3:          return T(S_TRF_PH_RED);
    default:                 return stale ? T(S_TRF_PH_STALE) : T(S_TRF_PH_OTHER);
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

/* Forced inline, so the four sections share traffic_get_handler's frame (5232 bytes, by
 * -fstack-usage). Left to GCC, two went out of line and the deepest path took 10000 of 16384. */
static inline __attribute__((always_inline)) void emit_prio_log(httpd_req_t *req);
static inline __attribute__((always_inline)) void emit_phase_log(httpd_req_t *req,
                                                                 const spatem_intersection_t *ints,
                                                                 int ni);
static inline __attribute__((always_inline)) void emit_traffic_lights(httpd_req_t *req,
                                                                      const spatem_intersection_t *ints,
                                                                      int ni, int notlive);
static inline __attribute__((always_inline)) void emit_warnings(httpd_req_t *req, uint32_t hours,
                                                                const stat_hour_t *rows, int n,
                                                                bool hist_ok);

/* Priority requests and the light's answers, newest first, read back from the card.
 * Own section rather than a column on /transit: an answer belongs to the intersection,
 * and one message can carry several requests. The module is priolog.c. */
#define PRIO_SHOW 120

static void emit_prio_log(httpd_req_t *req)
{
    char head[768];
    HTML_PRINTF(head,
        "<div class='grp' id='prio'><h2 class='ico'>&#128678; %s</h2>"
        "<details class='dtl'><summary>%s</summary><p class='note'>%s</p></details>",
        T(S_PRIO_TITLE), T(S_PRIO_SUM), T(S_PRIO_INTRO));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

    /* Static: only the httpd task renders a page, and 120 rows are 8 KB. */
    static EXT_RAM_BSS_ATTR prio_row_t rows[PRIO_SHOW];
    int n = priolog_read(rows, PRIO_SHOW);
    if (n <= 0)
    {
        char none[448];
        HTML_PRINTF(none, "<p class='note'>%s</p></div>",
                    sd_state(NULL, NULL) == SDST_OK ? T(S_PRIO_NONE) : T(S_PRIO_NOSD));
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
        return;
    }

    char th[512];
    HTML_PRINTF(th,
        "<div class='scroll'><table><thead><tr><th>%s</th><th>%s</th><th>%s</th>"
        "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
        "</tr></thead><tbody>",
        T(S_COL_TIME), T(S_PRIO_KIND), T(S_TRF_INTERSECTION), T(S_PRIO_WHO),
        T(S_PT_LINE), T(S_SREM_REQ_NO), T(S_PRIO_WHAT), T(S_PRIO_WAY));
    httpd_resp_send_chunk(req, th, HTTPD_RESP_USE_STRLEN);

    for (int i = 0; i < n; i++)
    {
        const prio_row_t *r = &rows[i];
        char when[24];
        fmt_when(r->seconds, 0, FMT_SEC, web_lang(), when, sizeof(when));

        /* Who asked: the role when it was sent, then the name, then the number. The
         * number alone is a temporary id and says nothing on its own. */
        /* 200: the longest role (27), two separators (20), a name of 23 quotes escaped to
         * 138 and a ten-digit id. The name comes from the sender, so web_addf, not +=. */
        char who[200], nameesc[ITS_SREM_NAME_LEN * 6], routeesc[ITS_SREM_ROUTE_LEN * 6];
        html_escape(r->name, nameesc, sizeof(nameesc));
        html_escape(r->route, routeesc, sizeof(routeesc));
        int wo = 0;
        if (r->role != PRIO_NO_ROLE)
            wo = web_addf(who, sizeof(who), wo, "%s", T(web_msgdetail_prio_role(r->role)));
        if (nameesc[0])
            wo = web_addf(who, sizeof(who), wo, "%s%s", wo ? " &middot; " : "", nameesc);
        if (r->requester_id)
            wo = web_addf(who, sizeof(who), wo, "%s%lu", wo ? " &middot; " : "",
                          (unsigned long)r->requester_id);
        if (!wo)
            snprintf(who, sizeof(who), "&ndash;");

        /* In and out: the kind of access point decides what the number means, and 0 on a
         * lane or approach means the intersection itself. */
        char way[96];
        int yo = snprintf(way, sizeof(way), "%s", "");
        for (int half = 0; half < 2; half++)
        {
            uint8_t kind = half ? r->out_kind : r->in_kind;
            uint16_t val = half ? r->out_val : r->in_val;
            if (kind == ITS_SREM_AP_NONE)
                continue;
            yo = web_addf(way, sizeof(way), yo, "%s", yo ? " &rarr; " : "");
            if (val == 0 && (kind == ITS_SREM_AP_LANE || kind == ITS_SREM_AP_APPROACH))
                yo = web_addf(way, sizeof(way), yo, "%s", T(S_AP_CENTER));
            else
                yo = web_addf(way, sizeof(way), yo, "%s %u",
                              T(web_msgdetail_prio_access(kind)), (unsigned)val);
        }
        if (!yo)
            snprintf(way, sizeof(way), "&ndash;");

        char isec[24];
        if (r->region)
            snprintf(isec, sizeof(isec), "%u/%u", (unsigned)r->region, (unsigned)r->id);
        else
            snprintf(isec, sizeof(isec), "%u", (unsigned)r->id);

        /* 588 of 768 at worst (who 199, route 95, way 95). */
        char row[768];
        HTML_PRINTF(row,
            "<tr><td>%s</td><td>%s</td><td class='mono'>%s</td><td>%s</td><td>%s</td>"
            "<td>%u</td><td>%s</td><td>%s</td></tr>",
            when, T(r->kind == 9 ? S_PRIO_REQ : S_PRIO_ANS), isec, who,
            routeesc[0] ? routeesc : "&ndash;", (unsigned)r->request_id,
            T(web_msgdetail_prio_code(r->kind, r->code)), way);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

    uint32_t lost = priolog_dropped();
    if (lost)
    {
        /* Rows missing from the table above are a warning (s.css). 129 of 256. */
        char ln[256];
        HTML_PRINTF(ln, "<div class='warn'><p>%lu %s</p></div>", (unsigned long)lost,
                    T(S_PRIO_LOST));
        httpd_resp_send_chunk(req, ln, HTTPD_RESP_USE_STRLEN);
    }
    /* The button only comes with rows. The script checks r.ok because the page needs no
     * password but the POST does, and a reload after a 401 would pass for a done delete. A 403
     * of web_csrf.c names its cause, so it is shown. ?lang= asks for the page's language,
     * because a bare POST would answer in German. */
    web_send_parts(req, "<p class='btnrow'><button class='dngr' onclick=\"if(confirm('",
                   T(S_PRIO_CLEAR_CONFIRM), "'))fetch('/traffic/prio/clear?lang='+"
                   "document.documentElement.lang,"
                   "{method:'POST'}).then(function(r){if(r.ok)location.reload();"
                   "else if(r.status==403)r.text().then(alert);});\">",
                   T(S_PRIO_CLEAR), "</button></p>", NULL);
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
}

/* Phases that ended, newest first, read back from the card. The module is spatlog.c, and it
 * only ever gets phases whose length was really measured. 120 phases are read. Coupled groups
 * share a row, so the table can have fewer rows for the same time. */
#define PHL_SHOW 120
/* At most this many groups in one row: 8 numbers of 3 digits fit sgs[48]. */
#define PHL_MERGE_MAX 8

static void emit_phase_log(httpd_req_t *req, const spatem_intersection_t *ints, int ni)
{
    /* 878 of 1024 bytes. The folded explanation is the long part. */
    char phhead[1024];
    HTML_PRINTF(phhead,
        "<div class='grp' id='phases'><h2 class='ico'>&#9201; %s</h2>"
        "<details class='dtl'><summary>%s</summary><p class='note'>%s</p></details>",
        T(S_PHL_TITLE), T(S_PRIO_SUM), T(S_PHL_INTRO));
    httpd_resp_send_chunk(req, phhead, HTTPD_RESP_USE_STRLEN);

    /* Static: only the httpd task renders a page, and 120 rows are 1.9 KB. */
    static EXT_RAM_BSS_ATTR spat_row_t rows[PHL_SHOW];
    int n = spatlog_read(rows, PHL_SHOW);
    if (n <= 0)
    {
        char phnone[448];
        HTML_PRINTF(phnone, "<p class='note'>%s</p></div>",
                    sd_state(NULL, NULL) == SDST_OK ? T(S_PHL_NONE) : T(S_PRIO_NOSD));
        httpd_resp_send_chunk(req, phnone, HTTPD_RESP_USE_STRLEN);
        return;
    }

    /* The row's key first (time, signal group), then the answer, the crossing last and
     * without wrapcell (.scroll td is nowrap): one line per row, and on the phone a phase is
     * never shown without its group, as groups interleave in the log. 159 of 448. */
    char phth[448];
    HTML_PRINTF(phth,
        "<div class='scroll'><table><thead><tr><th>%s</th><th>%s</th><th>%s</th>"
        "<th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
        T(S_COL_TIME), T(S_TRF_SG), T(S_PHL_PHASE), T(S_PHL_DUR),
        T(S_PHL_NEXT), T(S_TRF_INTERSECTION));
    httpd_resp_send_chunk(req, phth, HTTPD_RESP_USE_STRLEN);

    /* Names come from the sender (MAPEM): escaped once here, not per row. An intersection
     * that left the snapshot keeps its number. */
    static EXT_RAM_BSS_ATTR char nm[SPATEM_MAX_INT][ITS_MAP_NAME_LEN * 6];
    for (int k = 0; k < ni; k++)
        html_escape(ints[k].name, nm[k], sizeof(nm[k]));

    for (int i = 0; i < n; )
    {
        const spat_row_t *r = &rows[i];
        char when[24];
        fmt_when(r->seconds, 0, FMT_SEC, web_lang(), when, sizeof(when));

        char isec[24];
        if (r->region)
            snprintf(isec, sizeof(isec), "%u/%u", (unsigned)r->region, (unsigned)r->id);
        else
            snprintf(isec, sizeof(isec), "%u", (unsigned)r->id);

        /* The seconds are the point here, so FMT_DUR_PHASE keeps them up to 2 h. A light can
         * also hold red for hours, and such phases read in hours and minutes. */
        char phdur[FMT_DUR_MAX];
        fmt_dur(r->dur_sec, FMT_DUR_PHASE, phdur, sizeof(phdur));

        /* Groups the controller switches as one end their phase in the same second: one row
         * "1, 2". Next-door rows only, with the same intersection, phase, length and next phase. */
        uint8_t grp[PHL_MERGE_MAX];
        int ng = 0;
        grp[ng++] = r->sg;
        int j = i + 1;
        while (j < n && j - i < PHL_MERGE_MAX && rows[j].seconds == r->seconds &&
               rows[j].region == r->region && rows[j].id == r->id &&
               rows[j].phase == r->phase && rows[j].next == r->next &&
               rows[j].dur_sec == r->dur_sec)
            grp[ng++] = rows[j++].sg;
        /* Ascending, as the help text shows "1, 2": the log order inside one second is
         * arbitrary, and spatlog_read returns newest first. */
        for (int a = 1; a < ng; a++)
            for (int b = a; b > 0 && grp[b - 1] > grp[b]; b--)
            {
                uint8_t t = grp[b];
                grp[b] = grp[b - 1];
                grp[b - 1] = t;
            }
        char sgs[48];
        int so = web_addf(sgs, sizeof(sgs), 0, "%u", (unsigned)grp[0]);
        for (int a = 1; a < ng; a++)
            so = web_addf(sgs, sizeof(sgs), so, ", %u", (unsigned)grp[a]);

        /* The name from the handler's one snapshot. Static like phrow. 291 of 320 at worst
         * (escaped name 239, isec 23). */
        int k = -1;
        for (int q = 0; q < ni && k < 0; q++)
            if (ints[q].region == r->region && ints[q].id == r->id && nm[q][0])
                k = q;
        static EXT_RAM_BSS_ATTR char iscell[320];
        if (k >= 0)
            HTML_PRINTF(iscell, "%s <small class='mono'>%s</small>", nm[k], isec);
        else
            HTML_PRINTF(iscell, "<span class='mono'>%s</span>", isec);

        /* stale=false: a recorded phase is a fact of the past, never our own silence. */
        /* Static: only the httpd task renders /traffic, like rows[], and it keeps
         * traffic_get_handler's frame small. 599 of 768 at worst (iscell 319, 8 merged groups in
         * sgs 47, phdur 15). */
        static EXT_RAM_BSS_ATTR char phrow[768];
        HTML_PRINTF(phrow,
            "<tr><td>%s</td><td>%s</td><td><i class='amp %s'><b></b><b></b><b></b></i> %s</td>"
            "<td>%s</td><td><i class='amp %s'><b></b><b></b><b></b></i> %s</td>"
            "<td>%s</td></tr>",
            when, sgs,
            spat_phase_lamp(r->phase), spat_phase_name(r->phase, false), phdur,
            spat_phase_lamp(r->next), spat_phase_name(r->next, false),
            iscell);
        httpd_resp_send_chunk(req, phrow, HTTPD_RESP_USE_STRLEN);
        /* Past every row merged into this one. */
        i = j;
    }
    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

    uint32_t lost = spatlog_dropped();
    if (lost)
    {
        /* Rows missing from the table above are a warning (s.css). 129 of 256. */
        char phln[256];
        HTML_PRINTF(phln, "<div class='warn'><p>%lu %s</p></div>", (unsigned long)lost,
                    T(S_PRIO_LOST));
        httpd_resp_send_chunk(req, phln, HTTPD_RESP_USE_STRLEN);
    }
    /* Only with rows, r.ok, the 403 and its ?lang= as in emit_prio_log. */
    web_send_parts(req, "<p class='btnrow'><button class='dngr' onclick=\"if(confirm('",
                   T(S_PHL_CLEAR_CONFIRM), "'))fetch('/traffic/phases/clear?lang='+"
                   "document.documentElement.lang,"
                   "{method:'POST'}).then(function(r){if(r.ok)location.reload();"
                   "else if(r.status==403)r.text().then(alert);});\">",
                   T(S_PHL_CLEAR), "</button></p>", NULL);
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
}

/* Live traffic-light snapshot: one block per intersection, a small three-lamp signal per
 * signal group. Emitted inside #trf-body, so it refreshes with the page. */
/* Without any SPATEM it prints a short note instead. `notlive`: 1 for the 7 and 30 day
 * views, 2 for the 24 h view with the refresh set to 0, else 0. */
static void emit_traffic_lights(httpd_req_t *req, const spatem_intersection_t *ints, int ni,
                                int notlive)
{
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

    /* A view that does not poll says so right under "(live)". The note is a state, not help,
     * so it has no hlp class. */
    if (notlive == 1)
        web_send_parts(req, "<p class='note'>", T(S_TRF_NOTLIVE), "</p>", NULL);
    else if (notlive == 2)
        web_send_parts(req, "<p class='note'>", T(S_TRF_NOTLIVE_OFF), "</p>", NULL);

    /* Explanation + lamp legend, so the bare signal-group numbers below aren't cryptic. All dark
     * is listed too, with both its meanings. The lamps go dark after SPAT_STALE_SEC without
     * SPATEM, so it is a regular sight. */
    /* Each lamp and its word in one span.lg, so a line never ends between them (s.css). 1070 of
     * 1280 bytes. */
    char legend[1280];
    HTML_PRINTF(legend,
        "<p class='note hlp'>%s"
        "<span class='lg'><i class='amp g'><b></b><b></b><b></b></i>%s</span>"
        "<span class='lg'><i class='amp ry'><b></b><b></b><b></b></i>%s</span>"
        "<span class='lg'><i class='amp y'><b></b><b></b><b></b></i>%s</span>"
        "<span class='lg'><i class='amp r'><b></b><b></b><b></b></i>%s</span>"
        "<span class='lg'><i class='amp off'><b></b><b></b><b></b></i>%s / %s</span></p>",
        T(S_TRF_LIGHTS_INTRO), T(S_TRF_PH_GREEN), T(S_TRF_PH_REDAMBER),
        T(S_TRF_PH_AMBER), T(S_TRF_PH_RED), T(S_TRF_PH_OTHER), T(S_TRF_PH_STALE));
    httpd_resp_send_chunk(req, legend, HTTPD_RESP_USE_STRLEN);

    uint32_t now = (uint32_t)time(NULL);
    for (int i = 0; i < ni; i++)
    {
        const spatem_intersection_t *e = &ints[i];
        /* phase_seen, not last_seen: this number is shown next to the phase lamps and
         * must say how old THEY are, not when a MAPEM last arrived. An entry
         * seeded by a MAPEM alone has no phases yet (phase_seen 0 = never). It
         * falls back to last_seen, or its age would stay at 0 = "just now". */
        uint32_t seen = e->phase_seen ? e->phase_seen : e->last_seen;
        unsigned long age = (seen && now > seen) ? (unsigned long)(now - seen) : 0;
        /* Formatted like every other span on the page, because raw seconds become
         * unreadable after a night without reception. */
        char agebuf[FMT_AGE_MAX];
        fmt_age((uint32_t)age, FMT_DUR_ONE, web_lang(), agebuf, sizeof(agebuf));

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
                "<small>(%u/%u &middot; Rev %u &middot; %s)</small></div>",
                T(S_TRF_INTERSECTION), nameesc, (unsigned)e->region,
                (unsigned)e->id, (unsigned)e->revision, agebuf);
        else
            snprintf(head, sizeof(head),
                "<div class='isec'><div class='t'>%s %u/%u "
                "<small>(Rev %u &middot; %s)</small></div>",
                T(S_TRF_INTERSECTION), (unsigned)e->region, (unsigned)e->id,
                (unsigned)e->revision, agebuf);
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

        /* Controller mode / fault line. 256 covers every flag name set at
         * once (the German strings are the longer ones, ~186 bytes). */
        bool st_alert = false;
        char stbuf[256];
        if (spat_status_text(e->status, &st_alert, stbuf, sizeof(stbuf)))
        {
            /* A fault or an off/flashing mode is a verdict in red, from the shared token like the
             * other reds of s.css. Other modes are muted. 307 of 448. */
            char stline[448];
            snprintf(stline, sizeof(stline),
                "<p class='m' style='color:%s'>%s%s</p>",
                st_alert ? "var(--alarm)" : "var(--mute)", st_alert ? "&#9888; " : "", stbuf);
            httpd_resp_send_chunk(req, stline, HTTPD_RESP_USE_STRLEN);
        }

        /* Speed limit, minimum speed, reference lane width and refPoint altitude, when the MAPEM
         * carried them. */
        if (e->speed_max_kmh || e->speed_min_kmh || e->lane_width_cm || e->has_alt)
        {
            /* 126 of 192 at worst (590 km/h twice, 327,67 m, -1000,0 m) in EN, 125 in DE. */
            char geo[192], alt[FMT_ALT_MAX];
            const char *sep = "";
            int at = web_addf(geo, sizeof(geo), 0, "<p class='m'>");
            if (e->speed_max_kmh)
            {
                at = web_addf(geo, sizeof(geo), at, "%s %u km/h", T(S_TRF_SPEEDLIMIT),
                              (unsigned)e->speed_max_kmh);
                sep = " &middot; ";
            }
            if (e->speed_min_kmh)
            {
                at = web_addf(geo, sizeof(geo), at, "%s%s %u km/h", sep, T(S_TRF_SPEEDMIN),
                              (unsigned)e->speed_min_kmh);
                sep = " &middot; ";
            }
            if (e->lane_width_cm)
            {
                at = web_addf(geo, sizeof(geo), at, "%s%s %u%s%02u m", sep, T(S_TRF_LANEWIDTH),
                              (unsigned)(e->lane_width_cm / 100),
                              web_lang() == LANG_DE ? "," : ".",
                              (unsigned)(e->lane_width_cm % 100));
                sep = " &middot; ";
            }
            if (e->has_alt)
            {
                fmt_alt_cm(e->alt_cm, web_lang(), alt, sizeof alt);
                at = web_addf(geo, sizeof(geo), at, "%s%s %s", sep, T(S_TRF_ALT), alt);
            }
            web_addf(geo, sizeof(geo), at, "</p>");
            httpd_resp_send_chunk(req, geo, HTTPD_RESP_USE_STRLEN);
        }

        /* Read before the chips, not after: the running-phase clock below sits
         * on the chip, and the tallies are the only place that start is kept. */
        static EXT_RAM_BSS_ATTR spatem_phases_t phbuf;
        const spatem_phases_t *ph = spatem_phases(e->region, e->id, &phbuf) ? &phbuf : NULL;

        /* Why the lamps went dark: spatem_snapshot() blanks the phases of an
         * intersection silent for SPAT_STALE_SEC, which spatem.c sets to
         * SPAT_GAP_SEC. The newest of the per-group stamps stands in for that
         * instant on the monotonic clock, which no NTP step can fake. It only
         * lags once the 32 rows are full, and then the lamps go dark early. */
        bool ph_stale = false;
        if (ph)
        {
            uint32_t newest = 0;
            for (uint8_t r = 0; r < ph->n_rows; r++)
                if (ph->last_mono[r] > newest)
                    newest = ph->last_mono[r];
            ph_stale = newest && ph->now_mono > newest &&
                       ph->now_mono - newest > SPAT_GAP_SEC;
        }

        /* Opened here, not in the header: the two lines above are paragraphs
         * and would otherwise sit inside the chip row. */
        httpd_resp_send_chunk(req, "<div class='chips'>", HTTPD_RESP_USE_STRLEN);

        for (int s = 0; s < e->n; s++)
        {
            /* minEndTime is the EARLIEST the phase may end, not a promise --
             * the leading sign says so instead of reading like a countdown. */
            /* Only up to ten minutes. Further out the value is of no use to the viewer, and at a
             * light with long phases it would just stand still. The text under the legend names
             * this limit. */
            char cd[64] = "";
            if (e->change_at[s] > now && e->change_at[s] - now <= 600)
            {
                /* A space before it, so the chip may break there. fmt_dur keeps "7 min 0 s"
                 * whole. */
                char left[FMT_DUR_MAX];
                fmt_dur(e->change_at[s] - now, FMT_DUR_PHASE, left, sizeof(left));
                snprintf(cd, sizeof(cd), " <small>&ge;%s</small>", left);
            }

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

            /* Rows are keyed by group id, while e->sg[] is in message order. Indexing
             * the tallies by s would print one group's clock under another's lamp. */
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
                        char rd[FMT_DUR_MAX];
                        fmt_dur((uint32_t)(ph->now_mono - ph->since[r]), FMT_DUR_TWO, rd,
                                sizeof(rd));
                        snprintf(run, sizeof(run),
                                 " <small>%s %s</small>",
                                 T(S_TRF_PH_SINCE), rd);
                    }
                    break;
                }

            /* 449 of 768 bytes at worst (longest phase name, label 159, countdown 63, clock
             * 127). */
            char chip[768];
            HTML_PRINTF(chip,
                "<span class='chip' title='%s'><i class='amp %s'><b></b><b></b><b></b></i>"
                "%s%s%s</span>",
                spat_phase_name(e->phase[s], ph_stale), spat_phase_lamp(e->phase[s]),
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
            char dnote[448];
            HTML_PRINTF(dnote, "<p class='note hlp'>%s</p>", T(S_TRF_PH_TABLE_NOTE));
            httpd_resp_send_chunk(req, dnote, HTTPD_RESP_USE_STRLEN);
            /* A state, not help: the averages start over with every restart (spatem.h), so no
             * hlp. */
            web_send_parts(req, "<p class='note'>", T(S_TRF_PH_BOOT), "</p>", NULL);
            char dh[384];
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
                /* Static like drow below: only the httpd task renders /traffic. 52 of 64 (two
                 * durations of 15). */
                static EXT_RAM_BSS_ATTR char cell[4][64];
                for (int c = 0; c < 4; c++)
                {
                    if (ph->cnt[r][c])
                    {
                        char avg[FMT_DUR_MAX], mx[FMT_DUR_MAX];
                        fmt_dur(ph->secs[r][c] / ph->cnt[r][c], FMT_DUR_PHASE, avg, sizeof(avg));
                        fmt_dur(ph->max[r][c], FMT_DUR_PHASE, mx, sizeof(mx));
                        snprintf(cell[c], sizeof(cell[c]), "%s <small>(max %s)</small>", avg, mx);
                    }
                    else
                        snprintf(cell[c], sizeof(cell[c]), "&ndash;");
                }
                /* 0 would read as "never green", but the group may be green right now: only a
                 * finished phase is counted. So it shows &ndash; like the durations, not 0. */
                char cyc[16];
                if (ph->cnt[r][0])
                    snprintf(cyc, sizeof(cyc), "%lu", (unsigned long)ph->cnt[r][0]);
                else
                    snprintf(cyc, sizeof(cyc), "&ndash;");
                /* The direction words of the chips above, number first like the phase history:
                 * "3 &middot; Fussgaenger". Without a MAPEM only the number. 83 of 96. */
                char mvd[64];
                char sgc[96];
                spat_movement_text(e, ph->sg[r], mvd, sizeof(mvd));
                if (mvd[0])
                    HTML_PRINTF(sgc, "%u &middot; %s", (unsigned)ph->sg[r], mvd);
                else
                    HTML_PRINTF(sgc, "%u", (unsigned)ph->sg[r]);
                /* Static: only the httpd task renders /traffic, and it keeps traffic_get_handler's
                 * frame small. 425 of 448 (sgc 95, four cells of 63, cyc 15). */
                static EXT_RAM_BSS_ATTR char drow[448];
                HTML_PRINTF(drow,
                            "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                            "<td>%s</td></tr>",
                            sgc, cell[0], cell[1], cell[2], cell[3], cyc);
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

/* A bare 5 s swap would send scrolled tables back left and close open folds. This script keeps
 * both and the reading place, and it waits while the reader acts. It has its own activity
 * detector, because itsLive.idle() would count the script's own scrolls. */
static const char TRF_KEEP_JS[] =
    "<script>(function(){var la=0,own=0,pend=null;"
    "function hit(e){if(e.type==='scroll'&&Date.now()-own<200)return;la=Date.now();}"
    "['pointerdown','keydown','wheel','touchstart','scroll'].forEach(function(t){"
    "document.addEventListener(t,hit,{capture:true,passive:true});});"
    "function each(b,f){b.querySelectorAll('.grp[id]').forEach(function(g){"
    "g.querySelectorAll('.scroll').forEach(function(x,i){f('s'+g.id+i,x,'scrollLeft');});"
    "g.querySelectorAll('details').forEach(function(x,i){f('d'+g.id+i,x,'open');});});}"
    "function put(nb){var b=document.getElementById('trf-body'),m={},a=null,y=0;"
    "b.querySelectorAll('.grp[id]').forEach(function(g){var r=g.getBoundingClientRect();"
    "if(!a&&r.bottom>0){a=g.id;y=r.top;}});"
    "each(b,function(k,x,p){m[k]=x[p];});own=Date.now();b.innerHTML=nb.innerHTML;"
    "each(b,function(k,x,p){if(k in m)x[p]=m[k];});"
    "var g=a&&document.getElementById(a);if(g)scrollBy(0,g.getBoundingClientRect().top-y);}"
    "window.trfSwap=function(nb){pend=nb;if(Date.now()-la>=4000){pend=null;put(nb);}};"
    "setInterval(function(){if(pend&&Date.now()-la>=4000){var n=pend;pend=null;put(n);}},1000);"
    "})();</script>";

/* Closes #trf-body, then the script. It fetches the page again and swaps only #trf-body, without
 * a reload, so the background animation runs on. TRF_KEEP_JS keeps folds and place, and the
 * pause switch in the header stops the polling. */
static void traffic_refresh_footer(httpd_req_t *req, uint32_t ri)
{
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    if (ri > 0 && ri < 0xFFFFFFFF)
    {
        httpd_resp_send_chunk(req, TRF_KEEP_JS, HTTPD_RESP_USE_STRLEN);
        /* Static and HTML_PRINTF: a cut script silently stops the swap, and static takes 1 KB
         * off the httpd stack under traffic_get_handler's frame. 657 of 1024 (ri at 10 digits). */
        static EXT_RAM_BSS_ATTR char script[1024];
        /* itsSeen/itsWatch/itsLive come from the header (send_page_header_pausable, same ri
         * condition). itsSeen(d) copies #probs before the swap, so a held swap still feeds it. */
        HTML_PRINTF(script,
            /* The poll asks in the page's language: a fetch() is no page load, so without lang=
             * it would come back German. */
            "<script>(function(){var ri=%lu,t=null,U=new URL(location.href);U.hash='';"
            "if(!U.searchParams.has('lang'))"
            "U.searchParams.set('lang',document.documentElement.lang);"
            /* A hidden tab costs the device no SD reads. */
            "function tick(){if(document.hidden)return;"
            "fetch(U,{cache:'no-store'}).then(function(r){return r.text();})"
            ".then(function(h){var d=new DOMParser().parseFromString(h,'text/html');itsSeen(d);"
            "var nb=d.getElementById('trf-body');if(nb)trfSwap(nb);}).catch(function(){});}"
            "function run(){clearInterval(t);t=null;if(!itsLive.paused())t=setInterval(tick,ri*1000);}"
            /* Stale after two missed polls plus 3 s. The 1 lets the pause switch stop it. */
            "window.addEventListener('load',function(){itsWatch(ri*2000+3000,1);run();"
            "itsLive.on(function(p){if(!p)tick();run();});});})();</script>",
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
    /* Always with the id: a caller without one must not memo 0 for the next row. */
    uint32_t id = 0;
    int r = inventory_lookup_mac(mac, out, cap, &id);
    if (id_out) *id_out = id;
    /* A busy list is not an answer -- memoing it would let one timeout decide
     * every remaining row of the page. */
    if (r >= 0 && *n < RELAY_MEMO_N)
    {
        memcpy(m[*n].mac, mac, 6);
        snprintf(m[*n].name, sizeof(m[*n].name), "%s", out);
        m[*n].id = id;
        m[*n].hit = (int8_t)r;
        (*n)++;
    }
    return r;
}

/* a_fwd's rule for an address the row did not keep: a station the list names with an id other
 * than the warning's only passed it on, even as the GN source of a packet it re-sent. */
static bool relay_other_id(relay_memo_t *m, int *n, const uint8_t *mac, uint32_t sid)
{
    char nm[INV_NAME_LEN];
    uint32_t id = 0;
    relay_lookup(m, n, mac, nm, sizeof(nm), &id);
    return id && id != sid;
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
            "<tr><td>%s</td><td>%lu%s%02lu <small>(%lu / %lu)</small>"
            "<div class='bar' style='width:%u%%'></div></td></tr>",
            labels[b], (unsigned long)(v / 100),
            web_lang() == LANG_DE ? "," : ".", (unsigned long)(v % 100),
            (unsigned long)ev[b], (unsigned long)obs[b], pct);
        httpd_resp_send_chunk(req, r, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
}

/* "zuletzt empfangen vor 3 min" or "last received 3 min ago": the largest whole unit only.
 * The exact times are in the first column. */
static void trf_last_rx_text(const event_rec_t *e, uint32_t now, char *out, size_t cap)
{
    char a[FMT_AGE_MAX];
    fmt_age(now > e->last_seen ? now - e->last_seen : 0, FMT_DUR_ONE, web_lang(), a, sizeof(a));
    snprintf(out, cap, "%s %s", T(S_WARN_LAST_RX), a);
}

/* The state as a word, coloured only in addition, then when it ends or ended. A time on the
 * same day as now shows the clock alone, any other with the date in front. */
static void trf_state_cell(const event_rec_t *e, event_state_t st, uint32_t now,
                           char *out, size_t cap)
{
    char t[24], rx[96];
    uint32_t until = events_valid_until(e);
    switch (st)
    {
    case EVENT_STATE_ACTIVE:
        /* A warning, not a fault: orange on every page, like the start tile and the map. */
        fmt_when(until, now, FMT_SEC | FMT_SAMEDAY, web_lang(), t, sizeof(t));
        snprintf(out, cap, "<span class='v-warn'>%s</span><div class='sub'>%s %s</div>",
                 T(S_WARN_ACTIVE), T(S_WARN_VALID_UNTIL), t);
        break;
    case EVENT_STATE_EXPIRED:
        /* Without readable times the end is unknown, so the last reception stands in for it. */
        if (!until)
        {
            trf_last_rx_text(e, now, rx, sizeof(rx));
            snprintf(out, cap, "%s<div class='sub'>%s</div>", T(S_WARN_EXPIRED), rx);
            break;
        }
        fmt_when(until, now, FMT_SEC | FMT_SAMEDAY, web_lang(), t, sizeof(t));
        snprintf(out, cap, "%s<div class='sub'>%s %s</div>",
                 T(S_WARN_EXPIRED), T(S_SND_SINCE), t);
        break;
    case EVENT_STATE_CANCELLED:
        snprintf(out, cap, "<span class='ok'>%s</span>", T(S_DENM_CANCEL));
        break;
    case EVENT_STATE_NEGATED:
        snprintf(out, cap, "<span class='ok'>%s</span>", T(S_DENM_NEGATE));
        break;
    default:
        /* Without a set clock no span can be measured, so say why instead. */
        if (now < EVENTS_CLOCK_MIN)
            snprintf(out, cap, "%s<div class='sub'>%s</div>",
                     T(S_UNKNOWN), T(S_CLOCK_UNSET));
        else
        {
            trf_last_rx_text(e, now, rx, sizeof(rx));
            snprintf(out, cap, "%s<div class='sub'>%s</div>", T(S_UNKNOWN), rx);
        }
        break;
    }
}

/* GeoBroadcast area in words. The header carries a circle's radius as distance a, so a
 * and b count from the centre and a rectangle or ellipse spans twice each. */
static void trf_area_text(const event_rec_t *e, char *out, size_t cap)
{
    out[0] = '\0';
    if (e->area_shape == ITS_GN_AREA_CIRCLE)
        snprintf(out, cap, "<div class='sub'>%s: %s %u m</div>",
                 T(S_AREA_TARGET), T(S_AREA_CIRCLE), (unsigned)e->area_a_m);
    else if (e->area_shape == ITS_GN_AREA_RECT || e->area_shape == ITS_GN_AREA_ELLIPSE)
        snprintf(out, cap, "<div class='sub'>%s: %s %lu &times; %lu m, %u&deg;</div>",
                 T(S_AREA_TARGET),
                 e->area_shape == ITS_GN_AREA_RECT ? T(S_AREA_RECT) : T(S_AREA_ELLIPSE),
                 2ul * e->area_a_m, 2ul * e->area_b_m, (unsigned)e->area_angle_deg);
}

/* Warnings (DENM) of the chosen window, active ones first, then newest first. Needs no
 * hourly row, so it also shows right after the first flash. */
static void emit_warnings(httpd_req_t *req, uint32_t hours, const stat_hour_t *rows, int n,
                          bool hist_ok)
{
    /* The window line stays visible: the list covers only this window. 120 of 192 bytes. */
    char etitle[192];
    HTML_PRINTF(etitle,
        "<div class='grp' id='denm'><h2 class='ico'>&#9888;&#65039; %s</h2>"
        "<p class='note'>%s: %s</p>",
        T(S_EVT_TITLE), T(S_TRF_WINDOW),
        hours == 720 ? T(S_TRF_W_30D) : hours == 168 ? T(S_TRF_W_7D) : T(S_TRF_W_24H));
    httpd_resp_send_chunk(req, etitle, HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR event_rec_t evs[256];
    bool ev_ok = true, ev_capped = false;
    int en = events_read(hours, evs, 256, &ev_ok, &ev_capped);
    if (en == 0)
    {
        /* "None" is only true if the stored events were actually read. A busy card is a
         * warning, an empty window is information. 141 of 256 (the warning). */
        char none[256];
        if (ev_ok)
            snprintf(none, sizeof(none), "<p class='note'>%s</p>", T(S_EVT_NONE));
        else
            snprintf(none, sizeof(none), "<div class='warn'><p>%s</p></div>", T(S_TRF_BUSY));
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        /* Caveat first, then the table -- a busy card or a full array means the
         * rows below are a selection, not the window. */
        if (!ev_ok || ev_capped)
        {
            /* A busy card loses rows, which is a warning. The cap only keeps the newest, which
             * is information. 141 of 256 (the warning). */
            char note[256];
            if (!ev_ok)
                snprintf(note, sizeof(note), "<div class='warn'><p>%s</p></div>", T(S_TRF_BUSY));
            else
                snprintf(note, sizeof(note), "<p class='note'>%s</p>", T(S_EVT_CAPPED));
            httpd_resp_send_chunk(req, note, HTTPD_RESP_USE_STRLEN);
        }
        /* On a phone each row becomes a card (s.css .wcard). The cards place the cells by
         * position, so the column order below and in erow is fixed. */
        httpd_resp_send_chunk(req, "<div class='scroll'><table class='wcard'><thead><tr><th>",
                              HTTPD_RESP_USE_STRLEN);
        /* The warning second, so start and warning stand side by side on a phone. The signal
         * level is headed as on /messages and /senders: the unit in the head, bare numbers in the
         * cells. 99 of 256 (the longer word of each column, German 98). */
        char eh[256];
        snprintf(eh, sizeof(eh),
                 "%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
                 T(S_COL_TIME), T(S_EVT_WARNING), T(S_SYS_COL_STATE), T(S_COL_SENDER),
                 T(S_COL_RSSI));
        httpd_resp_send_chunk(req, eh, HTTPD_RESP_USE_STRLEN);
        relay_memo_t memo[RELAY_MEMO_N];
        int memo_n = 0;
        bool any_relay = false, any_term = false, any_denm = false;
        /* Active warnings first. The array keeps its newest-first order, because
         * the profile below takes its last row as the oldest. */
        uint32_t ev_now = (uint32_t)time(NULL);
        static EXT_RAM_BSS_ATTR uint16_t order[256];
        int on = 0;
        for (int pass = 0; pass < 2; pass++)
            for (int k = 0; k < en; k++)
                if ((events_state(&evs[k], ev_now) == EVENT_STATE_ACTIVE) == (pass == 0))
                    order[on++] = (uint16_t)k;
        for (int oi = 0; oi < on; oi++)
        {
            int i = order[oi];
            char when[24];
            fmt_when(evs[i].seconds, 0, FMT_SEC, web_lang(), when, sizeof(when));
            /* One row is one event: its end and the number of broadcasts on a small second line,
             * so start and warning stay side by side on a phone. The end shows its date only
             * when it fell on another day than the start. 87 of 96. */
            char wsub[96] = "";
            if (evs[i].count > 1 && evs[i].last_seen > evs[i].seconds)
            {
                char until[FMT_WHEN_MAX];
                fmt_when(evs[i].last_seen, evs[i].seconds, FMT_SEC | FMT_SAMEDAY, web_lang(),
                         until, sizeof(until));
                snprintf(wsub, sizeof(wsub),
                         "<div class='sub'>%s %s <small>(%u&times;)</small></div>",
                         T(S_EVT_UNTIL), until, (unsigned)evs[i].count);
            }
            /* The class says WHAT warned and the id says WHO. Both share one cell, so the table
             * needs no extra column on a phone. 138 of 160 (longest class, id, both remarks). */
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
            /* A second address shows a relay, and so does the hop count of the frames: a warning
             * heard only through one forwarder has one address. */
            bool relayed = evs[i].n_macs > 1 || evs[i].gn_hops_max > 0;
            if (relayed)
            {
                size_t o = strlen(sender);
                snprintf(sender + o, sizeof(sender) - o, " <small>(%s)</small>", T(S_EVT_RELAYED));
                any_relay = true;
            }

            /* Without a kept forwarder or originator, as in rows of older firmware, the sender
             * list tells which address relayed, not the order heard. The RSU is often heard
             * first. */
            static const uint8_t ZERO6[6];
            const uint8_t *omac = evs[i].mac_a;
            /* The row keeps the address of its first direct frame. That is a forwarder's when it
             * also relayed, or when the ids (2+ addresses) or the GN source (3+) say so. Without a
             * trusted one the GN source decides, and after it the ids. */
            bool o_known = memcmp(evs[i].orig_mac, ZERO6, 6) != 0 &&
                           memcmp(evs[i].orig_mac, evs[i].relay_mac, 6) != 0;
            char relay[352] = "";
            /* Every frame with a readable hop count came through a forwarder, all from one address.
             * That address is the forwarder's, and only the GN header can name the originator. */
            if (evs[i].n_macs == 1 && evs[i].gn_mhl && evs[i].gn_hops_min > 0)
            {
                char nm_a[INV_NAME_LEN] = "";
                char nmesc[INV_NAME_LEN * 6] = "";
                relay_lookup(memo, &memo_n, evs[i].mac_a, nm_a, sizeof(nm_a), NULL);
                if (nm_a[0])
                    html_escape(nm_a, nmesc, sizeof(nmesc));
                /* 272 of 352 (escaped name 239). */
                snprintf(relay, sizeof(relay), "<div class='sub'>%s %s</div>", T(S_EVT_RELAY_VIA),
                         nmesc[0] ? nmesc : T(S_EVT_RELAY_UNKNOWN));
            }
            else if (evs[i].n_macs > 1)
            {
                char nm_a[INV_NAME_LEN] = "", nm_b[INV_NAME_LEN] = "";
                char nmesc[INV_NAME_LEN * 6] = "";
                uint32_t id_a = 0, id_b = 0;
                relay_lookup(memo, &memo_n, evs[i].mac_a, nm_a, sizeof(nm_a), &id_a);
                relay_lookup(memo, &memo_n, evs[i].mac_b, nm_b, sizeof(nm_b), &id_b);
                /* The originator has the message's own station id. A listed station with
                 * another id only forwarded it. An empty name cannot tell the two apart. */
                bool b_orig = id_b && id_b == evs[i].sender_id;
                bool a_fwd = id_a && evs[i].sender_id && id_a != evs[i].sender_id;
                /* A kept originator listed with another id, or while another address is listed with
                 * the warning's id, only forwarded (0 hops: re-sent or RHL kept). */
                if (o_known && ((a_fwd && !memcmp(evs[i].orig_mac, evs[i].mac_a, 6)) ||
                                (id_b && id_b != evs[i].sender_id &&
                                 !memcmp(evs[i].orig_mac, evs[i].mac_b, 6)) ||
                                (b_orig && memcmp(evs[i].orig_mac, evs[i].mac_b, 6)) ||
                                (id_a && id_a == evs[i].sender_id &&
                                 memcmp(evs[i].orig_mac, evs[i].mac_a, 6))))
                    o_known = false;
                const char *nm = nm_b;
                unsigned via = evs[i].count_b;
                if (b_orig || a_fwd)
                {
                    nm = nm_a;
                    via = evs[i].count > evs[i].count_b
                            ? (unsigned)(evs[i].count - evs[i].count_b) : 0u;
                    /* With a third address the originator may be one that was not kept. */
                    if (b_orig || evs[i].n_macs == 2)
                        omac = evs[i].mac_b;
                    else
                        omac = ZERO6;
                }
                /* The swap above left no originator: the kept one may be a forwarder that kept
                 * the RHL, so the GN source outranks it. That holds unless the GN source is a kept
                 * address or is listed with another id, as then it re-sent the warning. */
                if (o_known && omac == ZERO6 && memcmp(evs[i].gn_src_mid, ZERO6, 6) &&
                    memcmp(evs[i].gn_src_mid, evs[i].orig_mac, 6) &&
                    !relay_other_id(memo, &memo_n, evs[i].gn_src_mid, evs[i].sender_id) &&
                    memcmp(evs[i].gn_src_mid, evs[i].relay_mac, 6))
                    o_known = false;
                /* The kept forwarder when it is mac_a or mac_b (the level cell may name it), else
                 * the address that is not the kept originator. Without either the swap above
                 * stands. */
                bool r_set = memcmp(evs[i].relay_mac, ZERO6, 6) != 0;
                int fw = r_set && !memcmp(evs[i].relay_mac, evs[i].mac_a, 6) ? 1
                       : r_set && !memcmp(evs[i].relay_mac, evs[i].mac_b, 6) ? 2
                       : o_known ? (memcmp(evs[i].mac_a, evs[i].orig_mac, 6) ? 1 : 2) : 0;
                if (fw == 1)
                {
                    nm = nm_a;
                    via = evs[i].count > evs[i].count_b
                            ? (unsigned)(evs[i].count - evs[i].count_b) : 0u;
                }
                else if (fw == 2)
                {
                    nm = nm_b;
                    via = evs[i].count_b;
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
                char gap[FMT_DUR_MAX];
                fmt_dur(evs[i].b_after_s, FMT_DUR_PHASE, gap, sizeof(gap));
                /* 336 of 352 (escaped name 239, gap 15, share 31). */
                snprintf(relay, sizeof(relay),
                         "<div class='sub'>%s %s &middot; %s %s%s</div>",
                         T(S_EVT_RELAY_VIA), nmesc[0] ? nmesc : T(S_EVT_RELAY_UNKNOWN),
                         T(S_EVT_RELAY_AFTER), gap, share);
            }
            /* Heard only relayed, every address is a forwarder's, however many there are. */
            if (evs[i].gn_mhl && evs[i].gn_hops_min > 0)
                omac = ZERO6;
            /* The kept originator beats every guess above. Else the GN source address, which
             * forwarders keep, unless a forwarder (relay_mac, a distrusted orig_mac) sent it. */
            if (o_known)
                omac = evs[i].orig_mac;
            else if (memcmp(evs[i].gn_src_mid, ZERO6, 6) &&
                     memcmp(evs[i].gn_src_mid, evs[i].relay_mac, 6) &&
                     memcmp(evs[i].gn_src_mid, evs[i].orig_mac, 6))
                omac = evs[i].gn_src_mid;
            /* Never the kept forwarder the rules above picked, unless it also came direct first
             * (orig_mac == relay_mac). Then the rules stand. */
            else if (!memcmp(omac, evs[i].relay_mac, 6) &&
                     memcmp(evs[i].relay_mac, evs[i].orig_mac, 6))
                omac = ZERO6;

            /* The originator's radio address under type and number, as on /messages and /senders.
             * All zero without a trusted orig_mac or usable GN source: only forwarders, a
             * third address or none, or the rules picked the kept forwarder (above). 45 of 48. */
            static EXT_RAM_BSS_ATTR char smac[48];
            smac[0] = '\0';
            if (memcmp(omac, ZERO6, 6))
                snprintf(smac, sizeof(smac),
                         "<div class='sub mono'>%02x:%02x:%02x:%02x:%02x:%02x</div>",
                         omac[0], omac[1], omac[2], omac[3], omac[4], omac[5]);

            /* How the stretch travelled (web_gn.h), under the relay line: German at its widest
             * 130 of text and 23 of markup, 153 of 192. Static like dden. */
            static EXT_RAM_BSS_ATTR char gnsub[192];
            static const char gopen[] = "<div class='sub'>", gclose[] = "</div>";
            size_t go = sizeof(gopen) - 1;
            size_t gl = web_gn_event(&evs[i], web_lang(), gnsub + go,
                                     sizeof(gnsub) - go - (sizeof(gclose) - 1));
            if (gl)
            {
                memcpy(gnsub, gopen, go);
                memcpy(gnsub + go + gl, gclose, sizeof(gclose));
            }
            else
                gnsub[0] = '\0';

            /* A span, not one value: with 60 repeats the last frame says nothing. Only frames
             * straight from the originator count. A warning heard only relayed shows the first
             * forwarder's span with its name.
             * 276 of 320 (German, 39 quotes escape to 234; 281 at nmesc_r's 239). */
            static EXT_RAM_BSS_ATTR char lvl[320];
            int8_t lo = evs[i].rssi_min, hi = evs[i].rssi_max;
            /* All kept addresses are the distrusted orig_mac or the forwarder (a third may be
             * direct): the direct span holds only forwarders' frames, so it counts as none. */
            const uint8_t *om = evs[i].orig_mac, *rm = evs[i].relay_mac;
            if (!o_known && memcmp(om, ZERO6, 6) && memcmp(rm, ZERO6, 6) && evs[i].n_macs <= 2 &&
                (!memcmp(evs[i].mac_a, om, 6) || !memcmp(evs[i].mac_a, rm, 6)) &&
                (evs[i].n_macs < 2 || !memcmp(evs[i].mac_b, om, 6) || !memcmp(evs[i].mac_b, rm, 6)))
                lo = hi = 0;
            /* A mixed row keeps its direct span. A kept originator without a reading keeps the
             * dash, as a forwarder's level there would read as the originator's. */
            bool via = !lo && !hi && !o_known && (evs[i].relay_rssi_min || evs[i].relay_rssi_max);
            int lv = 0;
            if (via)
            {
                lo = evs[i].relay_rssi_min;
                hi = evs[i].relay_rssi_max;
                char nm_r[INV_NAME_LEN] = "";
                char nmesc_r[INV_NAME_LEN * 6] = "";
                relay_lookup(memo, &memo_n, evs[i].relay_mac, nm_r, sizeof(nm_r), NULL);
                if (nm_r[0])
                    html_escape(nm_r, nmesc_r, sizeof(nmesc_r));
                lv = web_addf(lvl, sizeof(lvl), 0, "<small>%s %s</small> ", T(S_EVT_RELAY_VIA),
                              nmesc_r[0] ? nmesc_r : T(S_EVT_RELAY_UNKNOWN));
            }
            if (!lo && !hi)
                web_addf(lvl, sizeof(lvl), lv, "&ndash;");
            else if (lo == hi)
                web_addf(lvl, sizeof(lvl), lv, "%d", lo);
            else
                web_addf(lvl, sizeof(lvl), lv, "%d&hellip;%d", lo, hi);

            /* Link to the position when both coordinates are set. Not every
             * stored event has one. */
            char poslink[128] = "";
            if (evs[i].lat_e7 && evs[i].lon_e7)
                snprintf(poslink, sizeof(poslink),
                         " <a class='pin' href='/map?lang=%s&amp;lat=%ld&amp;lon=%ld' title='%s'>"
                         "&#128205;</a>",
                         web_lang() == LANG_EN ? "en" : "de",
                         (long)evs[i].lat_e7, (long)evs[i].lon_e7, T(S_EVT_SHOWPOS));

            event_state_t est = events_state(&evs[i], ev_now);
            if (est == EVENT_STATE_CANCELLED || est == EVENT_STATE_NEGATED)
                any_term = true;
            /* 128 of 256 at worst (expired without times, rx[96] full), 92 while active. The
             * area below takes 94 of 160. */
            char state[256];
            trf_state_cell(&evs[i], est, ev_now, state, sizeof(state));
            char area[160];
            trf_area_text(&evs[i], area, sizeof(area));

            /* The rest of the DENM in the words of /messages: the row rebuilt into a msg_extra_t.
             * The originator is shown only when it is another kind of station than the one in the
             * sender column. */
            static EXT_RAM_BSS_ATTR msg_extra_t dx;
            msg_extra_from_event(&dx, &evs[i]);
            if (web_msgdetail_station_cat(dx.denm_station_type) ==
                web_msgdetail_station_cat(evs[i].station_type))
                dx.denm_station_type = ITS_DENM_STATION_NONE;
            /* 435 of 488 (German; English 414): the twelve fields at their widest as the decoder
             * and events_read pass them. The div around it: 23 + 487 = 510 of 512. */
            static EXT_RAM_BSS_ATTR char dden[488];
            static EXT_RAM_BSS_ATTR char dsub[512];
            size_t dl = web_msgdetail_append_content(&dx, web_lang(), dden, 0, sizeof(dden));
            dsub[0] = '\0';
            if (dl)
            {
                snprintf(dsub, sizeof(dsub), "<div class='sub'>%s</div>", dden);
                any_denm = true;
            }

            /* 92 bytes of markup + when[24] + poslink[128] + wsub[96] + state[256] + sender[160] +
             * smac[48] + relay[352] + gnsub[192] + lvl[320] + cause[160] + area[160] +
             * dsub[512]: 2488 of 2560. Static like dden: only the httpd task renders /traffic. */
            static EXT_RAM_BSS_ATTR char erow[2560];
            /* Causes the table does not name show their raw code instead of a
             * guessed description. */
            char cause[160];
            const char *ct = denm_cause_text(evs[i].cause);
            const char *st2 = denm_sub_text(evs[i].cause, evs[i].subcause);
            if (ct && st2)
                snprintf(cause, sizeof(cause), "%s <small>(%s)</small>", ct, st2);
            else if (ct && evs[i].subcause)
            {
                /* The wording with its number from the table: 17 of 24 (%u at 10 digits). */
                char det[24];
                snprintf(det, sizeof(det), T(S_EVT_SUBCODE), (unsigned)evs[i].subcause);
                snprintf(cause, sizeof(cause), "%s <small>(%s)</small>", ct, det);
            }
            else if (ct)
                /* Sub-cause 0 is the sender saying "unavailable" -- say so,
                 * otherwise it reads as a missing feature of this page. */
                snprintf(cause, sizeof(cause), "%s <small>(%s)</small>", ct, T(S_EVT_NODETAIL));
            else if (evs[i].cause == 0)
                snprintf(cause, sizeof(cause), "%s", T(S_EVT_WARNING));
            else
                snprintf(cause, sizeof(cause), T(S_EVT_CAUSE_CODE), (unsigned)evs[i].cause);
            /* The warning cell wraps (wrapcell) instead of running off the right edge. */
            snprintf(erow, sizeof(erow),
                "<tr><td>%s%s%s</td><td class='wrapcell'>&#9888; %s%s%s</td><td>%s</td>"
                "<td>%s%s%s%s</td><td class='mono'>%s</td></tr>",
                when, poslink, wsub, cause, area, dsub, state, sender, smac, relay, gnsub, lvl);
            httpd_resp_send_chunk(req, erow, HTTPD_RESP_USE_STRLEN);
        }
        httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
        /* Like the relay hint: only when a row has the line it explains. */
        if (any_denm)
            web_send_parts(req, "<p class='note hlp'>", T(S_EVT_DETAIL_HINT), "</p>", NULL);
        /* Only when a row actually carries the marker -- everywhere else the
         * paragraph would explain something the reader cannot see. */
        if (any_relay)
        {
            web_send_parts(req, "<p class='note hlp'>", T(S_EVT_RELAY_HINT), "</p>", NULL);
        }
        if (any_term)
        {
            char th[384];
            HTML_PRINTF(th, "<p class='note hlp'>%s</p>", T(S_WARN_TERM_HINT));
            httpd_resp_send_chunk(req, th, HTTPD_RESP_USE_STRLEN);
        }

        /* Windows past 24 h only: in one day each hour occurs once. A partial
         * hourly read would leave the denominator short and overstate every bar. */
        /* ev_ok too: hist_ok covers only the hourly read. Without the stored
         * warnings the numerator is a handful of open RAM events. */
        /* n > 0: without an hourly row every bucket is unobserved and both tables
         * would stay empty. */
        if (hours > 24 && hist_ok && ev_ok && n > 0)
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
            HTML_PRINTF(pfh, "<p class='note hlp'>%s</p>", T(S_EVT_PROFILE_HINT));
            httpd_resp_send_chunk(req, pfh, HTTPD_RESP_USE_STRLEN);
        }
    }
    /* closes the warnings .grp (both branches above end here) */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
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
    /* 1: the 7 and 30 day views, 2: the 24 h view with the refresh set to 0. */
    int notlive = hours != 24 ? 1 : (ri == 0 || ri == 0xFFFFFFFF) ? 2 : 0;

    static EXT_RAM_BSS_ATTR stat_hour_t rows[720];
    bool hist_ok = true;
    int n = tstat_read(hours, rows, 720, &hist_ok);   /* oldest-first */

    /* Connection watcher and pause switch only where the page polls: same condition as the swap
     * script in traffic_refresh_footer, so the 7 d and 30 d views (ri 0) get neither. */
    if (ri > 0 && ri < 0xFFFFFFFF)
        send_page_header_pausable(req, T(S_TITLE_TRAFFIC), ri);
    else
        send_page_header(req, T(S_TITLE_TRAFFIC));

    const char *lc = web_lang() == LANG_DE ? "de" : "en";
    web_send_parts(req, "<p class='note hlp'>", T(S_TRF_INTRO), "</p>", NULL);
    /* Plain links, so the page works without JS and the 5 s poll stays on 24 h only. The chosen
     * view is filled. 298 of 448. */
    char win[448];
    HTML_PRINTF(win,
        "<p class='tools'><span class='cap'>%s</span>"
        " <a class='sgb' href='/traffic?hours=24&lang=%s'%s>%s</a>"
        " <a class='sgb' href='/traffic?hours=168&lang=%s'%s>%s</a>"
        " <a class='sgb' href='/traffic?hours=720&lang=%s'%s>%s</a></p>",
        T(S_TRF_WINDOW),
        lc, hours == 24 ? " aria-current='page'" : "", T(S_TRF_W_24H),
        lc, hours == 168 ? " aria-current='page'" : "", T(S_TRF_W_7D),
        lc, hours == 720 ? " aria-current='page'" : "", T(S_TRF_W_30D));
    httpd_resp_send_chunk(req, win, HTTPD_RESP_USE_STRLEN);

    /* Outside #trf-body on purpose: inside, the 5 s swap would rebuild it. Every section is
     * always emitted, so every link has a target. */
    /* 338 of 448 bytes. */
    char jump[448];
    HTML_PRINTF(jump,
        "<p class='jump'>%s: <a href='#lights'>%s</a> &middot; <a href='#denm'>%s</a>"
        " &middot; <a href='#prio'>%s</a> &middot; <a href='#phases'>%s</a>"
        " &middot; <a href='#inf'>%s</a> &middot; <a href='#stats'>%s</a></p>",
        T(S_TRF_JUMP), T(S_TRF_LIGHTS), T(S_EVT_TITLE), T(S_PRIO_TITLE), T(S_PHL_TITLE),
        T(S_INF_TITLE), T(S_TRF_STATS));
    httpd_resp_send_chunk(req, jump, HTTPD_RESP_USE_STRLEN);

    /* Everything below the intro/selector is the auto-refreshed fragment. */
    httpd_resp_send_chunk(req, "<div id='trf-body'>", HTTPD_RESP_USE_STRLEN);
    if (!hist_ok)
    {
        /* Inside the fragment: the page swaps only this part on refresh, so
         * the warning must appear and disappear with the data it describes. 141 of 384. */
        char warn[384];
        HTML_PRINTF(warn, "<div class='warn'><p>%s</p></div>", T(S_TRF_BUSY));
        httpd_resp_send_chunk(req, warn, HTTPD_RESP_USE_STRLEN);
    }

    /* One snapshot for the live lights and the names in the phase history, never a lookup under
     * the SPATEM lock per row. PSRAM like web_glance.c: 3.2 KB less internal RAM. */
    static EXT_RAM_BSS_ATTR spatem_intersection_t ints[SPATEM_MAX_INT];
    int ni = spatem_snapshot(ints, SPATEM_MAX_INT);

    /* Live lights first, then the warnings, active ones on top: both say what holds now. Neither
     * needs an hourly row, so both show right after the first flash too. */
    emit_traffic_lights(req, ints, ni, notlive);
    emit_warnings(req, hours, rows, n, hist_ok);
    emit_prio_log(req);
    emit_phase_log(req, ints, ni);
    web_infolog_emit(req);

    if (n == 0)
    {
        /* No hourly row yet is a normal start, not a fault: information, visible with the
         * explanations off. 200 of 384. */
        char nd[384];
        snprintf(nd, sizeof(nd),
                 "<div class='grp' id='stats'><h2 class='ico'>&#128202; %s</h2>"
                 "<p class='note'>%s</p></div>",
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
        /* Both sides must cover the SAME hours: `nc` counts the whole window,
         * so only rows from from_h up to now_h-1 may be subtracted from it. */
        uint32_t have = 0;
        for (int k = 0; k < nc; k++)
            if (rows[k].hour >= from_h && rows[k].hour < now_h) have++;
        silent = span > have ? span - have : 0;
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
        /* Clamped: snprintf returns the length it WANTED, so an unchecked sum would step
         * past the buffer. */
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
        /* In pieces, so no fixed buffer can cut this long text as it grows. */
        web_send_parts(req, "<p class='note hlp'>", T(S_TRF_AVAIL_HINT), "</p>", NULL);
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
    /* 225 of 448 bytes. */
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
        uint32_t t0 = rows[i].hour * 3600u;
        if (daily)
            fmt_day(t0, web_lang(), when, sizeof(when));
        else
            fmt_when(t0, 0, 0, web_lang(), when, sizeof(when));

        while (i >= 0)
        {
            if (trf_bucket_key(&rows[i], daily) != key)
                break;
            acc.total += rows[i].total;
            for (int c = 0; c < STAT_NCAT; c++)
            {
                acc.cat[c]     += rows[i].cat[c];
                /* Summing hours would count a traffic light once per hour.
                 * The busiest hour is a safe lower bound for the day. */
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
            /* 148 of 224 at worst (all four, English). One entry is at most 45, and the guard
             * leaves 56. */
            char cats[224];
            size_t so = 0;
            unsigned ncat = 0;
            for (unsigned k = 0; k < SPCATS_N && so + 56 < sizeof(cats); k++)
            {
                int c = spcats[k];
                if (!acc.sp_cnt[c]) continue;
                ncat++;
                so = (size_t)web_addf(cats, sizeof(cats), (int)so, "%s%s %lu / %lu",
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
        /* Without a measurement a dash, not "0 / 0", which would read as if the vehicles had
         * stood still. The class columns follow the same rule. */
        char hspd[32];
        if (hsp_cnt)
            snprintf(hspd, sizeof(hspd), "%lu / %lu",
                     (unsigned long)(hsp_sum / hsp_cnt), (unsigned long)hsp_max);
        else
            snprintf(hspd, sizeof(hspd), "&ndash;");
        char row[768];
        snprintf(row, sizeof(row),
            "<tr><td>%s</td>"
            "<td%s>%lu<div class='bar' style='width:%u%%'></div></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
            "<td>%s%s</td></tr>",
            when, rowcls, (unsigned long)acc.total, pct,
            cls[STAT_CAT_CAR], cls[STAT_CAT_BUS], cls[STAT_CAT_TRUCK],
            cls[STAT_CAT_TWOWHEEL], cls[STAT_CAT_PED], cls[STAT_CAT_RSU],
            cls[STAT_CAT_OTHER],
            hspd, spd2);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);

    char snote[1024];
    /* The identity note is a paragraph of its own: glued to the one before, the daily view ran
     * to about 350 visible characters, over the 240 a paragraph may have. 870 of 1024. */
    HTML_PRINTF(snote, "<p class='note hlp'>%s%s%s<br><br>%s</p></div>", T(S_TRF_SENDERS_NOTE),
                daily ? " " : "", daily ? T(S_TRF_SENDERS_DAY) : "", T(S_TRF_IDENT_NOTE));
    httpd_resp_send_chunk(req, snote, HTTPD_RESP_USE_STRLEN);

    traffic_refresh_footer(req, ri);
    return ESP_OK;
}

/* Destroys a recording on the card, so it needs the same web password as /senders/clear.
 * Without the 401 of send_auth_required the fetch() would just hang. */
esp_err_t traffic_prio_clear_post_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    priolog_clear();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

esp_err_t traffic_phases_clear_post_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    spatlog_clear();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* A warning that has ended stays in the reply this long, marked by its state. */
#define TRF_AREAS_ENDED_SEC 3600

static const char *trf_state_key(event_state_t st)
{
    switch (st)
    {
    case EVENT_STATE_ACTIVE:    return "active";
    case EVENT_STATE_EXPIRED:   return "expired";
    case EVENT_STATE_CANCELLED: return "cancelled";
    case EVENT_STATE_NEGATED:   return "negated";
    default:                    return "unknown";
    }
}

esp_err_t traffic_areas_json_handler(httpd_req_t *req)
{
    static EXT_RAM_BSS_ATTR event_rec_t cur[EVENTS_CURRENT_MAX];
    bool capped = false;
    int n = events_current(cur, EVENTS_CURRENT_MAX, &capped);
    if (n < 0)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "busy");
        return ESP_OK;
    }
    uint32_t now = (uint32_t)time(NULL);
    bool clock_ok = now >= EVENTS_CLOCK_MIN;

    /* Active first, each group by last reception, newest first. */
    uint8_t order[EVENTS_CURRENT_MAX];
    event_state_t st[EVENTS_CURRENT_MAX];
    int on = 0;
    for (int i = 0; i < n; i++)
    {
        st[i] = events_state(&cur[i], now);
        if (cur[i].area_shape == ITS_GN_AREA_NONE)
            continue;
        /* Without a set clock nothing can be judged as long over, so all of it stays. */
        if (st[i] != EVENT_STATE_ACTIVE && clock_ok)
        {
            uint32_t until = events_valid_until(&cur[i]);
            uint32_t ended = st[i] == EVENT_STATE_EXPIRED && until ? until : cur[i].last_seen;
            if (now > ended && now - ended > TRF_AREAS_ENDED_SEC)
                continue;
        }
        int j = on++;
        while (j > 0)
        {
            const event_rec_t *p = &cur[order[j - 1]];
            bool pa = st[order[j - 1]] == EVENT_STATE_ACTIVE, ia = st[i] == EVENT_STATE_ACTIVE;
            if (pa > ia || (pa == ia && p->last_seen >= cur[i].last_seen))
                break;
            order[j] = order[j - 1];
            j--;
        }
        order[j] = (uint8_t)i;
    }

    httpd_resp_set_type(req, "application/json");
    /* Same reasoning as /markers.json: a map served by another receiver reads
     * this cross-origin. Read-only, no credential involved. */
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");

    char head[64];
    if (clock_ok)
        snprintf(head, sizeof(head), "{\"now\":%lu,\"capped\":%s,\"areas\":[",
                 (unsigned long)now, capped ? "true" : "false");
    else
        snprintf(head, sizeof(head), "{\"now\":null,\"capped\":%s,\"areas\":[",
                 capped ? "true" : "false");
    if (httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN) != ESP_OK)
        return ESP_FAIL;

    static const char *const SHAPE[] = { "", "circle", "rect", "ellipse" };
    for (int k = 0; k < on; k++)
    {
        const event_rec_t *e = &cur[order[k]];
        uint32_t u = events_valid_until(e);
        char until[12] = "null";
        if (u)
            snprintf(until, sizeof(until), "%lu", (unsigned long)u);
        char ent[320];
        snprintf(ent, sizeof(ent),
                 "%s{\"station\":%lu,\"seq\":%u,\"cause\":%u,\"sub\":%u,\"state\":\"%s\","
                 "\"shape\":\"%s\",\"lat_e7\":%ld,\"lon_e7\":%ld,\"a\":%u,\"b\":%u,"
                 "\"angle\":%u,\"until\":%s,\"last\":%lu}",
                 k ? "," : "", (unsigned long)e->action_station, (unsigned)e->action_seq,
                 (unsigned)e->cause, (unsigned)e->subcause, trf_state_key(st[order[k]]),
                 SHAPE[e->area_shape], (long)e->area_lat_e7, (long)e->area_lon_e7,
                 (unsigned)e->area_a_m, (unsigned)e->area_b_m, (unsigned)e->area_angle_deg,
                 until, (unsigned long)e->last_seen);
        if (httpd_resp_send_chunk(req, ent, HTTPD_RESP_USE_STRLEN) != ESP_OK)
            return ESP_FAIL;
    }
    httpd_resp_send_chunk(req, "]}", HTTPD_RESP_USE_STRLEN);
    return httpd_resp_send_chunk(req, NULL, 0);
}

#endif /* CONFIG_ENABLE_SD */
