#include "sdkconfig.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "esp_attr.h"
#include "esp_http_server.h"
#include "esp_log.h"

#include "cpm_geo.h"
#include "cpm_store.h"
#include "events_log.h"
#include "its_cpm.h"
#include "web_cpm.h"
#include "webserver_priv.h"

static const char TAG[] = "WEBSERVER";

#define N_OF(t) (sizeof(t) / sizeof((t)[0]))

/* ================================================================== */
/*  GET /cpm.json -- what the CPMs of the last 3 s say, placed        */
/* ================================================================== */

/* The answer goes out in chunks of this buffer. Before each entity CPM_JSON_RESERVE bytes are
 * free, more than the widest: sender head 115 B, object row 149 B, area 370 B, each column at
 * its longest, value or null. A full store (8 senders of 64 objects and
 * 16 areas) went out as 123685 B in 34 chunks, the largest 3725 B. */
#define CPM_JSON_CAP      4096
#define CPM_JSON_RESERVE  512

/* Bit 4 of a sender's "x": an area could not be placed (cpm_geo_place). Bits 1 and 2 are the
 * store's CPM_STORE_X_*. */
#define CPM_JSON_X_UNPLACED  4u

/* httpd task only, like every page buffer: the answer, one sender copied out of the store, and
 * its areas as placed. 4096 + 6848 + 16 x 156 = 13440 B of PSRAM (riscv32-esp-elf-gcc 15.2). */
static EXT_RAM_BSS_ATTR char s_json[CPM_JSON_CAP];
static EXT_RAM_BSS_ATTR cpm_store_sender_t s_snap;

typedef struct {
    cpm_geo_area_t g;
    const cpm_store_area_t *e;       /* the stored area it was placed from, in s_snap */
} placed_t;
static EXT_RAM_BSS_ATTR placed_t s_placed[CPM_STORE_SENS + CPM_STORE_REGS];

typedef struct {
    httpd_req_t *req;
    size_t len;                      /* bytes in s_json */
    size_t mark;                     /* where the entity being written began */
    bool ok;                         /* the entity fitted so far */
    bool gone;                       /* a chunk failed: the browser left */
} jw_t;

static void jw_flush(jw_t *w)
{
    if (w->len && !w->gone && httpd_resp_send_chunk(w->req, s_json, w->len) != ESP_OK)
        w->gone = true;
    w->len = 0;
}

/* Each entity starts with the reserve free, so it never has to be split by a cut. */
static void jw_begin(jw_t *w)
{
    if (CPM_JSON_CAP - w->len < CPM_JSON_RESERVE)
        jw_flush(w);
    w->mark = w->len;
    w->ok = true;
}

/* Plain vsnprintf with the return checked: a piece that does not fit is not kept at all. */
static __attribute__((format(printf, 2, 3))) void jw_put(jw_t *w, const char *fmt, ...)
{
    if (!w->ok)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(s_json + w->len, CPM_JSON_CAP - w->len, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= CPM_JSON_CAP - w->len)
        w->ok = false;
    else
        w->len += (size_t)n;
}

/* A number after `pre`, or null for one that was not sent: the one place that writes null. In
 * 32-bit pieces, without a 64-bit printf: at the end of TimestampIts "t" reaches 5470961706, a
 * region's generation 5470961706103. */
static void jw_num(jw_t *w, const char *pre, bool has, int64_t v)
{
    uint64_t u = v < 0 ? 0u - (uint64_t)v : (uint64_t)v;
    if (!has)
        jw_put(w, "%snull", pre);
    else if (u < 1000000000u)
        jw_put(w, "%s%s%lu", pre, v < 0 ? "-" : "", (unsigned long)u);
    else
        jw_put(w, "%s%s%lu%09lu", pre, v < 0 ? "-" : "", (unsigned long)(u / 1000000000u),
               (unsigned long)(u % 1000000000u));
}

/* An entity that did not fit is taken back whole, so the JSON never holds half a value. The
 * reserve lies above the widest, so this only logs a mistake in these numbers. */
static bool jw_end(jw_t *w)
{
    if (w->ok)
        return true;
    ESP_LOGE(TAG, "/cpm.json: an entity past %u bytes left out", (unsigned)CPM_JSON_RESERVE);
    w->len = w->mark;
    return false;
}

/* Milliseconds from `t` to `now`; 0 for a note the sniffer made after `now` was read. */
static int64_t since(int64_t now, int64_t t)
{
    return now > t ? now - t : 0;
}

/* The frame an area counts from (TS 103 324 7.1.6, 7.1.7): a sensor shape lies around the
 * sender's latest position, turned with it on a vehicle; a region around its own CPM's
 * position. False for a sensor shape of a sender whose kind is not known. */
static bool area_frame(const cpm_store_sender_t *s, const cpm_store_area_t *e, cpm_geo_frame_t *f)
{
    bool sensor = e->a.src == ITS_CPM_AREA_SENSOR;
    if (sensor && s->kind == CPM_STORE_KIND_UNKNOWN)
        return false;
    f->ref_lat_e7 = sensor ? s->ref_lat_e7 : e->ref_lat_e7;
    f->ref_lon_e7 = sensor ? s->ref_lon_e7 : e->ref_lon_e7;
    f->body = sensor && s->kind == CPM_STORE_KIND_VEHICLE;
    f->heading_ddeg = s->has_heading ? s->heading_ddeg : CPM_GEO_NONE;
    f->edition = s->edition;
    f->edition_sure = s->edition != 0;
    return true;
}

/* One object row. Its column order is promised in the README, so new columns only go at the
 * end. The position counts from the reference position of the CPM that carried the object.
 * Its offset and that CPM's time follow at the end, so the popup counts from them, not from
 * the latest. */
static bool send_object(jw_t *w, const cpm_store_obj_t *e, int64_t now, bool first)
{
    const its_cpm_obj_t *o = &e->o;
    cpm_geo_motion_t m;
    cpm_geo_motion(o, &m);
    int32_t lat, lon;
    its_cpm_to_wgs84(e->ref_lat_e7, e->ref_lon_e7, o->x_cm, o->y_cm, &lat, &lon);
    jw_begin(w);
    jw_put(w, "%s[%u,%ld,%ld,%u,%u,%u", first ? "" : ",", (unsigned)o->id, (long)lat, (long)lon,
           (unsigned)o->cat, (unsigned)o->cls,
           (unsigned)(o->cls == ITS_CPM_CLS_GROUP ? o->group_size : o->sub));
    jw_num(w, ",", o->conf != 0, o->conf);
    jw_num(w, ",", m.speed_cms != CPM_GEO_NONE, m.speed_cms);
    jw_num(w, ",", m.course_ddeg != CPM_GEO_NONE, m.course_ddeg);
    jw_num(w, ",", m.orient_ddeg != CPM_GEO_NONE, m.orient_ddeg);
    jw_num(w, ",", m.len_dm != 0, m.len_dm);
    jw_num(w, ",", m.wid_dm != 0, m.wid_dm);
    jw_num(w, ",", m.hgt_dm != 0, m.hgt_dm);
    jw_num(w, ",", (o->flags & ITS_CPM_OF_Z) != 0, o->z_cm);
    jw_num(w, ",", m.age_ms != CPM_GEO_NONE, m.age_ms);
    jw_num(w, ",", o->quality != ITS_CPM_NO_QUALITY, o->quality);
    jw_num(w, ",", (o->flags & ITS_CPM_OF_LANE) != 0, o->lane);
    jw_num(w, ",", (o->flags & ITS_CPM_OF_CONN) != 0, o->conn);
    jw_num(w, ",", m.llp_dm != CPM_GEO_NONE, m.llp_dm);
    jw_num(w, ",", m.has_accel, m.accel_dms2);
    jw_num(w, ",", true, since(now, e->seen_ms));
    jw_put(w, ",%u", (unsigned)m.fl);
    jw_num(w, ",", true, o->x_cm);
    jw_num(w, ",", true, o->y_cm);
    jw_num(w, ",", e->ref_ms != 0, (int64_t)(events_its_to_unix_ms(e->ref_ms) / 1000u));
    jw_put(w, "]");
    return jw_end(w);
}

/* One area row, as cpm_geo_place() placed it. Its column order is promised in the README. A
 * region ends with its generation, the referenceTime all of the sender's regions share
 * (reg_gen), and in column 16 its place in it (segment x 256 + index in that segment's list),
 * so a map merging two receivers keeps regions of different messages apart and draws one once. */
static bool send_area(jw_t *w, const placed_t *p, uint64_t reg_gen, int64_t now, bool first)
{
    const cpm_geo_area_t *g = &p->g;
    const its_cpm_area_t *a = &p->e->a;
    bool sensor = g->src == ITS_CPM_AREA_SENSOR;
    unsigned n = g->n < ITS_CPM_AREA_PTS ? g->n : ITS_CPM_AREA_PTS;
    jw_begin(w);
    jw_put(w, "%s[%u,%u", first ? "" : ",", (unsigned)g->src, (unsigned)g->kind);
    jw_num(w, ",", sensor, a->sensor_id);
    jw_num(w, ",", sensor, a->sensor_type);
    jw_num(w, ",", a->conf != 0, a->conf);
    jw_put(w, ",%ld,%ld", (long)g->lat_e7, (long)g->lon_e7);
    jw_num(w, ",", g->a_dm != CPM_GEO_NONE, g->a_dm);
    jw_num(w, ",", g->b_dm != CPM_GEO_NONE, g->b_dm);
    jw_num(w, ",", g->rot_ddeg != CPM_GEO_NONE, g->rot_ddeg);
    jw_num(w, ",", g->from_ddeg != CPM_GEO_NONE, g->from_ddeg);
    jw_num(w, ",", g->to_ddeg != CPM_GEO_NONE, g->to_ddeg);
    jw_num(w, ",", true, g->flags);
    jw_num(w, ",", true, since(now, p->e->seen_ms));
    jw_put(w, ",[");
    for (unsigned i = 0; i < n; i++)
    {
        if (g->kind == ITS_CPM_SHAPE_POLYGON)
            jw_put(w, "%s[%ld,%ld]", i ? "," : "", (long)g->u.pt[i].e_cm, (long)g->u.pt[i].n_cm);
        else if (g->kind == ITS_CPM_SHAPE_RADIALS)
            jw_put(w, "%s[%u,%u,%u]", i ? "," : "", (unsigned)g->u.rs[i].range_dm,
                   (unsigned)g->u.rs[i].from, (unsigned)g->u.rs[i].to);
    }
    jw_put(w, "]");
    jw_num(w, ",", !sensor && reg_gen != 0, (int64_t)events_its_to_unix_ms(reg_gen));
    jw_num(w, ",", !sensor, (int64_t)p->e->seg * 256 + p->e->idx);
    jw_put(w, "]");
    return jw_end(w);
}

/* One sender. Its areas are placed first, because bit 4 of "x" (an area not placeable) goes
 * into the head, which is written before them. False when the head did not fit, and the
 * sender is left out. */
static bool send_sender(jw_t *w, const cpm_store_sender_t *s, int64_t now, bool first)
{
    unsigned ns = s->n_sens < CPM_STORE_SENS ? s->n_sens : CPM_STORE_SENS;
    unsigned nr = s->n_reg < CPM_STORE_REGS ? s->n_reg : CPM_STORE_REGS;
    unsigned no = s->n_obj < CPM_STORE_OBJS ? s->n_obj : CPM_STORE_OBJS;
    unsigned np = 0;
    bool miss = false;
    for (unsigned i = 0; i < ns + nr; i++)
    {
        const cpm_store_area_t *e = i < ns ? &s->sens[i] : &s->reg[i - ns];
        cpm_geo_frame_t f;
        if (area_frame(s, e, &f) && cpm_geo_place(&e->a, &f, &s_placed[np].g))
            s_placed[np++].e = e;
        else
            miss = true;
    }
    jw_begin(w);
    jw_put(w, "%s{\"i\":%lu,\"k\":%u", first ? "" : ",", (unsigned long)s->station_id,
           (unsigned)s->kind);
    jw_num(w, ",\"age\":", true, since(now, s->last_ms));
    jw_put(w, ",\"a\":%ld,\"o\":%ld", (long)s->ref_lat_e7, (long)s->ref_lon_e7);
    jw_num(w, ",\"t\":", s->ref_ms != 0, (int64_t)(events_its_to_unix_ms(s->ref_ms) / 1000u));
    jw_num(w, ",\"h\":", s->has_heading, s->heading_ddeg);
    /* Angles count by the proven edition, else by V3, the one the CPM ASN.1 imports. */
    jw_put(w, ",\"ed\":%u,\"es\":%u,\"x\":%u,\"ob\":[", s->edition == ITS_CPM_CDD_V4 ? 4u : 3u,
           s->edition ? 1u : 0u, (unsigned)(s->x | (miss ? CPM_JSON_X_UNPLACED : 0u)));
    if (!jw_end(w))
        return false;
    bool fr = true;
    for (unsigned i = 0; i < no && !w->gone; i++)
        if (send_object(w, &s->obj[i], now, fr))
            fr = false;
    jw_begin(w);
    jw_put(w, "],\"ar\":[");
    jw_end(w);
    fr = true;
    for (unsigned i = 0; i < np && !w->gone; i++)
        if (send_area(w, &s_placed[i], s->reg_gen, now, fr))
            fr = false;
    jw_begin(w);
    jw_put(w, "]}");
    jw_end(w);
    return true;
}

/* {"s":[senders],"c":0|1}; c is 1 for 3 s after a sender was pushed out of the full store.
 * The data is held in RAM only, so the route needs no SD card. */
esp_err_t web_cpm_json_get_handler(httpd_req_t *req)
{
    httpd_resp_set_type(req, "application/json");
    /* Other receivers' maps read this, like /markers.json: numbers only, no credential. */
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    jw_t w = { .req = req };
    int64_t now = cpm_store_now_ms();
    bool first = true;
    jw_begin(&w);
    jw_put(&w, "{\"s\":[");
    jw_end(&w);
    for (unsigned i = 0; i < CPM_STORE_SENDERS && !w.gone; i++)
        if (cpm_store_copy(i, now, &s_snap) && send_sender(&w, &s_snap, now, first))
            first = false;
    jw_begin(&w);
    jw_put(&w, "],\"c\":%u}", cpm_store_dropped(now) ? 1u : 0u);
    jw_end(&w);
    jw_flush(&w);
    if (w.gone)
        return ESP_FAIL;             /* the socket is dead: closing the reply would only fail again */
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  The CPM layer of /map                                             */
/* ================================================================== */

/* The texts of the layer by their key in ITS_CPM. The %u of q, gof, vn and stn is filled in
 * by the script. */
static const struct {
    char key[6];
    str_id_t id;
} CPM_WORDS[] = {
    { "lo", S_MAP_L_CPM }, { "la", S_MAP_L_CPM_AREA }, { "by", S_MAP_CPM_BY },
    { "hgt", S_MAP_CPM_HEIGHT }, { "age", S_MAP_CPM_AGE }, { "along", S_MAP_CPM_ALONG },
    { "conn", S_MAP_CPM_CONN }, { "from", S_MAP_CPM_FROMREF }, { "sen", S_MAP_CPMA_SENSOR },
    { "reg", S_MAP_CPMA_REGION }, { "conf", S_MAP_CPMA_CONF }, { "uns", S_MAP_CPMA_UNSURE },
    { "cut", S_MAP_CPMA_CUT }, { "q", S_CPM_QUALITY }, { "sure", S_CPM_SURE },
    { "head", S_CPM_HEADING }, { "meas", S_CPM_MEASURED }, { "reach", S_CPM_REACH },
    { "veh", S_CPM_FROM_VEH }, { "rsu", S_CPM_FROM_RSU }, { "gof", S_CPM_G_OF },
    { "vn", S_CPM_V_N }, { "stn", S_CPM_ST_N }, { "newer", S_CPM_CLS_NEWER },
    { "tw", S_CPM_TOWARD },
};

/* The word lists of cpm_class() and cpm_sensor_names() in web_msgdetail_cpm.c, so the popup names
 * a class as the detail line does. S_COUNT marks a vehicle value without a word ("" here). */
static const str_id_t CPM_CAT[ITS_CPM_CATS] = {
    [ITS_CPM_CAT_CAR] = S_CPM_CAT_CAR, [ITS_CPM_CAT_BUS] = S_CPM_CAT_BUS,
    [ITS_CPM_CAT_TRUCK] = S_CPM_CAT_TRUCK, [ITS_CPM_CAT_TRAM] = S_CPM_CAT_TRAM,
    [ITS_CPM_CAT_TWOWHEEL] = S_CPM_CAT_TWOWHEEL, [ITS_CPM_CAT_PED] = S_CPM_CAT_PED,
    [ITS_CPM_CAT_ANIMAL] = S_CPM_CAT_ANIMAL, [ITS_CPM_CAT_GROUP] = S_CPM_CAT_GROUP,
    [ITS_CPM_CAT_OTHER] = S_CPM_CAT_OTHER, [ITS_CPM_CAT_NONE] = S_CPM_CAT_NONE,
};
static const str_id_t CPM_SV[] = { S_CPM_V_UNKNOWN, S_CPM_CAT_PED, S_BVR_CYCLIST, S_CPM_M_MOPED,
    S_BVR_MOTORCYCLE, S_CPM_CAT_CAR, S_CPM_CAT_BUS, S_CPM_V_LTRUCK, S_CPM_V_HTRUCK,
    S_CPM_V_TRAILER, S_CPM_V_SPECIAL, S_CPM_CAT_TRAM, S_COUNT, S_CPM_CAT_ANIMAL, S_CPM_V_AGRI };
static const str_id_t CPM_SP[] = { S_CPM_CAT_PED, S_CPM_CAT_PED, S_CPM_P_WORKER, S_CPM_P_RESCUE };
static const str_id_t CPM_SB[] = { S_CPM_CAT_TWOWHEEL, S_BVR_CYCLIST, S_CPM_B_WHEELCHAIR,
    S_CPM_B_HORSE, S_CPM_B_SKATES, S_CPM_B_SCOOTER, S_CPM_B_PERSONAL, S_CPM_B_PEDELEC,
    S_CPM_B_SPEDELEC, S_CPM_B_ROADBIKE, S_CPM_B_KIDSBIKE };
static const str_id_t CPM_SM[] = { S_CPM_CAT_TWOWHEEL, S_CPM_M_MOPED, S_BVR_MOTORCYCLE,
    S_CPM_M_SIDE_R, S_CPM_M_SIDE_L };
static const str_id_t CPM_SA[] = { S_CPM_CAT_ANIMAL, S_CPM_A_WILD, S_CPM_A_FARM,
    S_CPM_A_SERVICE };
static const str_id_t CPM_SO[] = { S_CPM_O_UNKNOWN, S_CPM_O_SINGLE, S_CPM_O_MULTI,
    S_CPM_O_BULK };
static const str_id_t CPM_ST[] = { S_CPM_ST_UNDEF, S_CPM_ST_RADAR, S_CPM_ST_LIDAR, S_CPM_ST_MONO,
    S_CPM_ST_STEREO, S_CPM_ST_NIGHT, S_CPM_ST_ULTRA, S_CPM_ST_PMD, S_CPM_ST_LOOP,
    S_CPM_ST_SPHERE, S_CPM_ST_UWB, S_CPM_ST_ACOUSTIC, S_CPM_ST_LOCAL, S_CPM_ST_ITS };

static const struct {
    char key[4];
    const str_id_t *ids;
    uint8_t n;
} CPM_LISTS[] = {
    { "cat", CPM_CAT, N_OF(CPM_CAT) }, { "sv", CPM_SV, N_OF(CPM_SV) },
    { "sp", CPM_SP, N_OF(CPM_SP) }, { "sb", CPM_SB, N_OF(CPM_SB) },
    { "sm", CPM_SM, N_OF(CPM_SM) }, { "sa", CPM_SA, N_OF(CPM_SA) },
    { "so", CPM_SO, N_OF(CPM_SO) }, { "st", CPM_ST, N_OF(CPM_ST) },
};

/* The layer script. It polls /cpm.json of this device and of every peer once a second and
 * merges them by sender station, so an object two receivers hear is one marker. */
static const char WEB_CPM_MAP_JS[] =
    "<script>(function(){"
    "var C=window.ITS_CPM,A=window.itsMapApi;if(!C||!A)return;"
    "var map=A.map,PE=window.ITS_MAP_PEERS||[],SELF=window.ITS_MAP_SELF||location.host,"
    "DS=document.documentElement.lang=='de'?',':'.';"
    /* htxt() and dc() of the map script are private to it, so the layer brings its own. */
    "function dc(v){return v.toFixed(1).replace('.',DS);}"
    "function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;')"
    ".replace(/>/g,'&gt;').replace(/\"/g,'&quot;');}"
    /* Below the overlay pane (400): lanes, tracks and warning areas stay on top and clickable. */
    "map.createPane('cpmArea').style.zIndex=390;"
    /* Both layers are on by default; 'o' and 'a' in mapc keep them off in this browser. */
    "var oL=L.layerGroup(),aL=L.layerGroup(),mc='';"
    "try{mc=localStorage.getItem('mapc')||'';}catch(e){}"
    "if(mc.indexOf('o')<0)oL.addTo(map);if(mc.indexOf('a')<0)aL.addTo(map);"
    /* The swatch before each name is the legend; the control sets the name as HTML. */
    "var SW='<span style=\"display:inline-block;vertical-align:middle;margin-right:4px;"
    "box-sizing:border-box;';"
    "A.lctl.addOverlay(oL,SW+'width:10px;height:10px;border:2px dashed #f2b134;"
    "border-radius:50%\"></span>'+C.lo);"
    "A.lctl.addOverlay(aL,SW+'width:12px;height:10px;background:rgba(127,178,255,.3);"
    "border:1px solid #7fb2ff\"></span>'+C.la);"
    "map.on('overlayadd overlayremove',function(e){if(e.layer!==oL&&e.layer!==aL)return;"
    "var s=(map.hasLayer(oL)?'':'o')+(map.hasLayer(aL)?'':'a');"
    "try{localStorage.setItem('mapc',s);}catch(x){}});"
    /* One emoji per category, in the order of ITS_CPM_CAT_* (its_cpm.h). */
    "var EM=['\\ud83d\\ude97','\\ud83d\\ude8c','\\ud83d\\ude9a','\\ud83d\\ude8a','\\ud83d\\udeb2',"
    "'\\ud83d\\udeb6','\\ud83d\\udc3e','\\ud83d\\udc65','\\ud83d\\udce6','\\u26aa'];"
    /* The subclass words per ObjectClass, and the category word for a value past the list, as
     * cpm_class() in web_msgdetail_cpm.c; -1: a vehicle value without a word gets its number. */
    "var SUB={1:[C.sv,-1],2:[C.sp,5],3:[C.sb,4],4:[C.sm,4],5:[C.sa,6],8:[C.so,8]};"
    "function cw(o){var c=o[4],s=o[5],t=SUB[c],w;"
    "if(c===7)return C.gof.replace('%u',s);if(c===6||c===9)return C.newer;"
    "if(!t)return C.cat[o[3]]||C.cat[9];"
    "w=s<t[0].length?t[0][s]:t[1]<0?'':C.cat[t[1]];return w||C.vn.replace('%u',s);}"
    "function cc(b){return ITS_CAM_C[Math.round(b/450)%8];}"
    "function stw(t){return t<C.st.length?C.st[t]:C.stn.replace('%u',t);}"
    /* Metres per degree by the series of its_cpm_to_wgs84, on a flat plane at the anchor:
     * the device places the anchor, the browser only draws the outline around it. */
    "var R=Math.PI/1800;"
    "function mpd(la){var p=la*Math.PI/180;"
    "return [111132.954-559.822*Math.cos(2*p)+1.175*Math.cos(4*p),"
    "111412.84*Math.cos(p)-93.5*Math.cos(3*p)+0.118*Math.cos(5*p)];}"
    "function pt(q,e,n){return [q[0]+n/q[2][0],q[1]+(q[2][1]>=1?e/q[2][1]:0)];}"
    "function brg(q,d,b){return pt(q,d*Math.sin(b*R),d*Math.cos(b*R));}"
    /* A sector clockwise from f to t, in steps of 5 degrees at most; equal ends are a full
     * circle. */
    "function sec(q,d,f,t){var s=((t-f)%3600+3600)%3600||3600,k=Math.ceil(s/50),r=[[q[0],q[1]]];"
    "for(var i=0;i<=k;i++)r.push(brg(q,d,f+s*i/k));return r;}"
    /* Columns 5..14 of an area as Leaflet points. The a axis points along the bearing rot,
     * the b axis 90 degrees clockwise from it. */
    "function shape(a){var q=[a[5]/1e7,a[6]/1e7],x=a[7]/10,y=a[8]/10,"
    "s=Math.sin(a[9]*R),c=Math.cos(a[9]*R),p=[],i,u,v;q.push(mpd(q[0]));"
    "if(a[1]===0)for(i=0;i<4;i++){u=i<2?x:-x;v=i===0||i===3?y:-y;p.push(pt(q,u*s+v*c,u*c-v*s));}"
    "else if(a[1]===3)for(i=0;i<72;i++){u=x*Math.cos(i*Math.PI/36);v=y*Math.sin(i*Math.PI/36);"
    "p.push(pt(q,u*s+v*c,u*c-v*s));}"
    "else if(a[1]===1)for(i=0;i<72;i++)p.push(brg(q,x,i*50));"
    "else if(a[1]===2)for(i=0;i<a[14].length;i++)p.push(pt(q,a[14][i][0]/100,a[14][i][1]/100));"
    "else if(a[1]===4)p=sec(q,x,a[10],a[11]);"
    /* radialShapes: one polygon of all sectors; nonzero fills where they overlap. */
    "else for(i=0;i<a[14].length;i++)p.push([sec(q,a[14][i][0]/10,a[14][i][1],a[14][i][2])]);"
    "return p;}"
    /* Regions dotted, a surer detection a stronger blue, an uncertain position a paler edge. */
    "function ast(a){var r=a[0]===2;return {color:'#7fb2ff',weight:r?1.5:1,"
    "opacity:a[12]&1?0.35:0.7,fillColor:'#7fb2ff',"
    "fillOpacity:a[4]===null?0.08:0.04+0.14*a[4]/100,dashArray:r?'2,4':null,"
    "fillRule:a[1]===5?'nonzero':'evenodd'};}"
    /* The needle as in iconFor() of the map script, outside the dashed ring: the course while
     * the object moves (50 cm/s), else its orientation. */
    "function ico(o){var h=o[7]!==null&&o[7]>=50&&o[8]!==null?o[8]:o[9];"
    "return (h===null?'':'<span style=\"position:absolute;top:-11px;left:50%;width:0;height:0;"
    "margin-left:-5px;border-left:5px solid transparent;border-right:5px solid transparent;"
    "border-bottom:9px solid #f2b134;transform-origin:50% 27px;transform:rotate('+h/10+'deg);"
    "filter:drop-shadow(0 0 1px rgba(0,0,0,.9))\"></span>')+(EM[o[3]]||EM[9]);}"
    "function mk(h){return L.divIcon({className:'its-cpm-icon',iconSize:[36,36],iconAnchor:[18,18],"
    "html:'<div style=\"position:relative;width:36px;height:36px;box-sizing:border-box;"
    "border:2px dashed #f2b134;border-radius:50%;font-size:28px;line-height:32px;"
    "text-align:center\">'+h+'</div>'});}"
    /* Receiver names come from the settings, so they are escaped; the table texts carry
     * entities and go in as they are. */
    "function seen(e){return PE.length?'<br><small>'+ITS_MAP_SEEN_BY+' '+Object.keys(e.r)"
    ".map(function(r){return r===''?SELF:r;}).sort().map(esc).join(', ')+'</small>':'';}"
    /* Distance and direction count from the reference position of the object's own CPM (its
     * offset, columns 22 and 23). The time is that CPM's too (column 24), because a moving
     * sender has gone on since. */
    "function opop(e,o,s){var h='<b>'+(EM[o[3]]||EM[9])+' '+cw(o)+'</b>',z=[o[10],o[11],o[12]],"
    "ln=[],de=o[22]/100,dn=o[23]/100,d=Math.sqrt(de*de+dn*dn),dm;"
    "if(o[6]!==null)h+=', '+o[6]+' % '+C.sure;"
    "if(o[15]!==null)h+='<br>'+C.q.replace('%u',o[15]);"
    /* A lower bound is cut, not rounded up, as the detail line does it. */
    "if(o[7]!==null)h+='<br>'+(o[21]&1?'&ge; '+dc(Math.floor(o[7]*0.36)/10):dc(o[7]*0.036))+' km/h'"
    "+(o[7]>=50&&o[8]!==null?' '+C.tw+' '+cc(o[8]):'');"
    "if(o[19]!==null)h+='<br>'+ITS_MAP_ACCEL+' '+dc(o[19]/10)+' m/s\\u00b2';"
    "if(o[9]!==null)h+='<br>'+C.head+' '+Math.round(o[9]/10)+'\\u00b0 '+cc(o[9]);"
    "if(z[0]!==null||z[1]!==null||z[2]!==null)h+='<br>'+z.map(function(v){"
    "return v===null?'&ndash;':(v===255?'&ge; ':'')+dc(v/10);}).join(' \\u00d7 ')+' m';"
    "if(o[13]!==null)h+='<br>'+C.hgt+' '+dc(o[13]/100)+' m';"
    "if(o[14]!==null)h+='<br>'+C.age+' '+(o[21]&4?'&ge; ':'')+dc(o[14]/1000)+' s';"
    "if(o[16]!==null)ln.push(ITS_MAP_LANEPOS+' '+o[16]);"
    "if(o[17]!==null)ln.push(C.conn+' '+o[17]);"
    "if(o[18]!==null)ln.push((o[21]&16?'&ge; ':'')+dc(o[18]/10)+' m '+C.along);"
    "if(ln.length)h+='<br>'+ln.join(' &middot; ');"
    /* At the end of the coordinate range only a lower bound, so cut, not rounded. */
    "dm=o[21]&2?Math.floor(d):Math.round(d);"
    "h+='<br>'+(o[21]&2?'&ge; ':'')+dm+' m '+(dm?cc((Math.atan2(de,dn)/R+3600)%3600)+' ':'')+C.from;"
    "h+='<br>'+C.by+' '+s.i+(s.k===1?' &middot; '+C.veh:s.k===2?' &middot; '+C.rsu:'');"
    "h+=seen(e);if(o[24]!==null)h+='<br>'+C.meas+' '+itsTz.hm(o[24]*1000,1);return h;}"
    "function apop(e,a,s){var h=a[0]===1?'<b>'+C.sen+' '+a[2]+': '+stw(a[3])+'</b>':'<b>'+C.reg+'</b>',"
    "r=a[1]===1||a[1]===4?a[7]:null,i;"
    "if(a[1]===5)for(i=0;i<a[14].length;i++)r=Math.max(r||0,a[14][i][0]);"
    "if(r!==null)h+='<br>'+C.reach+' '+Math.round(r/10)+' m';"
    "if(a[4]!==null)h+='<br>'+C.conf+' '+a[4]+' % '+C.sure;"
    "h+='<br>'+ITS_MAP_SID+' '+s.i;if(a[12]&1)h+='<br>'+C.uns;return h+seen(e);}"
    /* Keys without the receiver: object station|objectId, area station|s|sensorId or
     * station|r|generation|place (column 16), so regions merge only within one referenceTime
     * (generation) and by their place in it. e.r: each receiver's row, the freshest drawn. */
    "var OB={},AR={},RT={},BUSY={},GONE={},CUT={},note=null,was=true;"
    "function best(e,c){var b=null;for(var r in e.r)if(!b||e.r[r].v[c]<b.v[c])b=e.r[r];return b;}"
    "function forget(T,r,keep){for(var k in T)if(T[k].r[r]&&!(keep&&keep[k]))delete T[k].r[r];}"
    /* A peer's answer ends up in popups as HTML, so only numbers pass; a sender or row with
     * anything else is left out. Cell 14 of an area row is its list of points. */
    "function nb(v){return typeof v==='number'&&isFinite(v);}"
    "function okr(v,ar){return Array.isArray(v)&&v.every(function(c,i){return ar&&i===14?"
    "Array.isArray(c)&&c.every(function(p){return Array.isArray(p)&&p.every(nb);})"
    ":c===null||nb(c);});}"
    "function arr(v){return Array.isArray(v)?v:[];}"
    /* Each answer is whole for its receiver: what it no longer lists loses that receiver. */
    "function put(r,d){var ko={},ka={},cut=!!d.c;"
    "arr(d.s).forEach(function(s){var n=0;if(!s||!nb(s.i)||!nb(s.k)||!nb(s.x))return;"
    "if(s.x&3)cut=true;"
    "arr(s.ob).forEach(function(v){if(!okr(v,false))return;var k=s.i+'|'+v[0];ko[k]=1;"
    "(OB[k]||(OB[k]={r:{}})).r[r]={v:v,s:s};});"
    "arr(s.ar).forEach(function(v){if(!okr(v,true))return;"
    "var k=s.i+(v[0]===1?'|s|'+v[2]:'|r|'+v[15]+'|'+(typeof v[16]==='number'?v[16]:'n'+n++));"
    "ka[k]=1;(AR[k]||(AR[k]={r:{}})).r[r]={v:v,s:s};});});"
    "forget(OB,r,ko);forget(AR,r,ka);CUT[r]=cut;RT[r]=Date.now();draw();}"
    /* A note in the style of the map script (.tracknote). It is set with innerHTML because
     * the text carries entities. */
    "function tag(on){if(!on){if(note){note.remove();note=null;}return;}if(note)return;"
    "note=L.control({position:'bottomleft'});note.onAdd=function(){"
    "var d=L.DomUtil.create('div','tracknote');d.innerHTML=C.cut;return d;};note.addTo(map);}"
    /* Markers and shapes are changed only where a value changed, and popups only when their
     * text did, so an open popup stays open through the poll. */
    "function draw(){var k,e,b,v,p,g,st,sk,re=false,cut=false;"
    "for(k in OB){e=OB[k];b=best(e,20);"
    "if(!b){if(e.m)oL.removeLayer(e.m);delete OB[k];continue;}"
    "v=b.v;g=v[1]+','+v[2];st=ico(v);"
    "if(!e.m){e.m=L.marker([v[1]/1e7,v[2]/1e7],{icon:mk(st),zIndexOffset:-500}).bindPopup('')"
    ".addTo(oL);e.g=g;e.i=st;}"
    "if(e.g!==g){e.m.setLatLng([v[1]/1e7,v[2]/1e7]);e.g=g;}"
    "if(e.i!==st){e.m.setIcon(mk(st));e.i=st;}"
    "p=opop(e,v,b.s);if(p!==e.p){e.p=p;e.m.setPopupContent(p);}}"
    "for(k in AR){e=AR[k];b=best(e,13);"
    "if(!b){if(e.l)aL.removeLayer(e.l);delete AR[k];continue;}"
    "v=b.v;g=[v[1],v[5],v[6],v[7],v[8],v[9],v[10],v[11],JSON.stringify(v[14])].join();"
    "st=ast(v);sk=JSON.stringify(st);"
    "if(e.l&&e.kd!==v[1]){aL.removeLayer(e.l);e.l=null;}"
    "if(!e.l){st.pane='cpmArea';e.l=L.polygon(shape(v),st).bindPopup('').addTo(aL);"
    "e.kd=v[1];e.g=g;e.sk=sk;re=true;}"
    "if(e.g!==g){e.l.setLatLngs(shape(v));e.g=g;}"
    "if(e.sk!==sk){e.l.setStyle(st);e.sk=sk;}"
    "p=apop(e,v,b.s);if(p!==e.p){e.p=p;e.l.setPopupContent(p);}}"
    /* A new shape is drawn on top, so the list order is restored. */
    "if(re)for(k in AR)AR[k].l.bringToFront();"
    "for(k in CUT)if(CUT[k])cut=true;tag(cut);}"
    /* Objects and areas are not in the playback: the layers empty while it runs and fill again
     * on the first tick after it. */
    "function tick(){var now=Date.now(),r,old=false;"
    "if(!A.live()){if(was){was=false;oL.clearLayers();aL.clearLayers();"
    "OB={};AR={};RT={};CUT={};tag(false);}return;}"
    "was=true;"
    /* A receiver that stopped answering loses its entries after 3 s, the store's own rule. */
    "for(r in RT)if(now-RT[r]>=3000){delete RT[r];delete CUT[r];forget(OB,r);forget(AR,r);old=true;}"
    "if(old)draw();"
    "if(!map.hasLayer(oL)&&!map.hasLayer(aL))return;"
    /* One request per receiver in flight, so a slow answer delays that receiver's next one. A
     * peer on older firmware answers 404 and is asked no more. */
    "[''].concat(PE).forEach(function(r){if(BUSY[r]||GONE[r])return;BUSY[r]=true;"
    "fetch(r?'http://'+r+'/cpm.json':'/cpm.json',{cache:'no-store'}).then(function(x){"
    "if(x.status===404)GONE[r]=true;if(!x.ok)throw x.status;return x.json();})"
    ".then(function(d){BUSY[r]=false;if(A.live())put(r,d);})"
    ".catch(function(){BUSY[r]=false;});});}"
    "tick();setInterval(tick,1000);"
    "})();</script>";

/* noinline and no large local: map_get_handler, the deepest chain of the httpd task, calls it. */
__attribute__((noinline)) void web_cpm_map_send(httpd_req_t *req)
{
    /* Below the map and the playback row, hidden with every help text by the switch. */
    web_send_parts(req, "<p class='note hlp'>", T(S_MAP_CPM_HINT), "</p>", NULL);
    /* Static: only the httpd task serves /map. German needs 1763, English 1685 (host build).
     * Plain snprintf with o checked before every write, as the warning-area texts. */
    static EXT_RAM_BSS_ATTR char lbl[2560];
    int o = snprintf(lbl, sizeof(lbl), "<script>var ITS_CPM={");
    for (size_t i = 0; i < N_OF(CPM_WORDS) && o > 0 && (size_t)o < sizeof(lbl); i++)
        o += snprintf(lbl + o, sizeof(lbl) - o, "%s%s:\"%s\"", i ? "," : "", CPM_WORDS[i].key,
                      T(CPM_WORDS[i].id));
    for (size_t i = 0; i < N_OF(CPM_LISTS) && o > 0 && (size_t)o < sizeof(lbl); i++)
    {
        o += snprintf(lbl + o, sizeof(lbl) - o, ",%s:[", CPM_LISTS[i].key);
        for (size_t j = 0; j < CPM_LISTS[i].n && o > 0 && (size_t)o < sizeof(lbl); j++)
        {
            str_id_t id = CPM_LISTS[i].ids[j];
            o += snprintf(lbl + o, sizeof(lbl) - o, "%s\"%s\"", j ? "," : "",
                          id == S_COUNT ? "" : T(id));
        }
        if (o > 0 && (size_t)o < sizeof(lbl))
            o += snprintf(lbl + o, sizeof(lbl) - o, "]");
    }
    if (o > 0 && (size_t)o < sizeof(lbl))
        o += snprintf(lbl + o, sizeof(lbl) - o, "};</script>");
    /* A cut script would lack its </script> and swallow the layer script behind it. Without
     * ITS_CPM the layer script does nothing. */
    if (o > 0 && (size_t)o < sizeof(lbl))
        httpd_resp_send_chunk(req, lbl, HTTPD_RESP_USE_STRLEN);
    else
        ESP_LOGW(TAG, "map CPM labels truncated");
    httpd_resp_send_chunk(req, WEB_CPM_MAP_JS, HTTPD_RESP_USE_STRLEN);
}
