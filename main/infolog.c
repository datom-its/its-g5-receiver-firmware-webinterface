#include "sdkconfig.h"

#include "infolog.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_attr.h"
#include "esp_log.h"

#if CONFIG_ENABLE_SD
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include "events_log.h"
#include "its_utf8.h"
#include "sdcard.h"

/* Measured with riscv32-esp-elf-gcc 15.2. The host tests build the same layout. */
_Static_assert(sizeof(infolog_cpm_t) == 184, "infolog_cpm_t is no longer 184 B");
_Static_assert(sizeof(infolog_evcsn_t) == 136, "infolog_evcsn_t is no longer 136 B");
_Static_assert(sizeof(infolog_rtcm_t) == 28, "infolog_rtcm_t is no longer 28 B");
_Static_assert(sizeof(infolog_slot_t) == 280 && offsetof(infolog_slot_t, u) == 56,
               "infolog_slot_t is no longer 280 B with u at 56");
/* The column offsets are uint16_t, and snapshot marks taken slots in a 64-bit mask. */
_Static_assert(sizeof(infolog_slot_t) < INFOLOG_ALWAYS && INFOLOG_SLOTS <= 64, "limits");
/* _TXTN caps both POIM texts at ITS_POIM_TEXT, as the page does. */
_Static_assert(sizeof(((its_poim_t *)0)->name) == ITS_POIM_TEXT &&
               sizeof(((its_poim_t *)0)->price) == ITS_POIM_TEXT, "POIM text size");

static const char TAG[] = "INFOLOG";

#define INFOLOG_DIR CONFIG_SNIFFER_MOUNT_POINT "/logs"

/* ------------------------------------------------------------------ */
/*  Columns: header and rows come from the same table                 */
/* ------------------------------------------------------------------ */

#define O(f)       ((uint16_t)offsetof(infolog_slot_t, f))
#define P_ALWAYS   INFOLOG_ALWAYS, 0
#define P(f)       O(f), 1
#define PM(f, m)   O(f), (uint8_t)(m)
#define P_READ     P(read)
#define NZ         INFOLOG_T_NZ

/* The first eleven columns of every file. */
#define HEAD_COLS \
    { "time",     O(last_s),   0, P_ALWAYS,  INFOLOG_T_U32 }, \
    { "first",    O(first_s),  0, P_ALWAYS,  INFOLOG_T_U32 }, \
    { "station",  O(station),  0, P_ALWAYS,  INFOLOG_T_U32 }, \
    { "mac",      O(mac),      0, P(has_mac), INFOLOG_T_MAC }, \
    { "rssi",     O(rssi),     0, P_ALWAYS,  INFOLOG_T_I8 | NZ }, \
    { "rssi_min", O(rssi_min), 0, P_ALWAYS,  INFOLOG_T_I8 | NZ }, \
    { "rssi_max", O(rssi_max), 0, P_ALWAYS,  INFOLOG_T_I8 | NZ }, \
    { "msgs",     O(win),      0, P_ALWAYS,  INFOLOG_T_U32 }, \
    { "why",      O(why),      0, P_ALWAYS,  INFOLOG_T_WHY }, \
    { "version",  O(version),  0, P_ALWAYS,  INFOLOG_T_U8 }, \
    { "read",     O(read),     0, P_ALWAYS,  INFOLOG_T_BOOL }

/* A content column without a presence flag of its own is empty unless the frame was read. */
#define CP(f) O(u.cpm.f)
static const infolog_col_t COLS_CPM[] = {
    HEAD_COLS,
    { "ref_time",     CP(c.ref_ms),         0, P_READ, INFOLOG_T_ITSMS | NZ },
    { "lat_e7",       CP(c.ref_lat_e7),     0, P(u.cpm.c.has_ref_pos), INFOLOG_T_I32 },
    { "lon_e7",       CP(c.ref_lon_e7),     0, P(u.cpm.c.has_ref_pos), INFOLOG_T_I32 },
    { "containers",   CP(containers),       0, P_READ, INFOLOG_T_U16 },
    { "bad",          CP(cont_bad),         0, P_READ, INFOLOG_T_U16 },
    { "n_containers", CP(n_containers),     0, P_READ, INFOLOG_T_U8 },
    { "objects",      CP(n_objects),        0, P_READ, INFOLOG_T_U8 },
    { "objects_here", CP(n_objects_here),   0, P_READ, INFOLOG_T_U16 },
    { "objects_read", CP(c.n_walked),       0, P_READ, INFOLOG_T_U16 },
    { "objects_max",  O(obj_max),           0, P(obj_seen), INFOLOG_T_U16 },
    { "sensors",      CP(n_sensors),        0, P_READ, INFOLOG_T_U16 },
    { "regions",      CP(n_regions),        0, P_READ, INFOLOG_T_U16 },
    { "heading",      CP(heading_ddeg),     0, P(u.cpm.has_heading), INFOLOG_T_U16 },
    { "seg_this",     CP(seg_this),         0, P_READ, INFOLOG_T_U8 | NZ },
    { "seg_total",    CP(seg_total),        0, P_READ, INFOLOG_T_U8 | NZ },
    { "list_form",    CP(list_form),        0, P_READ, INFOLOG_T_U8 | NZ },
    { "edition",      CP(c.dialect),        0, P_READ, INFOLOG_T_U8 | NZ },
    { "edition_sure", CP(c.dialect_sure),   0, P_READ, INFOLOG_T_BOOL },
    { "doubt",        CP(c.doubt),          0, P_READ, INFOLOG_T_U8 },
    { "cat_car",      CP(c.cat[ITS_CPM_CAT_CAR]),      0, P_READ, INFOLOG_T_U8 },
    { "cat_bus",      CP(c.cat[ITS_CPM_CAT_BUS]),      0, P_READ, INFOLOG_T_U8 },
    { "cat_truck",    CP(c.cat[ITS_CPM_CAT_TRUCK]),    0, P_READ, INFOLOG_T_U8 },
    { "cat_tram",     CP(c.cat[ITS_CPM_CAT_TRAM]),     0, P_READ, INFOLOG_T_U8 },
    { "cat_twowheel", CP(c.cat[ITS_CPM_CAT_TWOWHEEL]), 0, P_READ, INFOLOG_T_U8 },
    { "cat_ped",      CP(c.cat[ITS_CPM_CAT_PED]),      0, P_READ, INFOLOG_T_U8 },
    { "cat_animal",   CP(c.cat[ITS_CPM_CAT_ANIMAL]),   0, P_READ, INFOLOG_T_U8 },
    { "cat_group",    CP(c.cat[ITS_CPM_CAT_GROUP]),    0, P_READ, INFOLOG_T_U8 },
    { "cat_other",    CP(c.cat[ITS_CPM_CAT_OTHER]),    0, P_READ, INFOLOG_T_U8 },
    { "cat_none",     CP(c.cat[ITS_CPM_CAT_NONE]),     0, P_READ, INFOLOG_T_U8 },
    { "sensor_types", CP(c.sensor_types),   0, P_READ, INFOLOG_T_U32 },
    { "reach_dm",     CP(c.reach_dm),       0, P_READ, INFOLOG_T_U16 | NZ },
    { "reach_conf",   CP(c.reach_conf),     0, P_READ, INFOLOG_T_U8 | NZ },
    { "trailers",     CP(c.n_trailers),     0, P_READ, INFOLOG_T_U8 },
    { "map_kind",     CP(c.has_map),        CP(c.map_intersection), P(u.cpm.c.has_map), INFOLOG_T_MAPKIND },
    { "map_region",   CP(c.map_region),     0, P(u.cpm.c.map_has_region), INFOLOG_T_U16 },
    { "map_id",       CP(c.map_id),         0, P(u.cpm.c.has_map), INFOLOG_T_U16 },
    { "rate_min",     CP(c.rate_min_m),     CP(c.rate_min_e), P(u.cpm.c.has_rate), INFOLOG_T_RATE },
    { "rate_max",     CP(c.rate_max_m),     CP(c.rate_max_e), P(u.cpm.c.has_rate), INFOLOG_T_RATE },
};

/* The first station's columns are filled only when it has spots, as on the page (evcsn_text).
 * copy_content already clears has_pos without spots. */
#define EV(f) O(u.evcsn.f)
#define PSPOTS PM(u.evcsn.n_spots, 0xFF)
static const infolog_col_t COLS_EVCSN[] = {
    HEAD_COLS,
    { "poi_type",       EV(poi_type),   0, P_READ, INFOLOG_T_U16 },
    { "ts",             EV(ts_ms),      0, P_READ, INFOLOG_T_ITSMS | NZ },
    { "relay",          EV(relay),      0, P_READ, INFOLOG_T_BOOL },
    { "stations_total", EV(n_total),    0, P_READ, INFOLOG_T_U16 },
    { "stations_here",  EV(n_stations), 0, P_READ, INFOLOG_T_U16 },
    { "st_id",          EV(st_id),      0, PSPOTS, INFOLOG_T_U32 },
    { "lat_e7",         EV(lat_e7),     0, P(u.evcsn.has_pos), INFOLOG_T_I32 },
    { "lon_e7",         EV(lon_e7),     0, P(u.evcsn.has_pos), INFOLOG_T_I32 },
    { "spots",          EV(n_spots),    0, P_READ, INFOLOG_T_U8 | NZ },
    { "modes",          EV(modes),      0, PSPOTS, INFOLOG_T_U16 },
    { "access",         EV(access),     ITS_EVCSN_TEXT + 1, PSPOTS, INFOLOG_T_TXTZ },
    { "hours",          EV(hours),      ITS_EVCSN_TEXT + 1, PSPOTS, INFOLOG_T_TXTZ },
    { "price",          EV(price),      ITS_EVCSN_TEXT + 1, PSPOTS, INFOLOG_T_TXTZ },
};

/* The s_* columns follow poim_filter: each value only when its list came. */
#define PO(f) O(u.poim.f)
static const infolog_col_t COLS_POIM[] = {
    HEAD_COLS,
    { "list_broken",    PO(list_broken),    0, P_READ, INFOLOG_T_BOOL },
    { "broken",         PO(broken),         0, P_READ, INFOLOG_T_BOOL },
    { "engine_stop",    PO(engine_stop),    0, P_READ, INFOLOG_T_BOOL },
    { "newer",          PO(newer),          0, P_READ, INFOLOG_T_BOOL },
    { "out_of_range",   PO(out_of_range),   0, P_READ, INFOLOG_T_BOOL },
    { "tail_left",      PO(tail_left),      0, P_READ, INFOLOG_T_BOOL },
    { "blocks",         PO(n_blocks),       0, P_READ, INFOLOG_T_U8 },
    { "parking",        PO(n_parking),      0, P_READ, INFOLOG_T_U8 },
    { "other_types",    PO(other_type),     PO(n_other_types), P_READ, INFOLOG_T_LIST3 },
    { "other_more",     PO(other_more),     0, P_READ, INFOLOG_T_BOOL },
    { "provider",       PO(provider),       0, P(u.poim.has_mgmt), INFOLOG_T_U16 },
    { "country",        PO(country),        0, P(u.poim.has_mgmt), INFOLOG_T_U16 },
    { "entry",          PO(entry),          0, P(u.poim.has_mgmt), INFOLOG_T_U16 },
    { "poi_time",       PO(time_s),         0, P_READ, INFOLOG_T_U32 | NZ },
    { "ivims",          PO(n_ivim),         0, P_READ, INFOLOG_T_U8 },
    { "mapems",         PO(n_mapem),        0, P_READ, INFOLOG_T_U8 },
    { "map_kind",       PO(has_map),        PO(map_intersection), P(u.poim.has_map), INFOLOG_T_MAPKIND },
    { "map_region",     PO(map_region),     0, P(u.poim.map_has_region), INFOLOG_T_U16 },
    { "map_id",         PO(map_id),         0, P(u.poim.has_map), INFOLOG_T_U16 },
    { "lat_e7",         PO(lat_e7),         0, P(u.poim.has_pos), INFOLOG_T_I32 },
    { "lon_e7",         PO(lon_e7),         0, P(u.poim.has_pos), INFOLOG_T_I32 },
    { "alt_cm",         PO(alt_cm),         0, P(u.poim.has_alt), INFOLOG_T_I32 },
    { "name",           PO(name),           PO(name_len), P_READ, INFOLOG_T_TXTN },
    { "name_cut",       PO(name_cut),       0, P_READ, INFOLOG_T_BOOL },
    { "periods",        PO(n_periods),      0, P_READ, INFOLOG_T_U8 },
    { "days",           PO(days),           0, P(u.poim.has_period), INFOLOG_T_U8 },
    { "open",           PO(open_h),         0, P(u.poim.has_period), INFOLOG_T_HHMM },
    { "close",          PO(close_h),        0, P(u.poim.has_period), INFOLOG_T_HHMM },
    { "status",         PO(status),         0, P(u.poim.has_status), INFOLOG_T_U8 },
    { "free",           PO(occ.n_free),     0, P(u.poim.occ.has_free), INFOLOG_T_U16 },
    { "total",          PO(occ.n_total),    0, P(u.poim.occ.has_total), INFOLOG_T_U16 },
    { "rate",           PO(occ.rate),       0, P(u.poim.occ.has_rate), INFOLOG_T_U8 },
    { "trend",          PO(occ.trend),      0, P(u.poim.occ.has_trend), INFOLOG_T_U8 },
    { "statuses",       PO(n_status),       0, P_READ, INFOLOG_T_U8 },
    { "s_lists",        PO(sub.lists),      0, P(u.poim.has_sub), INFOLOG_T_U8 },
    { "s_more",         PO(sub.more),       0, P(u.poim.has_sub), INFOLOG_T_BOOL },
    { "s_vehicle",      PO(sub.veh_class),  PO(sub.veh_num),
      PM(u.poim.sub.lists, ITS_POIM_FILT_VEHICLE), INFOLOG_T_VCLASS },
    { "s_reservation",  PO(sub.reservation), 0, PM(u.poim.sub.lists, ITS_POIM_FILT_RESERVATION),
      INFOLOG_T_U8 },
    { "s_fee",          PO(sub.fee),        0, PM(u.poim.sub.lists, ITS_POIM_FILT_FEE), INFOLOG_T_U8 },
    { "s_goods",        PO(sub.goods),      0, P(u.poim.sub.has_goods), INFOLOG_T_U8 },
    { "s_dangerous",    PO(sub.dangerous),  0, P(u.poim.sub.has_dangerous), INFOLOG_T_U8 },
    { "s_special",      PO(sub.special),    0, PM(u.poim.sub.lists, ITS_POIM_FILT_LOAD), INFOLOG_T_U8 },
    { "s_stay_kind",    PO(sub.stay_kind),  0, PM(u.poim.sub.lists, ITS_POIM_FILT_STAY), INFOLOG_T_U8 },
    { "s_stay",         PO(sub.stay_num),   0, P(u.poim.sub.has_stay_num), INFOLOG_T_U32 },
    { "s_free",         PO(sub.occ.n_free), 0, P(u.poim.sub.occ.has_free), INFOLOG_T_U16 },
    { "s_total",        PO(sub.occ.n_total), 0, P(u.poim.sub.occ.has_total), INFOLOG_T_U16 },
    { "s_rate",         PO(sub.occ.rate),   0, P(u.poim.sub.occ.has_rate), INFOLOG_T_U8 },
    { "s_trend",        PO(sub.occ.trend),  0, P(u.poim.sub.occ.has_trend), INFOLOG_T_U8 },
    { "areas",          PO(n_areas),        0, P_READ, INFOLOG_T_U16 },
    { "areas_at_least", PO(areas_at_least), 0, P_READ, INFOLOG_T_BOOL },
    { "area_id",        PO(area_id),        0, P(u.poim.has_area), INFOLOG_T_U16 },
    { "a_free",         PO(area_occ.n_free), 0, P(u.poim.area_occ.has_free), INFOLOG_T_U16 },
    { "a_total",        PO(area_occ.n_total), 0, P(u.poim.area_occ.has_total), INFOLOG_T_U16 },
    { "a_rate",         PO(area_occ.rate),  0, P(u.poim.area_occ.has_rate), INFOLOG_T_U8 },
    { "a_trend",        PO(area_occ.trend), 0, P(u.poim.area_occ.has_trend), INFOLOG_T_U8 },
    { "level",          PO(level),          0, P_READ, INFOLOG_T_I8 },
    { "height",         PO(height),         0, P(u.poim.has_height), INFOLOG_T_U8 },
    { "related",        PO(n_related),      0, P_READ, INFOLOG_T_U8 },
    { "price",          PO(price),          PO(price_len), P_READ, INFOLOG_T_TXTN },
    { "price_cut",      PO(price_cut),      0, P_READ, INFOLOG_T_BOOL },
};

#define RT(f) O(u.rtcm.f)
static const infolog_col_t COLS_RTCM[] = {
    HEAD_COLS,
    { "counter",     RT(msg_cnt), 0, P_READ, INFOLOG_T_U8 },
    { "rev",         RT(rev),     0, P_READ, INFOLOG_T_U8 },
    { "corrections", RT(n_msgs),  0, P_READ, INFOLOG_T_U8 },
    { "bytes",       RT(bytes),   0, P_READ, INFOLOG_T_U16 },
    { "minute",      RT(minute),  0, P(u.rtcm.has_minute), INFOLOG_T_U32 },
    { "lat_e7",      RT(lat_e7),  0, P(u.rtcm.has_anchor), INFOLOG_T_I32 },
    { "lon_e7",      RT(lon_e7),  0, P(u.rtcm.has_anchor), INFOLOG_T_I32 },
    { "elev_dm",     RT(elev_dm), 0, P(u.rtcm.has_elev), INFOLOG_T_I32 },
    { "status",      RT(status),  0, P(u.rtcm.has_status), INFOLOG_T_U8 },
};

#define NCOLS(a) (sizeof(a) / sizeof((a)[0]))

/* One file per kind, in the order the tick appends them. The names are the labels of /messages. */
typedef struct {
    uint8_t kind;
    uint8_t n;
    const infolog_col_t *cols;
    const char *csv, *old;
} il_kind_t;

static const il_kind_t KINDS[] = {
    { 14, NCOLS(COLS_CPM),   COLS_CPM,   INFOLOG_DIR "/cpm.csv",    INFOLOG_DIR "/cpm.1.csv" },
    { 11, NCOLS(COLS_EVCSN), COLS_EVCSN, INFOLOG_DIR "/evcsn.csv",  INFOLOG_DIR "/evcsn.1.csv" },
    { 3,  NCOLS(COLS_POIM),  COLS_POIM,  INFOLOG_DIR "/poim.csv",   INFOLOG_DIR "/poim.1.csv" },
    { 13, NCOLS(COLS_RTCM),  COLS_RTCM,  INFOLOG_DIR "/rtcmem.csv", INFOLOG_DIR "/rtcmem.1.csv" },
};
#define N_KINDS NCOLS(KINDS)

const infolog_col_t *infolog_cols(uint8_t kind, size_t *n)
{
    for (size_t k = 0; k < N_KINDS; k++)
        if (KINDS[k].kind == kind)
        {
            if (n)
                *n = KINDS[k].n;
            return KINDS[k].cols;
        }
    if (n)
        *n = 0;
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Row writer, no snprintf: small frames on the 4096-byte sysmon stack */
/* ------------------------------------------------------------------ */

typedef struct {
    char  *p;
    size_t n, cap;
    bool   full;
} wb_t;

static void wb_c(wb_t *w, char c)
{
    if (w->n + 1 < w->cap)       /* one byte stays for the NUL */
        w->p[w->n++] = c;
    else
        w->full = true;
}

static void wb_s(wb_t *w, const char *s)
{
    while (*s)
        wb_c(w, *s++);
}

/* At least `digits` digits, zeros in front (at most 9 are asked for). */
static void wb_u(wb_t *w, uint32_t v, unsigned digits)
{
    char d[10];
    unsigned k = 0;
    do
    {
        d[k++] = (char)('0' + v % 10u);
        v /= 10u;
    } while (v || k < digits);
    while (k)
        wb_c(w, d[--k]);
}

static void wb_i(wb_t *w, int32_t v)
{
    if (v < 0)
        wb_c(w, '-');
    wb_u(w, v < 0 ? 0u - (uint32_t)v : (uint32_t)v, 1);
}

static size_t wb_end(wb_t *w)
{
    if (w->full)
    {
        w->p[0] = '\0';
        return 0;
    }
    w->p[w->n] = '\0';
    return w->n;
}

/* m x 10^e as the exact decimal it stands for, as cpm_rate_str on the page. its_decode.c hands
 * over -5..2 only, and anything else stays empty. */
static void wb_rate(wb_t *w, uint8_t m, int8_t e)
{
    if (e < -5 || e > 2)
        return;
    uint32_t div = 1;
    for (int i = 0; i < (e < 0 ? -e : e); i++)
        div *= 10u;
    if (e >= 0)
    {
        wb_u(w, m * div, 1);
        return;
    }
    unsigned digits = (unsigned)-e;
    uint32_t frac = m % div;
    wb_u(w, m / div, 1);
    if (!frac)
        return;
    for (; frac % 10u == 0; digits--)
        frac /= 10u;
    wb_c(w, '.');
    wb_u(w, frac, digits);
}

/* A spreadsheet takes a field starting with one of these for a formula. A leading ' stops it. */
static bool formula_start(uint8_t c)
{
    return c == '=' || c == '+' || c == '-' || c == '@' || c == '\'';
}

/* An air text as one quoted field, cleaned by the page's rule (add_text_utf8_n): broken pieces
 * and hidden characters, CR, LF and NUL included, become '?'. */
static void wb_text(wb_t *w, const char *t, size_t len)
{
    if (!len)
        return;
    wb_c(w, '"');
    for (size_t i = 0; i < len;)
    {
        const uint8_t *u = (const uint8_t *)t + i;
        uint8_t lo, hi;
        size_t wd = its_utf8_lead(u[0], &lo, &hi), got = 1;
        while (got < wd && got < len - i && u[got] >= (got == 1 ? lo : 0x80) &&
               u[got] <= (got == 1 ? hi : 0xBF))
            got++;
        bool ok = wd > 0 && got == wd && !its_utf8_unshown(its_utf8_cp(u, wd));
        if (i == 0 && ok && wd == 1 && formula_start(u[0]))
            wb_c(w, '\'');
        if (!ok)
            wb_c(w, '?');
        else
            for (size_t k = 0; k < wd; k++)
            {
                if (u[k] == '"')
                    wb_c(w, '"');
                wb_c(w, (char)u[k]);
            }
        i += got;
    }
    wb_c(w, '"');
}

static void wb_col(wb_t *w, const infolog_slot_t *s, const infolog_col_t *c)
{
    static const char *const WHY[] = { "", "minute", "new", "change", "hour" };
    static const char HEX[] = "0123456789abcdef";
    const uint8_t *b = (const uint8_t *)s, *v = b + c->off;
    if (c->pres != INFOLOG_ALWAYS && !(b[c->pres] & c->pres_mask))
        return;
    bool nz = (c->type & INFOLOG_T_NZ) != 0;
    uint16_t u16;
    uint32_t u32;
    int32_t i32;
    uint64_t u64;
    switch (c->type & INFOLOG_T_MASK)
    {
    case INFOLOG_T_U8:
        if (!nz || v[0])
            wb_u(w, v[0], 1);
        break;
    case INFOLOG_T_U16:
        memcpy(&u16, v, sizeof u16);
        if (!nz || u16)
            wb_u(w, u16, 1);
        break;
    case INFOLOG_T_U32:
        memcpy(&u32, v, sizeof u32);
        if (!nz || u32)
            wb_u(w, u32, 1);
        break;
    case INFOLOG_T_I8:
        if (!nz || v[0])
            wb_i(w, (int8_t)v[0]);
        break;
    case INFOLOG_T_I32:
        memcpy(&i32, v, sizeof i32);
        if (!nz || i32)
            wb_i(w, i32);
        break;
    case INFOLOG_T_BOOL:
        wb_c(w, v[0] ? '1' : '0');
        break;
    case INFOLOG_T_ITSMS:
        /* Two halves like jw_num in web_cpm.c: no 64-bit printf. A 42-bit TimestampIts ends
         * near 5.5e12 ms, so the high half stays far below 2^32. */
        memcpy(&u64, v, sizeof u64);
        if (nz && !u64)
            break;
        u64 = events_its_to_unix_ms(u64);
        if (u64 >= 1000000000u)
        {
            wb_u(w, (uint32_t)(u64 / 1000000000u), 1);
            wb_u(w, (uint32_t)(u64 % 1000000000u), 9);
        }
        else
            wb_u(w, (uint32_t)u64, 1);
        break;
    case INFOLOG_T_TXTZ:
        wb_text(w, (const char *)v, strnlen((const char *)v, c->aux));
        break;
    case INFOLOG_T_TXTN:
        wb_text(w, (const char *)v, b[c->aux] < ITS_POIM_TEXT ? b[c->aux] : ITS_POIM_TEXT);
        break;
    case INFOLOG_T_HHMM:
        wb_u(w, v[0], 2);
        wb_c(w, ':');
        wb_u(w, v[1], 2);
        break;
    case INFOLOG_T_RATE:
        wb_rate(w, v[0], (int8_t)b[c->aux]);
        break;
    case INFOLOG_T_LIST3:
        /* Spaces, because a spreadsheet reads "2/5" as a date. A leading '-' gets a ' in front,
         * as in a text, so it is no formula. */
        for (unsigned i = 0; i < b[c->aux] && i < 3; i++)
        {
            memcpy(&i32, v + 4 * i, sizeof i32);
            if (i)
                wb_c(w, ' ');
            else if (i32 < 0)
                wb_c(w, '\'');
            wb_i(w, i32);
        }
        break;
    case INFOLOG_T_VCLASS:
        /* Only a letter of the EU classes the decoder names: nothing else reaches the file. */
        if (v[0] && strchr("LMNOTG", v[0]))
        {
            wb_c(w, (char)v[0]);
            if (b[c->aux])
                wb_u(w, b[c->aux], 1);
        }
        break;
    case INFOLOG_T_MAPKIND:
        if (v[0])
            wb_c(w, b[c->aux] ? '1' : '2');
        break;
    case INFOLOG_T_MAC:
        for (unsigned i = 0; i < 6; i++)
        {
            if (i)
                wb_c(w, ':');
            wb_c(w, HEX[v[i] >> 4]);
            wb_c(w, HEX[v[i] & 15]);
        }
        break;
    case INFOLOG_T_WHY:
        if (v[0] < sizeof(WHY) / sizeof(WHY[0]))
            wb_s(w, WHY[v[0]]);
        break;
    default:
        break;
    }
}

size_t infolog_header(uint8_t kind, char *out, size_t cap)
{
    size_t n;
    const infolog_col_t *c = infolog_cols(kind, &n);
    if (!c || !out || !cap)
        return 0;
    wb_t w = { .p = out, .cap = cap };
    for (size_t i = 0; i < n; i++)
    {
        if (i)
            wb_c(&w, ',');
        wb_s(&w, c[i].name);
    }
    wb_c(&w, '\n');
    return wb_end(&w);
}

size_t infolog_format(const infolog_slot_t *s, char *out, size_t cap)
{
    size_t n;
    const infolog_col_t *c = s ? infolog_cols(s->kind, &n) : NULL;
    if (!c || !out || !cap)
        return 0;
    wb_t w = { .p = out, .cap = cap };
    for (size_t i = 0; i < n; i++)
    {
        if (i)
            wb_c(&w, ',');
        wb_col(&w, s, &c[i]);
    }
    wb_c(&w, '\n');
    return wb_end(&w);
}

/* ------------------------------------------------------------------ */
/*  The table                                                          */
/* ------------------------------------------------------------------ */

/* In PSRAM like inventory's table, so its 64 x 280 B put no load on the internal heap. */
static EXT_RAM_BSS_ATTR infolog_slot_t s_tab[INFOLOG_SLOTS];
static SemaphoreHandle_t s_lock;
/* Two writers (eviction on the sniffer task, failed appends on sysmon), one lockless reader:
 * __atomic keeps every add and the page's read whole. */
static uint32_t s_lost;
static uint32_t s_busy;          /* notes dropped because the lock was held; sniffer task only */
static uint32_t s_busy_log_s;    /* when that was last logged */

/* Tick state, sysmon task only. */
static uint32_t s_try_s[N_KINDS];    /* last append attempt per file */
static bool s_hdr_ok[N_KINDS];       /* first line checked; cleared by a missing card or a failure */
static uint8_t s_backoff_left, s_backoff_step;
/* A file whose first line or rotation failed waits alone, so it cannot hold the other three up. */
static uint8_t s_file_left[N_KINDS], s_file_step[N_KINDS];
static bool s_warn_armed = true;
/* One caller (the tick), so one copy each, off the stack. */
static EXT_RAM_BSS_ATTR infolog_slot_t s_snap;
static EXT_RAM_BSS_ATTR char s_line[INFOLOG_LINE_MAX];
static EXT_RAM_BSS_ATTR char s_first[INFOLOG_LINE_MAX];

void infolog_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

uint32_t infolog_lost(void)
{
    return __atomic_load_n(&s_lost, __ATOMIC_RELAXED);
}

/* Seconds from `then` to `now`. A clock that stepped back counts as long ago, so nothing waits
 * on a time that may not come again. */
static uint32_t since(uint32_t now, uint32_t then)
{
    return now >= then ? now - then : UINT32_MAX;
}

#define FNV_START 2166136261u

static inline uint32_t fnv(uint32_t h, const void *p, size_t n)
{
    const uint8_t *b = (const uint8_t *)p;
    while (n--)
        h = (h ^ *b++) * 16777619u;
    return h;
}

/* One sender may name several car parks or charging stations in turns. Keyed by the sender
 * alone, each would look like a change of the other. */
static uint32_t sub_key(uint8_t kind, const msg_extra_t *x)
{
    if (kind == 11)
        return x->evcsn_n_spots ? x->evcsn_st_id : 0;
    if (kind != 3)
        return 0;
    const its_poim_t *p = &x->poim;
    uint32_t h = FNV_START;
    if (p->has_mgmt)
    {
        h = fnv(h, &p->provider, sizeof p->provider);
        h = fnv(h, &p->country, sizeof p->country);
        return fnv(h, &p->entry, sizeof p->entry);
    }
    if (p->has_pos)
    {
        h = fnv(h, &p->lat_e7, sizeof p->lat_e7);
        return fnv(h, &p->lon_e7, sizeof p->lon_e7);
    }
    return 0;
}

/* Under the lock: this sender's EVCSN key heard last, NULL when it has none. */
static infolog_slot_t *newest_evcsn(uint32_t station)
{
    infolog_slot_t *best = NULL;
    for (int i = 0; i < INFOLOG_SLOTS; i++)
        if (s_tab[i].used && s_tab[i].kind == 11 && s_tab[i].station == station &&
            (!best || s_tab[i].last_s > best->last_s))
            best = &s_tab[i];
    return best;
}

/* What decides a 'change' row: everything but the sender's own timestamp, which moves with
 * every message. its_poim_t comes filled from zero, so its padding hashes the same each time. */
static uint32_t change_key(uint8_t kind, uint8_t version, bool read, const its_decoded_t *d,
                           const msg_extra_t *x)
{
    uint32_t h = fnv(FNV_START, &version, 1);
    h = fnv(h, &read, 1);
    if (kind == 3)
    {
        const size_t t = offsetof(its_poim_t, time_s), after = t + sizeof x->poim.time_s;
        h = fnv(h, &x->poim, t);
        return fnv(h, (const uint8_t *)&x->poim + after, sizeof x->poim - after);
    }
    const char *txt[3] = { x->evcsn_access, x->evcsn_hours, x->evcsn_price };
    h = fnv(h, &d->evcsn_poi_type, sizeof d->evcsn_poi_type);
    h = fnv(h, &x->evcsn_relay, 1);
    h = fnv(h, &x->evcsn_has_pos, 1);
    h = fnv(h, &x->evcsn_n_spots, 1);
    h = fnv(h, &x->evcsn_n_total, sizeof x->evcsn_n_total);
    h = fnv(h, &x->evcsn_n_stations, sizeof x->evcsn_n_stations);
    h = fnv(h, &x->evcsn_modes, sizeof x->evcsn_modes);
    h = fnv(h, &x->evcsn_st_id, sizeof x->evcsn_st_id);
    h = fnv(h, &x->evcsn_lat_e7, sizeof x->evcsn_lat_e7);
    h = fnv(h, &x->evcsn_lon_e7, sizeof x->evcsn_lon_e7);
    for (int i = 0; i < 3; i++)   /* with the NUL, so "ab"+"c" differs from "a"+"bc" */
        h = fnv(h, txt[i], strnlen(txt[i], ITS_EVCSN_TEXT) + 1);
    return h;
}

/* A row the key still owes the card: a CPM or RTCMEM window, a first or a changed EVCSN/POIM. */
static bool row_owed(const infolog_slot_t *s)
{
    if (!s->win)
        return false;
    return s->kind == 14 || s->kind == 13 || !s->row_wr_s || s->fp != s->row_fp;
}

/* Under the lock: the slot of this key, else a free one, else the one heard longest ago. */
static infolog_slot_t *slot_for(uint8_t kind, uint32_t station, uint32_t sub)
{
    infolog_slot_t *free_s = NULL, *old = NULL;
    for (int i = 0; i < INFOLOG_SLOTS; i++)
    {
        infolog_slot_t *s = &s_tab[i];
        if (!s->used)
        {
            if (!free_s)
                free_s = s;
            continue;
        }
        if (s->kind == kind && s->station == station && s->sub == sub)
            return s;
        if (!old || s->last_s < old->last_s)
            old = s;
    }
    infolog_slot_t *s = free_s ? free_s : old;
    /* Without a card nothing is being recorded, so nothing is lost (S_PRIO_NOSD says so). */
    if (!free_s && row_owed(old) && sdcard_is_mounted())
        __atomic_fetch_add(&s_lost, 1, __ATOMIC_RELAXED);
    memset(s, 0, sizeof *s);
    s->used = true;
    s->kind = kind;
    s->station = station;
    s->sub = sub;
    return s;
}

/* Under the lock: the newest content in place, straight from x and d (no copy on the stack). */
static void copy_content(infolog_slot_t *s, const its_decoded_t *d, const msg_extra_t *x)
{
    if (s->kind == 14)
    {
        infolog_cpm_t *c = &s->u.cpm;
        c->wrong_version = x->cpm_wrong_version;
        c->other_version = x->cpm_other_version;
        c->has_heading = x->cpm_has_heading;
        c->n_containers = x->cpm_n_containers;
        c->n_objects = x->cpm_n_objects;
        c->seg_this = x->cpm_seg_this;
        c->seg_total = x->cpm_seg_total;
        c->list_form = x->cpm_list_form;
        c->containers = x->cpm_containers;
        c->cont_bad = x->cpm_cont_bad;
        c->n_objects_here = x->cpm_n_objects_here;
        c->n_sensors = x->cpm_n_sensors;
        c->n_regions = x->cpm_n_regions;
        c->heading_ddeg = x->cpm_heading_ddeg;
        c->c = x->cpm;
    }
    else if (s->kind == 11)
    {
        infolog_evcsn_t *e = &s->u.evcsn;
        e->relay = x->evcsn_relay;
        /* Without its spots the page shows no place of the station, so the file does not either. */
        e->has_pos = x->evcsn_has_pos && x->evcsn_n_spots;
        e->n_spots = x->evcsn_n_spots;
        e->poi_type = d->evcsn_poi_type;
        e->n_total = x->evcsn_n_total;
        e->n_stations = x->evcsn_n_stations;
        e->modes = x->evcsn_modes;
        e->st_id = x->evcsn_st_id;
        e->lat_e7 = x->evcsn_lat_e7;
        e->lon_e7 = x->evcsn_lon_e7;
        e->ts_ms = d->evcsn_ts_ms;
        memcpy(e->access, x->evcsn_access, sizeof e->access);
        memcpy(e->hours, x->evcsn_hours, sizeof e->hours);
        memcpy(e->price, x->evcsn_price, sizeof e->price);
    }
    else if (s->kind == 3)
        s->u.poim = x->poim;
    else if (!x->rtcm_n_msgs)
        /* The page says nothing of an RTCMEM without corrections, so the file does not either. */
        memset(&s->u.rtcm, 0, sizeof s->u.rtcm);
    else
    {
        infolog_rtcm_t *r = &s->u.rtcm;
        r->msg_cnt = x->rtcm_msg_cnt;
        r->rev = x->rtcm_rev;
        r->n_msgs = x->rtcm_n_msgs;
        r->status = x->rtcm_status;
        r->has_status = x->rtcm_has_status;
        r->has_minute = x->rtcm_has_minute;
        r->has_anchor = x->rtcm_has_anchor;
        r->has_elev = x->rtcm_has_elev;
        r->bytes = x->rtcm_bytes;
        r->minute = x->rtcm_minute;
        r->lat_e7 = x->rtcm_lat_e7;
        r->lon_e7 = x->rtcm_lon_e7;
        r->elev_dm = x->rtcm_elev_dm;
    }
}

void infolog_note(uint32_t seconds, int rssi, const uint8_t *mac, const its_decoded_t *d,
                  const msg_extra_t *x, uint32_t pdu_station)
{
    /* Before the clock is set, a time would be seconds since boot, so the message is skipped. */
    if (!s_lock || !d || !x || seconds < EVENTS_CLOCK_MIN)
        return;
    uint8_t kind = its_msg_kind(d->pdu_version, d->message_id);
    if (kind != 14 && kind != 11 && kind != 3 && kind != 13)
        return;
    bool read = kind == 14 ? x->cpm_read : kind == 11 ? x->evcsn_read :
                kind == 3 ? x->poim.read : x->rtcm_n_msgs > 0;
    /* The header's stationId: d->station_id stays 0 whenever the frame has no usable position. */
    uint32_t station = pdu_station ? pdu_station : d->station_id;
    uint32_t sub = sub_key(kind, x);
    uint32_t fp = (kind == 11 || kind == 3) ? change_key(kind, d->pdu_version, read, d, x) : 0;
    int8_t r = (rssi < 0 && rssi > -128) ? (int8_t)rssi : 0;   /* 0 = no RF reading */
    /* A forwarder's level and MAC are not the sender's: a relayed frame keeps the row's. */
    bool direct = its_gn_hops(&x->gn) <= 0;

    /* Timeout 0: the sniffer never waits. The tick and the page hold the lock for copies only. */
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
    {
        s_busy++;
        if (since(seconds, s_busy_log_s) >= 60)
        {
            s_busy_log_s = seconds;
            ESP_LOGW(TAG, "table busy, %lu messages not counted since boot", (unsigned long)s_busy);
        }
        return;
    }
    /* An EVCSN without spots names no charging station. It counts with this sender's EVCSN key
     * heard last, not as a key (station, 0) whose row would say nothing. A named station's
     * content stays as it is. */
    infolog_slot_t *s = kind == 11 && !x->evcsn_n_spots ? newest_evcsn(station) : NULL;
    bool count_only = s && s->u.evcsn.n_spots;
    if (!s)
        s = slot_for(kind, station, sub);
    s->total++;
    if (!s->win)
        s->first_s = seconds;
    s->win++;
    s->last_s = seconds;
    if (direct)
    {
        s->rssi = r;
        if (r && (!s->rssi_min || r < s->rssi_min))
            s->rssi_min = r;
        if (r && (!s->rssi_max || r > s->rssi_max))
            s->rssi_max = r;
        s->has_mac = mac != NULL;
        if (mac)
            memcpy(s->mac, mac, sizeof s->mac);
        else
            memset(s->mac, 0, sizeof s->mac);
    }
    if (!count_only)
    {
        s->version = d->pdu_version;
        s->read = read;
        s->fp = fp;
        copy_content(s, d, x);
    }
    if (kind == 14 && read)
    {
        s->obj_seen = true;
        if (x->cpm_n_objects > s->obj_max)
            s->obj_max = x->cpm_n_objects;
    }
    xSemaphoreGive(s_lock);
}

int infolog_snapshot(infolog_slot_t *out, int max)
{
    if (!s_lock || !out || max <= 0)
        return 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return -1;
    uint64_t taken = 0;
    int n = 0;
    for (; n < max; n++)
    {
        int best = -1;
        for (int i = 0; i < INFOLOG_SLOTS; i++)
            if (s_tab[i].used && !((taken >> i) & 1u) &&
                (best < 0 || s_tab[i].last_s > s_tab[best].last_s))
                best = i;
        if (best < 0)
            break;
        taken |= 1ull << best;
        out[n] = s_tab[best];
    }
    xSemaphoreGive(s_lock);
    return n;
}

void infolog_to_extra(const infolog_slot_t *s, msg_extra_t *x)
{
    if (!x)
        return;
    memset(x, 0, sizeof *x);
    if (!s)
        return;
    x->message_id = s->kind;
    if (s->kind == 14)
    {
        const infolog_cpm_t *c = &s->u.cpm;
        x->cpm_read = s->read;
        x->cpm_wrong_version = c->wrong_version;
        x->cpm_other_version = c->other_version;
        x->cpm_has_heading = c->has_heading;
        x->cpm_n_containers = c->n_containers;
        x->cpm_n_objects = c->n_objects;
        x->cpm_seg_this = c->seg_this;
        x->cpm_seg_total = c->seg_total;
        x->cpm_list_form = c->list_form;
        x->cpm_containers = c->containers;
        x->cpm_cont_bad = c->cont_bad;
        x->cpm_n_objects_here = c->n_objects_here;
        x->cpm_n_sensors = c->n_sensors;
        x->cpm_n_regions = c->n_regions;
        x->cpm_heading_ddeg = c->heading_ddeg;
        x->cpm = c->c;
    }
    else if (s->kind == 11)
    {
        const infolog_evcsn_t *e = &s->u.evcsn;
        x->evcsn_read = s->read;
        x->evcsn_relay = e->relay;
        x->evcsn_has_pos = e->has_pos;
        x->evcsn_n_spots = e->n_spots;
        x->evcsn_n_total = e->n_total;
        x->evcsn_n_stations = e->n_stations;
        x->evcsn_modes = e->modes;
        x->evcsn_st_id = e->st_id;
        x->evcsn_lat_e7 = e->lat_e7;
        x->evcsn_lon_e7 = e->lon_e7;
        memcpy(x->evcsn_access, e->access, sizeof x->evcsn_access);
        memcpy(x->evcsn_hours, e->hours, sizeof x->evcsn_hours);
        memcpy(x->evcsn_price, e->price, sizeof x->evcsn_price);
    }
    else if (s->kind == 3)
        x->poim = s->u.poim;
    else if (s->kind == 13)
    {
        const infolog_rtcm_t *r = &s->u.rtcm;
        x->rtcm_msg_cnt = r->msg_cnt;
        x->rtcm_rev = r->rev;
        x->rtcm_n_msgs = r->n_msgs;
        x->rtcm_status = r->status;
        x->rtcm_has_status = r->has_status;
        x->rtcm_has_minute = r->has_minute;
        x->rtcm_has_anchor = r->has_anchor;
        x->rtcm_has_elev = r->has_elev;
        x->rtcm_bytes = r->bytes;
        x->rtcm_minute = r->minute;
        x->rtcm_lat_e7 = r->lat_e7;
        x->rtcm_lon_e7 = r->lon_e7;
        x->rtcm_elev_dm = r->elev_dm;
    }
}

/* ------------------------------------------------------------------ */
/*  The tick: rows to the card                                         */
/* ------------------------------------------------------------------ */

/* Why a row is due now, 0 if it is not. No row without messages since the last one. */
static uint8_t due_why(const infolog_slot_t *s, uint32_t now)
{
    if (!s->used || !s->win)
        return 0;
    if (s->kind == 14 || s->kind == 13)
        return since(now, s->first_s) >= INFOLOG_EVERY_S ? INFOLOG_WHY_MINUTE : 0;
    if (!s->row_wr_s)
        return INFOLOG_WHY_NEW;
    /* Against the last WRITTEN key, so a flip back within the gap writes nothing. */
    uint32_t gap = since(now, s->row_wr_s);
    if (s->fp != s->row_fp && gap >= INFOLOG_GAP_S)
        return INFOLOG_WHY_CHANGE;
    return gap >= INFOLOG_HOUR_S ? INFOLOG_WHY_HOUR : 0;
}

/* A bit mask of the files that have a due row, whose last attempt is INFOLOG_APPEND_S or more
 * ago and that wait for no failure of their own. The time is read under the lock: every note
 * that opened a window before saw no later second. */
static unsigned due_kinds(void)
{
    unsigned m = 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return 0;
    uint32_t now = (uint32_t)time(NULL);
    for (unsigned k = 0; k < N_KINDS; k++)
    {
        if (since(now, s_try_s[k]) < INFOLOG_APPEND_S)
            continue;
        if (s_file_left[k])
            continue;
        for (int i = 0; i < INFOLOG_SLOTS; i++)
            if (s_tab[i].kind == KINDS[k].kind && due_why(&s_tab[i], now))
            {
                m |= 1u << k;
                break;
            }
    }
    xSemaphoreGive(s_lock);
    return m;
}

/* Takes slot i's row into s_snap and closes its window: from here the row is written at most
 * once, whatever happens to the file. 1 taken, 0 not due, -1 lock busy. */
static int take_row(int i, uint8_t kind)
{
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return -1;
    infolog_slot_t *s = &s_tab[i];
    uint32_t now = (uint32_t)time(NULL);
    uint8_t why = s->kind == kind ? due_why(s, now) : 0;
    if (why)
    {
        s_snap = *s;
        s_snap.why = why;
        s->win = 0;
        s->first_s = 0;
        s->obj_max = 0;
        s->obj_seen = false;
        s->rssi_min = s->rssi_max = 0;
        s->row_fp = s->fp;
        s->row_wr_s = now;
    }
    xSemaphoreGive(s_lock);
    return why ? 1 : 0;
}

/* AP_FAIL: the card failed and every file waits. AP_FILE: only this file waits, because a read
 * of it or its rotation failed or its name was refused. AP_WAIT: nothing written, no verdict. */
enum { AP_OK, AP_WAIT, AP_FAIL, AP_FILE };

/* A row cut by power or a card error (FatFs keeps what a failed write got out) is removed.
 * While a download holds the file, or with no '\n' in the look-back, the row is only ended,
 * with '"\n' in a quoted text. */
static int mend_tail(FILE *f, long size, const char **fail)
{
    char last;
    long back = size < INFOLOG_LINE_MAX ? size : INFOLOG_LINE_MAX, i;
    unsigned quotes = 0;
    *fail = "read";
    if (fseek(f, size - 1, SEEK_SET) != 0 || fread(&last, 1, 1, f) != 1)
        return AP_FILE;
    if (last == '\n')
        return AP_OK;
    if (fseek(f, size - back, SEEK_SET) != 0 || fread(s_first, 1, (size_t)back, f) != (size_t)back)
        return AP_FILE;
    for (i = back - 1; i >= 0 && s_first[i] != '\n'; i--)
        quotes += s_first[i] == '"';
    if (i >= 0 && sdcard_read_active() == 0)
    {
        /* FS_LOCK=0: no truncation under a download. fflush first: picolibc seeks back over what
         * fread buffered, and after the cut that seek could make FatFs grow the file again. */
        *fail = "mend";
        return fflush(f) == 0 && ftruncate(fileno(f), (off_t)(size - back + i + 1)) == 0 ? AP_OK : AP_FAIL;
    }
    /* 'a+' reads and writes one FILE: C wants a positioning call between the two. */
    if (fseek(f, 0, SEEK_END) != 0)
        return AP_FILE;
    *fail = "mend";
    return fputs(quotes & 1u ? "\"\n" : "\n", f) != EOF ? AP_OK : AP_FAIL;
}

/* <kind>.csv becomes <kind>.1.csv, like system.log: a rename, never a rewrite. A missing .1 is
 * fine. A cut between remove and rename leaves <kind>.csv, which the next open rotates. */
static bool rotate_file(const il_kind_t *kd)
{
    remove(kd->old);
    return rename(kd->csv, kd->old) == 0;
}

/* EACCES, EEXIST, EISDIR: FatFs refused this name (a directory or read-only file of that name), so
 * it waits alone. Any other failed open is the card's. */
static FILE *open_csv(const il_kind_t *kd, int *r, const char **fail)
{
    errno = 0;                   /* mkdir leaves EEXIST behind */
    FILE *f = fopen(kd->csv, "a+");
    *fail = "open";
    *r = f ? AP_OK : errno == EACCES || errno == EEXIST || errno == EISDIR ? AP_FILE : AP_FAIL;
    return f;
}

/* <kind>.csv open for appending, with our header first and a whole last line. Nothing is taken
 * from the table here, so any failure is tried again later. */
static int open_kind(unsigned k, FILE **out, const char **fail)
{
    const il_kind_t *kd = &KINDS[k];
    int r;
    mkdir(INFOLOG_DIR, 0777);
    FILE *f = open_csv(kd, &r, fail);
    if (!f)
        return r;
    long size = fseek(f, 0, SEEK_END) == 0 ? ftell(f) : -1;
    bool rotate = size >= (long)INFOLOG_FILE_CAP, drop = false;
    if (size > 0 && !rotate && !s_hdr_ok[k])
    {
        /* picolibc's fgets hands back what came before a read error, and poim's 555-B header
         * spans two sectors: a cut read is a failed read, not a foreign first line. */
        if (fseek(f, 0, SEEK_SET) != 0 || !fgets(s_first, sizeof s_first, f) || ferror(f) ||
            !infolog_header(kd->kind, s_line, sizeof s_line))
            size = -1;
        else if (strcmp(s_first, s_line) == 0)
            s_hdr_ok[k] = true;
        else
        {
            /* A foreign first line moves to .1. A file that is nothing but a cut header of
             * ours is removed instead, so it cannot push a full .1 out. */
            size_t fl = strlen(s_first);
            rotate = true;
            drop = (size_t)size == fl && strncmp(s_first, s_line, fl) == 0;
        }
    }
    if (size < 0)
    {
        /* Its size or its first line could not be read: this file waits alone. */
        fclose(f);
        *fail = "read";
        return AP_FILE;
    }
    if (rotate)
    {
        fclose(f);
        /* FATFS has FS_LOCK=0: no unlink while a download streams a file. */
        if (sdcard_read_active() != 0)
            return AP_WAIT;
        if (drop ? remove(kd->csv) != 0 : !rotate_file(kd))
        {
            *fail = "rotate";
            return AP_FILE;
        }
        f = open_csv(kd, &r, fail);
        if (!f)
            return r;
        size = 0;
    }
    if (size == 0)
    {
        if (!infolog_header(kd->kind, s_line, sizeof s_line) || fputs(s_line, f) == EOF)
        {
            fclose(f);
            *fail = "header";
            return AP_FAIL;
        }
        s_hdr_ok[k] = true;
    }
    else if ((r = mend_tail(f, size, fail)) != AP_OK)
    {
        fclose(f);
        return r;
    }
    /* 'a+' reads and writes one FILE: C wants a positioning call between the two. */
    if (fseek(f, 0, SEEK_END) != 0)
    {
        fclose(f);
        *fail = "seek";
        return AP_FAIL;
    }
    *out = f;
    return AP_OK;
}

/* All due rows of one file in one fopen. A taken row reaches the card at most once. Counted lost
 * once each: the row whose fputs or fflush failed (the append ends there), every row of a failed
 * fclose (an upper bound: FatFs may still write them), none when only ftell failed. */
static int append_kind(unsigned k, const char **fail)
{
    const il_kind_t *kd = &KINDS[k];
    s_try_s[k] = (uint32_t)time(NULL);
    FILE *f = NULL;
    int r = open_kind(k, &f, fail);
    if (r != AP_OK)
        return r;
    uint32_t sent = 0;
    bool put_failed = false;
    for (int i = 0; i < INFOLOG_SLOTS && !put_failed; i++)
    {
        int t = take_row(i, kd->kind);
        if (t < 0)
            break;
        if (!t)
            continue;
        if (!infolog_format(&s_snap, s_line, sizeof s_line))
        {
            /* Only a stale INFOLOG_LINE_MAX gets here. */
            __atomic_fetch_add(&s_lost, 1, __ATOMIC_RELAXED);
            ESP_LOGE(TAG, "%s row wider than %u B, lost", kd->csv, (unsigned)INFOLOG_LINE_MAX);
            continue;
        }
        sent++;
        /* picolibc drops its whole 128-B buffer when a write fails, an earlier row's tail with it,
         * and fclose hides a failed flush: row by row, a failure costs this row and shows here. */
        put_failed = fputs(s_line, f) == EOF || fflush(f) != 0;
    }
    /* Nothing is buffered here, so ftell only reads picolibc's position. The check for -1
     * stays as a guard. */
    long end = ftell(f);
    if (fclose(f) != 0)
    {
        __atomic_fetch_add(&s_lost, sent, __ATOMIC_RELAXED);
        *fail = "close";
        return AP_FAIL;
    }
    if (put_failed)
    {
        __atomic_fetch_add(&s_lost, 1, __ATOMIC_RELAXED);
        *fail = "write";
        return AP_FAIL;
    }
    if (end < 0)
    {
        *fail = "tell";
        return AP_FAIL;
    }
    /* Size, not days. Should the rename fail, the next open rotates before it appends. */
    if (end >= (long)INFOLOG_FILE_CAP && sdcard_read_active() == 0)
        (void)rotate_file(kd);
    /* No row written (the table stayed busy): this file's back-off and the warnings stay as they are. */
    return sent ? AP_OK : AP_WAIT;
}

/* 30 s, 1, 2, 4, 8 min at the 5-s tick: a dead card, or one file that keeps failing, costs 11
 * attempts in its first hour. */
static uint8_t backoff_next(uint8_t step)
{
    return !step ? INFOLOG_BACKOFF_MIN : step >= INFOLOG_BACKOFF_MAX / 2 ? INFOLOG_BACKOFF_MAX :
           (uint8_t)(step * 2);
}

/* One file failed on its own: it alone waits, with one warning per streak of failures. */
static void file_failed(unsigned k, const char *why)
{
    if (!s_file_step[k])
        ESP_LOGW(TAG, "%s: %s failed, this file tries again later (%lu rows lost since boot)",
                 KINDS[k].csv, why, (unsigned long)infolog_lost());
    s_file_step[k] = backoff_next(s_file_step[k]);
    s_file_left[k] = s_file_step[k];
    s_hdr_ok[k] = false;
}

void infolog_tick(void)
{
    if (!s_lock || (uint32_t)time(NULL) < EVENTS_CLOCK_MIN)
        return;
    for (unsigned k = 0; k < N_KINDS; k++)
        if (s_file_left[k])
            s_file_left[k]--;
    /* The tick that counts down to 0 tries again: 6 ticks are 30 s, as for one file. */
    if (s_backoff_left && --s_backoff_left)
        return;
    /* No card: the SD lock is not taken at all. The windows grow, and the first append covers
     * the gap. A card put back in may hold edited files, so their first line is checked again. */
    if (!sdcard_is_mounted())
    {
        memset(s_hdr_ok, 0, sizeof s_hdr_ok);
        return;
    }
    unsigned kinds = due_kinds();
    if (!kinds)
        return;              /* nothing due: the SD lock stays untouched */
    /* A card-wide failure ends the loop. A failure of one file holds up only that file. */
    const char *fail = NULL, *where = INFOLOG_DIR, *file_why[N_KINDS] = { NULL };
    bool wrote = false;
    if (!sdcard_io_begin_timeout(2000))
        fail = "lock";
    else
    {
        for (unsigned k = 0; k < N_KINDS && !fail; k++)
        {
            if (!(kinds & (1u << k)))
                continue;
            const char *why = NULL;
            int r = append_kind(k, &why);
            if (r == AP_OK)
            {
                wrote = true;
                s_file_step[k] = 0;
            }
            else if (r == AP_FILE)
                file_why[k] = why;
            else if (r == AP_FAIL)
            {
                fail = why;
                where = KINDS[k].csv;
            }
        }
        sdcard_io_end();
    }
    for (unsigned k = 0; k < N_KINDS; k++)
        if (file_why[k])
            file_failed(k, file_why[k]);
    if (!fail)
    {
        s_backoff_step = 0;
        if (wrote)
            s_warn_armed = true;
        return;
    }
    s_backoff_step = backoff_next(s_backoff_step);
    s_backoff_left = s_backoff_step;
    /* A failed close may have left only part of a header we wrote: read the first lines again. */
    memset(s_hdr_ok, 0, sizeof s_hdr_ok);
    if (s_warn_armed)
    {
        s_warn_armed = false;
        ESP_LOGW(TAG, "%s: %s failed on the card, trying again later (%lu rows lost since boot)",
                 where, fail, (unsigned long)infolog_lost());
    }
}

#else  /* !CONFIG_ENABLE_SD: no card, so no table and no page */

void infolog_init(void) { }

void infolog_note(uint32_t seconds, int rssi, const uint8_t *mac, const its_decoded_t *d,
                  const msg_extra_t *x, uint32_t pdu_station)
{
    (void)seconds; (void)rssi; (void)mac; (void)d; (void)x; (void)pdu_station;
}

void infolog_tick(void) { }

int infolog_snapshot(infolog_slot_t *out, int max)
{
    (void)out;
    (void)max;
    return 0;
}

uint32_t infolog_lost(void)
{
    return 0;
}

void infolog_to_extra(const infolog_slot_t *s, msg_extra_t *x)
{
    (void)s;
    if (x)
        memset(x, 0, sizeof *x);
}

const infolog_col_t *infolog_cols(uint8_t kind, size_t *n)
{
    (void)kind;
    if (n)
        *n = 0;
    return NULL;
}

size_t infolog_header(uint8_t kind, char *out, size_t cap)
{
    (void)kind;
    if (out && cap)
        out[0] = '\0';
    return 0;
}

size_t infolog_format(const infolog_slot_t *s, char *out, size_t cap)
{
    (void)s;
    if (out && cap)
        out[0] = '\0';
    return 0;
}

#endif
