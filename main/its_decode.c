#include "its_decode.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <math.h>

#define ETHERTYPE_GEONET 0x8947u
#define ETHERTYPE_IPV6   0x86DDu
#define ETHERTYPE_WSMP   0x88DCu

static uint16_t rd_u16be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t rd_u32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* Reads nbits (1..32) at absolute bit offset bitoff, MSB-first (UPER
 * bit-packing) -- the only bit-level reader needed, since everything else in
 * this file is fixed-shape byte-aligned binary. Returns false if the read
 * would run past len*8 or nbits is out of range. */
static bool read_bits_msb(const uint8_t *frame, size_t len, size_t bitoff,
                           unsigned nbits, uint32_t *out)
{
    if (nbits == 0 || nbits > 32) return false;
    if (bitoff + nbits > len * 8) return false;
    uint32_t v = 0;
    for (unsigned i = 0; i < nbits; i++)
    {
        size_t bit = bitoff + i;
        uint8_t byte = frame[bit / 8];
        unsigned shift = 7 - (unsigned)(bit % 8);
        v = (v << 1) | ((byte >> shift) & 1u);
    }
    *out = v;
    return true;
}

/* 802.11 MAC header length for the common ITS-G5 case: Data/QoS Data, OCB
 * mode (ToDS=0, FromDS=0, no HT Control). Returns 0 for anything else so the
 * caller bails out rather than mis-parse. */
static size_t mac80211_header_len(const uint8_t *f, size_t len)
{
    if (len < 24)
        return 0;
    uint8_t fc0 = f[0], fc1 = f[1];
    uint8_t type = (fc0 >> 2) & 0x3;
    bool to_ds   = (fc1 & 0x01) != 0;
    bool from_ds = (fc1 & 0x02) != 0;
    bool order   = (fc1 & 0x80) != 0;
    if (type != 2 /* Data */ || to_ds || from_ds || order)
        return 0;
    bool qos = ((fc0 >> 4) & 0x8) != 0;
    size_t hlen = qos ? 26 : 24;
    return len >= hlen ? hlen : 0;
}

typedef struct { uint8_t id; const char *name; } msgid_name_t;

/* ITS PDU header "messageId" -> facility message name (ETSI TS 102 894-2
 * registry, matches Wireshark's its.messageId). rfu1(7)/rfu2(8) reserved,
 * intentionally absent. */
static const msgid_name_t MSGID_NAMES[] = {
    { 1,  "DENM" },   { 2,  "CAM" },    { 3,  "POIM" },  { 4,  "SPATEM" },
    { 5,  "MAPEM" },  { 6,  "IVIM" },   { 9,  "SREM" },  { 10, "SSEM" },
    { 11, "EVCSN" },  { 12, "SAEM" },   { 13, "RTCMEM" },{ 14, "CPM" },
    { 15, "IMZM" },   { 16, "VAM" },    { 17, "DSM" },   { 18, "PCIM" },
    { 19, "PCVM" },   { 20, "MCM" },    { 21, "PAM" },
};

static const char *lookup_msgid_name(uint8_t id)
{
    for (size_t i = 0; i < sizeof(MSGID_NAMES) / sizeof(MSGID_NAMES[0]); i++)
        if (MSGID_NAMES[i].id == id)
            return MSGID_NAMES[i].name;
    return NULL;
}

/* GeoNetworking Common Header "header type" -> extended header length (ETSI
 * EN 302 636-4-1). GeoBroadcast/-Anycast carry a leading 4-byte sequence-
 * number+reserved field before the position vector -- easy to miss, this
 * was wrong at 40 instead of 44 once already. -1 = not handled here. */
static int gn_ext_header_len(uint8_t header_type)
{
    switch (header_type)
    {
    case 1: return 24;  /* Beacon: Source LongPV only, nothing follows */
    case 2: return 44;  /* GeoUnicast */
    case 3: return 44;  /* GeoAnycast: SN+Reserved(4) + Source LongPV(24) + Geo-Area(16) */
    case 4: return 44;  /* GeoBroadcast: SN+Reserved(4) + Source LongPV(24) + Geo-Area(16) */
    case 5: return 28;  /* TSB, single- or multi-hop */
    default: return -1; /* Location Service (6) and anything else */
    }
}

typedef struct { uint8_t code; const char *name; } station_type_name_t;

/* GeoNetworking GN_ADDR "ITS-S type" (5 bits, first byte of the Source
 * Position Vector). Matches Wireshark's geonw.src_pos.addr.type; unlisted
 * values fall back to no label. */
static const station_type_name_t STATION_TYPES[] = {
    { 1,  "Ped" },       { 2,  "Cyclist" },  { 3,  "Moped" },
    { 4,  "Motorcycle" },{ 5,  "Car" },      { 6,  "Bus" },
    { 7,  "LTruck" },    { 8,  "HTruck" },   { 9,  "Trailer" },
    { 10, "Special" },   { 11, "Tram" },     { 15, "RSU" },
};

static const char *lookup_station_name(uint8_t t)
{
    for (size_t i = 0; i < sizeof(STATION_TYPES) / sizeof(STATION_TYPES[0]); i++)
        if (STATION_TYPES[i].code == t)
            return STATION_TYPES[i].name;
    return NULL; /* 0 = unknown, or a value we don't have a name for */
}

/* Parses a GeoNetworking "Common Header onward" (Common Header + extended
 * header + BTP-B + facility message), starting at `off` in `frame`. Used
 * both on unsecured GN packets and on the structure re-embedded inside a
 * Secured Packet (see unwrap_secured) -- same shape either way. Outputs:
 * station name (or NULL), the ITS PDU header's byte offset (SIZE_MAX if
 * unreached), and the Source Position Vector's byte offset (SIZE_MAX if this
 * header type doesn't carry one) -- both needed again by its_decode_frame,
 * kept in one traversal rather than walked twice. */
static void parse_common_onward(const uint8_t *frame, size_t len, size_t off,
                                 char *out, size_t out_size, const char **station_out,
                                 size_t *pdu_off_out, size_t *pv_off_out)
{
    *station_out = NULL;
    *pdu_off_out = SIZE_MAX;
    *pv_off_out = SIZE_MAX;
    if (len < off + 8) { snprintf(out, out_size, "?"); return; }
    uint8_t common_nh   = (frame[off]     >> 4) & 0x0F;
    uint8_t header_type = (frame[off + 1] >> 4) & 0x0F;
    off += 8;

    if (header_type == 1)
    {
        /* Beacon: still carries a Source Position Vector (station type is
         * readable) but no facility payload follows. */
        if (len >= off + 1)
        {
            *station_out = lookup_station_name((frame[off] >> 2) & 0x1F);
            *pv_off_out = off;
        }
        snprintf(out, out_size, "GeoNet-Beacon");
        return;
    }
    int ext_len = gn_ext_header_len(header_type);
    if (ext_len < 0) { snprintf(out, out_size, "GeoNet-LS"); return; }
    if (len < off + (size_t)ext_len) { snprintf(out, out_size, "?"); return; }

    /* GeoUnicast/TSB start with the Source Position Vector directly;
     * GeoAnycast/GeoBroadcast lead with a 4-byte sequence-number+reserved
     * field first (see gn_ext_header_len). */
    size_t pv_off = (header_type == 3 || header_type == 4) ? off + 4 : off;
    *station_out = lookup_station_name((frame[pv_off] >> 2) & 0x1F);
    *pv_off_out = pv_off;
    off += (size_t)ext_len;

    if (common_nh == 2) /* BTP-B: destination port is the first 2 bytes */
    {
        if (len < off + 2) { snprintf(out, out_size, "GeoNet"); return; }
        uint16_t port = rd_u16be(frame + off);
        /* ITS PDU header starts right after the 4-byte BTP-B header;
         * reported regardless of whether a name is found, so
         * its_decode_frame can look further into the body without redoing
         * this walk. Falls back to the raw port if messageId isn't in the
         * table. */
        if (len >= off + 6) *pdu_off_out = off + 4;
        const char *name = (len >= off + 6) ? lookup_msgid_name(frame[off + 5]) : NULL;
        if (name) snprintf(out, out_size, "%s", name);
        else      snprintf(out, out_size, "GeoNet:%u", (unsigned)port);
    }
    else if (common_nh == 1) { snprintf(out, out_size, "BTP-A"); }
    else if (common_nh == 3) { snprintf(out, out_size, "IPv6-GN"); }
    else                     { snprintf(out, out_size, "GeoNet"); }
}

/* Reads a COER length determinant (ITU-T X.696 clause 8.6) at frame[off]:
 * short form (top bit clear) is the length directly, in that one byte; long
 * form (top bit set) gives, in the low 7 bits, how many following big-endian
 * octets encode the actual length. Returns false if there isn't room, or the
 * encoded length needs an implausible number of octets (defends against a
 * corrupt or crafted frame; real messages need at most 2). */
static bool read_oer_length(const uint8_t *frame, size_t len, size_t off,
                             size_t *value_len, size_t *field_len)
{
    if (off >= len) return false;
    uint8_t b0 = frame[off];
    if ((b0 & 0x80) == 0)
    {
        *value_len = b0;
        *field_len = 1;
        return true;
    }
    size_t n = b0 & 0x7F;
    if (n == 0 || n > 4 || off + 1 + n > len)
        return false;
    size_t v = 0;
    for (size_t i = 0; i < n; i++)
        v = (v << 8) | frame[off + 1 + i];
    *value_len = v;
    *field_len = 1 + n;
    return true;
}

/* --- SPATEM (SAE J2735 SPAT) UPER decode, scope B ------------------------
 * A running MSB-first bit cursor over the frame (bounded by `nbits`), used
 * only here -- SPAT is deeply bit-packed with variable-length inner lists, so
 * a stateful cursor reads far cleaner than absolute-offset read_bits_msb
 * calls. `err` latches once a read runs past the end. Bit layout validated
 * against real traffic (445/445 sampled frames) -- see reference-its-decode
 * in project memory before touching any field width. */
typedef struct { const uint8_t *b; size_t nbits, pos; bool err; } spat_bitr_t;

static uint32_t sb(spat_bitr_t *r, unsigned n)
{
    uint32_t v = 0;
    for (unsigned i = 0; i < n; i++)
    {
        if (r->pos >= r->nbits) { r->err = true; return v; }
        v = (v << 1) | ((r->b[r->pos >> 3] >> (7 - (r->pos & 7))) & 1u);
        r->pos++;
    }
    return v;
}

/* TimeChangeDetails: opt{startTime,maxEndTime,likelyTime,confidence,nextTime}
 * (5b) + mandatory minEndTime; TimeMark=16b, confidence=4b. Must be fully
 * consumed either way to keep the cursor aligned -- amber / pre-movement
 * events carry it. Returns minEndTime (TimeMark, tenths of a second within
 * the current hour; 36001 = unknown). */
static uint32_t spat_read_time_change(spat_bitr_t *r)
{
    uint32_t o = sb(r, 5);
    if (o & 0x10) sb(r, 16);          /* startTime */
    uint32_t min_end = sb(r, 16);     /* minEndTime (mandatory) */
    if (o & 0x08) sb(r, 16);          /* maxEndTime */
    if (o & 0x04) sb(r, 16);          /* likelyTime */
    if (o & 0x02) sb(r, 4);           /* confidence */
    if (o & 0x01) sb(r, 16);          /* nextTime */
    return min_end;
}

/* AdvisorySpeedList (rare here): consume to stay aligned. */
static void spat_skip_speeds(spat_bitr_t *r)
{
    uint32_t n = sb(r, 4) + 1;
    for (uint32_t i = 0; i < n && !r->err; i++)
    {
        sb(r, 1);                 /* ext */
        uint32_t o = sb(r, 4);
        sb(r, 2);                 /* type */
        if (o & 0x8) sb(r, 13);
        if (o & 0x4) sb(r, 3);
        if (o & 0x2) sb(r, 16);
        if (o & 0x1) sb(r, 8);
    }
}

/* One ConnectionManeuverAssist (per-movement maneuverAssistList is variable-
 * length and must be fully walked to reach the next movement). */
static void spat_skip_conn_maneuver(spat_bitr_t *r)
{
    sb(r, 1);                     /* ext */
    uint32_t o = sb(r, 5);
    sb(r, 8);                     /* connectionID */
    if (o & 0x10) sb(r, 8);
    if (o & 0x08) sb(r, 8);
    if (o & 0x04) sb(r, 1);
    if (o & 0x02) sb(r, 1);
}

/* Parse a SPAT message starting at bit `start` (= (pdu_off+6)*8, right after
 * the 6-byte ItsPduHeader) into `out`. Only the first IntersectionState is
 * decoded (every observed SPATEM carries exactly one). Optional fields not
 * seen in real traffic (SPAT name/regional, enabledLanes, per-movement/event
 * regional) cause a clean abort (out->valid stays false) rather than a guess. */
static void parse_spatem(const uint8_t *frame, size_t len, size_t start,
                         its_spat_t *out)
{
    out->valid = false;
    out->n = 0;
    spat_bitr_t r = { frame, len * 8, start, false };

    /* SPAT preamble: ext(1) + opt{timeStamp,name,regional}(3) */
    sb(&r, 1);
    uint32_t sopt = sb(&r, 3);
    if (sopt & 0x4) sb(&r, 20);   /* timeStamp MinuteOfTheYear */
    if (sopt & 0x2) return;       /* name DescriptiveName (not seen) */
    if (sopt & 0x1) return;       /* regional (not seen) */

    uint32_t n_int = sb(&r, 5) + 1;
    if (n_int < 1) return;

    /* IntersectionState */
    sb(&r, 1);                    /* ext */
    uint32_t opt = sb(&r, 6);     /* name,moy,timeStamp,enabledLanes,maneuverAssist,regional */
    bool has_moy = (opt >> 4) & 1, has_ts = (opt >> 3) & 1, has_enabled = (opt >> 2) & 1;

    uint32_t region = sb(&r, 1) ? sb(&r, 16) : 0;
    uint32_t iid = sb(&r, 16);
    uint32_t revision = sb(&r, 7);
    out->status = (uint16_t)sb(&r, 16);   /* IntersectionStatusObject flags */
    /* Reference time-of-hour in tenths of a second (TimeMark's own scale),
     * for the countdown below. Prefer our own clock: measured against real
     * captures it beats the RSU's moy/timeStamp (median error -0.1 s vs
     * +0.7 s), because those fields stay frozen for several messages while
     * frames arrive at ~10/s. The RSU clock is only the fallback for when
     * our own isn't NTP-synced yet. */
    uint32_t moy = has_moy ? sb(&r, 20) : 0;
    uint32_t dsecond = has_ts ? sb(&r, 16) : 0;
    bool have_clock = has_moy && has_ts && dsecond < 60000;
    uint32_t now_tenths = have_clock ? (moy % 60) * 600 + dsecond / 100 : 0;

    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0 && tv.tv_sec > 1600000000)
    {
        now_tenths = (uint32_t)((tv.tv_sec % 3600) * 10 + tv.tv_usec / 100000);
        have_clock = true;
    }
    if (has_enabled) return;

    uint32_t n_mov = sb(&r, 8) + 1;
    uint8_t cnt = 0;
    for (uint32_t m = 0; m < n_mov && !r.err; m++)
    {
        sb(&r, 1);                /* MovementState ext */
        uint32_t mopt = sb(&r, 3);/* movementName,maneuverAssistList,regional */
        bool m_name = (mopt >> 2) & 1, m_maneuver = (mopt >> 1) & 1, m_reg = mopt & 1;
        if (m_name || m_reg) return;
        uint32_t sg = sb(&r, 8);
        uint32_t n_ev = sb(&r, 4) + 1;
        uint32_t phase = 0xFF;
        int16_t secs = -1;
        for (uint32_t e = 0; e < n_ev && !r.err; e++)
        {
            sb(&r, 1);            /* MovementEvent ext */
            uint32_t eopt = sb(&r, 3);
            bool has_timing = (eopt >> 2) & 1, has_speeds = (eopt >> 1) & 1, has_ereg = eopt & 1;
            uint32_t es = sb(&r, 4);   /* eventState: 4 bits, no extension marker */
            if (e == 0) phase = es;
            if (has_timing)
            {
                uint32_t min_end = spat_read_time_change(&r);
                /* Only the first event's timing is the current phase's end.
                 * 36001 = "unknown" per TimeMark; wrap across the hour. */
                if (e == 0 && have_clock && min_end <= 36000)
                {
                    int32_t d = (int32_t)min_end - (int32_t)now_tenths;
                    if (d < 0) d += 36000;
                    /* Anything beyond ~10 min isn't a plausible signal phase;
                     * treat as unknown rather than show a bogus countdown. */
                    if (d <= 6000) secs = (int16_t)(d / 10);
                }
            }
            if (has_speeds) spat_skip_speeds(&r);
            if (has_ereg) return;
        }
        if (cnt < ITS_SPAT_MAX_SG)
        {
            out->sg[cnt] = (uint8_t)sg;
            out->phase[cnt] = (uint8_t)phase;
            out->secs[cnt] = secs;
            cnt++;
        }
        if (m_maneuver)
        {
            uint32_t n_ma = sb(&r, 4) + 1;
            for (uint32_t k = 0; k < n_ma && !r.err; k++) spat_skip_conn_maneuver(&r);
        }
    }
    if (r.err && cnt == 0) return;   /* nothing usable */

    out->region = (uint16_t)region;
    out->id = (uint16_t)iid;
    out->revision = (uint8_t)revision;
    out->n = cnt;
    out->valid = true;
}

/* --- MAPEM (SAE J2735 MapData) stage-1 decode ----------------------------
 * Walks only as far as the first IntersectionGeometry's name + id, which sit
 * before the (much larger) lane geometry. Bit layout verified field-by-field
 * against real captured MAPEM -- see reference-its-decode in project memory. */
static void parse_mapem(const uint8_t *frame, size_t len, size_t start,
                        its_map_t *out, its_map_geom_t *geom)
{
    out->valid = false;
    out->name[0] = '\0';
    spat_bitr_t r = { frame, len * 8, start, false };

    /* MapData: ext(1) + opt{timeStamp,layerType,layerID,intersections,
     * roadSegments,dataParameters,restrictionList,regional}(8) */
    sb(&r, 1);
    uint32_t opt = sb(&r, 8);
    bool has_ts     = (opt >> 7) & 1;
    bool has_ltype  = (opt >> 6) & 1;
    bool has_lid    = (opt >> 5) & 1;
    bool has_ints   = (opt >> 4) & 1;
    if (has_ts) sb(&r, 20);           /* MinuteOfTheYear */
    sb(&r, 7);                        /* msgIssueRevision MsgCount */
    if (has_ltype) return;            /* LayerType (extensible enum, not seen) */
    if (has_lid) sb(&r, 7);           /* LayerID 0..100 */
    if (!has_ints) return;

    uint32_t n_int = sb(&r, 5) + 1;   /* IntersectionGeometryList SIZE(1..32) */
    if (n_int < 1) return;

    /* IntersectionGeometry: ext(1) + opt{name,laneWidth,speedLimits,
     * preemptPriorityData,regional}(5) */
    sb(&r, 1);
    uint32_t gopt = sb(&r, 5);
    bool has_name = (gopt >> 4) & 1;
    bool has_lw = (gopt >> 3) & 1;
    bool has_sl = (gopt >> 2) & 1;

    if (has_name)
    {
        /* DescriptiveName ::= IA5String (SIZE(1..63)): 6-bit count-1, then
         * 7 bits per character (128-value alphabet, no octet alignment). */
        uint32_t n = sb(&r, 6) + 1;
        size_t w = 0;
        for (uint32_t i = 0; i < n && !r.err; i++)
        {
            uint32_t c = sb(&r, 7);
            if (w + 1 < sizeof(out->name) && c >= 0x20 && c < 0x7F)
                out->name[w++] = (char)c;
        }
        out->name[w] = '\0';
    }
    if (r.err) return;

    /* id IntersectionReferenceID { region OPTIONAL(16b), id 16b } */
    uint32_t region = sb(&r, 1) ? sb(&r, 16) : 0;
    uint32_t iid = sb(&r, 16);
    if (r.err) return;

    out->region = (uint16_t)region;
    out->id = (uint16_t)iid;
    out->valid = true;

    /* --- Lane geometry, to learn what each signal group controls ---------
     * Everything from here on is optional enrichment: if any construct we
     * haven't seen in real traffic turns up, we bail out and simply leave
     * n_sg at 0, keeping the name/id above. Widths validated against 9734
     * real MAPEM frames -- see reference-its-decode before touching one. */
    out->revision = (uint8_t)sb(&r, 7);
    /* refPoint Position3D: 3 preamble bits (ext + elevation + regional),
     * then lat/long as UPER-biased integers (we don't need their values). */
    sb(&r, 1);
    bool has_elev = sb(&r, 1);
    bool ref_regional = sb(&r, 1);
    int32_t ref_lat = (int32_t)((int64_t)sb(&r, 31) - 900000000);
    int32_t ref_lon = (int32_t)((int64_t)sb(&r, 32) - 1800000000);
    if (has_elev) sb(&r, 16);
    if (ref_regional) return;

    /* Metres per 1e-7 degree, for turning the cm node offsets into absolute
     * positions. Longitude shrinks with latitude; computed once per MAPEM,
     * which only happens on a revision change, so the float cost is moot. */
    double lat_scale = 1e7 / 111320.0;
    double lon_scale = 1e7 / (111320.0 * cos((double)ref_lat / 1e7 * M_PI / 180.0));
    if (geom)
    {
        geom->region = out->region;
        geom->id = out->id;
        geom->ref_lat_e7 = ref_lat;
        geom->ref_lon_e7 = ref_lon;
        geom->n_lanes = 0;
    }
    if (has_lw) out->lane_width_cm = (uint16_t)sb(&r, 15);   /* LaneWidth, cm */
    if (has_sl)
    {
        /* RegulatorySpeedLimit: what kind of limit, then the value in
         * 0.02 m/s steps. Only the plain vehicle max/min are kept -- the
         * school-zone and truck variants would need their own UI. */
        uint32_t n = sb(&r, 4) + 1;
        for (uint32_t i = 0; i < n && !r.err; i++)
        {
            uint32_t type = sb(&r, 5), vel = sb(&r, 13);
            /* 0.02 m/s -> km/h: v * 0.02 * 3.6 = v * 0.072 */
            uint16_t kmh = (uint16_t)((vel * 72 + 500) / 1000);
            if (type == 5 && !out->speed_max_kmh) out->speed_max_kmh = kmh;
            if (type == 4 && !out->speed_min_kmh) out->speed_min_kmh = kmh;
        }
    }

    uint32_t n_lanes = sb(&r, 8) + 1;   /* LaneList SIZE(1..255) */
    uint8_t cnt = 0;
    for (uint32_t li = 0; li < n_lanes && !r.err; li++)
    {
        sb(&r, 1);
        uint32_t lopt = sb(&r, 7);      /* name,ingress,egress,maneuvers,connectsTo,overlays,regional */
        uint32_t lane_id = sb(&r, 8);
        its_lane_geom_t *lg = NULL;
        if (geom && geom->n_lanes < ITS_GEOM_MAX_LANES)
        {
            lg = &geom->lane[geom->n_lanes];
            lg->lane_id = (uint8_t)lane_id;
            lg->signal_group = 0xFF;
            lg->maneuvers = 0;
            lg->n_nodes = 0;
        }
        if ((lopt >> 6) & 1)            /* name */
        {
            uint32_t n = sb(&r, 6) + 1;
            for (uint32_t i = 0; i < n && !r.err; i++) sb(&r, 7);
        }
        if ((lopt >> 5) & 1) sb(&r, 4); /* ingressApproach */
        if ((lopt >> 4) & 1) sb(&r, 4); /* egressApproach */

        /* LaneAttributes: 1 preamble bit, directionalUse 2, sharedWith 10 */
        sb(&r, 1); sb(&r, 2); sb(&r, 10);
        sb(&r, 1);
        uint32_t ltype = sb(&r, 3);
        /* `vehicle` is an EXTENSIBLE BIT STRING(8) -> 9 bits; every other
         * lane type (crosswalk, bike, sidewalk, ...) is 16. */
        sb(&r, ltype == 0 ? 9 : 16);
        bool is_crosswalk = (ltype == 1);
        if (lg) lg->lane_type = (uint8_t)ltype;

        if ((lopt >> 3) & 1) sb(&r, 12);  /* lane-level maneuvers */

        sb(&r, 2);                        /* NodeListXY CHOICE */
        uint32_t n_nodes = sb(&r, 6) + 2; /* NodeSetXY SIZE(2..63) */
        double x_cm = 0, y_cm = 0;
        for (uint32_t i = 0; i < n_nodes && !r.err; i++)
        {
            sb(&r, 1);
            bool has_attr = sb(&r, 1);
            uint32_t kind = sb(&r, 3);    /* NodeOffsetPointXY, no ext bit */
            static const uint8_t DELTA[6] = { 10, 11, 12, 13, 14, 16 };
            static const int32_t BIAS[6]  = { 512, 1024, 2048, 4096, 8192, 32768 };
            if (kind < 6)
            {
                /* Offsets are signed centimetres, relative to the previous
                 * node (the first one to the intersection refPoint). */
                int32_t dx = (int32_t)sb(&r, DELTA[kind]) - BIAS[kind];
                int32_t dy = (int32_t)sb(&r, DELTA[kind]) - BIAS[kind];
                x_cm += dx; y_cm += dy;
                if (lg && lg->n_nodes < ITS_GEOM_MAX_NODES)
                {
                    lg->lat_e7[lg->n_nodes] = ref_lat + (int32_t)(y_cm / 100.0 * lat_scale);
                    lg->lon_e7[lg->n_nodes] = ref_lon + (int32_t)(x_cm / 100.0 * lon_scale);
                    lg->n_nodes++;
                }
            }
            else if (kind == 6) { sb(&r, 32); sb(&r, 32); }
            else return;                  /* regional node */
            if (!has_attr) continue;

            sb(&r, 1);
            uint32_t ao = sb(&r, 7);      /* localNode,disabled,enabled,data,dWidth,dElevation,regional */
            if ((ao >> 6) & 1)
            {
                uint32_t c = sb(&r, 3) + 1;
                for (uint32_t k = 0; k < c && !r.err; k++) { sb(&r, 1); sb(&r, 4); }
            }
            for (int shift = 5; shift >= 4; shift--)   /* disabled, enabled */
                if ((ao >> shift) & 1)
                {
                    uint32_t c = sb(&r, 3) + 1;
                    for (uint32_t k = 0; k < c && !r.err; k++) sb(&r, 7);
                }
            if ((ao >> 3) & 1) return;    /* data attributes, not seen */
            if ((ao >> 2) & 1) sb(&r, 10);
            if ((ao >> 1) & 1) sb(&r, 10);
            if (ao & 1) return;           /* regional */
        }

        if (!((lopt >> 2) & 1))
        {
            if (lg) geom->n_lanes++;      /* egress lane: geometry only */
            continue;
        }

        uint32_t n_conn = sb(&r, 4) + 1;
        for (uint32_t i = 0; i < n_conn && !r.err; i++)
        {
            uint32_t copt = sb(&r, 4);    /* remoteIntersection,signalGroup,userClass,connectionID */
            bool has_man = sb(&r, 1);
            sb(&r, 8);                    /* connecting lane id */
            uint32_t man = has_man ? sb(&r, 12) : 0;
            if ((copt >> 3) & 1) { sb(&r, 16); sb(&r, 16); }
            uint32_t sg = ((copt >> 2) & 1) ? sb(&r, 8) : 0xFFFF;
            if ((copt >> 1) & 1) sb(&r, 8);   /* userClass -- easy to miss */
            if (copt & 1) sb(&r, 8);          /* connectionID */
            if (sg == 0xFFFF || r.err)
                continue;

            /* Fold into the per-signal-group table. */
            uint8_t slot = cnt;
            for (uint8_t k = 0; k < cnt; k++)
                if (out->sg[k] == (uint8_t)sg) { slot = k; break; }
            if (slot == cnt)
            {
                if (cnt >= ITS_SPAT_MAX_SG) continue;
                out->sg[cnt] = (uint8_t)sg;
                out->maneuvers[cnt] = 0;
                out->ped[cnt] = true;     /* cleared by the first road lane */
                cnt++;
            }
            out->maneuvers[slot] |= (uint16_t)man;
            if (!is_crosswalk) out->ped[slot] = false;
            if (lg && lg->signal_group == 0xFF)
            {
                lg->signal_group = (uint8_t)sg;
                lg->maneuvers = (uint16_t)man;
            }
        }
        if (lg) geom->n_lanes++;
    }
    if (!r.err)
    {
        out->n_sg = cnt;
        if (geom) geom->valid = true;
    }
}

/* --- DENM cause category --------------------------------------------------
 * Walks the ManagementContainer to reach the SituationContainer's cause
 * code. Field widths cross-checked against tshark's own byte offsets on real
 * DENMs (originatingStationId, sequenceNumber, latitude and altitudeValue all
 * land on the bytes tshark reports).
 *
 * CAVEAT, deliberately conservative: every DENM captured here so far is the
 * same cause ("trafficCondition"), so only that one value is actually
 * confirmed. Callers therefore treat anything they don't have a label for as
 * "warning, code N" rather than inventing a description. */
/* Decodes a DENM's cause and sub-cause. Structure per ETSI TS 103 831
 * (DENM v2) and TS 102 894-2 (CDD); every field width below was then checked
 * against tshark on real frames -- mopt, stationType, informationQuality,
 * cause and sub-cause all match on 71/71.
 *
 * The trap that cost the most: **DenmPayload has no extension marker**, so
 * there is no ext bit before its three optional-container bits. Assuming one
 * shifted everything by a single bit, which silently mis-read the management
 * optional mask and put the cause 22 bits off -- while still yielding a
 * plausible-looking number. Don't add it back.
 *
 * The CHOICE index doubles as the classic cause code: the ASN.1 keeps
 * `reserved` placeholders so that e.g. accident is still 2, slowVehicle 26. */
static void parse_denm_cause(const uint8_t *frame, size_t len, size_t start,
                             its_decoded_t *d)
{
    spat_bitr_t r = { frame, len * 8, start, false };

    uint32_t dopt = sb(&r, 3);          /* situation, location, alacarte */
    bool has_situation = (dopt >> 2) & 1;

    sb(&r, 1);                          /* ManagementContainer extension bit */
    uint32_t mopt = sb(&r, 5);          /* termination, awarenessDistance,
                                         * trafficDirection, validityDuration,
                                         * transmissionInterval */

    d->denm_station = sb(&r, 32);       /* actionId.originatingStationId */
    d->denm_seq = (uint16_t)sb(&r, 16); /* actionId.sequenceNumber */

    sb(&r, 42); sb(&r, 42);             /* detectionTime, referenceTime */
    if ((mopt >> 4) & 1) sb(&r, 1);     /* termination */

    /* eventPosition: where the hazard IS, which is not where the sender is --
     * an RSU warns about a jam some way down the road. Same UPER-biased
     * encoding as CAM's referencePosition. The sentinels (900000001 /
     * 1800000001 = unavailable) must not become a marker at sea. */
    uint32_t elat = sb(&r, 31), elon = sb(&r, 32);
    if (!r.err && elat != 1800000001u && elon != 3600000001u)
    {
        d->denm_lat_e7 = (int32_t)((int64_t)elat - 900000000);
        d->denm_lon_e7 = (int32_t)((int64_t)elon - 1800000000);
        d->has_denm_pos = (d->denm_lat_e7 != 0 || d->denm_lon_e7 != 0);
    }
    sb(&r, 12); sb(&r, 12); sb(&r, 12); /* positionConfidenceEllipse */
    sb(&r, 20); sb(&r, 4);              /* altitude value + confidence */
    if ((mopt >> 3) & 1) sb(&r, 3);     /* awarenessDistance */
    if ((mopt >> 2) & 1) sb(&r, 2);     /* awarenessTrafficDirection */
    if ((mopt >> 1) & 1) sb(&r, 17);    /* validityDuration */
    if (mopt & 1)        sb(&r, 14);    /* transmissionInterval */
    sb(&r, 8);                          /* stationType */

    if (!has_situation || r.err)
        return;

    sb(&r, 1);                          /* SituationContainer extension bit */
    sb(&r, 2);                          /* linkedCause, eventZone */
    sb(&r, 3);                          /* informationQuality */
    sb(&r, 1);                          /* CauseCodeV2 extension bit */
    uint32_t cause = sb(&r, 8);         /* CauseCodeChoice index = cause code */
    uint32_t sub   = sb(&r, 8);         /* the chosen alternative's sub-cause */
    if (r.err)
        return;
    d->denm_cause = (uint8_t)cause;
    d->denm_subcause = (uint8_t)sub;
}

/* --- Public-transport container, walked properly ---------------------------
 * Reaches specialVehicleContainer by decoding the CAM structurally instead of
 * hunting for a byte signature. `start` is the referencePosition anchor
 * (pdu_off+9)*8+4; the three CamParameters preamble bits sit just before it.
 *
 * Field widths come from the ETSI ASN.1 (EN 302 637-2 / TS 102 894-2), with
 * one deliberate deviation: the CDD v2 published there declares PathHistory
 * as SEQUENCE (SIZE(40)) -- fixed, hence no length determinant -- but real
 * frames carry 2/4/8/9/10 points, so the SIZE(0..40) form with a 6-bit length
 * is what is actually on the wire. Trusting the file here would have thrown
 * the walk off by everything after the low-frequency container.
 *
 * Returns false if the frame doesn't carry a public-transport container or
 * the walk hit something unexpected; `*out_line` is only touched on success. */
static bool parse_cam_detail(const uint8_t *frame, size_t len, size_t start,
                             its_decoded_t *d)
{
    uint8_t *out_line = &d->pt_line;
    bool *out_embarking = &d->pt_embarking;
    its_cam_detail_t *cd = &d->cam;
    cd->role = 0xFF;

    if (start < 4)
        return false;

    /* CamParameters preamble, immediately before the anchor:
     * [ext][lowFrequencyContainer present][specialVehicleContainer present]
     * then BasicContainer's own extension bit (the 4th, at start-1). */
    uint32_t pre;
    if (!read_bits_msb(frame, len, start - 4, 4, &pre))
        return false;
    bool has_lf = (pre >> 2) & 1;
    bool has_sv = (pre >> 1) & 1;

    spat_bitr_t r = { frame, len * 8, start, false };

    /* ReferencePosition -- kept, since PathHistory's deltas are relative to
     * it and have to be summed back into absolute positions. */
    int32_t ref_lat = (int32_t)((int64_t)sb(&r, 31) - 900000000);
    int32_t ref_lon = (int32_t)((int64_t)sb(&r, 32) - 1800000000);
    sb(&r, 12); sb(&r, 12); sb(&r, 12);  /* positionConfidenceEllipse */
    sb(&r, 20); sb(&r, 4);          /* altitude value + confidence */

    /* HighFrequencyContainer CHOICE: 2 alternatives + extension marker. */
    if (sb(&r, 1))
        return false;               /* extension alternative -- unknown shape */
    if (sb(&r, 1) != 0)
        return false;               /* rsuContainerHighFrequency, not a vehicle */

    uint32_t hopt = sb(&r, 7);      /* no extension marker on this SEQUENCE */
    uint32_t hdg = sb(&r, 12); sb(&r, 7);   /* heading value + confidence */
    if (!r.err && hdg <= 3600)      /* 3601 = unavailable */
    {
        cd->has_heading = true;
        cd->heading_ddeg = (uint16_t)hdg;
    }
    sb(&r, 14); sb(&r, 7);          /* speed */
    sb(&r, 2);                      /* driveDirection */
    sb(&r, 10); sb(&r, 3);          /* vehicleLength + confidence */
    sb(&r, 6);                      /* vehicleWidth */
    sb(&r, 9); sb(&r, 7);           /* longitudinalAcceleration */
    sb(&r, 11); sb(&r, 3);          /* curvature value + confidence */
    sb(&r, 1); sb(&r, 2);           /* curvatureCalculationMode (extensible) */
    sb(&r, 16); sb(&r, 4);          /* yawRate value + confidence */
    if ((hopt >> 6) & 1)
    {
        uint32_t ac = sb(&r, 7);               /* accelerationControl */
        if (!r.err) { cd->has_accel_ctrl = true; cd->accel_ctrl = (uint8_t)ac; }
    }
    if ((hopt >> 5) & 1) sb(&r, 4);            /* lanePosition */
    if ((hopt >> 4) & 1) { sb(&r, 10); sb(&r, 7); }  /* steeringWheelAngle */
    if ((hopt >> 3) & 1) { sb(&r, 9); sb(&r, 7); }   /* lateralAcceleration */
    if ((hopt >> 2) & 1) { sb(&r, 9); sb(&r, 7); }   /* verticalAcceleration */
    if ((hopt >> 1) & 1) sb(&r, 3);            /* performanceClass */
    if (hopt & 1)
    {
        sb(&r, 1);                             /* CenDsrcTollingZone ext */
        uint32_t zopt = sb(&r, 1);
        sb(&r, 31); sb(&r, 32);                /* protectedZone lat / long */
        if (zopt) sb(&r, 16);                  /* cenDsrcTollingZoneID */
    }

    if (has_lf)
    {
        if (sb(&r, 1))
            return false;           /* LowFrequencyContainer extension */
        /* Only one alternative in the root, so the CHOICE index is 0 bits. */
        uint32_t role = sb(&r, 4);  /* vehicleRole */
        uint32_t lights = sb(&r, 8);/* exteriorLights */
        if (!r.err)
        {
            cd->role = (uint8_t)role;
            cd->has_lights = true;
            cd->ext_lights = (uint8_t)lights;
        }
        uint32_t n = sb(&r, 6);     /* PathHistory length -- see note above */
        if (n > 40 || r.err)
            return false;
        /* Each point is an offset from the PREVIOUS one, the first from the
         * reference position, so they have to be accumulated. */
        int32_t plat = ref_lat, plon = ref_lon;
        for (uint32_t i = 0; i < n && !r.err; i++)
        {
            uint32_t popt = sb(&r, 1);         /* pathDeltaTime present */
            int32_t dlat = (int32_t)sb(&r, 18) - 131071;
            int32_t dlon = (int32_t)sb(&r, 18) - 131071;
            sb(&r, 15);                        /* deltaAltitude */
            if (popt) { sb(&r, 1); sb(&r, 16); }  /* extensible constraint */
            plat += dlat;
            plon += dlon;
            if (!r.err && cd->n_path < ITS_PATH_MAX)
            {
                cd->path_lat_e7[cd->n_path] = plat;
                cd->path_lon_e7[cd->n_path] = plon;
                cd->n_path++;
            }
        }
    }

    if (!has_sv)
        return false;               /* no special-vehicle container follows */

    /* SpecialVehicleContainer CHOICE: 7 alternatives + extension marker. */
    if (sb(&r, 1))
        return false;
    if (sb(&r, 3) != 0)
        return false;               /* not publicTransportContainer */

    uint32_t topt = sb(&r, 1);      /* ptActivation present */
    bool embarking = sb(&r, 1) != 0;
    if (r.err)
        return false;
    if (out_embarking) *out_embarking = embarking;
    if (!topt)
        return true;                /* PT vehicle, but no line telegram */

    sb(&r, 8);                      /* ptActivationType (1 = VDV R09) */
    uint32_t nbytes = sb(&r, 5) + 1;/* PtActivationData SIZE(1..20) */
    if (nbytes > 20 || r.err)
        return false;

    /* R09 telegram: five fixed bytes, then the line number as BCD. */
    static const uint8_t R09[5] = { 0x91, 0x06, 0x00, 0x00, 0x00 };
    if (nbytes < 6)
        return true;
    for (int i = 0; i < 5; i++)
        if (sb(&r, 8) != R09[i])
            return true;            /* some other activation telegram */
    uint32_t v = sb(&r, 8);
    if (r.err)
        return false;
    uint8_t hi = (v >> 4) & 0xF, lo = v & 0xF;
    if (hi > 9 || lo > 9)
        return true;                /* not BCD -- report the container only */
    if (out_line) *out_line = (uint8_t)(hi * 10 + lo);
    return true;
}


/* Unwraps an ETSI TS 103 097 / IEEE 1609.2 "Secured Packet" envelope (GN
 * Basic Header next-header == 2) far enough to reach the plain
 * GeoNetworking structure it carries as payload, without ever touching the
 * certificate/signature that follows. Only the two CHOICE tag *values* are
 * checked (0x81 "signedData", 0x80 "unsecuredData"); anything else bails
 * out to plain "Signed" rather than guess at an unverified encoding. */
static bool unwrap_secured(const uint8_t *frame, size_t len, size_t off,
                           size_t *inner_off, size_t *inner_len)
{
    /* off is right after the 4-byte GN Basic Header. */
    if (len < off + 6) return false;
    /* frame[off]   = Ieee1609Dot2Data.protocolVersion (not checked) */
    uint8_t content_tag = frame[off + 1];
    /* frame[off+2] = hashId (not checked, doesn't affect layout) */
    /* frame[off+3] = payload choice-tag (not checked, fixed 1 byte either way) */
    /* frame[off+4] = payload.data.protocolVersion (not checked) */
    uint8_t inner_tag = frame[off + 5];
    if (content_tag != 0x81 || inner_tag != 0x80)
        return false;

    size_t value_len, field_len;
    if (!read_oer_length(frame, len, off + 6, &value_len, &field_len))
        return false;
    size_t start = off + 6 + field_len;
    if (start > len)
        return false;

    *inner_off = start;
    *inner_len = value_len < (len - start) ? value_len : (len - start);
    return true;
}

/* Walks the GN/secured/BTP layers exactly like its_decode_frame does, but
 * only far enough to reach a MAPEM body, then decodes its lane geometry.
 * Kept separate so the kilobyte-sized result never lands on the packet
 * path's stack; call it rarely (once per intersection revision). */
bool its_decode_map_geometry(const uint8_t *frame, size_t len, its_map_geom_t *out)
{
    if (!out) return false;
    out->valid = false;

    size_t off = mac80211_header_len(frame, len);
    if (off == 0 || len < off + 8)
        return false;
    const uint8_t *llc = frame + off;
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 ||
        llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00)
        return false;
    if (rd_u16be(llc + 6) != ETHERTYPE_GEONET)
        return false;
    off += 8;
    if (len < off + 4)
        return false;
    uint8_t basic_nh = frame[off] & 0x0F;
    off += 4;

    char label[ITS_LABEL_LEN];
    const char *station = NULL;
    size_t pdu_off = SIZE_MAX, pv_off = SIZE_MAX, pdu_len = len;
    if (basic_nh == 2)
    {
        size_t inner_off, inner_len;
        if (!unwrap_secured(frame, len, off, &inner_off, &inner_len))
            return false;
        pdu_len = inner_off + inner_len;
        parse_common_onward(frame, pdu_len, inner_off, label, sizeof(label),
                            &station, &pdu_off, &pv_off);
    }
    else if (basic_nh == 1)
        parse_common_onward(frame, len, off, label, sizeof(label),
                            &station, &pdu_off, &pv_off);
    else
        return false;

    if (pdu_off == SIZE_MAX || pdu_len < pdu_off + 6 || frame[pdu_off + 1] != 5)
        return false;

    its_map_t tmp;
    parse_mapem(frame, pdu_len, (pdu_off + 6) * 8, &tmp, out);
    if (out->valid)
        out->revision = tmp.revision;
    return out->valid;
}

uint8_t its_peek_message_id(const uint8_t *frame, size_t len)
{
    its_decoded_t d;
    its_decode_frame(frame, len, &d);
    return d.message_id;
}

void its_decode_frame(const uint8_t *frame, size_t len, its_decoded_t *r)
{
    memset(r, 0, sizeof *r);
    char *out = r->label;
    const size_t out_size = sizeof r->label;

    if (!out || out_size == 0)
        return;

    size_t off = mac80211_header_len(frame, len);
    if (off == 0 || len < off + 8 /* LLC/SNAP */)
    {
        snprintf(out, out_size, "?");
        return;
    }

    const uint8_t *llc = frame + off;
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 ||
        llc[3] != 0x00 || llc[4] != 0x00 || llc[5] != 0x00)
    {
        snprintf(out, out_size, "?");
        return;
    }
    uint16_t ethertype = rd_u16be(llc + 6);
    off += 8;

    if (ethertype == ETHERTYPE_IPV6) { snprintf(out, out_size, "IPv6"); return; }
    if (ethertype == ETHERTYPE_WSMP) { snprintf(out, out_size, "WSMP"); return; }
    if (ethertype != ETHERTYPE_GEONET) { snprintf(out, out_size, "?"); return; }

    /* GeoNetworking Basic Header (4 bytes): Version(hi nibble) | NextHeader(lo nibble). */
    if (len < off + 4) { snprintf(out, out_size, "?"); return; }
    uint8_t basic_nh = frame[off] & 0x0F;
    off += 4;

    char label[32];
    const char *station = NULL;
    size_t pdu_off = SIZE_MAX;
    size_t pv_off = SIZE_MAX;
    size_t pdu_len = len; /* bounds to use with pdu_off below; differs for the unwrapped-secured case */

    if (basic_nh == 2)
    {
        size_t inner_off, inner_len;
        if (unwrap_secured(frame, len, off, &inner_off, &inner_len))
        {
            pdu_len = inner_off + inner_len;
            parse_common_onward(frame, pdu_len, inner_off, label, sizeof(label), &station, &pdu_off, &pv_off);
        }
        else
            snprintf(label, sizeof(label), "Signed");
    }
    else if (basic_nh == 1)
    {
        parse_common_onward(frame, len, off, label, sizeof(label), &station, &pdu_off, &pv_off);
    }
    else
    {
        snprintf(label, sizeof(label), "?"); /* not "Common Header follows" */
    }

    /* Built in two bounded steps rather than one "%s %s": the label buffer is
     * as large as the output, so a single format is provably truncatable and
     * -Werror=format-truncation rejects it. */
    size_t lo = 0;
    if (station)
    {
        int n = snprintf(out, out_size, "%s ", station);
        lo = (n > 0 && (size_t)n < out_size) ? (size_t)n : out_size - 1;
    }
    snprintf(out + lo, out_size - lo, "%s", label);

    /* ItsPduHeader.stationId is present for every facility message (not just
     * CAM), right after protocolVersion+messageId -- read it once here so
     * both the GN-layer position fallback below and the CAM-specific
     * position further down can use it as the map marker's tracking key. */
    bool have_sid = pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6;
    uint32_t sid = have_sid ? rd_u32be(frame + pdu_off + 2) : 0;

    /* Raw numeric type fields (station type from the Source Position Vector,
     * messageId from the ITS PDU header) for callers that aggregate/branch. */
    if (pv_off != SIZE_MAX && pdu_len > pv_off)
        r->station_type = (frame[pv_off] >> 2) & 0x1F;
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 2)
        r->message_id = frame[pdu_off + 1];

    /* SPATEM (messageId 4): decode traffic-light phases. The SPAT message
     * begins right after the 6-byte ItsPduHeader (protocolVersion+messageId+
     * stationId), i.e. bit (pdu_off+6)*8; parse_spatem walks it from there. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 4)
        parse_spatem(frame, pdu_len, (pdu_off + 6) * 8, &r->spat);

    /* MAPEM (messageId 5): same entry point, the intersection's name/id. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 5)
        parse_mapem(frame, pdu_len, (pdu_off + 6) * 8, &r->map, NULL);

    /* DENM (messageId 1): what the warning is actually about. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 1)
        parse_denm_cause(frame, pdu_len, (pdu_off + 6) * 8, r);

    /* CAM (messageId 2) from a bus/tram may carry its line number. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 2 &&
        frame[pdu_off + 1] == 2)
        r->pt_container = parse_cam_detail(frame, pdu_len, (pdu_off + 9) * 8 + 4, r);

    /* GN-layer position: the Source Position Vector carries a position for
     * EVERY message, not just CAM (this is what puts RSUs on the map).
     * Plain big-endian signed integers, no UPER bit-packing, no bias/offset
     * (unlike CAM's referencePosition below). Layout relative to pv_off:
     * GN_ADDR(8)+Timestamp(4)+Latitude(4)+Longitude(4)+PAI&Speed(2)+
     * Heading(2) = 24 bytes. Only a fallback -- CAM's own body position
     * overrides it below when available. */
    if (have_sid && pv_off != SIZE_MAX && pdu_len >= pv_off + 20)
    {
        int32_t gn_lat = (int32_t)rd_u32be(frame + pv_off + 12);
        int32_t gn_lon = (int32_t)rd_u32be(frame + pv_off + 16);
        if (gn_lat != 0 || gn_lon != 0) /* 0,0 = clearly not a real fix */
        {
            r->station_id = sid;
            r->lat_e7 = gn_lat;
            r->lon_e7 = gn_lon;
            r->has_position = true;
        }

        /* Speed sits right after the position: PAI(1 bit)+Speed(15 bits),
         * 0.01 m/s units (raw value is already cm/s). The 15 bits are TWO'S
         * COMPLEMENT (EN 302 636-4-1) -- a reversing vehicle sends a negative
         * speed, which without sign extension would surface as ~327 m/s.
         * Skipped for RSUs (stationary -- a speed reading is meaningless). */
        if (pdu_len >= pv_off + 22 && !(station && strcmp(station, "RSU") == 0))
        {
            uint16_t raw = rd_u16be(frame + pv_off + 20) & 0x7FFF;
            r->speed_cmps = (raw & 0x4000) ? (int32_t)raw - 0x8000 : (int32_t)raw;
            r->has_speed = true;
        }
    }

    /* CAM position overrides the GN-layer fallback above when available --
     * see its_decode.h for the field semantics. */
    if (!have_sid)
        return;
    if (frame[pdu_off + 1] != 2 /* CAM */)
        return;

    /* referencePosition starts at byte pdu_off+9 (protocolVersion+messageId+
     * stationId+generationDeltaTime+basicContainer.stationType), PLUS 4
     * extra UPER bits: CamParameters' extension marker + 2 optional-
     * container presence bits, plus 1 from basicContainer's own extensible
     * SEQUENCE. Empirically pinned down (byte offset alone gives garbage
     * lat/lon) -- don't simplify this without re-validating against tshark. */
    size_t bitoff = (pdu_off + 9) * 8 + 4;
    uint32_t raw_lat, raw_lon;
    if (!read_bits_msb(frame, pdu_len, bitoff, 31, &raw_lat))
        return;
    if (!read_bits_msb(frame, pdu_len, bitoff + 31, 32, &raw_lon))
        return;

    /* Vehicle dimensions, further into the same BasicVehicleContainerHigh-
     * Frequency. Offsets from the (already validated) referencePosition
     * anchor: lat31+lon32, posConfidenceEllipse 12+12+12, altitude 20+4,
     * HighFrequencyContainer CHOICE 2, container optional-bitmap 7,
     * heading 12+7, speed 14+7, driveDirection 2 = 174 bits, then
     * vehicleLength 10, its confidence 3, vehicleWidth 6.
     *
     * Two things that a spec skim gets wrong, both caught by comparing
     * against tshark on real CAMs: the confidence enum is 3 bits, not 2 (it
     * has five values -- the four trailer states plus "unavailable"), and
     * both sizes are UPER constrained integers with lower bound 1, so the
     * encoded value is the real one minus 1. */
    {
        uint32_t vlen, vwid;
        if (read_bits_msb(frame, pdu_len, bitoff + 174, 10, &vlen) &&
            read_bits_msb(frame, pdu_len, bitoff + 187, 6, &vwid))
        {
            vlen += 1;  /* VehicleLengthValue ::= INTEGER (1..1023) */
            vwid += 1;  /* VehicleWidth      ::= INTEGER (1..62)   */
            /* Both types reserve their top TWO values: outOfRange then
             * unavailable (1022/1023 and 61/62). Report neither as a size. */
            r->veh.length_dm = (vlen >= 1022) ? 0 : (uint16_t)vlen;
            r->veh.width_dm = (vwid >= 61) ? 0 : (uint8_t)vwid;
            r->veh.valid = true;
        }
    }

    /* ETSI's dedicated "unavailable" sentinels for Latitude/Longitude. */
    if (raw_lat == 900000001u || raw_lon == 1800000001u)
        return;

    r->station_id = sid;
    r->lat_e7 = (int32_t)((int64_t)raw_lat - 900000000);
    r->lon_e7 = (int32_t)((int64_t)raw_lon - 1800000000);
    r->has_position = true;
}
