#include "its_decode.h"
#include "its_bits.h"
#include "its_utf8.h"

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

/* Reads nbits (1..32) at an absolute bit offset, MSB-first (UPER bit packing).
 * False on overrun or an out-of-range width. */
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

/* Message kind (see msg_kind) -> facility message name, from the messageId registry of
 * TS 102 894-2. Wireshark names every 3 "poim", version 0 included. */
static const msgid_name_t MSGID_NAMES[] = {
    { 1,  "DENM" },   { 2,  "CAM" },    { 3,  "POIM" },  { 4,  "SPATEM" },
    { 5,  "MAPEM" },  { 6,  "IVIM" },   { 9,  "SREM" },  { 10, "SSEM" },
    { 11, "EVCSN" },  { 12, "SAEM" },   { 13, "RTCMEM" },{ 14, "CPM" },
    { 15, "IMZM" },   { 16, "VAM" },    { 17, "DSM" },   { 18, "PCIM" },
    { 19, "PCVM" },   { 20, "MCM" },    { 21, "PAM" },
    /* CDD V3.1 names 7 and 8 (TS 101 556-3 recharging spot reservation, TS 101 556-2 tyre
     * pressure). V4.1 only reserved them later, so a frame with 7 or 8 is one of the two. */
    { 7,  "EV-RSR" }, { 8,  "TISTPG" },
};

static const char *lookup_msgid_name(uint8_t id)
{
    for (size_t i = 0; i < sizeof(MSGID_NAMES) / sizeof(MSGID_NAMES[0]); i++)
        if (MSGID_NAMES[i].id == id)
            return MSGID_NAMES[i].name;
    return NULL;
}

/* The label /messages shows for a message kind, NULL for an unnamed one. It uses the same
 * table as the frame label. */
const char *its_msgid_name(uint8_t kind)
{
    return lookup_msgid_name(kind);
}

/* messageId 3 at protocolVersion 0 is the old EVCSN of TS 101 556-1. CDD 4.1.1 gave 3 to
 * POIM, which is version 1. The label, the dispatch and /senders (its_msg_kind) ask here, so
 * they cannot differ. */
static uint8_t msg_kind(uint8_t version, uint8_t id)
{
    return (id == 3 && version == 0) ? 11 : id;
}

uint8_t its_msg_kind(uint8_t version, uint8_t id)
{
    return msg_kind(version, id);
}

/* GeoNetworking Common Header "header type" -> extended header length (ETSI EN
 * 302 636-4-1). -1 = not handled here. Easy to get wrong, see the cases below. */
static int gn_ext_header_len(uint8_t header_type)
{
    switch (header_type)
    {
    case 1: return 24;  /* Beacon: Source LongPV only, nothing follows */
    case 2: return 48;  /* GeoUnicast: SN+Res(4) + Source LongPV(24) + Dest ShortPV(20) */
    case 3: return 44;  /* GeoAnycast: SN+Reserved(4) + Source LongPV(24) + Geo-Area(16) */
    case 4: return 44;  /* GeoBroadcast: SN+Reserved(4) + Source LongPV(24) + Geo-Area(16) */
    case 5: return 28;  /* TSB: 24 + 4, the order depends on the sub-type */
    default: return -1; /* Location Service (6) and anything else */
    }
}

typedef struct { uint8_t code; const char *name; } station_type_name_t;

/* GeoNetworking GN_ADDR "ITS-S type" (5 bits, first byte of the Source
 * Position Vector). Matches Wireshark's geonw.src_pos.addr.type. */
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

/* Latitude and Longitude as UPER sends them: 31 and 32 bits above the lower bound. The top
 * value of each means "unavailable". Anything above it is outside the ASN.1 range, such as a
 * latitude of 124 degrees or a longitude that no longer fits an int32. The CDD marks the
 * LOWEST longitude as valueNotUsed. None of these values is a position. */
static bool pos_from_raw(uint32_t raw_lat, uint32_t raw_lon, int32_t *lat, int32_t *lon)
{
    if (raw_lat >= 1800000001u || raw_lon >= 3600000001u || raw_lon == 0)
        return false;
    *lat = (int32_t)((int64_t)raw_lat - 900000000);
    *lon = (int32_t)((int64_t)raw_lon - 1800000000);
    return true;
}

/* Parses GeoNetworking "Common Header onward" at `off` (plain or re-embedded secured form).
 * Yields name, ITS-PDU and position vector offsets, and area and DCC fields into a non-NULL `d`. */
static void parse_common_onward(const uint8_t *frame, size_t len, size_t off,
                                 char *out, size_t out_size, const char **station_out,
                                 size_t *pdu_off_out, size_t *pv_off_out, its_decoded_t *d)
{
    *station_out = NULL;
    *pdu_off_out = SIZE_MAX;
    *pv_off_out = SIZE_MAX;
    if (len < off + 8) { snprintf(out, out_size, "?"); return; }
    uint8_t common_nh   = (frame[off]     >> 4) & 0x0F;
    uint8_t header_type = (frame[off + 1] >> 4) & 0x0F;
    uint8_t header_sub  = frame[off + 1] & 0x0F;
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
    /* Only type 6 is the Location Service. Types 0 and 7..15 are undefined in
     * EN 302 636-4-1, and calling one of them "LS" would claim what the frame never said. */
    if (ext_len < 0)
    {
        if (header_type == 6)
            snprintf(out, out_size, "GeoNet-LS");
        else
            snprintf(out, out_size, "GeoNet-HT%u", (unsigned)header_type);
        return;
    }
    if (len < off + (size_t)ext_len) { snprintf(out, out_size, "?"); return; }

    /* GeoUnicast, GeoAnycast, GeoBroadcast and multi-hop TSB lead with a 4-byte
     * sequence number and reserved field. SHB (sub-type 0) and Beacon do not. */
    bool sn_first = header_type == 2 || header_type == 3 || header_type == 4 ||
                    (header_type == 5 && header_sub != 0);
    size_t pv_off = sn_first ? off + 4 : off;
    *station_out = lookup_station_name((frame[pv_off] >> 2) & 0x1F);
    *pv_off_out = pv_off;

    /* The GeoAnycast or GeoBroadcast area follows the Source Position Vector (EN 302 636-4-1
     * table 14). Only sub-types 0 to 2, circle, rectangle and ellipse, are defined. */
    if (d && (header_type == 3 || header_type == 4) && header_sub <= 2)
    {
        const uint8_t *a = frame + pv_off + 24;
        d->gn_area_shape = (uint8_t)(ITS_GN_AREA_CIRCLE + header_sub);
        d->gn_area_lat_e7 = (int32_t)rd_u32be(a);
        d->gn_area_lon_e7 = (int32_t)rd_u32be(a + 4);
        d->gn_area_a_m = rd_u16be(a + 8);
        d->gn_area_b_m = rd_u16be(a + 10);
        d->gn_area_angle_deg = rd_u16be(a + 12);
    }
    /* In a single-hop broadcast the DCC-MCO field follows the Source Position Vector. Its
     * third byte carries the transmit power in bits 0 to 4, and bit 0 is the MSB. */
    if (d && header_type == 5 && header_sub == 0)
    {
        const uint8_t *m = frame + pv_off + 24;
        d->has_dcc = true;
        d->dcc_cbr_r0_hop = m[0];
        d->dcc_cbr_r1_hop = m[1];
        d->dcc_tx_power_dbm = (uint8_t)(m[2] >> 3);
    }
    off += (size_t)ext_len;

    if (common_nh == 2) /* BTP-B: destination port is the first 2 bytes */
    {
        if (len < off + 2) { snprintf(out, out_size, "GeoNet"); return; }
        uint16_t port = rd_u16be(frame + off);
        /* ITS PDU header starts right after the 4-byte BTP-B header; reported even
         * without a name so its_decode_frame needn't redo this walk. */
        if (len >= off + 6) *pdu_off_out = off + 4;
        const char *name = (len >= off + 6)
                           ? lookup_msgid_name(msg_kind(frame[off + 4], frame[off + 5])) : NULL;
        if (name) snprintf(out, out_size, "%s", name);
        else      snprintf(out, out_size, "GeoNet:%u", (unsigned)port);
    }
    else if (common_nh == 1) { snprintf(out, out_size, "BTP-A"); }
    else if (common_nh == 3) { snprintf(out, out_size, "IPv6-GN"); }
    else                     { snprintf(out, out_size, "GeoNet"); }
}

/* TimeChangeDetails: 5 option bits, then the mandatory minEndTime (TimeMark,
 * 16 bits). Consumed fully to keep the cursor aligned. Returns minEndTime. */
static uint32_t spat_read_time_change(its_bitr_t *r)
{
    uint32_t o = its_bits_read(r, 5);
    if (o & 0x10) its_bits_skip(r, 16);       /* startTime */
    uint32_t min_end = its_bits_read(r, 16);  /* minEndTime (mandatory) */
    if (o & 0x08) its_bits_skip(r, 16);       /* maxEndTime */
    if (o & 0x04) its_bits_skip(r, 16);       /* likelyTime */
    if (o & 0x02) its_bits_skip(r, 4);        /* confidence */
    if (o & 0x01) its_bits_skip(r, 16);       /* nextTime */
    return min_end;
}

/* AdvisorySpeed: 1 ext bit + FIVE option bits; widths from the pinned release2
 * ASN.1 (confidence = SpeedConfidenceDSRC, 3 bits, NOT the 7-bit ETSI type). */
static void spat_skip_speeds(its_bitr_t *r)
{
    uint32_t n = its_bits_read(r, 4) + 1;   /* SIZE(1..16) length determinant */
    for (uint32_t i = 0; i < n && !r->err; i++)
    {
        if (its_bits_read(r, 1)) { r->err = true; return; }  /* extension addition present */
        uint32_t o = its_bits_read(r, 5);    /* speed,confidence,distance,class,regional */
        its_bits_skip(r, 3);                 /* type: extensible ENUMERATED (1 ext + 2) */
        if (o & 0x10) its_bits_skip(r, 9);   /* speed      SpeedAdvice         (0..500)   */
        if (o & 0x08) its_bits_skip(r, 3);   /* confidence SpeedConfidenceDSRC (8 values) */
        if (o & 0x04) its_bits_skip(r, 14);  /* distance   ZoneLength          (0..10000) */
        if (o & 0x02) its_bits_skip(r, 8);   /* class      RestrictionClassID  (0..255)   */
        if (o & 0x01) { r->err = true; return; }  /* regional: open type, not walkable */
    }
}

/* One ConnectionManeuverAssist, walked fully to stay aligned; both length
 * fields are ZoneLength (14 bits, not 8). */
static void spat_skip_conn_maneuver(its_bitr_t *r)
{
    if (its_bits_read(r, 1)) { r->err = true; return; }  /* extension addition present */
    uint32_t o = its_bits_read(r, 5);    /* queueLen,availStorageLen,waitOnStop,pedBike,regional */
    its_bits_skip(r, 8);                 /* connectionID LaneConnectionID (0..255) */
    if (o & 0x10) its_bits_skip(r, 14);  /* queueLength           ZoneLength (0..10000) */
    if (o & 0x08) its_bits_skip(r, 14);  /* availableStorageLength ZoneLength (0..10000) */
    if (o & 0x04) its_bits_skip(r, 1);   /* waitOnStop       BOOLEAN */
    if (o & 0x02) its_bits_skip(r, 1);   /* pedBicycleDetect BOOLEAN */
    if (o & 0x01) r->err = true;         /* regional: open type, not walkable */
}

/* IntersectionState.regional, SIZE(1..4) open types. The EU profile (addGrpC, regionId 3) puts
 * the answers to priority requests there. Only its first option bit is read. Not inlined, so
 * its stack frame stays off the receive task's deepest call chain, which runs through
 * parse_mapem. */
static __attribute__((noinline)) void spat_read_regional(its_bitr_t *r, uint8_t *items)
{
    uint32_t n = its_bits_read(r, 2) + 1;
    for (uint32_t i = 0; i < n && !r->err; i++)
    {
        uint32_t region = its_bits_read(r, 8);
        size_t len = its_bits_uper_length(r);
        size_t at = r->pos;
        its_bits_skip(r, len * 8);
        if (r->err || region != 3)
            continue;
        its_bitr_t c = { r->b, at + len * 8, at, false };
        its_bits_skip(&c, 1);                 /* extension bit */
        if (its_bits_read(&c, 1) && !c.err)   /* activePrioritizations OPTIONAL */
            *items |= ITS_SPAT_PRIO;
    }
}

/* Marks in parse_spatem's items that an extension bit was 1. It is never handed out.
 * A separate local cost the receive path 16 B of stack (its_decode_frame 352 -> 368). */
#define SPAT_EXT_SEEN 0x80
_Static_assert(!(SPAT_EXT_SEEN & (ITS_SPAT_ASSIST | ITS_SPAT_PRIO | ITS_SPAT_WHOLE)),
               "the walk-only mark must not be an item");

/* Parses SPAT at bit `start` into `out`; first IntersectionState only. Constructs
 * unseen in real traffic abort cleanly (out->valid false) rather than guess. */
static void parse_spatem(const uint8_t *frame, size_t len, size_t start,
                         its_spat_t *out)
{
    out->valid = false;
    out->n = 0;
    out->items = 0;
    its_bitr_t r = its_bitr_init(frame, len, start);

    /* SPAT preamble: ext(1) + opt{timeStamp,name,regional}(3) */
    its_bits_skip(&r, 1);
    uint32_t sopt = its_bits_read(&r, 3);
    if (sopt & 0x4) its_bits_skip(&r, 20);  /* timeStamp MinuteOfTheYear */
    if (sopt & 0x2) return;                 /* name DescriptiveName (not seen) */
    if (sopt & 0x1) return;                 /* regional (not seen) */

    uint32_t n_int = its_bits_read(&r, 5) + 1;
    if (n_int < 1) return;

    /* IntersectionState. Its extension bit and those of the movements and events below are
     * recorded. An addition stays unread at the end of its SEQUENCE, so everything walked
     * after it is shifted. */
    uint8_t ext = (uint8_t)(its_bits_read(&r, 1) ? SPAT_EXT_SEEN : 0);
    uint32_t opt = its_bits_read(&r, 6);  /* name,moy,timeStamp,enabledLanes,maneuverAssist,regional */
    /* Bail out like the SPAT-level name above: the variable-length string would
     * otherwise be walked as the region/id/revision/status that follow. */
    if ((opt >> 5) & 1) return;   /* name DescriptiveName (not seen) */
    bool has_moy = (opt >> 4) & 1, has_ts = (opt >> 3) & 1, has_enabled = (opt >> 2) & 1;
    /* WHOLE needs a single intersection, because a later one is never read. It is cleared
     * again if the walk below breaks off or meets an extension. */
    uint8_t items = (uint8_t)(ext | ((opt >> 1) & 1 ? ITS_SPAT_ASSIST : 0) |
                              (n_int == 1 ? ITS_SPAT_WHOLE : 0));

    uint32_t region = its_bits_read(&r, 1) ? its_bits_read(&r, 16) : 0;
    uint32_t iid = its_bits_read(&r, 16);
    uint32_t revision = its_bits_read(&r, 7);
    out->status = (uint16_t)its_bits_read(&r, 16);  /* IntersectionStatusObject flags */
    /* Countdown reference in TimeMark scale: prefer our own NTP clock over the
     * RSU's (its moy/timeStamp freeze across messages); RSU clock is the fallback. */
    uint32_t moy = has_moy ? its_bits_read(&r, 20) : 0;
    uint32_t dsecond = has_ts ? its_bits_read(&r, 16) : 0;
    bool have_clock = has_moy && has_ts && dsecond < 60000;
    uint32_t now_tenths = have_clock ? (moy % 60) * 600 + dsecond / 100 : 0;

    struct timeval tv;
    if (gettimeofday(&tv, NULL) == 0 && tv.tv_sec > 1600000000)
    {
        now_tenths = (uint32_t)((tv.tv_sec % 3600) * 10 + tv.tv_usec / 100000);
        have_clock = true;
    }
    if (has_enabled) return;

    uint32_t n_mov = its_bits_read(&r, 8) + 1;
    uint8_t cnt = 0;
    for (uint32_t m = 0; m < n_mov && !r.err; m++)
    {
        if (its_bits_read(&r, 1))              /* MovementState ext */
            items |= SPAT_EXT_SEEN;
        uint32_t mopt = its_bits_read(&r, 3);  /* movementName,maneuverAssistList,regional */
        bool m_name = (mopt >> 2) & 1, m_maneuver = (mopt >> 1) & 1, m_reg = mopt & 1;
        if (m_name || m_reg) return;
        uint32_t sg = its_bits_read(&r, 8);
        uint32_t n_ev = its_bits_read(&r, 4) + 1;
        uint32_t phase = 0xFF;
        int16_t secs = -1;
        for (uint32_t e = 0; e < n_ev && !r.err; e++)
        {
            if (its_bits_read(&r, 1))          /* MovementEvent ext */
                items |= SPAT_EXT_SEEN;
            uint32_t eopt = its_bits_read(&r, 3);
            bool has_timing = (eopt >> 2) & 1, has_speeds = (eopt >> 1) & 1, has_ereg = eopt & 1;
            uint32_t es = its_bits_read(&r, 4);  /* eventState: 4 bits, no extension marker */
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
                    /* No tighter bound than the TimeMark range itself: a phase can
                     * legitimately last for hours at a traffic-dependent intersection. */
                    if (d <= 36000) secs = (int16_t)(d / 10);
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
            items |= ITS_SPAT_ASSIST;
            uint32_t n_ma = its_bits_read(&r, 4) + 1;
            for (uint32_t k = 0; k < n_ma && !r.err; k++) spat_skip_conn_maneuver(&r);
        }
    }
    if (r.err && cnt == 0) return;   /* nothing usable */
    /* Behind the movements: the intersection's own maneuverAssistList, then its regional part. */
    if (!r.err && ((opt >> 1) & 1))
    {
        uint32_t n_ma = its_bits_read(&r, 4) + 1;
        for (uint32_t k = 0; k < n_ma && !r.err; k++) spat_skip_conn_maneuver(&r);
    }
    if (!r.err && (opt & 1))
        spat_read_regional(&r, &items);
    if (r.err)
        items &= (uint8_t)~ITS_SPAT_WHOLE;
    /* An extension addition that this build cannot place means the message was read only in
     * part. All items are dropped then. Only a set SSP bit gives a yes, and no item read out
     * of shifted bits can turn into a no. */
    if (items & SPAT_EXT_SEEN)
        items &= (uint8_t)~(SPAT_EXT_SEEN | ITS_SPAT_ASSIST | ITS_SPAT_PRIO | ITS_SPAT_WHOLE);

    out->region = (uint16_t)region;
    out->id = (uint16_t)iid;
    out->revision = (uint8_t)revision;
    out->n = cnt;
    out->items = items;
    out->valid = true;
}

/* Defined further down next to read_ext_count. The MAPEM refPoint needs it too. */
static void skip_ext_additions(its_bitr_t *r);

/* The EU profile puts the refPoint altitude here (Position3D-addGrpC, regionId 3) and leaves
 * elevation unused. Each entry is an open type: the outer reader steps over its length first. */
static void read_ref_regional(its_bitr_t *r, bool *has_alt, int32_t *alt_cm)
{
    uint32_t n = its_bits_read(r, 2) + 1;   /* SIZE(1..4) */
    bool taken = false;
    for (uint32_t i = 0; i < n; i++)
    {
        uint32_t region = its_bits_read(r, 8);
        size_t len = its_bits_uper_length(r);
        if (r->err)
            return;
        size_t at = r->pos;
        its_bits_skip(r, len * 8);
        if (r->err)
            return;
        if (region != 3 || taken)
            continue;
        /* Extension bit, then AltitudeValue in 20 bits from -100000. The first usable entry
         * wins over elevation. Raw 900001 is the value 800001, "unavailable". It leaves what
         * elevation gave, like any raw value above it. */
        its_bitr_t c = { r->b, at + len * 8, at, false };
        its_bits_skip(&c, 1);
        uint32_t v = its_bits_read(&c, 20);
        if (!c.err && v <= 900000)
        {
            *has_alt = true;
            *alt_cm = (int32_t)v - 100000;
            taken = true;
        }
    }
}

/* Skips regional entries of a lane and its nodes (EU: LaneAttributes-, NodeAttributeSet-,
 * ConnectionTrajectory-addGrpC). Inlined: as a call its own 48 B frame made the receive task
 * 16 B deeper on riscv32. */
static inline __attribute__((always_inline)) void skip_regional(its_bitr_t *r, uint32_t n)
{
    for (uint32_t i = 0; i < n && !r->err; i++)
    {
        its_bits_skip(r, 8);                             /* regionId */
        its_bits_skip(r, its_bits_uper_length(r) * 8);   /* the entry, an open type */
    }
}

/* --- MAPEM (SAE J2735 MapData) decode ------------------------------------
 * Reads the first IntersectionGeometry's name and id, then the lane geometry
 * that follows them. Node data and regional nodes end it early. `road_seg`
 * (optional) reports whether the message carried a roadSegments list, which
 * the permission check holds against its own SSP bit. It is only written once
 * the intersections question is settled, see below.
 * `ref_has_alt`/`ref_alt_cm` (optional): the refPoint altitude, once its block was read whole. */
static void parse_mapem(const uint8_t *frame, size_t len, size_t start,
                        its_map_t *out, its_map_geom_t *geom, bool *road_seg,
                        bool *ref_has_alt, int32_t *ref_alt_cm)
{
    out->valid = false;
    out->name[0] = '\0';
    its_bitr_t r = its_bitr_init(frame, len, start);

    /* MapData: ext(1) + opt{timeStamp,layerType,layerID,intersections,
     * roadSegments,dataParameters,restrictionList,regional}(8) */
    its_bits_skip(&r, 1);
    uint32_t opt = its_bits_read(&r, 8);
    bool has_ts     = (opt >> 7) & 1;
    bool has_ltype  = (opt >> 6) & 1;
    bool has_lid    = (opt >> 5) & 1;
    bool has_ints   = (opt >> 4) & 1;
    /* Only the option bitmap tells which of the two geometry lists came. It has a fixed
     * place right behind the extension bit. A frame too short for the bitmap sets r.err,
     * and then neither flag may be believed. */
    bool has_roads  = (opt >> 3) & 1;
    bool opt_read   = !r.err;
    if (has_ts) its_bits_skip(&r, 20);  /* MinuteOfTheYear */
    its_bits_skip(&r, 7);               /* msgIssueRevision MsgCount */
    if (has_ltype) return;              /* LayerType (extensible enum, not seen) */
    if (has_lid) its_bits_skip(&r, 7);  /* LayerID 0..100 */
    if (!has_ints)
    {
        /* No intersection list at all, so what this MapData carries is settled here. */
        if (road_seg && opt_read) *road_seg = has_roads;
        return;
    }

    uint32_t n_int = its_bits_read(&r, 5) + 1;  /* IntersectionGeometryList SIZE(1..32) */
    if (n_int < 1) return;

    /* IntersectionGeometry: ext(1) + opt{name,laneWidth,speedLimits,
     * preemptPriorityData,regional}(5) */
    its_bits_skip(&r, 1);
    uint32_t gopt = its_bits_read(&r, 5);
    bool has_name = (gopt >> 4) & 1;
    bool has_lw = (gopt >> 3) & 1;
    bool has_sl = (gopt >> 2) & 1;

    if (has_name)
    {
        /* DescriptiveName ::= IA5String (SIZE(1..63)): 6-bit count-1, then
         * 7 bits per character (128-value alphabet, no octet alignment). */
        uint32_t n = its_bits_read(&r, 6) + 1;
        size_t w = 0;
        for (uint32_t i = 0; i < n && !r.err; i++)
        {
            uint32_t c = its_bits_read(&r, 7);
            if (w + 1 < sizeof(out->name) && c >= 0x20 && c < 0x7F)
                out->name[w++] = (char)c;
        }
        out->name[w] = '\0';
    }
    if (r.err) return;

    /* id IntersectionReferenceID { region OPTIONAL(16b), id 16b } */
    uint32_t region = its_bits_read(&r, 1) ? its_bits_read(&r, 16) : 0;
    uint32_t iid = its_bits_read(&r, 16);
    if (r.err) return;

    out->region = (uint16_t)region;
    out->id = (uint16_t)iid;
    out->valid = true;
    /* An intersection was read, so both lists are known. Reporting the road segment list any
     * earlier would let a MAPEM whose intersections stayed unread pass on bit 1 alone. */
    if (road_seg) *road_seg = has_roads;

    /* Lane geometry is optional enrichment. A walk that ends early leaves the
     * geometry invalid, while name and id stay. */
    out->revision = (uint8_t)its_bits_read(&r, 7);
    /* refPoint Position3D: 3 preamble bits (ext + elevation + regional),
     * then lat/long as UPER-biased integers. */
    bool ref_ext = its_bits_read(&r, 1) != 0;
    bool has_elev = its_bits_read(&r, 1);
    bool ref_regional = its_bits_read(&r, 1);
    uint32_t raw_lat = its_bits_read(&r, 31);
    uint32_t raw_lon = its_bits_read(&r, 32);
    /* Without a real reference point there is no geometry. Lane width, speed limits and the
     * lane list still read fine, so the walk goes on and only the geometry is dropped. */
    int32_t ref_lat = 0, ref_lon = 0;
    if (!pos_from_raw(raw_lat, raw_lon, &ref_lat, &ref_lon))
        geom = NULL;
    bool alt_ok = false;
    int32_t alt = 0;
    if (has_elev)
    {
        /* Elevation counts decimetres from -4096. DSRC.asn reserves -4096 (raw 0) for a
         * sender that does not know its height. */
        uint32_t raw = its_bits_read(&r, 16);
        if (!r.err && raw != 0)
        {
            alt_ok = true;
            alt = ((int32_t)raw - 4096) * 10;
        }
    }
    /* The refPoint's regional part and extensions are walked too. Stopping here would lose
     * the lanes. */
    if (ref_regional) read_ref_regional(&r, &alt_ok, &alt);
    if (ref_ext) skip_ext_additions(&r);
    if (r.err) return;
    if (ref_has_alt) *ref_has_alt = alt_ok;
    if (ref_alt_cm) *ref_alt_cm = alt;

    /* 1e-7 degree units per metre, to turn the cm node offsets into absolute
     * positions. A longitude degree shrinks as latitude grows. */
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
    if (has_lw) out->lane_width_cm = (uint16_t)its_bits_read(&r, 15);  /* LaneWidth, cm */
    if (has_sl)
    {
        /* RegulatorySpeedLimit: kind of limit, then the value in 0.02 m/s steps.
         * Only the plain vehicle max/min are kept; other variants need their own UI. */
        uint32_t n = its_bits_read(&r, 4) + 1;
        for (uint32_t i = 0; i < n && !r.err; i++)
        {
            uint32_t type = its_bits_read(&r, 5), vel = its_bits_read(&r, 13);
            /* 0.02 m/s -> km/h: v * 0.02 * 3.6 = v * 0.072 */
            uint16_t kmh = (uint16_t)((vel * 72 + 500) / 1000);
            if (vel == 8191) continue;    /* Velocity "unavailable" (DSRC.asn), not 590 km/h */
            if (type == 5 && !out->speed_max_kmh) out->speed_max_kmh = kmh;
            if (type == 4 && !out->speed_min_kmh) out->speed_min_kmh = kmh;
        }
    }

    uint32_t n_lanes = its_bits_read(&r, 8) + 1;  /* LaneList SIZE(1..255) */
    uint8_t cnt = 0;
    for (uint32_t li = 0; li < n_lanes && !r.err; li++)
    {
        its_bits_skip(&r, 1);
        uint32_t lopt = its_bits_read(&r, 7);  /* name,ingress,egress,maneuvers,connectsTo,overlays,regional */
        uint32_t lane_id = its_bits_read(&r, 8);
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
            uint32_t n = its_bits_read(&r, 6) + 1;
            for (uint32_t i = 0; i < n && !r.err; i++) its_bits_skip(&r, 7);
        }
        if ((lopt >> 5) & 1) its_bits_skip(&r, 4);  /* ingressApproach */
        if ((lopt >> 4) & 1) its_bits_skip(&r, 4);  /* egressApproach */

        /* LaneAttributes: regional bit, directionalUse 2, sharedWith 10. The regional
         * entry (EU: LaneAttributes-addGrpC) comes after laneType. */
        bool la_regional = its_bits_read(&r, 1);
        its_bits_skip(&r, 2); its_bits_skip(&r, 10);
        its_bits_skip(&r, 1);
        uint32_t ltype = its_bits_read(&r, 3);
        /* `vehicle` is an EXTENSIBLE BIT STRING(8) -> 9 bits; every other
         * lane type (crosswalk, bike, sidewalk, ...) is 16. */
        its_bits_skip(&r, ltype == 0 ? 9 : 16);
        if (la_regional) skip_regional(&r, 1);
        bool is_crosswalk = (ltype == 1);
        if (lg) lg->lane_type = (uint8_t)ltype;

        if ((lopt >> 3) & 1) its_bits_skip(&r, 12);  /* lane-level maneuvers */

        its_bits_skip(&r, 2);                         /* NodeListXY CHOICE */
        uint32_t n_nodes = its_bits_read(&r, 6) + 2;  /* NodeSetXY SIZE(2..63) */
        double x_cm = 0, y_cm = 0;
        for (uint32_t i = 0; i < n_nodes && !r.err; i++)
        {
            its_bits_skip(&r, 1);
            bool has_attr = its_bits_read(&r, 1);
            uint32_t kind = its_bits_read(&r, 3);  /* NodeOffsetPointXY, no ext bit */
            static const uint8_t DELTA[6] = { 10, 11, 12, 13, 14, 16 };
            static const int32_t BIAS[6]  = { 512, 1024, 2048, 4096, 8192, 32768 };
            if (kind < 6)
            {
                /* Offsets are signed centimetres, relative to the previous
                 * node (the first one to the intersection refPoint). */
                int32_t dx = (int32_t)its_bits_read(&r, DELTA[kind]) - BIAS[kind];
                int32_t dy = (int32_t)its_bits_read(&r, DELTA[kind]) - BIAS[kind];
                x_cm += dx; y_cm += dy;
                if (lg && lg->n_nodes < ITS_GEOM_MAX_NODES)
                {
                    lg->lat_e7[lg->n_nodes] = ref_lat + (int32_t)(y_cm / 100.0 * lat_scale);
                    lg->lon_e7[lg->n_nodes] = ref_lon + (int32_t)(x_cm / 100.0 * lon_scale);
                    lg->n_nodes++;
                }
            }
            else if (kind == 6) its_bits_skip(&r, 32 + 31);   /* node-LatLon: lon, then lat */
            else return;                  /* regional node */
            if (!has_attr) continue;

            its_bits_skip(&r, 1);
            uint32_t ao = its_bits_read(&r, 7);  /* localNode,disabled,enabled,data,dWidth,dElevation,regional */
            if ((ao >> 6) & 1)
            {
                uint32_t c = its_bits_read(&r, 3) + 1;
                for (uint32_t k = 0; k < c && !r.err; k++) { its_bits_skip(&r, 1); its_bits_skip(&r, 4); }
            }
            for (int shift = 5; shift >= 4; shift--)   /* disabled, enabled */
                if ((ao >> shift) & 1)
                {
                    uint32_t c = its_bits_read(&r, 3) + 1;
                    for (uint32_t k = 0; k < c && !r.err; k++) its_bits_skip(&r, 7);
                }
            if ((ao >> 3) & 1) return;    /* data attributes, not seen */
            if ((ao >> 2) & 1) its_bits_skip(&r, 10);
            if ((ao >> 1) & 1) its_bits_skip(&r, 10);
            if (ao & 1) skip_regional(&r, its_bits_read(&r, 2) + 1);   /* regional */
        }

        /* Without connectsTo (an egress lane) the lane is geometry only. */
        uint32_t n_conn = ((lopt >> 2) & 1) ? its_bits_read(&r, 4) + 1 : 0;
        for (uint32_t i = 0; i < n_conn && !r.err; i++)
        {
            uint32_t copt = its_bits_read(&r, 4);  /* remoteIntersection,signalGroup,userClass,connectionID */
            bool has_man = its_bits_read(&r, 1);
            its_bits_skip(&r, 8);         /* connecting lane id */
            uint32_t man = has_man ? its_bits_read(&r, 12) : 0;
            /* IntersectionReferenceID = presence bit + optional 16-bit region +
             * 16-bit id, so 17 or 33 bits, never a flat 32. */
            if ((copt >> 3) & 1) { if (its_bits_read(&r, 1)) its_bits_skip(&r, 16); its_bits_skip(&r, 16); }
            uint32_t sg = ((copt >> 2) & 1) ? its_bits_read(&r, 8) : 0xFFFF;
            if ((copt >> 1) & 1) its_bits_skip(&r, 8);  /* userClass -- easy to miss */
            if (copt & 1) its_bits_skip(&r, 8);         /* connectionID */
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
        /* overlays (1..5 LaneIDs) and the regional list (EU: ConnectionTrajectory-addGrpC)
         * close the lane. The next lane starts right after them. */
        if ((lopt >> 1) & 1) its_bits_skip(&r, (its_bits_read(&r, 3) + 1) * 8);
        if (lopt & 1) skip_regional(&r, its_bits_read(&r, 2) + 1);
        if (lg) geom->n_lanes++;
    }
    if (!r.err)
    {
        out->n_sg = cnt;
        if (geom) geom->valid = true;
    }
}

/* TimestampIts is 42 bits wide. The high bits get their own statement because C
 * leaves the evaluation order of the operands of | unspecified. */
static uint64_t read_timestamp_its(its_bitr_t *r)
{
    uint64_t hi = its_bits_read(r, 10);
    return (hi << 32) | its_bits_read(r, 32);
}

/* Skips a DDateTime: seven optional fields, no extension marker, so seven option bits and
 * then only the ones that are there. Widths measured against the ETSI ASN.1 with a second
 * encoder: 12, 4, 5, 5, 6, 16, 11 bits. */
static void skip_ddatetime(its_bitr_t *r)
{
    uint32_t opt = its_bits_read(r, 7);
    static const uint8_t W[7] = { 12, 4, 5, 5, 6, 16, 11 };
    for (int i = 0; i < 7; i++)
        if ((opt >> (6 - i)) & 1)
            its_bits_skip(r, W[i]);
}

/* FullPositionVector of an RTCMEM: the base station the corrections refer to. Longitude
 * comes BEFORE latitude here, unlike everywhere else in the CDD. Returns false when the
 * sequence carried an extension, because then nothing after it can be located. */
static bool parse_rtcm_anchor(its_bitr_t *r, its_decoded_t *d)
{
    bool ext = its_bits_read(r, 1) != 0;
    uint32_t opt = its_bits_read(r, 8);   /* utcTime, elevation, heading, speed,
                                           * posAccuracy, timeConfidence, posConfidence,
                                           * speedConfidence -- in field order */
    if ((opt >> 7) & 1)
        skip_ddatetime(r);
    uint32_t lon = its_bits_read(r, 32);
    uint32_t lat = its_bits_read(r, 31);
    if (!r->err && pos_from_raw(lat, lon, &d->rtcm_lat_e7, &d->rtcm_lon_e7))
        d->rtcm_has_anchor = true;
    /* Elevation counts decimetres with an offset of -4096. DSRC sends -4096 (raw 0) when the
     * sender does not know its elevation, so that is no height. */
    if ((opt >> 6) & 1)
    {
        uint32_t elev = its_bits_read(r, 16);
        if (!r->err && elev != 0)
        {
            d->rtcm_has_elev = true;
            d->rtcm_elev_dm = (int32_t)elev - 4096;
        }
    }
    /* The rest only has to be stepped over, so that the corrections list can be found:
     * heading 15, speed 16, position accuracy 32, time confidence 6, position confidence
     * 8, speed/heading/throttle confidence 8. */
    static const uint8_t W[6] = { 15, 16, 32, 6, 8, 8 };
    for (int i = 0; i < 6; i++)
        if ((opt >> (5 - i)) & 1)
            its_bits_skip(r, W[i]);
    return !ext && !r->err;
}

/* RTCMEM (TS 103 301, RTCMcorrections out of ETSI-ITS-DSRC). What the corrections MEAN is
 * not read: the ASN.1 says the message numbering is the GNSS receiver's business, and the
 * RTCM standard itself is not ours. So the page gets count, length and revision. */
static void parse_rtcmem(const uint8_t *frame, size_t len, size_t start, its_decoded_t *d)
{
    its_bitr_t r = its_bitr_init(frame, len, start);

    its_bits_skip(&r, 1);                 /* extension marker of RTCMcorrections */
    uint32_t opt = its_bits_read(&r, 4);  /* timeStamp, anchorPoint, rtcmHeader, regional */
    uint32_t cnt = its_bits_read(&r, 7);  /* MsgCount 0..127 */
    /* RTCM-Revision is an extensible ENUMERATED: one bit says whether the value is one of
     * the four in the root, then two bits carry which one. A value beyond those four is a
     * normally small number instead: a flag and six bits, or a length in octets. Skipping
     * it as if it were two bits would read every field after it in the wrong place. Same
     * shape as read_small_number in its_srem.c. */
    uint8_t rev = ITS_RTCM_REV_NONE;
    if (its_bits_read(&r, 1) == 0)
        rev = (uint8_t)its_bits_read(&r, 2);
    else if (its_bits_read(&r, 1) == 0)
        its_bits_skip(&r, 6);
    else
    {
        size_t n = its_bits_uper_length(&r);
        if (n == 0 || n > 4)
            return;
        its_bits_skip(&r, n * 8);
    }
    if (r.err)
        return;
    d->rtcm_msg_cnt = (uint8_t)cnt;
    d->rtcm_rev = rev;

    if ((opt >> 3) & 1)
    {
        uint32_t minute = its_bits_read(&r, 20);   /* MinuteOfTheYear 0..527040 */
        if (!r.err && minute <= 527040)
        {
            d->rtcm_has_minute = true;
            d->rtcm_minute = minute;
        }
    }
    if (((opt >> 2) & 1) && !parse_rtcm_anchor(&r, d))
        return;                            /* an extension in there hides everything after */
    if ((opt >> 1) & 1)
    {
        /* RTCMheader: the GNSS status as eight named bits, then the antenna offsets
         * (12 + 9 + 10 bits), which say nothing without the mast's own geometry. */
        uint32_t st = its_bits_read(&r, 8);
        its_bits_skip(&r, 31);
        if (!r.err)
        {
            d->rtcm_has_status = true;
            d->rtcm_status = (uint8_t)st;
        }
    }
    if (r.err)
        return;

    /* RTCMmessageList is SIZE(1..5), so three bits carry the count with 1 as the offset.
     * Every message is an OCTET STRING SIZE(1..1023): ten bits of length, again with 1 as
     * the offset, then the bytes themselves. UPER pads nothing, so they are not aligned. */
    uint32_t n = its_bits_read(&r, 3) + 1;
    if (r.err || n > 5)
        return;
    uint32_t total = 0;
    for (uint32_t i = 0; i < n && !r.err; i++)
    {
        uint32_t l = its_bits_read(&r, 10) + 1;
        if (r.err || l > 1023)
            return;
        its_bits_skip(&r, l * 8);
        total += l;
    }
    if (r.err)
        return;
    d->rtcm_n_msgs = (uint8_t)n;
    d->rtcm_bytes = (uint16_t)total;
}

/* The count of a SEQUENCE OF with an extensible SIZE(lb..ub, ...). One bit says whether the
 * count lies in the root. If it does, the offset from lb follows in the bits the root range
 * needs. If not, a length determinant follows. */
static uint32_t read_ext_count(its_bitr_t *r, uint32_t lb, unsigned root_bits)
{
    if (its_bits_read(r, 1) == 0)
        return lb + its_bits_read(r, root_bits);
    return (uint32_t)its_bits_uper_length(r);
}

/* UPER extension additions behind the root of an extensible SEQUENCE whose extension bit
 * was set: a normally small bitmap length, the bitmap, then one open type for each addition
 * that is present. Same shape as skip_extensions in its_srem.c. */
static void skip_ext_additions(its_bitr_t *r)
{
    size_t n = its_bits_read(r, 1) ? its_bits_uper_length(r) : its_bits_read(r, 6) + 1;
    size_t present = 0;
    for (size_t i = 0; i < n && !r->err; i++)
        present += its_bits_read(r, 1);
    for (size_t i = 0; i < present && !r->err; i++)
    {
        size_t l = its_bits_uper_length(r);
        if (!r->err)
            its_bits_skip(r, l * 8);
    }
}

/* A list says how many entries follow. Every entry carries at least one bit, so a count
 * larger than the bits left in the container is a number the message cannot hold. Without
 * this an announcement of 300 sensors in three bytes would go on the page as 300. */
static bool count_fits(const its_bitr_t *c, uint32_t count)
{
    return !c->err && count <= c->nbits - c->pos;
}

/* Walks the CPM container list in one of the two readings of WrappedCpmContainers
 * SIZE(1..8, ...): with the extension bit in front of the count, as the ASN.1 reads and
 * asn1tools writes, or without it, as Wireshark reads by default. Its developers hold
 * that ConstraintWrappedCpmContainers takes the bit away. Each container is an open type
 * with its own length in bytes and is read through a reader fenced to those bytes, so a
 * misread inside cannot spill into the next one. Writes into d only when `commit` is set.
 * Returns false when the walk runs past the message or meets an impossible count.
 * `tier` says how much the list looks like a conforming one, by what clause 7.1.1 of
 * TS 103 324 says in words. With exactly one of the two ids that name the sender: 2 = no
 * container twice and the perceived object container there ("shall be present"), 1 = one of
 * these two, 0 = neither. Without exactly one such id it is 0. The ASN.1 writes down only
 * part of that. Ids 6..16 are undefined, not wrong. */
static bool cpm_walk(its_bitr_t r, bool with_ext, bool commit, its_decoded_t *d,
                     size_t *end_pos, int *tier)
{
    uint32_t n = with_ext ? read_ext_count(&r, 1, 3) : 1 + its_bits_read(&r, 3);
    if (r.err || n == 0 || n > 16)
        return false;
    uint16_t seen = 0;
    bool twice = false;
    for (uint32_t i = 0; i < n; i++)
    {
        uint32_t id = its_bits_read(&r, 4) + 1;   /* CpmContainerId 1..16 */
        size_t clen = its_bits_uper_length(&r);   /* the open type's length in bytes */
        if (r.err || r.pos + clen * 8 > r.nbits)
            return false;
        if (seen & (uint16_t)(1u << (id - 1)))
            twice = true;
        seen |= (uint16_t)(1u << (id - 1));
        its_bitr_t c = { r.b, r.pos + clen * 8, r.pos, false };
        its_bits_skip(&r, clen * 8);
        if (!commit)
            continue;
        /* The place of each defined id, for its_cpm.c. When a container comes twice, the last
         * one counts, for its place as for its bad bit. A bad last one leaves its count at 0
         * and no heading, and never falls back to an earlier twin's. A place beyond the 16
         * bits of cpm_cont_at is dropped, and an earlier twin's place with it. No frame off
         * the radio is that long. */
        if (id <= ITS_CPM_OBJECTS && c.pos + clen * 8 <= UINT16_MAX)
        {
            d->cpm_cont_at[id - 1] = (uint16_t)c.pos;
            d->cpm_cont_bytes[id - 1] = (uint16_t)clen;
        }
        else if (id <= ITS_CPM_OBJECTS)
        {
            d->cpm_cont_at[id - 1] = 0;
            d->cpm_cont_bytes[id - 1] = 0;
        }
        d->cpm_n_containers++;
        d->cpm_containers |= (uint16_t)(1u << (id - 1));
        /* A twin counts by the last in this as well: an earlier one's bad bit is dropped. */
        d->cpm_cont_bad &= (uint16_t)~(1u << (id - 1));
        switch (id)
        {
        case ITS_CPM_ORIG_VEHICLE:
        {
            its_bits_skip(&c, 1);                  /* extension marker */
            its_bits_skip(&c, 3);                  /* pitch, roll, trailer data */
            /* Wgs84AngleValue 0..3601: 3600 is "do not use", 3601 "unavailable". */
            uint32_t hv = its_bits_read(&c, 12);
            if (c.err)
            {
                d->cpm_cont_bad |= (uint16_t)(1u << (id - 1));
                d->cpm_has_heading = false;
                d->cpm_heading_ddeg = 0;
            }
            else
            {
                d->cpm_has_heading = hv < 3600;
                d->cpm_heading_ddeg = hv < 3600 ? (uint16_t)hv : 0;
            }
            break;
        }
        case ITS_CPM_ORIG_RSU:
            /* its_cpm.c reads the map reference itself. Here only two bits have to be
             * there, the extension marker and the option bit of that reference. */
            its_bits_skip(&c, 2);
            if (c.err)
                d->cpm_cont_bad |= (uint16_t)(1u << (id - 1));
            break;
        case ITS_CPM_SENSOR_INFO:
        {
            uint32_t ns = read_ext_count(&c, 1, 7);    /* SIZE(1..128, ...) */
            if (c.err || !count_fits(&c, ns))
            {
                d->cpm_cont_bad |= (uint16_t)(1u << (id - 1));
                d->cpm_n_sensors = 0;
            }
            else
                d->cpm_n_sensors = (uint16_t)ns;
            break;
        }
        case ITS_CPM_REGION:
        {
            uint32_t nr = read_ext_count(&c, 1, 8);    /* SIZE(1..256, ...) */
            if (c.err || !count_fits(&c, nr))
            {
                d->cpm_cont_bad |= (uint16_t)(1u << (id - 1));
                d->cpm_n_regions = 0;
            }
            else
                d->cpm_n_regions = (uint16_t)nr;
            break;
        }
        case ITS_CPM_OBJECTS:
        {
            its_bits_skip(&c, 1);                      /* extension marker of the container */
            uint32_t known = its_bits_read(&c, 8);     /* numberOfPerceivedObjects */
            uint32_t here = read_ext_count(&c, 0, 8);  /* PerceivedObjects SIZE(0..255, ...) */
            if (c.err || !count_fits(&c, here))
            {
                d->cpm_cont_bad |= (uint16_t)(1u << (id - 1));
                d->cpm_n_objects = 0;
                d->cpm_n_objects_here = 0;
            }
            else
            {
                d->cpm_n_objects = (uint8_t)known;
                d->cpm_n_objects_here = (uint16_t)here;
            }
            break;
        }
        default:
            break;                                     /* counted and marked, content unread */
        }
    }
    *end_pos = r.pos;
    bool one_sender = (seen & 0x3u) == 0x1u || (seen & 0x3u) == 0x2u;
    bool objects = (seen & (1u << (ITS_CPM_OBJECTS - 1))) != 0;
    *tier = !one_sender ? 0 : !twice ? (objects ? 2 : 1) : (objects ? 1 : 0);
    return true;
}

/* A walk ends exactly when at most the padding of the last byte is left and that padding is
 * zero, which is what UPER writes. A walk in the wrong reading is one bit off from the first
 * length onward and practically never lands there. */
static bool cpm_ends_exactly(const its_bitr_t *r, size_t end_pos)
{
    if (end_pos > r->nbits || r->nbits - end_pos >= 8)
        return false;
    its_bitr_t t = { r->b, r->nbits, end_pos, false };
    return its_bits_read(&t, (unsigned)(r->nbits - end_pos)) == 0;
}

/* CPM (TS 103 324): a management container, then the list of containers. `len` must be the
 * exact end of the message, not of the frame, because the choice between the two readings of
 * the list depends on it. Layout measured with asn1tools against the ETSI ASN.1. */
static void parse_cpm(const uint8_t *frame, size_t len, size_t start, its_decoded_t *d)
{
    its_bitr_t r = its_bitr_init(frame, len, start);

    bool payload_ext = its_bits_read(&r, 1) != 0;  /* CpmPayload: additions follow the list */
    bool mgmt_ext = its_bits_read(&r, 1) != 0;     /* ManagementContainer extension marker */
    uint32_t mopt = its_bits_read(&r, 2);          /* segmentationInfo, messageRateRange */
    uint64_t ref_ms = read_timestamp_its(&r);
    uint32_t lat = its_bits_read(&r, 31), lon = its_bits_read(&r, 32);
    its_bits_skip(&r, 12); its_bits_skip(&r, 12); its_bits_skip(&r, 12); /* PosConfidenceEllipse */
    its_bits_skip(&r, 20); its_bits_skip(&r, 4);                         /* altitude + confidence */
    uint8_t seg_total = 0, seg_this = 0;
    if ((mopt >> 1) & 1)
    {
        /* CardinalNumber3b and OrdinalNumber3b, both 1..8 in three bits. */
        seg_total = (uint8_t)(its_bits_read(&r, 3) + 1);
        seg_this = (uint8_t)(its_bits_read(&r, 3) + 1);
    }
    /* messageRateRange: min and max, each a mantissa in 7 bits with offset 1 and an exponent
     * in 3 bits with offset -5. Split only once the read is known to be whole. */
    uint32_t rate = (mopt & 1) ? its_bits_read(&r, 20) : 0;
    /* Additions to the management container come after its root fields and before the
     * list. Stepping over them keeps the list in place. */
    if (mgmt_ext)
        skip_ext_additions(&r);
    /* cpm_pdu_at has 16 bits. No frame off the radio (2346 bytes at most) reaches past them. */
    if (r.err || start / 8 - 6 > UINT16_MAX)
        return;
    d->cpm_read = true;
    d->cpm_ref_ms = ref_ms;
    d->cpm_seg_total = seg_total;
    d->cpm_seg_this = seg_this;
    d->cpm_pdu_at = (uint16_t)(start / 8 - 6);   /* the six-byte ItsPduHeader before `start` */
    if (mopt & 1)
    {
        d->cpm_has_rate = true;
        d->cpm_rate_min_m = (uint8_t)((rate >> 13) + 1);
        d->cpm_rate_min_e = (int8_t)((int)((rate >> 10) & 7u) - 5);
        d->cpm_rate_max_m = (uint8_t)(((rate >> 3) & 0x7Fu) + 1);
        d->cpm_rate_max_e = (int8_t)((int)(rate & 7u) - 5);
    }
    if (pos_from_raw(lat, lon, &d->cpm_lat_e7, &d->cpm_lon_e7))
    {
        d->cpm_has_pos = true;   /* pos_from_raw already threw out what is no place */
    }

    /* Both readings are walked and weighed. The heavier wins, and a tie goes to the ASN.1's
     * own reading. Ending exactly on the message end outweighs everything else. Among exact
     * endings the tier of cpm_walk decides, and a reading that only walks at all comes last.
     * An exact end alone is not enough, because a small message read one bit off can land
     * on its end by chance. On 45000 test messages this misread 6, all in Wireshark's
     * reading and without the object container. Of 50000 with an id sent twice it misreads
     * 18, 13 of them in the ASN.1's own reading. When additions follow the list, the list
     * does not end the message, and only the last step applies. */
    size_t end_a = 0, end_b = 0;
    int tier_a = 0, tier_b = 0;
    bool ok_a = cpm_walk(r, true, false, d, &end_a, &tier_a);
    bool ok_b = cpm_walk(r, false, false, d, &end_b, &tier_b);
    bool exact_a = !payload_ext && ok_a && cpm_ends_exactly(&r, end_a);
    bool exact_b = !payload_ext && ok_b && cpm_ends_exactly(&r, end_b);
    int w_a = !ok_a ? -1 : exact_a ? 100 + tier_a : 0;
    int w_b = !ok_b ? -1 : exact_b ? 100 + tier_b : 0;
    if (w_a < 0 && w_b < 0)
        return;
    bool with_ext = w_a >= w_b;
    (void)cpm_walk(r, with_ext, true, d, &end_a, &tier_a);
    d->cpm_list_form = with_ext ? ITS_CPM_LIST_EXT : ITS_CPM_LIST_NOEXT;
}

/* A UTF8String: in UPER its size constraint is not visible, so it is always an octet count
 * followed by the octets. What is kept is valid UTF-8 by Unicode table 3-7: an overlong
 * form, a surrogate or a value past U+10FFFF is no character. Each broken piece becomes one
 * '?'. A piece ends before the first byte that cannot continue its character, so a broken
 * byte never eats the character after it. What its_utf8_unshown() names becomes '?' as well.
 * A text longer than `cap - 1` bytes ends in U+2026 at a whole character, so a cut text never
 * looks complete. A byte the frame ended inside is no byte and ends the string.
 * With dst NULL the string is only stepped over. */
static void read_utf8(its_bitr_t *r, char *dst, size_t cap)
{
    size_t n = its_bits_uper_length(r);
    size_t k = 0, i = 0;
    bool cut = false;
    int pend = -1;               /* a byte that broke the character before and starts the next */
    while ((pend >= 0 || i < n) && !r->err)
    {
        uint8_t c;
        if (pend >= 0)
        {
            c = (uint8_t)pend;
            pend = -1;
        }
        else
        {
            c = (uint8_t)its_bits_read(r, 8);
            if (r->err)
                break;
            i++;
        }
        uint8_t lo, hi;
        size_t w = its_utf8_lead(c, &lo, &hi);
        uint8_t ch[4] = { c, 0, 0, 0 };
        size_t got = 1;
        while (w > 1 && got < w && i < n)
        {
            uint8_t cc = (uint8_t)its_bits_read(r, 8);
            if (r->err)
                break;
            i++;
            if (cc < (got == 1 ? lo : 0x80) || cc > (got == 1 ? hi : 0xBF))
            {
                pend = cc;
                break;
            }
            ch[got++] = cc;
        }
        if (r->err)
            break;
        bool valid = w > 0 && got == w;
        if (valid && its_utf8_unshown(its_utf8_cp(ch, w)))
            valid = false;
        if (!dst || cut)
            continue;
        size_t need = valid ? w : 1;
        if (k + need + 1 > cap)
        {
            cut = true;
            continue;
        }
        if (valid)
            for (size_t j = 0; j < w; j++)
                dst[k++] = (char)ch[j];
        else
            dst[k++] = '?';
    }
    if (!dst)
        return;
    if (cut && cap >= 4)
    {
        /* Room for the three bytes of the ellipsis, made by dropping whole characters. */
        while (k + 3 + 1 > cap && k > 0)
        {
            do
                k--;
            while (k > 0 && ((uint8_t)dst[k] & 0xC0) == 0x80);
        }
        memcpy(dst + k, "\xE2\x80\xA6", 3);
        k += 3;
    }
    dst[k] = '\0';
}

/* EVCSN (TS 101 556-1, Annex A; the module is not on ETSI-Forge), as messageId 11 or as 3 at
 * version 0. A POI header, then a list of charging stations of which the first is read.
 * Nothing in here is extensible except the station itself, and its additions come after
 * its last field, so they never move anything this reads. Layout measured with asn1tools. */
static void parse_evcsn(const uint8_t *frame, size_t len, size_t start, its_decoded_t *d)
{
    its_bitr_t r = its_bitr_init(frame, len, start);

    uint32_t poi = its_bits_read(&r, 16);          /* POIType 0..65535 */
    uint64_t ts = read_timestamp_its(&r);
    bool relay = its_bits_read(&r, 1) != 0;
    uint32_t total = its_bits_read(&r, 8) + 1;     /* NumberStations 1..256 */
    uint32_t nst = its_bits_read(&r, 8) + 1;       /* SIZE(1..256) */
    if (r.err)
        return;
    d->evcsn_read = true;
    d->evcsn_poi_type = (uint16_t)poi;
    d->evcsn_ts_ms = ts;
    d->evcsn_relay = relay;
    d->evcsn_n_total = (uint16_t)total;
    d->evcsn_n_stations = (uint16_t)nst;

    /* The first ItsChargingStationData: an extension bit, then the seven optional fields in
     * the order of the ASN.1 -- utilityDistributorId, providerID, address, phoneNumber,
     * digitalMap, bookingContactInfo, payment. */
    its_bits_skip(&r, 1);
    uint32_t opt = its_bits_read(&r, 7);
    uint32_t sid = its_bits_read(&r, 32);
    if ((opt >> 6) & 1) read_utf8(&r, NULL, 0);
    if ((opt >> 5) & 1) read_utf8(&r, NULL, 0);
    uint32_t lat = its_bits_read(&r, 31), lon = its_bits_read(&r, 32);
    its_bits_skip(&r, 12); its_bits_skip(&r, 12); its_bits_skip(&r, 12); /* PosConfidenceEllipse */
    its_bits_skip(&r, 20); its_bits_skip(&r, 4);                         /* altitude + confidence */
    if ((opt >> 4) & 1) read_utf8(&r, NULL, 0);
    /* NumericString SIZE(1..16): four bits of count, then four bits a digit. */
    if ((opt >> 3) & 1)
        its_bits_skip(&r, (its_bits_read(&r, 4) + 1) * 4);
    /* Read into locals first: a frame that ends inside the station must not leave half a
     * station behind. Zeroed, as the memcpy below also copies the bytes after each NUL. */
    char access[ITS_EVCSN_TEXT + 1] = { 0 }, hours[ITS_EVCSN_TEXT + 1] = { 0 },
         price[ITS_EVCSN_TEXT + 1] = { 0 };
    read_utf8(&r, access, sizeof access);
    /* DigitalMap: SIZE(1..256) of ReferencePosition, 123 bits each. */
    if ((opt >> 2) & 1)
        its_bits_skip(&r, (size_t)(its_bits_read(&r, 8) + 1) * 123);
    read_utf8(&r, hours, sizeof hours);
    read_utf8(&r, price, sizeof price);
    if ((opt >> 1) & 1) read_utf8(&r, NULL, 0);
    if (opt & 1) read_utf8(&r, NULL, 0);
    if (r.err)
        return;
    d->evcsn_st_id = sid;
    memcpy(d->evcsn_access, access, sizeof access);
    memcpy(d->evcsn_hours, hours, sizeof hours);
    memcpy(d->evcsn_price, price, sizeof price);
    if (pos_from_raw(lat, lon, &d->evcsn_lat_e7, &d->evcsn_lon_e7))
    {
        d->evcsn_has_pos = true;   /* pos_from_raw already threw out what is no place */
    }

    /* ItsChargingSpots SIZE(1..16). A spot is not extensible: two option bits (evEquipmentID,
     * parkingPlacesData), then ChargingSpotType as a BIT STRING without a size. That is a
     * length in BITS, then the bits, named bit 0 first. */
    uint32_t nsp = its_bits_read(&r, 4) + 1;
    uint16_t modes = 0;
    for (uint32_t i = 0; i < nsp && !r.err; i++)
    {
        uint32_t sopt = its_bits_read(&r, 2);
        size_t nb = its_bits_uper_length(&r);
        for (size_t b = 0; b < nb && !r.err; b++)
            if (its_bits_read(&r, 1) && b < 16)
                modes |= (uint16_t)(1u << b);
        if ((sopt >> 1) & 1) read_utf8(&r, NULL, 0);          /* evEquipmentID */
        its_bits_skip(&r, its_bits_uper_length(&r));           /* typeOfReceptacle, in bits */
        read_utf8(&r, NULL, 0);                                /* energyAvailability */
        /* ParkingPlacesData SIZE(1..4) of SpotAvailability: 11 bits of minutes, 1 blocking. */
        if (sopt & 1)
            its_bits_skip(&r, (its_bits_read(&r, 2) + 1) * 12);
    }
    if (r.err)
        return;
    d->evcsn_n_spots = (uint8_t)nsp;
    d->evcsn_modes = modes;
}

/* DENM LocationContainer: how fast and in which direction things move at the hazard, the
 * detection zone leading to it and the kind of road. The trace points are deltas from the
 * eventPosition, the same PathHistory shape the CAM carries, so they are summed back the
 * same way. Called with the reader standing on the container. */
static void parse_denm_location(its_bitr_t *r, its_decoded_t *d)
{
    /* Its additions follow roadType, after everything read here, so nothing needs skipping. */
    its_bits_skip(r, 1);                    /* LocationContainer extension bit */
    uint32_t lopt = its_bits_read(r, 3);    /* eventSpeed, eventPositionHeading, roadType */
    uint16_t speed = 0, heading = 0;
    if ((lopt >> 2) & 1)
    {
        speed = (uint16_t)its_bits_read(r, 14);   /* SpeedValue, 0.01 m/s */
        its_bits_skip(r, 7);                      /* speedConfidence */
    }
    if ((lopt >> 1) & 1)
    {
        heading = (uint16_t)its_bits_read(r, 12); /* HeadingValue, 0.1 degree */
        its_bits_skip(r, 7);                      /* headingConfidence */
    }
    if (r->err)
        return;
    /* 16383 is the speed's "unavailable" and must not reach the page as a number. */
    if (((lopt >> 2) & 1) && speed != 16383)
    {
        d->denm_has_speed = true;
        d->denm_speed_cms = speed;
    }
    /* 3601 is "unavailable" and 3602 and above do not exist. 3600 stays (doNotUse in 2.x,
     * 360.0 deg in 1.x), the same bound as for the CAM. */
    if (((lopt >> 1) & 1) && heading <= 3600)
    {
        d->denm_has_heading = true;
        d->denm_heading_ddeg = heading;
    }

    /* Traces is SEQUENCE SIZE(1..7), so 3 bits carry the count with 1 as the offset.
     * Every trace is a PathHistory of its own. Only the first one is kept. */
    uint32_t nt = its_bits_read(r, 3) + 1;
    if (r->err || nt > 7)
        return;
    int32_t plat = d->denm_lat_e7, plon = d->denm_lon_e7;
    for (uint32_t t = 0; t < nt && !r->err; t++)
    {
        uint32_t n = its_bits_read(r, 6);   /* PathHistory SIZE(0..40), as in the CAM */
        if (r->err || n > 40)
            return;
        for (uint32_t i = 0; i < n && !r->err; i++)
        {
            uint32_t popt = its_bits_read(r, 1);        /* pathDeltaTime present */
            int32_t dlat = (int32_t)its_bits_read(r, 18) - 131071;
            int32_t dlon = (int32_t)its_bits_read(r, 18) - 131071;
            its_bits_skip(r, 15);                       /* deltaAltitude */
            if (popt) { its_bits_skip(r, 1); its_bits_skip(r, 16); }
            plat += dlat;
            plon += dlon;
            /* Only the first trace is kept, and only while the event position was read:
             * without it the sum would start at zero and put the trail off Africa. */
            if (!r->err && t == 0 && d->has_denm_pos && d->denm_n_path < ITS_PATH_MAX)
            {
                d->denm_path_lat_e7[d->denm_n_path] = plat;
                d->denm_path_lon_e7[d->denm_n_path] = plon;
                d->denm_n_path++;
            }
        }
        /* A pair, set once the first trace was read whole: events_log folds them together, and
         * a cut trace or 41..63 points would replace a known count with none. */
        if (t == 0 && !r->err)
        {
            d->denm_n_traces = (uint8_t)nt;
            d->denm_path_len = (uint8_t)n;
        }
    }
    if (r->err)
        return;
    if (lopt & 1)
    {
        uint32_t road = its_bits_read(r, 2);
        if (!r->err)
            d->denm_road_type = (uint8_t)road;
    }
}

/* DENM ManagementContainer and cause (TS 103 831/CDD). DenmPayload has NO extension
 * marker, so do not read one. The CHOICE index doubles as the classic cause code. */
static void parse_denm(const uint8_t *frame, size_t len, size_t start,
                       uint8_t version, its_decoded_t *d)
{
    its_bitr_t r = its_bitr_init(frame, len, start);

    uint32_t dopt = its_bits_read(&r, 3);   /* situation, location, alacarte */
    bool has_situation = (dopt >> 2) & 1;

    bool mext = its_bits_read(&r, 1) != 0;  /* ManagementContainer extension bit */
    uint32_t mopt = its_bits_read(&r, 5);   /* termination, awarenessDistance, trafficDirection,
                                             * validityDuration, transmissionInterval */

    d->denm_station = its_bits_read(&r, 32);        /* actionId.originatingStationId */
    d->denm_seq = (uint16_t)its_bits_read(&r, 16);  /* actionId.sequenceNumber */

    uint64_t detection_ms = read_timestamp_its(&r);
    uint64_t reference_ms = read_timestamp_its(&r);
    uint8_t termination = ITS_DENM_TERM_NONE;
    if ((mopt >> 4) & 1)                    /* Termination: 1 bit, no extension marker */
        termination = its_bits_read(&r, 1) ? ITS_DENM_TERM_NEGATION : ITS_DENM_TERM_CANCELLATION;

    /* eventPosition is where the hazard IS, not where the sender is. */
    uint32_t elat = its_bits_read(&r, 31), elon = its_bits_read(&r, 32);
    if (!r.err && pos_from_raw(elat, elon, &d->denm_lat_e7, &d->denm_lon_e7))
    {
        d->has_denm_pos = true;   /* pos_from_raw already threw out what is no place */
    }
    its_bits_skip(&r, 12); its_bits_skip(&r, 12); its_bits_skip(&r, 12); /* positionConfidenceEllipse */
    /* Altitude of the hazard, 20 bits with -100000 as the offset and 900001 as "unavailable".
     * It is the same encoding as the CAM's reference position. */
    uint32_t ealt = its_bits_read(&r, 20);
    its_bits_skip(&r, 4);                                                /* altitudeConfidence */
    uint8_t aware_dist = ITS_DENM_DIST_NONE, traffic_dir = ITS_DENM_DIR_NONE;
    if ((mopt >> 3) & 1) aware_dist = (uint8_t)its_bits_read(&r, 3);     /* StandardLength3b */
    if ((mopt >> 2) & 1) traffic_dir = (uint8_t)its_bits_read(&r, 2);    /* TrafficDirection */
    bool validity_sent = (mopt >> 1) & 1;
    /* validityDuration is DEFAULT 600, so an absent field means 600 seconds. */
    uint32_t validity_s = validity_sent ? its_bits_read(&r, 17) : 600;
    /* DeltaTimeMilliSecondPositive is 1..10000, so the offset is 1 and 14 bits carry it. */
    uint32_t tx_interval = (mopt & 1) ? its_bits_read(&r, 14) + 1 : 0;
    uint32_t station_type = its_bits_read(&r, 8);

    if (!r.err)
    {
        d->denm_termination = termination;
        d->denm_detection_ms = detection_ms;
        d->denm_reference_ms = reference_ms;
        d->denm_validity_s = validity_s;
        d->denm_validity_sent = validity_sent;
        d->denm_aware_dist = aware_dist;
        d->denm_traffic_dir = traffic_dir;
        d->denm_tx_interval_ms = tx_interval > 0xFFFFu ? 0xFFFFu : (uint16_t)tx_interval;
        d->denm_station_type = (uint8_t)station_type;
        if (ealt <= 900000)
        {
            d->denm_has_alt = true;
            d->denm_alt_cm = (int32_t)ealt - 100000;
        }
    }
    /* Additions follow stationType, in front of the SituationContainer. The root fields are
     * committed first: they were read whole, whatever the additions hold. */
    if (mext)
        skip_ext_additions(&r);
    if (r.err)
        return;

    if (has_situation)
    {
        bool sext = its_bits_read(&r, 1) != 0;  /* SituationContainer extension bit */
        /* linkedCause first, then eventHistory (eventZone from version 2 on). Both are walked
         * over below, eventZone only counted, so the location container stays reachable. */
        uint32_t sopt = its_bits_read(&r, 2);
        uint32_t quality = its_bits_read(&r, 3);        /* InformationQuality 0..7 */
        /* protocolVersion 1 sends the cause as two bytes without an extension marker. Later
         * versions put one in front, both in CauseCode with an extension and in CauseCodeV2. */
        if (version != 1)
            its_bits_skip(&r, 1);           /* extension bit of the cause */
        uint32_t cause = its_bits_read(&r, 8);  /* CauseCodeChoice index = cause code */
        uint32_t sub   = its_bits_read(&r, 8);  /* the chosen alternative's sub-cause */
        if (r.err)
            return;
        d->denm_cause = (uint8_t)cause;
        d->denm_subcause = (uint8_t)sub;
        d->denm_info_quality = (uint8_t)quality;

        if ((sopt >> 1) & 1)                /* linkedCause: a second cause code */
        {
            if (version != 1)
                its_bits_skip(&r, 1);
            its_bits_skip(&r, 16);
        }
        if (sopt & 1)
        {
            /* EventHistory: 1..23 points, so 5 bits carry the count with 1 as the offset.
             * Each point is a delta position, an optional delta time and its own quality. */
            uint32_t np = its_bits_read(&r, 5) + 1;
            if (r.err || np > 23)
                return;
            for (uint32_t i = 0; i < np && !r.err; i++)
            {
                uint32_t topt = its_bits_read(&r, 1);
                its_bits_skip(&r, 18); its_bits_skip(&r, 18); its_bits_skip(&r, 15);
                if (topt) { its_bits_skip(&r, 1); its_bits_skip(&r, 16); }
                its_bits_skip(&r, 3);
            }
            if (!r.err)
                d->denm_n_hist = (uint8_t)np;
        }
        /* Version 2.2 puts linkedDenms and eventEnd here, before the LocationContainer.
         * Without the skip the location would be read from the wrong bits. */
        if (sext)
            skip_ext_additions(&r);
        if (r.err)
            return;
    }

    if ((dopt >> 1) & 1)
        parse_denm_location(&r, d);
}

/* Walks the CAM structurally to specialVehicleContainer, names the container it finds and
 * notes the two zone announcements. PathHistory is SIZE(0..40) with a 6-bit length, as in
 * ITS-Container V1.3.1 and in the CDD from V2.2.1 on. Returns true for a public transport
 * container that was read, which is what pt_container means. */
static bool parse_cam_detail(const uint8_t *frame, size_t len, size_t start,
                             its_decoded_t *d)
{
    bool *out_embarking = &d->pt_embarking;
    its_cam_detail_t *cd = &d->cam;
    cd->role = 0xFF;

    if (start < 12)
        return false;

    /* The CamParameters preamble is 12 bits before the anchor, NOT 4. The nine
     * bits in between are the basicContainer extension marker and stationType. */
    uint32_t pre;
    if (!read_bits_msb(frame, len, start - 12, 3, &pre))
        return false;
    bool has_lf = (pre >> 1) & 1;
    bool has_sv = pre & 1;

    its_bitr_t r = its_bitr_init(frame, len, start);

    /* ReferencePosition is kept because PathHistory's deltas are relative to
     * it and have to be summed back into absolute positions. */
    uint32_t raw_lat = its_bits_read(&r, 31);
    uint32_t raw_lon = its_bits_read(&r, 32);
    int32_t ref_lat = 0, ref_lon = 0;
    bool ref_ok = pos_from_raw(raw_lat, raw_lon, &ref_lat, &ref_lon);
    its_bits_skip(&r, 12); its_bits_skip(&r, 12); its_bits_skip(&r, 12);  /* positionConfidenceEllipse */
    /* AltitudeValue is constrained to -100000..800001, so 20 bits with the lower bound
     * as the offset. 900001 is the encoded "unavailable" (value 800001). */
    uint32_t alt = its_bits_read(&r, 20);
    its_bits_skip(&r, 4);                         /* altitudeConfidence */
    if (!r.err && alt <= 900000)
    {
        cd->has_alt = true;
        cd->alt_cm = (int32_t)alt - 100000;
    }

    /* HighFrequencyContainer CHOICE: 2 alternatives + extension marker. */
    if (its_bits_read(&r, 1))
        return false;               /* extension alternative -- unknown shape */
    if (its_bits_read(&r, 1) != 0)
    {
        /* rsuContainerHighFrequency, not a vehicle. It is an extensible SEQUENCE, so the
         * extension bit comes first and the option bit for its zone list right after it.
         * That option bit is readable even when an extension follows. */
        its_bits_skip(&r, 1);
        uint32_t zones = its_bits_read(&r, 1);
        if (!r.err)
        {
            d->cam_zone = zones != 0;
            /* An RSU CAM carries no vehicle containers, so the choice is settled. */
            if (!has_lf && !has_sv)
                d->cam_special = ITS_CAM_SVC_NONE;
        }
        return false;
    }

    uint32_t hopt = its_bits_read(&r, 7);  /* no extension marker on this SEQUENCE */
    uint32_t hdg = its_bits_read(&r, 12); its_bits_skip(&r, 7);  /* heading value + confidence */
    if (!r.err && hdg <= 3600)      /* 3601 = unavailable */
    {
        cd->has_heading = true;
        cd->heading_ddeg = (uint16_t)hdg;
    }
    its_bits_skip(&r, 14); its_bits_skip(&r, 7);  /* speed */
    cd->drive_dir = (uint8_t)its_bits_read(&r, 2);          /* driveDirection */
    its_bits_skip(&r, 10); its_bits_skip(&r, 3);  /* vehicleLength + confidence */
    its_bits_skip(&r, 6);                         /* vehicleWidth */
    /* LongitudinalAccelerationValue is -160..161, so 9 bits with -160 as the offset.
     * 321 is the encoded "unavailable" (value 161). */
    uint32_t la = its_bits_read(&r, 9);
    its_bits_skip(&r, 7);                         /* accelerationConfidence */
    if (!r.err && la <= 320)
    {
        cd->has_long_accel = true;
        cd->long_accel = (int16_t)((int32_t)la - 160);
    }
    its_bits_skip(&r, 11); its_bits_skip(&r, 3);  /* curvature value + confidence */
    its_bits_skip(&r, 1); its_bits_skip(&r, 2);   /* curvatureCalculationMode (extensible) */
    its_bits_skip(&r, 16); its_bits_skip(&r, 4);  /* yawRate value + confidence */
    if ((hopt >> 6) & 1)
    {
        uint32_t ac = its_bits_read(&r, 7);    /* accelerationControl */
        if (!r.err) { cd->has_accel_ctrl = true; cd->accel_ctrl = (uint8_t)ac; }
    }
    if ((hopt >> 5) & 1)
    {
        uint32_t lp = its_bits_read(&r, 4);     /* lanePosition, -1..14 */
        if (!r.err)
        {
            cd->has_lane = true;
            cd->lane = (int8_t)((int32_t)lp - 1);
        }
    }
    if ((hopt >> 4) & 1) { its_bits_skip(&r, 10); its_bits_skip(&r, 7); }  /* steeringWheelAngle */
    if ((hopt >> 3) & 1) { its_bits_skip(&r, 9); its_bits_skip(&r, 7); }   /* lateralAcceleration */
    if ((hopt >> 2) & 1) { its_bits_skip(&r, 9); its_bits_skip(&r, 7); }   /* verticalAcceleration */
    if ((hopt >> 1) & 1) its_bits_skip(&r, 3);  /* performanceClass */
    if (hopt & 1)
    {
        d->cam_zone = true;                    /* shares its SSP bit with the RSU zone list */
        its_bits_skip(&r, 1);                  /* CenDsrcTollingZone ext */
        uint32_t zopt = its_bits_read(&r, 1);
        its_bits_skip(&r, 31); its_bits_skip(&r, 32);  /* protectedZone lat / long */
        if (zopt) its_bits_skip(&r, 16);               /* cenDsrcTollingZoneID */
    }

    if (has_lf)
    {
        if (its_bits_read(&r, 1))
            return false;           /* LowFrequencyContainer extension */
        /* Only one alternative in the root, so the CHOICE index is 0 bits. */
        uint32_t role = its_bits_read(&r, 4);    /* vehicleRole */
        uint32_t lights = its_bits_read(&r, 8);  /* exteriorLights */
        if (!r.err)
        {
            cd->role = (uint8_t)role;
            cd->has_lights = true;
            cd->ext_lights = (uint8_t)lights;
        }
        uint32_t n = its_bits_read(&r, 6);  /* PathHistory length -- see note above */
        if (n > 40 || r.err)
            return false;
        /* Each point is an offset from the PREVIOUS one, the first from the
         * reference position, so they have to be accumulated. */
        int32_t plat = ref_lat, plon = ref_lon;
        for (uint32_t i = 0; i < n && !r.err; i++)
        {
            uint32_t popt = its_bits_read(&r, 1);  /* pathDeltaTime present */
            int32_t dlat = (int32_t)its_bits_read(&r, 18) - 131071;
            int32_t dlon = (int32_t)its_bits_read(&r, 18) - 131071;
            its_bits_skip(&r, 15);             /* deltaAltitude */
            if (popt) { its_bits_skip(&r, 1); its_bits_skip(&r, 16); }  /* extensible constraint */
            plat += dlat;
            plon += dlon;
            /* Without a real reference position the sums are no real places either. The
             * walk still goes on for what comes after the path. */
            if (!r.err && ref_ok && cd->n_path < ITS_PATH_MAX)
            {
                cd->path_lat_e7[cd->n_path] = plat;
                cd->path_lon_e7[cd->n_path] = plon;
                cd->n_path++;
            }
        }
    }

    if (!has_sv)
    {
        if (!r.err)
            d->cam_special = ITS_CAM_SVC_NONE;  /* no special-vehicle container follows */
        return false;
    }

    /* SpecialVehicleContainer CHOICE: 7 alternatives + extension marker. */
    if (its_bits_read(&r, 1))
    {
        if (!r.err)
            d->cam_special = ITS_CAM_SVC_EXT;
        return false;
    }
    uint32_t svc = its_bits_read(&r, 3);
    if (r.err)
        return false;
    d->cam_special = (uint8_t)(ITS_CAM_SVC_PT + svc);
    if (svc != 0)
        return false;               /* not publicTransportContainer, so nothing more is read */

    uint32_t topt = its_bits_read(&r, 1);  /* ptActivation present */
    bool embarking = its_bits_read(&r, 1) != 0;
    if (r.err)
        return false;
    if (out_embarking) *out_embarking = embarking;
    if (!topt)
        return true;                /* PT vehicle, but no line telegram */

    its_bits_skip(&r, 8);                        /* ptActivationType (1 = VDV R09) */
    uint32_t nbytes = its_bits_read(&r, 5) + 1;  /* PtActivationData SIZE(1..20) */
    if (nbytes > 20 || r.err)
        return false;

    /* VDV R09.16, 9 bytes, numbers in BCD: 0 Modus(4)|TY(4), 1 ZV(1)|ZW(3)|TL(4),
     * 2-3 MP(16), 4 PR(2)|HA(2)|LN1(4), 5 LN2|LN3, 6 KN, 7 ZN1|ZN2, 8 ZN3|ZL(3). */
    if (nbytes < 9)
        return true;
    uint8_t b[9];
    for (int i = 0; i < 9; i++)
        b[i] = (uint8_t)its_bits_read(&r, 8);
    if (r.err)
        return false;
    /* Gate on Modus=9, TY=1 AND TL=6: only that combination has the fixed
     * R09.16 layout below. Modus alone would force-decode other subtypes. */
    if ((b[0] >> 4) != 9 || (b[0] & 0x0F) != 1 || (b[1] & 0x0F) != 6)
        return true;

    uint8_t ln1 = b[4] & 0x0F, ln2 = b[5] >> 4,   ln3 = b[5] & 0x0F;
    uint8_t kn1 = b[6] >> 4,   kn2 = b[6] & 0x0F;
    uint8_t zn1 = b[7] >> 4,   zn2 = b[7] & 0x0F, zn3 = b[8] >> 4;
    if (ln1 > 9 || ln2 > 9 || ln3 > 9 || kn1 > 9 || kn2 > 9 ||
        zn1 > 9 || zn2 > 9 || zn3 > 9)
        return true;                /* not BCD -- report the container only */

    d->pt_line      = (uint16_t)(ln1 * 100 + ln2 * 10 + ln3);
    d->pt_course    = (uint8_t)(kn1 * 10 + kn2);
    d->pt_dest      = (uint16_t)(zn1 * 100 + zn2 * 10 + zn3);
    d->pt_point     = (uint16_t)((b[2] << 8) | b[3]);
    d->pt_priority  = (uint8_t)(b[4] >> 6);
    d->pt_request   = (uint8_t)((b[4] >> 4) & 0x03);
    d->pt_train_len = (uint8_t)(b[8] & 0x07);   /* ZL is 3 bits, not 4 */
    /* ZV is the sign of the schedule deviation: 0 = late, 1 = early. */
    int16_t zw = (int16_t)((b[1] >> 4) & 0x07);
    d->pt_deviation = (b[1] & 0x80) ? (int16_t)-zw : zw;
    d->pt_telegram  = true;
    return true;
}


/* Unwraps a TS 103 097 Secured Packet just far enough to reach the embedded
 * GeoNetworking payload; unknown CHOICE tags bail out to plain "Signed". */
static bool unwrap_secured(const uint8_t *frame, size_t len, size_t off,
                           size_t *inner_off, size_t *inner_len)
{
    /* off is right after the 4-byte GN Basic Header. */
    if (len < off + 6) return false;
    /* frame[off]   = Ieee1609Dot2Data.protocolVersion (not checked) */
    uint8_t content_tag = frame[off + 1];
    /* frame[off+2..+4] = hashId, payload choice-tag, payload.data.protocolVersion:
     * unchecked, but each a fixed single byte, so the offsets below still hold. */
    uint8_t inner_tag = frame[off + 5];
    if (content_tag != 0x81 || inner_tag != 0x80)
        return false;

    size_t value_len, field_len;
    if (!its_oer_length(frame, len, off + 6, &value_len, &field_len))
        return false;
    size_t start = off + 6 + field_len;
    if (start > len)
        return false;

    *inner_off = start;
    *inner_len = value_len < (len - start) ? value_len : (len - start);
    return true;
}

/* Like its_decode_frame, but walks only far enough to reach a MAPEM body and
 * decode its lane geometry. Separate so the kilobyte-sized result stays off the
 * packet path's stack. Call it rarely, once per intersection revision. */
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
                            &station, &pdu_off, &pv_off, NULL);
    }
    else if (basic_nh == 1)
        parse_common_onward(frame, len, off, label, sizeof(label),
                            &station, &pdu_off, &pv_off, NULL);
    else
        return false;

    if (pdu_off == SIZE_MAX || pdu_len < pdu_off + 6 || frame[pdu_off + 1] != 5)
        return false;

    its_map_t tmp;
    /* No road_seg here: the geometry walk has no permission check behind it. The altitude
     * reaches spatem through its_decode_frame. */
    parse_mapem(frame, pdu_len, (pdu_off + 6) * 8, &tmp, out, NULL, NULL, NULL);
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
    /* 0 is a real value in all five of these (unknown station type, lessThan50m,
     * allTrafficDirections, urban without separation, quality 0), so "not read" needs a
     * value of its own. */
    r->denm_station_type = ITS_DENM_STATION_NONE;
    r->denm_aware_dist = ITS_DENM_DIST_NONE;
    r->denm_traffic_dir = ITS_DENM_DIR_NONE;
    r->denm_road_type = ITS_DENM_ROAD_NONE;
    r->denm_info_quality = ITS_DENM_QUALITY_NONE;
    /* Revision 0 means "unknown" and is a real value of the standard. */
    r->rtcm_rev = ITS_RTCM_REV_NONE;
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

    /* Addr2 = sender, fixed at offset 10 for the frame shape accepted above. */
    memcpy(r->src_mac, frame + 10, 6);
    r->has_src_mac = true;

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
    /* It stays outside a signed envelope, so its_gn.c reads LT and RHL even for "Signed". */
    if (off < 0xFFFF) r->gn_basic_at = (uint16_t)off;
    off += 4;

    char label[32];
    const char *station = NULL;
    size_t pdu_off = SIZE_MAX;
    size_t pv_off = SIZE_MAX;
    size_t pdu_len = len; /* bound for the pdu_off reads. The secured path recomputes it. */
    size_t common_off = SIZE_MAX;   /* where the GN Common Header starts, for PL and its_gn.c */

    if (basic_nh == 2)
    {
        size_t inner_off, inner_len;
        if (unwrap_secured(frame, len, off, &inner_off, &inner_len))
        {
            pdu_len = inner_off + inner_len;
            common_off = inner_off;
            parse_common_onward(frame, pdu_len, inner_off, label, sizeof(label),
                                &station, &pdu_off, &pv_off, r);
        }
        else
            snprintf(label, sizeof(label), "Signed");
    }
    else if (basic_nh == 1)
    {
        common_off = off;
        parse_common_onward(frame, len, off, label, sizeof(label),
                            &station, &pdu_off, &pv_off, r);
    }
    else
    {
        snprintf(label, sizeof(label), "?"); /* not "Common Header follows" */
    }

    /* Two bounded steps, not one "%s %s": the label buffer is as large as the
     * output, so a single format is truncatable and -Werror rejects it. */
    size_t lo = 0;
    if (station)
    {
        int n = snprintf(out, out_size, "%s ", station);
        lo = (n > 0 && (size_t)n < out_size) ? (size_t)n : out_size - 1;
    }
    snprintf(out + lo, out_size - lo, "%s", label);

    /* ItsPduHeader.stationId exists for EVERY facility message, not just CAM.
     * Both position paths below use it as the map marker's tracking key. */
    bool have_sid = pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6;
    uint32_t sid = have_sid ? rd_u32be(frame + pdu_off + 2) : 0;

    /* Raw numeric type fields (station type from the Source Position Vector,
     * messageId from the ITS PDU header) for callers that aggregate/branch. */
    if (pv_off != SIZE_MAX && pdu_len > pv_off)
        r->station_type = (frame[pv_off] >> 2) & 0x1F;
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 2)
    {
        r->pdu_version = frame[pdu_off];
        r->message_id = frame[pdu_off + 1];
    }
    /* Where the Common Header and the position vector lie, for its_gn.c. pdu_len ends the bytes
     * the Common Header belongs to: the frame, or the signed payload. */
    if (common_off != SIZE_MAX && pdu_len <= 0xFFFF)
    {
        r->gn_common_at = (uint16_t)common_off;
        r->gn_end = (uint16_t)pdu_len;
    }
    if (pv_off != SIZE_MAX && pv_off < 0xFFFF)
        r->gn_pv_at = (uint16_t)pv_off;

    /* SPATEM (messageId 4): traffic-light phases. Every facility body starts
     * right after the 6-byte ItsPduHeader, hence bit (pdu_off+6)*8. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 4)
        parse_spatem(frame, pdu_len, (pdu_off + 6) * 8, &r->spat);

    /* MAPEM (messageId 5), from the same entry point: the intersection's name, id, lanes
     * and altitude. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 5)
        parse_mapem(frame, pdu_len, (pdu_off + 6) * 8, &r->map, NULL,
                    &r->map_road_segments, &r->map_has_alt, &r->map_alt_cm);

    /* DENM (messageId 1): what the warning is about and how long it holds. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 1)
        parse_denm(frame, pdu_len, (pdu_off + 6) * 8, frame[pdu_off], r);

    /* RTCMEM (messageId 13): how many GNSS corrections it carries, and for where. Its body
     * starts behind the six-byte header, like the other bodies. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 13)
        parse_rtcmem(frame, pdu_len, (pdu_off + 6) * 8, r);

    /* EVCSN (messageId 11 at any version, or 3 at version 0): charging stations. Its header is
     * the old ItsPduHeader, still six bytes: protocolVersion, messageID and stationID. POIM
     * (3 at version 1) is read by its_poim.c from msg_extra.c. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        msg_kind(frame[pdu_off], frame[pdu_off + 1]) == 11)
        parse_evcsn(frame, pdu_len, (pdu_off + 6) * 8, r);

    /* CPM (messageId 14), protocolVersion 2 only: what the sensors of a station see. Six-byte
     * header as well. Version 1 is TR 103 562 and has another body, so it is only named.
     * It gets the exact end of the message: an unsigned frame still carries what the radio
     * appends, and the choice between the two readings of the container list hangs on
     * whether the walk ends exactly there. PL counts from behind the GN extended header,
     * so it covers the four BTP bytes in front of pdu_off. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 14 && frame[pdu_off] != 2)
    {
        /* A flag of its own: version 0 would be indistinguishable from "no CPM" otherwise. */
        r->cpm_wrong_version = true;
        r->cpm_other_version = frame[pdu_off];   /* version 1 is TR 103 562, another shape */
    }
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 14 && frame[pdu_off] == 2)
    {
        size_t cpm_end = pdu_len;
        if (common_off != SIZE_MAX && common_off + 6 <= pdu_len && pdu_off >= 4)
        {
            size_t pl = ((size_t)frame[common_off + 4] << 8) | frame[common_off + 5];
            if (pdu_off - 4 + pl < cpm_end)
                cpm_end = pdu_off - 4 + pl;
        }
        parse_cpm(frame, cpm_end, (pdu_off + 6) * 8, r);
    }

    /* SAEM (messageId 12): EN 302 890-1 sets protocolVersion 1, and its body is not decoded.
     * Another version is only named, like a CPM that is not version 2. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6 &&
        frame[pdu_off + 1] == 12 && frame[pdu_off] != 1)
    {
        r->saem_wrong_version = true;             /* version 0 would read as "no SAEM" otherwise */
        r->saem_other_version = frame[pdu_off];
    }

    /* CAM (messageId 2) from a bus/tram may carry its line number. */
    if (pdu_off != SIZE_MAX && pdu_len >= pdu_off + 2 &&
        frame[pdu_off + 1] == 2)
        r->pt_container = parse_cam_detail(frame, pdu_len, (pdu_off + 9) * 8 + 4, r);

    /* GN Source Position Vector: every message has a position here, which puts RSUs
     * on the map. The ints are plain big-endian. A CAM's own position overrides it. */
    if (have_sid && pv_off != SIZE_MAX && pdu_len >= pv_off + 20)
    {
        /* Plain two's complement here, not UPER-biased, but the same range as in the CDD.
         * 0,0 is what a station without a fix sends. */
        int32_t gn_lat = (int32_t)rd_u32be(frame + pv_off + 12);
        int32_t gn_lon = (int32_t)rd_u32be(frame + pv_off + 16);
        if ((gn_lat != 0 || gn_lon != 0) &&
            gn_lat >= -900000000 && gn_lat <= 900000000 &&
            gn_lon > -1800000000 && gn_lon <= 1800000000)
        {
            r->station_id = sid;
            r->lat_e7 = gn_lat;
            r->lon_e7 = gn_lon;
            r->has_position = true;
        }

        /* PAI(1)+Speed(15) right after the position, cm/s in TWO'S COMPLEMENT, so
         * a reversing vehicle reads negative. The speed is not decoded for RSUs. */
        if (pdu_len >= pv_off + 22 && !(station && strcmp(station, "RSU") == 0))
        {
            uint16_t raw = rd_u16be(frame + pv_off + 20) & 0x7FFF;
            r->speed_cmps = (raw & 0x4000) ? (int32_t)raw - 0x8000 : (int32_t)raw;
            r->has_speed = true;
        }
    }

    /* CAM position overrides the GN-layer fallback above when available.
     * See its_decode.h for the field semantics. */
    if (!have_sid)
        return;
    if (frame[pdu_off + 1] != 2 /* CAM */)
        return;

    /* referencePosition = byte pdu_off+8 PLUS 12 bits (ext + 2 option bits +
     * basicContainer ext + stationType 8). Re-validate against tshark before touching. */
    size_t bitoff = (pdu_off + 9) * 8 + 4;
    uint32_t raw_lat, raw_lon;
    if (!read_bits_msb(frame, pdu_len, bitoff, 31, &raw_lat))
        return;
    if (!read_bits_msb(frame, pdu_len, bitoff + 31, 32, &raw_lon))
        return;

    /* Vehicle dimensions at fixed bit offsets from the validated anchor (174 bits
     * to driveDirection, then length 10 + conf 3 + width 6); sizes are lower-bound-1 encoded. */
    {
        /* Only valid for basicVehicleContainerHighFrequency, so check the CHOICE
         * at +123 first. RSU CAMs have unrelated bits at +174. */
        uint32_t hf_ext, hf_alt;
        if (!read_bits_msb(frame, pdu_len, bitoff + 123, 1, &hf_ext) || hf_ext)
            goto skip_dimensions;
        if (!read_bits_msb(frame, pdu_len, bitoff + 124, 1, &hf_alt) || hf_alt)
            goto skip_dimensions;

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
skip_dimensions:
    ;   /* a label needs a statement, and a declaration is only one from C23 on */

    /* Checked in the ENCODED domain, where the raw values are still UPER-biased. */
    int32_t lat, lon;
    if (!pos_from_raw(raw_lat, raw_lon, &lat, &lon))
        return;

    r->station_id = sid;
    r->lat_e7 = lat;
    r->lon_e7 = lon;
    r->has_position = true;
}
