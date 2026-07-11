#include "its_decode.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

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

void its_decode_frame(const uint8_t *frame, size_t len, char *out, size_t out_size,
                      bool *has_position, int32_t *lat_e7, int32_t *lon_e7,
                      uint32_t *station_id, bool *has_speed, int32_t *speed_cmps)
{
    *has_position = false;
    *has_speed = false;

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

    if (station) snprintf(out, out_size, "%s %s", station, label);
    else         snprintf(out, out_size, "%s", label);

    /* ItsPduHeader.stationId is present for every facility message (not just
     * CAM), right after protocolVersion+messageId -- read it once here so
     * both the GN-layer position fallback below and the CAM-specific
     * position further down can use it as the map marker's tracking key. */
    bool have_sid = pdu_off != SIZE_MAX && pdu_len >= pdu_off + 6;
    uint32_t sid = have_sid ? rd_u32be(frame + pdu_off + 2) : 0;

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
            *station_id = sid;
            *lat_e7 = gn_lat;
            *lon_e7 = gn_lon;
            *has_position = true;
        }

        /* Speed sits right after the position: PAI(1 bit)+Speed(15 bits),
         * 0.01 m/s units (raw value is already cm/s). Skipped for RSUs
         * (stationary -- a speed reading there is meaningless). */
        if (pdu_len >= pv_off + 22 && !(station && strcmp(station, "RSU") == 0))
        {
            *speed_cmps = rd_u16be(frame + pv_off + 20) & 0x7FFF;
            *has_speed = true;
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

    /* ETSI's dedicated "unavailable" sentinels for Latitude/Longitude. */
    if (raw_lat == 900000001u || raw_lon == 1800000001u)
        return;

    *station_id = sid;
    *lat_e7 = (int32_t)((int64_t)raw_lat - 900000000);
    *lon_e7 = (int32_t)((int64_t)raw_lon - 1800000000);
    *has_position = true;
}
