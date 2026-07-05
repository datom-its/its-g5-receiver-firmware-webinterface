#include "its_decode.h"

#include <stdbool.h>
#include <stdio.h>

#define ETHERTYPE_GEONET 0x8947u
#define ETHERTYPE_IPV6   0x86DDu
#define ETHERTYPE_WSMP   0x88DCu

static uint16_t rd_u16be(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

/* Length of the 802.11 MAC header for the common ITS-G5 case: a Data or QoS
 * Data frame sent outside the context of a BSS (OCB mode), i.e. ToDS=0,
 * FromDS=0, no HT Control field -- true for the ad-hoc broadcast frames CAM
 * and DENM are sent as. Returns 0 for anything else, so the caller bails out
 * rather than mis-parse (e.g. a 4-address WDS frame, which isn't used here). */
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

typedef struct { uint16_t port; const char *name; } btp_port_name_t;

/* Only the two message types we're fully confident about (ETSI TS 103 301
 * well-known BTP port numbers). Everything else is reported as
 * "GeoNet:<port>" -- see the header comment for why. */
static const btp_port_name_t KNOWN_BTP_PORTS[] = {
    { 2001, "CAM" },
    { 2002, "DENM" },
};

static const char *lookup_btp_name(uint16_t port)
{
    for (size_t i = 0; i < sizeof(KNOWN_BTP_PORTS) / sizeof(KNOWN_BTP_PORTS[0]); i++)
        if (KNOWN_BTP_PORTS[i].port == port)
            return KNOWN_BTP_PORTS[i].name;
    return NULL;
}

/* GeoNetworking Common Header "header type" field -> length of the following
 * extended header, per ETSI EN 302 636-4-1. Facility messages (CAM/DENM) are
 * always carried by TSB (single- or multi-hop broadcast, type 5) or
 * GeoBroadcast/-Anycast (types 3/4); Beacon (1) and Location Service (6)
 * frames don't carry a facility payload at all. GeoUnicast (2) isn't used by
 * broadcast facility messages but is included for completeness.
 * -1 means "not handled here" (variable-length / out of scope). */
static int gn_ext_header_len(uint8_t header_type)
{
    switch (header_type)
    {
    case 1: return 24;  /* Beacon: Source LongPV only, nothing follows */
    case 2: return 44;  /* GeoUnicast */
    case 3: return 40;  /* GeoAnycast */
    case 4: return 40;  /* GeoBroadcast */
    case 5: return 28;  /* TSB, single- or multi-hop */
    default: return -1; /* Location Service (6) and anything else */
    }
}

void its_decode_msg_type(const uint8_t *frame, size_t len, char *out, size_t out_size)
{
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

    if (basic_nh == 2)
    {
        /* ETSI TS 103 097 secured envelope: variable-length cert/signature,
         * not parsed here -- but distinguishing "signed" from "unparseable"
         * is itself useful, since most real road traffic is signed. */
        snprintf(out, out_size, "Signed");
        return;
    }
    if (basic_nh != 1) { snprintf(out, out_size, "?"); return; } /* not "Common Header follows" */

    /* Common Header (8 bytes): NextHeader(hi nibble) | Reserved(lo nibble),
     * HeaderType(hi nibble) | HeaderSubtype(lo nibble), ... */
    if (len < off + 8) { snprintf(out, out_size, "?"); return; }
    uint8_t common_nh   = (frame[off]     >> 4) & 0x0F;
    uint8_t header_type = (frame[off + 1] >> 4) & 0x0F;
    off += 8;

    if (header_type == 1) { snprintf(out, out_size, "GeoNet-Beacon"); return; }
    int ext_len = gn_ext_header_len(header_type);
    if (ext_len < 0) { snprintf(out, out_size, "GeoNet-LS"); return; }
    if (len < off + (size_t)ext_len) { snprintf(out, out_size, "?"); return; }
    off += (size_t)ext_len;

    if (common_nh == 2) /* BTP-B: destination port is the first 2 bytes */
    {
        if (len < off + 2) { snprintf(out, out_size, "GeoNet"); return; }
        uint16_t port = rd_u16be(frame + off);
        const char *name = lookup_btp_name(port);
        if (name) snprintf(out, out_size, "%s", name);
        else      snprintf(out, out_size, "GeoNet:%u", (unsigned)port);
    }
    else if (common_nh == 1) { snprintf(out, out_size, "BTP-A"); }
    else if (common_nh == 3) { snprintf(out, out_size, "IPv6-GN"); }
    else                     { snprintf(out, out_size, "GeoNet"); }
}
