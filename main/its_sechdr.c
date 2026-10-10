#include "its_sechdr.h"

#include <string.h>

#include "events_log.h"

/* The rules come from TS 103 097 V2.2.1 (2026-03) clause 5.2, the profiles 7.1.1 (CAM) and
 * 7.1.2 (DENM) and Annex A, and from the types and comments of the IEEE 1609.2 ASN.1. */

#define KIND_DENM 1   /* CDD MessageId */
#define KIND_CAM  2
#define KIND_MAPEM 5

/* TS 102 965 V2.4.1 Annex A Table A.1. POIM has two services (1619, 1621) and EVCSN none, so
 * both stay 0 like the kinds without an entry. */
static const uint32_t ITS_AID[] = {
    [KIND_DENM] = 37,      /* DEN basic service */
    [KIND_CAM]  = 36,      /* CA basic service */
    [4]         = 137,     /* SPATEM: TLM service */
    [5]         = 138,     /* MAPEM: RLT service */
    [6]         = 139,     /* IVIM: IVI service */
    [9]         = 140,     /* SREM: TLC Request service */
    [10]        = 637,     /* SSEM: TLC Status service; 141 is GN-MGMT */
    [12]        = 540801,  /* SAEM: SA service */
    [13]        = 540802,  /* RTCMEM: GPC service */
    [14]        = 639,     /* CPM: CP service */
    [15]        = 640,     /* IMZM: IMZ basic service */
    [16]        = 638,     /* VAM: VRU Awareness basic service */
};

uint32_t its_sechdr_its_aid(uint8_t kind)
{
    return kind < sizeof ITS_AID / sizeof ITS_AID[0] ? ITS_AID[kind] : 0;
}

/* Time64 counts TAI microseconds since 2004 like TimestampIts counts milliseconds, so the leap
 * table of events_log.c applies. The guard keeps ms * 1000 + 999 inside 64 bits. */
static uint64_t to_unix_us(uint64_t t)
{
    uint64_t ms = events_its_to_unix_ms(t / 1000u);
    return ms > (UINT64_MAX - 999u) / 1000u ? UINT64_MAX : ms * 1000u + t % 1000u;
}

void its_sechdr_fill(its_sechdr_t *h, const its_sec_info_t *s, const its_decoded_t *d)
{
    memset(h, 0, sizeof *h);
    if (!s || !d || !s->valid || s->content != ITS_SEC_SIGNED ||
        !(s->flags & ITS_SEC_HAVE_HEADER))
        return;

    uint16_t hdr = s->header;
    bool have_signer = (s->flags & ITS_SEC_HAVE_SIGNER) != 0;
    bool by_cert = have_signer && s->signer == ITS_SEC_SIGNER_CERTIFICATE;
    h->read = true;
    h->hdr = hdr;
    h->hash_id = s->hash_id;
    h->xflags = s->xflags;
    h->contrib = s->contrib;
    h->n_inline = s->n_inline;
    h->pdu_type = s->pdu_type;
    h->sig_type = (s->flags & ITS_SEC_HAVE_SIGNATURE) ? s->sig_type : 0xFF;
    h->key_type = by_cert && s->cert_count > 0 ? s->key_type : 0xFF;
    h->cert_count = by_cert ? s->cert_count : 0;
    h->has_data = (s->flags & ITS_SEC_HAVE_PAYLOAD) != 0;

    if (hdr & ITS_SEC_HDR_GENERATION_TIME)
    {
        h->gen_us = to_unix_us(s->generation_time);
        h->has_gen = true;
    }
    if (hdr & ITS_SEC_HDR_EXPIRY_TIME)
    {
        h->exp_us = to_unix_us(s->expiry_time);
        h->has_exp = true;
    }

    uint16_t dev = 0;
    if (hdr & ITS_SEC_HDR_LOCATION)
    {
        int32_t lat = s->gen_lat;
        int32_t lon = s->gen_lon;
        h->lat_e7 = lat;
        h->lon_e7 = lon;
        h->elev = s->gen_elev;
        /* IEEE 1609.2 NinetyDegreeInt and OneEightyDegreeInt. Longitude starts at -1799999999,
         * not at the -1800000000 of the CDD. */
        if (lat < -900000000 || lat > 900000001 || lon < -1799999999 || lon > 1800000001)
        {
            h->loc = SEC_LOC_RANGE;
            dev |= SEC_DEV_RANGE;
        }
        else if (lat == 900000001 || lon == 1800000001)   /* the "unknown" of each type */
        {
            h->loc = SEC_LOC_UNKNOWN;
        }
        else if (d->has_position && lat == d->lat_e7 && lon == d->lon_e7)
        {
            h->loc = SEC_LOC_SAME;
        }
        else
        {
            h->loc = SEC_LOC_OTHER;
            if (d->has_position)
            {
                h->has_ref = true;
                h->ref_lat_e7 = d->lat_e7;
                h->ref_lon_e7 = d->lon_e7;
            }
        }
    }

    /* A type only for an ITS PDU (protocolVersion 1 to 3): any other BTP payload has a second
     * byte too. Every type a rule below names has a name, so the name needs no test. */
    uint8_t kind = d->message_id && d->pdu_version >= 1 && d->pdu_version <= 3
                 ? its_msg_kind(d->pdu_version, d->message_id) : 0;
    /* The body gives an ellipsoid height in cm too, so the page can set both side by side: the
     * CAM its reference position, the DENM its event position, the MAPEM its intersection. */
    if (kind == KIND_CAM && d->cam.has_alt)
    {
        h->msg_alt_cm = d->cam.alt_cm;
        h->has_msg_alt = true;
    }
    else if (kind == KIND_DENM && d->denm_has_alt)
    {
        h->msg_alt_cm = d->denm_alt_cm;
        h->has_msg_alt = true;
    }
    else if (kind == KIND_MAPEM && d->map_has_alt)
    {
        h->msg_alt_cm = d->map_alt_cm;
        h->has_msg_alt = true;
    }

    /* The profile follows the message. Only an envelope without data leaves the PSID to name
     * it. Data that is no known ITS PDU gets the rules of no message type. */
    bool by_psid = kind == 0 && !h->has_data;
    bool cam = kind == KIND_CAM || (by_psid && s->psid == ITS_AID[KIND_CAM]);
    bool denm = kind == KIND_DENM || (by_psid && s->psid == ITS_AID[KIND_DENM]);

    /* 5.2: p2pcdLearningRequest and missingCrlIdentifier "always absent" (Annex A ABSENT). */
    uint16_t forbid = hdr & (ITS_SEC_HDR_P2PCD_LEARNING | ITS_SEC_HDR_MISSING_CRL);
    /* Annex A: encryptionKey only as aes128Ccm, eciesNistP256 or eciesBrainpoolP256r1. */
    if (s->xflags & ITS_SEC_X_ENC_FORM)
        forbid |= ITS_SEC_HDR_ENCRYPTION_KEY;
    /* 5.2: in contributedExtensions only EtsiOriginatingHeaderInfoExtension, contributorId 2. */
    if (s->contrib & ITS_SEC_C_FOREIGN)
        forbid |= ITS_SEC_HDR_CONTRIBUTED_EXT;
    /* 5.2: the payload is "either" data or extDataHash, never both, and Annex A allows only
     * sha256HashedData for the latter. No profile names SignedDataPayload.omitted. */
    if ((s->xflags & ITS_SEC_X_HASH_NOT256) || ((s->xflags & ITS_SEC_X_EXT_HASH) && h->has_data))
        forbid |= SEC_FORBID_EXT_HASH;
    if (s->xflags & ITS_SEC_X_OMITTED)
        forbid |= SEC_FORBID_OMITTED;
    /* 7.1.1 and 7.1.2 last bullet: every header part the profile does not name "shall not be
     * used and be absent". A CAM may carry inlineP2pcdRequest and requestedCertificate. */
    if (cam)
        forbid |= hdr & (ITS_SEC_HDR_EXPIRY_TIME | ITS_SEC_HDR_LOCATION |
                         ITS_SEC_HDR_ENCRYPTION_KEY | ITS_SEC_HDR_PDU_FUNCTIONAL);
    if (denm)
        forbid |= hdr & (ITS_SEC_HDR_EXPIRY_TIME | ITS_SEC_HDR_ENCRYPTION_KEY |
                         ITS_SEC_HDR_INLINE_P2PCD | ITS_SEC_HDR_REQUESTED_CERT |
                         ITS_SEC_HDR_PDU_FUNCTIONAL);
    /* 7.1.1 and 7.1.2: EtsiTs103097Data-Signed "containing the CAM" or DENM, Annex A data
     * PRESENT. A hash alone does not contain the message. */
    if ((cam || denm) && (s->xflags & ITS_SEC_X_EXT_HASH) && !h->has_data)
        forbid |= SEC_FORBID_EXT_HASH;
    if (forbid)
        dev |= SEC_DEV_FORBID;

    /* 5.2: generationTime "always present" (Annex A PRESENT). */
    if (!(hdr & ITS_SEC_HDR_GENERATION_TIME))
        dev |= SEC_DEV_TIME;
    /* 7.1.2: generationLocation "shall be present". */
    if (denm && !(hdr & ITS_SEC_HDR_LOCATION))
        dev |= SEC_DEV_LOC;
    /* IEEE 1609.2 HeaderInfo: invalid if generationTime is not strictly earlier than expiryTime.
     * Compared raw, before the conversion can clamp either. */
    if ((hdr & ITS_SEC_HDR_GENERATION_TIME) && (hdr & ITS_SEC_HDR_EXPIRY_TIME) &&
        s->expiry_time <= s->generation_time)
        dev |= SEC_DEV_ORDER;
    /* Annex A: hashId sha256 (0) or sha384 (1). 5.2: an ECDSA signature, Annex A sm2Signature
     * ABSENT. */
    if (s->hash_id > 1)
        dev |= SEC_DEV_ALG;
    if (h->sig_type == ITS_SEC_SIG_SM2 || h->sig_type == ITS_SEC_SIG_OTHER)
        dev |= SEC_DEV_ALG;
    /* 5.2: signer digest or certificate, and "only one entry" (Annex A SIZE(1)). 7.1.2: a DENM
     * by certificate. The signer has one form, so at most one of the three is set. */
    if (have_signer && s->signer == ITS_SEC_SIGNER_DIGEST)
    {
        if (denm)
            dev |= SEC_DEV_DIGEST;
    }
    else if (have_signer && !by_cert)
    {
        dev |= SEC_DEV_SIGNER;
    }
    else if (by_cert && s->cert_count != 1)
    {
        dev |= SEC_DEV_CHAIN;
    }
    /* 5.2 and 7.1.1/7.1.2: psid is the ITS-AID of the contained message. */
    uint32_t want = its_sechdr_its_aid(kind);
    if (want && s->psid != want)
    {
        dev |= SEC_DEV_PSID;
        h->want_psid = want;
    }
    h->forbid = forbid;
    h->dev = dev;
}

void its_sechdr_note_rx(its_sechdr_t *h, uint32_t sec, uint32_t usec)
{
    if (!h || !h->read || sec < EVENTS_CLOCK_MIN || usec > 999999u)
        return;
    h->rx_us = sec * 1000000ull + usec;
    h->has_rx = true;
}

void its_sechdr_unit_fold(its_sechdr_unit_t *u, const its_sechdr_t *h)
{
    if (!u || !h || !h->read)
        return;
    if (h->sig_type != 0xFF)
    {
        u->sig_type = h->sig_type;
        u->has |= SEC_UNIT_SIG;
    }
    if (h->key_type != 0xFF)
    {
        u->key_type = h->key_type;
        u->has |= SEC_UNIT_KEY;
    }
    u->hash_id = h->hash_id;
    u->has |= SEC_UNIT_HASH;
    if (h->hdr & ITS_SEC_HDR_LOCATION)
    {
        u->elev = h->elev;
        u->has |= SEC_UNIT_ELEV;
    }
    if (h->dev)
    {
        if (u->dev_frames < UINT32_MAX)
            u->dev_frames++;
        u->dev_mask |= h->dev;
    }
}
