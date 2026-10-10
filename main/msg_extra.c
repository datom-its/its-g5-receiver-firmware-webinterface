#include "msg_extra.h"

#include <string.h>

/* Only the receive path writes these, so a reader can see one counter a step ahead of another.
 * Every single value stays whole, because an aligned word is read and written in one go. */
static msg_perm_stats_t s_perm;

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

/* Offset of the GeoNetworking Basic Header in the frame shapes its_decode_frame accepts:
 * an OCB data frame without ToDS, FromDS or HT Control, then LLC/SNAP. 0 means none. */
static size_t basic_header_off(const uint8_t *f, size_t len)
{
    if (len < 24 || ((f[0] >> 2) & 0x3) != 2 || (f[1] & 0x83))
        return 0;
    size_t off = (f[0] & 0x80) ? 26 : 24;
    if (len < off + 8 + 4)
        return 0;
    const uint8_t *llc = f + off;
    if (llc[0] != 0xAA || llc[1] != 0xAA || llc[2] != 0x03 || llc[3] || llc[4] || llc[5] ||
        rd16(llc + 6) != 0x8947)
        return 0;
    return off + 8;
}

/* Extended header length behind the 8-byte Common Header (EN 302 636-4-1), or -1 for the
 * header types without a facility message, such as Beacon and Location Service. */
static int ext_header_len(uint8_t header_type)
{
    switch (header_type)
    {
    case 2:
        return 48;
    case 3:
    case 4:
        return 44;
    case 5:
        return 28;
    default:
        return -1;
    }
}

/* Find the ITS PDU behind a Common Header at `common`. `avail` bytes belong to the packet,
 * and the PDU length comes from the header's payload length field, not from the frame. */
static bool find_pdu(const uint8_t *f, size_t common, size_t avail, const uint8_t **pdu,
                     size_t *pdu_len)
{
    if (avail < 8)
        return false;
    const uint8_t *c = f + common;
    int ext = ext_header_len(c[1] >> 4);
    if ((c[0] >> 4) != 2 || ext < 0)          /* Facility messages ride on BTP-B. */
        return false;
    size_t start = 8 + (size_t)ext;
    size_t pl = rd16(c + 4);
    /* The payload holds the 4-byte BTP-B header and at least the 6-byte ItsPduHeader. */
    if (pl < 4 + 6 || start + pl > avail)
        return false;
    *pdu = c + start + 4;
    *pdu_len = pl - 4;
    return true;
}

/* The list comes from the frame or from the cache, and both hold ITS_SEC_MAX_PSIDS entries. */
static bool psid_listed(const uint32_t *list, uint8_t n, uint32_t psid)
{
    if (n > ITS_SEC_MAX_PSIDS)
        n = ITS_SEC_MAX_PSIDS;
    for (uint8_t i = 0; i < n; i++)
        if (list[i] == psid)
            return true;
    return false;
}

/* content_check answers in the values of its_perm_cont_t: the three it shares with its_perm_t,
 * and this one for a message that carries nothing any bit of this service governs. A plain
 * number, so its answers stay of one type beside the its_perm_t ones. */
#define PERM_CONTENT_NOTHING 3
#define PERM_CONTENT_SKIPPED 0xFF   /* The PSID answer ended the check before the bits. */
_Static_assert((int)ITS_PERM_CONT_UNKNOWN == (int)ITS_PERM_UNKNOWN &&
               (int)ITS_PERM_CONT_OK == (int)ITS_PERM_OK &&
               (int)ITS_PERM_CONT_BAD == (int)ITS_PERM_BAD &&
               (int)ITS_PERM_CONT_FREE == PERM_CONTENT_NOTHING,
               "perm_cont takes the answers of the bits as they are");

/* Read permission bit `bit` of a bitmap SSP. Byte 0 is the version, and from byte 1 on bit 0
 * is the most significant bit of a byte. Returns 1 for set, 0 for clear, and -1 when the SSP
 * is too short to hold that bit. An SSP may be cut behind its last set bit, and it may also
 * be missing entirely, so a bit nobody wrote down stays unknown instead of becoming a no. */
static int ssp_bit(const uint8_t *ssp, size_t n, unsigned bit)
{
    size_t byte = 1u + bit / 8u;
    if (byte >= n)
        return -1;
    return (ssp[byte] >> (7u - bit % 8u)) & 1;
}

static uint8_t perm_from_bit(int bit)
{
    return bit < 0 ? ITS_PERM_UNKNOWN : bit ? ITS_PERM_OK : ITS_PERM_BAD;
}

/* Byte 0 of an SSP names the version of the service's bit layout. Version 0 is the one-byte
 * test form with no bits, and a version we do not know must not be read as bits either.
 * With no bytes at hand the version is not what blocks the answer. */
static bool ssp_version_is(const uint8_t *ssp, size_t n, uint8_t want)
{
    return n == 0 || ssp[0] == want;
}

/* The causeCode each DENM permission bit stands for, bit 0 first (EN 302 637-3). A cause that
 * is not in this list has no bit of its own, so the SSP says nothing about it. */
#define DENM_CAUSE_BITS 24
static const uint8_t k_denm_cause[DENM_CAUSE_BITS] = {
      1,  2,  3,  6,  9, 10, 11, 12,
     14, 15, 17, 18, 19, 26, 27, 91,
     92, 93, 94, 95, 96, 97, 98, 99,
};

/* The permission bit of each BasicVehicleRole, role number first, 0xFF where the standard
 * gives a role no bit of its own (basicVehicle, none-unknown, roadSideSource, stopNgo,
 * nonMotorized). Only roles 1 to 7 use the bit of their own number. From truck on the two
 * lists differ, so the table is written out instead of calculated (TS 103 301 table 21). */
#define SREM_ROLE_BITS 24
static const uint8_t k_srem_role_bit[SREM_ROLE_BITS] = {
    0xFF,    1,    2,    3,    4,    5,    6,    7,  /*  0 basicVehicle .. 7 safetyCar */
    0xFF,    8,    9, 0xFF,   10,   11,   12,   13,  /*  8 none-unknown .. 15 dot */
      14,   15, 0xFF,   16,   17, 0xFF,   18,   19,  /* 16 transit .. 23 tram */
};

/* SPATEM bit 1 answers priority requests (activePrioritizations), bit 2 gives manoeuvre hints
 * (a maneuverAssistList), TS 103 301 table 7. A message not read to its end may hold either
 * item unseen, so for such a message only a set bit allows. A no wins over an open answer. */
static uint8_t spat_items_check(const its_spat_t *s, const uint8_t *ssp, size_t n,
                                uint8_t *detail)
{
    uint8_t ans = ITS_PERM_OK;
    for (unsigned bit = 1; bit <= 2; bit++)
    {
        uint8_t item = bit == 1 ? ITS_SPAT_PRIO : ITS_SPAT_ASSIST, a;
        if (s->items & item)
            a = perm_from_bit(ssp_bit(ssp, n, bit));
        else if ((s->items & ITS_SPAT_WHOLE) || ssp_bit(ssp, n, bit) == 1)
            a = ITS_PERM_OK;
        else
            a = ITS_PERM_UNKNOWN;
        if (a == ITS_PERM_BAD)
            return a;
        if (a == ITS_PERM_UNKNOWN)
            ans = a;
    }
    /* Bit 0 was read, so the bits were at hand: an open answer comes from the unread rest. */
    *detail = (uint8_t)(ans == ITS_PERM_UNKNOWN);
    return ans;
}

/* Hold what the message carries against the SSP bits of the certificate. `n` is 0 when no SSP
 * bytes are at hand, which makes every bit unknown while a message that needs no bit at all
 * still comes out as PERM_CONTENT_NOTHING. `by` and `detail` name the rule that decided. */
static uint8_t content_check(const its_decoded_t *d, const msg_prio_t *prio, uint32_t psid,
                             const uint8_t *ssp, size_t n, uint8_t *by, uint8_t *detail)
{
    if (psid == 37)                     /* DENM: one bit per causeCode, four bytes */
    {
        if (!ssp_version_is(ssp, n, 1))
        {
            *by = ITS_PERM_BY_SSP_VER;
            return ITS_PERM_UNKNOWN;
        }
        *by = ITS_PERM_BY_DENM_CAUSE;
        *detail = d->denm_cause;
        if (!d->denm_cause)
            return ITS_PERM_UNKNOWN;    /* no cause read, so no bit can be held against it */
        for (unsigned i = 0; i < DENM_CAUSE_BITS; i++)
            if (k_denm_cause[i] == d->denm_cause)
                return perm_from_bit(ssp_bit(ssp, n, i));
        return ITS_PERM_UNKNOWN;
    }

    if (psid == 36)                     /* CAM: bit 0 a zone, bits 1..7 the special containers */
    {
        if (!ssp_version_is(ssp, n, 1))
        {
            *by = ITS_PERM_BY_SSP_VER;
            return ITS_PERM_UNKNOWN;
        }
        if (d->cam_zone)
        {
            uint8_t a = perm_from_bit(ssp_bit(ssp, n, 0));
            *by = ITS_PERM_BY_CAM_ZONE;
            if (a != ITS_PERM_OK)
                return a;
        }
        if (d->cam_special != ITS_CAM_SVC_NONE)
        {
            *by = ITS_PERM_BY_CAM_CONT;
            *detail = d->cam_special;
            /* The walk never reached the choice, the container is an extension alternative,
             * or the value stands for no container at all. No bit covers any of those, so
             * the answer stays open instead of reading a bit of the next byte. */
            if (d->cam_special < ITS_CAM_SVC_PT || d->cam_special > ITS_CAM_SVC_SAFETYCAR)
                return ITS_PERM_UNKNOWN;
            /* The seven containers sit in bits 1 to 7 in their CHOICE order, so the bit of
             * a container is its ITS_CAM_SVC_* value minus one. */
            return perm_from_bit(ssp_bit(ssp, n, d->cam_special - 1u));
        }
        if (d->cam_zone)
            return ITS_PERM_OK;         /* bit 0 said yes, and nothing else needed a bit */
        /* No zone and no special container: no bit of this service governs this CAM, so the
         * version byte is all that was held against it. Leaving the PSID rule standing here
         * would claim the bits were never looked at. */
        *by = ITS_PERM_BY_SERVICE;
        return PERM_CONTENT_NOTHING;
    }

    if (psid == 140)                    /* SREM: bit 0 the request, bits 1..19 the role */
    {
        if (!ssp_version_is(ssp, n, 3))
        {
            *by = ITS_PERM_BY_SSP_VER;
            return ITS_PERM_UNKNOWN;
        }
        *by = ITS_PERM_BY_CONTENT;
        if (prio->message_id != 9)
            return ITS_PERM_UNKNOWN;    /* PSID 140 without a readable SREM behind it */
        if (prio->n_items)
        {
            uint8_t a = perm_from_bit(ssp_bit(ssp, n, 0));
            if (a != ITS_PERM_OK)
                return a;
        }
        if (!prio->has_role)
            return prio->n_items ? ITS_PERM_OK : ITS_PERM_UNKNOWN;
        *by = ITS_PERM_BY_SREM_ROLE;
        *detail = prio->role;
        if (prio->role >= SREM_ROLE_BITS || k_srem_role_bit[prio->role] == 0xFF)
            return ITS_PERM_UNKNOWN;   /* a role the standard gives no bit of its own */
        return perm_from_bit(ssp_bit(ssp, n, k_srem_role_bit[prio->role]));
    }

    if (psid == 137 || psid == 138)     /* SPATEM phases and more, MAPEM geometry lists */
    {
        if (!ssp_version_is(ssp, n, 1))
        {
            *by = ITS_PERM_BY_SSP_VER;
            return ITS_PERM_UNKNOWN;
        }
        *by = ITS_PERM_BY_CONTENT;
        bool bit0 = psid == 137 ? d->spat.valid : d->map.valid;
        /* MAPEM only: bit 1 is the road segment list, which a MapData may carry beside the
         * intersections of bit 0 or instead of them. Each list is held against its own bit,
         * and the first no ends the check. */
        bool bit1 = psid == 138 && d->map_road_segments;
        if (!bit0 && !bit1)
            return ITS_PERM_UNKNOWN;    /* nothing read that a bit could be held against */
        if (bit0)
        {
            uint8_t a = perm_from_bit(ssp_bit(ssp, n, 0));
            if (a != ITS_PERM_OK)
                return a;
        }
        if (psid == 137)                /* SPATEM: bit 1 and bit 2 as well */
            return spat_items_check(&d->spat, ssp, n, detail);
        return bit1 ? perm_from_bit(ssp_bit(ssp, n, 1)) : (uint8_t)ITS_PERM_OK;
    }

    if (psid == 637)                    /* SSEM (TLC Status, TS 102 965 Annex A); 141 is GN-MGMT */
    {
        *by = ITS_PERM_BY_SERVICE;
        /* Here the version is the whole rule, so without bytes there is nothing to confirm.
         * The services above differ, because there a missing bit answers "unknown" by itself. */
        if (!n)
            return ITS_PERM_UNKNOWN;
        return ssp_version_is(ssp, n, 1) ? PERM_CONTENT_NOTHING : ITS_PERM_UNKNOWN;
    }

    /* IVIM names its provider with a code from a list this build does not have,
     * and an unlisted PSID has no layout at all. Both stay open. */
    *by = ITS_PERM_BY_SERVICE;
    return ITS_PERM_UNKNOWN;
}

/* Hold the message against the permissions of the certificate that signed it: the PSID
 * against appPermissions, then the content against the bits of the matching SSP. A list too
 * long to keep, a missing PSID or a certificate never seen leaves the answer open. Returns the
 * service answer; `content` gets the content answer, PERM_CONTENT_SKIPPED when there is none. */
static uint8_t perm_check(const its_sec_info_t *sec, const its_sig_summary_t *sig,
                          const uint8_t *frame, size_t len, const its_decoded_t *d,
                          const msg_prio_t *prio, its_certcache_entry_t *tmp, msg_extra_t *x,
                          uint8_t *content)
{
    *content = PERM_CONTENT_SKIPPED;
    x->perm_psid = 0;
    x->perm_by = ITS_PERM_BY_NONE;
    x->perm_detail = 0;
    if (!sec->valid || sec->content != ITS_SEC_SIGNED ||
        !(sec->flags & ITS_SEC_HAVE_HEADER) || !sec->psid)
        return ITS_PERM_UNKNOWN;
    x->perm_psid = sec->psid;

    const uint32_t *list;
    uint8_t n;
    /* The SSP travels with the certificate only. An entry found for this PSID also answers
     * the PSID question by itself, even when the kept list was cut short. */
    bool entry_found = (sec->flags & ITS_SEC_SSP_ABSENT) || sec->ssp_form != ITS_SEC_SSP_NONE;
    const uint8_t *ssp = NULL;
    size_t ssp_len = 0;
    /* Whether the service is granted without content limits, and whether bytes exist that
     * cannot be read. Both can come from the frame or from the cache, so they are kept apart
     * from sec, whose SSP fields only ever describe the frame in hand. */
    bool ssp_open = false, ssp_unusable = false;
    if (sig->kind == ITS_SIG_CERT && sec->cert_count > 0)
    {
        if ((sec->flags & ITS_SEC_PSIDS_CUT) && !entry_found)
            return ITS_PERM_UNKNOWN;
        list = sec->app_psids;
        n = sec->n_psids;
        ssp_open = (sec->flags & ITS_SEC_SSP_ABSENT) != 0;
        if (sec->ssp_form == ITS_SEC_SSP_BITMAP && sec->ssp_len &&
            (size_t)sec->ssp_off + sec->ssp_len <= len)
        {
            ssp = frame + sec->ssp_off;
            ssp_len = sec->ssp_len;
        }
        else if (!ssp_open && sec->ssp_form != ITS_SEC_SSP_NONE)
        {
            ssp_unusable = true;
        }
    }
    /* A digest names a certificate the sender announced earlier, and the cache kept its
     * permissions along with it: the PSIDs, and the permission bytes of every service a
     * frame has shown so far. Without them every bit of such a message would stay open. */
    else if (sig->kind == ITS_SIG_DIGEST && sig->has_id && its_certcache_lookup(sig->id, tmp))
    {
        if (tmp->psids_cut)
            return ITS_PERM_UNKNOWN;
        list = tmp->app_psids;
        n = tmp->n_psids;
        entry_found = false;
        const uint8_t *kept = NULL;
        uint8_t kept_len = 0, kept_form = 0;
        if (its_certcache_ssp(tmp, sec->psid, &kept, &kept_len, &kept_form))
        {
            if (kept_form == ITS_CERTCACHE_SSP_OPEN)
                ssp_open = true;
            else if (kept_form == ITS_SEC_SSP_BITMAP && kept_len)
            {
                ssp = kept;
                ssp_len = kept_len;
            }
            else
            {
                ssp_unusable = true;
            }
        }
    }
    else
    {
        return ITS_PERM_UNKNOWN;
    }

    x->perm_by = ITS_PERM_BY_PSID;
    if (!entry_found && !psid_listed(list, n, sec->psid))
        return ITS_PERM_BAD;

    uint8_t by = ITS_PERM_BY_PSID, detail = 0, ans;
    if (ssp_open)
    {
        /* No SSP beside that PSID: the service is granted and its contents are not
         * restricted, which is what IEEE 1609.2 and the ETSI service profiles say. */
        by = ITS_PERM_BY_SSP_NONE;
        ans = PERM_CONTENT_NOTHING;
    }
    else if (ssp_unusable)
    {
        /* The entry carries an SSP whose bytes are not at hand: no bitmap, empty, longer
         * than ssp_len holds, or outside the frame. Not even the version byte can be read,
         * so nothing about this service is settled. That includes the services whose whole
         * rule is the version. */
        by = ITS_PERM_BY_SSP_FORM;
        ans = ITS_PERM_UNKNOWN;
    }
    else
    {
        ans = content_check(d, prio, sec->psid, ssp, ssp_len, &by, &detail);
    }
    x->perm_by = by;
    x->perm_detail = detail;
    *content = ans;
    return ITS_PERM_OK;
}

static void prio_from_srem(msg_prio_t *p, const its_srem_t *s)
{
    p->message_id = 9;
    p->has_role = s->has_type;
    p->role = s->role;
    p->requestor_kind = s->requestor_kind;
    p->requestor_id = s->requestor_id;
    memcpy(p->name, s->name, sizeof p->name);
    memcpy(p->route, s->route_name, sizeof p->route);
    p->name[sizeof p->name - 1] = '\0';
    p->route[sizeof p->route - 1] = '\0';
    uint8_t n = s->n_requests < MSG_PRIO_ITEMS ? s->n_requests : MSG_PRIO_ITEMS;
    for (uint8_t i = 0; i < n; i++)
    {
        const its_srem_request_t *q = &s->req[i];
        msg_prio_item_t *it = &p->item[i];
        it->has_region = q->has_region;
        it->region = q->region;
        it->id = q->id;
        it->request_id = q->request_id;
        it->code = q->request_type;
        it->in = q->inbound;
        it->out = q->outbound;
    }
    p->n_items = n;
    p->more = s->truncated || s->n_requests > n;
}

static void prio_from_ssem(msg_prio_t *p, const its_ssem_t *s)
{
    p->message_id = 10;
    size_t base = 0;
    uint8_t n = 0;
    for (uint8_t st = 0; st < s->n_status && st < ITS_SSEM_MAX_STATUS; st++)
    {
        const its_ssem_status_t *ss = &s->status[st];
        for (uint8_t j = 0; j < ss->n_packages; j++)
        {
            size_t k = base + j;
            if (k >= s->n_packages || k >= ITS_SSEM_MAX_PKG)
                break;
            if (n == MSG_PRIO_ITEMS)
            {
                p->more = true;
                break;
            }
            const its_ssem_package_t *pk = &s->pkg[k];
            msg_prio_item_t *it = &p->item[n++];
            it->has_region = ss->has_region;
            it->region = ss->region;
            it->id = ss->id;
            it->requester_kind = pk->requester_kind;
            it->requester_id = pk->requester_id;
            it->request_id = pk->request_id;
            it->code = pk->status;
            it->in = pk->inbound;
            it->out = pk->outbound;
        }
        base += ss->n_packages;
    }
    p->n_items = n;
    p->more = p->more || s->truncated;
}

void msg_extra_from_frame(msg_extra_t *x, const uint8_t *frame, size_t len,
                          const its_decoded_t *d, bool note_cache, uint32_t now_sec,
                          msg_extra_scratch_t *xs)
{
    memset(x, 0, sizeof *x);
    /* Before the early returns below, so an earlier frame's station never stays. */
    xs->pdu_station = 0;
    x->message_id = d->message_id;
    /* Before the returns below, so a frame they skip still shows how it travelled. */
    its_gn_fill(&x->gn, frame, len, d);
    if (note_cache) its_gn_track(&x->gn, now_sec);
    if (d->has_dcc && (d->dcc_cbr_r0_hop || d->dcc_cbr_r1_hop || d->dcc_tx_power_dbm))
    {
        x->has_dcc = true;
        x->dcc_cbr_r0 = d->dcc_cbr_r0_hop;
        x->dcc_cbr_r1 = d->dcc_cbr_r1_hop;
        x->dcc_tx_power_dbm = d->dcc_tx_power_dbm;
    }
    if (d->message_id == 1)
    {
        x->denm_termination = d->denm_termination;
        x->denm_validity_s = d->denm_validity_s;
        x->denm_validity_sent = d->denm_validity_sent;
        x->denm_aware_dist = d->denm_aware_dist;
        x->denm_traffic_dir = d->denm_traffic_dir;
        x->denm_road_type = d->denm_road_type;
        x->denm_station_type = d->denm_station_type;
        x->denm_quality = d->denm_info_quality;
        x->denm_n_traces = d->denm_n_traces;
        x->denm_path_len = d->denm_path_len;
        x->denm_n_hist = d->denm_n_hist;
        x->denm_has_alt = d->denm_has_alt;
        x->denm_alt_cm = d->denm_alt_cm;
        x->denm_has_speed = d->denm_has_speed;
        x->denm_speed_cms = d->denm_speed_cms;
        x->denm_has_heading = d->denm_has_heading;
        x->denm_heading_ddeg = d->denm_heading_ddeg;
        x->denm_tx_interval_ms = d->denm_tx_interval_ms;
    }
    else
    {
        /* Not a DENM: the memset left these at 0, which would read as "lessThan50m". */
        x->denm_aware_dist = ITS_DENM_DIST_NONE;
        x->denm_traffic_dir = ITS_DENM_DIR_NONE;
        x->denm_road_type = ITS_DENM_ROAD_NONE;
        x->denm_station_type = ITS_DENM_STATION_NONE;
        x->denm_quality = ITS_DENM_QUALITY_NONE;
    }
    if (d->message_id == 5)
    {
        x->map_has_alt = d->map_has_alt;
        x->map_alt_cm = d->map_alt_cm;
    }
    if (d->message_id == 13)
    {
        x->rtcm_msg_cnt = d->rtcm_msg_cnt;
        x->rtcm_rev = d->rtcm_rev;
        x->rtcm_n_msgs = d->rtcm_n_msgs;
        x->rtcm_bytes = d->rtcm_bytes;
        x->rtcm_has_minute = d->rtcm_has_minute;
        x->rtcm_minute = d->rtcm_minute;
        x->rtcm_has_anchor = d->rtcm_has_anchor;
        x->rtcm_lat_e7 = d->rtcm_lat_e7;
        x->rtcm_lon_e7 = d->rtcm_lon_e7;
        x->rtcm_has_elev = d->rtcm_has_elev;
        x->rtcm_elev_dm = d->rtcm_elev_dm;
        x->rtcm_has_status = d->rtcm_has_status;
        x->rtcm_status = d->rtcm_status;
    }
    if (d->message_id == 14)
    {
        x->cpm_wrong_version = d->cpm_wrong_version;  /* also without a reading */
        x->cpm_other_version = d->cpm_other_version;
    }
    if (d->message_id == 12)
    {
        x->saem_wrong_version = d->saem_wrong_version;
        x->saem_other_version = d->saem_other_version;
    }
    if (d->message_id == 14 && d->cpm_read)
    {
        x->cpm_read = true;
        x->cpm_n_containers = d->cpm_n_containers;
        x->cpm_containers = d->cpm_containers;
        x->cpm_cont_bad = d->cpm_cont_bad;
        x->cpm_n_objects = d->cpm_n_objects;
        x->cpm_n_objects_here = d->cpm_n_objects_here;
        x->cpm_n_sensors = d->cpm_n_sensors;
        x->cpm_n_regions = d->cpm_n_regions;
        x->cpm_seg_this = d->cpm_seg_this;
        x->cpm_seg_total = d->cpm_seg_total;
        x->cpm_has_heading = d->cpm_has_heading;
        x->cpm_heading_ddeg = d->cpm_heading_ddeg;
        x->cpm_list_form = d->cpm_list_form;
    }
    /* Before the security path, whose early returns would skip it, and for every frame, so
     * cpm_all_n never holds the objects of an earlier CPM. A missing frame counts as 0 bytes. */
    (void)its_cpm_decode(frame, frame ? len : 0, d, &x->cpm, xs->cpm_all, ITS_CPM_ALL_MAX,
                         &xs->cpm_all_n);
    /* evcsn_read, not messageId 11: an EVCSN also comes as 3 at protocolVersion 0. */
    if (d->evcsn_read)
    {
        x->evcsn_read = true;
        x->evcsn_relay = d->evcsn_relay;
        x->evcsn_has_pos = d->evcsn_has_pos;
        x->evcsn_n_spots = d->evcsn_n_spots;
        x->evcsn_n_total = d->evcsn_n_total;
        x->evcsn_n_stations = d->evcsn_n_stations;
        x->evcsn_modes = d->evcsn_modes;
        x->evcsn_st_id = d->evcsn_st_id;
        x->evcsn_lat_e7 = d->evcsn_lat_e7;
        x->evcsn_lon_e7 = d->evcsn_lon_e7;
        memcpy(x->evcsn_access, d->evcsn_access, sizeof x->evcsn_access);
        memcpy(x->evcsn_hours, d->evcsn_hours, sizeof x->evcsn_hours);
        memcpy(x->evcsn_price, d->evcsn_price, sizeof x->evcsn_price);
    }
    x->area_shape = d->gn_area_shape;
    x->area_a_m = d->gn_area_a_m;
    x->area_b_m = d->gn_area_b_m;
    x->area_angle_deg = d->gn_area_angle_deg;

    size_t bh = frame ? basic_header_off(frame, len) : 0;
    if (!bh)
        return;
    uint8_t nh = frame[bh] & 0x0F;
    size_t common = 0, avail = 0;
    if (nh == 1)
    {
        x->sig.kind = ITS_SIG_UNSIGNED;
        common = bh + 4;
        avail = len - common;
    }
    else if (nh == 2)
    {
        its_decode_security(frame, len, bh + 4, &xs->sec);
        /* Before the payload test, so a header whose content came as a hash is judged too. */
        its_sechdr_fill(&x->sechdr, &xs->sec, d);
        if (xs->sec.valid && xs->sec.content == ITS_SEC_SIGNED &&
            (xs->sec.flags & ITS_SEC_HAVE_PAYLOAD))
        {
            common = xs->sec.payload_off;
            avail = xs->sec.payload_len;
        }
    }
    else
    {
        return;
    }

    const uint8_t *pdu = NULL;
    size_t pdu_len = 0;
    bool have_pdu = common && find_pdu(frame, common, avail, &pdu, &pdu_len);
    uint32_t station = have_pdu ? rd32(pdu + 2) : d->station_id;
    xs->pdu_station = have_pdu ? rd32(pdu + 2) : 0;

    if (nh == 2)
    {
        if (note_cache)
            /* The frame length is known here, so the cache can bound every read itself
             * instead of trusting what its_security promised about the offsets. */
            its_certcache_note_len(frame, len, &xs->sec, station, now_sec, &x->sig);
        else
            its_sig_summarize_len(frame, len, &xs->sec, &x->sig);
    }

    /* The SREM summary has to be there before the permission check: the SSP of PSID 140
     * grants a role, and the role is in the message body, not in the envelope. */
    if (have_pdu && pdu[1] == 9 && its_decode_srem(pdu, pdu_len, &xs->srem))
        prio_from_srem(&x->prio, &xs->srem);
    else if (have_pdu && pdu[1] == 10 && its_decode_ssem(pdu, pdu_len, &xs->ssem))
        prio_from_ssem(&x->prio, &xs->ssem);
    /* POIM gets the exact PDU length from find_pdu. It checks the version itself and also
     * fills x->poim for a version it does not read, so the page can name that version. */
    if (have_pdu && pdu[1] == 3)
        (void)its_decode_poim(pdu, pdu_len, &x->poim);

    if (nh == 2)
    {
        uint8_t content;
        x->perm_svc = perm_check(&xs->sec, &x->sig, frame, len, d, &x->prio, &xs->cert, x,
                                 &content);
        /* Two answers, never one: the content answer only exists after a yes for the service. */
        x->perm_cont = content == PERM_CONTENT_SKIPPED ? (uint8_t)ITS_PERM_CONT_UNKNOWN : content;
        if (note_cache)
        {
            /* One service answer per envelope; the content counters split its yes further. */
            if (content == PERM_CONTENT_SKIPPED)
            {
                if (x->perm_svc == ITS_PERM_BAD)
                    s_perm.bad++;
                else
                    s_perm.unknown++;
            }
            else
            {
                s_perm.ok++;
                if (content == ITS_PERM_CONT_OK)
                    s_perm.content_ok++;
                else if (content == ITS_PERM_CONT_BAD)
                    s_perm.content_bad++;
                else if (content == ITS_PERM_CONT_UNKNOWN)
                    s_perm.content_unknown++;
                else
                    s_perm.content_none++;
            }
        }
    }
}

/* The same DENM fields as the frame copy above. Termination, validity and the area have
 * their own cells on /traffic, so they are not copied. */
void msg_extra_from_event(msg_extra_t *x, const event_rec_t *e)
{
    memset(x, 0, sizeof *x);
    x->message_id = 1;
    const event_denm_t *d = &e->denm;
    x->denm_aware_dist = d->aware_dist;
    x->denm_traffic_dir = d->traffic_dir;
    x->denm_road_type = d->road_type;
    x->denm_station_type = d->origin_type;
    x->denm_quality = d->info_quality;
    x->denm_n_traces = d->n_traces;
    x->denm_path_len = d->path_len;
    x->denm_n_hist = d->n_hist;
    x->denm_has_alt = d->alt_cm != EVENT_ALT_NONE;
    x->denm_alt_cm = d->alt_cm;
    x->denm_has_speed = d->speed_cms != EVENT_SPEED_NONE;
    x->denm_speed_cms = d->speed_cms;
    x->denm_has_heading = d->heading_ddeg != EVENT_HEADING_NONE;
    x->denm_heading_ddeg = d->heading_ddeg;
    x->denm_tx_interval_ms = d->tx_interval_ms;
}

void msg_extra_perm_stats(msg_perm_stats_t *out)
{
    *out = s_perm;
}
