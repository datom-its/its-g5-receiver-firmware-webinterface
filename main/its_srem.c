#include "its_srem.h"

#include <string.h>

#include "its_bits.h"

#define MSGID_SREM  9
#define MSGID_SSEM  10

/* These UPER field widths follow from the value range, fixed size or alphabet of each ASN.1 type. */
#define BITS_PROTOCOL_VERSION       8
#define BITS_MESSAGE_ID             8
#define BITS_STATION_ID             32
#define BITS_MINUTE_OF_YEAR         20
#define BITS_DSECOND                16
#define BITS_MSG_COUNT              7
#define BITS_SIZE_1_TO_32           5
#define BITS_SIZE_1_TO_4            2
#define BITS_SIZE_1_TO_63           6
#define BITS_REGION_ID              8
#define BITS_ROAD_REGULATOR_ID      16
#define BITS_INTERSECTION_ID        16
#define BITS_REQUEST_ID             8
#define BITS_LANE_ID                8
#define BITS_APPROACH_ID            4
#define BITS_LANE_CONNECTION_ID     8
#define BITS_REQUEST_SUB_ROLE       4
#define BITS_IMPORTANCE_LEVEL       4
#define BITS_ISO3833_VEHICLE_TYPE   8
#define BITS_LATITUDE               31
#define BITS_LONGITUDE              32
#define BITS_ELEVATION              16
#define BITS_ANGLE                  15
#define BITS_TRANSMISSION_STATE     3
#define BITS_VELOCITY               13
#define BITS_TRANSIT_STATUS         8
#define BITS_TRANSIT_OCCUPANCY      3
#define BITS_DELTA_TIME             8
#define BITS_IA5_CHAR               7

#define MINUTE_OF_YEAR_MAX          527040u
#define ROLE_ROOT_COUNT             23u
#define ROLE_TRAM                   23u

static bool read_flag(its_bitr_t *r)
{
    return its_bits_read(r, 1) != 0;
}

/* This reads an X.691 normally small non-negative whole number. A long form above 4 octets
 * is rejected, since no extension index of these types needs one. */
static uint32_t read_small_number(its_bitr_t *r)
{
    if (!read_flag(r))
        return its_bits_read(r, 6);
    size_t n = its_bits_uper_length(r);
    if (n == 0 || n > 4)
    {
        r->err = true;
        return 0;
    }
    return its_bits_read(r, (unsigned)(n * 8));
}

/* An open type is an unconstrained length in octets followed by that many octets. */
static void skip_open_type(its_bitr_t *r)
{
    size_t n = its_bits_uper_length(r);
    if (!r->err)
        its_bits_skip(r, n * 8);
}

/* After a set extension bit come the bitmap length, the bitmap and one open type per set bit.
 * The length is a 0 bit and n - 1 in 6 bits, or a 1 bit and n as unconstrained length above 64. */
static void skip_extensions(its_bitr_t *r)
{
    size_t n = read_flag(r) ? its_bits_uper_length(r) : its_bits_read(r, 6) + 1;
    size_t present = 0;
    for (size_t i = 0; i < n && !r->err; i++)
        present += its_bits_read(r, 1);
    for (size_t i = 0; i < present && !r->err; i++)
        skip_open_type(r);
}

static void skip_regional(its_bitr_t *r)
{
    its_bits_skip(r, BITS_REGION_ID);
    skip_open_type(r);
}

static void skip_regional_list(its_bitr_t *r)
{
    unsigned n = its_bits_read(r, BITS_SIZE_1_TO_4) + 1;
    for (unsigned i = 0; i < n && !r->err; i++)
        skip_regional(r);
}

/* This is for an extensible ENUMERATED whose root has exactly 2^bits values, so every root
 * index is valid. */
static uint8_t read_enum(its_bitr_t *r, unsigned bits)
{
    if (!read_flag(r))
        return (uint8_t)its_bits_read(r, bits);
    (void)read_small_number(r);
    return ITS_SREM_ENUM_EXT;
}

/* BasicVehicleRole has 23 root values in 5 bits, so indexes 23 to 31 are invalid. Its only
 * extension value is tram (23) at extension index 0. */
static uint8_t read_role(its_bitr_t *r)
{
    if (read_flag(r))
        return read_small_number(r) == 0 ? ROLE_TRAM : ITS_SREM_ENUM_EXT;
    uint32_t v = its_bits_read(r, 5);
    if (v >= ROLE_ROOT_COUNT)
        r->err = true;
    return (uint8_t)v;
}

/* MinuteOfTheYear takes 20 bits, but only values up to 527040 are in range. */
static uint32_t read_minute(its_bitr_t *r)
{
    uint32_t v = its_bits_read(r, BITS_MINUTE_OF_YEAR);
    if (v > MINUTE_OF_YEAR_MAX)
        r->err = true;
    return v;
}

/* Both VehicleID alternatives are 32 bits: TemporaryID is a fixed 4-octet string without a
 * length, and StationID is a 32-bit integer. */
static uint8_t read_vehicle_id(its_bitr_t *r, uint32_t *id)
{
    uint8_t kind = read_flag(r) ? ITS_SREM_ID_STATION : ITS_SREM_ID_ENTITY;
    *id = its_bits_read(r, 32);
    return kind;
}

static bool read_intersection_ref(its_bitr_t *r, uint16_t *region, uint16_t *id)
{
    bool has_region = read_flag(r);
    if (has_region)
        *region = (uint16_t)its_bits_read(r, BITS_ROAD_REGULATOR_ID);
    *id = (uint16_t)its_bits_read(r, BITS_INTERSECTION_ID);
    return has_region;
}

static void read_access_point(its_bitr_t *r, its_srem_access_t *ap)
{
    if (read_flag(r))
    {
        (void)read_small_number(r);
        skip_open_type(r);
        ap->kind = ITS_SREM_AP_EXT;
        ap->value = 0;
        return;
    }
    switch (its_bits_read(r, 2))
    {
    case 0:
        ap->kind = ITS_SREM_AP_LANE;
        ap->value = (uint8_t)its_bits_read(r, BITS_LANE_ID);
        break;
    case 1:
        ap->kind = ITS_SREM_AP_APPROACH;
        ap->value = (uint8_t)its_bits_read(r, BITS_APPROACH_ID);
        break;
    case 2:
        ap->kind = ITS_SREM_AP_CONNECTION;
        ap->value = (uint8_t)its_bits_read(r, BITS_LANE_CONNECTION_ID);
        break;
    default:
        /* Index 3 is invalid, since the root has only three alternatives. */
        r->err = true;
        break;
    }
}

/* DescriptiveName is an IA5String of 1 to 63 characters, and without an alphabet constraint each
 * character takes 7 bits. The 6-bit length field can also say 64, which is out of range. */
static void read_name(its_bitr_t *r, char *dst, size_t cap)
{
    unsigned n = its_bits_read(r, BITS_SIZE_1_TO_63) + 1;
    if (n > 63)
        r->err = true;
    size_t k = 0;
    for (unsigned i = 0; i < n && !r->err; i++)
    {
        uint32_t c = its_bits_read(r, BITS_IA5_CHAR);
        if (k + 1 < cap)
            dst[k++] = (c < 0x20 || c == 0x7F) ? '?' : (char)c;
    }
    dst[k] = '\0';
}

/* In RequestorType the regional field is a single RegionalExtension, not a list. */
static uint8_t read_requestor_type(its_bitr_t *r, bool *has_hpms, uint8_t *hpms)
{
    bool ext = read_flag(r);
    bool has_subrole = read_flag(r);
    bool has_request = read_flag(r);
    bool has_iso3883 = read_flag(r);
    bool has_hpms_type = read_flag(r);
    bool has_regional = read_flag(r);
    uint8_t role = read_role(r);
    if (has_subrole)
        its_bits_skip(r, BITS_REQUEST_SUB_ROLE);
    if (has_request)
        its_bits_skip(r, BITS_IMPORTANCE_LEVEL);
    if (has_iso3883)
        its_bits_skip(r, BITS_ISO3833_VEHICLE_TYPE);
    if (has_hpms_type)
    {
        *hpms = read_enum(r, 4);
        *has_hpms = true;
    }
    if (has_regional)
        skip_regional(r);
    if (ext)
        skip_extensions(r);
    return role;
}

static void skip_position_vector(its_bitr_t *r)
{
    bool ext = read_flag(r);
    bool has_heading = read_flag(r);
    bool has_speed = read_flag(r);

    bool pos_ext = read_flag(r);
    bool has_elevation = read_flag(r);
    bool has_pos_regional = read_flag(r);
    its_bits_skip(r, BITS_LATITUDE + BITS_LONGITUDE);
    if (has_elevation)
        its_bits_skip(r, BITS_ELEVATION);
    if (has_pos_regional)
        skip_regional_list(r);
    if (pos_ext)
        skip_extensions(r);

    if (has_heading)
        its_bits_skip(r, BITS_ANGLE);
    if (has_speed)
        its_bits_skip(r, BITS_TRANSMISSION_STATE + BITS_VELOCITY);
    if (ext)
        skip_extensions(r);
}

static void read_requestor(its_bitr_t *r, its_srem_t *out)
{
    bool ext = read_flag(r);
    bool has_type = read_flag(r);
    bool has_position = read_flag(r);
    bool has_name = read_flag(r);
    bool has_route_name = read_flag(r);
    bool has_transit_status = read_flag(r);
    bool has_occupancy = read_flag(r);
    bool has_schedule = read_flag(r);
    bool has_regional = read_flag(r);
    out->requestor_kind = read_vehicle_id(r, &out->requestor_id);
    if (has_type)
    {
        out->role = read_requestor_type(r, &out->has_hpms, &out->hpms_type);
        out->has_type = true;
    }
    if (has_position)
        skip_position_vector(r);
    if (has_name)
        read_name(r, out->name, sizeof out->name);
    if (has_route_name)
        read_name(r, out->route_name, sizeof out->route_name);
    if (has_transit_status)
        its_bits_skip(r, BITS_TRANSIT_STATUS);
    if (has_occupancy)
        its_bits_skip(r, BITS_TRANSIT_OCCUPANCY);
    if (has_schedule)
        its_bits_skip(r, BITS_DELTA_TIME);
    if (has_regional)
        skip_regional_list(r);
    if (ext)
        skip_extensions(r);
}

static void read_request_package(its_bitr_t *r, its_srem_request_t *q)
{
    bool ext = read_flag(r);
    bool has_minute = read_flag(r);
    bool has_second = read_flag(r);
    bool has_duration = read_flag(r);
    bool has_regional = read_flag(r);

    bool req_ext = read_flag(r);
    bool has_outbound = read_flag(r);
    bool has_req_regional = read_flag(r);
    q->has_region = read_intersection_ref(r, &q->region, &q->id);
    q->request_id = (uint8_t)its_bits_read(r, BITS_REQUEST_ID);
    q->request_type = read_enum(r, 2);
    read_access_point(r, &q->inbound);
    if (has_outbound)
        read_access_point(r, &q->outbound);
    if (has_req_regional)
        skip_regional_list(r);
    if (req_ext)
        skip_extensions(r);

    if (has_minute)
    {
        q->minute = read_minute(r);
        q->has_minute = 1;
    }
    if (has_second)
    {
        q->second = (uint16_t)its_bits_read(r, BITS_DSECOND);
        q->has_second = 1;
    }
    if (has_duration)
    {
        q->duration = (uint16_t)its_bits_read(r, BITS_DSECOND);
        q->has_duration = 1;
    }
    if (has_regional)
        skip_regional_list(r);
    if (ext)
        skip_extensions(r);
}

bool its_decode_srem(const uint8_t *pdu, size_t len, its_srem_t *out)
{
    memset(out, 0, sizeof *out);
    if (pdu == NULL)
        return false;
    its_bitr_t r = its_bitr_init(pdu, len, 0);
    its_bits_skip(&r, BITS_PROTOCOL_VERSION);
    if (its_bits_read(&r, BITS_MESSAGE_ID) != MSGID_SREM)
        return false;
    out->station_id = its_bits_read(&r, BITS_STATION_ID);

    bool ext = read_flag(&r);
    bool has_time_stamp = read_flag(&r);
    bool has_seq = read_flag(&r);
    bool has_requests = read_flag(&r);
    bool has_regional = read_flag(&r);
    if (has_time_stamp)
        its_bits_skip(&r, BITS_MINUTE_OF_YEAR);
    its_bits_skip(&r, BITS_DSECOND);
    if (has_seq)
    {
        out->sequence_number = (uint8_t)its_bits_read(&r, BITS_MSG_COUNT);
        out->has_seq = true;
    }
    if (has_requests)
    {
        /* Requests beyond the limit are still walked, because the requestor follows them. */
        its_srem_request_t spare;
        memset(&spare, 0, sizeof spare);
        unsigned n = its_bits_read(&r, BITS_SIZE_1_TO_32) + 1;
        for (unsigned i = 0; i < n && !r.err; i++)
        {
            if (i < ITS_SREM_MAX_REQ)
            {
                read_request_package(&r, &out->req[i]);
                out->n_requests++;
            }
            else
            {
                read_request_package(&r, &spare);
                out->truncated = true;
            }
        }
    }
    read_requestor(&r, out);
    if (has_regional)
        skip_regional_list(&r);
    if (ext)
        skip_extensions(&r);

    if (r.err)
    {
        memset(out, 0, sizeof *out);
        return false;
    }
    out->valid = true;
    return true;
}

static void read_status_package(its_bitr_t *r, its_ssem_package_t *p)
{
    bool ext = read_flag(r);
    bool has_requester = read_flag(r);
    bool has_outbound = read_flag(r);
    bool has_minute = read_flag(r);
    bool has_second = read_flag(r);
    bool has_duration = read_flag(r);
    bool has_regional = read_flag(r);
    if (has_requester)
    {
        bool req_ext = read_flag(r);
        bool has_role = read_flag(r);
        bool has_type_data = read_flag(r);
        p->requester_kind = read_vehicle_id(r, &p->requester_id);
        p->request_id = (uint8_t)its_bits_read(r, BITS_REQUEST_ID);
        p->requester_seq = (uint8_t)its_bits_read(r, BITS_MSG_COUNT);
        if (has_role)
        {
            p->role = read_role(r);
            p->has_role = 1;
        }
        if (has_type_data)
        {
            bool unused_has_hpms = false;
            uint8_t unused_hpms = 0;
            uint8_t type_role = read_requestor_type(r, &unused_has_hpms, &unused_hpms);
            if (!has_role)
            {
                p->role = type_role;
                p->has_role = 1;
            }
        }
        if (req_ext)
            skip_extensions(r);
    }
    read_access_point(r, &p->inbound);
    if (has_outbound)
        read_access_point(r, &p->outbound);
    if (has_minute)
    {
        p->minute = read_minute(r);
        p->has_minute = 1;
    }
    if (has_second)
    {
        p->second = (uint16_t)its_bits_read(r, BITS_DSECOND);
        p->has_second = 1;
    }
    if (has_duration)
    {
        p->duration = (uint16_t)its_bits_read(r, BITS_DSECOND);
        p->has_duration = 1;
    }
    p->status = read_enum(r, 3);
    if (has_regional)
        skip_regional_list(r);
    if (ext)
        skip_extensions(r);
}

bool its_decode_ssem(const uint8_t *pdu, size_t len, its_ssem_t *out)
{
    memset(out, 0, sizeof *out);
    if (pdu == NULL)
        return false;
    its_bitr_t r = its_bitr_init(pdu, len, 0);
    its_bits_skip(&r, BITS_PROTOCOL_VERSION);
    if (its_bits_read(&r, BITS_MESSAGE_ID) != MSGID_SSEM)
        return false;
    out->station_id = its_bits_read(&r, BITS_STATION_ID);

    bool ext = read_flag(&r);
    bool has_time_stamp = read_flag(&r);
    bool has_seq = read_flag(&r);
    bool has_regional = read_flag(&r);
    if (has_time_stamp)
        its_bits_skip(&r, BITS_MINUTE_OF_YEAR);
    its_bits_skip(&r, BITS_DSECOND);
    if (has_seq)
        its_bits_skip(&r, BITS_MSG_COUNT);

    /* Everything is walked to the end, so a cut frame fails even past the kept entries. */
    its_ssem_status_t spare_status;
    its_ssem_package_t spare_pkg;
    memset(&spare_status, 0, sizeof spare_status);
    memset(&spare_pkg, 0, sizeof spare_pkg);
    unsigned n_status = its_bits_read(&r, BITS_SIZE_1_TO_32) + 1;
    for (unsigned i = 0; i < n_status && !r.err; i++)
    {
        bool keep = i < ITS_SSEM_MAX_STATUS;
        its_ssem_status_t *st = keep ? &out->status[i] : &spare_status;
        bool st_ext = read_flag(&r);
        bool st_has_regional = read_flag(&r);
        st->sequence_number = (uint8_t)its_bits_read(&r, BITS_MSG_COUNT);
        st->has_region = read_intersection_ref(&r, &st->region, &st->id);
        unsigned n_pkg = its_bits_read(&r, BITS_SIZE_1_TO_32) + 1;
        for (unsigned j = 0; j < n_pkg && !r.err; j++)
        {
            if (keep && out->n_packages < ITS_SSEM_MAX_PKG)
            {
                read_status_package(&r, &out->pkg[out->n_packages]);
                out->n_packages++;
                st->n_packages++;
            }
            else
            {
                read_status_package(&r, &spare_pkg);
                out->truncated = true;
            }
        }
        if (st_has_regional)
            skip_regional_list(&r);
        if (st_ext)
            skip_extensions(&r);
        if (keep)
            out->n_status++;
        else
            out->truncated = true;
    }
    if (has_regional)
        skip_regional_list(&r);
    if (ext)
        skip_extensions(&r);

    if (r.err)
    {
        memset(out, 0, sizeof *out);
        return false;
    }
    out->valid = true;
    return true;
}
