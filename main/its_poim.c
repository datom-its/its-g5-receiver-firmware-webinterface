#include "its_poim.h"

#include <string.h>

#include "events_log.h"
#include "its_bits.h"
#include "its_utf8.h"

/* Layout from TS 103 916 (POIM-PDU-Description, POIM-CommonContainers, POIM-ParkingAvailability)
 * and CDD 4.1.1, measured with asn1tools. */

#define MSGID_POIM        3
#define POIM_VERSION      1
#define POI_TYPE_PARKING  1
#define POI_TYPE_ROOT_MAX 128   /* PoiType INTEGER(1..128,...) */
#define HEADER_BITS       48    /* protocolVersion 8, messageId 8, stationId 32 */

/* These UPER field widths follow from the value range or fixed size of each ASN.1 type. */
#define BITS_BLOCK_COUNT      3    /* WrappedPoiInformationBlocks SIZE(1..8,...) */
#define BITS_POI_TYPE         7    /* PoiType 1..128 */
#define BITS_COUNTRY          10   /* CountryCode BIT STRING SIZE(10) */
#define BITS_PROVIDER         14   /* IssuerIdentifier 0..16383 */
#define BITS_PROVIDER_ALL     24   /* Provider: both of the above */
#define BITS_ID2B             16   /* Identifier2B 0..65535 */
#define BITS_TS_HIGH          10   /* TimestampIts is 42 bits, read as 10 + 32 */
#define BITS_TS               42
#define BITS_IVI_ID           15   /* IviIdentificationNumber 1..32767 */
#define BITS_LIST_8           3    /* SIZE(1..8,...) */
#define BITS_LIST_16          4    /* SIZE(1..16,...) */
#define BITS_LIST_4           2    /* SIZE(1..4,...) */
#define BITS_LIST_32          5    /* SIZE(1..32,...) */
#define BITS_LAT              31   /* Latitude -900000000..900000001 */
#define BITS_LON              32   /* Longitude -1800000000..1800000001 */
#define BITS_ALT              20   /* AltitudeValue -100000..800001 */
#define BITS_DAYS             8    /* DayOfWeek BIT STRING SIZE(8) */
#define BITS_HOURS            5    /* 0..23 */
#define BITS_MINS             6    /* 0..59 */
#define BITS_OPENING_STATUS   4    /* 0..15 */
#define BITS_RATE             7    /* OccupancyRate 1..101 */
#define BITS_TREND            4    /* OccupancyTrend 0..15 */
#define BITS_SPACES           14   /* NumberOfSpaces 1..16383 */
#define BITS_CONFIDENCE       7    /* ConfidenceLevel 1..101 */
#define BITS_VEH_CHOICE       3    /* EuVehicleCategoryCode, six alternatives */
#define BITS_RESERVATION      5    /* ParkingReservationType 0..31 */
#define BITS_FEE              3    /* ParkingFeeType 0..7 */
#define BITS_GOODS            4    /* GoodsType 0..15 */
#define BITS_DANGEROUS        5    /* DangerousGoodsBasic, 20 values */
#define BITS_SPECIAL          4    /* SpecialTransportType BIT STRING SIZE(4) */
#define BITS_STAY_CHOICE      3    /* ParkingOccupancyInfo, seven root alternatives */
#define BITS_AREA_OPT         17   /* presence bits of ParkingArea */
#define BITS_LEVEL            5    /* level -8..16 */
#define BITS_ARRANGEMENT      3    /* ParkingAreaArrangementType 0..7 */
#define BITS_HEIGHT           7    /* VehicleHeight 1..128 */
#define BITS_DELTA_POS        36   /* DeltaPosition: 18 + 18 */
#define BITS_DELTA_REF_POS    51   /* DeltaReferencePosition: 18 + 18 + 15 */
#define BITS_WGS84_ANGLE      19   /* Wgs84Angle: 12 + 7 */
#define BITS_SPACE_OPT        8    /* presence bits of ParkingSpaceDetailed */
#define BITS_SPACE_STATUS     4    /* ParkingSpaceStatus, nine root alternatives */
#define BITS_PERCENT          7    /* partiallyOccupied 0..100 */
#define BITS_NEAR_SPACES      3    /* accessViaParkingSpaces SIZE(0..7) */

/* Smallest encoding of one element in bits. A count is believed only when that many of the
 * smallest element still fit the bits left, so a wrong count cannot claim what never came. */
#define MIN_BLOCK      24   /* poiType 8, octet length 8, one octet: X.691 pads empty to one */
#define MIN_IVIM_REF   40   /* Provider 24, the number in its 16-bit root form */
#define MIN_MAP_REF    18   /* choice bit, region presence bit, id 16 */
#define MIN_PERIOD     30   /* days 8, two TimeOfDay of 11 */
#define MIN_STATUS     53   /* extension bit, 5 presence bits, OccupancyInformation 47 */
#define MIN_VEHICLE    3    /* the choice index of T or G, which carry nothing */
#define MIN_LOAD       7    /* extension bit, 2 presence bits, SpecialTransportType 4 */
#define MIN_STAY       4    /* extension bit and the index of a NULL alternative */
#define MIN_AREA_LIST  8    /* an empty ParkingAreas: its count in the 8-bit form */
/* 1 + 17 presence bits, id 16, OccupancyInformation 47, GeoPosition 64 without altitude,
 * arrangementType 3, and allowedVehicleCategories with one T or G: 3 + 3. */
#define MIN_AREA       154
#define MIN_SPACE      34   /* 1 + 8 presence bits, id 16, status 5, occupancyRule 4 */
#define MIN_RELATED    50   /* ext bit, timestamp presence bit, poiType 8, Provider 24, id 16 */

#define LAT_MAX           900000000
#define LAT_UNAVAILABLE   900000001
#define LON_MAX           1800000000
#define LON_UNAVAILABLE   1800000001
#define ALT_UNAVAILABLE   800001
#define RATE_UNAVAILABLE  101
#define SPACES_UNAVAILABLE 16383
#define TREND_NAMED_MAX   7
#define TREND_UNKNOWN     15
#define STATUS_NAMED_MAX  3
#define STATUS_UNKNOWN    15
#define GOODS_NAMED_MAX   14
#define RESERVATION_NAMED_MAX 13
#define FEE_NAMED_MAX     2
#define DANGEROUS_COUNT   20
#define STAY_ROOT_COUNT   7    /* ParkingOccupancyInfo. Extensions are numbered from 7 on. */
#define LEVEL_MIN         (-8)
#define LEVEL_MAX         16
#define IVI_ID_EXT_VALUE  8388607   /* the one extension value the CDD names */

/* The reader of the first parking block. `halt` is the stop at the engine type: nothing behind
 * it can be placed, but that is no fault of the message, so it is kept apart from `r.err`. */
typedef struct {
    its_bitr_t r;
    its_poim_t *out;
    bool halt;
} pa_t;

static bool read_flag(its_bitr_t *r)
{
    return its_bits_read(r, 1) != 0;
}

static bool live(const pa_t *p)
{
    return !p->r.err && !p->halt;
}

static uint8_t cap8(uint32_t n)
{
    return n > UINT8_MAX ? UINT8_MAX : (uint8_t)n;
}

static uint64_t read_timestamp(its_bitr_t *r)
{
    uint64_t hi = its_bits_read(r, BITS_TS_HIGH);
    return (hi << 32) | its_bits_read(r, 32);
}

/* TimestampIts reaches 2143, but Unix seconds in 32 bits reach only 2106.
 * A later time is dropped. */
static bool ts_to_unix(uint64_t its_ms, uint32_t *out)
{
    uint64_t s = events_its_to_unix_ms(its_ms) / 1000u;
    if (s > UINT32_MAX)
        return false;
    *out = (uint32_t)s;
    return true;
}

/* This reads an X.691 normally small non-negative whole number. A long form above 4 octets
 * is rejected, since no extension index here needs one. */
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

/* An unconstrained whole number: an octet count, then two's complement. A value past int64
 * stops growing, so every range check behind it still rejects it. */
static int64_t read_unc_int(its_bitr_t *r)
{
    size_t n = its_bits_uper_length(r);
    int64_t v = 0;
    bool big = false;
    for (size_t i = 0; i < n && !r->err; i++)
    {
        uint32_t o = its_bits_read(r, 8);
        if (i == 0 && (o & 0x80u))
            v = -1;
        if (v > INT64_MAX / 256 || v < INT64_MIN / 256)
            big = true;
        if (!big)
            v = v * 256 + (int64_t)o;
    }
    return v;
}

/* PoiType INTEGER(1..128,...): 7 bits in the root, else an unconstrained number. */
static int32_t read_poi_type(its_bitr_t *r)
{
    if (!read_flag(r))
        return (int32_t)its_bits_read(r, BITS_POI_TYPE) + 1;
    int64_t v = read_unc_int(r);
    if (v > INT32_MAX)
        return INT32_MAX;
    if (v < INT32_MIN)
        return INT32_MIN;
    return (int32_t)v;
}

static void skip_open_type(its_bitr_t *r)
{
    size_t n = its_bits_uper_length(r);
    if (!r->err)
        its_bits_skip(r, n * 8);
}

/* After a set extension bit come the bitmap length, the bitmap and one open type per set bit.
 * The length is a 0 bit and n - 1 in 6 bits, or a 1 bit and n as unconstrained length. */
static void skip_additions(pa_t *p)
{
    its_bitr_t *r = &p->r;
    size_t n = read_flag(r) ? its_bits_uper_length(r) : its_bits_read(r, 6) + 1;
    size_t present = 0;
    for (size_t i = 0; i < n && !r->err; i++)
        present += its_bits_read(r, 1);
    for (size_t i = 0; i < present && !r->err; i++)
        skip_open_type(r);
    if (live(p))
        p->out->newer = true;
}

/* A count that the bits left cannot hold means the block lost its place; see MIN_*. */
static bool count_fits(pa_t *p, uint32_t n, size_t min_bits)
{
    if (!live(p))
        return false;
    if (n > (p->r.nbits - p->r.pos) / min_bits)
    {
        p->r.err = true;
        return false;
    }
    return true;
}

/* The count of SEQUENCE (SIZE(1..ub,...)) OF: a size-extension bit, then count - 1 in the
 * root bits or an unconstrained count. Returns 0 when the count was not believed. The
 * extension form is a size from a later version, so a believed one sets newer. */
static uint32_t read_count_ext(pa_t *p, unsigned root_bits, size_t min_bits)
{
    bool ext = read_flag(&p->r);
    uint32_t n = ext ? (uint32_t)its_bits_uper_length(&p->r)
                     : its_bits_read(&p->r, root_bits) + 1;
    if (!count_fits(p, n, min_bits))
        return 0;
    if (ext)
        p->out->newer = true;
    return n;
}

/* The count of a SEQUENCE OF without SIZE: an unconstrained length, zero allowed. */
static uint32_t read_count(pa_t *p, size_t min_bits)
{
    uint32_t n = (uint32_t)its_bits_uper_length(&p->r);
    return count_fits(p, n, min_bits) ? n : 0;
}

/* A UTF8String. Its SIZE is not PER-visible, so it comes as an octet count and the octets.
 * With `dst` the first ITS_POIM_TEXT octets are kept, cut before a lead byte whose character
 * would reach past them. The search goes back at most 3 bytes, since a character has at most
 * 3 bytes after its lead. Stray bytes stay in and show as '?' on the page. */
static void read_text(pa_t *p, char *dst, uint8_t *dst_len, bool *cut)
{
    size_t n = its_bits_uper_length(&p->r);
    if (!live(p))
        return;
    if (n > (p->r.nbits - p->r.pos) / 8)
    {
        p->r.err = true;
        return;
    }
    if (dst == NULL)
    {
        its_bits_skip(&p->r, n * 8);
        return;
    }
    /* One octet more than kept: it decides whether the cut falls inside a character. */
    uint8_t buf[ITS_POIM_TEXT + 1];
    size_t take = n < sizeof buf ? n : sizeof buf;
    for (size_t i = 0; i < take; i++)
        buf[i] = (uint8_t)its_bits_read(&p->r, 8);
    its_bits_skip(&p->r, (n - take) * 8);
    size_t k = n;
    if (n > ITS_POIM_TEXT)
    {
        k = ITS_POIM_TEXT;
        while (k > ITS_POIM_TEXT - 3 && (buf[k] & 0xC0u) == 0x80u)
            k--;
        /* All are kept unless that byte starts a character running past them. A continuation
         * byte (a fourth in a row, or a stray one) has width 0. */
        uint8_t lo, hi;
        if (its_utf8_lead(buf[k], &lo, &hi) <= ITS_POIM_TEXT - k)
            k = ITS_POIM_TEXT;
        *cut = true;
    }
    memcpy(dst, buf, k);
    *dst_len = (uint8_t)k;
}

/* NumberOfSpaces: 16383 only means "not available", and 16384 fits the 14 bits but not the type. */
static void keep_spaces(pa_t *p, uint32_t v, uint16_t *dst, bool *has)
{
    if (v < SPACES_UNAVAILABLE)
    {
        *dst = (uint16_t)v;
        *has = true;
    }
    else if (v > SPACES_UNAVAILABLE)
    {
        p->out->out_of_range = true;
    }
}

/* OccupancyInformation. `o` is NULL for one that is not kept. Its trend still counts for newer. */
static void read_occupancy(pa_t *p, its_poim_occ_t *o)
{
    bool ext = read_flag(&p->r);
    uint32_t rate = its_bits_read(&p->r, BITS_RATE) + 1;
    uint32_t trend = its_bits_read(&p->r, BITS_TREND);
    uint32_t n_free = its_bits_read(&p->r, BITS_SPACES) + 1;
    uint32_t n_total = its_bits_read(&p->r, BITS_SPACES) + 1;
    its_bits_skip(&p->r, BITS_CONFIDENCE);
    if (!live(p))
        return;
    if (trend > TREND_NAMED_MAX && trend < TREND_UNKNOWN)
        p->out->newer = true;
    if (o != NULL)
    {
        if (rate < RATE_UNAVAILABLE)
        {
            o->rate = (uint8_t)rate;
            o->has_rate = true;
        }
        else if (rate > RATE_UNAVAILABLE)
        {
            p->out->out_of_range = true;
        }
        if (trend <= TREND_NAMED_MAX)
        {
            o->trend = (uint8_t)trend;
            o->has_trend = true;
        }
        keep_spaces(p, n_free, &o->n_free, &o->has_free);
        keep_spaces(p, n_total, &o->n_total, &o->has_total);
    }
    if (ext)
        skip_additions(p);
}

/* GeoPosition. Its altitude has DEFAULT 800001, so it comes as 800001 or not at all, and both
 * mean none. Only the facility position is kept. The position of an area is stepped over. */
static void read_geo(pa_t *p, bool keep)
{
    bool has_alt = read_flag(&p->r);
    int64_t lat = (int64_t)its_bits_read(&p->r, BITS_LAT) - LAT_MAX;
    int64_t lon = (int64_t)its_bits_read(&p->r, BITS_LON) - LON_MAX;
    int64_t alt = has_alt ? (int64_t)its_bits_read(&p->r, BITS_ALT) - 100000 : ALT_UNAVAILABLE;
    if (!keep || !live(p))
        return;
    its_poim_t *o = p->out;
    if (lat > LAT_UNAVAILABLE || lon > LON_UNAVAILABLE)
    {
        o->out_of_range = true;
    }
    else if (lat <= LAT_MAX && lon <= LON_MAX && lon != -LON_MAX)
    {
        /* CDD v4 marks -180 degrees as valueNotUsed, so it is no position. pos_from_raw in
         * its_decode.c does the same. */
        o->lat_e7 = (int32_t)lat;
        o->lon_e7 = (int32_t)lon;
        o->has_pos = true;
    }
    if (alt > ALT_UNAVAILABLE)
    {
        o->out_of_range = true;
    }
    else if (alt != ALT_UNAVAILABLE)
    {
        o->alt_cm = (int32_t)alt;
        o->has_alt = true;
    }
}

/* EuVehicleCategoryCode: a choice of L, M, N, O (an enumeration each) or T, G (nothing).
 * Returns false for an enumeration index past the named values. */
static bool read_vehicle(pa_t *p, char *cls, uint8_t *num)
{
    static const char CLASS[6] = { 'L', 'M', 'N', 'O', 'T', 'G' };
    static const uint8_t WIDTH[4] = { 3, 2, 2, 2 };
    static const uint8_t NAMED[4] = { 7, 3, 3, 4 };
    uint32_t alt = its_bits_read(&p->r, BITS_VEH_CHOICE);
    if (alt >= sizeof CLASS)
    {
        /* Index 6 or 7 has no alternative, so its width is unknown. */
        p->r.err = true;
        return false;
    }
    *cls = CLASS[alt];
    *num = 0;
    if (alt >= sizeof WIDTH)
        return true;
    uint32_t v = its_bits_read(&p->r, WIDTH[alt]);
    if (v >= NAMED[alt])
        return false;
    *num = (uint8_t)(v + 1);
    return true;
}

static void skip_vehicles(pa_t *p)
{
    uint32_t n = read_count_ext(p, BITS_LIST_4, MIN_VEHICLE);
    char cls;
    uint8_t num;
    for (uint32_t i = 0; i < n && live(p); i++)
        (void)read_vehicle(p, &cls, &num);
}

/* LoadType. With `s` its values go into the kept entry. */
static void read_load(pa_t *p, its_poim_status_t *s)
{
    bool ext = read_flag(&p->r);
    bool has_goods = read_flag(&p->r);
    bool has_dangerous = read_flag(&p->r);
    uint32_t goods = 0;
    if (has_goods)
    {
        if (read_flag(&p->r))
        {
            int64_t v = read_unc_int(&p->r);
            goods = (v < 0 || v > UINT8_MAX) ? UINT8_MAX : (uint32_t)v;
        }
        else
        {
            goods = its_bits_read(&p->r, BITS_GOODS);
        }
    }
    uint32_t dangerous = has_dangerous ? its_bits_read(&p->r, BITS_DANGEROUS) : 0;
    uint32_t special = its_bits_read(&p->r, BITS_SPECIAL);
    if (!live(p))
        return;
    if (has_goods && goods > GOODS_NAMED_MAX)
        p->out->newer = true;
    if (s != NULL)
    {
        if (has_goods)
        {
            s->goods = (uint8_t)goods;
            s->has_goods = true;
        }
        if (has_dangerous && dangerous < DANGEROUS_COUNT)
        {
            s->dangerous = (uint8_t)dangerous;
            s->has_dangerous = true;
        }
        else if (has_dangerous)
        {
            p->out->out_of_range = true;
        }
        /* The first bit on the air is bit 0 of the standard. */
        uint8_t bits = 0;
        for (unsigned b = 0; b < BITS_SPECIAL; b++)
            if ((special >> (BITS_SPECIAL - 1 - b)) & 1u)
                bits = (uint8_t)(bits | (1u << b));
        s->special = bits;
    }
    if (ext)
        skip_additions(p);
}

static uint32_t read_loads(pa_t *p, its_poim_status_t *first)
{
    uint32_t n = read_count_ext(p, BITS_LIST_4, MIN_LOAD);
    for (uint32_t i = 0; i < n && live(p); i++)
        read_load(p, i == 0 ? first : NULL);
    return n;
}

/* A list of ParkingReservationType. The values 14..31 have no name yet. */
static uint32_t read_reservations(pa_t *p, uint8_t *first)
{
    uint32_t n = read_count_ext(p, BITS_LIST_4, BITS_RESERVATION);
    for (uint32_t i = 0; i < n && live(p); i++)
    {
        uint32_t v = its_bits_read(&p->r, BITS_RESERVATION);
        if (!live(p))
            break;
        if (v > RESERVATION_NAMED_MAX)
            p->out->newer = true;
        if (i == 0 && first != NULL)
            *first = (uint8_t)v;
    }
    return n;
}

/* The minutes of limitedDuration: an INTEGER without bounds, so only 0..UINT32_MAX is kept. */
static void keep_stay_num(pa_t *p, its_poim_status_t *s, int64_t v)
{
    if (v < 0 || v > UINT32_MAX)
    {
        p->out->out_of_range = true;
        return;
    }
    s->stay_num = (uint32_t)v;
    s->has_stay_num = true;
}

/* ParkingOccupancyInfo. With `s` the alternative and its number go into the kept entry. */
static void read_stay(pa_t *p, its_poim_status_t *s)
{
    if (read_flag(&p->r))
    {
        uint32_t idx = read_small_number(&p->r);
        skip_open_type(&p->r);
        if (!live(p))
            return;
        p->out->newer = true;
        if (s != NULL)
            s->stay_kind = idx > UINT8_MAX - STAY_ROOT_COUNT ? UINT8_MAX
                                                             : (uint8_t)(idx + STAY_ROOT_COUNT);
        return;
    }
    uint32_t alt = its_bits_read(&p->r, BITS_STAY_CHOICE);
    int64_t minutes = 0;
    uint64_t ts = 0;
    switch (alt)
    {
    case 3:
    case 4:
        minutes = read_unc_int(&p->r);
        break;
    case 5:
    case 6:
        ts = read_timestamp(&p->r);
        break;
    case 7:
        /* Index 7 has no alternative, so its width is unknown. */
        p->r.err = true;
        return;
    default:
        break;
    }
    if (s == NULL || !live(p))
        return;
    s->stay_kind = (uint8_t)alt;
    if (alt == 3 || alt == 4)
    {
        keep_stay_num(p, s, minutes);
    }
    else if (alt == 5 || alt == 6)
    {
        if (ts_to_unix(ts, &s->stay_num))
            s->has_stay_num = true;
        else
            p->out->out_of_range = true;
    }
}

/* One ParkingStatus. `keep` is set for the first entry, whose values the page shows. */
static void read_status_entry(pa_t *p, its_poim_status_t *s, bool keep)
{
    bool ext = read_flag(&p->r);
    bool has_vehicles = read_flag(&p->r);
    bool has_reservations = read_flag(&p->r);
    bool has_loads = read_flag(&p->r);
    bool has_fees = read_flag(&p->r);
    bool has_stays = read_flag(&p->r);
    uint32_t n;
    if (has_vehicles)
    {
        n = read_count_ext(p, BITS_LIST_4, MIN_VEHICLE);
        for (uint32_t i = 0; i < n && live(p); i++)
        {
            char cls = 0;
            uint8_t num = 0;
            bool named = read_vehicle(p, &cls, &num);
            if (i > 0 || !live(p))
                continue;
            if (named)
            {
                s->veh_class = cls;
                s->veh_num = num;
                s->lists = (uint8_t)(s->lists | ITS_POIM_FILT_VEHICLE);
            }
            else if (keep)
            {
                p->out->out_of_range = true;
            }
        }
        if (n > 1)
            s->more = true;
    }
    if (has_reservations)
    {
        n = read_reservations(p, &s->reservation);
        if (n > 0)
            s->lists = (uint8_t)(s->lists | ITS_POIM_FILT_RESERVATION);
        if (n > 1)
            s->more = true;
    }
    if (has_loads)
    {
        n = read_loads(p, keep ? s : NULL);
        if (n > 0)
            s->lists = (uint8_t)(s->lists | ITS_POIM_FILT_LOAD);
        if (n > 1)
            s->more = true;
    }
    if (has_fees)
    {
        n = read_count_ext(p, BITS_LIST_4, BITS_FEE);
        for (uint32_t i = 0; i < n && live(p); i++)
        {
            uint32_t v = its_bits_read(&p->r, BITS_FEE);
            if (!live(p))
                break;
            if (v > FEE_NAMED_MAX)
                p->out->newer = true;
            if (i == 0)
                s->fee = (uint8_t)v;
        }
        if (n > 0)
            s->lists = (uint8_t)(s->lists | ITS_POIM_FILT_FEE);
        if (n > 1)
            s->more = true;
    }
    if (has_stays)
    {
        n = read_count_ext(p, BITS_LIST_4, MIN_STAY);
        for (uint32_t i = 0; i < n && live(p); i++)
            read_stay(p, (i == 0 && keep) ? s : NULL);
        if (n > 0)
            s->lists = (uint8_t)(s->lists | ITS_POIM_FILT_STAY);
        if (n > 1)
            s->more = true;
    }
    read_occupancy(p, keep ? &s->occ : NULL);
    if (ext)
        skip_additions(p);
}

/* PoiBlockManagementContainer: provider, entry and time, then the linked IVIM and MAPEM. */
static void read_management(pa_t *p)
{
    its_poim_t *o = p->out;
    bool ext = read_flag(&p->r);
    bool has_ivims = read_flag(&p->r);
    bool has_mapems = read_flag(&p->r);
    uint32_t country = its_bits_read(&p->r, BITS_COUNTRY);
    uint32_t provider = its_bits_read(&p->r, BITS_PROVIDER);
    uint32_t entry = its_bits_read(&p->r, BITS_ID2B);
    uint64_t ts = read_timestamp(&p->r);
    if (!live(p))
        return;
    o->has_mgmt = true;
    o->country = (uint16_t)country;
    o->provider = (uint16_t)provider;
    o->entry = (uint16_t)entry;
    if (!ts_to_unix(ts, &o->time_s))
        o->out_of_range = true;
    if (has_ivims)
    {
        uint32_t n = read_count_ext(p, BITS_LIST_8, MIN_IVIM_REF);
        o->n_ivim = cap8(n);
        for (uint32_t i = 0; i < n && live(p); i++)
        {
            its_bits_skip(&p->r, BITS_PROVIDER_ALL);
            if (!read_flag(&p->r))
                its_bits_skip(&p->r, BITS_IVI_ID);
            else if (read_unc_int(&p->r) != IVI_ID_EXT_VALUE && live(p))
                o->newer = true;
        }
    }
    if (has_mapems)
    {
        uint32_t n = read_count_ext(p, BITS_LIST_8, MIN_MAP_REF);
        o->n_mapem = cap8(n);
        for (uint32_t i = 0; i < n && live(p); i++)
        {
            bool intersection = read_flag(&p->r);
            bool has_region = read_flag(&p->r);
            uint32_t region = has_region ? its_bits_read(&p->r, BITS_ID2B) : 0;
            uint32_t id = its_bits_read(&p->r, BITS_ID2B);
            if (i > 0 || !live(p))
                continue;
            o->has_map = true;
            o->map_intersection = intersection;
            o->map_has_region = has_region;
            o->map_region = (uint16_t)region;
            o->map_id = (uint16_t)id;
        }
    }
    if (ext)
        skip_additions(p);
}

/* Periods: only the first is kept, and only when all four times can be. DayOfWeek sends
 * bit 0 ("unused") first, and bit n becomes (1 << n). */
static void read_periods(pa_t *p)
{
    its_poim_t *o = p->out;
    uint32_t n = read_count_ext(p, BITS_LIST_8, MIN_PERIOD);
    o->n_periods = cap8(n);
    for (uint32_t i = 0; i < n && live(p); i++)
    {
        uint32_t days = its_bits_read(&p->r, BITS_DAYS);
        uint32_t oh = its_bits_read(&p->r, BITS_HOURS);
        uint32_t om = its_bits_read(&p->r, BITS_MINS);
        uint32_t ch = its_bits_read(&p->r, BITS_HOURS);
        uint32_t cm = its_bits_read(&p->r, BITS_MINS);
        if (i > 0 || !live(p))
            continue;
        if (oh > 23 || om > 59 || ch > 23 || cm > 59)
        {
            o->out_of_range = true;
            continue;
        }
        uint8_t mask = 0;
        for (unsigned b = 1; b < BITS_DAYS; b++)
            if ((days >> (BITS_DAYS - 1 - b)) & 1u)
                mask = (uint8_t)(mask | (1u << b));
        o->days = mask;
        o->open_h = (uint8_t)oh;
        o->open_m = (uint8_t)om;
        o->close_h = (uint8_t)ch;
        o->close_m = (uint8_t)cm;
        o->has_period = true;
    }
}

/* GeneralParkingPlaceContainer: keeps position, name and opening times, skips the other texts. */
static void read_place(pa_t *p)
{
    its_poim_t *o = p->out;
    bool ext = read_flag(&p->r);
    bool has_periods = read_flag(&p->r);
    bool has_address = read_flag(&p->r);
    bool has_phone = read_flag(&p->r);
    bool has_website = read_flag(&p->r);
    read_geo(p, true);
    read_text(p, o->name, &o->name_len, &o->name_cut);
    if (has_periods)
        read_periods(p);
    if (has_address)
        read_text(p, NULL, NULL, NULL);
    if (has_phone)
        read_text(p, NULL, NULL, NULL);
    if (has_website)
        read_text(p, NULL, NULL, NULL);
    if (ext)
        skip_additions(p);
}

/* ParkingStatusContainer: the opening status, the occupancy of the whole facility and the
 * list of counts per kind of space, of which the first is kept whole. */
static void read_aggregated(pa_t *p)
{
    its_poim_t *o = p->out;
    bool ext = read_flag(&p->r);
    bool has_occ = read_flag(&p->r);
    bool has_list = read_flag(&p->r);
    uint32_t status = its_bits_read(&p->r, BITS_OPENING_STATUS);
    if (live(p))
    {
        if (status <= STATUS_NAMED_MAX)
        {
            o->status = (uint8_t)status;
            o->has_status = true;
        }
        else if (status != STATUS_UNKNOWN)
        {
            o->newer = true;
        }
    }
    if (has_occ)
    {
        its_poim_occ_t occ;
        memset(&occ, 0, sizeof occ);
        read_occupancy(p, &occ);
        if (live(p))
            o->occ = occ;
    }
    if (has_list)
    {
        uint32_t n = read_count_ext(p, BITS_LIST_16, MIN_STATUS);
        o->n_status = cap8(n);
        its_poim_status_t s;
        for (uint32_t i = 0; i < n && live(p); i++)
        {
            memset(&s, 0, sizeof s);
            read_status_entry(p, &s, i == 0);
            if (i == 0 && live(p))
            {
                o->sub = s;
                o->has_sub = true;
            }
        }
    }
    if (ext)
        skip_additions(p);
}

static void skip_delta_positions(pa_t *p)
{
    uint32_t n = read_count_ext(p, BITS_LIST_32, BITS_DELTA_POS);
    its_bits_skip(&p->r, (size_t)n * BITS_DELTA_POS);
}

static void read_arrangement(pa_t *p)
{
    uint32_t v = its_bits_read(&p->r, BITS_ARRANGEMENT);
    if (live(p) && v > 4 && v < 7)   /* 5 and 6 are reserved, 7 is "unknown" */
        p->out->newer = true;
}

/* ParkingSpaceDetailed with the fields of ParkingSpaceBasic in place: only walked. */
static void read_space(pa_t *p)
{
    bool ext = read_flag(&p->r);
    uint32_t opt = its_bits_read(&p->r, BITS_SPACE_OPT);
#define SPACE_HAS(i) (((opt >> (BITS_SPACE_OPT - 1 - (i))) & 1u) != 0)
    its_bits_skip(&p->r, BITS_ID2B);
    if (SPACE_HAS(0))
        its_bits_skip(&p->r, BITS_DELTA_REF_POS);
    if (read_flag(&p->r))
    {
        (void)read_small_number(&p->r);
        skip_open_type(&p->r);
        if (live(p))
            p->out->newer = true;
    }
    else
    {
        switch (its_bits_read(&p->r, BITS_SPACE_STATUS))
        {
        case 0: case 1: case 3: case 7: case 8:
            break;
        case 2: case 5: case 6:
            its_bits_skip(&p->r, BITS_TS);
            break;
        case 4:
            its_bits_skip(&p->r, BITS_PERCENT);
            break;
        default:
            /* Indexes 9 to 15 have no alternative, so their width is unknown. */
            p->r.err = true;
            return;
        }
    }
    if (SPACE_HAS(1))
        read_arrangement(p);
    if (SPACE_HAS(2))
        skip_delta_positions(p);
    if (SPACE_HAS(3))
        its_bits_skip(&p->r, BITS_WGS84_ANGLE);
    read_stay(p, NULL);
    if (SPACE_HAS(4))
        its_bits_skip(&p->r, BITS_ID2B);
    if (SPACE_HAS(5))
        its_bits_skip(&p->r, BITS_ID2B);
    if (SPACE_HAS(6))
        its_bits_skip(&p->r, (size_t)its_bits_read(&p->r, BITS_NEAR_SPACES) * BITS_ID2B);
    if (SPACE_HAS(7))
        (void)read_reservations(p, NULL);
#undef SPACE_HAS
    if (ext)
        skip_additions(p);
}

static void read_spaces(pa_t *p)
{
    uint32_t n = read_count(p, MIN_SPACE);
    for (uint32_t i = 0; i < n && live(p); i++)
        read_space(p);
}

/* ParkingArea. The first one gives id, occupancy, level, height and price. The engine list
 * holds a type of unknown width, so the block cannot be placed behind it. */
static void read_area(pa_t *p, bool keep)
{
    its_poim_t *o = p->out;
    bool ext = read_flag(&p->r);
    uint32_t opt = its_bits_read(&p->r, BITS_AREA_OPT);
#define AREA_HAS(i) (((opt >> (BITS_AREA_OPT - 1 - (i))) & 1u) != 0)
    uint32_t id = its_bits_read(&p->r, BITS_ID2B);
    its_poim_occ_t occ;
    memset(&occ, 0, sizeof occ);
    read_occupancy(p, keep ? &occ : NULL);
    if (keep && live(p))
    {
        o->area_id = (uint16_t)id;
        o->area_occ = occ;
        o->has_area = true;
    }
    read_geo(p, false);
    if (AREA_HAS(0))
    {
        /* level INTEGER(-8..16,...): 17..23 fit the root bits but not the root range. */
        bool level_ext = read_flag(&p->r);
        int64_t level = level_ext ? read_unc_int(&p->r)
                                  : (int64_t)its_bits_read(&p->r, BITS_LEVEL) + LEVEL_MIN;
        if (level_ext && live(p))
            o->newer = true;   /* a level the root range does not know, like GoodsType past 15 */
        if (keep && live(p))
        {
            if ((!level_ext && level > LEVEL_MAX) || level < INT8_MIN || level > INT8_MAX)
                o->out_of_range = true;
            else
                o->level = (int8_t)level;
        }
    }
    read_arrangement(p);
    if (AREA_HAS(1))
        skip_delta_positions(p);
    if (AREA_HAS(2))
        its_bits_skip(&p->r, BITS_WGS84_ANGLE);
    if (AREA_HAS(3))
        its_bits_skip(&p->r, BITS_ID2B);
    skip_vehicles(p);
    if (AREA_HAS(4))
    {
        if (live(p))
        {
            o->engine_stop = true;
            p->halt = true;
        }
        return;
    }
    if (AREA_HAS(5))
        (void)read_loads(p, NULL);
    if (AREA_HAS(6))
        (void)read_loads(p, NULL);
    if (AREA_HAS(7))
    {
        uint32_t h = its_bits_read(&p->r, BITS_HEIGHT) + 1;
        if (keep && live(p))
        {
            o->height = (uint8_t)h;
            o->has_height = true;
        }
    }
    if (AREA_HAS(8))
        (void)read_reservations(p, NULL);
    if (AREA_HAS(9))
    {
        if (keep)
            read_text(p, o->price, &o->price_len, &o->price_cut);
        else
            read_text(p, NULL, NULL, NULL);
    }
    for (unsigned i = 10; i <= 12; i++)   /* payment, booking, access texts */
        if (AREA_HAS(i))
            read_text(p, NULL, NULL, NULL);
    if (AREA_HAS(13))
        its_bits_skip(&p->r, (size_t)read_count(p, BITS_DELTA_POS) * BITS_DELTA_POS);
    if (AREA_HAS(14))
        its_bits_skip(&p->r, (size_t)read_count(p, BITS_ID2B) * BITS_ID2B);
    if (AREA_HAS(15))
        read_spaces(p);
    if (AREA_HAS(16))
        read_spaces(p);
#undef AREA_HAS
    if (ext)
        skip_additions(p);
}

/* ParkingSupplyCapabilitiesContainer: a list of lists of areas. n_areas sums the inner counts
 * that were believed. areas_at_least says that not every inner count was reached. */
static void read_detailed(pa_t *p)
{
    its_poim_t *o = p->out;
    uint32_t outer = read_count(p, MIN_AREA_LIST);
    bool counted = live(p);
    bool first = true;
    for (uint32_t i = 0; i < outer && counted; i++)
    {
        uint32_t inner = read_count(p, MIN_AREA);
        if (!live(p))
        {
            counted = false;
            break;
        }
        uint32_t sum = (uint32_t)o->n_areas + inner;
        o->n_areas = sum > UINT16_MAX ? UINT16_MAX : (uint16_t)sum;
        for (uint32_t j = 0; j < inner && live(p); j++)
        {
            read_area(p, first);
            first = false;
        }
        /* Behind a stop the next inner count is out of reach. */
        if (!live(p) && i + 1 < outer)
            counted = false;
    }
    o->areas_at_least = !counted;
}

/* RelatedPoiInfoBlockContainer: only counted, but walked to reach what follows. */
static void read_related(pa_t *p)
{
    its_poim_t *o = p->out;
    uint32_t n = read_count(p, MIN_RELATED);
    o->n_related = cap8(n);
    for (uint32_t i = 0; i < n && live(p); i++)
    {
        bool ext = read_flag(&p->r);
        bool has_ts = read_flag(&p->r);
        int32_t type = read_poi_type(&p->r);
        if (live(p) && (type < 1 || type > POI_TYPE_ROOT_MAX))
            o->newer = true;   /* a type number from a later version */
        its_bits_skip(&p->r, BITS_PROVIDER_ALL + BITS_ID2B);
        if (has_ts)
            its_bits_skip(&p->r, BITS_TS);
        if (ext)
            skip_additions(p);
    }
}

/* The first ParkingAvailabilityBlock, read through a reader fenced to [start, end). The
 * facility data comes before the areas, so a stop in an area leaves it standing. */
static void read_parking(const uint8_t *pdu, size_t start, size_t end, bool cut_short,
                         its_poim_t *out)
{
    pa_t p = { { pdu, end, start, false }, out, false };
    bool ext = read_flag(&p.r);
    bool has_detailed = read_flag(&p.r);
    bool has_related = read_flag(&p.r);
    read_management(&p);
    read_place(&p);
    read_aggregated(&p);
    if (has_detailed)
        read_detailed(&p);
    if (has_related)
        read_related(&p);
    if (ext)
        skip_additions(&p);
    if (p.halt)
        return;
    if (p.r.err)
    {
        out->broken = true;
        return;
    }
    /* A block cut by the PDU end has no end of its own to compare with. */
    if (cut_short)
        return;
    size_t left = p.r.nbits - p.r.pos;
    if (left > 7 || its_bits_read(&p.r, (unsigned)left) != 0)
        out->tail_left = true;
}

static void note_other_type(its_poim_t *out, int32_t type)
{
    for (uint8_t i = 0; i < out->n_other_types; i++)
        if (out->other_type[i] == type)
            return;
    if (out->n_other_types < ITS_POIM_OTHER_TYPES)
        out->other_type[out->n_other_types++] = type;
    else
        out->other_more = true;
}

bool its_decode_poim(const uint8_t *pdu, size_t len, its_poim_t *out)
{
    memset(out, 0, sizeof *out);
    if (pdu == NULL || len < HEADER_BITS / 8 || pdu[1] != MSGID_POIM || pdu[0] == 0)
        return false;
    if (pdu[0] != POIM_VERSION)
    {
        out->wrong_version = true;
        out->other_version = pdu[0];
        return false;
    }
    out->read = true;

    its_bitr_t r = its_bitr_init(pdu, len, HEADER_BITS);
    uint32_t n;
    if (!read_flag(&r))
    {
        n = its_bits_read(&r, BITS_BLOCK_COUNT) + 1;
    }
    else
    {
        n = (uint32_t)its_bits_uper_length(&r);
        if (n == 0)
            out->list_broken = true;
    }
    if (r.err)
    {
        out->list_broken = true;
        return true;
    }
    out->n_blocks = cap8(n);
    /* A count the PDU cannot hold is noted, but the blocks that did come are still read. */
    if (n > (r.nbits - r.pos) / MIN_BLOCK)
        out->list_broken = true;

    for (uint32_t i = 0; i < n; i++)
    {
        int32_t type = read_poi_type(&r);
        size_t octets = its_bits_uper_length(&r);   /* a fragmented length sets err */
        if (r.err)
        {
            out->list_broken = true;
            break;
        }
        size_t start = r.pos;
        size_t end = start + octets * 8;
        bool cut_short = end > r.nbits;
        if (cut_short)
        {
            end = r.nbits;
            out->list_broken = true;
        }
        if (type == POI_TYPE_PARKING)
        {
            if (out->n_parking == 0)
                read_parking(pdu, start, end, cut_short, out);
            out->n_parking = cap8((uint32_t)out->n_parking + 1);
        }
        else
        {
            note_other_type(out, type);
        }
        r.pos = end;
        if (cut_short)
            break;
    }
    return true;
}
