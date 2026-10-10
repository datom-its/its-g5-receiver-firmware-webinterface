#pragma once

/* This module decodes POIM (messageId 3, protocolVersion 1) of ETSI TS 103 916: a list of POI
 * blocks, each a type number and an open type. Parking availability (poiType 1) is the only
 * block type the standard defines so far. Version 0 under messageId 3 is the old EVCSN, which
 * its_decode.c reads. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Raw bytes kept per air text. The page shows at most 40 bytes of output, and a shown character
 * never comes out shorter than its raw bytes. A hidden one (its_utf8_unshown) becomes a one-byte
 * '?', so a cut text full of them shows fewer than 40. */
#define ITS_POIM_TEXT         40
#define ITS_POIM_OTHER_TYPES  3    /* The page names at most three other block types. */

/* NumberOfSpaces names 101 "unavailable", but its comment gives 16383 for that, and 101 is also
 * a plain count. So the decoder drops 16383 and keeps 101, and the page adds "or not stated". */
#define ITS_POIM_SPACES_MAYBE_NA  101

/* The filter lists of a ParkingStatus entry, in ASN.1 order. Its count holds for all of the
 * sent lists at once (logical AND), so it is no share of the total. */
#define ITS_POIM_FILT_VEHICLE      (1u << 0)   /* vehicleTypes */
#define ITS_POIM_FILT_RESERVATION  (1u << 1)   /* reservationTypes */
#define ITS_POIM_FILT_LOAD         (1u << 2)   /* loadTypes */
#define ITS_POIM_FILT_FEE          (1u << 3)   /* parkingFeeTypes */
#define ITS_POIM_FILT_STAY         (1u << 4)   /* occupancyTypes: how long one may park */

/* DayOfWeek keeps bit n of the standard as (1 << n): 1 is Monday, 7 Sunday. Bit 0 is the
 * standard's "unused" and is dropped. S_TRF_WDAYS starts on Sunday, so day n is entry n % 7. */
#define ITS_POIM_DAYS_ALL  0xFEu

/* One OccupancyInformation. A value that only means "not available" leaves its flag false:
 * 16383 spaces, rate 101, trend 15. confidence is not kept. */
typedef struct {
    uint16_t n_free;       /* free spaces, 1..16382, see ITS_POIM_SPACES_MAYBE_NA */
    uint16_t n_total;      /* all spaces, same range */
    uint8_t  rate;         /* percent, 1..100, the sender's figure, never recomputed */
    uint8_t  trend;        /* OccupancyTrend, set only for the named 0..7; 8..14 set newer */
    bool     has_free;
    bool     has_total;
    bool     has_rate;
    bool     has_trend;
} its_poim_occ_t;

/* The first ParkingStatus entry: a count for one kind of space. Only the first value of each
 * filter list is kept. With several lists the page must say that they narrow the count, and
 * `more` asks for an ellipsis. The enumerations are kept as sent and the page names them. A
 * value without a name sets newer. */
typedef struct {
    its_poim_occ_t occ;
    /* Minutes for stay_kind 3 and 4, Unix seconds UTC for 5 and 6. has_stay_num is false for a
     * negative value or one past 32 bits, and out_of_range is set then. */
    uint32_t stay_num;
    bool     has_stay_num;
    /* ITS_POIM_FILT_* of the lists sent. 0 can come: ParkingStatus asks for at least one list
     * in a WITH COMPONENTS rule, which PER does not see. */
    uint8_t  lists;
    bool     more;         /* a list held more than one value */
    /* EU vehicle category 'L', 'M', 'N', 'O', 'T' or 'G'. An index past the named ones drops
     * the vehicle bit from `lists` and sets out_of_range, so this is never empty when shown. */
    char     veh_class;
    uint8_t  veh_num;      /* the digit after it, as in N3; 0 for T and G */
    uint8_t  reservation;  /* ParkingReservationType 0..31; 14..31 are reserved */
    uint8_t  fee;          /* ParkingFeeType 0..7; 3..7 are reserved */
    bool     has_goods;
    bool     has_dangerous;
    uint8_t  goods;        /* GoodsType; 15 and extension values (capped at 255) have no name */
    uint8_t  dangerous;    /* DangerousGoodsBasic 0..19 */
    uint8_t  special;      /* SpecialTransportType, bit n of the standard as (1 << n) */
    uint8_t  stay_kind;    /* ParkingOccupancyInfo alternative 0..6; extensions count on from 7 */
} its_poim_status_t;

/* Everything after the counts describes the FIRST parking block only. Later ones are counted
 * and skipped by their open-type length. Air texts are the raw UTF-8 octets without a NUL: the
 * page checks them with the its_utf8.h rules. A longer text is cut before a lead byte whose
 * character would pass ITS_POIM_TEXT, otherwise at ITS_POIM_TEXT, so at least 37 bytes stay.
 * *_cut asks for the ellipsis. */
typedef struct {
    bool     read;             /* the header was messageId 3 with protocolVersion 1 */
    bool     wrong_version;    /* messageId 3 with a protocolVersion above 1; nothing else is set */
    uint8_t  other_version;    /* that protocolVersion; 0 is the old EVCSN and never lands here */
    /* The block list ran past the PDU, announced more blocks than it can hold, or announced none
     * in its extension form. n_parking and other_type then hold only what was reached. */
    bool     list_broken;
    /* The first parking block lost its place in the bits (a count larger than the bits left, a
     * length past its end, a choice index with no alternative). The rest of it is not read. */
    bool     broken;
    /* notAllowedEngineCharacteristics was met: a type of unknown width, so nothing
     * behind it in that block can be found. Its width is never guessed. */
    bool     engine_stop;
    bool     newer;            /* the first parking block held reserved values or extensions */
    /* A value outside what its type allows was left out (an hour past 23, a rate past 101, a
     * vehicle index past the named ones). The rest of the block was still read. */
    bool     out_of_range;
    /* The first parking block was read to its end with more than its zero padding left over.
     * The sender and this reading disagree about its shape, so doubt its fields below. */
    bool     tail_left;
    uint8_t  n_blocks;         /* blocks the list announces, capped at 255 */
    uint8_t  n_parking;        /* blocks of poiType 1 that were reached, capped at 255 */
    uint8_t  n_other_types;    /* distinct other poiType numbers kept in other_type */
    bool     other_more;       /* a further distinct type came that did not fit */
    /* poiType values as sent, in the order they came. Extension values past int32 are capped. */
    int32_t  other_type[ITS_POIM_OTHER_TYPES];

    /* managementContainer, valid with has_mgmt. */
    bool     has_mgmt;
    uint16_t provider;         /* providerIdentifier 0..16383, unique only with the country */
    uint16_t country;          /* CountryCode, its 10 bits as sent with the first one highest */
    uint16_t entry;            /* blockIdentificationNumber */
    /* timestamp in Unix seconds UTC, leap seconds taken out. 0 means none: past the year 2106
     * (TimestampIts reaches 2143) it is dropped and out_of_range is set. */
    uint32_t time_s;
    uint8_t  n_ivim;           /* linkedIvims, only counted: the IVIM content is not decoded */
    uint8_t  n_mapem;          /* linkedMapems */
    bool     has_map;          /* the first MAPEM reference below was read */
    bool     map_intersection; /* it names an intersection, otherwise a road segment */
    bool     map_has_region;
    uint16_t map_region;
    uint16_t map_id;

    /* placeInfo. The position is the facility's, not the sender's from the GN header. */
    bool     has_pos;          /* false for "unavailable", -180 degrees or out of range */
    bool     has_alt;          /* false for 800001 "unavailable" and when it was not sent */
    int32_t  lat_e7, lon_e7;   /* WGS84, 1e-7 degree units */
    /* AltitudeValue in centimetres. The named -100000 and 800000 mean "this or beyond". */
    int32_t  alt_cm;
    uint8_t  name_len;         /* 0 when empty or not read */
    bool     name_cut;
    char     name[ITS_POIM_TEXT];
    uint8_t  n_periods;        /* openingPeriods entries */
    /* The first period was read and all four times are real (hour 0..23, minute 0..59). An
     * impossible time leaves this false and sets out_of_range. */
    bool     has_period;
    uint8_t  days;             /* see ITS_POIM_DAYS_ALL */
    /* Local time of the facility without a zone, as sent: closing before opening runs past
     * midnight, and 00:00 to 00:00 can mean all day or none. */
    uint8_t  open_h, open_m, close_h, close_m;

    /* aggregatedstatus */
    bool     has_status;       /* only for the named 0..3; 15 is "unknown", 4..14 set newer */
    /* OpeningStatus as sent: 0 closed, 1 open, 2 subscribersOnly, 3 full; the page names them. */
    uint8_t  status;
    its_poim_occ_t occ;        /* currentOccupancy; all flags false when it was not sent */
    uint8_t  n_status;         /* detailedStatus entries */
    bool     has_sub;          /* sub below was read */
    its_poim_status_t sub;

    /* detailedstatus, a list of ParkingAreas lists. n_areas sums the inner counts that were read
     * and fit the bits left at the smallest size an area can have. areas_at_least says not every
     * inner count was reached. */
    uint16_t n_areas;
    bool     areas_at_least;
    bool     has_area;         /* id and area_occ of the first area were read */
    uint16_t area_id;
    its_poim_occ_t area_occ;
    /* -8..16, 0 when not sent (the DEFAULT). An extension value sets newer and is kept if it
     * fits int8. A root value past 16 or an extension value outside int8 leaves 0 and sets
     * out_of_range. */
    int8_t   level;
    /* heightRestriction, a VehicleHeight as sent: 1..125 are steps of 5 cm, and the page maps
     * 126..128, whose names and comment in the standard disagree. */
    bool     has_height;
    uint8_t  height;
    uint8_t  price_len;        /* pricingInformation; 0 when not sent or not reached */
    bool     price_cut;
    char     price[ITS_POIM_TEXT];

    uint8_t  n_related;        /* relatedPoi entries, only counted, capped at 255 */
} its_poim_t;

/* `pdu` starts at the ItsPduHeader, and `len` is the exact PDU length: nothing at or past
 * pdu + len is read. `out` is always filled completely, starting from zero. Returns true for a
 * version 1 header, and `read` is then set whatever the blocks held. A higher version returns
 * false with only wrong_version and other_version set. Anything else returns false with all
 * zero. */
bool its_decode_poim(const uint8_t *pdu, size_t len, its_poim_t *out);

#ifdef __cplusplus
}
#endif
