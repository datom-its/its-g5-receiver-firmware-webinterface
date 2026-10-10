#pragma once

/* This module reads the contents of the CPM containers (TS 103 324 V2.1.1, messageId 14) whose
 * places its_decode.c recorded: the perceived objects, the sensors, the perception regions, the
 * trailers of a sending vehicle and the map reference of a sending roadside unit. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_decode.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ITS_CPM_DETAIL_OBJS  2    /* objects kept in its_cpm_t for the detail line */
#define ITS_CPM_ALL_MAX      64   /* the caller's list of every object (msg_extra scratch) */

/* The object container depends on the CDD edition. V3 is the one the CPM ASN.1 imports. V4 is
 * the newer one Wireshark reads, with VRU subclasses 4 bits wide and one more extension bit. */
#define ITS_CPM_CDD_V3  3
#define ITS_CPM_CDD_V4  4

/* The tally of the detail line, in its order. An object counts under its most likely class. */
enum {
    ITS_CPM_CAT_CAR, ITS_CPM_CAT_BUS, ITS_CPM_CAT_TRUCK, ITS_CPM_CAT_TRAM, ITS_CPM_CAT_TWOWHEEL,
    ITS_CPM_CAT_PED, ITS_CPM_CAT_ANIMAL, ITS_CPM_CAT_GROUP, ITS_CPM_CAT_OTHER, ITS_CPM_CAT_NONE,
    ITS_CPM_CATS
};

/* ObjectClass, with the VRU CHOICE unfolded. `sub` of its_cpm_obj_t is the TrafficParticipantType
 * for VEHICLE, the subprofile value for PED..ANIMAL (the V3 'max' is 15 as in V4), OtherSubClass
 * for OTHER. The two NEWER kinds are extension alternatives, skipped by their length. */
#define ITS_CPM_CLS_NONE       0   /* no classification sent */
#define ITS_CPM_CLS_VEHICLE    1
#define ITS_CPM_CLS_PED        2
#define ITS_CPM_CLS_BIKE       3   /* bicyclistAndLightVruVehicle */
#define ITS_CPM_CLS_MOTO       4
#define ITS_CPM_CLS_ANIMAL     5
#define ITS_CPM_CLS_VRU_NEWER  6
#define ITS_CPM_CLS_GROUP      7   /* group_size, group_profiles */
#define ITS_CPM_CLS_OTHER      8
#define ITS_CPM_CLS_NEWER      9

/* vel_kind and acc_kind: POLAR keeps magnitude and direction in a/b, CART the x and y parts. */
#define ITS_CPM_KIN_NONE   0
#define ITS_CPM_KIN_POLAR  1
#define ITS_CPM_KIN_CART   2

/* flags of its_cpm_obj_t: which optional values were sent. XY_EDGE: x or y is -131072 or
 * 131071, which the CDD names "out of range". The object is then at least that far away. */
#define ITS_CPM_OF_ID       (1u << 0)
#define ITS_CPM_OF_Z        (1u << 1)
#define ITS_CPM_OF_HEADING  (1u << 2)   /* z_angle below 3600 */
#define ITS_CPM_OF_AGE      (1u << 3)
#define ITS_CPM_OF_LANE     (1u << 4)
#define ITS_CPM_OF_CONN     (1u << 5)
#define ITS_CPM_OF_LLP      (1u << 6)
#define ITS_CPM_OF_XY_EDGE  (1u << 7)

#define ITS_CPM_NO_QUALITY  0xFF     /* objectPerceptionQuality not sent */
#define ITS_CPM_NO_ANGLE    0xFFFF   /* its_cpm_compass of 3600 "not used" or 3601 "unavailable" */

/* One perceived object, raw CDD values unless said otherwise. Positions are East-North-Up
 * around the management container's reference position. Angles count counter-clockwise from
 * east in 0.1 degree (its_cpm_compass turns them into a course). */
typedef struct {
    int32_t  x_cm, y_cm, z_cm;   /* x east, y north */
    uint16_t id;                 /* objectId, with ITS_CPM_OF_ID */
    int16_t  dt_ms;              /* measurementDeltaTime, -2048..2047 */
    /* v_a..a_b keep the value as sent, even past the end of their type: a cartesian velocity part
     * up to 16384, an acceleration part up to 351 and a magnitude up to 255 (both types end at
     * 161), a polar direction 3602..4095. The map checks them in cpm_geo_motion() (cpm_geo.c). */
    /* POLAR: SpeedValue 0.01 m/s (16382 out of range, 16383 unavailable) and CartesianAngleValue
     * (3601 unavailable). CART: VelocityComponentValue x, y in 0.01 m/s. */
    int16_t  v_a, v_b;
    /* POLAR: AccelerationMagnitudeValue 0.1 m/s2 (161 unavailable) and CartesianAngleValue.
     * CART: AccelerationValue x, y in 0.1 m/s2. */
    int16_t  a_a, a_b;
    uint16_t z_angle;            /* angles.zAngle: the box orientation, not the course */
    uint16_t age_ms;             /* objectAge 0..2047; 1500 means "observed for more than 1.5 s" */
    uint16_t llp_dm;             /* along the lane; 32766 out of range, 32767 unavailable */
    uint16_t flags;              /* ITS_CPM_OF_* */
    uint8_t  vel_kind, acc_kind; /* ITS_CPM_KIN_* */
    uint8_t  len_dm, wid_dm, hgt_dm;  /* objectDimensionX/Y/Z 1..255 (255 out of range); 0 = none */
    uint8_t  quality;            /* 0..15, ITS_CPM_NO_QUALITY when not sent */
    /* The most likely class has the highest ConfidenceLevel, where "unavailable" ranks as 0 and
     * a tie keeps the first. conf is 1..100 percent, 0 for "unavailable" or a value past 101. */
    uint8_t  cls, sub, conf;
    uint8_t  n_classes;          /* 1..8, 0 without classification */
    uint8_t  group_size;         /* clusterCardinalitySize of a GROUP */
    uint8_t  group_profiles;     /* VruClusterProfiles, the standard's bit 0 is 0x8 (pedestrian) */
    uint8_t  n_sensor_ids;       /* sensorIdList entries, capped at 255 */
    uint8_t  lane, conn;         /* laneId, connectionId with their flags */
    uint8_t  cat;                /* ITS_CPM_CAT_* of the chosen class */
} its_cpm_obj_t;

/* What one CPM carries beyond the counts its_decode.c reads. `doubt` has bit (id - 1) for each
 * container 1..5 that runs past the frame or whose walk did not end exactly on its length.
 * Values read before the fault are kept, the rest is missing. */
typedef struct {
    bool     read;               /* its_decoded_t.cpm_read was set */
    uint8_t  dialect;            /* ITS_CPM_CDD_*, 0 without an object container */
    uint8_t  doubt;
    uint8_t  n_obj;              /* objects in obj[] */
    uint16_t n_walked;           /* objects read completely, the tally counts these */
    uint8_t  cat[ITS_CPM_CATS];  /* objects per category, capped at 255 */
    uint32_t sensor_types;       /* bit n for SensorType n, 0..31 */
    /* The farthest range of a sensor (circular radius, radial range, largest radialShapes range)
     * in 0.1 m, and its perceptionRegionConfidence 1..100 (0 = not sent or unavailable). */
    uint16_t reach_dm;
    uint8_t  reach_conf;
    uint8_t  n_trailers;         /* trailers of a sending vehicle */
    bool     has_map;            /* the RSU's MapReference */
    bool     map_intersection;   /* else a road segment */
    bool     map_has_region;
    /* The edition of `dialect` is proven: exactly one of the two object walks ended exactly.
     * The field fills the padding after map_has_region, so the struct stays at 160 B. */
    bool     dialect_sure;
    uint16_t map_region, map_id;
    /* messageRateRange: mantissa x 10^exponent messages per second, as its_decode.c read them. */
    bool     has_rate;
    uint8_t  rate_min_m, rate_max_m;
    int8_t   rate_min_e, rate_max_e;
    bool     has_ref_pos;        /* the origin of every object position */
    int32_t  ref_lat_e7, ref_lon_e7;
    uint32_t station_id;         /* ItsPduHeader.stationId */
    uint64_t ref_ms;             /* referenceTime, TimestampIts */
    its_cpm_obj_t obj[ITS_CPM_DETAIL_OBJS];   /* the first objects in message order */
} its_cpm_t;

/* The Shape CHOICE of the CDD, in its order. NEWER is an extension alternative, which the map
 * cannot draw. */
#define ITS_CPM_SHAPE_RECT     0
#define ITS_CPM_SHAPE_CIRCLE   1
#define ITS_CPM_SHAPE_POLYGON  2
#define ITS_CPM_SHAPE_ELLIPSE  3
#define ITS_CPM_SHAPE_RADIAL   4
#define ITS_CPM_SHAPE_RADIALS  5   /* radialShapes */
#define ITS_CPM_SHAPE_NEWER    6

/* src of its_cpm_area_t: a sensor's perceptionRegionShape or a PerceptionRegion. */
#define ITS_CPM_AREA_SENSOR  1
#define ITS_CPM_AREA_REGION  2

/* 16 is the root maximum of both the polygon and the radialShapes list. 8 regions are
 * MaxPerceptionRegions of TS 103 324 annex F. 8 sensor shapes are kept per message. */
#define ITS_CPM_AREA_PTS   16
#define ITS_CPM_AREA_SENS  8
#define ITS_CPM_AREA_REGS  8

/* flags of its_cpm_area_t. REF: shapeReferencePoint or centerPoint sent (radialShapes always
 * carry their offset). CUT: more points or entries came than pt[] or rs[] keep. */
#define ITS_CPM_AF_REF     (1u << 0)
#define ITS_CPM_AF_ORIENT  (1u << 1)   /* rectangle or ellipse orientation sent */
#define ITS_CPM_AF_CUT     (1u << 2)
#define ITS_CPM_AF_SHADOW  (1u << 3)   /* shadowingApplies */

/* One area as sent. The angles stay raw 12 bits: the edition decides later whether they are
 * Wgs84AngleValue (V3) or CartesianAngleValue (V4, and radialShapes in both). cpm_geo_place()
 * checks them. Heights, z values and vertical angles are stepped over: the map is flat. */
typedef struct {
    uint8_t  src, kind;          /* ITS_CPM_AREA_*, ITS_CPM_SHAPE_* */
    uint8_t  sensor_id, sensor_type;   /* only for a sensor, 0 for a region */
    uint8_t  conf;               /* perceptionRegionConfidence 1..100, 0 = none or unavailable */
    uint8_t  flags;              /* ITS_CPM_AF_* */
    uint8_t  n;                  /* points in pt[] or entries in rs[] */
    uint8_t  ref_point_id;       /* radialShapes */
    int16_t  ref_x_cm, ref_y_cm; /* shapeReferencePoint, centerPoint or the radialShapes offset */
    uint16_t a_dm, b_dm;         /* radius, range, semiLength, semiMajor; semiBreadth, semiMinor */
    uint16_t ang_a, ang_b;       /* orientation or radial start; radial end */
    union {
        struct { int16_t x_cm, y_cm; } pt[ITS_CPM_AREA_PTS];   /* polygon, from the reference */
        struct { uint16_t range_dm, start, end; } rs[ITS_CPM_AREA_PTS];   /* radialShapes */
    } u;
} its_cpm_area_t;                /* 116 B (riscv32-esp-elf-gcc 15.2 and clang) */

/* The areas of one CPM in area[0 .. n_sens + n_regs - 1], the sensors first, then the regions.
 * *_shapes count every complete entry with a shape, kept or not. Entries past the caps are read
 * into `spare`, so no area lies on the caller's stack. */
typedef struct {
    uint8_t  n_sens, n_regs;
    uint16_t sens_shapes, reg_shapes;
    its_cpm_area_t area[ITS_CPM_AREA_SENS + ITS_CPM_AREA_REGS];
    its_cpm_area_t spare;
} its_cpm_areas_t;               /* 6 + 17 x 116 = 1978 B */

/* Reads the containers its_decode_frame recorded in d, from the same `frame` of `len` bytes.
 * `out` is always filled completely, starting from zero. `all` gets up to all_cap objects and
 * *all_n their count (both may be NULL). Returns false when d holds no read CPM. No float. */
bool its_cpm_decode(const uint8_t *frame, size_t len, const its_decoded_t *d, its_cpm_t *out,
                    its_cpm_obj_t *all, size_t all_cap, uint16_t *all_n);

/* The sensor shapes (container 3) and perception regions (container 4) of the CPM in d, from
 * the same frame. `out` is always filled from zero. Returns false when d holds no read CPM.
 * No float. */
bool its_cpm_areas(const uint8_t *frame, size_t len, const its_decoded_t *d, its_cpm_areas_t *out);

/* A counter-clockwise angle from east (CartesianAngleValue) as a course clockwise from north,
 * both in 0.1 degree: (900 - a) mod 3600. ITS_CPM_NO_ANGLE for 3600 and above. */
uint16_t its_cpm_compass(uint16_t ccw_from_east_ddeg);

/* An object's east/north offset in cm from the reference point as WGS84 1e-7 degree. Over the
 * +-1310.72 m a CPM reaches it is at most 0.34 m off at 48 degrees (0.83 m at 70). A sphere
 * of 111319.49 m per degree would be 3.2 m off there. Uses double, so call it in the page
 * handler, not in the receive path. */
void its_cpm_to_wgs84(int32_t ref_lat_e7, int32_t ref_lon_e7, int32_t x_cm, int32_t y_cm,
                      int32_t *lat_e7, int32_t *lon_e7);

#ifdef __cplusplus
}
#endif
