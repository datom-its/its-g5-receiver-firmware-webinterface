#pragma once

/* The geometry of the CPM map layer: an area as sent plus its sender's pose become a shape in
 * WGS84 and compass bearings, and an object's raw motion values become checked ones. The one
 * gate between the store and /cpm.json for values past their types (its_cpm.c keeps them raw).
 * Uses double: call it from the page handler, not from the receive path. */

#include <stdbool.h>
#include <stdint.h>

#include "its_cpm.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CPM_GEO_NONE  0xFFFFu    /* a value not sent, or one the shape has none of */

/* What an area counts from. body: the sender is a vehicle, so its sensor shapes lie in its body
 * frame (x forward, y left, TS 103 324 7.1.6) turned by the heading. Regions stay East-North-Up.
 * The caller places no sensor shape of a sender whose kind is unknown. */
typedef struct {
    int32_t  ref_lat_e7, ref_lon_e7;   /* the reference position the shape counts from */
    bool     body;
    uint16_t heading_ddeg;       /* orientationAngle, compass 0..3599; CPM_GEO_NONE when not sent */
    uint8_t  edition;            /* ITS_CPM_CDD_V4, or anything else for the V3 reading */
    bool     edition_sure;       /* proven by an object container (its_cpm_t.dialect_sure) */
} cpm_geo_frame_t;

/* flags of cpm_geo_area_t, the fl column of an area in /cpm.json. UNSURE: an angle whose meaning
 * rests on an unproven edition, or a V3 WGS84 angle read in a vehicle's body frame. */
#define CPM_GEO_AF_UNSURE  (1u << 0)
#define CPM_GEO_AF_TURNS   (1u << 1)   /* in a vehicle's body frame: moves and turns with it */
#define CPM_GEO_AF_PART    (1u << 2)   /* ITS_CPM_AF_CUT: only the first points or entries */
#define CPM_GEO_AF_SHADOW  (1u << 3)   /* shadowingApplies */

/* One placed area. Angles are compass bearings in 0.1 degree, sizes in 0.1 m, CPM_GEO_NONE
 * where the kind has none. A sector runs clockwise from `from` to `to`; equal means a full circle. */
typedef struct {
    int32_t  lat_e7, lon_e7;     /* anchor: reference point, centre or sensor position */
    uint8_t  kind, flags, n, src;     /* ITS_CPM_SHAPE_*, CPM_GEO_AF_*, entries in u, ITS_CPM_AREA_* */
    uint16_t a_dm, b_dm;         /* radius, range, semi-length or semi-major; semi-breadth or minor */
    uint16_t rot_ddeg;           /* rectangle and ellipse: the bearing of the a axis */
    uint16_t from_ddeg, to_ddeg; /* single sector */
    union {
        struct { int32_t e_cm, n_cm; } pt[ITS_CPM_AREA_PTS];   /* polygon, east/north of the anchor */
        struct { uint16_t range_dm, from, to; } rs[ITS_CPM_AREA_PTS];   /* radialShapes */
    } u;
} cpm_geo_area_t;                /* 152 B */

/* Places `a` in frame `f` into `out`, which is always filled from zero. False when it cannot be
 * placed: an extension kind, a needed angle of 3600 or more, a body frame without heading, or
 * radialShapes on a trailer (refPointId not 0). */
bool cpm_geo_place(const its_cpm_area_t *a, const cpm_geo_frame_t *f, cpm_geo_area_t *out);

/* fl of cpm_geo_motion_t, the fl column of an object in /cpm.json: the value is a lower bound. */
#define CPM_GEO_MF_SPEED_MIN  (1u << 0)   /* SpeedValue 16382, or a velocity part on an end */
#define CPM_GEO_MF_DIST_MIN   (1u << 1)   /* ITS_CPM_OF_XY_EDGE */
#define CPM_GEO_MF_AGE_MIN    (1u << 2)   /* objectAge 1500 and above: observed at least 1.5 s */
#define CPM_GEO_MF_SIZE_MIN   (1u << 3)   /* a dimension of 255 */
#define CPM_GEO_MF_LLP_MIN    (1u << 4)   /* lane position 32766 */

/* An object's motion and sizes, checked against their types. A course needs a speed. The
 * acceleration along it needs a course and at least 50 cm/s. */
typedef struct {
    uint16_t speed_cms;          /* CPM_GEO_NONE without a speed */
    uint16_t course_ddeg;        /* compass bearing of the velocity, CPM_GEO_NONE without one */
    uint16_t orient_ddeg;        /* compass bearing of the box (zAngle), else CPM_GEO_NONE */
    uint16_t age_ms;             /* objectAge, 1500 at most; CPM_GEO_NONE when not sent */
    uint16_t llp_dm;             /* along the lane, CPM_GEO_NONE when not sent or unavailable */
    int16_t  accel_dms2;         /* 0.1 m/s2 along the course, with has_accel */
    bool     has_accel;
    uint8_t  len_dm, wid_dm, hgt_dm;   /* 1..255, 0 when not sent or unavailable */
    uint8_t  fl;                 /* CPM_GEO_MF_* */
} cpm_geo_motion_t;

void cpm_geo_motion(const its_cpm_obj_t *o, cpm_geo_motion_t *m);

#ifdef __cplusplus
}
#endif
