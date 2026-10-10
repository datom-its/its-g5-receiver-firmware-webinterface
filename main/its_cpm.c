#include "its_cpm.h"

#include <math.h>
#include <string.h>

#include "its_bits.h"

/* Layout from the CPM ASN.1 of TS 103 324 V2.1.1 with its CDD (major version 3) and the newer
 * CDD Wireshark uses (V4), checked against asn1tools in both editions. */

/* Presence bits of PerceivedObject: 14 optional components, the first one highest. */
#define PO_ID        (1u << 13)
#define PO_VEL       (1u << 12)
#define PO_ACC       (1u << 11)
#define PO_ANGLES    (1u << 10)
#define PO_YAWRATE   (1u << 9)
#define PO_MATRICES  (1u << 8)
#define PO_DIM_Z     (1u << 7)
#define PO_DIM_Y     (1u << 6)
#define PO_DIM_X     (1u << 5)
#define PO_AGE       (1u << 4)
#define PO_QUALITY   (1u << 3)
#define PO_SENSORS   (1u << 2)
#define PO_CLASS     (1u << 1)
#define PO_MAPPOS    (1u << 0)
#define PO_BITS      14

/* Smallest encoding of one list element in bits. A count is believed only when that many of
 * the smallest element still fit the bits left, so a wrong count cannot claim what never came. */
#define MIN_OBJECT   88   /* ext, 14 presence bits, deltaTime 12, position without z: 1 + 30 + 30 */
#define MIN_SENSOR   17   /* ext, 2 presence bits, sensorId 8, sensorType 5, shadowingApplies 1 */
#define MIN_REGION   42   /* ext, 3 presence bits, 12, 7, a bare circular Shape 18, 1 */
#define MIN_TRAILER  39   /* ext, 3 presence bits, refPointId 8, hitchPointOffset 8, angle 19 */
#define MIN_POINT    33   /* CartesianPosition3d without z */
#define MIN_RADIAL   38   /* RadialShapeDetails: 2 presence bits, range and two angles of 12 */
#define MIN_CLASS    14   /* ext, choice index 2, vehicleSubClass 4, ConfidenceLevel 7 */
#define MIN_MATRIX   31   /* 1 + 13 component bits, column count 4, one column of one cell 13 */
#define MIN_COLUMN   13   /* ext, count 4, one cell */
#define MIN_ID1      8
#define MIN_ID2      16

#define COORD_BITS      18       /* CartesianCoordinateLarge -131072..131071 */
#define COORD_LOW       (-131072)
#define COORD_HIGH      131071   /* both ends are named "out of range" */
#define CART_BITS       16       /* CartesianCoordinate -32768..32767, the points of a Shape */
#define CART_LOW        (-32768)
#define SMALL_BITS      12       /* CartesianCoordinateSmall -3094..1001, the radialShapes offset */
#define SMALL_LOW       (-3094)
#define CONF_UNAVAIL    101      /* ConfidenceLevel "unavailable" */
#define DIM_UNAVAIL     256      /* ObjectDimensionValue "unavailable" */
#define ANGLE_NOT_USED  3600     /* CartesianAngleValue: 3600 "not used", 3601 "unavailable" */

/* VRU subprofiles in the V3 CDD are ENUMERATED: an index of 3/4/3/3 bits over 5/10/6/5 names
 * whose last one is 'max' = 15. V4 sends the value itself in 4 bits. */
static const uint8_t V3_VRU_BITS[4]  = { 3, 4, 3, 3 };
static const uint8_t V3_VRU_NAMES[4] = { 5, 10, 6, 5 };
#define VRU_MAX_VALUE 15

static bool read_flag(its_bitr_t *r)
{
    return its_bits_read(r, 1) != 0;
}

static uint8_t cap8(uint32_t n)
{
    return n > UINT8_MAX ? UINT8_MAX : (uint8_t)n;
}

/* Sets err when n elements of min_bits each cannot fit the bits left, which stops the walk. */
static bool count_fits(its_bitr_t *r, uint32_t n, uint32_t min_bits)
{
    if (r->err)
        return false;
    if ((uint64_t)n * min_bits > r->nbits - r->pos)
    {
        r->err = true;
        return false;
    }
    return true;
}

/* The count of SEQUENCE SIZE(lb..ub, ...) OF: an extension bit, then the offset from lb in the
 * root bits or an unconstrained count. 0 when it was not believed (err is set then). */
static uint32_t read_count(its_bitr_t *r, uint32_t lb, unsigned root_bits, uint32_t min_bits)
{
    uint32_t n = read_flag(r) ? (uint32_t)its_bits_uper_length(r)
                              : lb + its_bits_read(r, root_bits);
    return count_fits(r, n, min_bits) ? n : 0;
}

static void skip_open_type(its_bitr_t *r)
{
    size_t n = its_bits_uper_length(r);
    if (!r->err)
        its_bits_skip(r, n * 8);
}

/* An extension alternative of a CHOICE: a normally small index, then the value as an open type.
 * A long index form above 4 octets is rejected, as no ASN.1 here has that many alternatives. */
static void skip_choice_ext(its_bitr_t *r)
{
    if (read_flag(r))
    {
        size_t n = its_bits_uper_length(r);
        if (n == 0 || n > 4)
            r->err = true;
        else
            its_bits_skip(r, n * 8);
    }
    else
        its_bits_skip(r, 6);
    skip_open_type(r);
}

/* Extension additions of a SEQUENCE whose extension bit was set: a normally small bitmap
 * length, the bitmap, then one open type for each present addition. */
static void skip_additions(its_bitr_t *r)
{
    size_t n = read_flag(r) ? its_bits_uper_length(r) : its_bits_read(r, 6) + 1;
    size_t present = 0;
    for (size_t i = 0; i < n && !r->err; i++)
        present += its_bits_read(r, 1);
    for (size_t i = 0; i < present && !r->err; i++)
        skip_open_type(r);
}

/* A container ends exactly when at most its zero padding is left. A walk with the wrong layout
 * goes astray at the first misread field and ends exactly only by chance (rates at
 * its_cpm_decode). */
static bool ends_exactly(its_bitr_t c)
{
    if (c.err || c.nbits - c.pos >= 8)
        return false;
    return its_bits_read(&c, (unsigned)(c.nbits - c.pos)) == 0;
}

/* ConfidenceLevel 1..101 in 7 bits: percent 1..100, and 0 for 101 "unavailable" or a value the
 * type does not allow, which also ranks it lowest. */
static uint8_t read_confidence(its_bitr_t *r)
{
    uint32_t v = its_bits_read(r, 7) + 1;
    return v < CONF_UNAVAIL ? (uint8_t)v : 0;
}

/* CartesianPosition3d: x and y in 0.01 m into *x and *y when x is not NULL, z stepped over. */
static void read_cart3d(its_bitr_t *r, int16_t *x, int16_t *y)
{
    bool z = read_flag(r);
    int32_t vx = (int32_t)its_bits_read(r, CART_BITS) + CART_LOW;
    int32_t vy = (int32_t)its_bits_read(r, CART_BITS) + CART_LOW;
    if (z)
        its_bits_skip(r, CART_BITS);
    if (x)
    {
        *x = (int16_t)vx;
        *y = (int16_t)vy;
    }
}

/* Reads a present shapeReferencePoint or centerPoint and keeps it in *a when a is not NULL. */
static void read_ref(its_bitr_t *r, its_cpm_area_t *a)
{
    if (!a)
    {
        read_cart3d(r, NULL, NULL);
        return;
    }
    a->flags |= ITS_CPM_AF_REF;
    read_cart3d(r, &a->ref_x_cm, &a->ref_y_cm);
}

/* How many list entries pt[] or rs[] hold. More than 16 can only come behind the extension,
 * and such a list is flagged as cut. */
static void keep_count(its_cpm_area_t *a, uint32_t n)
{
    a->n = (uint8_t)(n < ITS_CPM_AREA_PTS ? n : ITS_CPM_AREA_PTS);
    if (n > ITS_CPM_AREA_PTS)
        a->flags |= ITS_CPM_AF_CUT;
}

/* RadialShapes: refPointId, the offset x, y, [z], and the list. Returns the largest range. */
static uint32_t read_radials(its_bitr_t *r, its_cpm_area_t *a)
{
    uint32_t o = its_bits_read(r, 1), reach = 0;
    uint32_t ref_id = its_bits_read(r, 8);
    int32_t x = (int32_t)its_bits_read(r, SMALL_BITS) + SMALL_LOW;
    int32_t y = (int32_t)its_bits_read(r, SMALL_BITS) + SMALL_LOW;
    if (o)
        its_bits_skip(r, SMALL_BITS);
    if (a)
    {
        a->flags |= ITS_CPM_AF_REF;      /* the offset is not optional here */
        a->ref_point_id = (uint8_t)ref_id;
        a->ref_x_cm = (int16_t)x;
        a->ref_y_cm = (int16_t)y;
    }
    uint32_t n = read_count(r, 1, 4, MIN_RADIAL);
    for (uint32_t i = 0; i < n && !r->err; i++)
    {
        uint32_t oo = its_bits_read(r, 2);
        uint32_t range = its_bits_read(r, 12);
        uint32_t start = its_bits_read(r, 12);
        uint32_t end = its_bits_read(r, 12);
        if (oo & 2)
            its_bits_skip(r, 12);
        if (oo & 1)
            its_bits_skip(r, 12);
        if (range > reach)
            reach = range;
        if (a && i < ITS_CPM_AREA_PTS)
        {
            a->u.rs[i].range_dm = (uint16_t)range;
            a->u.rs[i].start = (uint16_t)start;
            a->u.rs[i].end = (uint16_t)end;
        }
    }
    if (a)
        keep_count(a, n);
    return reach;
}

/* Shape. Returns a sensor's reach in 0.1 m: the radius of a circle, the range of a radial shape
 * or the largest range of radialShapes, and 0 for the shapes without one. With `a` it also keeps
 * the shape for its_cpm_areas. its_cpm_decode passes NULL, and the bits are walked the same
 * either way. */
static uint32_t read_shape(its_bitr_t *r, its_cpm_area_t *a)
{
    if (read_flag(r))
    {
        skip_choice_ext(r);
        if (a)
            a->kind = ITS_CPM_SHAPE_NEWER;
        return 0;
    }
    uint32_t reach = 0, o, n, len, wid, ang_a, ang_b;
    uint32_t kind = its_bits_read(r, 3);
    if (a)
        a->kind = (uint8_t)kind;
    switch (kind)
    {
    case ITS_CPM_SHAPE_RECT:             /* centerPoint, two half sizes, orientation, height */
    case ITS_CPM_SHAPE_ELLIPSE:          /* the same fields for the two semi-axes */
        o = its_bits_read(r, 3);
        if (o & 4)
            read_ref(r, a);
        len = its_bits_read(r, 12);
        wid = its_bits_read(r, 12);
        ang_a = (o & 2) ? its_bits_read(r, 12) : 0;   /* orientation */
        if (o & 1)
            its_bits_skip(r, 12);
        if (a)
        {
            a->a_dm = (uint16_t)len;
            a->b_dm = (uint16_t)wid;
            a->ang_a = (uint16_t)ang_a;
            if (o & 2)
                a->flags |= ITS_CPM_AF_ORIENT;
        }
        break;
    case ITS_CPM_SHAPE_CIRCLE:           /* shapeReferencePoint, radius, height */
        o = its_bits_read(r, 2);
        if (o & 2)
            read_ref(r, a);
        reach = its_bits_read(r, 12);
        if (o & 1)
            its_bits_skip(r, 12);
        if (a)
            a->a_dm = (uint16_t)reach;
        break;
    case ITS_CPM_SHAPE_POLYGON:          /* shapeReferencePoint, points, height */
        o = its_bits_read(r, 2);
        if (o & 2)
            read_ref(r, a);
        /* SIZE(3..16,...) on a SIZE(1..16,...) type: asn1tools and tshark both count from 1. */
        n = read_count(r, 1, 4, MIN_POINT);
        for (uint32_t i = 0; i < n && !r->err; i++)
        {
            bool keep = a && i < ITS_CPM_AREA_PTS;
            read_cart3d(r, keep ? &a->u.pt[i].x_cm : NULL, keep ? &a->u.pt[i].y_cm : NULL);
        }
        if (o & 1)
            its_bits_skip(r, 12);
        if (a)
            keep_count(a, n);
        break;
    case ITS_CPM_SHAPE_RADIAL:           /* shapeReferencePoint, range, 4 opening angles */
        o = its_bits_read(r, 3);
        if (o & 4)
            read_ref(r, a);
        reach = its_bits_read(r, 12);
        ang_a = its_bits_read(r, 12);    /* horizontal opening angles, start and end */
        ang_b = its_bits_read(r, 12);
        if (o & 2)
            its_bits_skip(r, 12);
        if (o & 1)
            its_bits_skip(r, 12);
        if (a)
        {
            a->a_dm = (uint16_t)reach;
            a->ang_a = (uint16_t)ang_a;
            a->ang_b = (uint16_t)ang_b;
        }
        break;
    case ITS_CPM_SHAPE_RADIALS:          /* refPointId, offset, list */
        reach = read_radials(r, a);
        break;
    default:                             /* 6 and 7 name no alternative */
        r->err = true;
        break;
    }
    return reach;
}

/* MapReference: roadsegment or intersection, each an optional region and an id. */
static void read_map_ref(its_bitr_t *r, bool *intersection, bool *has_region, uint16_t *region,
                         uint16_t *id)
{
    *intersection = read_flag(r);
    *has_region = read_flag(r);
    *region = *has_region ? (uint16_t)its_bits_read(r, 16) : 0;
    *id = (uint16_t)its_bits_read(r, 16);
}

/* VruSubProfileBicyclist values, the same in both CDD editions. */
#define BIKE_WHEELCHAIR  2
#define BIKE_HORSE       3
#define BIKE_SKATES      4

/* Which category a class counts under. Vehicle values the constraint leaves out (1..4, 12, 13;
 * PER still carries 0..14) keep the meaning TrafficParticipantType gives them. */
static uint8_t category(uint8_t cls, uint8_t sub)
{
    switch (cls)
    {
    case ITS_CPM_CLS_VEHICLE:
        switch (sub)
        {
        case 1:  return ITS_CPM_CAT_PED;
        case 2: case 3: case 4: case 12: return ITS_CPM_CAT_TWOWHEEL;
        case 5:  return ITS_CPM_CAT_CAR;
        case 6:  return ITS_CPM_CAT_BUS;
        case 7: case 8: return ITS_CPM_CAT_TRUCK;
        case 11: return ITS_CPM_CAT_TRAM;
        case 13: return ITS_CPM_CAT_ANIMAL;
        default: return ITS_CPM_CAT_OTHER;   /* unknown, trailer, special, agricultural */
        }
    case ITS_CPM_CLS_PED:    return ITS_CPM_CAT_PED;
    case ITS_CPM_CLS_BIKE:
        /* Wheelchair and roller skates count as pedestrian, horse and rider as other. */
        if (sub == BIKE_WHEELCHAIR || sub == BIKE_SKATES)
            return ITS_CPM_CAT_PED;
        return sub == BIKE_HORSE ? ITS_CPM_CAT_OTHER : ITS_CPM_CAT_TWOWHEEL;
    case ITS_CPM_CLS_MOTO:   return ITS_CPM_CAT_TWOWHEEL;
    case ITS_CPM_CLS_ANIMAL: return ITS_CPM_CAT_ANIMAL;
    case ITS_CPM_CLS_GROUP:  return ITS_CPM_CAT_GROUP;
    case ITS_CPM_CLS_NONE:   return ITS_CPM_CAT_NONE;
    default:                 return ITS_CPM_CAT_OTHER;   /* OTHER and both NEWER */
    }
}

/* One ObjectClass. A V3 VRU index past the named values is an error: that is what tells the
 * two dialects apart. */
static void read_class(its_bitr_t *r, bool v4, uint8_t *cls, uint8_t *sub, uint8_t *gsize,
                       uint8_t *gprof)
{
    *sub = 0;
    *gsize = 0;
    *gprof = 0;
    if (read_flag(r))
    {
        skip_choice_ext(r);
        *cls = ITS_CPM_CLS_NEWER;
        return;
    }
    switch (its_bits_read(r, 2))
    {
    case 0:
        /* TrafficParticipantType (unknown|passengerCar..tram|agricultural): PER sees 0..14. */
        *cls = ITS_CPM_CLS_VEHICLE;
        *sub = (uint8_t)its_bits_read(r, 4);
        break;
    case 1:
    {
        if (read_flag(r))
        {
            skip_choice_ext(r);
            *cls = ITS_CPM_CLS_VRU_NEWER;
            break;
        }
        uint32_t k = its_bits_read(r, 2);   /* pedestrian, bicyclist, motorcyclist, animal */
        *cls = (uint8_t)(ITS_CPM_CLS_PED + k);
        if (v4)
            *sub = (uint8_t)its_bits_read(r, 4);
        else
        {
            uint32_t idx = its_bits_read(r, V3_VRU_BITS[k]);
            if (idx >= V3_VRU_NAMES[k])
                r->err = true;
            *sub = (uint8_t)(idx == V3_VRU_NAMES[k] - 1u ? VRU_MAX_VALUE : idx);
        }
        break;
    }
    case 2:
    {
        /* VruClusterInformation: clusterId, clusterBoundingBoxShape, clusterProfiles. */
        bool ext = read_flag(r);
        uint32_t o = its_bits_read(r, 3);
        if (o & 4)
            its_bits_skip(r, 8);
        if (o & 2)
            (void)read_shape(r, NULL);
        *gsize = (uint8_t)its_bits_read(r, 8);
        if (o & 1)
            *gprof = (uint8_t)its_bits_read(r, 4);
        if (ext)
            skip_additions(r);
        *cls = ITS_CPM_CLS_GROUP;
        break;
    }
    default:
        *cls = ITS_CPM_CLS_OTHER;
        *sub = (uint8_t)its_bits_read(r, 8);
        break;
    }
}

/* One CartesianCoordinateWithConfidence: 18 bits of value, 12 of confidence. */
static int32_t read_coord(its_bitr_t *r, uint16_t *flags)
{
    int32_t v = (int32_t)its_bits_read(r, COORD_BITS) + COORD_LOW;
    its_bits_skip(r, 12);
    if (v == COORD_LOW || v == COORD_HIGH)
        *flags |= ITS_CPM_OF_XY_EDGE;
    return v;
}

/* Magnitude and direction, or x and y, of a velocity or acceleration CHOICE. `mag` and `comp`
 * are the widths of the polar magnitude and of a cartesian part, `low` its lower bound. */
static uint8_t read_kinematic(its_bitr_t *r, unsigned mag, unsigned comp, int32_t low,
                              int16_t *a, int16_t *b)
{
    bool cart = read_flag(r);
    bool z = read_flag(r);
    if (!cart)
    {
        *a = (int16_t)its_bits_read(r, mag);
        its_bits_skip(r, 7);
        *b = (int16_t)its_bits_read(r, 12);     /* CartesianAngleValue */
        its_bits_skip(r, 7);
    }
    else
    {
        *a = (int16_t)((int32_t)its_bits_read(r, comp) + low);
        its_bits_skip(r, 7);
        *b = (int16_t)((int32_t)its_bits_read(r, comp) + low);
        its_bits_skip(r, 7);
    }
    if (z)
        its_bits_skip(r, comp + 7);
    return cart ? ITS_CPM_KIN_CART : ITS_CPM_KIN_POLAR;
}

/* lowerTriangularCorrelationMatrices: only stepped over. The list of columns is SIZE(1..13) in
 * V3 and SIZE(1..13,...) in V4, the one wire difference outside the VRU classes. */
static void skip_matrices(its_bitr_t *r, bool v4)
{
    uint32_t nm = its_bits_read(r, 2) + 1;
    if (!count_fits(r, nm, MIN_MATRIX))
        return;
    for (uint32_t i = 0; i < nm && !r->err; i++)
    {
        if (read_flag(r))                /* MatrixIncludedComponents past 13 bits: length in bits */
            its_bits_skip(r, its_bits_uper_length(r));
        else
            its_bits_skip(r, 13);
        uint32_t ncol = v4 ? read_count(r, 1, 4, MIN_COLUMN) : its_bits_read(r, 4) + 1;
        if (!count_fits(r, ncol, MIN_COLUMN))
            return;
        for (uint32_t j = 0; j < ncol && !r->err; j++)
        {
            uint32_t cells = read_count(r, 1, 4, 8);
            its_bits_skip(r, (size_t)cells * 8);
        }
    }
}

/* ObjectDimension: value 1..256 in 8 bits, confidence 5. 0 stands for 256 "unavailable". */
static uint8_t read_dimension(its_bitr_t *r)
{
    uint32_t v = its_bits_read(r, 8) + 1;
    its_bits_skip(r, 5);
    return v < DIM_UNAVAIL ? (uint8_t)v : 0;
}

/* One PerceivedObject into *o. The caller keeps it only when r->err is still clear. */
static void read_object(its_bitr_t *r, bool v4, its_cpm_obj_t *o)
{
    memset(o, 0, sizeof *o);
    o->quality = ITS_CPM_NO_QUALITY;
    bool ext = read_flag(r);
    uint32_t opt = its_bits_read(r, PO_BITS);
    if (opt & PO_ID)
    {
        o->id = (uint16_t)its_bits_read(r, 16);
        o->flags |= ITS_CPM_OF_ID;
    }
    o->dt_ms = (int16_t)((int32_t)its_bits_read(r, 12) - 2048);
    bool z = read_flag(r);
    o->x_cm = read_coord(r, &o->flags);
    o->y_cm = read_coord(r, &o->flags);
    if (z)
    {
        uint16_t zflags = 0;             /* an edge of z is no edge of the ground position */
        o->z_cm = read_coord(r, &zflags);
        o->flags |= ITS_CPM_OF_Z;
    }
    if (opt & PO_VEL)                    /* SpeedValue 14 bits, VelocityComponentValue 15 bits */
        o->vel_kind = read_kinematic(r, 14, 15, -16383, &o->v_a, &o->v_b);
    if (opt & PO_ACC)                    /* magnitude 8 bits, AccelerationValue 9 from -160 */
        o->acc_kind = read_kinematic(r, 8, 9, -160, &o->a_a, &o->a_b);
    if (opt & PO_ANGLES)
    {
        uint32_t yx = its_bits_read(r, 2);
        o->z_angle = (uint16_t)its_bits_read(r, 12);
        its_bits_skip(r, 7);
        if (o->z_angle < ANGLE_NOT_USED)
            o->flags |= ITS_CPM_OF_HEADING;
        if (yx & 2)
            its_bits_skip(r, 19);
        if (yx & 1)
            its_bits_skip(r, 19);
    }
    if (opt & PO_YAWRATE)
        its_bits_skip(r, 9 + 3);
    if (opt & PO_MATRICES)
        skip_matrices(r, v4);
    if (opt & PO_DIM_Z)
        o->hgt_dm = read_dimension(r);
    if (opt & PO_DIM_Y)
        o->wid_dm = read_dimension(r);
    if (opt & PO_DIM_X)
        o->len_dm = read_dimension(r);
    if (opt & PO_AGE)
    {
        o->age_ms = (uint16_t)its_bits_read(r, 11);
        o->flags |= ITS_CPM_OF_AGE;
    }
    if (opt & PO_QUALITY)
        o->quality = (uint8_t)its_bits_read(r, 4);
    if (opt & PO_SENSORS)
    {
        uint32_t n = read_count(r, 1, 7, MIN_ID1);
        its_bits_skip(r, (size_t)n * 8);
        o->n_sensor_ids = cap8(n);
    }
    o->cat = ITS_CPM_CAT_NONE;
    if (opt & PO_CLASS)
    {
        uint32_t n = its_bits_read(r, 3) + 1;    /* SIZE(1..8), no extension */
        int best = -1;
        if (!count_fits(r, n, MIN_CLASS))
            return;
        for (uint32_t i = 0; i < n; i++)
        {
            uint8_t cls, sub, gsize, gprof;
            read_class(r, v4, &cls, &sub, &gsize, &gprof);
            uint8_t conf = read_confidence(r);
            if (r->err)
                break;
            if ((int)conf > best)
            {
                best = conf;
                o->cls = cls;
                o->sub = sub;
                o->conf = conf;
                o->group_size = gsize;
                o->group_profiles = gprof;
            }
        }
        o->n_classes = (uint8_t)n;
        o->cat = category(o->cls, o->sub);
    }
    if (opt & PO_MAPPOS)
    {
        bool mext = read_flag(r);
        uint32_t mo = its_bits_read(r, 4);
        if (mo & 8)
        {
            its_bits_skip(r, 1);         /* MapReference: roadsegment or intersection */
            if (read_flag(r))
                its_bits_skip(r, 16);    /* region */
            its_bits_skip(r, 16);        /* id */
        }
        if (mo & 4)
        {
            o->lane = (uint8_t)its_bits_read(r, 8);
            o->flags |= ITS_CPM_OF_LANE;
        }
        if (mo & 2)
        {
            o->conn = (uint8_t)its_bits_read(r, 8);
            o->flags |= ITS_CPM_OF_CONN;
        }
        if (mo & 1)
        {
            o->llp_dm = (uint16_t)its_bits_read(r, 15);
            its_bits_skip(r, 10);
            o->flags |= ITS_CPM_OF_LLP;
        }
        if (mext)
            skip_additions(r);
    }
    if (ext)
        skip_additions(r);
}

/* The object tallies and lists of `out`, cleared before a walk in the other dialect commits. */
static void clear_objects(its_cpm_t *out, uint16_t *all_n)
{
    out->n_walked = 0;
    out->n_obj = 0;
    memset(out->cat, 0, sizeof out->cat);
    memset(out->obj, 0, sizeof out->obj);
    if (all_n)
        *all_n = 0;
}

/* PerceivedObjectContainer in one dialect. With `out` NULL it only tells whether the walk ends
 * exactly. Otherwise every complete object is counted and kept, and a broken one ends the walk. */
static bool walk_objects(its_bitr_t c, bool v4, its_cpm_t *out, its_cpm_obj_t *all,
                         size_t all_cap, uint16_t *all_n)
{
    bool ext = read_flag(&c);
    its_bits_skip(&c, 8);                /* numberOfPerceivedObjects, which its_decode.c keeps */
    uint32_t n = read_count(&c, 0, 8, MIN_OBJECT);   /* SIZE(0..255, ...) */
    for (uint32_t i = 0; i < n && !c.err; i++)
    {
        its_cpm_obj_t o;
        read_object(&c, v4, &o);
        if (c.err)
            break;
        if (!out)
            continue;
        if (out->n_walked < UINT16_MAX)
            out->n_walked++;
        if (out->cat[o.cat] < UINT8_MAX)
            out->cat[o.cat]++;
        if (out->n_obj < ITS_CPM_DETAIL_OBJS)
            out->obj[out->n_obj++] = o;
        if (all && *all_n < all_cap)
            all[(*all_n)++] = o;
    }
    if (ext && !c.err)
        skip_additions(&c);
    return ends_exactly(c);
}

/* Returns the cleared slot for the next sensor or region: the next free one, or `spare` once
 * the cap is reached. With `spare` an entry is walked the same way whether it is kept or not. */
static its_cpm_area_t *area_slot(its_cpm_areas_t *s, bool full)
{
    its_cpm_area_t *a = full ? &s->spare : &s->area[s->n_sens + s->n_regs];
    memset(a, 0, sizeof *a);
    return a;
}

/* A complete entry with a shape: counted always, kept when it is not in `spare`. */
static void keep_area(its_cpm_areas_t *s, const its_cpm_area_t *a, uint8_t *kept, uint16_t *shapes)
{
    if (*shapes < UINT16_MAX)
        (*shapes)++;
    if (a != &s->spare)
        (*kept)++;
}

/* SensorInformationContainer: the kinds of sensor and the farthest reach, per complete entry.
 * its_cpm_areas passes `areas` and no `out`. Then every complete entry with a shape is counted,
 * and the first ITS_CPM_AREA_SENS of them are kept. */
static bool walk_sensors(its_bitr_t c, its_cpm_t *out, its_cpm_areas_t *areas)
{
    uint32_t n = read_count(&c, 1, 7, MIN_SENSOR);   /* SIZE(1..128, ...) */
    for (uint32_t i = 0; i < n && !c.err; i++)
    {
        its_cpm_area_t *a = areas ? area_slot(areas, areas->n_sens >= ITS_CPM_AREA_SENS) : NULL;
        bool ext = read_flag(&c);
        uint32_t o = its_bits_read(&c, 2);           /* shape, confidence */
        uint32_t id = its_bits_read(&c, 8);          /* sensorId */
        uint32_t type = its_bits_read(&c, 5);
        uint32_t reach = (o & 2) ? read_shape(&c, a) : 0;
        uint8_t conf = (o & 1) ? read_confidence(&c) : 0;
        bool shadow = read_flag(&c);                 /* shadowingApplies */
        if (ext)
            skip_additions(&c);
        if (c.err)
            break;
        if (out)
        {
            out->sensor_types |= (uint32_t)1u << type;
            if (reach > out->reach_dm)
            {
                out->reach_dm = (uint16_t)reach;
                out->reach_conf = conf;
            }
        }
        if (a && (o & 2))                     /* shapeless types 0, 12, 13 (7.1.6): no area */
        {
            a->src = ITS_CPM_AREA_SENSOR;
            a->sensor_id = (uint8_t)id;
            a->sensor_type = (uint8_t)type;
            a->conf = conf;
            if (shadow)
                a->flags |= ITS_CPM_AF_SHADOW;
            keep_area(areas, a, &areas->n_sens, &areas->sens_shapes);
        }
    }
    return ends_exactly(c);
}

/* PerceptionRegionContainer: walking it tells whether the sender and this reading agree on its
 * shape. With `areas` from its_cpm_areas every complete region is counted, and the first
 * ITS_CPM_AREA_REGS are kept for the map. */
static bool walk_regions(its_bitr_t c, its_cpm_areas_t *areas)
{
    uint32_t n = read_count(&c, 1, 8, MIN_REGION);   /* SIZE(1..256, ...) */
    for (uint32_t i = 0; i < n && !c.err; i++)
    {
        its_cpm_area_t *a = areas ? area_slot(areas, areas->n_regs >= ITS_CPM_AREA_REGS) : NULL;
        bool ext = read_flag(&c);
        uint32_t o = its_bits_read(&c, 3);
        its_bits_skip(&c, 12);                       /* measurementDeltaTime */
        uint8_t conf = read_confidence(&c);          /* perceptionRegionConfidence */
        (void)read_shape(&c, a);
        bool shadow = read_flag(&c);                 /* shadowingApplies */
        if (o & 4)
        {
            uint32_t k = read_count(&c, 1, 7, MIN_ID1);
            its_bits_skip(&c, (size_t)k * 8);
        }
        if (o & 2)
            its_bits_skip(&c, 8);                    /* numberOfPerceivedObjects */
        if (o & 1)
        {
            uint32_t k = read_count(&c, 0, 8, MIN_ID2);   /* SIZE(0..255, ...) */
            its_bits_skip(&c, (size_t)k * 16);
        }
        if (ext)
            skip_additions(&c);
        if (a && !c.err)
        {
            a->src = ITS_CPM_AREA_REGION;
            a->conf = conf;
            if (shadow)
                a->flags |= ITS_CPM_AF_SHADOW;
            keep_area(areas, a, &areas->n_regs, &areas->reg_shapes);
        }
    }
    return ends_exactly(c);
}

/* OriginatingVehicleContainer: its_decode.c reads the orientation, this counts the trailers. */
static bool walk_vehicle(its_bitr_t c, its_cpm_t *out)
{
    bool ext = read_flag(&c);
    uint32_t o = its_bits_read(&c, 3);               /* pitch, roll, trailerDataSet */
    its_bits_skip(&c, 19);                           /* orientationAngle */
    if (o & 4)
        its_bits_skip(&c, 19);
    if (o & 2)
        its_bits_skip(&c, 19);
    if (o & 1)
    {
        uint32_t n = read_count(&c, 1, 3, MIN_TRAILER);   /* SIZE(1..8, ...) */
        for (uint32_t i = 0; i < n && !c.err; i++)
        {
            bool text = read_flag(&c);
            uint32_t to = its_bits_read(&c, 3);      /* frontOverhang, rearOverhang, width */
            its_bits_skip(&c, 8 + 8);                /* refPointId, hitchPointOffset */
            if (to & 4)
                its_bits_skip(&c, 8);
            if (to & 2)
                its_bits_skip(&c, 8);
            if (to & 1)
                its_bits_skip(&c, 6);                /* VehicleWidth 1..62 */
            its_bits_skip(&c, 19);                   /* hitchAngle */
            if (text)
                skip_additions(&c);
            if (c.err)
                break;
            if (out->n_trailers < UINT8_MAX)
                out->n_trailers++;
        }
    }
    if (ext && !c.err)
        skip_additions(&c);
    return ends_exactly(c);
}

/* OriginatingRsuContainer: the MAPEM the roadside unit refers to, kept only when complete. */
static bool walk_rsu(its_bitr_t c, its_cpm_t *out)
{
    bool ext = read_flag(&c);
    if (read_flag(&c))
    {
        bool inter, has_region;
        uint16_t region, id;
        read_map_ref(&c, &inter, &has_region, &region, &id);
        if (!c.err)
        {
            out->has_map = true;
            out->map_intersection = inter;
            out->map_has_region = has_region;
            out->map_region = region;
            out->map_id = id;
        }
    }
    if (ext && !c.err)
        skip_additions(&c);
    return ends_exactly(c);
}

/* Dialect: V3 is tried first. That never misreads a V3 frame, while V4 first would misread V3
 * frames. A V4 frame whose V3 walk happens to end exactly is misread as V3, 0.4 to 1.6 % in
 * tests. dialect_sure is set only when exactly one walk ends exactly. The map needs the edition
 * for the angles. */
/* Stack, riscv gcc -Os -fstack-usage: 144 here + walk_objects 240 + read_shape 48 + read_count
 * 32 + its_bits_uper_length 16 = 480 B on the deepest path, no recursion. */
bool its_cpm_decode(const uint8_t *frame, size_t len, const its_decoded_t *d, its_cpm_t *out,
                    its_cpm_obj_t *all, size_t all_cap, uint16_t *all_n)
{
    memset(out, 0, sizeof *out);
    if (all_n)
        *all_n = 0;
    else
        all = NULL;
    if (!d->cpm_read)
        return false;
    out->read = true;
    out->has_ref_pos = d->cpm_has_pos;
    out->ref_lat_e7 = d->cpm_lat_e7;
    out->ref_lon_e7 = d->cpm_lon_e7;
    out->ref_ms = d->cpm_ref_ms;
    out->has_rate = d->cpm_has_rate;
    out->rate_min_m = d->cpm_rate_min_m;
    out->rate_max_m = d->cpm_rate_max_m;
    out->rate_min_e = d->cpm_rate_min_e;
    out->rate_max_e = d->cpm_rate_max_e;
    size_t p = d->cpm_pdu_at;
    if (p + 6 <= len)
        out->station_id = ((uint32_t)frame[p + 2] << 24) | ((uint32_t)frame[p + 3] << 16) |
                          ((uint32_t)frame[p + 4] << 8) | frame[p + 5];

    for (unsigned id = ITS_CPM_ORIG_VEHICLE; id <= ITS_CPM_OBJECTS; id++)
    {
        size_t at = d->cpm_cont_at[id - 1], bytes = d->cpm_cont_bytes[id - 1];
        if (bytes == 0)
            continue;                                /* not in this message */
        uint8_t bit = (uint8_t)(1u << (id - 1));
        if (at + bytes * 8 > len * 8)
        {
            out->doubt |= bit;                       /* the container runs past this frame */
            continue;
        }
        its_bitr_t c = { frame, at + bytes * 8, at, false };
        bool exact = true;
        switch (id)
        {
        case ITS_CPM_ORIG_VEHICLE: exact = walk_vehicle(c, out); break;
        case ITS_CPM_ORIG_RSU:     exact = walk_rsu(c, out); break;
        case ITS_CPM_SENSOR_INFO:  exact = walk_sensors(c, out, NULL); break;
        case ITS_CPM_REGION:       exact = walk_regions(c, NULL); break;
        case ITS_CPM_OBJECTS:
            out->dialect = ITS_CPM_CDD_V3;
            exact = walk_objects(c, false, out, all, all_cap, all_n);
            if (!exact && walk_objects(c, true, NULL, NULL, 0, NULL))
            {
                clear_objects(out, all_n);
                (void)walk_objects(c, true, out, all, all_cap, all_n);
                out->dialect = ITS_CPM_CDD_V4;
                out->dialect_sure = true;
                exact = true;
            }
            else if (exact)
                out->dialect_sure = !walk_objects(c, true, NULL, NULL, 0, NULL);
            break;
        }
        if (!exact)
            out->doubt |= bit;
    }
    return true;
}

/* Containers 3 and 4 walked once more, now keeping the shapes. The map needs them and the detail
 * line does not, so its_cpm_decode leaves them out. A container sent twice is read from its last
 * copy, as in its_cpm_decode. Stack: 80 here + walk_sensors 96 + read_shape 48 + read_count 32
 * + its_bits_uper_length 16 = 272 B. */
bool its_cpm_areas(const uint8_t *frame, size_t len, const its_decoded_t *d, its_cpm_areas_t *out)
{
    memset(out, 0, sizeof *out);
    if (!d->cpm_read)
        return false;
    for (unsigned id = ITS_CPM_SENSOR_INFO; id <= ITS_CPM_REGION; id++)
    {
        size_t at = d->cpm_cont_at[id - 1];
        size_t end = at + (size_t)d->cpm_cont_bytes[id - 1] * 8;
        if (end == at || end > len * 8)
            continue;                                /* not in this message, or not in this frame */
        its_bitr_t c = { frame, end, at, false };    /* fenced to the container */
        if (id == ITS_CPM_SENSOR_INFO)
            (void)walk_sensors(c, NULL, out);
        else
            (void)walk_regions(c, out);
    }
    return true;
}

uint16_t its_cpm_compass(uint16_t ccw_from_east_ddeg)
{
    if (ccw_from_east_ddeg >= ANGLE_NOT_USED)
        return ITS_CPM_NO_ANGLE;
    return (uint16_t)((900u + 3600u - ccw_from_east_ddeg) % 3600u);
}

/* Metres per degree on the WGS84 ellipsoid by the usual series in the latitude. The tangent
 * plane's curvature is left out. The multiple angles come from one cos by the identities. */
void its_cpm_to_wgs84(int32_t ref_lat_e7, int32_t ref_lon_e7, int32_t x_cm, int32_t y_cm,
                      int32_t *lat_e7, int32_t *lon_e7)
{
    const double e7_to_rad = 3.14159265358979323846 / 1.8e9;
    double c1 = cos(ref_lat_e7 * e7_to_rad);
    double c2 = 2.0 * c1 * c1 - 1.0;                 /* cos 2phi */
    double c3 = c1 * (2.0 * c2 - 1.0);               /* cos 3phi */
    double c4 = 2.0 * c2 * c2 - 1.0;                 /* cos 4phi */
    double c5 = 2.0 * c1 * c4 - c3;                  /* cos 5phi */
    double m_lat = 111132.954 - 559.822 * c2 + 1.175 * c4;
    double m_lon = 111412.84 * c1 - 93.5 * c3 + 0.118 * c5;
    double lat = ref_lat_e7 + y_cm * 1e5 / m_lat;    /* cm / 100 / m_per_deg * 1e7 */
    if (lat > 900000000.0)
        lat = 900000000.0;
    if (lat < -900000000.0)
        lat = -900000000.0;
    double lon = ref_lon_e7;
    if (m_lon >= 1.0)                                /* at the pole east has no meaning */
        lon += x_cm * 1e5 / m_lon;
    lon = fmod(lon, 3600000000.0);                   /* near a pole 1310 m are several turns */
    long long l = llround(lon);                      /* lround's long has 32 bits on riscv32 */
    if (l > 1800000000LL)                            /* wrapped after rounding: -180 stays out */
        l -= 3600000000LL;
    if (l <= -1800000000LL)
        l += 3600000000LL;
    *lat_e7 = (int32_t)lround(lat);
    *lon_e7 = (int32_t)l;
}
