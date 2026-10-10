#include "cpm_geo.h"

#include <math.h>
#include <string.h>

_Static_assert(sizeof(cpm_geo_area_t) == 152, "cpm_geo_area_t is 152 B");
_Static_assert(ITS_CPM_NO_ANGLE == CPM_GEO_NONE, "its_cpm_compass says 'none' as this module does");

#define RAD         (3.14159265358979323846 / 1800.0)   /* 0.1 degree in radians */
#define ANGLE_END   3600    /* 3600 and above: not used, unavailable, or past the type */
#define ENU_X       900     /* the bearing of East-North-Up's x axis */

/* A raw angle as a counter-clockwise angle of the shape's own frame. V3 fields are
 * Wgs84AngleValue: clockwise from north, which is the frame's y axis. */
static uint16_t cart_angle(uint16_t raw, bool v3)
{
    return v3 ? (uint16_t)((900u + 3600u - raw) % 3600u) : raw;
}

/* A counter-clockwise angle c of a frame whose x axis points to bearing f, as a bearing. */
static uint16_t bearing(uint16_t f, uint16_t c)
{
    return (uint16_t)((f + 3600u - c) % 3600u);
}

/* A point of the frame as east/north cm: body x forward, y left turned by the heading (TS 103 324
 * Figure 10). East-North-Up is the case s = 1, c = 0. */
static void to_en(double s, double c, int32_t x, int32_t y, int32_t *e, int32_t *n)
{
    *e = (int32_t)lround(x * s - y * c);
    *n = (int32_t)lround(x * c + y * s);
}

bool cpm_geo_place(const its_cpm_area_t *a, const cpm_geo_frame_t *f, cpm_geo_area_t *out)
{
    memset(out, 0, sizeof *out);
    out->a_dm = out->b_dm = out->rot_ddeg = out->from_ddeg = out->to_ddeg = CPM_GEO_NONE;
    out->kind = a->kind;
    out->src = a->src;
    bool body = f->body && a->src == ITS_CPM_AREA_SENSOR;   /* regions never turn (7.1.7) */
    bool v3 = f->edition != ITS_CPM_CDD_V4;                  /* the edition the CPM ASN.1 imports */
    if (a->kind > ITS_CPM_SHAPE_RADIALS)
        return false;                /* an extension alternative says nothing we can draw */
    if (body && f->heading_ddeg >= ANGLE_END)
        return false;
    if (a->kind == ITS_CPM_SHAPE_RADIALS && a->ref_point_id != 0)
        return false;                /* on a trailer, whose reference point needs EN 302 890-2 */
    uint16_t fx = body ? f->heading_ddeg : ENU_X;            /* the bearing of the frame's x axis */
    double s = 1.0, c = 0.0;
    if (body)
    {
        s = sin(fx * RAD);
        c = cos(fx * RAD);
    }
    unsigned n = a->n < ITS_CPM_AREA_PTS ? a->n : ITS_CPM_AREA_PTS;
    bool dep = false;                /* has an angle whose meaning the edition decides */
    switch (a->kind)
    {
    case ITS_CPM_SHAPE_RECT:
    case ITS_CPM_SHAPE_ELLIPSE:
        dep = (a->flags & ITS_CPM_AF_ORIENT) != 0;
        if (dep && a->ang_a >= ANGLE_END)
            return false;
        /* Without orientation the a axis lies on the frame's x axis: east, or forward. */
        out->rot_ddeg = bearing(fx, dep ? cart_angle(a->ang_a, v3) : 0);
        out->a_dm = a->a_dm;
        out->b_dm = a->b_dm;
        break;
    case ITS_CPM_SHAPE_CIRCLE:
        out->a_dm = a->a_dm;
        break;
    case ITS_CPM_SHAPE_POLYGON:
        for (unsigned i = 0; i < n; i++)
            to_en(s, c, a->u.pt[i].x_cm, a->u.pt[i].y_cm, &out->u.pt[i].e_cm, &out->u.pt[i].n_cm);
        out->n = (uint8_t)n;
        break;
    case ITS_CPM_SHAPE_RADIAL:
    {
        dep = true;
        if (a->ang_a >= ANGLE_END || a->ang_b >= ANGLE_END)
            return false;
        /* Counter-clockwise from cs to ce. V3 bearings sweep clockwise from start to end, so
         * their ends swap when they turn into counter-clockwise angles. */
        uint16_t cs = v3 ? cart_angle(a->ang_b, true) : a->ang_a;
        uint16_t ce = v3 ? cart_angle(a->ang_a, true) : a->ang_b;
        out->from_ddeg = bearing(fx, ce);
        out->to_ddeg = bearing(fx, cs);
        out->a_dm = a->a_dm;
        break;
    }
    case ITS_CPM_SHAPE_RADIALS:      /* CartesianAngleValue in both editions */
        for (unsigned i = 0; i < n; i++)
        {
            if (a->u.rs[i].start >= ANGLE_END || a->u.rs[i].end >= ANGLE_END)
                return false;
            out->u.rs[i].range_dm = a->u.rs[i].range_dm;
            out->u.rs[i].from = bearing(fx, a->u.rs[i].end);
            out->u.rs[i].to = bearing(fx, a->u.rs[i].start);
        }
        out->n = (uint8_t)n;
        break;
    }
    if (body)
        out->flags |= CPM_GEO_AF_TURNS;
    if (a->flags & ITS_CPM_AF_CUT)
        out->flags |= CPM_GEO_AF_PART;
    if (a->flags & ITS_CPM_AF_SHADOW)
        out->flags |= CPM_GEO_AF_SHADOW;
    /* Unsure when the edition is not proven, or when a V3 WGS84 angle is read literally in a
     * body frame. V3 gives no rule for that. The NOTE of 7.1.6 only swaps East-North-Up for the
     * body frame. */
    if (dep && (!f->edition_sure || (v3 && body)))
        out->flags |= CPM_GEO_AF_UNSURE;
    int32_t e, nn;
    to_en(s, c, a->ref_x_cm, a->ref_y_cm, &e, &nn);
    its_cpm_to_wgs84(f->ref_lat_e7, f->ref_lon_e7, e, nn, &out->lat_e7, &out->lon_e7);
    return true;
}

/* The object's acceleration projected on its velocity, rounded to 0.1 m/s2. A polar magnitude of
 * 160 is only a lower bound, which says nothing once projected. */
static bool along_course(const its_cpm_obj_t *o, int16_t *out)
{
    double ax, ay, ux, uy;
    if (o->acc_kind == ITS_CPM_KIN_POLAR)
    {
        if (o->a_a < 0 || o->a_a >= 160 || o->a_b < 0 || o->a_b >= ANGLE_END)
            return false;
        if (o->vel_kind == ITS_CPM_KIN_POLAR)
        {
            *out = (int16_t)lround(o->a_a * cos((o->a_b - o->v_b) * RAD));
            return true;
        }
        ax = o->a_a * cos(o->a_b * RAD);
        ay = o->a_a * sin(o->a_b * RAD);
    }
    else if (o->acc_kind == ITS_CPM_KIN_CART)
    {
        if (o->a_a < -159 || o->a_a > 159 || o->a_b < -159 || o->a_b > 159)
            return false;            /* -160 and 160 are bounds, 161 unavailable, 162.. no type */
        ax = o->a_a;
        ay = o->a_b;
    }
    else
        return false;
    if (o->vel_kind == ITS_CPM_KIN_POLAR)
    {
        ux = cos(o->v_b * RAD);
        uy = sin(o->v_b * RAD);
    }
    else
    {
        double v = sqrt((double)o->v_a * o->v_a + (double)o->v_b * o->v_b);
        ux = o->v_a / v;
        uy = o->v_b / v;
    }
    *out = (int16_t)lround(ax * ux + ay * uy);
    return true;
}

void cpm_geo_motion(const its_cpm_obj_t *o, cpm_geo_motion_t *m)
{
    memset(m, 0, sizeof *m);
    m->speed_cms = m->course_ddeg = m->orient_ddeg = m->age_ms = m->llp_dm = CPM_GEO_NONE;
    if (o->vel_kind == ITS_CPM_KIN_POLAR && o->v_a >= 0 && o->v_a < 16383)
    {
        m->speed_cms = (uint16_t)o->v_a;
        if (o->v_a == 16382)         /* "greater than 163.81 m/s" */
            m->fl |= CPM_GEO_MF_SPEED_MIN;
        if (o->v_b >= 0 && o->v_b < ANGLE_END)   /* the only check: bearing() takes any value */
            m->course_ddeg = bearing(ENU_X, (uint16_t)o->v_b);
    }
    else if (o->vel_kind == ITS_CPM_KIN_CART && o->v_a < 16383 && o->v_b < 16383)
    {
        /* 16383 is unavailable, 16384 past the type; -16383 and 16382 are bounds. */
        m->speed_cms = (uint16_t)lround(sqrt((double)o->v_a * o->v_a + (double)o->v_b * o->v_b));
        if (o->v_a == -16383 || o->v_a == 16382 || o->v_b == -16383 || o->v_b == 16382)
            m->fl |= CPM_GEO_MF_SPEED_MIN;
        if (o->v_a || o->v_b)
        {
            /* Cut, not rounded: so the octant always agrees with the detail line's vec_octant. */
            double b = atan2(o->v_a, o->v_b) / RAD;
            if (b < 0.0)
                b += 3600.0;
            m->course_ddeg = (uint16_t)((unsigned)floor(b) % 3600u);
        }
    }
    if (m->course_ddeg != CPM_GEO_NONE && m->speed_cms >= 50)
        m->has_accel = along_course(o, &m->accel_dms2);
    if (o->flags & ITS_CPM_OF_HEADING)
        m->orient_ddeg = its_cpm_compass(o->z_angle);
    if (o->flags & ITS_CPM_OF_AGE)
    {
        m->age_ms = o->age_ms < 1500 ? o->age_ms : 1500;
        if (o->age_ms >= 1500)
            m->fl |= CPM_GEO_MF_AGE_MIN;
    }
    if ((o->flags & ITS_CPM_OF_LLP) && o->llp_dm < 32767)
    {
        m->llp_dm = o->llp_dm;
        if (o->llp_dm == 32766)
            m->fl |= CPM_GEO_MF_LLP_MIN;
    }
    m->len_dm = o->len_dm;
    m->wid_dm = o->wid_dm;
    m->hgt_dm = o->hgt_dm;
    if (o->len_dm == 255 || o->wid_dm == 255 || o->hgt_dm == 255)
        m->fl |= CPM_GEO_MF_SIZE_MIN;
    if (o->flags & ITS_CPM_OF_XY_EDGE)
        m->fl |= CPM_GEO_MF_DIST_MIN;
}
