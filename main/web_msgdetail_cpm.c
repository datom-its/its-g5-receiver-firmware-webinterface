#include "web_msgdetail_priv.h"

/* The container ids of a mask, as numbers behind a label. */
static void add_id_list(sb_t *b, uint16_t mask)
{
    const char *sep = " ";
    for (unsigned id = 1; id <= 16; id++)
        if (mask & (1u << (id - 1)))
        {
            sb_add(b, "%s%u", sep, id);
            sep = ", ";
        }
}

/* CPM stage 2: the contents its_cpm.c read (x->cpm). Only numbers and table words go in, so the
 * line needs no escaping for HTML or for the JSON strings of /ws and /markers.json. */

/* Compass words as the CAM line in webserver.c writes them: NO/O/SO on German pages. */
static const char *compass_word(unsigned octant, lang_t lang)
{
    static const char *const DE[8] = { "N", "NO", "O", "SO", "S", "SW", "W", "NW" };
    static const char *const EN[8] = { "N", "NE", "E", "SE", "S", "SW", "W", "NW" };
    return (lang == LANG_DE ? DE : EN)[octant % 8u];
}

#define NO_OCTANT 8u

/* The octant of an east/north vector, from north clockwise. The border at 22.5 degrees is
 * tan 22.5 = sqrt 2 - 1, and e < (sqrt 2 - 1) n holds exactly when (e + n)^2 < 2 n^2. */
static unsigned vec_octant(int32_t e, int32_t n)
{
    uint64_t ae = (uint64_t)(e < 0 ? -(int64_t)e : (int64_t)e);
    uint64_t an = (uint64_t)(n < 0 ? -(int64_t)n : (int64_t)n);
    uint64_t s = (ae + an) * (ae + an);
    if (s == 0)
        return NO_OCTANT;
    if (s < 2u * an * an)
        return n > 0 ? 0u : 4u;
    if (s < 2u * ae * ae)
        return e > 0 ? 2u : 6u;
    if (n > 0)
        return e > 0 ? 1u : 7u;
    return e > 0 ? 3u : 5u;
}

/* A CartesianAngleValue counts 0.1 degree counter-clockwise from east. Its course is
 * (900 - a) mod 3600, as in its_cpm_compass. 3600 "not used" and 3601 "unavailable" have no
 * course. */
static unsigned angle_octant(int32_t a)
{
    if (a < 0 || a >= 3600)
        return NO_OCTANT;
    uint32_t c = (900u + 3600u - (uint32_t)a) % 3600u;
    return (unsigned)((c + 225u) / 450u % 8u);
}

/* Floor of the square root, two bits at a time. */
static uint32_t isqrt64(uint64_t v)
{
    uint64_t r = 0, bit = (uint64_t)1 << 62;
    while (bit > v)
        bit >>= 2;
    for (; bit; bit >>= 2)
    {
        if (v >= r + bit)
        {
            v -= r + bit;
            r = (r >> 1) + bit;
        }
        else
            r >>= 1;
    }
    return (uint32_t)r;
}

/* The most likely class in words. A value without a word of its own gets the word of the
 * kind it is counted under. A vehicle value without a word gets its number instead (S_COUNT
 * marks those). */
static void cpm_class(sb_t *b, const its_cpm_obj_t *o, lang_t lang)
{
    /* TrafficParticipantType: 1..4, 12 and 13 lie outside the vehicle constraint. 1..4 and 13
     * keep their meaning, as in the tally of its_cpm.c. 12 (light VRU vehicle) and 15 have no
     * word here. */
    static const str_id_t VEH[] = { S_CPM_V_UNKNOWN, S_CPM_CAT_PED, S_BVR_CYCLIST, S_CPM_M_MOPED,
        S_BVR_MOTORCYCLE, S_CPM_CAT_CAR, S_CPM_CAT_BUS, S_CPM_V_LTRUCK, S_CPM_V_HTRUCK,
        S_CPM_V_TRAILER, S_CPM_V_SPECIAL, S_CPM_CAT_TRAM, S_COUNT, S_CPM_CAT_ANIMAL, S_CPM_V_AGRI };
    /* The VRU subprofiles, from 0 "unavailable" on. 15 is 'max' and, like the reserved values,
     * has no word. Bicyclist 9 and 10 exist only in the newer edition. */
    static const str_id_t PED[] = { S_CPM_CAT_PED, S_CPM_CAT_PED, S_CPM_P_WORKER, S_CPM_P_RESCUE };
    static const str_id_t BIKE[] = { S_CPM_CAT_TWOWHEEL, S_BVR_CYCLIST, S_CPM_B_WHEELCHAIR,
        S_CPM_B_HORSE, S_CPM_B_SKATES, S_CPM_B_SCOOTER, S_CPM_B_PERSONAL, S_CPM_B_PEDELEC,
        S_CPM_B_SPEDELEC, S_CPM_B_ROADBIKE, S_CPM_B_KIDSBIKE };
    static const str_id_t MOTO[] = { S_CPM_CAT_TWOWHEEL, S_CPM_M_MOPED, S_BVR_MOTORCYCLE,
        S_CPM_M_SIDE_R, S_CPM_M_SIDE_L };
    static const str_id_t ANIMAL[] = { S_CPM_CAT_ANIMAL, S_CPM_A_WILD, S_CPM_A_FARM,
        S_CPM_A_SERVICE };
    static const str_id_t OTHER[] = { S_CPM_O_UNKNOWN, S_CPM_O_SINGLE, S_CPM_O_MULTI,
        S_CPM_O_BULK };
#define N_OF(t) (sizeof(t) / sizeof((t)[0]))
    const str_id_t *w;
    size_t n;
    str_id_t kind;
    switch (o->cls)
    {
    case ITS_CPM_CLS_VEHICLE: w = VEH;    n = N_OF(VEH);    kind = S_COUNT;            break;
    case ITS_CPM_CLS_PED:     w = PED;    n = N_OF(PED);    kind = S_CPM_CAT_PED;      break;
    case ITS_CPM_CLS_BIKE:    w = BIKE;   n = N_OF(BIKE);   kind = S_CPM_CAT_TWOWHEEL; break;
    case ITS_CPM_CLS_MOTO:    w = MOTO;   n = N_OF(MOTO);   kind = S_CPM_CAT_TWOWHEEL; break;
    case ITS_CPM_CLS_ANIMAL:  w = ANIMAL; n = N_OF(ANIMAL); kind = S_CPM_CAT_ANIMAL;   break;
    case ITS_CPM_CLS_OTHER:   w = OTHER;  n = N_OF(OTHER);  kind = S_CPM_CAT_OTHER;    break;
    case ITS_CPM_CLS_GROUP:
        sb_add(b, S(S_CPM_G_OF), (unsigned)o->group_size);
        return;
    default:                  /* an extension alternative, of ObjectClass or of the VRU CHOICE */
        sb_add(b, "%s", S(S_CPM_CLS_NEWER));
        return;
    }
#undef N_OF
    str_id_t id = o->sub < n ? w[o->sub] : kind;
    if (id == S_COUNT)
        sb_add(b, S(S_CPM_V_N), (unsigned)o->sub);
    else
        sb_add(b, "%s", S(id));
}

/* A velocity part on -16383 or 16382 stands for at least 163.83 or 163.81 m/s. */
static uint32_t vel_part(int16_t v)
{
    if (v == 16382)
        return 16381u;
    return (uint32_t)(v < 0 ? -(int32_t)v : (int32_t)v);
}

/* Speed and course. At an end of its range the value is a lower bound, so its tenths are cut
 * ("&ge; 589,7 km/h" for SpeedValue 16382). 16383 "unavailable" and the 16384 that the 15
 * bits of a cartesian component let through leave the speed out. */
static void cpm_speed(sb_t *b, const its_cpm_obj_t *o, lang_t lang)
{
    uint32_t cms, c36;               /* 0.01 m/s, and 36 times that for the km/h */
    bool at_least;
    unsigned oct;
    if (o->vel_kind == ITS_CPM_KIN_POLAR)
    {
        if (o->v_a < 0 || o->v_a >= 16383)
            return;
        at_least = o->v_a == 16382;
        cms = at_least ? 16381u : (uint32_t)o->v_a;
        c36 = cms * 36u;
        oct = angle_octant(o->v_b);
    }
    else if (o->vel_kind == ITS_CPM_KIN_CART)
    {
        if (o->v_a >= 16383 || o->v_b >= 16383)
            return;
        at_least = o->v_a == 16382 || o->v_a == -16383 || o->v_b == 16382 || o->v_b == -16383;
        uint64_t vx = vel_part(o->v_a), vy = vel_part(o->v_b);
        cms = isqrt64(vx * vx + vy * vy);
        /* One root of 36^2 (vx^2 + vy^2): the km/h are not cut to whole cm/s first. */
        c36 = isqrt64((vx * vx + vy * vy) * 1296u);
        oct = vec_octant(o->v_a, o->v_b);
    }
    else
        return;
    if (at_least)
    {
        uint32_t t = cms * 36u / 100u;     /* 0.01 m/s in tenths of km/h, cut */
        sb_add(b, ", &ge; %lu%c%lu km/h", (unsigned long)(t / 10u), lang == LANG_DE ? ',' : '.',
               (unsigned long)(t % 10u));
    }
    else
    {
        uint32_t kmh = (c36 + 500u) / 1000u;
        sb_add(b, ", %lu km/h", (unsigned long)kmh);
        if (!kmh)
            oct = NO_OCTANT;           /* what stands still has no course */
    }
    if (oct != NO_OCTANT)
        sb_add(b, " %s %s", S(S_CPM_TOWARD), compass_word(oct, lang));
}

/* One object: class and how sure, quality, where from the sender's reference point, speed.
 * A coordinate on an end of its range means at least that far, so the metres are cut.
 * noinline: inlined into content_parts, it would push denm_text out of line and grow the
 * msg_detail_text stack chain from 688 to 720 bytes. */
static __attribute__((noinline)) void cpm_object(sb_t *b, const its_cpm_obj_t *o, lang_t lang)
{
    size_t m = item_begin(b, SEP);
    sb_add(b, "%s", S(S_CPM_OBJ));
    if (o->flags & ITS_CPM_OF_ID)
        sb_add(b, " %u", (unsigned)o->id);
    sb_add(b, ": ");
    if (o->cls != ITS_CPM_CLS_NONE)
    {
        cpm_class(b, o, lang);
        if (o->conf)
            sb_add(b, ", %u %% %s", (unsigned)o->conf, S(S_CPM_SURE));
        sb_add(b, ", ");
    }
    if (o->quality != ITS_CPM_NO_QUALITY)
    {
        sb_add(b, S(S_CPM_QUALITY), (unsigned)o->quality);
        sb_add(b, ", ");
    }
    uint64_t d2 = (uint64_t)((int64_t)o->x_cm * o->x_cm) + (uint64_t)((int64_t)o->y_cm * o->y_cm);
    uint32_t cm = isqrt64(d2);
    bool edge = (o->flags & ITS_CPM_OF_XY_EDGE) != 0;
    unsigned long metres = (unsigned long)(edge ? cm / 100u : (cm + 50u) / 100u);
    sb_add(b, "%s%lu m", edge ? "&ge; " : "", metres);
    /* Like the course below 0.5 km/h: what rounds to 0 m has no side. */
    unsigned oct = vec_octant(o->x_cm, o->y_cm);
    if (oct != NO_OCTANT && metres)
        sb_add(b, " %s", compass_word(oct, lang));
    cpm_speed(b, o, lang);
    item_end(b, m);
}

/* The kinds of all objects read, in the order of the tally. Left out when every one of them
 * is already shown as an object of its own. */
static void cpm_kinds(sb_t *b, const its_cpm_t *c, lang_t lang)
{
    static const str_id_t CAT[ITS_CPM_CATS] = {
        [ITS_CPM_CAT_CAR] = S_CPM_CAT_CAR, [ITS_CPM_CAT_BUS] = S_CPM_CAT_BUS,
        [ITS_CPM_CAT_TRUCK] = S_CPM_CAT_TRUCK, [ITS_CPM_CAT_TRAM] = S_CPM_CAT_TRAM,
        [ITS_CPM_CAT_TWOWHEEL] = S_CPM_CAT_TWOWHEEL, [ITS_CPM_CAT_PED] = S_CPM_CAT_PED,
        [ITS_CPM_CAT_ANIMAL] = S_CPM_CAT_ANIMAL, [ITS_CPM_CAT_GROUP] = S_CPM_CAT_GROUP,
        [ITS_CPM_CAT_OTHER] = S_CPM_CAT_OTHER, [ITS_CPM_CAT_NONE] = S_CPM_CAT_NONE,
    };
    if (c->n_walked <= c->n_obj)
        return;
    size_t m = item_begin(b, SEP);
    sb_add(b, "%s:", S(S_CPM_KINDS));
    const char *sep = " ";
    for (unsigned i = 0; i < ITS_CPM_CATS; i++)
        if (c->cat[i])
        {
            sb_add(b, "%s%s %u", sep, S(CAT[i]), (unsigned)c->cat[i]);
            sep = ", ";
        }
    item_end(b, m);
}

#define CPM_SENSOR_NAMES 4   /* names in the sensor item; the rest is counted as "+N more" */

/* The kinds of sensor after the sensor count, in the order of their numbers. */
static void cpm_sensor_names(sb_t *b, uint32_t types, lang_t lang)
{
    static const str_id_t ST[] = { S_CPM_ST_UNDEF, S_CPM_ST_RADAR, S_CPM_ST_LIDAR, S_CPM_ST_MONO,
        S_CPM_ST_STEREO, S_CPM_ST_NIGHT, S_CPM_ST_ULTRA, S_CPM_ST_PMD, S_CPM_ST_LOOP,
        S_CPM_ST_SPHERE, S_CPM_ST_UWB, S_CPM_ST_ACOUSTIC, S_CPM_ST_LOCAL, S_CPM_ST_ITS };
    unsigned shown = 0, more = 0;
    for (unsigned t = 0; t < 32; t++)
    {
        if (!(types & ((uint32_t)1u << t)))
            continue;
        if (shown == CPM_SENSOR_NAMES)
        {
            more++;
            continue;
        }
        sb_add(b, "%s", shown++ ? ", " : ": ");
        if (t < sizeof(ST) / sizeof(ST[0]))
            sb_add(b, "%s", S(ST[t]));
        else
            sb_add(b, S(S_CPM_ST_N), t);
    }
    if (more)
        sb_add(b, ", +%u %s", more, S(S_CPM_MORE));
}

/* One end of a message rate with its NUL: 8 bytes for "0,00255", the widest an 8-bit mantissa
 * gives at exponent -5; at 2 "25500" takes 6. its_decode.c reads up to 128 (7 bits + 1). */
#define CPM_RATE_MAX 8

/* MessageRateHz as the exact decimal it stands for: "0,5", "10", "0,00001". False for an
 * exponent outside -5..2, which its_decode.c cannot hand over. */
static bool cpm_rate_str(uint8_t mant, int8_t exp, lang_t lang, char *out, size_t cap)
{
    if (exp < -5 || exp > 2)
        return false;
    if (exp >= 0)
    {
        uint32_t v = mant;
        for (int i = 0; i < exp; i++)
            v *= 10u;
        snprintf(out, cap, "%lu", (unsigned long)v);
        return true;
    }
    unsigned digits = (unsigned)-exp;
    uint32_t div = 1;
    for (unsigned i = 0; i < digits; i++)
        div *= 10u;
    uint32_t whole = mant / div, frac = mant % div;
    if (!frac)
    {
        snprintf(out, cap, "%lu", (unsigned long)whole);
        return true;
    }
    for (; frac % 10u == 0; digits--)
        frac /= 10u;
    snprintf(out, cap, "%lu%c%0*lu", (unsigned long)whole, lang == LANG_DE ? ',' : '.',
             (int)digits, (unsigned long)frac);
    return true;
}

/* TimestampIts counts TAI milliseconds from 2004 as Time32 counts its seconds, so the same
 * conversion applies (web_time32_to_unix, right from 2017 on). A sender clock that
 * web_clock_set takes for unset is left out: its time of day would mean nothing. */
static bool cpm_clock(uint64_t its_ms, lang_t lang, char *out, size_t cap)
{
    uint64_t s = its_ms / 1000u;
    if (s == 0 || s > UINT32_MAX)
        return false;
    uint64_t u = web_time32_to_unix((uint32_t)s);
    if (u > UINT32_MAX || !web_clock_set((uint32_t)u))
        return false;
    fmt_clock((uint32_t)u, (uint32_t)(its_ms % 1000u) * 1000u, lang, out, cap);
    return out[0] != '\0';
}

/* CPM: what the sensors of a station see. The object count comes first because it is what
 * the message is for; the rest says who is looking and with how many sensors. */
void cpm_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    size_t m;
    if (x->cpm_wrong_version)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %u %s", S(S_CPM_VERSION), (unsigned)x->cpm_other_version, S(S_NOT_READ));
        item_end(b, m);
        return;
    }
    if (!x->cpm_read)
        return;
    const its_cpm_t *c = &x->cpm;   /* c->read equals cpm_read here (both from d->cpm_read); the
                                     * guards keep hand-built entries safe */
    /* A count is only shown when its container held what its shape needs. */
    uint16_t ok = (uint16_t)(x->cpm_containers & ~x->cpm_cont_bad);
    if (ok & (1u << (ITS_CPM_OBJECTS - 1)))
    {
        /* Both numbers only when they differ: a split CPM carries part of what is known.
         * More in this message than the station knows is the sender contradicting itself. */
        m = item_begin(b, SEP);
        sb_add(b, "%s %u", S(S_CPM_OBJECTS), (unsigned)x->cpm_n_objects);
        if (x->cpm_n_objects_here != x->cpm_n_objects)
        {
            sb_add(b, " (%s %u", S(S_LBL_HERE), (unsigned)x->cpm_n_objects_here);
            if (x->cpm_n_objects_here > x->cpm_n_objects)
                sb_add(b, ", %s", S(S_CONTRADICTS));
            sb_add(b, ")");
        }
        item_end(b, m);
        if (c->read)
        {
            cpm_kinds(b, c, lang);
            for (unsigned i = 0; i < c->n_obj && i < ITS_CPM_DETAIL_OBJS; i++)
                cpm_object(b, &c->obj[i], lang);
        }
    }
    if (ok & (1u << (ITS_CPM_SENSOR_INFO - 1)))
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %u", S(S_CPM_SENSORS), (unsigned)x->cpm_n_sensors);
        if (c->read && c->sensor_types)
            cpm_sensor_names(b, c->sensor_types, lang);
        item_end(b, m);
        /* The farthest sensor, and how sure its sender is of what lies within that reach. */
        if (c->read && c->reach_dm)
        {
            m = item_begin(b, SEP);
            sb_add(b, "%s %u m", S(S_CPM_REACH), (unsigned)((c->reach_dm + 5u) / 10u));
            if (c->reach_conf)
                sb_add(b, " (%u %% %s)", (unsigned)c->reach_conf, S(S_CPM_SURE));
            item_end(b, m);
        }
    }
    if (ok & (1u << (ITS_CPM_REGION - 1)))
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %u", S(S_CPM_REGIONS), (unsigned)x->cpm_n_regions);
        item_end(b, m);
    }
    if (x->cpm_seg_total)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %u %s %u", S(S_CPM_PART), (unsigned)x->cpm_seg_this, S(S_CPM_OF),
               (unsigned)x->cpm_seg_total);
        if (x->cpm_seg_this > x->cpm_seg_total)
            sb_add(b, " (%s)", S(S_CONTRADICTS));
        item_end(b, m);
    }
    /* How often the sender means to send, both ends exact. Ends in the wrong order are
     * shown as sent. Marking them S_CONTRADICTS would cost the second object its room on
     * the longest detail line. */
    char lo[CPM_RATE_MAX], hi[CPM_RATE_MAX];
    if (c->read && c->has_rate && cpm_rate_str(c->rate_min_m, c->rate_min_e, lang, lo, sizeof lo) &&
        cpm_rate_str(c->rate_max_m, c->rate_max_e, lang, hi, sizeof hi))
    {
        m = item_begin(b, SEP);
        sb_add(b, S(S_CPM_RATE), lo, hi);
        item_end(b, m);
    }
    /* Containers 1 and 2 say who sent it. The standard allows only one of the two. */
    if (x->cpm_containers & (1u << (ITS_CPM_ORIG_VEHICLE - 1)))
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(S_CPM_FROM_VEH));
        /* The angle is a number too, so it follows the same rule as the counts. */
        if (x->cpm_has_heading && (ok & (1u << (ITS_CPM_ORIG_VEHICLE - 1))))
            sb_add(b, " &middot; %s %u&deg;", S(S_CPM_HEADING), (unsigned)(x->cpm_heading_ddeg / 10));
        if (c->read && c->n_trailers && (ok & (1u << (ITS_CPM_ORIG_VEHICLE - 1))))
            sb_add(b, " &middot; %s %u", S(S_CPM_TRAILERS), (unsigned)c->n_trailers);
        item_end(b, m);
    }
    else if (x->cpm_containers & (1u << (ITS_CPM_ORIG_RSU - 1)))
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(S_CPM_FROM_RSU));
        /* The MAPEM the unit refers to, written region/id like the intersections of SREM. */
        if (c->read && c->has_map && (ok & (1u << (ITS_CPM_ORIG_RSU - 1))))
        {
            sb_add(b, " &middot; %s ", S(c->map_intersection ? S_CPM_MAP_INT : S_CPM_MAP_SEG));
            if (c->map_has_region)
                sb_add(b, "%u/", (unsigned)c->map_region);
            sb_add(b, "%u", (unsigned)c->map_id);
        }
        item_end(b, m);
    }
    char t[16];   /* HH:MM:SS takes 9 with the NUL; fmt_clock's boot form ("31536000,999s") 14 */
    if (c->read && cpm_clock(c->ref_ms, lang, t, sizeof t))
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %s", S(S_CPM_MEASURED), t);
        item_end(b, m);
    }
    if (x->cpm_list_form == ITS_CPM_LIST_NOEXT)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(S_CPM_LIST_NOEXT));
        item_end(b, m);
    }
    /* Only the object container differs between the two editions of the CDD. */
    if (c->read && c->dialect == ITS_CPM_CDD_V4)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(S_CPM_NEWER_EDITION));
        item_end(b, m);
    }
    /* Ids 6..16 are not defined yet. They are named by number rather than dropped, so a
     * newer sender shows that it sent more than this firmware can read. */
    uint16_t other = x->cpm_containers & (uint16_t)~0x1Fu;
    if (other)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(S_CPM_OTHER));
        add_id_list(b, other);
        item_end(b, m);
    }
    if (x->cpm_cont_bad)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(S_CPM_BAD));
        add_id_list(b, x->cpm_cont_bad);
        item_end(b, m);
    }
    /* A container whose walk did not end on its length. What came before the fault is shown
     * above. One already named unreadable is not named twice. */
    uint16_t doubt = (uint16_t)(c->read ? c->doubt & ~x->cpm_cont_bad : 0);
    if (doubt)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(S_CPM_DOUBT));
        add_id_list(b, doubt);
        item_end(b, m);
    }
}
