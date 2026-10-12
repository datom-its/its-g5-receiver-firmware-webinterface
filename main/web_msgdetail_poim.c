#include "web_msgdetail_priv.h"

/* Output bytes of one POIM air text before the ellipsis, the italics not counted. A shown
 * character never comes out shorter than it went in, so the decoder has to keep at least this
 * many raw bytes. A hidden one comes out shorter (one '?'), and such a text ends earlier. */
#define POIM_TEXT_OUT 40
_Static_assert(ITS_POIM_TEXT >= POIM_TEXT_OUT,
               "the decoder keeps fewer raw bytes than the page shows");


/* Free and total spaces. In TS 103 916, 101 is a count and "not stated" at once, so each 101
 * keeps its own note. Only when neither is 101 does more free than total mean that the
 * sender contradicts himself. */
static void poim_spaces(sb_t *b, const its_poim_occ_t *o, lang_t lang)
{
    bool na_free = o->has_free && o->n_free == ITS_POIM_SPACES_MAYBE_NA;
    bool na_total = o->has_total && o->n_total == ITS_POIM_SPACES_MAYBE_NA;
    if (o->has_free)
    {
        sb_add(b, "%s %u", S(S_POIM_FREE), (unsigned)o->n_free);
        if (na_free)
            sb_add(b, " (%s)", S(S_POIM_OR_NA));
        if (o->has_total)
            sb_add(b, " %s", S(S_CPM_OF));
    }
    else if (o->has_total)
        sb_add(b, "%s", S(S_POIM_SPACES));
    if (o->has_total)
    {
        sb_add(b, " %u", (unsigned)o->n_total);
        if (na_total)
            sb_add(b, " (%s)", S(S_POIM_OR_NA));
    }
    if (o->has_free && o->has_total && !na_free && !na_total && o->n_free > o->n_total)
        sb_add(b, " (%s)", S(S_CONTRADICTS));
}

/* Spaces, then the sender's own rate, never one computed from the spaces, then the trend as
 * a verb behind it: the trend is the occupancy's, so "rising" means it fills up. */
static void poim_occupancy(sb_t *b, const its_poim_occ_t *o, lang_t lang)
{
    static const str_id_t TREND[8] = {
        S_POIM_TR_DOWN, S_POIM_TR_DOWN_FAST, S_POIM_TR_DOWN_SLOW, S_POIM_TR_UP,
        S_POIM_TR_UP_FAST, S_POIM_TR_UP_SLOW, S_POIM_TR_STABLE, S_POIM_TR_VARIES,
    };
    bool spaces = o->has_free || o->has_total;
    bool trend = o->has_trend && o->trend < 8;
    if (spaces)
        poim_spaces(b, o, lang);
    if (!o->has_rate && !trend)
        return;
    sb_add(b, "%s%s", spaces ? ", " : "", S(S_POIM_OCC));
    if (o->has_rate)
        sb_add(b, " %u %%", (unsigned)o->rate);
    if (trend)
        sb_add(b, "%s%s", o->has_rate ? ", " : " ", S(TREND[o->trend]));
}

/* S_TRF_WDAYS starts on Sunday, so day n of the POIM (1 Monday .. 7 Sunday) is entry n % 7. */
static void poim_wday(sb_t *b, unsigned n, lang_t lang)
{
    const char *p = S(S_TRF_WDAYS);
    for (unsigned i = n % 7; i && p; i--)
    {
        p = strchr(p, ',');
        if (p)
            p++;
    }
    if (!p)
        return;
    const char *end = strchr(p, ',');
    sb_add(b, "%.*s", (int)(end ? (size_t)(end - p) : strlen(p)), p);
}

/* Monday to Sunday, three or more days in a row as a range. No run wraps from Sunday to
 * Monday: the list reads in the week's order, not round it. */
static void poim_days(sb_t *b, uint8_t days, lang_t lang)
{
    if ((days & ITS_POIM_DAYS_ALL) == ITS_POIM_DAYS_ALL)
    {
        sb_add(b, "%s", S(S_POIM_DAILY));
        return;
    }
    if (!(days & ITS_POIM_DAYS_ALL))
    {
        sb_add(b, "%s", S(S_POIM_NODAYS));
        return;
    }
    const char *sep = "";
    for (unsigned d = 1; d <= 7; d++)
    {
        if (!(days & (1u << d)))
            continue;
        unsigned last = d;
        while (last < 7 && (days & (1u << (last + 1))))
            last++;
        if (last - d >= 2)
        {
            sb_add(b, "%s", sep);
            poim_wday(b, d, lang);
            sb_add(b, "&ndash;");
            poim_wday(b, last, lang);
        }
        else
            for (unsigned k = d; k <= last; k++)
            {
                sb_add(b, "%s", k == d ? sep : ", ");
                poim_wday(b, k, lang);
            }
        sep = ", ";
        d = last;
    }
}

/* The word of one load entry: the named goods first, then dangerous goods, then the first
 * special transport bit. *more says the entry names more than that word. */
static bool poim_load_word(const its_poim_status_t *s, str_id_t *id, bool *more)
{
    static const str_id_t GOODS[15] = {
        S_POIM_GOODS_AMMO, S_POIM_GOODS_CHEM, S_POIM_GOODS_EMPTY, S_POIM_GOODS_FUEL,
        S_POIM_GOODS_GLASS, S_POIM_GOODS_DANGER, S_POIM_GOODS_LIQUID, S_POIM_GOODS_LIVESTOCK,
        S_POIM_GOODS_PEOPLE, S_POIM_GOODS_ENV, S_POIM_GOODS_WATER, S_POIM_GOODS_PERISH,
        S_POIM_GOODS_PHARMA, S_POIM_GOODS_VEHICLES, S_POIM_GOODS_REEFER,
    };
    static const str_id_t SPECIAL[4] = {
        S_POIM_STT_HEAVY, S_POIM_STT_WIDTH, S_POIM_STT_LENGTH, S_POIM_STT_HEIGHT,
    };
    unsigned parts = (s->has_goods ? 1u : 0u) + (s->has_dangerous ? 1u : 0u);
    for (unsigned k = 0; k < 4; k++)
        parts += (s->special >> k) & 1u;
    *more = parts > 1;
    if (s->has_goods && s->goods < 15)
        *id = GOODS[s->goods];
    else if (s->has_dangerous)
        *id = S_BVR_DANGEROUS;
    else
    {
        for (unsigned k = 0; k < 4; k++)
            if (s->special & (1u << k))
            {
                *id = SPECIAL[k];
                return true;
            }
        return false;
    }
    return true;
}

/* The filter of the first ParkingStatus entry: the first value of the first list that has a
 * name, in the order reservation, class, load, stay, fee. All its lists hold at once, so more
 * lists get words that narrow. More values in one list get only an ellipsis, since the
 * standard says nothing on how they combine. Without any name the count still gets S_UNKNOWN,
 * or it would read like the count of the whole facility. */
static void poim_filter(sb_t *b, const its_poim_status_t *s, lang_t lang)
{
    static const str_id_t RES[14] = {
        S_POIM_RES_DISABLED, S_POIM_RES_PREGNANT, S_POIM_RES_WOMEN, S_POIM_RES_PARENTS,
        S_POIM_RES_LOADING, S_POIM_RES_EV_MANUAL, S_POIM_RES_EV_AUTO, S_POIM_RES_REEFER,
        S_POIM_RES_VIP, S_POIM_RES_PREBOOK, S_POIM_RES_BOOKABLE, S_POIM_RES_NOBOOK,
        S_POIM_RES_VALET, S_POIM_RES_PERMIT,
    };
    static const str_id_t FEE[3] = { S_POIM_FEE_TIME, S_POIM_FEE_FLAT, S_POIM_FEE_SUBSCR };
    static const str_id_t STAY[3] = { S_POIM_OT_UNKNOWN, S_POIM_OT_UNLIMITED, S_POIM_OT_CHARGING };
    unsigned n_lists = 0;
    for (unsigned k = 0; k < 5; k++)
        n_lists += (s->lists >> k) & 1u;
    bool more = s->more, load_more = false;
    str_id_t load;
    char when[FMT_WHEN_MAX];
    if ((s->lists & ITS_POIM_FILT_RESERVATION) && s->reservation < 14)
        sb_add(b, "%s", S(RES[s->reservation]));
    else if ((s->lists & ITS_POIM_FILT_VEHICLE) && s->veh_class && strchr("LMNOTG", s->veh_class))
    {
        sb_add(b, "%s %c", S(S_POIM_CLASS_FOR), s->veh_class);
        if (s->veh_num >= 1 && s->veh_num <= 9)
            sb_add(b, "%u", (unsigned)s->veh_num);
    }
    else if ((s->lists & ITS_POIM_FILT_LOAD) && poim_load_word(s, &load, &load_more))
    {
        sb_add(b, "%s %s", S(S_POIM_LOAD), S(load));
        more = more || load_more;
    }
    else if ((s->lists & ITS_POIM_FILT_STAY) && s->stay_kind <= 2)
        sb_add(b, "%s", S(STAY[s->stay_kind]));
    /* 3 and 4 count minutes, 5 and 6 are a point in time. Without its number only 4 still
     * says something true. On its own (3) the limit names the parking time. Behind the
     * charging word (4) it does not need to. */
    else if ((s->lists & ITS_POIM_FILT_STAY) && (s->stay_kind == 3 || s->stay_kind == 4) &&
             s->has_stay_num)
        sb_add(b, "%s%s%s %lu %s", s->stay_kind == 4 ? S(S_POIM_OT_CHARGING) : "",
               s->stay_kind == 4 ? ", " : "",
               S(s->stay_kind == 4 ? S_POIM_OT_MAX : S_POIM_OT_LIMIT), (unsigned long)s->stay_num,
               S(S_UNIT_MIN));
    else if ((s->lists & ITS_POIM_FILT_STAY) && s->stay_kind == 4)
        sb_add(b, "%s", S(S_POIM_OT_CHARGING));
    else if ((s->lists & ITS_POIM_FILT_STAY) && (s->stay_kind == 5 || s->stay_kind == 6) &&
             s->has_stay_num && fmt_when(s->stay_num, 0, FMT_YEAR, lang, when, sizeof when))
        sb_add(b, "%s %s", S(s->stay_kind == 5 ? S_POIM_OT_UNTIL : S_POIM_OT_FORCED), when);
    else if ((s->lists & ITS_POIM_FILT_FEE) && s->fee < 3)
        sb_add(b, "%s", S(FEE[s->fee]));
    else
    {
        sb_add(b, "%s", S(S_UNKNOWN));
        return;
    }
    /* The words for more lists already say "not this alone". An ellipsis beside them would
     * cost the longest detail line bytes it does not have. */
    if (n_lists > 1)
        sb_add(b, ", %s", S(S_POIM_MORE_COND));
    else if (more)
        sb_add(b, " &hellip;");
}

/* Vehicle height in steps of 5 cm. 126..128 get one text: the names and the comment of
 * VehicleHeight disagree about which of them means what. */
static void poim_height(sb_t *b, uint8_t h, lang_t lang)
{
    if (h >= 126)
    {
        sb_add(b, "%s", S(S_POIM_HEIGHT_OPEN));
        return;
    }
    unsigned cm = h * 5u;
    sb_add(b, "%s %u%s%02u m", S(S_POIM_HEIGHT), cm / 100, lang == LANG_DE ? "," : ".", cm % 100);
}

/* POIM (TS 103 916): parking facilities. The counts cover the whole message. Everything after
 * them is about the first facility, in the order a driver asks: open, room, when, where, and
 * its first area with that area's price. What could not be read comes last, as for the CPM. */
void poim_text(sb_t *b, const its_poim_t *p, lang_t lang)
{
    size_t m;
    if (p->wrong_version)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %u %s", S(S_POIM_VERSION), (unsigned)p->other_version, S(S_NOT_READ));
        item_end(b, m);
        return;
    }
    if (!p->read)
        return;
    /* A broken list may hide more facilities behind the break. */
    if (p->n_parking)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %s%s%u", S(S_POIM_PLACES), p->list_broken ? S(S_POIM_ATLEAST) : "",
               p->list_broken ? " " : "", (unsigned)p->n_parking);
        item_end(b, m);
    }
    /* A cut with nothing kept still says that a name came. */
    if (p->name_len || p->name_cut)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s: ", S(S_SREM_NAME));
        add_text_utf8_n(b, p->name, p->name_len < sizeof(p->name) ? p->name_len : sizeof(p->name),
                        p->name_cut, POIM_TEXT_OUT);
        item_end(b, m);
    }
    if (p->has_status && p->status <= 3)
    {
        static const str_id_t ST[4] = { S_POIM_ST_CLOSED, S_POIM_ST_OPEN, S_POIM_ST_SUBSCR,
                                        S_POIM_ST_FULL };
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(ST[p->status]));
        /* "Full" says no space is free, and 1 is the fewest NumberOfSpaces can carry. */
        if (p->status == 3 && p->occ.has_free && p->occ.n_free > 1 &&
            p->occ.n_free != ITS_POIM_SPACES_MAYBE_NA)
            sb_add(b, " (%s)", S(S_CONTRADICTS));
        item_end(b, m);
    }
    const its_poim_occ_t *o = &p->occ;
    bool own_spaces = o->has_free || o->has_total;
    bool occ_shown = own_spaces || o->has_rate || (o->has_trend && o->trend < 8);
    if (occ_shown)
    {
        m = item_begin(b, SEP);
        poim_occupancy(b, o, lang);
        item_end(b, m);
    }
    char when[FMT_WHEN_MAX];
    if (p->has_mgmt && fmt_when(p->time_s, 0, FMT_YEAR, lang, when, sizeof when))
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %s", S(S_TRUSTLIST_DATE), when);
        item_end(b, m);
    }
    /* A count for a kind of space, never "of them": a count for trucks is no part of the
     * total for cars. Without a number the filter alone would say nothing. How many counts
     * came is shown first, as for the areas. After the numbers it would read as more
     * spaces. */
    if (p->has_sub && (p->sub.occ.has_free || p->sub.occ.has_total))
    {
        m = item_begin(b, SEP);
        if (p->n_status > 1)
            sb_add(b, "%s %u, ", S(S_POIM_COUNTS), (unsigned)p->n_status);
        poim_filter(b, &p->sub, lang);
        sb_add(b, ": ");
        poim_spaces(b, &p->sub.occ, lang);
        item_end(b, m);
    }
    /* Local time of the facility without a zone, shown as sent, over midnight included. */
    if (p->has_period)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s ", S(S_EVCSN_HOURS));
        poim_days(b, p->days, lang);
        sb_add(b, " %02u:%02u&ndash;%02u:%02u", (unsigned)p->open_h, (unsigned)p->open_m,
               (unsigned)p->close_h, (unsigned)p->close_m);
        if (p->n_periods > 1)
            sb_add(b, " &hellip; %s", S(S_MORE));
        item_end(b, m);
    }
    /* The facility's position, not the sender's from the GN header in front of this line. */
    if (p->has_pos)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %.5f, %.5f", S(S_EVCSN_POS), p->lat_e7 / 1e7, p->lon_e7 / 1e7);
        if (p->has_alt)
        {
            /* AltitudeValue names its two ends "this or beyond". */
            int32_t cm = p->alt_cm;
            char alt[FMT_ALT_MAX];
            fmt_alt_cm(cm, lang, alt, sizeof alt);
            sb_add(b, " &middot; %s %s%s", S(S_LBL_ALT),
                   cm <= -100000 ? "&le;" : cm >= 800000 ? "&ge;" : "", alt);
        }
        item_end(b, m);
    }
    /* The spaces of the first area only stand in when the facility gave no spaces of its own: a
     * rate or a trend alone gives no count. The price is the area's, not the facility's
     * (ParkingArea.pricingInformation), so it stays inside the area. The decoder keeps it only
     * with the area. */
    if (p->n_areas)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %s%s%u", S(S_POIM_AREAS), p->areas_at_least ? S(S_POIM_ATLEAST) : "",
               p->areas_at_least ? " " : "", (unsigned)p->n_areas);
        if (p->has_area)
        {
            const char *sep = ": ";
            sb_add(b, ", %s %u", S(S_POIM_AREA), (unsigned)p->area_id);
            if (!own_spaces && (p->area_occ.has_free || p->area_occ.has_total))
            {
                sb_add(b, "%s", sep);
                poim_spaces(b, &p->area_occ, lang);
                sep = ", ";
            }
            if (p->level)
            {
                sb_add(b, "%s%s %+d", sep, S(S_POIM_LEVEL), (int)p->level);
                sep = ", ";
            }
            if (p->has_height && p->height >= 1 && p->height <= 128)
            {
                sb_add(b, "%s", sep);
                poim_height(b, p->height, lang);
                sep = ", ";
            }
            /* A cut with nothing kept still says that a price came. */
            if (p->price_len || p->price_cut)
            {
                sb_add(b, "%s%s ", sep, S(S_EVCSN_PRICE));
                add_text_utf8_n(b, p->price,
                                p->price_len < sizeof(p->price) ? p->price_len : sizeof(p->price),
                                p->price_cut, POIM_TEXT_OUT);
            }
        }
        item_end(b, m);
    }
    /* The IVIM content is not decoded, so only the count is shown. It comes before its word,
     * so it reads as a count and not as a number like the MAPEM reference behind it. That
     * reference is written the way add_intersection writes one. */
    if (p->n_ivim || p->has_map)
    {
        m = item_begin(b, SEP);
        if (p->n_ivim)
            sb_add(b, "%u %s%s", (unsigned)p->n_ivim, S(S_POIM_LINK_IVIM), p->has_map ? ", " : "");
        if (p->has_map)
        {
            sb_add(b, "%s ", S(p->map_intersection ? S_POIM_LINK_X : S_POIM_LINK_SEG));
            if (p->map_has_region)
                sb_add(b, "%u/", (unsigned)p->map_region);
            sb_add(b, "%u", (unsigned)p->map_id);
            if (p->n_mapem > 1)
                sb_add(b, " (+%u)", (unsigned)(p->n_mapem - 1u));
        }
        item_end(b, m);
    }
    /* n_related, the bare count of references to other entries, is left out. With it the
     * longest detail line would pass its byte budget. */
    /* The provider number is unique only with its country. The country stays the raw 10 bits
     * in hex: the letters need the ITA-2 table, which is not here. */
    if (p->has_mgmt)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %03X/%u, %s %s %u", S(S_POIM_PROVIDER), (unsigned)p->country,
               (unsigned)p->provider, S(S_POIM_ENTRY), S(S_SREM_REQ_NO), (unsigned)p->entry);
        item_end(b, m);
    }
    if (p->n_other_types)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(S_POIM_OTHER_KIND));
        for (uint8_t i = 0; i < p->n_other_types && i < ITS_POIM_OTHER_TYPES; i++)
            sb_add(b, "%s%ld", i ? ", " : " ", (long)p->other_type[i]);
        sb_add(b, "%s %s", p->other_more ? " &hellip;" : "", S(S_PERM_WHY_NOTREAD));
        item_end(b, m);
    }
    const struct { bool on; str_id_t id; } FLAG[] = {
        { p->engine_stop, S_POIM_ENGINE }, { p->broken, S_POIM_BROKEN },
        { p->list_broken, S_POIM_LIST_BROKEN }, { p->newer, S_POIM_NEWER },
        { p->out_of_range, S_POIM_OUT_OF_RANGE }, { p->tail_left, S_POIM_TAIL_LEFT },
    };
    for (size_t i = 0; i < sizeof(FLAG) / sizeof(FLAG[0]); i++)
        if (FLAG[i].on)
        {
            m = item_begin(b, SEP);
            sb_add(b, "%s", S(FLAG[i].id));
            item_end(b, m);
        }
}
