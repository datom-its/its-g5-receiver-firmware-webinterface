#include "web_msgdetail.h"
#include "web_msgdetail_priv.h"

void sb_add(sb_t *b, const char *fmt, ...)
{
    if (b->full)
        return;
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(b->s + b->n, b->cap - b->n, fmt, ap);
    va_end(ap);
    if (k < 0 || (size_t)k >= b->cap - b->n)
    {
        b->full = true;
        b->s[b->n] = '\0';
        return;
    }
    b->n += (size_t)k;
}

/* An item that does not fit completely is taken back as a whole. */
size_t item_begin(sb_t *b, const char *sep)
{
    size_t mark = b->n;
    if (b->n)
        sb_add(b, "%s", sep);
    return mark;
}

void item_end(sb_t *b, size_t mark)
{
    if (b->full)
    {
        b->n = mark;
        b->s[mark] = '\0';
    }
}


/* Frame text keeps letters, digits and a few safe marks. Other printable characters become
 * numeric entities and the rest a question mark, so nothing can end the markup or JSON string. */
void add_escaped(sb_t *b, const char *in)
{
    for (; *in && !b->full; in++)
    {
        unsigned char c = (unsigned char)*in;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == ' ' || c == '.' || c == '-' || c == '_' || c == '/' || c == ':' || c == '+' ||
            c == '?')
            sb_add(b, "%c", c);
        else if (c >= 0x20 && c < 0x7F)
            sb_add(b, "&#%u;", c);
        else
            sb_add(b, "?");
    }
}

/* 255 stands for a fully busy channel. One step is 0.4 %, so small loads keep a decimal. */
static void add_cbr(sb_t *b, uint8_t v, lang_t lang)
{
    unsigned tenths = (v * 1000u + 127u) / 255u;
    if (tenths % 10 == 0)
        sb_add(b, "%u %%", tenths / 10);
    else
        sb_add(b, "%u%c%u %%", tenths / 10, lang == LANG_DE ? ',' : '.', tenths % 10);
}

/* A power of 0 dBm is taken as not filled in, because so many senders leave it at 0. */
static void dcc_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    size_t m;
    if (x->dcc_tx_power_dbm)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %u dBm", S(S_DCC_TXPOWER), (unsigned)x->dcc_tx_power_dbm);
        item_end(b, m);
    }
    m = item_begin(b, SEP);
    sb_add(b, "%s ", S(S_DCC_CBR));
    add_cbr(b, x->dcc_cbr_r0, lang);
    if (x->dcc_cbr_r1)
    {
        sb_add(b, ", %s ", S(S_DCC_CBR_NEIGH));
        add_cbr(b, x->dcc_cbr_r1, lang);
    }
    item_end(b, m);
}

/* Short spans through fmt_us: ms below a second, then seconds with one decimal ("9,3 s"). */
void add_us(sb_t *b, uint32_t us, lang_t lang)
{
    char t[FMT_US_MAX];
    fmt_us(us, lang, t, sizeof t);
    sb_add(b, "%s", t);
}

/* StationType -> the road-user words of the statistics, one table for every page that uses
 * these words. It is a claim of the station, not a measurement. */
str_id_t web_msgdetail_station_cat(uint8_t st)
{
    switch (st)
    {
    case 1:                 return S_CAT_PED;
    case 2: case 3: case 4: return S_CAT_TWOWHEEL;
    case 5:                 return S_CAT_CAR;
    case 6:                 return S_CAT_BUS;
    case 7: case 8: case 9: return S_CAT_TRUCK;
    case 15:                return S_CAT_RSU;
    default:                return S_CAT_OTHER;
    }
}

/* MAPEM: the altitude of the intersection's reference point. Its lanes are drawn on /map. */
static void map_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    char alt[FMT_ALT_MAX];
    fmt_alt_cm(x->map_alt_cm, lang, alt, sizeof alt);
    size_t m = item_begin(b, SEP);
    sb_add(b, "%s %s", S(S_MAP_REF_ALT), alt);
    item_end(b, m);
}

/* RTCMEM: how many GNSS corrections the message carries, for which point, and what the
 * sending receiver says about itself. What the corrections MEAN stays unread. The ASN.1
 * hands their numbering to the GNSS receiver in the vehicle, and the RTCM standard that
 * would explain it is not at hand. So the line gives count, bytes and edition, and invents
 * nothing. */
static void rtcm_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    if (!x->rtcm_n_msgs)
        return;                  /* nothing was read, so nothing is claimed */
    size_t m = item_begin(b, SEP);
    sb_add(b, "%s %u &middot; %u %s", S(S_RTCM_CORR), (unsigned)x->rtcm_n_msgs,
           (unsigned)x->rtcm_bytes, S(S_UNIT_BYTES));
    item_end(b, m);

    m = item_begin(b, SEP);
    if (x->rtcm_rev == ITS_RTCM_REV_2 || x->rtcm_rev == ITS_RTCM_REV_3)
        sb_add(b, "RTCM %u", x->rtcm_rev == ITS_RTCM_REV_2 ? 2u : 3u);
    else if (x->rtcm_rev == ITS_RTCM_REV_UNKNOWN)
        sb_add(b, "%s", S(S_RTCM_REV_NONE));   /* the sender itself says it does not know */
    else
        sb_add(b, "%s", S(S_RTCM_REV_OTHER));
    item_end(b, m);

    if (x->rtcm_has_anchor)
    {
        /* The base station the corrections belong to, not the sender of the message. */
        size_t k = item_begin(b, SEP);
        /* Five decimals, same as the position on the message line, and a dot in both
         * languages: coordinates are written that way everywhere on this device. */
        sb_add(b, "%s %.5f, %.5f", S(S_RTCM_ANCHOR),
               x->rtcm_lat_e7 / 1e7, x->rtcm_lon_e7 / 1e7);
        if (x->rtcm_has_elev)
        {
            /* The decoder gives -4095..61439 dm, so times ten stays far inside int32. */
            char alt[FMT_ALT_MAX];
            fmt_alt_cm(x->rtcm_elev_dm * 10, lang, alt, sizeof alt);
            sb_add(b, " &middot; %s %s", S(S_LBL_ALT), alt);
        }
        item_end(b, k);
    }
    if (x->rtcm_has_status)
    {
        static const struct { uint8_t bit; str_id_t id; } ST[] = {
            { ITS_GNSS_UNAVAILABLE, S_GNSS_UNAVAIL },
            { ITS_GNSS_HEALTHY, S_GNSS_HEALTHY },
            { ITS_GNSS_MONITORED, S_GNSS_MONITORED },
            { ITS_GNSS_BASESTATION, S_GNSS_BASE },
            { ITS_GNSS_PDOP_UNDER5, S_GNSS_PDOP },
            { ITS_GNSS_INVIEW_UNDER5, S_GNSS_INVIEW },
            { ITS_GNSS_LOCAL_CORR, S_GNSS_LOCAL },
            { ITS_GNSS_NETWORK_CORR, S_GNSS_NETWORK },
        };
        for (size_t i = 0; i < sizeof(ST) / sizeof(ST[0]); i++)
            if (x->rtcm_status & ST[i].bit)
            {
                size_t k = item_begin(b, SEP);
                sb_add(b, "%s", S(ST[i].id));
                item_end(b, k);
            }
    }
    /* The counter and the minute only say whether something was missed, so they go last. */
    m = item_begin(b, SEP);
    sb_add(b, "%s %u", S(S_RTCM_CNT), (unsigned)x->rtcm_msg_cnt);
    item_end(b, m);
    if (x->rtcm_has_minute)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %lu", S(S_RTCM_MINUTE), (unsigned long)x->rtcm_minute);
        item_end(b, m);
    }
}

/* Italics mark where an air text starts and ends: a sender can type a middle dot or a quote
 * that looks like the page's own, but never a tag, since '<' is escaped. */
#define AIR_ON  "<i>"
#define AIR_OFF "</i>"

/* A text from the air or a sender name, for HTML AND for the JSON strings /messages puts them
 * into raw ("h", "sn"), sent in WebSocket text frames. Escaped are the five that mean
 * something in HTML, and the backslash: raw in that JSON string, a sender's "Mo\Fr" would
 * break the whole live list. add_escaped() above would turn every umlaut into '?', which is
 * right for certificate names and wrong for an address. */
static void add_utf8_core(sb_t *b, const char *t)
{
    while (*t && !b->full)
    {
        /* Air text has passed read_utf8 already, but a name read back from the SD card has
         * passed no check. A browser closes the whole WebSocket on one broken byte, and a
         * bidi control turns the rest of the line around. The NUL at the end fails the
         * bounds, so this never reads past the string. */
        const uint8_t *u = (const uint8_t *)t;
        uint8_t lo, hi;
        size_t w = its_utf8_lead(u[0], &lo, &hi);
        bool ok = w > 0;
        for (size_t j = 1; ok && j < w; j++)
            if (u[j] < (j == 1 ? lo : 0x80) || u[j] > (j == 1 ? hi : 0xBF))
                ok = false;
        if (!ok || its_utf8_unshown(its_utf8_cp(u, w)))
        {
            sb_add(b, "?");
            t += ok ? w : 1;
            continue;
        }
        if (w > 1)
        {
            sb_add(b, "%.*s", (int)w, t);
            t += w;
            continue;
        }
        switch (*t)
        {
        case '&':  sb_add(b, "&amp;");  break;
        case '<':  sb_add(b, "&lt;");   break;
        case '>':  sb_add(b, "&gt;");   break;
        case '"':  sb_add(b, "&quot;"); break;
        case '\'': sb_add(b, "&#39;");  break;
        case '\\': sb_add(b, "&#92;");  break;
        default:   sb_add(b, "%c", *t); break;
        }
        t++;
    }
}

static void add_text_utf8(sb_t *b, const char *t)
{
    sb_add(b, AIR_ON);
    add_utf8_core(b, t);
    sb_add(b, AIR_OFF);
}

size_t web_msgdetail_escape(const char *in, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    sb_t b = { out, cap, 0, false };
    out[0] = '\0';
    add_utf8_core(&b, in ? in : "");
    return b.n;
}

/* EVCSN: charging stations. The count first, then the first station with what a driver
 * wants to know: where it is, whether he may use it, when, what it costs, how it charges. */
static void evcsn_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    if (!x->evcsn_read)
        return;
    size_t m = item_begin(b, SEP);
    /* More stations in the message than the sender says it has is a contradiction of his. */
    sb_add(b, "%s %u", S(S_EVCSN_STATIONS), (unsigned)x->evcsn_n_total);
    if (x->evcsn_n_stations != x->evcsn_n_total)
    {
        sb_add(b, " (%s %u", S(S_LBL_HERE), (unsigned)x->evcsn_n_stations);
        if (x->evcsn_n_stations > x->evcsn_n_total)
            sb_add(b, ", %s", S(S_CONTRADICTS));
        sb_add(b, ")");
    }
    item_end(b, m);
    if (!x->evcsn_n_spots)
        return;                  /* the first station could not be read to its end */
    m = item_begin(b, SEP);
    sb_add(b, "%s %lu", S(S_EVCSN_STATION), (unsigned long)x->evcsn_st_id);
    item_end(b, m);
    if (x->evcsn_has_pos)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s %.5f, %.5f", S(S_EVCSN_POS), x->evcsn_lat_e7 / 1e7, x->evcsn_lon_e7 / 1e7);
        item_end(b, m);
    }
    static const struct { str_id_t id; size_t off; } TXT[] = {
        { S_EVCSN_ACCESS, offsetof(msg_extra_t, evcsn_access) },
        { S_EVCSN_HOURS, offsetof(msg_extra_t, evcsn_hours) },
        { S_EVCSN_PRICE, offsetof(msg_extra_t, evcsn_price) },
    };
    for (size_t i = 0; i < sizeof(TXT) / sizeof(TXT[0]); i++)
    {
        const char *t = (const char *)x + TXT[i].off;
        if (!t[0])
            continue;
        m = item_begin(b, SEP);
        sb_add(b, "%s ", S(TXT[i].id));
        add_text_utf8(b, t);
        item_end(b, m);
    }
    m = item_begin(b, SEP);
    sb_add(b, "%s %u", S(S_EVCSN_SPOTS), (unsigned)x->evcsn_n_spots);
    item_end(b, m);
    static const struct { uint8_t bit; str_id_t id; } MODE[] = {
        { ITS_EVCS_MODE1, S_EVCS_MODE1 }, { ITS_EVCS_MODE2, S_EVCS_MODE2 },
        { ITS_EVCS_MODE3, S_EVCS_MODE3 }, { ITS_EVCS_FAST_EXT, S_EVCS_FAST_EXT },
        { ITS_EVCS_QUICKDROP, S_EVCS_QUICKDROP }, { ITS_EVCS_INDUCT_STAND, S_EVCS_INDUCT_STAND },
        { ITS_EVCS_INDUCT_DRIVE, S_EVCS_INDUCT_DRIVE },
    };
    for (size_t i = 0; i < sizeof(MODE) / sizeof(MODE[0]); i++)
        if (x->evcsn_modes & (1u << MODE[i].bit))
        {
            m = item_begin(b, SEP);
            sb_add(b, "%s", S(MODE[i].id));
            item_end(b, m);
        }
    if (x->evcsn_relay)
    {
        m = item_begin(b, SEP);
        sb_add(b, "%s", S(S_EVCSN_RELAY));
        item_end(b, m);
    }
}

/* add_text_utf8 for a text with a length and no NUL: a NUL inside becomes '?' instead of
 * ending it. The output stops before the whole character or entity that would pass `max`,
 * and an ellipsis marks that cut as it marks the decoder's own (`cut`). */
void add_text_utf8_n(sb_t *b, const char *t, size_t len, bool cut, size_t max)
{
    size_t shown = 0;
    sb_add(b, AIR_ON);
    for (size_t i = 0; i < len && !b->full;)
    {
        /* The checks of add_text_utf8, bounded by the length instead of the NUL. A broken
         * piece is one '?' per maximal subpart (Unicode D93b), as read_utf8 makes it for EVCSN. */
        const uint8_t *u = (const uint8_t *)t + i;
        uint8_t lo, hi;
        size_t w = its_utf8_lead(u[0], &lo, &hi);
        size_t got = 1;
        while (got < w && got < len - i && u[got] >= (got == 1 ? lo : 0x80) &&
               u[got] <= (got == 1 ? hi : 0xBF))
            got++;
        bool ok = w > 0 && got == w;
        const char *piece = t + i;
        size_t n = 1, step = got;
        if (!ok || its_utf8_unshown(its_utf8_cp(u, w)))
            piece = "?";
        else if (w > 1)
            n = w;
        else
        {
            switch (u[0])
            {
            case '&':  piece = "&amp;";  n = 5; break;
            case '<':  piece = "&lt;";   n = 4; break;
            case '>':  piece = "&gt;";   n = 4; break;
            case '"':  piece = "&quot;"; n = 6; break;
            case '\'': piece = "&#39;";  n = 5; break;
            case '\\': piece = "&#92;";  n = 5; break;
            default:   break;
            }
        }
        if (shown + n > max)
        {
            cut = true;
            break;
        }
        sb_add(b, "%.*s", (int)n, piece);
        shown += n;
        i += step;
    }
    /* The raw U+2026, 3 bytes against 8 for the entity, as read_utf8 marks a cut EVCSN text:
     * the longest detail line needs those bytes. */
    if (cut)
        sb_add(b, "\xE2\x80\xA6");
    sb_add(b, AIR_OFF);
}

/* Distances a and b run from the centre to the edge, so a rectangle or an ellipse spans
 * twice as much (EN 302 931). The same shape as the area line on /traffic. */
static void area_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    size_t m = item_begin(b, SEP);
    if (x->area_shape == ITS_GN_AREA_CIRCLE)
        sb_add(b, "%s: %s %u m", S(S_AREA_TARGET), S(S_AREA_CIRCLE), (unsigned)x->area_a_m);
    else
        sb_add(b, "%s: %s %lu &times; %lu m, %u&deg;", S(S_AREA_TARGET),
               S(x->area_shape == ITS_GN_AREA_RECT ? S_AREA_RECT : S_AREA_ELLIPSE),
               2ul * x->area_a_m, 2ul * x->area_b_m, (unsigned)x->area_angle_deg);
    item_end(b, m);
}

/* What the message says, the first half of a detail line. */
static void content_parts(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    if (x->prio.message_id == 9 || x->prio.message_id == 10)
        prio_text(b, &x->prio, lang);
    /* IVIM and SAEM: the body is not decoded, so the line says so instead of staying empty. */
    if (x->message_id == 6 || x->message_id == 12)
    {
        size_t m = item_begin(b, SEP);
        if (x->message_id == 12 && x->saem_wrong_version)
            sb_add(b, "%s %u %s", S(S_SAEM_VERSION), (unsigned)x->saem_other_version,
                   S(S_NOT_READ));
        else
            sb_add(b, "%s", S(x->message_id == 6 ? S_IVIM_NOTE : S_SAEM_NOTE));
        item_end(b, m);
    }
    if (x->message_id == 1)
        denm_text(b, x, lang);
    if (x->message_id == 13)
        rtcm_text(b, x, lang);
    if (x->message_id == 5 && x->map_has_alt)
        map_text(b, x, lang);
    if (x->message_id == 14)
        cpm_text(b, x, lang);
    /* By what was read, not by the number: an old EVCSN also comes as messageId 3, version 0. */
    if (x->evcsn_read)
        evcsn_text(b, x, lang);
    if (x->poim.read || x->poim.wrong_version)
        poim_text(b, &x->poim, lang);
    if (x->area_shape >= ITS_GN_AREA_CIRCLE && x->area_shape <= ITS_GN_AREA_ELLIPSE)
        area_text(b, x, lang);
    if (x->has_dcc)
        dcc_text(b, x, lang);
}

size_t web_msgdetail_append(const msg_extra_t *x, const uint8_t *src_mac,
                            const its_certcache_entry_t *cc, lang_t lang,
                            char *out, size_t used, size_t cap)
{
    if (!out || !cap || used >= cap)
        return used;
    sb_t b = { out, cap, used, false };
    out[used] = '\0';
    content_parts(&b, x, lang);
    sign_parts(&b, x, src_mac, cc, lang);
    return b.n;
}

size_t web_msgdetail_append_content(const msg_extra_t *x, lang_t lang,
                                    char *out, size_t used, size_t cap)
{
    if (!out || !cap || used >= cap)
        return used;
    sb_t b = { out, cap, used, false };
    out[used] = '\0';
    content_parts(&b, x, lang);
    return b.n;
}

size_t web_msgdetail_radio(uint8_t tx_power_dbm, uint8_t cbr_max, lang_t lang,
                           char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    sb_t b = { out, cap, 0, false };
    out[0] = '\0';
    if (tx_power_dbm)
        sb_add(&b, "%s %u dBm, ", S(S_DCC_TXPOWER), (unsigned)tx_power_dbm);
    sb_add(&b, "%s ", S(S_DCC_CBR_MAX));
    add_cbr(&b, cbr_max, lang);
    item_end(&b, 0);
    return b.n;
}
