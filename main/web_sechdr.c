#include "web_sechdr.h"

#include <math.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#include "its_security.h"
#include "web_fmt.h"

/* A copy of the string writer sb_t of web_msgdetail.c. A host test cuts sb_t out of that file
 * and expects it there exactly once, so the two modules cannot share it through a header. */
typedef struct
{
    char  *s;
    size_t cap;
    size_t n;
    bool   full;                 /* Set by the first piece that did not fit. */
} sw_t;

#define SEP " &middot; "
/* The sign of PERM_WARN in web_msgdetail.c: the line has no colour, so the sign says it. */
#define SEC_WARN "&#9888; "
#define S(id) web_str((id), lang)
#define HAS(v, bit) (((v) & (bit)) != 0)

static void sw_add(sw_t *w, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void sw_add(sw_t *w, const char *fmt, ...)
{
    if (w->full)
        return;
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(w->s + w->n, w->cap - w->n, fmt, ap);
    va_end(ap);
    if (k < 0 || (size_t)k >= w->cap - w->n)
    {
        w->full = true;
        w->s[w->n] = '\0';
        return;
    }
    w->n += (size_t)k;
}

static size_t item_begin(sw_t *w)
{
    size_t mark = w->n;
    if (w->n)
        sw_add(w, "%s", SEP);
    return mark;
}

/* An item that did not fit is taken back whole, and nothing after it is tried. */
static void item_end(sw_t *w, size_t mark)
{
    if (w->full)
    {
        w->n = mark;
        w->s[mark] = '\0';
    }
}

/* The remarks of one item share one bracket, separated by commas. */
static void note(sw_t *w, int *k, const char *s)
{
    sw_add(w, "%s%s", (*k)++ ? ", " : " (", s);
}

static void notes_end(sw_t *w, int k)
{
    if (k)
        sw_add(w, ")");
}

static void warn_item(sw_t *w, const char *s)
{
    size_t m = item_begin(w);
    sw_add(w, "%s%s", SEC_WARN, s);
    item_end(w, m);
}

/* Unix seconds of a header time; false from 2106 on, where the 32-bit input of fmt_when ends
 * (UINT64_MAX, the "too far to convert" of its_sechdr.h, lands there too). */
static bool secs32(uint64_t us, uint32_t *s)
{
    if (us / 1000000u > UINT32_MAX)
        return false;
    *s = (uint32_t)(us / 1000000u);
    return true;
}

/* A header time as clock time. The date shows only when there is no reception stamp or the
 * stamp falls on another local day. */
static void add_when(sw_t *w, const its_sechdr_t *h, uint64_t us, lang_t lang)
{
    char when[FMT_WHEN_MAX];
    uint32_t s;
    unsigned fl = FMT_SEC | FMT_YEAR;
    if (!secs32(us, &s))
    {
        sw_add(w, "%s", S(S_SEC_TIME_FAR));
        return;
    }
    if (h->has_rx)
        fl |= FMT_SAMEDAY;
    fmt_when(s, h->has_rx ? (uint32_t)(h->rx_us / 1000000u) : 0, fl, lang, when, sizeof when);
    sw_add(w, "%s", when[0] ? when : S(S_UNKNOWN));
}

/* The signing time and, with a reception stamp, the gap to it. */
static void time_item(sw_t *w, const its_sechdr_t *h, lang_t lang)
{
    size_t m = item_begin(w);
    sw_add(w, "%s ", S(S_SEC_SIGNED));
    add_when(w, h, h->gen_us, lang);
    /* Past 2106 the words say enough. A gap of decades would add nothing. */
    uint32_t s;
    if (h->has_rx && secs32(h->gen_us, &s))
    {
        char gap[FMT_US_MAX];
        /* Reception minus signing. Under 50 us fmt_us prints "0,0 ms", so that gap reads as at
         * reception. From 50 us on the words say which came first. */
        bool before = h->rx_us >= h->gen_us;
        uint64_t us = before ? h->rx_us - h->gen_us : h->gen_us - h->rx_us;
        if (us < 50)
            sw_add(w, " (%s)", S(S_SEC_AT_RX));
        else
        {
            fmt_us(us, lang, gap, sizeof gap);
            sw_add(w, " (%s %s)", gap, S(before ? S_SEC_BEFORE_RX : S_SEC_AFTER_RX));
        }
    }
    item_end(w, m);
}

/* IEEE 1609.2 Elevation counts decimetres above -409.5 m, so raw 4095 is 0 m. */
static void add_elev(sw_t *w, uint16_t elev, lang_t lang)
{
    char alt[FMT_ALT_MAX];
    fmt_alt_cm(((int32_t)elev - 4095) * 10, lang, alt, sizeof alt);
    sw_add(w, "%s %s", S(S_LBL_ALT), alt);
}

/* Haversine on the mean earth radius. Double math is fine here, because only httpd and httpslow
 * call this module, never the 4 KB receive task. */
static double dist_m(int32_t la1, int32_t lo1, int32_t la2, int32_t lo2)
{
    const double rad = 3.14159265358979323846 / 180e7;
    double sp = sin((la2 - (double)la1) * rad / 2), sl = sin((lo2 - (double)lo1) * rad / 2);
    double a = sp * sp + cos(la1 * rad) * cos(la2 * rad) * sl * sl;
    return 2.0 * 6371000.0 * atan2(sqrt(a), sqrt(a < 1.0 ? 1.0 - a : 0.0));
}

static void add_dist(sw_t *w, double d, lang_t lang)
{
    unsigned long m = (unsigned long)(d + 0.5);
    if (m < 10000)
        sw_add(w, "%lu m", m);
    else
    {
        char km[24];
        fmt_dec(d / 1000.0, 1, false, lang, km, sizeof km);
        sw_add(w, "%s km", km);
    }
}

static void place_item(sw_t *w, const its_sechdr_t *h, lang_t lang)
{
    bool no = HAS(h->forbid, ITS_SEC_HDR_LOCATION);
    size_t m = item_begin(w);
    sw_add(w, "%s%s", no || h->loc == SEC_LOC_RANGE ? SEC_WARN : "", S(S_SEC_PLACE));
    if (no)
        sw_add(w, " (%s)", S(S_SEC_NOT_ALLOWED));
    sw_add(w, ": ");
    switch (h->loc)
    {
    case SEC_LOC_SAME:
        sw_add(w, "%s", S(S_SEC_AT_SENDER));
        break;
    case SEC_LOC_OTHER:
        sw_add(w, "%.5f, %.5f", h->lat_e7 / 1e7, h->lon_e7 / 1e7);
        if (h->has_ref)
        {
            sw_add(w, ", ");
            add_dist(w, dist_m(h->ref_lat_e7, h->ref_lon_e7, h->lat_e7, h->lon_e7), lang);
            sw_add(w, " %s", S(S_SEC_FROM_SENDER));
        }
        break;
    case SEC_LOC_RANGE:
        /* Numbers outside their type mean nothing, so none are shown. */
        sw_add(w, "%s", S(S_SEC_LOC_RANGE));
        break;
    default:
        sw_add(w, "%s", S(S_UNKNOWN));
        break;
    }
    sw_add(w, ", ");
    add_elev(w, h->elev, lang);
    /* The altitude from the message body beside it. 800001 means "unavailable". */
    if (h->has_msg_alt && h->msg_alt_cm != 800001)
    {
        char alt[FMT_ALT_MAX];
        fmt_alt_cm(h->msg_alt_cm, lang, alt, sizeof alt);
        sw_add(w, " (%s %s)", S(S_SEC_ALT_MSG), alt);
    }
    item_end(w, m);
}

static void expiry_item(sw_t *w, const its_sechdr_t *h, lang_t lang)
{
    bool order = HAS(h->dev, SEC_DEV_ORDER), no = HAS(h->forbid, ITS_SEC_HDR_EXPIRY_TIME);
    int k = 0;
    size_t m = item_begin(w);
    sw_add(w, "%s%s ", order || no ? SEC_WARN : "", S(S_SEC_EXPIRES));
    add_when(w, h, h->exp_us, lang);
    if (order)
        note(w, &k, S(S_SEC_NOT_AFTER));
    if (h->has_rx && h->rx_us > h->exp_us)
        note(w, &k, S(S_SEC_EXPIRED_RX));
    if (no)
        note(w, &k, S(S_SEC_NOT_ALLOWED));
    notes_end(w, k);
    item_end(w, m);
}

/* SHA-256 is the rule and goes unsaid. The other two are proper names in both languages. */
static void add_hash(sw_t *w, uint8_t id, lang_t lang)
{
    if (id == 1)
        sw_add(w, ", SHA-384");
    else if (id == 2)
        sw_add(w, ", SM3");
    else if (id != 0)
        sw_add(w, ", %s", S(S_SEC_HASH_UNKNOWN));
}

/* its_sec_key_t in words: the curve, or "implicit" for a key rebuilt from the certificate. */
static const char *key_word(uint8_t key, lang_t lang)
{
    const char *n = its_sec_alg_name(key);
    return n ? n : S(key == ITS_SEC_KEY_RECONSTRUCTION ? S_SEC_KEY_IMPLICIT : S_UNKNOWN);
}

static void alg_item(sw_t *w, const its_sechdr_t *h, uint8_t cache_key, lang_t lang)
{
    const char *sig = its_sec_alg_name(h->sig_type);
    bool bad = HAS(h->dev, SEC_DEV_ALG);
    uint8_t key = h->key_type != 0xFF ? h->key_type : cache_key;
    int k = 0;
    size_t m = item_begin(w);
    sw_add(w, "%s%s %s", bad ? SEC_WARN : "", S(S_SEC_ALG), sig ? sig : S(S_UNKNOWN));
    add_hash(w, h->hash_id, lang);
    /* its_sec_sig_t and its_sec_key_t share 0..4 (_Static_assert in its_security.c). Above
     * that the same number means another thing (key 5 implicit, signature 5 other). */
    if (key != 0xFF && (key > ITS_SEC_KEY_SM2 || key != h->sig_type))
    {
        note(w, &k, S(S_SEC_CERT_KEY));
        sw_add(w, ": %s", key_word(key, lang));
    }
    if (bad)
        note(w, &k, S(S_SEC_NOT_ALLOWED));
    notes_end(w, k);
    item_end(w, m);
}

/* One rare part: sign and "not allowed" when the profile forbids it here, and "unreadable" or
 * the number it carried (num < 0: none) in the same bracket. */
static void rare(sw_t *w, str_id_t id, bool no, bool unreadable, long num, lang_t lang)
{
    int k = 0;
    size_t m = item_begin(w);
    sw_add(w, "%s%s", no ? SEC_WARN : "", S(id));
    if (unreadable)
        note(w, &k, S(S_SEC_UNREADABLE));
    else if (num >= 0)
    {
        sw_add(w, " (%ld", num);
        k++;
    }
    if (no)
        note(w, &k, S(S_SEC_NOT_ALLOWED));
    notes_end(w, k);
    item_end(w, m);
}

static void rare_parts(sw_t *w, const its_sechdr_t *h, lang_t lang)
{
    uint16_t hd = h->hdr, fb = h->forbid;
    uint8_t x = h->xflags, c = h->contrib;
    if (HAS(hd, ITS_SEC_HDR_INLINE_P2PCD))
        rare(w, S_SEC_ASKS, HAS(fb, ITS_SEC_HDR_INLINE_P2PCD), HAS(x, ITS_SEC_X_INLINE_BAD),
             h->n_inline, lang);
    if (HAS(hd, ITS_SEC_HDR_P2PCD_LEARNING))
        rare(w, S_SEC_ASKS, HAS(fb, ITS_SEC_HDR_P2PCD_LEARNING), false, -1, lang);
    if (HAS(hd, ITS_SEC_HDR_REQUESTED_CERT))
        rare(w, S_SEC_SENDS_CA, HAS(fb, ITS_SEC_HDR_REQUESTED_CERT), HAS(x, ITS_SEC_X_REQCERT_BAD),
             -1, lang);
    if (HAS(hd, ITS_SEC_HDR_MISSING_CRL))
        rare(w, S_SEC_ASKS_CRL, HAS(fb, ITS_SEC_HDR_MISSING_CRL), false, -1, lang);
    if (HAS(hd, ITS_SEC_HDR_CONTRIBUTED_EXT))
    {
        if (HAS(c, ITS_SEC_C_CRL))
            rare(w, S_SEC_ASKS_CRL, false, false, -1, lang);
        if (HAS(c, ITS_SEC_C_CTL))
            rare(w, S_SEC_ASKS_CTL, false, false, -1, lang);
        /* The rest of the list, and the list itself when neither request above came of it.
         * A block the profile forbids is always one of the rest. */
        if (HAS(c, ITS_SEC_C_ETSI | ITS_SEC_C_FOREIGN | ITS_SEC_C_BAD) ||
            !HAS(c, ITS_SEC_C_CRL | ITS_SEC_C_CTL) || HAS(fb, ITS_SEC_HDR_CONTRIBUTED_EXT))
            rare(w, S_SEC_CONTRIB, HAS(fb, ITS_SEC_HDR_CONTRIBUTED_EXT), HAS(c, ITS_SEC_C_BAD),
                 -1, lang);
    }
    if (HAS(hd, ITS_SEC_HDR_ENCRYPTION_KEY))
        rare(w, S_SEC_ENC_KEY, HAS(fb, ITS_SEC_HDR_ENCRYPTION_KEY), false, -1, lang);
    if (HAS(hd, ITS_SEC_HDR_PDU_FUNCTIONAL))
        rare(w, S_SEC_PDU, HAS(fb, ITS_SEC_HDR_PDU_FUNCTIONAL), HAS(x, ITS_SEC_X_PDU_BAD),
             h->pdu_type, lang);
    /* Beside the data the hash is a second payload, which its_sechdr.c always forbids. */
    if (HAS(x, ITS_SEC_X_EXT_HASH))
        rare(w, h->has_data ? S_SEC_EXT_HASH_TOO : S_SEC_EXT_HASH, HAS(fb, SEC_FORBID_EXT_HASH),
             false, -1, lang);
    if (HAS(x, ITS_SEC_X_OMITTED))
        rare(w, S_SEC_OMITTED, HAS(fb, SEC_FORBID_OMITTED), false, -1, lang);
    if (HAS(x, ITS_SEC_X_EXT_OTHER))
        rare(w, S_SEC_EXT_OTHER, false, false, -1, lang);
}

size_t web_sechdr_append(const its_sechdr_t *h, uint8_t cache_key, lang_t lang,
                         char *out, size_t used, size_t cap)
{
    if (!out || !cap || used >= cap)
        return used;
    out[used] = '\0';
    if (!h || !h->read)
        return used;
    sw_t w = { out, cap, used, false };

    /* The deviations first, so a line that runs full keeps the warnings and drops details. */
    if (HAS(h->dev, SEC_DEV_PSID))
    {
        size_t m = item_begin(&w);
        sw_add(&w, "%s%s (%s %lu)", SEC_WARN, S(S_SEC_DEV_PSID), S(S_SEC_PSID_WANT),
               (unsigned long)h->want_psid);
        item_end(&w, m);
    }
    /* its_sechdr_fill sets at most one of these three, and else-if keeps it at one. */
    if (HAS(h->dev, SEC_DEV_SIGNER))
        warn_item(&w, S(S_SEC_DEV_SIGNER));
    else if (HAS(h->dev, SEC_DEV_DIGEST))
        warn_item(&w, S(S_SEC_DEV_DIGEST));
    else if (HAS(h->dev, SEC_DEV_CHAIN))
    {
        size_t m = item_begin(&w);
        sw_add(&w, "%s%u %s", SEC_WARN, (unsigned)h->cert_count, S(S_SEC_DEV_CHAIN));
        item_end(&w, m);
    }
    if (HAS(h->dev, SEC_DEV_TIME))
        warn_item(&w, S(S_SEC_DEV_TIME));
    if (HAS(h->dev, SEC_DEV_LOC))
        warn_item(&w, S(S_SEC_DEV_LOC));

    if (h->has_gen)
        time_item(&w, h, lang);
    if (HAS(h->hdr, ITS_SEC_HDR_LOCATION))
        place_item(&w, h, lang);
    if (h->has_exp)
        expiry_item(&w, h, lang);
    if (h->sig_type != 0xFF || h->hash_id != 0)
        alg_item(&w, h, cache_key, lang);
    rare_parts(&w, h, lang);
    return w.n;
}

size_t web_sechdr_unit(const its_sechdr_unit_t *u, lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    out[0] = '\0';
    if (!u)
        return 0;
    sw_t w = { out, cap, 0, false };
    bool sig = HAS(u->has, SEC_UNIT_SIG), key = HAS(u->has, SEC_UNIT_KEY);
    uint8_t hash = 0;
    if (HAS(u->has, SEC_UNIT_HASH))
        hash = u->hash_id;

    /* The algorithm item of the message line, without the verdicts: those are counted below. */
    if (sig || hash)
    {
        const char *n = sig ? its_sec_alg_name(u->sig_type) : NULL;
        size_t m = item_begin(&w);
        sw_add(&w, "%s %s", S(S_SEC_ALG), n ? n : S(S_UNKNOWN));
        add_hash(&w, hash, lang);
        /* Only 0..4 name the same curve in both types (see alg_item). */
        if (key && (!sig || u->key_type > ITS_SEC_KEY_SM2 || u->key_type != u->sig_type))
            sw_add(&w, " (%s: %s)", S(S_SEC_CERT_KEY), key_word(u->key_type, lang));
        item_end(&w, m);
    }
    if (HAS(u->has, SEC_UNIT_ELEV))
    {
        size_t m = item_begin(&w);
        add_elev(&w, u->elev, lang);
        item_end(&w, m);
    }
    if (u->dev_frames)
    {
        size_t m = item_begin(&w);
        sw_add(&w, "%s%s: %lu", SEC_WARN, S(S_SND_SEC_DEV), (unsigned long)u->dev_frames);
        item_end(&w, m);
    }
    return w.n;
}
