#include "web_msgdetail.h"

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#include "its_crl.h"
#include "its_utf8.h"
#include "its_trustlist.h"
#include "web_fmt.h"
#include "web_gn.h"
#include "web_msgsig.h"
#include "web_sechdr.h"

typedef struct
{
    char  *s;
    size_t cap;
    size_t n;
    bool   full;                 /* Set by the first piece that did not fit. */
} sb_t;

static void sb_add(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void sb_add(sb_t *b, const char *fmt, ...)
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
static size_t item_begin(sb_t *b, const char *sep)
{
    size_t mark = b->n;
    if (b->n)
        sb_add(b, "%s", sep);
    return mark;
}

static void item_end(sb_t *b, size_t mark)
{
    if (b->full)
    {
        b->n = mark;
        b->s[mark] = '\0';
    }
}

#define SEP " &middot; "
#define S(id) web_str((id), lang)

/* Frame text keeps letters, digits and a few safe marks. Other printable characters become
 * numeric entities and the rest a question mark, so nothing can end the markup or JSON string. */
static void add_escaped(sb_t *b, const char *in)
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

static void add_id(sb_t *b, const uint8_t *id)
{
    sb_add(b, "%02x%02x%02x%02x&hellip;", id[0], id[1], id[2], id[3]);
}

/* Vehicle stacks often derive the MAC from the last 6 bytes of the HashedId8 and change the two
 * lowest bits of the first byte to mark a local unicast address. This is a hint, no check. */
static bool mac_matches(const uint8_t *id, const uint8_t *mac)
{
    return mac && ((mac[0] ^ id[2]) & 0xFC) == 0 && memcmp(mac + 1, id + 3, 5) == 0;
}

static void sig_text(sb_t *b, const its_sig_summary_t *g, const uint8_t *mac, lang_t lang)
{
    switch (g->kind)
    {
    case ITS_SIG_UNSIGNED:
        sb_add(b, "%s", S(S_SIG_UNSIGNED));
        return;
    case ITS_SIG_OTHER:
        sb_add(b, "%s", S(S_SIG_OTHER));
        return;
    case ITS_SIG_DIGEST:
        sb_add(b, "%s", S(S_SIG_DIGEST));
        break;
    case ITS_SIG_CERT:
        sb_add(b, "%s", S(S_SIG_CERT));
        break;
    default:
        return;
    }
    if (g->has_id)
    {
        sb_add(b, " ");
        add_id(b, g->id);
    }

    /* The remarks go into one parenthesis, separated by commas. */
    int notes = 0;
    const char *open = " (";
    if (!g->has_id)
        sb_add(b, "%s%s", notes++ ? ", " : open, S(S_SIG_ID_UNKNOWN));
    if (g->kind == ITS_SIG_DIGEST && g->cert == ITS_CERT_KNOWN)
        sb_add(b, "%s%s", notes++ ? ", " : open, S(S_SIG_KNOWN));
    else if (g->kind == ITS_SIG_DIGEST && g->cert == ITS_CERT_MISSING)
        sb_add(b, "%s%s", notes++ ? ", " : open, S(S_SIG_MISSING));
    if (g->has_issuer)
    {
        sb_add(b, "%s%s ", notes++ ? ", " : open, S(S_SIG_ISSUER));
        add_id(b, g->issuer_id);
    }
    if (g->has_id && mac_matches(g->id, mac))
        sb_add(b, "%s%s", notes++ ? ", " : open, S(S_SIG_MAC));
    if (notes)
        sb_add(b, ")");
}

/* Never called with 0, which means no time at all rather than the start of 2004. */
static void add_day(sb_t *b, uint32_t t32, lang_t lang)
{
    char day[WEB_DAY_MAX];
    web_day_str(t32, lang, day, sizeof(day));
    sb_add(b, "%s", day);
}

/* The lock stands beside the word, never instead of it. */
#define TRUST_LOCK "&#128274;"
/* A withdrawn certificate is the one verdict that needs colour: every signature in its chain
 * matched, so the bare word would read like one more detail instead of a refusal. */
#define TRUST_STOP_ON  "<span style='color:var(--alarm)'>&#9940; "
#define TRUST_STOP_OFF "</span>"

static str_id_t why_name(uint8_t why)
{
    switch (why)
    {
    case ITS_VERIFY_WHY_PARSE:    return S_TRUST_WHY_PARSE;
    case ITS_VERIFY_WHY_LONG:     return S_TRUST_WHY_LONG;
    case ITS_VERIFY_WHY_IMPLICIT: return S_TRUST_WHY_IMPLICIT;
    case ITS_VERIFY_WHY_NONCANON: return S_TRUST_WHY_FORM;
    case ITS_VERIFY_WHY_ISSUER:   return S_TRUST_WHY_ISSUER;
    case ITS_VERIFY_WHY_ROOT:     return S_TRUST_WHY_ROOT;
    case ITS_VERIFY_WHY_CURVE:    return S_TRUST_WHY_CURVE;
    case ITS_VERIFY_WHY_CRYPTO:   return S_TRUST_WHY_CRYPTO;
    case ITS_VERIFY_WHY_CHAIN:    return S_TRUST_WHY_CHAIN;
    case ITS_VERIFY_WHY_EXPIRED:  return S_TRUST_WHY_EXPIRED;
    case ITS_VERIFY_WHY_NOTYET:   return S_TRUST_WHY_NOTYET;
    case ITS_VERIFY_WHY_NOPERIOD: return S_TRUST_WHY_NOPERIOD;
    case ITS_VERIFY_WHY_CLOCK:    return S_TRUST_WHY_CLOCK;
    case ITS_VERIFY_WHY_NOISSUE:  return S_TRUST_WHY_NOISSUE;
    case ITS_VERIFY_WHY_NOPERM:   return S_TRUST_WHY_NOPERM;
    case ITS_VERIFY_WHY_DEEP:     return S_TRUST_WHY_DEEP;
    case ITS_VERIFY_WHY_PERMFORM: return S_TRUST_WHY_PERMFORM;
    default:                      return S_TRUST_WHY_OTHER;
    }
}

/* With `names` the root and the issuer are named, otherwise the trust list and the number of
 * signatures. Both names come out of received certificates, so they are escaped. */
static void trust_text(sb_t *b, const its_certcache_entry_t *e, bool names, lang_t lang)
{
    switch (e->verify)
    {
    case ITS_VERIFY_CHECKED:
        sb_add(b, "%s %s", TRUST_LOCK, S(S_TRUST_YES));
        if (names)
        {
            if (!e->root_name[0])
                break;
            sb_add(b, " (");
            add_escaped(b, e->root_name);
            if (e->issuer_name[0] && strcmp(e->issuer_name, e->root_name) != 0)
            {
                sb_add(b, ", ");
                add_escaped(b, e->issuer_name);
            }
            sb_add(b, ")");
            if (e->issuer_from == ITS_VERIFY_ISSUER_BUILTIN)
                sb_add(b, "%s%s", SEP, S(S_TRUST_FROM_STORE));
            else if (e->issuer_from == ITS_VERIFY_ISSUER_ROOT)
                sb_add(b, "%s%s", SEP, S(S_TRUST_SRC_ROOT));
            break;
        }
        if (e->verify_env < ITS_TRUST_ENV_COUNT)
            sb_add(b, "%s%s %s", SEP, S(S_TRUST_LIST), its_trustlist_env_name(e->verify_env));
        if (e->verify_chain)
            sb_add(b, "%s%s %u", SEP, S(S_TRUST_CHAIN), (unsigned)e->verify_chain);
        break;
    case ITS_VERIFY_UNCHECKABLE:
        sb_add(b, "%s: %s", S(S_TRUST_NOCHECK), S(why_name(e->verify_why)));
        break;
    case ITS_VERIFY_INVALID:
        if (e->verify_why == ITS_VERIFY_WHY_NONE)
            sb_add(b, "%s", S(S_TRUST_SIG_INVALID));
        else
            sb_add(b, "%s: %s", S(S_TRUST_INVALID), S(why_name(e->verify_why)));
        break;
    case ITS_VERIFY_REVOKED:
        sb_add(b, "%s%s%s", TRUST_STOP_ON, S(S_TRUST_REVOKED), TRUST_STOP_OFF);
        /* The date of the list that names THIS certificate, the same one /trust shows in its
         * table. The oldest date over all lists belongs to another root and is years off. */
        {
            size_t li;
            its_crl_list_t cl;
            if (its_crl_list_of(e->id, NULL, &li) && its_crl_list_at(li, &cl) && cl.this_update)
            {
                sb_add(b, " (%s ", S(S_CRL_DATE_PRE));
                add_day(b, cl.this_update, lang);
                sb_add(b, ")");
            }
        }
        break;
    default:
        sb_add(b, "%s", S(S_TRUST_UNCHECKED));
        break;
    }
}

/* The sign repeats what the words already say, because the line carries no colour. */
#define PERM_WARN "&#9888; "

/* The seven special containers of a CAM carry the same seven meanings as the vehicle roles,
 * so they read with the same words. The table starts at ITS_CAM_SVC_PT. */
static str_id_t cam_cont_name(uint8_t svc)
{
    static const str_id_t CONT[] = {
        S_BVR_PUBLIC, S_BVR_SPECIAL, S_BVR_DANGEROUS, S_BVR_ROADWORK,
        S_BVR_RESCUE, S_BVR_EMERGENCY, S_BVR_SAFETYCAR,
    };
    return svc >= ITS_CAM_SVC_PT && svc <= ITS_CAM_SVC_SAFETYCAR
               ? CONT[svc - ITS_CAM_SVC_PT] : S_UNKNOWN;
}

/* Defined further down with the other request texts, because the role table is there. */
static str_id_t role_name(uint8_t role);

/* What the content answer was held against, in a few words. The verdict itself comes before
 * this text, so this only names the rule and the number it looked at. For an answer that
 * stayed open it also names what was missing. Nothing here may read as a no: what the
 * standard does not settle is unknown, and that difference is the whole point of the item. */
static void perm_why(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    bool stayed_open = x->perm_cont == ITS_PERM_CONT_UNKNOWN;
    /* Which gap left the answer open. A digest names a certificate the frame did not carry.
     * The store has its bits only for services an earlier frame showed, so under a digest
     * the bits are what is missing. With the certificate at hand the bytes are there, but
     * the bit for this one thing is not: either the standard defines none or the bitmap
     * ends before it. */
    str_id_t gap = x->sig.kind == ITS_SIG_DIGEST ? S_PERM_WHY_NOBITS : S_PERM_WHY_NOBIT;
    switch (x->perm_by)
    {
    case ITS_PERM_BY_SSP_NONE:
        sb_add(b, "%s", S(S_PERM_WHY_SSP_NONE));
        return;
    case ITS_PERM_BY_SSP_VER:
        sb_add(b, "%s", S(S_PERM_WHY_SSP_VER));
        return;
    case ITS_PERM_BY_SSP_FORM:
        sb_add(b, "%s", S(S_PERM_WHY_SSP_FORM));
        return;
    case ITS_PERM_BY_DENM_CAUSE:
        sb_add(b, "%s ", S(S_PERM_WHY_CAUSE));
        if (!x->perm_detail)
        {
            sb_add(b, "%s", S(S_PERM_WHY_NOTREAD));  /* no cause in the message */
            return;
        }
        sb_add(b, "%u", (unsigned)x->perm_detail);
        if (stayed_open)
            sb_add(b, ", %s", S(gap));
        return;
    case ITS_PERM_BY_CAM_CONT:
        sb_add(b, "%s ", S(S_PERM_WHY_EXTRA));
        if (x->perm_detail == ITS_CAM_SVC_UNREAD)
        {
            sb_add(b, "%s", S(S_PERM_WHY_NOTREAD));
            return;
        }
        /* An extension container has no bit of its own, so its name is unknown as well and
         * the missing bit needs no second sentence. */
        sb_add(b, "%s", S(cam_cont_name(x->perm_detail)));
        if (stayed_open && x->perm_detail != ITS_CAM_SVC_EXT)
            sb_add(b, ", %s", S(gap));
        return;
    case ITS_PERM_BY_CAM_ZONE:
        sb_add(b, "%s", S(S_PERM_WHY_ZONE));
        if (stayed_open)
            sb_add(b, ", %s", S(gap));
        return;
    case ITS_PERM_BY_SREM_ROLE:
    {
        /* The word for a role that has no name of its own already carries the word role, so
         * the label in front of it would only repeat itself. */
        str_id_t role = role_name(x->perm_detail);
        if (role == S_BVR_OTHER)
            sb_add(b, "%s", S(role));
        else
            sb_add(b, "%s %s", S(S_PERM_WHY_ROLE), S(role));
        if (stayed_open)
            sb_add(b, ", %s", S(gap));
        return;
    }
    case ITS_PERM_BY_CONTENT:
        /* Only called when the answer stayed open. Detail 1 means the bits were at hand and
         * the message was read only in part. Under a digest, detail 0 names the missing bits,
         * although content_check also gives an unread body 0. */
        sb_add(b, "%s", S(x->perm_detail ? S_PERM_WHY_PART
                          : x->sig.kind == ITS_SIG_DIGEST ? gap : S_PERM_WHY_NOTREAD));
        return;
    case ITS_PERM_BY_SERVICE:
        /* Only the SSEM (637) has no bits, so there the version is the whole rule. A yes for
         * any other service means its bits exist and the message carried nothing they govern. */
        if (stayed_open)
            sb_add(b, "%s", S(S_PERM_WHY_SERVICE));
        else
            sb_add(b, "%s", S(x->perm_psid == 637 ? S_PERM_WHY_VERONLY : S_PERM_WHY_NOTHING));
        return;
    default:
        /* A service rule, which never decides a content answer, or a rule a later firmware
         * adds without a text here. */
        sb_add(b, "%s", S(S_PERM_WHY_UNCHECKED));
        return;
    }
}

/* Whether the certificate lists the service of the message (its PSID). A statement of its own:
 * it says nothing about the signature, and the content follows as a second item. */
static void perm_svc_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    if (x->perm_svc == ITS_PERM_BAD)
        sb_add(b, "%s%s", PERM_WARN, S(S_PERM_BAD));
    else
        sb_add(b, "%s", S(x->perm_svc == ITS_PERM_OK ? S_PERM_OK : S_PERM_UNKNOWN));
    if (x->perm_psid)
        sb_add(b, " (PSID %lu)", (unsigned long)x->perm_psid);
}

/* Whether the bits beside that PSID allow what the message carries. Only said after a yes for
 * the service: without it there are no bits to hold the content against. */
static void perm_cont_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    bool open = x->perm_cont == ITS_PERM_CONT_UNKNOWN;
    if (x->perm_cont == ITS_PERM_CONT_BAD)
        sb_add(b, "%s%s", PERM_WARN, S(S_PERM_CONT_BAD));
    else
        sb_add(b, "%s", S(open ? S_PERM_CONT_UNKNOWN : S_PERM_CONT_OK));
    /* A rule this build has no words for keeps the bare verdict unless it stayed open, and so
     * does a decided content rule, whose name would only repeat the word in front. */
    bool known = x->perm_by >= ITS_PERM_BY_SSP_NONE && x->perm_by <= ITS_PERM_BY_SERVICE;
    if (open || (known && x->perm_by != ITS_PERM_BY_CONTENT))
    {
        sb_add(b, " (");
        perm_why(b, x, lang);
        sb_add(b, ")");
    }
}

/* A frame without a signer gets no permission item at all, because there is no certificate
 * whose permission could be meant. */
static bool perm_worth_saying(const msg_extra_t *x)
{
    return x->perm_svc != ITS_PERM_UNKNOWN || x->perm_psid ||
           x->sig.kind == ITS_SIG_CERT || x->sig.kind == ITS_SIG_DIGEST;
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

/* Hours from 2 h and minutes from 2 min when exact, seconds otherwise, with a no-break space
 * before the unit (fmt_dur). */
static void add_duration(sb_t *b, uint32_t s)
{
    char d[FMT_DUR_MAX];
    fmt_dur(s, FMT_DUR_EXACT, d, sizeof d);
    sb_add(b, "%s", d);
}

/* Short spans through fmt_us: ms below a second, then seconds with one decimal ("9,3 s"). */
static void add_us(sb_t *b, uint32_t us, lang_t lang)
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

static void denm_text(sb_t *b, const msg_extra_t *x, lang_t lang)
{
    if (x->denm_termination == ITS_DENM_TERM_CANCELLATION ||
        x->denm_termination == ITS_DENM_TERM_NEGATION)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s", S(x->denm_termination == ITS_DENM_TERM_CANCELLATION
                          ? S_DENM_CANCEL : S_DENM_NEGATE));
        item_end(b, m);
    }
    if (x->denm_validity_s)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s ", S(S_DENM_VALID));
        add_duration(b, x->denm_validity_s);
        if (!x->denm_validity_sent)
            sb_add(b, " (%s)", S(S_DENM_DEFAULT));
        item_end(b, m);
    }
    /* How far from the spot the warning is meant to matter. The steps are fixed, so the
     * distance is printed from the step, not from a number in the message. */
    if (x->denm_aware_dist <= ITS_DENM_DIST_OVER)
    {
        static const char *const STEP[] = { "50 m", "100 m", "200 m", "500 m",
                                            "1 km", "5 km", "10 km" };
        size_t m = item_begin(b, SEP);
        if (x->denm_aware_dist == ITS_DENM_DIST_OVER)
            sb_add(b, "%s", S(S_DENM_DIST_OVER));
        else
            sb_add(b, "%s %s", S(S_DENM_AWARE), STEP[x->denm_aware_dist]);
        item_end(b, m);
    }
    if (x->denm_traffic_dir <= ITS_DENM_DIR_OPPOSITE)
    {
        static const str_id_t DIR[] = { S_DENM_DIR_ALL, S_DENM_DIR_UP,
                                        S_DENM_DIR_DOWN, S_DENM_DIR_OPP };
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %s", S(S_DENM_DIR), S(DIR[x->denm_traffic_dir]));
        item_end(b, m);
    }
    if (x->denm_road_type <= ITS_DENM_ROAD_RURAL_SEP)
    {
        static const str_id_t ROAD[] = { S_DENM_ROAD_UO, S_DENM_ROAD_US,
                                         S_DENM_ROAD_FO, S_DENM_ROAD_FS };
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s", S(ROAD[x->denm_road_type]));
        item_end(b, m);
    }
    /* InformationQuality counts 1 (lowest) to 7 (highest). 0 means the sender did not say,
     * and "0/7" would read as a judgement it never made. */
    if (x->denm_quality >= 1 && x->denm_quality <= 7)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u/7", S(S_DENM_QUALITY), (unsigned)x->denm_quality);
        item_end(b, m);
    }
    if (x->denm_has_speed)
    {
        /* 0.01 m/s on the wire, and 3.6/100 turns it into km/h. */
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u km/h", S(S_DENM_AT_SPEED),
               (unsigned)((x->denm_speed_cms * 36u + 500u) / 1000u));
        item_end(b, m);
    }
    if (x->denm_has_heading)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u&deg;", S(S_DENM_AT_DIR), (unsigned)(x->denm_heading_ddeg / 10));
        item_end(b, m);
    }
    if (x->denm_has_alt)
    {
        char alt[FMT_ALT_MAX];
        fmt_alt_cm(x->denm_alt_cm, lang, alt, sizeof alt);
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %s", S(S_LBL_ALT), alt);
        item_end(b, m);
    }
    if (x->denm_tx_interval_ms)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s ", S(S_DENM_REPEAT));
        /* 1..10000 ms by TS 102 894-2, but the 14 bits let up to 16384 through: ms below a
         * second, then seconds with one decimal ("16,4 s" at most). */
        add_us(b, (uint32_t)x->denm_tx_interval_ms * 1000u, lang);
        item_end(b, m);
    }
    /* The points of the first trace as sent (up to 40), not the 8 the decoder keeps. */
    if (x->denm_path_len)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u %s", S(S_DENM_ZONE), (unsigned)x->denm_path_len,
               S(x->denm_path_len == 1 ? S_DENM_POINT : S_DENM_POINTS));
        if (x->denm_n_traces > 1)
            sb_add(b, " (1/%u)", (unsigned)x->denm_n_traces);
        item_end(b, m);
    }
    /* eventZone (eventHistory before 2.x): how far the spot itself reaches. */
    if (x->denm_n_hist)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %u %s", S(S_DENM_EXTENT), (unsigned)x->denm_n_hist,
               S(x->denm_n_hist == 1 ? S_DENM_POINT : S_DENM_POINTS));
        item_end(b, m);
    }
    if (x->denm_station_type != ITS_DENM_STATION_NONE)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s %s", S(S_DENM_STATION), S(web_msgdetail_station_cat(x->denm_station_type)));
        item_end(b, m);
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
static void cpm_text(sb_t *b, const msg_extra_t *x, lang_t lang)
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

/* Output bytes of one POIM air text before the ellipsis, the italics not counted. A shown
 * character never comes out shorter than it went in, so the decoder has to keep at least this
 * many raw bytes. A hidden one comes out shorter (one '?'), and such a text ends earlier. */
#define POIM_TEXT_OUT 40
_Static_assert(ITS_POIM_TEXT >= POIM_TEXT_OUT,
               "the decoder keeps fewer raw bytes than the page shows");

/* add_text_utf8 for a text with a length and no NUL: a NUL inside becomes '?' instead of
 * ending it. The output stops before the whole character or entity that would pass `max`,
 * and an ellipsis marks that cut as it marks the decoder's own (`cut`). */
static void add_text_utf8_n(sb_t *b, const char *t, size_t len, bool cut, size_t max)
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
static void poim_text(sb_t *b, const its_poim_t *p, lang_t lang)
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

static str_id_t role_name(uint8_t role)
{
    static const str_id_t ROLES[24] = {
        S_SREM_VEHICLE, S_BVR_PUBLIC, S_BVR_SPECIAL, S_BVR_DANGEROUS,
        S_BVR_ROADWORK, S_BVR_RESCUE, S_BVR_EMERGENCY, S_BVR_SAFETYCAR,
        S_UNKNOWN, S_BVR_TRUCK, S_BVR_MOTORCYCLE, S_BVR_ROADSIDE,
        S_BVR_POLICE, S_BVR_FIRE, S_BVR_AMBULANCE, S_BVR_DOT,
        S_BVR_TRANSIT, S_BVR_SLOW, S_BVR_STOPNGO, S_BVR_CYCLIST,
        S_DIR_PED, S_BVR_NONMOTOR, S_BVR_MILITARY, S_BVR_TRAM,
    };
    return role < 24 ? ROLES[role] : S_BVR_OTHER;
}

static void add_intersection(sb_t *b, const msg_prio_item_t *it)
{
    if (it->has_region)
        sb_add(b, "%u/%u", (unsigned)it->region, (unsigned)it->id);
    else
        sb_add(b, "%u", (unsigned)it->id);
}

/* A lane or approach 0 means the intersection itself. */
static void add_access(sb_t *b, const its_srem_access_t *a, lang_t lang)
{
    switch (a->kind)
    {
    case ITS_SREM_AP_LANE:
    case ITS_SREM_AP_APPROACH:
        if (a->value == 0)
            sb_add(b, "%s", S(S_AP_CENTER));
        else
            sb_add(b, "%s %u", S(a->kind == ITS_SREM_AP_LANE ? S_AP_LANE : S_AP_APPROACH),
                   (unsigned)a->value);
        break;
    case ITS_SREM_AP_CONNECTION:
        sb_add(b, "%s %u", S(S_AP_CONNECTION), (unsigned)a->value);
        break;
    default:
        sb_add(b, "%s", S(S_AP_OTHER));
        break;
    }
}

static void add_requester(sb_t *b, uint8_t kind, uint32_t id, lang_t lang)
{
    if (kind == ITS_SREM_ID_STATION)
        sb_add(b, "%s %lu", S(S_SREM_VEHICLE), (unsigned long)id);
    else
        sb_add(b, "%s %08lx", S(S_SREM_ENTITY), (unsigned long)id);
}

static str_id_t request_type_name(uint8_t code);
static str_id_t status_name(uint8_t code);

str_id_t web_msgdetail_prio_code(uint8_t kind, uint8_t code)
{
    return kind == 9 ? request_type_name(code) : status_name(code);
}

str_id_t web_msgdetail_prio_role(uint8_t role)
{
    return role_name(role);
}

/* Lane, approach or connection: which kind of access point the number means. Same words
 * as add_access() above, so the log and the message detail read alike. */
str_id_t web_msgdetail_prio_access(uint8_t kind)
{
    switch (kind)
    {
    case ITS_SREM_AP_LANE:       return S_AP_LANE;
    case ITS_SREM_AP_APPROACH:   return S_AP_APPROACH;
    case ITS_SREM_AP_CONNECTION: return S_AP_CONNECTION;
    default:                     return S_AP_OTHER;
    }
}

static str_id_t request_type_name(uint8_t code)
{
    switch (code)
    {
    case 1:  return S_PRT_REQUEST;
    case 2:  return S_PRT_UPDATE;
    case 3:  return S_PRT_CANCEL;
    default: return S_PRT_UNKNOWN;
    }
}

static str_id_t status_name(uint8_t code)
{
    switch (code)
    {
    case 0:  return S_UNKNOWN;
    case 1:  return S_SSEM_ST_REQUESTED;
    case 2:  return S_SSEM_ST_PROCESSING;
    case 3:  return S_SSEM_ST_WATCH;
    case 4:  return S_SSEM_ST_GRANTED;
    case 5:  return S_SSEM_ST_REJECTED;
    case 6:  return S_SSEM_ST_MAXPRESENCE;
    case 7:  return S_SSEM_ST_LOCKED;
    default: return S_SSEM_ST_OTHER;
    }
}

/* One item per request or answer: intersection, what, and the details in a parenthesis. */
static void prio_text(sb_t *b, const msg_prio_t *p, lang_t lang)
{
    bool srem = p->message_id == 9;
    for (uint8_t i = 0; i < p->n_items && i < MSG_PRIO_ITEMS; i++)
    {
        const msg_prio_item_t *it = &p->item[i];
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s ", S(srem ? S_SREM_AT : S_SSEM_AT));
        add_intersection(b, it);
        sb_add(b, ": %s", S(srem ? request_type_name(it->code) : status_name(it->code)));
        const char *next = " (";
        bool with_request = srem || it->requester_kind != ITS_SREM_ID_NONE;
        if (!srem && with_request)
        {
            sb_add(b, "%s", next);
            add_requester(b, it->requester_kind, it->requester_id, lang);
            next = ", ";
        }
        if (with_request)
        {
            sb_add(b, "%s%s %u", next, S(S_SREM_REQ_NO), (unsigned)it->request_id);
            next = ", ";
        }
        if (it->in.kind != ITS_SREM_AP_NONE || it->out.kind != ITS_SREM_AP_NONE)
        {
            sb_add(b, "%s", next);
            next = ", ";
            if (it->in.kind != ITS_SREM_AP_NONE)
                add_access(b, &it->in, lang);
            if (it->out.kind != ITS_SREM_AP_NONE)
            {
                sb_add(b, "%s", it->in.kind != ITS_SREM_AP_NONE ? " &rarr; " : "&rarr; ");
                add_access(b, &it->out, lang);
            }
        }
        if (next[0] == ',')
            sb_add(b, ")");
        item_end(b, m);
    }
    if (p->more)
    {
        size_t m = item_begin(b, " ");
        sb_add(b, "&hellip; %s", S(S_MORE));
        item_end(b, m);
    }
    if (!srem)
        return;
    if (p->has_role)
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s: %s", S(S_SREM_ROLE), S(role_name(p->role)));
        item_end(b, m);
    }
    if (p->requestor_kind == ITS_SREM_ID_STATION || p->requestor_kind == ITS_SREM_ID_ENTITY)
    {
        size_t m = item_begin(b, SEP);
        add_requester(b, p->requestor_kind, p->requestor_id, lang);
        item_end(b, m);
    }
    if (p->name[0])
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s: ", S(S_SREM_NAME));
        add_escaped(b, p->name);
        item_end(b, m);
    }
    if (p->route[0])
    {
        size_t m = item_begin(b, SEP);
        sb_add(b, "%s: ", S(S_SREM_ROUTE));
        add_escaped(b, p->route);
        item_end(b, m);
    }
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

/* Who signed it, what the checks say about that, what its signature header claims and how the
 * frame travelled: the second half. */
static void sign_parts(sb_t *b, const msg_extra_t *x, const uint8_t *src_mac,
                       const its_certcache_entry_t *cc, lang_t lang)
{
    if (x->sig.kind != ITS_SIG_NONE)
    {
        size_t m = item_begin(b, SEP);
        sig_text(b, &x->sig, src_mac, lang);
        item_end(b, m);
    }
    if (cc)
    {
        size_t m = item_begin(b, SEP);
        trust_text(b, cc, true, lang);
        item_end(b, m);
    }
    if (perm_worth_saying(x))
    {
        size_t m = item_begin(b, SEP);
        perm_svc_text(b, x, lang);
        item_end(b, m);
    }
    if (x->perm_svc == ITS_PERM_OK)
    {
        size_t m = item_begin(b, SEP);
        perm_cont_text(b, x, lang);
        item_end(b, m);
    }
    /* Whether this message itself was signed with that key (web_msgsig.c): an item of its own,
     * never mixed into the chain verdict before it. */
    if (!b->full)
        b->n = web_msgsig_append(&x->msgsig, lang, b->s, b->n, b->cap);
    /* The signature header, then how the frame travelled. A line that runs full drops those
     * items first, never the verdict. */
    if (!b->full)
        b->n = web_sechdr_append(&x->sechdr, cc ? cc->key_type : 0xFF, lang, b->s, b->n, b->cap);
    if (!b->full)
        b->n = web_gn_append(&x->gn, lang, b->s, b->n, b->cap);
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

/* The buffer starts at `used`, so the first item gets no separator in front. */
size_t web_msgdetail_append_sign(const msg_extra_t *x, const uint8_t *src_mac,
                                 const its_certcache_entry_t *cc, lang_t lang,
                                 char *out, size_t used, size_t cap)
{
    if (!out || !cap || used >= cap)
        return used;
    sb_t b = { out + used, cap - used, 0, false };
    out[used] = '\0';
    sign_parts(&b, x, src_mac, cc, lang);
    return used + b.n;
}

size_t web_msgdetail_trust(const its_certcache_entry_t *cc, lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    sb_t b = { out, cap, 0, false };
    out[0] = '\0';
    if (cc)
        trust_text(&b, cc, true, lang);
    item_end(&b, 0);
    return b.n;
}

size_t web_msgdetail_trust_short(const its_certcache_entry_t *cc, lang_t lang,
                                 char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    sb_t b = { out, cap, 0, false };
    out[0] = '\0';
    if (cc)
        trust_text(&b, cc, false, lang);
    item_end(&b, 0);
    return b.n;
}

size_t web_msgdetail_trust_counts(const its_verify_stats_t *v, lang_t lang,
                                  char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    sb_t b = { out, cap, 0, false };
    out[0] = '\0';
    /* One check lands in exactly one of these four, so they add up to the checks made. */
    uint64_t done = (uint64_t)v->checked + v->unavailable + v->invalid + v->revoked;
    /* The self test comes first, because it says whether this device can check at all. */
    if (v->selftest)
    {
        sb_add(&b, "%s ", S(v->selftest == 1 ? S_TRUST_SELFTEST_OK : S_TRUST_SELFTEST_FAIL));
        add_us(&b, v->selftest_us, lang);
    }
    if (!done && !v->dropped)
    {
        if (v->selftest)
            sb_add(&b, "%s", SEP);
        sb_add(&b, "%s%s%s", S(S_TRUST_NO_CHECKS_YET), SEP, S(S_SINCE_BOOT));
        item_end(&b, 0);
        return b.n;
    }
    if (v->selftest)
        sb_add(&b, "%s", SEP);
    sb_add(&b, "%s %lu", S(S_TRUST_YES), (unsigned long)v->checked);
    sb_add(&b, "%s%s %lu", SEP, S(S_TRUST_NOCHECK), (unsigned long)v->unavailable);
    sb_add(&b, "%s%s %lu", SEP, S(S_TRUST_INVALID), (unsigned long)v->invalid);
    /* Expired checks are a part of the invalid ones, so they stand in the same item. */
    if (v->expired)
        sb_add(&b, " (%s %lu)", S(S_TRUST_C_EXPIRED), (unsigned long)v->expired);
    sb_add(&b, "%s%s%s %lu%s", SEP, v->revoked ? TRUST_STOP_ON : "", S(S_TRUST_REVOKED),
           (unsigned long)v->revoked, v->revoked ? TRUST_STOP_OFF : "");
    if (v->dropped)
        sb_add(&b, "%s%s %lu", SEP, S(S_TRUST_DROPPED), (unsigned long)v->dropped);
    sb_add(&b, "%s%s %lu", SEP, S(S_TRUST_ISSUERS), (unsigned long)v->issuers);
    if (v->us_max)
    {
        sb_add(&b, "%s%s ", SEP, S(S_TRUST_SLOWEST));
        add_us(&b, v->us_max, lang);
    }
    /* Measured, not calculated: the built-in authority store nests one check inside
     * another, and this is the room that was really left over. */
    if (v->stack_left)
        sb_add(&b, "%s%s %lu B", SEP, S(S_TRUST_STACK_LEFT), (unsigned long)v->stack_left);
    sb_add(&b, "%s%s", SEP, S(S_SINCE_BOOT));
    item_end(&b, 0);
    return b.n;
}

/* The three answers of one tile, which add up to its number. `free` is the part of the yes
 * that had no bit to look at, and only the content tile shows it. */
static void perm_three(sb_t *b, uint64_t ok, uint64_t free, uint64_t bad, uint64_t open,
                       lang_t lang)
{
    sb_add(b, "%s %llu", S(S_PERM_C_OK), (unsigned long long)ok);
    if (free)
        sb_add(b, " (%s %llu)", S(S_PERM_C_FREE), (unsigned long long)free);
    sb_add(b, "%s%s%s %llu", SEP, bad ? PERM_WARN : "", S(S_PERM_C_BAD),
           (unsigned long long)bad);
    sb_add(b, "%s%s %llu", SEP, S(S_PERM_C_OPEN), (unsigned long long)open);
}

size_t web_msgdetail_perm_counts(const msg_perm_stats_t *p, lang_t lang,
                                 char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    sb_t b = { out, cap, 0, false };
    out[0] = '\0';
    if (!p->ok && !p->bad && !p->unknown)
        sb_add(&b, "%s", S(S_PERM_NONE_YET));
    else
        perm_three(&b, p->ok, 0, p->bad, p->unknown, lang);
    sb_add(&b, "%s%s", SEP, S(S_SINCE_BOOT));
    item_end(&b, 0);
    return b.n;
}

size_t web_msgdetail_perm_cont_counts(const msg_perm_stats_t *p, lang_t lang,
                                      char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    sb_t b = { out, cap, 0, false };
    out[0] = '\0';
    /* Every service yes gets a content answer, so `ok` is the number on this tile. FREE is a yes
     * without a bit to look at: no SSP beside the PSID, or nothing in the message a bit governs. */
    if (!p->ok)
        sb_add(&b, "%s", S(S_PERM_CONT_NONE_YET));
    else
        perm_three(&b, (uint64_t)p->content_ok + p->content_none, p->content_none,
                   p->content_bad, p->content_unknown, lang);
    sb_add(&b, "%s%s", SEP, S(S_SINCE_BOOT));
    item_end(&b, 0);
    return b.n;
}

size_t web_msgdetail_trustlists(lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    sb_t b = { out, cap, 0, false };
    out[0] = '\0';
    unsigned have = 0;
    for (uint8_t env = 0; env < ITS_TRUST_ENV_COUNT; env++)
    {
        const its_trust_list_t *l = its_trustlist_list(env);
        if (l && l->n_roots)
            have++;
    }
    if (!have)
    {
        sb_add(&b, "%s", S(S_TRUSTLIST_NONE));
        item_end(&b, 0);
        return b.n;
    }
    /* The label is the heading of the table on /trust and links there, so the count needs no
     * word of its own. */
    sb_add(&b, "<a href='/trust?lang=%s#t-roots'>%s</a>: ", lang == LANG_EN ? "en" : "de",
           S(S_TRUST_H_ROOTS));
    unsigned shown = 0;
    for (uint8_t env = 0; env < ITS_TRUST_ENV_COUNT; env++)
    {
        const its_trust_list_t *l = its_trustlist_list(env);
        if (!l || !l->n_roots)
            continue;
        sb_add(&b, "%s%s %u", shown++ ? SEP : "", its_trustlist_env_name(env),
               (unsigned)l->n_roots);
        if (l->generation_time)
        {
            sb_add(&b, ", %s ", S(S_TRUSTLIST_DATE));
            add_day(&b, l->generation_time, lang);
        }
    }
    sb_add(&b, "%s%lu %s", SEP, (unsigned long)its_trustlist_count(), S(S_TRUSTLIST_TOTAL));
    /* When the roots listed above add up to less than this number, S_TRUSTLIST_GAP says so.
     * Without it the gap would read like an arithmetic error. */
    unsigned roots = 0;
    for (uint8_t env = 0; env < ITS_TRUST_ENV_COUNT; env++)
    {
        const its_trust_list_t *l = its_trustlist_list(env);
        if (l)
            roots += l->n_roots;
    }
    if (its_trustlist_count() > roots)
        sb_add(&b, ", %s", S(S_TRUSTLIST_GAP));
    item_end(&b, 0);
    return b.n;
}

size_t web_msgdetail_sig(const its_sig_summary_t *sig, const uint8_t *src_mac, lang_t lang,
                         char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    sb_t b = { out, cap, 0, false };
    out[0] = '\0';
    sig_text(&b, sig, src_mac, lang);
    item_end(&b, 0);
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
