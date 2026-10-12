#include "web_msgsig.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "its_security.h"
#include "web_fmt.h"
#include "web_strings.h"

/* The string writer of web_sechdr.c once more, under its own name. A host test expects sb_t
 * exactly once, in web_msgdetail_priv.h, and only the detail-line files include that header. */
typedef struct
{
    char  *s;
    size_t cap;
    size_t n;
    bool   full;                 /* Set by the first piece that did not fit. */
} mw_t;

#define SEP " &middot; "
/* The sign of PERM_WARN in web_msgdetail_sec.c: the line has no colour, so the sign says it. */
#define SIG_WARN "&#9888; "
#define S(id) web_str((id), lang)

static void mw_add(mw_t *w, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void mw_add(mw_t *w, const char *fmt, ...)
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

static str_id_t why_name(uint8_t why)
{
    switch (why)
    {
    case ITS_MSGSIG_WHY_NOCERT: return S_MSIG_WHY_NOCERT;
    case ITS_MSGSIG_WHY_FORM:   return S_MSIG_WHY_FORM;
    case ITS_MSGSIG_WHY_HASH:   return S_MSIG_WHY_HASH;
    case ITS_MSGSIG_WHY_CRYPTO: return S_MSIG_WHY_CRYPTO;
    case ITS_MSGSIG_WHY_CURVE:  return S_MSIG_WHY_CURVE;
    default:                    return S_UNKNOWN;
    }
}

static void verdict(mw_t *w, uint8_t state, uint8_t why, lang_t lang)
{
    switch (state)
    {
    case ITS_MSGSIG_OK:
        mw_add(w, "%s", S(S_MSIG_OK));
        break;
    case ITS_MSGSIG_BAD:
        mw_add(w, "%s%s", SIG_WARN, S(S_MSIG_BAD));
        if (why != ITS_MSGSIG_WHY_NONE)
            mw_add(w, " (%s)", S(why_name(why)));
        break;
    case ITS_MSGSIG_PENDING:
        mw_add(w, "%s", S(S_MSIG_PENDING));
        break;
    case ITS_MSGSIG_SAMPLE:
        mw_add(w, "%s", S(S_MSIG_SAMPLE));
        break;
    case ITS_MSGSIG_BUSY:
        mw_add(w, "%s", S(S_MSIG_BUSY));
        break;
    default:
        mw_add(w, "%s: %s", S(S_MSIG_NOCHECK), S(why_name(why)));
        break;
    }
}

size_t web_msgsig_append(const its_msgsig_t *m, lang_t lang, char *out, size_t used, size_t cap)
{
    if (!out || !cap || used >= cap)
        return used;
    if (!m || m->state == ITS_MSGSIG_NONE)
        return used;
    mw_t w = { out, cap, used, false };
    if (used)
        mw_add(&w, "%s", SEP);
    verdict(&w, m->state, m->why, lang);
    /* A message that was not checked says how its certificate fared so far, so the line does not
     * leave the reader with "not checked" alone. */
    bool open = m->state == ITS_MSGSIG_SAMPLE || m->state == ITS_MSGSIG_BUSY ||
                m->state == ITS_MSGSIG_PENDING;
    if (open && (m->ok || m->bad))
        mw_add(&w, " (%s: %u %s, %s%u %s)", S(S_MSIG_SO_FAR), (unsigned)m->ok, S(S_MSIG_N_OK),
               m->bad ? SIG_WARN : "", (unsigned)m->bad, S(S_MSIG_N_BAD));
    if (w.full)
    {
        out[used] = '\0';
        return used;
    }
    return w.n;
}

size_t web_msgsig_cert(const its_msgsig_cert_t *c, bool title, lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    mw_t w = { out, cap, 0, false };
    out[0] = '\0';
    if (!c)
        return 0;
    if (title)
        mw_add(&w, "%s: ", S(S_MSIG_CERT_TITLE));
    if (!c->ok && !c->bad)
        mw_add(&w, "%s", S(S_MSIG_NONE_YET));
    else
        mw_add(&w, "%u %s, %s%u %s", (unsigned)c->ok, S(S_MSIG_N_OK), c->bad ? SIG_WARN : "",
               (unsigned)c->bad, S(S_MSIG_N_BAD));
    return w.full ? 0 : w.n;
}

size_t web_msgsig_cells(const its_msgsig_rec_t *r, const char *who, const char *msg,
                        uint32_t now, lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    mw_t w = { out, cap, 0, false };
    out[0] = '\0';
    if (!r)
        return 0;
    static const char H[] = "0123456789abcdef";
    char id[17], when[FMT_WHEN_MAX], took[FMT_US_MAX];
    for (int i = 0; i < 8; i++)
    {
        id[i * 2] = H[r->id[i] >> 4];
        id[i * 2 + 1] = H[r->id[i] & 0x0F];
    }
    id[16] = '\0';
    /* A self-signed certificate has no HashedId8 here. */
    static const uint8_t NOID[8];
    if (!memcmp(r->id, NOID, 8))
        snprintf(id, sizeof id, "&ndash;");
    /* Before the clock is set, r->at counts from the start: it is no date. */
    if (!web_clock_set(r->at)
        || !fmt_when(r->at, now, FMT_SEC | FMT_SAMEDAY, lang, when, sizeof when))
        snprintf(when, sizeof when, "&ndash;");
    if (r->us)
        fmt_us(r->us, lang, took, sizeof took);
    else
        snprintf(took, sizeof took, "&ndash;");
    const char *alg = its_sec_alg_name(r->curve);
    bool bad = r->state == ITS_MSGSIG_BAD;
    mw_add(&w, "<td>%s</td><td>", when);
    /* The sender as on /messages: the words on top, the station number small below them. */
    if (!who)
        who = "";
    if (who[0] && r->station)
        mw_add(&w, "%s<div class='sub mono'>%lu</div>", who, (unsigned long)r->station);
    else if (who[0])
        mw_add(&w, "%s", who);
    else if (r->station)
        mw_add(&w, "<span class='mono'>%lu</span>", (unsigned long)r->station);
    else
        mw_add(&w, "&ndash;");
    if (msg)
        mw_add(&w, "</td><td>%s</td>", msg);
    else
        mw_add(&w, "</td><td>PSID %lu</td>", (unsigned long)r->psid);
    mw_add(&w, "<td><span class='mono'>%s</span></td><td>%s</td><td><span class='%s'>", id,
           alg ? alg : S(S_UNKNOWN), bad ? "bad" : r->state == ITS_MSGSIG_OK ? "ok" : "sub");
    verdict(&w, r->state, r->why, lang);
    mw_add(&w, "</span></td><td>%s</td>", took);
    return w.full ? 0 : w.n;
}

/* "ECDSA NIST P-256 ø 19,4 ms, höchstens 25,0 ms" over the matches, the only timed checks. */
static void curve_time(mw_t *w, const its_msgsig_stats_t *s, int ci, uint8_t key, lang_t lang)
{
    if (!s->n[ci])
        return;
    char avg[FMT_US_MAX], max[FMT_US_MAX];
    fmt_us(s->us_sum[ci] / s->n[ci], lang, avg, sizeof avg);
    fmt_us(s->us_max[ci], lang, max, sizeof max);
    const char *name = its_sec_alg_name(key);
    mw_add(w, "%s%s &oslash; %s, %s %s", SEP, name ? name : S(S_UNKNOWN), avg, S(S_MSIG_MAX), max);
}

size_t web_msgsig_counts(const its_msgsig_stats_t *s, lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    mw_t w = { out, cap, 0, false };
    out[0] = '\0';
    if (!s)
        return 0;
    mw_add(&w, "%lu %s, %s%lu %s, %llu %s%s%s: %lu %s, %lu %s",
           (unsigned long)s->ok, S(S_MSIG_N_OK), s->bad ? SIG_WARN : "", (unsigned long)s->bad,
           S(S_MSIG_N_BAD), (unsigned long long)s->nocheck + s->refused, S(S_MSIG_N_NOCHECK), SEP,
           S(S_MSIG_N_NOTCHECKED), (unsigned long)s->sample, S(S_MSIG_N_SAMPLE),
           (unsigned long)s->busy, S(S_MSIG_N_BUSY));
    curve_time(&w, s, 0, ITS_SEC_KEY_ECDSA_NIST_P256, lang);
    curve_time(&w, s, 1, ITS_SEC_KEY_ECDSA_BRAINPOOL_P256, lang);
    mw_add(&w, "%s%s", SEP, S(S_SINCE_BOOT));
    return w.full ? 0 : w.n;
}
