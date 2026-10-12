#include "web_trust.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "esp_attr.h"
#include "esp_log.h"

#include "inventory.h"
#include "its_castore.h"
#include "its_certcache.h"
#include "its_crl.h"
#include "its_decode.h"
#include "its_msgsig.h"
#include "its_security.h"
#include "its_trustlist.h"
#include "its_verify.h"
#include "web_msgdetail.h"
#include "web_msgsig.h"
#include "webserver_priv.h"

static const char TAG[] = "WEBSERVER";

/* ================================================================== */
/*  /trust -- the material the chain check rests on                    */
/* ================================================================== */

/* The page carries 36 trust-list entries (31 of them roots), 48 authorities, 24 revocation
 * lists and up to 512 received certificates, so it never fits one buffer. Rows go into s_row,
 * are appended to s_out and leave as an HTTP chunk once s_out is full. Both buffers are static
 * and placed in external RAM: only the httpd task renders a page, and the 16 kB task stack has
 * no room for them. */
#define TRUST_OUT_MAX 4096
/* The widest row is one of the received certificates: 16 identifier characters and the key
 * line under them, the verdict word, a reason of at most 160 bytes, two escaped names at 256
 * bytes each, the source and the root environment, a validity span, the state word and a
 * frame count, plus the markup. That adds up to 1057 bytes (German), so 1536 leaves room.
 * Most notes go out on their own. The few that pass through here stay under 400 bytes
 * including markup. */
#define TRUST_ROW_MAX 1536
/* A name from CertificateId.name. The generators cut those at 31 characters and every
 * character escapes to at most 6 bytes, so 256 holds the worst case with room to spare.
 * html_escape stops on a whole entity, so a longer name would be shortened, never broken. */
#define TRUST_NAME_MAX 256

static EXT_RAM_BSS_ATTR char s_out[TRUST_OUT_MAX];
static EXT_RAM_BSS_ATTR char s_row[TRUST_ROW_MAX];
static EXT_RAM_BSS_ATTR char s_name_a[TRUST_NAME_MAX];
static EXT_RAM_BSS_ATTR char s_name_b[TRUST_NAME_MAX];
static size_t s_used;

static void out_flush(httpd_req_t *req)
{
    if (!s_used)
        return;
    /* Zeroed first: a failed send must not let the next call ship the same bytes again. */
    size_t n = s_used;
    s_used = 0;
    httpd_resp_send_chunk(req, s_out, (ssize_t)n);
}

/* Append one finished piece of markup. A piece that does not fit flushes first, so no piece
 * is ever cut in half and none is sent twice. */
static void out_add(httpd_req_t *req, const char *s)
{
    size_t n = strlen(s);
    if (n > sizeof(s_out))
    {
        /* Longer than the whole buffer: send it on its own rather than drop it. */
        out_flush(req);
        httpd_resp_send_chunk(req, s, (ssize_t)n);
        return;
    }
    if (s_used + n > sizeof(s_out))
        out_flush(req);
    memcpy(s_out + s_used, s, n);
    s_used += n;
}

/* ---- time and validity -------------------------------------------- */

/* The seconds a Duration year stands for, the average length of a year. its_verify.c holds
 * the same number, because it may not depend on the web interface. */
#define TRUST_YEAR_SECONDS 31556952u

/* Seconds of a Duration, as its_verify.c counts them: the two units below a second round
 * down, so a period shorter than a second covers nothing. */
static uint64_t duration_seconds(uint16_t value, uint8_t unit)
{
    switch (unit)
    {
    case ITS_SEC_DUR_MICROSECONDS: return value / 1000000u;
    case ITS_SEC_DUR_MILLISECONDS: return value / 1000u;
    case ITS_SEC_DUR_SECONDS:      return value;
    case ITS_SEC_DUR_MINUTES:      return (uint64_t)value * 60u;
    case ITS_SEC_DUR_HOURS:        return (uint64_t)value * 3600u;
    case ITS_SEC_DUR_SIXTY_HOURS:  return (uint64_t)value * 216000u;
    case ITS_SEC_DUR_YEARS:        return (uint64_t)value * TRUST_YEAR_SECONDS;
    default:                       return 0;
    }
}

typedef enum
{
    VS_NONE = 0,   /* No usable period, so nothing may be said about it. */
    VS_NOCLOCK,    /* The clock is not set, so no date can be judged. */
    VS_EARLY,      /* The period has not started yet. */
    VS_VALID,
    VS_EXPIRED,
} val_state_t;

/* Fail-closed: a missing start or a missing clock never comes out as valid. */
static val_state_t validity_state(uint32_t now_unix, uint32_t start, uint16_t dur, uint8_t unit)
{
    if (!start)
        return VS_NONE;
    if (!web_clock_set(now_unix))
        return VS_NOCLOCK;
    uint64_t from = web_time32_to_unix(start);
    uint64_t to = from + duration_seconds(dur, unit);
    if (now_unix < from)
        return VS_EARLY;
    return now_unix >= to ? VS_EXPIRED : VS_VALID;
}

/* The pill class and the word for one state. Only VS_VALID is green. Every other state is
 * either a warning or a plain word, so an expired entry can never read as a valid one. */
static void validity_words(val_state_t s, const char **cls, const char **word)
{
    switch (s)
    {
    case VS_VALID:   *cls = "ok";  *word = T(S_TRUST_V_VALID);  break;
    case VS_EXPIRED: *cls = "bad"; *word = T(S_WARN_EXPIRED);   break;
    case VS_EARLY:   *cls = "bad"; *word = T(S_TRUST_V_NOTYET); break;
    case VS_NOCLOCK: *cls = "sub"; *word = T(S_CLOCK_UNSET);    break;
    default:         *cls = "sub"; *word = T(S_UNKNOWN);        break;
    }
}

/* The last second of a validity as a Time32, for web_day_str. A period that reaches past
 * the Time32 range is pinned to its end, which still prints as a far future day. */
static uint32_t validity_end_time32(uint32_t start, uint16_t dur, uint8_t unit)
{
    if (!start)
        return 0;
    uint64_t end = (uint64_t)start + duration_seconds(dur, unit);
    return end > 0xFFFFFFFFu ? 0xFFFFFFFFu : (uint32_t)end;
}

/* "01.01.2024 &ndash; 01.01.2027", or the empty-value dash alone: both days come from one
 * start and are empty together, and "x &ndash; &ndash;" would read as a broken span. */
static void validity_span(uint32_t start, uint16_t dur, uint8_t unit, char *out, size_t cap)
{
    char from[WEB_DAY_MAX], to[WEB_DAY_MAX];
    web_day_str(start, web_lang(), from, sizeof(from));
    web_day_str(validity_end_time32(start, dur, unit), web_lang(), to, sizeof(to));
    if (!from[0] || !to[0])
        snprintf(out, cap, "&ndash;");
    else
        snprintf(out, cap, "%s &ndash; %s", from, to);
}

/* ---- identifiers --------------------------------------------------- */

/* One HashedId8 as 16 lower-case hex characters, the spelling of every page (/messages and
 * /senders show the first 8 and an ellipsis). A browser search ignores case. */
static void id8_hex(const uint8_t id[8], char out[17])
{
    static const char H[] = "0123456789abcdef";
    for (int i = 0; i < 8; i++)
    {
        out[i * 2]     = H[id[i] >> 4];
        out[i * 2 + 1] = H[id[i] & 0x0F];
    }
    out[16] = '\0';
}

/* Both hash forms in one cell. Which form a certificate is named by is decided by whoever
 * refers to it, so showing only one would make a row look wrong to a reader holding the
 * other. */
static void id8_cell(const uint8_t id256[8], const uint8_t id384[8], char *out, size_t cap)
{
    char a[17], b[17];
    id8_hex(id256, a);
    id8_hex(id384, b);
    snprintf(out, cap, "<span class='mono'>%s</span><div class='sub mono'>SHA-384: %s</div>",
             a, b);
}

/* ---- words for the enumerations ------------------------------------ */

static str_id_t role_name(uint8_t role)
{
    return role == ITS_TRUST_ROLE_TLM ? S_TRUST_ROLE_TLM : S_TRUST_ROLE_ROOT;
}

/* The key of a certificate in the words of the message line: the curve, or "implicit" for a
 * key that is only computed from the certificate and its issuer. */
static const char *key_word(uint8_t key)
{
    const char *n = its_sec_alg_name(key);
    return n ? n : T(key == ITS_SEC_KEY_RECONSTRUCTION ? S_SEC_KEY_IMPLICIT : S_UNKNOWN);
}

static str_id_t verdict_name(uint8_t state)
{
    switch (state)
    {
    case ITS_VERIFY_CHECKED:     return S_TRUST_YES;
    case ITS_VERIFY_UNCHECKABLE: return S_TRUST_NOCHECK;
    case ITS_VERIFY_INVALID:     return S_TRUST_INVALID;
    case ITS_VERIFY_REVOKED:     return S_TRUST_REVOKED;
    default:                     return S_TRUST_UNCHECKED;
    }
}

/* A withdrawn certificate gets the class "bad", like an invalid one. Every signature in its
 * chain may still match, but the row must not read as a plain pass. */
static const char *verdict_class(uint8_t state)
{
    switch (state)
    {
    case ITS_VERIFY_CHECKED: return "ok";
    case ITS_VERIFY_INVALID:
    case ITS_VERIFY_REVOKED: return "bad";
    default:                 return "sub";
    }
}

/* The same mapping as in web_msgdetail_sec.c. It is kept here as well, because a page may not
 * reach into another page's file. */
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

/* ---- the five tables ----------------------------------------------- */

/* With `folded` a built-in table waits behind its count. It uses class fold, not dtl, because
 * the help switch hides dtl. The caller closes it with </details>. capx is markup after the
 * count of an open section, or "". */
static void section_head(httpd_req_t *req, const char *anchor, const char *title,
                         unsigned long count, const char *unit, const char *hint,
                         bool folded, const char *capx)
{
    if (folded)
    {
        HTML_PRINTF(s_row, "<div class='grp' id='%s'><h2>%s</h2><p class='note hlp'>",
                    anchor, title);
        out_add(req, s_row);
        out_add(req, hint);
        HTML_PRINTF(s_row, "</p><details class='fold'><summary>%lu %s</summary>", count, unit);
        out_add(req, s_row);
        return;
    }
    HTML_PRINTF(s_row, "<div class='grp' id='%s'><h2>%s</h2>"
                       "<p class='cap'>%lu %s%s</p><p class='note hlp'>",
                anchor, title, count, unit, capx);
    out_add(req, s_row);
    out_add(req, hint);
    out_add(req, "</p>");
}

/* Every entry of the built-in trust lists: the roots a chain has to end at, and the list
 * managers that signed the lists themselves. The count comes from the table, never from a
 * number written here, which would rot the next time the generator runs. */
static void roots_table(httpd_req_t *req, uint32_t now_unix)
{
    section_head(req, "t-roots", T(S_TRUST_H_ROOTS), (unsigned long)its_trustlist_count(),
                 T(S_TRUSTLIST_TOTAL), T(S_TRUST_N_ROOTS), true, "");

    /* The state comes second, so on a phone it shows next to the name without scrolling. */
    HTML_PRINTF(s_row, "<div class='scroll'><table><thead><tr>"
                       "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
                       "</tr></thead><tbody>",
                T(S_TRUST_C_NAME), T(S_TRUST_C_STATE), T(S_TRUST_C_VALID), T(S_TRUST_C_ROLE),
                T(S_TRUST_C_ENV), T(S_TRUST_C_ID));
    out_add(req, s_row);

    its_trust_entry_t e;
    for (size_t i = 0; its_trustlist_at(i, &e); i++)
    {
        const char *cls, *word;
        char ids[128], span[48];
        html_escape(e.name ? e.name : "", s_name_a, sizeof(s_name_a));
        id8_cell(e.id8_sha256, e.id8_sha384, ids, sizeof(ids));
        validity_span(e.validity_start, e.duration, e.duration_unit, span, sizeof(span));
        validity_words(validity_state(now_unix, e.validity_start, e.duration, e.duration_unit),
                       &cls, &word);
        /* A predecessor is named by a later entry, so its own period may well be over while
         * certificates issued under it are still in use. Saying so keeps the expired mark
         * from looking like a fault. */
        HTML_PRINTF(s_row,
            "<tr><td class='wrapcell'>%s%s%s%s</td><td><span class='%s'>%s</span></td>"
            "<td>%s</td><td>%s</td><td>%s</td><td>%s<div class='sub'>%s: %s</div></td></tr>",
            s_name_a,
            (e.flags & ITS_TRUST_PREDECESSOR) ? "<div class='sub'>" : "",
            (e.flags & ITS_TRUST_PREDECESSOR) ? T(S_TRUST_PRED) : "",
            (e.flags & ITS_TRUST_PREDECESSOR) ? "</div>" : "",
            cls, word, span, T(role_name(e.role)), its_trustlist_env_name(e.env), ids,
            T(S_SEC_KEY), key_word(e.key_type));
        out_add(req, s_row);
    }
    out_add(req, "</tbody></table></div></details></div>");
}

/* The built-in authority certificates. Their names repeat across roots, so the identifier
 * and the root belong in every row: 0_EU-AA_L0 and 0_EU-EA_L0 each name three different
 * certificates from three different roots. */
static void authorities_table(httpd_req_t *req, uint32_t now_unix)
{
    size_t n_ca = its_castore_count();
    section_head(req, "t-ca", T(S_TRUST_H_CAS), (unsigned long)n_ca,
                 n_ca == 1 ? T(S_CASTORE_CERT) : T(S_CASTORE_CERTS), T(S_TRUST_N_CAS), true, "");

    HTML_PRINTF(s_row, "<div class='scroll'><table><thead><tr>"
                       "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
                       "<th>%s</th></tr></thead><tbody>",
                T(S_TRUST_C_NAME), T(S_TRUST_C_STATE), T(S_TRUST_C_VALID), T(S_TRUST_C_KIND),
                T(S_TRUST_C_ENV), T(S_TRUST_C_ID), T(S_TRUST_C_ROOT));
    out_add(req, s_row);

    its_castore_entry_t e;
    for (size_t i = 0; its_castore_at(i, &e); i++)
    {
        const char *cls, *word;
        char ids[128], span[48];
        its_verify_cert_t c;
        its_trust_entry_t root;
        /* The store keeps the bytes only, so the period and the issuer are read from the
         * certificate itself. Reading it is a walk over the bytes, no signature check. */
        bool parsed = its_verify_parse(e.cert, e.cert_len, &c) && c.ok;
        bool have_root = parsed && !c.self_signed && c.hash_alg <= ITS_TRUST_HASH_SHA384 &&
                         its_trustlist_find_alg(c.issuer_id, c.hash_alg, &root);

        html_escape(e.name ? e.name : "", s_name_a, sizeof(s_name_a));
        if (have_root)
            html_escape(root.name ? root.name : "", s_name_b, sizeof(s_name_b));
        else
            snprintf(s_name_b, sizeof(s_name_b), "<span class='sub'>%s</span>",
                     T(S_TRUST_ROOT_NONE));
        id8_cell(e.id8_sha256, e.id8_sha384, ids, sizeof(ids));
        if (parsed)
        {
            validity_span(c.valid_start, c.duration, c.duration_unit, span, sizeof(span));
            validity_words(validity_state(now_unix, c.valid_start, c.duration, c.duration_unit),
                           &cls, &word);
        }
        else
        {
            /* Unreadable bytes may not turn into a validity. The row says so. */
            snprintf(span, sizeof(span), "&ndash;");
            validity_words(VS_NONE, &cls, &word);
        }
        /* Unreadable bytes name no key either. */
        HTML_PRINTF(s_row,
            "<tr><td class='wrapcell'>%s</td><td><span class='%s'>%s</span></td><td>%s</td>"
            "<td>%s</td><td>%s</td><td>%s<div class='sub'>%s: %s</div></td><td>%s</td></tr>",
            s_name_a, cls, word, span, e.is_aa ? T(S_TRUST_KIND_AA) : T(S_TRUST_KIND_EA),
            its_trustlist_env_name(e.env), ids, T(S_SEC_KEY),
            parsed ? key_word(c.key_type) : "&ndash;", s_name_b);
        out_add(req, s_row);
    }
    out_add(req, "</tbody></table></div></details></div>");
}

/* The built-in revocation lists. A list only grows stale, never wrong, so the two dates are
 * the whole story: what it knew, and when it wanted to be renewed. */
static void crl_table(httpd_req_t *req, uint32_t now_unix)
{
    section_head(req, "t-crl", T(S_TRUST_H_CRLS), (unsigned long)its_crl_lists(),
                 T(S_CRL_LISTS), T(S_TRUST_N_CRLS), true, "");

    HTML_PRINTF(s_row, "<div class='scroll'><table><thead><tr>"
                       "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
                       "</tr></thead><tbody>",
                T(S_TRUST_C_ROOT), T(S_TRUST_C_THIS), T(S_TRUST_C_NEXT), T(S_TRUST_C_ENTRIES),
                T(S_TRUST_C_ENV), T(S_TRUST_C_ID));
    out_add(req, s_row);

    uint32_t now32 = web_clock_set(now_unix) ? web_unix_to_time32(now_unix) : 0;
    unsigned long sum = 0;
    its_crl_list_t l;
    for (size_t i = 0; its_crl_list_at(i, &l); i++)
    {
        char id[17], this_day[WEB_DAY_MAX], next_day[WEB_DAY_MAX];
        html_escape(l.root_name ? l.root_name : "", s_name_a, sizeof(s_name_a));
        id8_hex(l.root_id8, id);
        web_day_str(l.this_update, web_lang(), this_day, sizeof(this_day));
        web_day_str(l.next_update, web_lang(), next_day, sizeof(next_day));
        /* Overdue only with a clock to measure it against, and only for a list that asked
         * for a renewal at all. */
        bool late = now32 && l.next_update && now32 >= l.next_update;
        sum += l.entries;
        /* An overdue list keeps its date, and a note under the date says it is overdue. */
        HTML_PRINTF(s_row,
            "<tr><td>%s</td><td>%s</td><td>%s%s%s%s</td><td>%u</td><td>%s</td>"
            "<td class='mono'>%s</td></tr>",
            s_name_a,
            this_day[0] ? this_day : "&ndash;",
            next_day[0] ? next_day : "&ndash;",
            late ? "<div class='sub'>" : "",
            late ? T(S_TRUST_CRL_LATE) : "",
            late ? "</div>" : "",
            (unsigned)l.entries, its_trustlist_env_name(l.env), id);
        out_add(req, s_row);
    }
    out_add(req, "</tbody></table></div>");

    /* The identifiers are held once across all lists, so the column adds up higher than the
     * total whenever two lists name the same certificate. Saying both numbers is the only
     * way the table and the total do not look like a contradiction. */
    HTML_PRINTF(s_row, "<p class='note'>%s: %lu &middot; %s: %lu</p>",
                T(S_TRUST_CRL_IDS), (unsigned long)its_crl_count(),
                T(S_TRUST_CRL_SUM), sum);
    out_add(req, s_row);
    /* The sentence that explains the difference appears only when there is one. With no
     * identifier in two lists, it would contradict the two equal numbers above it. */
    if (sum != (unsigned long)its_crl_count())
    {
        HTML_PRINTF(s_row, "<p class='note hlp'>%s</p>", T(S_TRUST_CRL_IDS_HINT));
        out_add(req, s_row);
    }

    /* The withdrawn identifiers themselves. A number alone cannot be looked up against a
     * certificate the user holds; the identifier can. One row per entry, because the list
     * grows with the next build and a single buffer would not. */
    if (its_crl_count())
    {
        uint8_t id8[8];
        size_t li;
        HTML_PRINTF(s_row, "<div class='scroll'><table><thead><tr><th>%s</th><th>%s</th>"
                           "<th>%s</th></tr></thead><tbody>",
                    T(S_TRUST_C_ID), T(S_TRUST_C_ROOT), T(S_TRUST_C_THIS));
        out_add(req, s_row);
        for (size_t i = 0; its_crl_revoked_at(i, id8, &li); i++)
        {
            char id[17], day[WEB_DAY_MAX];
            id8_hex(id8, id);
            s_name_a[0] = '\0';
            day[0] = '\0';
            if (its_crl_list_at(li, &l))
            {
                html_escape(l.root_name ? l.root_name : "", s_name_a, sizeof(s_name_a));
                web_day_str(l.this_update, web_lang(), day, sizeof(day));
            }
            HTML_PRINTF(s_row, "<tr><td class='mono'>%s</td><td>%s</td><td>%s</td></tr>",
                        id, s_name_a[0] ? s_name_a : "&ndash;", day[0] ? day : "&ndash;");
            out_add(req, s_row);
        }
        out_add(req, "</tbody></table></div>");
    }
    out_add(req, "</details></div>");
}

/* The certificates this device received itself. Only this table and the message checks
 * change while the device runs. */
static void seen_table(httpd_req_t *req, uint32_t now_unix)
{
    /* Read entries first and used after. In the other order, a certificate arriving between
     * the two reads would make an empty table look merely busy. A busy table lock makes
     * its_certcache_used() answer 0, and no slot is ever freed, so entries > 0 with
     * used == 0 means "not readable right now", never "nothing received". */
    its_certcache_stats_t st;
    its_certcache_stats(&st);
    size_t used = its_certcache_used();
    bool busy = used == 0 && st.entries > 0;

    /* The way back to the counters, the same name as the tile on /system: 67 of 128. */
    char back[128];
    HTML_PRINTF(back, " &middot; <a href='/system?lang=%s#s-cert'>%s</a>",
                web_lang() == LANG_EN ? "en" : "de", T(S_TRUST_CHECKS));
    unsigned long n_seen = (unsigned long)(busy ? st.entries : used);
    section_head(req, "t-seen", T(S_TRUST_H_SEEN), n_seen,
                 n_seen == 1 ? T(S_CASTORE_CERT) : T(S_CASTORE_CERTS), T(S_TRUST_N_SEEN), false,
                 back);

    if (!used)
    {
        /* A busy table leaves the view incomplete and gets a warning like S_TRF_BUSY.
         * No certificate at all is plain information. */
        if (busy)
            HTML_PRINTF(s_row, "<div class='warn'><p>%s</p></div></div>", T(S_TRUST_SEEN_BUSY));
        else
            HTML_PRINTF(s_row, "<p class='note'>%s</p></div>", T(S_TRUST_SEEN_NONE));
        out_add(req, s_row);
        return;
    }

    HTML_PRINTF(s_row, "<div class='scroll'><table><thead><tr>"
                       "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
                       "<th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody>",
                T(S_TRUST_C_ID), T(S_TRUST_C_VERDICT), T(S_TRUST_C_REASON),
                T(S_SIG_ISSUER), T(S_TRUST_C_SOURCE), T(S_TRUST_C_ROOT),
                T(S_TRUST_C_VALID), T(S_TRUST_C_FRAMES), T(S_MSIG_TITLE));
    out_add(req, s_row);

    its_certcache_entry_t e;
    for (size_t i = 0; i < used && its_certcache_at(i, &e); i++)
    {
        const char *cls, *word;
        /* msig: both counts at 65535 is 41 of 96 bytes (EN). */
        char id[17], span[48], why[160], msig[96];
        its_msgsig_cert_t mc;
        if (!its_msgsig_cert(e.id, &mc) ||
            !web_msgsig_cert(&mc, false, web_lang(), msig, sizeof msig))
            snprintf(msig, sizeof msig, "&ndash;");
        val_state_t vs = validity_state(now_unix, e.validity_start, e.duration, e.duration_unit);
        id8_hex(e.id, id);
        html_escape(e.issuer_name, s_name_a, sizeof(s_name_a));
        html_escape(e.root_name, s_name_b, sizeof(s_name_b));
        validity_span(e.validity_start, e.duration, e.duration_unit, span, sizeof(span));
        validity_words(vs, &cls, &word);

        /* The reason cell: why the check ended where it did, and for a withdrawn certificate
         * the date of the list that named it, because that says how old the withdrawal is. */
        if (e.verify == ITS_VERIFY_REVOKED)
        {
            size_t li = 0;
            its_crl_list_t l;
            /* If this identifier is on no list itself, its issuer was withdrawn. */
            if (its_crl_list_of(e.id, NULL, &li) && its_crl_list_at(li, &l))
            {
                char day[WEB_DAY_MAX] = "";
                web_day_str(l.this_update, web_lang(), day, sizeof(day));
                snprintf(why, sizeof(why), "%s%s%s", T(S_TRUST_CRL_SINCE),
                         day[0] ? " " : "", day);
            }
            else
                snprintf(why, sizeof(why), "%s", T(S_TRUST_CRL_ISSUER));
        }
        /* As in the message detail: a signature that does not match has no further reason,
         * because the verdict itself is the reason. */
        else if (e.verify == ITS_VERIFY_INVALID && e.verify_why == ITS_VERIFY_WHY_NONE)
            snprintf(why, sizeof(why), "%s", T(S_TRUST_SIG_INVALID));
        else if (e.verify_why == ITS_VERIFY_WHY_NONE)
            snprintf(why, sizeof(why), "&ndash;");
        else
            snprintf(why, sizeof(why), "%s", T(why_name(e.verify_why)));

        /* The identifier in a span, so the key line under it keeps the normal font. */
        HTML_PRINTF(s_row,
            "<tr><td><span class='mono'>%s</span><div class='sub'>%s: %s</div></td>"
            "<td><span class='%s'>%s</span></td><td>%s</td>"
            "<td>%s</td><td>%s</td><td>%s%s%s</td>"
            "<td>%s<div class='sub'><span class='%s'>%s</span></div></td>"
            "<td>%lu</td><td>%s</td></tr>",
            id, T(S_SEC_KEY), key_word(e.key_type), verdict_class(e.verify),
            T(verdict_name(e.verify)), why,
            s_name_a[0] ? s_name_a : "&ndash;",
            e.issuer_from == ITS_VERIFY_ISSUER_BUILTIN ? T(S_TRUST_SRC_BUILTIN)
                : e.issuer_from == ITS_VERIFY_ISSUER_SENT ? T(S_TRUST_SRC_SENT)
                : e.issuer_from == ITS_VERIFY_ISSUER_ROOT ? T(S_TRUST_SRC_ROOT)
                : T(S_TRUST_SRC_NONE),
            s_name_b[0] ? s_name_b : "&ndash;",
            e.verify_env < ITS_TRUST_ENV_COUNT ? " &middot; " : "",
            e.verify_env < ITS_TRUST_ENV_COUNT ? its_trustlist_env_name(e.verify_env) : "",
            span, cls, word,
            (unsigned long)(e.cert_frames + e.digest_frames), msig);
        out_add(req, s_row);
    }
    out_add(req, "</tbody></table></div></div>");
}

/* The newest message checks of its_msgsig.c, newest first: what the sample found, row by row. */
static void msgsig_table(httpd_req_t *req, uint32_t now_unix)
{
    its_msgsig_rec_t r;
    size_t n = 0;
    while (its_msgsig_recent(n, &r))
        n++;
    /* The way back to the counter, the same name as the tile on /system: 69 of 128. */
    char back[128];
    HTML_PRINTF(back, " &middot; <a href='/system?lang=%s#s-cert'>%s</a>",
                web_lang() == LANG_EN ? "en" : "de", T(S_MSIG_TITLE));
    section_head(req, "t-msig", T(S_MSIG_TITLE), (unsigned long)n,
                 n == 1 ? T(S_MSIG_CHECK) : T(S_MSIG_CHECKS), T(S_MSIG_T_HINT), false, back);
#if CONFIG_ENABLE_SD
    /* Only a build with a card records and has the setting the text links to. */
    out_add(req, "<p class='note hlp'>");
    out_add(req, T(S_MSIG_T_REC));
    out_add(req, "</p>");
#endif
    if (!n)
    {
        HTML_PRINTF(s_row, "<p class='note'>%s</p></div>", T(S_MSIG_T_NONE));
        out_add(req, s_row);
        return;
    }
    HTML_PRINTF(s_row, "<div class='scroll'><table><thead><tr>"
                       "<th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th><th>%s</th>"
                       "<th>%s</th></tr></thead><tbody>",
                T(S_COL_TIME), T(S_COL_SENDER), T(S_MSIG_C_MSG), T(S_TRUST_C_ID), T(S_SEC_ALG),
                T(S_TRUST_C_VERDICT), T(S_MSIG_C_US));
    out_add(req, s_row);
    /* The cells are at most 551 bytes (longest reason, a name of quotes only, every number at
     * its widest). Static, off the stack of the httpd task. */
    static EXT_RAM_BSS_ATTR char cells[640];
    /* The name of /senders, escaped: 39 quotes are 6 bytes each as &quot;. */
    static EXT_RAM_BSS_ATTR char name[40], who[240];
    _Static_assert(sizeof name == INV_NAME_LEN && sizeof who == INV_NAME_LEN * 6,
                   "name and who follow INV_NAME_LEN");
    bool inv_busy = false;
    for (size_t i = 0; i < n && its_msgsig_recent(i, &r); i++)
    {
        /* The sender is the name /senders knows. A listed sender without a name is shown as a
         * roadside unit, any other by the road-user word of its station type. After one busy
         * answer the page stops asking, because each lookup on a held list waits 50 ms. */
        int listed = inv_busy ? -1 : inventory_lookup_station(r.station, name, sizeof name);
        inv_busy |= listed < 0;
        who[0] = '\0';
        if (listed > 0 && name[0])
            html_escape(name, who, sizeof who);
        else if (listed > 0)
            snprintf(who, sizeof who, "%s", T(S_CAT_RSU));
        else if (r.stype)
            snprintf(who, sizeof who, "%s", T(web_msgdetail_station_cat(r.stype)));
        if (!web_msgsig_cells(&r, who, its_msgid_name(r.msg_kind), now_unix, web_lang(), cells,
                              sizeof cells))
            continue;
        out_add(req, "<tr>");
        out_add(req, cells);
        out_add(req, "</tr>");
    }
    out_add(req, "</tbody></table></div></div>");
}

/* ================================================================== */

esp_err_t trust_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* First thing, not last: a request that died halfway through the last page left bytes
     * behind, and they must not be shipped on top of this one. */
    s_used = 0;
    send_page_header(req, T(S_TITLE_TRUST));

    uint32_t now_unix = (uint32_t)time(NULL);

    out_add(req, "<p class='note hlp'>");
    out_add(req, T(S_TRUST_INTRO));
    out_add(req, "</p><p class='note hlp'>");
    out_add(req, T(S_TRUST_INTRO_NOT));
    out_add(req, "</p><p class='note hlp'>");
    out_add(req, T(S_TRUST_KEY_NOTE));
    out_add(req, "</p>");
    /* Without a set clock no row may carry a verdict about a date, so the page says it once
     * at the top instead of repeating it in every line. */
    if (!web_clock_set(now_unix))
    {
        out_add(req, "<div class='warn'><p>");
        out_add(req, T(S_TRUST_NOCLOCK_NOTE));
        /* The same remedy as on /system and in the fault bar. Only out_add and T are used,
         * because a host test builds this file with its own stand-ins. */
        out_add(req, web_lang() == LANG_EN ? " <a href='/settings?lang=en#g-net'>"
                                           : " <a href='/settings?lang=de#g-net'>");
        out_add(req, T(S_CLOCK_FIX));
        out_add(req, "</a>");
        out_add(req, "</p></div>");
    }
    HTML_PRINTF(s_row,
        "<p class='jump'>%s: <a href='#t-seen'>%s</a> &middot; <a href='#t-msig'>%s</a>"
        " &middot; <a href='#t-roots'>%s</a> &middot; <a href='#t-ca'>%s</a>"
        " &middot; <a href='#t-crl'>%s</a></p>",
        T(S_TRF_JUMP), T(S_TRUST_H_SEEN), T(S_MSIG_TITLE), T(S_TRUST_H_ROOTS), T(S_TRUST_H_CAS),
        T(S_TRUST_H_CRLS));
    out_add(req, s_row);

    /* The two tables that change in operation come first. The three built-in ones fold away. */
    seen_table(req, now_unix);
    msgsig_table(req, now_unix);
    roots_table(req, now_unix);
    authorities_table(req, now_unix);
    crl_table(req, now_unix);
    /* A link to a folded table (jump line, /system) opens its fold. The script holds no double
     * quote and no backslash, because a host test rejects both on this page. */
    out_add(req, "<script>(function(){function o(h){var g=h&&h.charAt(0)==='#'&&"
                 "document.getElementById(h.slice(1)),f=g&&g.querySelector('details.fold');"
                 "if(f)f.open=true;}o(location.hash);addEventListener('hashchange',function(){"
                 "o(location.hash);});document.addEventListener('click',function(e){"
                 "var a=e.target.closest&&e.target.closest('a');"
                 "if(a)o(a.getAttribute('href')||'');});})();</script>");

    out_add(req, PAGE_FOOTER);
    out_flush(req);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}
