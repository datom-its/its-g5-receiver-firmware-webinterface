#include "web_msgdetail_priv.h"

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

/* Who signed it, what the checks say about that, what its signature header claims and how the
 * frame travelled: the second half. */
void sign_parts(sb_t *b, const msg_extra_t *x, const uint8_t *src_mac,
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
