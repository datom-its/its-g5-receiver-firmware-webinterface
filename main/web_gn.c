#include "web_gn.h"

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

#include "web_fmt.h"

/* A third copy of the string writer sb_t of web_msgdetail_priv.h, as in web_sechdr.c. A host test
 * expects sb_t exactly once in that header, and only the detail-line files include it. */
typedef struct
{
    char  *s;
    size_t cap;
    size_t n;
    bool   full;                 /* Set by the first piece that did not fit. */
} gw_t;

#define SEP " &middot; "
/* The warning sign of web_sechdr.c. The grey line has no warning colour, so the sign says it. */
#define GN_WARN "&#9888; "
/* The no-break space of web_fmt.c, so "950 ms" is spelled like fmt_us and fmt_dur write. */
#define NBSP "\xC2\xA0"
#define S(id) web_str((id), lang)

static void gw_add(gw_t *w, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

static void gw_add(gw_t *w, const char *fmt, ...)
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

static size_t item_begin(gw_t *w)
{
    size_t mark = w->n;
    if (w->n)
        gw_add(w, "%s", SEP);
    return mark;
}

/* An item that did not fit is taken back whole, and nothing after it is tried. */
static void item_end(gw_t *w, size_t mark)
{
    if (w->full)
    {
        w->n = mark;
        w->s[mark] = '\0';
    }
}

/* The remarks of one item share one bracket, separated by commas. */
static void note(gw_t *w, int *k, const char *s)
{
    gw_add(w, "%s%s", (*k)++ ? ", " : " (", s);
}

/* Hops from RHL and MHL (clause 10.3.2 table 18). SHB and Beacon go one hop by design
 * (RHL = MHL = 1), so they say nothing here. */
static void hops_item(gw_t *w, const its_gn_t *g, lang_t lang)
{
    if (!g->has_common || (g->rhl == 1 && g->mhl == 1))
        return;
    int h = its_gn_hops(g);
    size_t m = item_begin(w);
    if (h < 0)
    {
        gw_add(w, "%s", GN_WARN);
        gw_add(w, S(S_GN_HOPS_BAD), (unsigned)g->rhl, (unsigned)g->mhl);
    }
    else
    {
        if (h == 0)
            gw_add(w, "%s", S(S_GN_DIRECT));
        else
            gw_add(w, S(S_GN_RELAYED), (unsigned)h);
        /* Past the 1/1 case above mhl is at least 2 here, so the plural always fits. */
        gw_add(w, ", ");
        gw_add(w, S(S_GN_MAXHOPS), (unsigned)g->mhl);
        /* The MID of the source address is its MAC, which a forwarder keeps (table 1). */
        if (h > 0 && g->has_lpv)
        {
            char mac[18];            /* 17 of 18 */
            const uint8_t *a = g->addr + 2;
            snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x", a[0], a[1], a[2], a[3],
                     a[4], a[5]);
            gw_add(w, ", ");
            gw_add(w, S(S_GN_ORIGIN), mac);
        }
    }
    item_end(w, m);
}

/* The words and rule of the signing time in web_sechdr.c: an age of 0 ms is at reception, not
 * "0,0 ms" before it. From 1 ms on the position came first. */
static void age_item(gw_t *w, const its_gn_t *g, lang_t lang)
{
    if (!g->has_age && !g->age_off)
        return;
    size_t m = item_begin(w);
    if (g->has_age && g->age_ms == 0)
        gw_add(w, "%s %s", S(S_GN_POS), S(S_SEC_AT_RX));
    else if (g->has_age)
    {
        char d[FMT_US_MAX];
        bool before = g->age_ms >= 0;
        uint64_t ms = before ? (uint64_t)g->age_ms : (uint64_t)(-(int64_t)g->age_ms);
        fmt_us(ms * 1000u, lang, d, sizeof d);
        gw_add(w, "%s %s %s", S(S_GN_POS), d, S(before ? S_SEC_BEFORE_RX : S_SEC_AFTER_RX));
    }
    else
        gw_add(w, "%s", S(S_GN_POS_CLOCK));
    item_end(w, m);
}

/* FIRST, OLD and NONE (archive search, playback) get no remark: nothing to compare with. */
static void sn_item(gw_t *w, const its_gn_t *g, lang_t lang)
{
    if (!g->has_sn)
        return;
    size_t m = item_begin(w);
    gw_add(w, S(S_GN_SN), (unsigned)g->sn);
    if (g->sn_cls == GN_SN_DUP)
        gw_add(w, " (%s)", S(S_GN_SN_DUP));
    else if (g->sn_cls == GN_SN_LATE)
        gw_add(w, " (%s)", S(S_GN_SN_LATE));
    else if (g->sn_cls == GN_SN_NEW && g->gap)
    {
        gw_add(w, " (");
        gw_add(w, S(S_GN_SN_GAP), (unsigned)g->gap);
        gw_add(w, ")");
    }
    item_end(w, m);
}

/* Exact, not rounded: LT counts 50-ms steps. "950 ms", "3,15 s", "60 s", "105 min". */
static void life_item(gw_t *w, const its_gn_t *g, lang_t lang)
{
    uint32_t ms = its_gn_lifetime_ms(g->lt);
    size_t m = item_begin(w);
    gw_add(w, "%s ", S(S_GN_LIFETIME));
    if (ms < 1000)
        gw_add(w, "%lu" NBSP "ms", (unsigned long)ms);
    else if (ms % 1000 == 0)
    {
        char d[FMT_DUR_MAX];
        fmt_dur(ms / 1000, FMT_DUR_EXACT, d, sizeof d);
        gw_add(w, "%s", d);
    }
    else
    {
        /* Only the decimals the value needs. The fraction is not 0 here, so the loop ends. */
        unsigned f = ms % 1000, dig = 3;
        while (f % 10 == 0)
        {
            f /= 10;
            dig--;
        }
        gw_add(w, "%lu%c%0*u" NBSP "s", (unsigned long)(ms / 1000), lang == LANG_DE ? ',' : '.',
               (int)dig, f);
    }
    item_end(w, m);
}

/* TS 102 636-4-2 table 4: TC ID 0 to 3 are the four access categories of ITS-G5, AC_VO first. */
static void tc_item(gw_t *w, const its_gn_t *g, lang_t lang)
{
    static const str_id_t PRIO[4] = { S_GN_PRIO_0, S_GN_PRIO_1, S_GN_PRIO_2, S_GN_PRIO_3 };
    if (!g->has_common)
        return;
    unsigned id = g->tc & 0x3F;
    int k = 0;
    size_t m = item_begin(w);
    gw_add(w, S(S_GN_TCLASS), id);
    note(w, &k, id < 4 ? S(PRIO[id]) : S(S_GN_TC_UNDEF));
    if (g->tc & 0x80)
        note(w, &k, S(S_GN_SCF));
    if (g->tc & 0x40)
        note(w, &k, S(S_GN_OFFLOAD));
    gw_add(w, ")");               /* the bracket always holds the class word */
    item_end(w, m);
}

/* Only a contradiction is news: a roadside unit that calls itself mobile, a vehicle that does not.
 * The station type is in the source address, bits 6..2 of its first byte (table 1). */
static void mobility_item(gw_t *w, const its_gn_t *g, lang_t lang)
{
    if (!g->has_common || !g->has_lpv)
        return;
    unsigned st = (g->addr[0] >> 2) & 0x1F;
    bool mobile = (g->flags & 0x80) != 0;
    str_id_t id;
    if (st == 15 && mobile)
        id = S_GN_MOBILE;
    else if (st >= 1 && st <= 14 && !mobile)
        id = S_GN_FIXED;
    else
        return;
    size_t m = item_begin(w);
    gw_add(w, "%s", S(id));
    item_end(w, m);
}

size_t web_gn_append(const its_gn_t *g, lang_t lang, char *out, size_t used, size_t cap)
{
    if (!out || !cap || used >= cap)
        return used;
    out[used] = '\0';
    if (!g || !g->has_basic)
        return used;
    gw_t w = { out, cap, used, false };
    hops_item(&w, g, lang);
    age_item(&w, g, lang);
    sn_item(&w, g, lang);
    life_item(&w, g, lang);
    tc_item(&w, g, lang);
    mobility_item(&w, g, lang);
    return w.n;
}

size_t web_gn_event(const event_rec_t *e, lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    out[0] = '\0';
    if (!e)
        return 0;
    gw_t w = { out, cap, 0, false };
    size_t m;
    /* mhl 0: no frame with a readable hop count came, the hop fields say nothing. */
    if (e->gn_mhl && e->gn_hops_max > 0)
    {
        m = item_begin(&w);
        gw_add(&w, S(S_EVT_GN_RELAYED), (unsigned)e->gn_hops_max);
        item_end(&w, m);
        if (e->gn_hops_min == 0)
        {
            m = item_begin(&w);
            gw_add(&w, "%s", S(S_EVT_GN_DIRECT));
            item_end(&w, m);
        }
    }
    if (e->gn_relayed)
    {
        m = item_begin(&w);
        gw_add(&w, S(S_EVT_GN_ONLY_RELAY), (unsigned)e->gn_relayed, (unsigned)e->gn_got);
        item_end(&w, m);
    }
    if (e->gn_missing)
    {
        m = item_begin(&w);
        gw_add(&w, S(S_EVT_GN_MISSING), (unsigned)e->gn_missing);
        item_end(&w, m);
    }
    return w.n;
}

size_t web_gn_unit(const its_gn_unit_t *u, lang_t lang, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    out[0] = '\0';
    if (!u || !u->got)
        return 0;
    gw_t w = { out, cap, 0, false };
    /* The share of what was sent: the missing ones count in the whole. */
    char pct[24];                /* "100,0" at the most: 5 of 24 */
    fmt_dec(u->missing * 100.0 / ((double)u->got + u->missing), 1, false, lang, pct, sizeof pct);
    size_t m = item_begin(&w);
    gw_add(&w, S(S_SND_SN_MISS), (unsigned long)u->missing);
    gw_add(&w, " (%s&nbsp;%%)", pct);
    item_end(&w, m);
    if (u->relayed)
    {
        m = item_begin(&w);
        gw_add(&w, S(S_SND_SN_RELAY), (unsigned long)u->relayed);
        item_end(&w, m);
    }
    return w.n;
}
