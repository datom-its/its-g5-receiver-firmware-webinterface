#include "its_gn.h"

#include <string.h>

#include "events_log.h"

#ifdef ESP_PLATFORM
#include "esp_attr.h"
#else
#ifndef EXT_RAM_BSS_ATTR
#define EXT_RAM_BSS_ATTR
#endif
#endif

/* Every layout is EN 302 636-4-1 V1.4.1 clause 9, checked against tshark on recorded traffic.
 * Another GN version is read with the same layout, because only V1.4.1 is at hand. */

#define GN_UNIX_2004_MS 1072915200000LL   /* 2004-01-01 00:00:00 UTC, where TST counts from */
#define GN_ST_RSU       15                /* station type of a roadside unit, table 1 */
#define GN_FLAG_MOBILE  0x80              /* Common Header Flags bit 0 (itsGnIsMobile), table 7 */

static uint16_t be16(const uint8_t *p)
{
    return (uint16_t)(p[0] << 8 | p[1]);
}

static uint32_t be32(const uint8_t *p)
{
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}

void its_gn_fill(its_gn_t *g, const uint8_t *frame, size_t len, const its_decoded_t *d)
{
    if (!g)
        return;
    memset(g, 0, sizeof *g);
    if (!frame || !d)
        return;

    /* Basic Header, table 4: LT at +2, RHL at +3. */
    size_t b = d->gn_basic_at;
    if (b && b + 4 <= len)
    {
        g->lt = frame[b + 2];
        g->rhl = frame[b + 3];
        g->has_basic = true;
    }

    /* Common Header, table 7: HT/HST +1, TC +2 (table 10), Flags +3, MHL +6. Behind a signed
     * envelope only the signed payload belongs to it, so gn_end bounds every read from here on. */
    size_t end = d->gn_end < len ? d->gn_end : len;
    size_t c = d->gn_common_at;
    if (!c || c + 8 > end)
        return;
    g->ht = frame[c + 1];
    g->tc = frame[c + 2];
    g->flags = frame[c + 3];
    g->mhl = frame[c + 6];
    g->has_common = true;

    /* Table 9 defines HT 1 to 6. Behind 0 and 7..15 nothing known follows. */
    uint8_t ht = (uint8_t)(g->ht >> 4), hst = (uint8_t)(g->ht & 0x0F);
    if (ht < 1 || ht > 6)
        return;
    /* GUC, GAC, GBC, multi-hop TSB and LS lead with SN and 2 reserved bytes (tables 11, 12, 14,
     * 16, 17). Beacon and SHB have neither (tables 13, 15, 8.3.2). A TSB sub-type above 1 is read
     * as multi-hop, as its_decode.c does. */
    bool sn_type = ht == 2 || ht == 3 || ht == 4 || ht == 6 || (ht == 5 && hst != 0);
    size_t e = c + 8;
    if (sn_type && e + 2 <= end)
    {
        g->sn = be16(frame + e);
        g->has_sn = true;
    }
    /* Source Long Position Vector, table 2: GN_ADDR +0, TST +8, heading +22. */
    size_t lpv = e + (sn_type ? 4 : 0);
    if (lpv + 24 > end)
        return;
    memcpy(g->addr, frame + lpv, sizeof g->addr);
    g->tst = be32(frame + lpv + 8);
    g->heading_ddeg = be16(frame + lpv + 22);
    g->has_lpv = true;
}

void its_gn_note_rx(its_gn_t *g, uint32_t sec, uint32_t usec)
{
    if (!g)
        return;
    g->age_ms = 0;
    g->has_age = false;
    g->age_off = false;
    /* TST 0 means unknown (8.2.3). Below EVENTS_CLOCK_MIN our clock counts from boot. */
    if (!g->has_lpv || g->tst == 0 || sec < EVENTS_CLOCK_MIN || usec > 999999u)
        return;
    int64_t rx_ms = (int64_t)sec * 1000 + (int64_t)(usec / 1000u);
    /* TST is TAI ms since 2004 mod 2^32 (table 2). Our clock, taken without leap seconds, is a
     * few seconds behind it, so the full value is the one congruent to TST nearest to that. */
    int64_t approx = rx_ms - GN_UNIX_2004_MS;
    int32_t diff = (int32_t)((uint32_t)approx - g->tst);
    int64_t full = approx - diff;
    int64_t age = rx_ms - (int64_t)events_its_to_unix_ms((uint64_t)full);
    if (age < -GN_AGE_MAX_MS || age > GN_AGE_MAX_MS)
    {
        g->age_off = true;
        return;
    }
    g->age_ms = (int32_t)age;
    g->has_age = true;
}

/* One source for Annex A: a window of numbers below the newest instead of a list. */
typedef struct
{
    uint8_t  addr[8];   /* GN_ADDR of the source */
    uint16_t last;      /* newest number heard */
    uint8_t  depth;     /* last - 1 .. last - depth are this run's: heard or counted in a gap */
    uint32_t win;       /* bit k-1: number last - k was heard, k = 1..GN_TRACK_WINDOW */
    uint32_t last_s;    /* now_s of this source's latest frame, copies included */
} gn_src_t;

_Static_assert(sizeof(gn_src_t) == 20, "update the size comment of s_src");
_Static_assert(GN_TRACK_WINDOW == 32, "the window is one uint32_t");

/* 64 x 20 B = 1280 B in PSRAM. Only the receive task reads and writes them. */
static EXT_RAM_BSS_ATTR gn_src_t s_src[GN_TRACK_SOURCES];
static EXT_RAM_BSS_ATTR uint8_t s_used;   /* s_src[0 .. s_used - 1] hold a source */

static void run_start(gn_src_t *s, const its_gn_t *g)
{
    s->last = g->sn;
    s->win = 0;
    s->depth = 0;
}

void its_gn_track(its_gn_t *g, uint32_t now_s)
{
    if (!g)
        return;
    g->sn_cls = GN_SN_NONE;
    g->gap = 0;
    /* A forwarder keeps the source's SN and GN_ADDR, so both together name one packet. */
    if (!g->has_sn || !g->has_lpv)
        return;

    gn_src_t *s = NULL;
    for (uint8_t i = 0; i < s_used; i++)
        if (memcmp(s_src[i].addr, g->addr, sizeof g->addr) == 0)
        {
            s = &s_src[i];
            break;
        }
    if (!s)
    {
        if (s_used < GN_TRACK_SOURCES)
            s = &s_src[s_used++];
        else
        {
            s = &s_src[0];
            for (uint8_t i = 1; i < GN_TRACK_SOURCES; i++)
                if (s_src[i].last_s < s->last_s)
                    s = &s_src[i];
        }
        memcpy(s->addr, g->addr, sizeof s->addr);
        run_start(s, g);
        s->last_s = now_s;
        g->sn_cls = GN_SN_FIRST;
        return;
    }

    uint8_t cls;
    /* After a long silence or a clock that stepped back the numbers in between are unknown. */
    if (now_s < s->last_s || now_s - s->last_s > GN_TRACK_SILENCE_S)
    {
        run_start(s, g);
        cls = GN_SN_FIRST;
    }
    else
    {
        /* SN counts mod 2^16 (8.3.2), so the step is taken mod 2^16 as well. */
        uint16_t d = (uint16_t)(g->sn - s->last);
        if (d == 0)
            cls = GN_SN_DUP;
        else if (d <= GN_TRACK_STEP_MAX)
        {
            s->win = d >= 32 ? 0 : s->win << d;
            if (d <= 32)
                s->win |= 1u << (d - 1);
            /* The d numbers below the new one were heard (the old last) or counted in the gap. */
            uint32_t n = s->depth + (uint32_t)d;
            s->depth = (uint8_t)(n > GN_TRACK_WINDOW ? GN_TRACK_WINDOW : n);
            s->last = g->sn;
            g->gap = (uint16_t)(d - 1);
            cls = GN_SN_NEW;
        }
        else
        {
            uint32_t back = 65536u - d;
            /* Only what this run accounted for can be late: below its start no gap was counted. */
            if (back <= s->depth)
            {
                uint32_t bit = 1u << (back - 1);
                if (s->win & bit)
                    cls = GN_SN_DUP;
                else
                {
                    s->win |= bit;
                    cls = GN_SN_LATE;
                }
            }
            else if (back <= GN_TRACK_STEP_MAX)
                cls = GN_SN_OLD;
            else
            {
                run_start(s, g);
                cls = GN_SN_FIRST;
            }
        }
    }
    s->last_s = now_s;
    g->sn_cls = cls;
}

void its_gn_track_reset(void)
{
    memset(s_src, 0, sizeof s_src);
    s_used = 0;
}

int its_gn_hops(const its_gn_t *g)
{
    /* The source sets RHL = MHL and every forwarder takes one off RHL, never off MHL (table 18,
     * table 7 note). A received RHL of 0 was not to be forwarded (table 4). */
    if (!g || !g->has_basic || !g->has_common || g->rhl == 0 || g->rhl > g->mhl)
        return -1;
    return g->mhl - g->rhl;
}

uint32_t its_gn_lifetime_ms(uint8_t lt)
{
    /* Table 6: the base in bits 1..0, the multiplier 0..63 in bits 7..2. */
    static const uint32_t BASE_MS[4] = { 50, 1000, 10000, 100000 };
    return (uint32_t)(lt >> 2) * BASE_MS[lt & 3];
}

uint16_t its_gn_heading(const its_decoded_t *d, const its_gn_t *g)
{
    if (!d)
        return 0xFFFF;
    /* A CAM has its own heading field, so its LPV heading adds nothing. */
    if (d->message_id == 2)
        return d->cam.has_heading ? d->cam.heading_ddeg : 0xFFFF;
    /* The mobile flag is in the Common Header (table 7), the heading in the LPV (table 2). */
    if (!g || !g->has_common || !g->has_lpv)
        return 0xFFFF;
    if (!(g->flags & GN_FLAG_MOBILE))
        return 0xFFFF;
    /* A roadside unit stands still: what it writes there is no direction of travel (8.2.3). */
    if (((g->addr[0] >> 2) & 0x1F) == GN_ST_RSU)
        return 0xFFFF;
    /* A sender without a heading also writes 0 (8.2.3). 3600 and above are no angle. */
    if (g->heading_ddeg < 1 || g->heading_ddeg > 3599)
        return 0xFFFF;
    return g->heading_ddeg;
}

static uint32_t sat_add(uint32_t a, uint32_t b)
{
    return a > UINT32_MAX - b ? UINT32_MAX : a + b;
}

void its_gn_unit_fold(its_gn_unit_t *u, const its_gn_t *g)
{
    if (!u || !g)
        return;
    switch (g->sn_cls)
    {
    case GN_SN_FIRST:
    case GN_SN_NEW:
    case GN_SN_LATE:
        /* Each number counts once in a run, at its first copy. That copy decides "relayed". */
        u->got = sat_add(u->got, 1);
        if (its_gn_hops(g) > 0)
            u->relayed = sat_add(u->relayed, 1);
        if (g->sn_cls == GN_SN_NEW)
            u->missing = sat_add(u->missing, g->gap);
        /* A late number fills a gap counted before; a saturated count stays. */
        else if (g->sn_cls == GN_SN_LATE && u->missing > 0 && u->missing < UINT32_MAX)
            u->missing--;
        break;
    case GN_SN_DUP:
        u->dup = sat_add(u->dup, 1);
        break;
    default:   /* none, or too far below to tell */
        break;
    }
}
