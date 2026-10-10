#include "sdkconfig.h"

#include "sd_rcache.h"

/* A build without SD support never calls these. */
#if CONFIG_ENABLE_SD

#include <string.h>

/* Compares the anchor in small steps, so it needs no shared buffer and little stack on the
 * httpd task. */
static bool same_anchor(const sdrc_t *c, FILE *f)
{
    char b[64];
    if (fseek(f, (long)(c->off - c->alen), SEEK_SET) != 0)
        return false;
    for (uint16_t k = 0; k < c->alen;)
    {
        size_t n = c->alen - k < sizeof b ? (size_t)(c->alen - k) : sizeof b;
        if (fread(b, 1, n, f) != n || memcmp(b, c->anchor + k, n) != 0)
            return false;
        k += (uint16_t)n;
    }
    return true;
}

FILE *sdrc_open(sdrc_t *c, const char *path, uint32_t gen, bool may_tail)
{
    c->tail = false;
    bool try_tail = may_tail && c->valid && c->gen == gen && c->off > 0;
    c->valid = false;
    c->gen = gen;
    c->lost = false;
    c->pend = 0;
    FILE *f = fopen(path, "r");
    if (f && try_tail && same_anchor(c, f))
    {
        c->tail = true;
        c->pos = c->end = c->off;
        return f;
    }
    c->off = c->pos = c->end = 0;
    c->alen = 0;
    /* Reopen, so the caller gets a fresh FILE as without a cache. A read error of the check
     * then stays with the closed one. */
    if (f && try_tail)
    {
        fclose(f);
        f = fopen(path, "r");
    }
    return f;
}

/* The anchor rolls on with the read: it was compared at open, and only sdrc_done uses it again. */
static void keep_last(sdrc_t *c, const char *b, size_t n)
{
    if (n >= SDRC_ANCHOR)
    {
        memcpy(c->anchor, b + n - SDRC_ANCHOR, SDRC_ANCHOR);
        c->alen = SDRC_ANCHOR;
        return;
    }
    size_t keep = c->alen + n > SDRC_ANCHOR ? SDRC_ANCHOR - n : c->alen;
    memmove(c->anchor, c->anchor + c->alen - keep, keep);
    memcpy(c->anchor + keep, b, n);
    c->alen = (uint16_t)(keep + n);
}

/* fgets stops at the first '\n', so one found before the piece's end is its last byte. In a
 * piece that ran into the end of the file, NUL bytes may hide the true length. The cached
 * place therefore stays before such a piece. */
void sdrc_piece(sdrc_t *c, FILE *f, const char *b, size_t cap)
{
    if (c->lost)
        return;
    const char *nl = memchr(b, '\n', cap - 1);
    if (feof(f) || (!nl && b[cap - 1] != '\0'))
    {
        c->lost = true;
        return;
    }
    size_t n = nl ? (size_t)(nl - b) + 1 : cap - 1;
    keep_last(c, b, n);
    c->pos += (uint32_t)n;
    c->pend = nl ? 0 : c->pend + (uint32_t)n;
    if (nl)
        c->end = c->pos;
}

void sdrc_done(sdrc_t *c, FILE *f, bool ok)
{
    if (!ok || c->end == 0)
        return;
    /* Pieces of a row cut at the end lie past the place. If they leave too short an anchor,
     * the anchor is read once more. That only happens after a failed write or an append
     * during tstat_read. */
    uint32_t want = c->end < SDRC_ANCHOR ? c->end : SDRC_ANCHOR;
    if (c->alen < c->pend + want)
    {
        if (fseek(f, (long)(c->end - want), SEEK_SET) != 0 ||
            fread(c->anchor, 1, want, f) != want)
            return;
        c->alen = (uint16_t)want;
    }
    else
        c->alen = (uint16_t)(c->alen - c->pend);
    c->off = c->end;
    c->valid = true;
}

#endif /* CONFIG_ENABLE_SD */
