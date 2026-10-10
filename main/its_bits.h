#pragma once

/* Bit and byte readers shared by the ITS message decoders. UPER messages are
 * read bit by bit, and the IEEE 1609.2 envelope in COER uses byte lengths. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* MSB-first bit cursor over a byte buffer. `err` latches on the first read past
 * the end, so a decoder can check it once after a whole walk. */
typedef struct {
    const uint8_t *b;
    size_t nbits, pos;
    bool err;
} its_bitr_t;

static inline its_bitr_t its_bitr_init(const uint8_t *buf, size_t len_bytes, size_t start_bit)
{
    its_bitr_t r = { buf, len_bytes * 8, start_bit, false };
    return r;
}

/* Reads n bits, at most 32. */
static inline uint32_t its_bits_read(its_bitr_t *r, unsigned n)
{
    uint32_t v = 0;
    for (unsigned i = 0; i < n; i++)
    {
        if (r->pos >= r->nbits) { r->err = true; return v; }
        v = (v << 1) | ((r->b[r->pos >> 3] >> (7 - (r->pos & 7))) & 1u);
        r->pos++;
    }
    return v;
}

/* Skips n bits, for fields and extensions a decoder does not keep. */
static inline void its_bits_skip(its_bitr_t *r, size_t n)
{
    if (r->pos + n > r->nbits) { r->pos = r->nbits; r->err = true; return; }
    r->pos += n;
}

/* X.691 unconstrained length determinant. Fragmented lengths (16384 and more)
 * do not occur in these messages, so they set `err`. */
static inline size_t its_bits_uper_length(its_bitr_t *r)
{
    if (its_bits_read(r, 1) == 0) return its_bits_read(r, 7);
    if (its_bits_read(r, 1) == 0) return its_bits_read(r, 14);
    r->err = true;
    return 0;
}

/* COER length prefix at byte `off`. Short form below 128, long form with up to
 * four length bytes. Returns false when it would run past `len`. */
static inline bool its_oer_length(const uint8_t *buf, size_t len, size_t off,
                                  size_t *value_len, size_t *field_len)
{
    if (off >= len) return false;
    uint8_t b0 = buf[off];
    if ((b0 & 0x80) == 0)
    {
        *value_len = b0;
        *field_len = 1;
        return true;
    }
    size_t n = b0 & 0x7F;
    if (n == 0 || n > 4 || off + 1 + n > len)
        return false;
    size_t v = 0;
    for (size_t i = 0; i < n; i++)
        v = (v << 8) | buf[off + 1 + i];
    *value_len = v;
    *field_len = 1 + n;
    return true;
}
