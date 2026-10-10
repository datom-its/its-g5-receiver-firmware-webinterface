#pragma once

/* The rules for text from the air. read_utf8 in its_decode.c applies them while decoding and
 * add_text_utf8 in web_msgdetail.c as the last step before the page. its_poim.c and infolog.c
 * use them too, so all lists agree. Header only: every host test that builds one of these files
 * gets it without a new source. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* The width of the character a lead byte starts, 0 when it cannot start one, and the
 * bounds of the byte after it. Four lead bytes narrow them (Unicode table 3-7): that is
 * what rules out overlong forms, surrogates and values past U+10FFFF. */
static inline size_t its_utf8_lead(uint8_t c, uint8_t *lo, uint8_t *hi)
{
    *lo = c == 0xE0 ? 0xA0 : c == 0xF0 ? 0x90 : 0x80;
    *hi = c == 0xED ? 0x9F : c == 0xF4 ? 0x8F : 0xBF;
    return c < 0x80 ? 1 : (c >= 0xC2 && c < 0xE0) ? 2 :
           (c >= 0xE0 && c < 0xF0) ? 3 : (c >= 0xF0 && c < 0xF5) ? 4 : 0;
}

/* The code point of a character already checked with its_utf8_lead. */
static inline uint32_t its_utf8_cp(const uint8_t *ch, size_t w)
{
    if (w == 1)
        return ch[0];
    if (w == 2)
        return ((uint32_t)(ch[0] & 0x1F) << 6) | (ch[1] & 0x3F);
    if (w == 3)
        return ((uint32_t)(ch[0] & 0x0F) << 12) | ((uint32_t)(ch[1] & 0x3F) << 6) | (ch[2] & 0x3F);
    return ((uint32_t)(ch[0] & 0x07) << 18) | ((uint32_t)(ch[1] & 0x3F) << 12) |
           ((uint32_t)(ch[2] & 0x3F) << 6) | (ch[3] & 0x3F);
}

/* What is valid UTF-8 and still no text for the page: C0, DEL and C1 controls, and the
 * characters that turn the writing direction of the rest of the line or break it. A U+202E
 * in a station name would show price, spots and even the signature verdict backwards. */
static inline bool its_utf8_unshown(uint32_t cp)
{
    return cp < 0x20 || (cp >= 0x7F && cp < 0xA0) ||
           cp == 0x061C || cp == 0x200E || cp == 0x200F || (cp >= 0x202A && cp <= 0x202E) ||
           (cp >= 0x2066 && cp <= 0x2069) || cp == 0x2028 || cp == 0x2029;
}
