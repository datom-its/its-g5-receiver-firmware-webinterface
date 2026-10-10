#pragma once

#include <stddef.h>
#include <stdint.h>

#include "its_sechdr.h"
#include "web_strings.h"

/* The signature header in words: the items of the grey signature line on /messages and the
 * line of a roadside unit on /senders. HTML without quotes or backslashes, so the message feed
 * can put it into a JSON string unchanged. `out` stays terminated, and an item that does not
 * fit is left out whole, never cut. */

/* Append the header items of one message after `used` bytes, each behind " &middot; " (the first
 * one only when used > 0). `cache_key` is the key of the signing certificate from the certificate
 * cache, 0xFF when unknown. The key of a certificate in the frame takes precedence. Nothing
 * without h->read. Returns the new length, which stays below cap. */
size_t web_sechdr_append(const its_sechdr_t *h, uint8_t cache_key, lang_t lang,
                         char *out, size_t used, size_t cap);

/* The line of one roadside unit: algorithm, key when it differs, height, deviations. Returns
 * the length, 0 when there is nothing to say. */
size_t web_sechdr_unit(const its_sechdr_unit_t *u, lang_t lang, char *out, size_t cap);
