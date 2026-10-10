#pragma once

#include <stddef.h>
#include <stdint.h>

#include "events_log.h"
#include "its_gn.h"
#include "web_strings.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The GeoNetworking headers in words: the last items of the grey line on /messages, the line of
 * a warning on /traffic and of a roadside unit on /senders. HTML without quotes or backslashes,
 * so the message feed can put it into a JSON string unchanged. An item that does not fit is
 * left out whole, never cut. */

/* Append the items of one frame after `used` bytes, each behind " &middot; " (the first one only
 * when used > 0): hops, position age, sequence number, lifetime, traffic class, mobility. Nothing
 * without g->has_basic. Returns the new length, which stays below cap. */
size_t web_gn_append(const its_gn_t *g, lang_t lang, char *out, size_t used, size_t cap);

/* The line of one warning: relayed up to, also direct, only relayed, missing. Returns the length,
 * 0 when there is nothing to say. */
size_t web_gn_event(const event_rec_t *e, lang_t lang, char *out, size_t cap);

/* The line of one roadside unit: missing with its share, only relayed. Returns the length, 0
 * before a first number was heard. */
size_t web_gn_unit(const its_gn_unit_t *u, lang_t lang, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
