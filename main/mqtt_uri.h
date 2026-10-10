#pragma once

/* One reader for the MQTT URI: the settings form, the import and mqtt.cpp must split it the
 * same way. Pure C without IDF headers, so the host tests compile it as it is. */

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Four U+2022 in UTF-8. /settings shows it in place of the password. */
#define MQTT_URI_MASK "\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2\xE2\x80\xA2"

/* Longest host mqtt_uri_host() returns. mqtt_state_t.host has room for it plus the NUL. */
#define MQTT_URI_HOST_MAX 63

/* Copies uri with the password replaced by the mask, or unchanged when it has none. False and
 * out = "" when it does not fit: the mask can make the URI up to 11 bytes longer. */
bool mqtt_uri_mask(const char *uri, char *out, size_t cap);

/* True when the password part contains U+2022, i.e. the mask came back from the form. */
bool mqtt_uri_has_mask(const char *uri);

/* The host alone, "" when absent or not plain: only [A-Za-z0-9._-] or an [IPv6] literal, at
 * most MQTT_URI_HOST_MAX bytes. So it needs no escaping in HTML or JSON. */
void mqtt_uri_host(const char *uri, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
