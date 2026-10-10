#pragma once

/* The MQTT state in words, for the start page, /settings and /status.json. */

#include <stddef.h>

#include "mqtt.h"

/* "to <host>" ("an <host>" in German) without user or password. Empty when the URI has no
 * plain host. */
void web_mqtt_target(const mqtt_state_t *s, char *out, size_t cap);

/* Since when and why the link is down: empty while connected and during the first try.
 * sep goes between time and reason: "&middot;" for HTML, a raw middle dot for JSON. */
void web_mqtt_detail(const mqtt_state_t *s, const char *sep, char *out, size_t cap);

/* The state row of /settings: connected or not, the target, and the detail line. */
void web_mqtt_state_cell(char *out, size_t cap);
