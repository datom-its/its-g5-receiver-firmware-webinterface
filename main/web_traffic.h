#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_http_server.h"

#include "spatem.h"

/* /traffic: counts by road user per hour (per day for the longer windows),
 * the signal groups of every intersection, and the warning list. */
esp_err_t traffic_get_handler(httpd_req_t *req);

/* Warning texts, also used by the map popups. */
const char *denm_cause_text(uint8_t cause);
const char *denm_sub_text(uint8_t cause, uint8_t sub);

/* One movement of a signal group, as text. */
void spat_movement_text(const spatem_intersection_t *e, uint8_t sg,
                        char *out, size_t out_size);
