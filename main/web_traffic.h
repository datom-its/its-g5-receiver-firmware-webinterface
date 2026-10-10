#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_http_server.h"

#include "spatem.h"

/* /traffic: counts by road user per hour (per day for the longer windows),
 * the signal groups of every intersection, and the warning list. */
esp_err_t traffic_get_handler(httpd_req_t *req);

/* JSON for the map: warnings held in RAM that carry a GeoBroadcast area, active
 * ones and those ended within the last hour. Needs CONFIG_ENABLE_SD. */
esp_err_t traffic_areas_json_handler(httpd_req_t *req);

/* POST: delete the priority requests or the phase history on the card. Behind the web password,
 * like /senders/clear. Both need CONFIG_ENABLE_SD. */
esp_err_t traffic_prio_clear_post_handler(httpd_req_t *req);
esp_err_t traffic_phases_clear_post_handler(httpd_req_t *req);

/* Warning texts, also used by the map popups. */
const char *denm_cause_text(uint8_t cause);

/* Lamp class (g, y, r, ry, off) of a MovementPhaseState, as on /traffic and /map. */
const char *web_phase_lamp(uint8_t phase);
const char *denm_sub_text(uint8_t cause, uint8_t sub);

/* One movement of a signal group, as text. */
void spat_movement_text(const spatem_intersection_t *e, uint8_t sg,
                        char *out, size_t out_size);
