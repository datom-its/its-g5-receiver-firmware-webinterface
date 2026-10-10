#pragma once

#include "esp_http_server.h"

/* GET /map and what only the map reads: the phases (/spatem.json) and lanes (/lanes.json). */
esp_err_t map_get_handler(httpd_req_t *req);
esp_err_t spatem_json_handler(httpd_req_t *req);
esp_err_t lanes_json_handler(httpd_req_t *req);

/* SD builds only: /markers.json for the maps of other receivers, the tracks and the playback.
 * webserver.c hands the last two to the slow worker. */
esp_err_t markers_json_handler(httpd_req_t *req);
esp_err_t tracks_get_handler(httpd_req_t *req);
esp_err_t playback_get_handler(httpd_req_t *req);
