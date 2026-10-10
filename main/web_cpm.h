#pragma once

#include "esp_http_server.h"

/* GET /cpm.json: the objects and areas of the CPMs of the last 3 s, with their positions
 * worked out (cpm_store.c, cpm_geo.c). Numbers only, so no ?lang. Other receivers' maps read it
 * too (CORS). */
esp_err_t web_cpm_json_get_handler(httpd_req_t *req);

/* The CPM layer of /map: its help paragraph, its texts and its script. Sent after the map
 * script, whose window.itsMapApi it needs. */
void web_cpm_map_send(httpd_req_t *req);
