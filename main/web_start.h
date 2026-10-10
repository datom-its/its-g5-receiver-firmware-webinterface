#pragma once

#include "esp_http_server.h"

/* GET /, the start page, and GET /status.json, which the start page polls. Other programs and
 * the peer tables of other receivers read it too. */
esp_err_t status_page_handler(httpd_req_t *req);
esp_err_t status_json_get_handler(httpd_req_t *req);
