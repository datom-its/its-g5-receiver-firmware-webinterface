#pragma once

#include "esp_http_server.h"

/* /settings: everything the device lets you change, and the POST that
 * saves it. Both behind the web password. */
esp_err_t settings_get_handler(httpd_req_t *req);
esp_err_t settings_post_handler(httpd_req_t *req);
