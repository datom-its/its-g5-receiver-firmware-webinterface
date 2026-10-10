#pragma once

#include "esp_http_server.h"

/* The settings as a file: GET /settings/export.json downloads it, POST
 * /settings/import takes it back as a form upload. Both behind the web password. */
esp_err_t settings_export_get_handler(httpd_req_t *req);
esp_err_t settings_import_post_handler(httpd_req_t *req);
