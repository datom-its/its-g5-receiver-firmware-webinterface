#pragma once

#include "esp_http_server.h"

/* The 401 answer to a page load: status, the page with menu that names the user and the way
 * back in. The caller has set WWW-Authenticate. httpd task only (static buffers). */
esp_err_t web_auth_page(httpd_req_t *req);
