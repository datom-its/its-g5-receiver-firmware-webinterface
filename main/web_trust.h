#pragma once

#include "esp_http_server.h"

/* GET /trust: the built-in roots, authorities and revocation lists, and the certificates this
 * device saw. The page is long, so it is streamed in chunks instead of built in one buffer. */
esp_err_t trust_get_handler(httpd_req_t *req);
