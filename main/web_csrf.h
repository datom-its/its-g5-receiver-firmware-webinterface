#pragma once

#include "esp_http_server.h"

/* The handler of every POST route (webserver_init): another site's POST gets 403, every other
 * one the route in user_ctx. It runs before any password check, so an open device is covered. */
esp_err_t web_csrf_gate(httpd_req_t *req);

/* The ws_pre_handshake_cb of /ws: another site's page gets 403 before the 101, so no WebSocket. */
esp_err_t web_csrf_ws_gate(httpd_req_t *req);
