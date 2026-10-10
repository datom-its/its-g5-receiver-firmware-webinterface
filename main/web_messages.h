#pragma once

#include "esp_http_server.h"

/* GET /messages: the newest frames, kept live over /ws. */
esp_err_t messages_get_handler(httpd_req_t *req);

/* The archive search and its .pcap export. SD builds only; webserver.c hands them to the
 * slow worker. */
esp_err_t messages_search_stream(httpd_req_t *req);
esp_err_t messages_export_stream(httpd_req_t *req);
