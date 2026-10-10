#pragma once

#include "esp_http_server.h"

/* The re-send form of /senders. The job itself, POST /sdcard/upload_rsu and its status,
 * stays in web_files.c. SD builds only. */
void web_rsu_section(httpd_req_t *req);
