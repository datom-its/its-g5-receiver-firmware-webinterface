#pragma once

#include "esp_http_server.h"

/* A whole folder or a multi-file selection as one .tar, streamed. Used by
 * /sdcard/tar and /fs/tar. */
esp_err_t sdcard_tar_handler(httpd_req_t *req);
esp_err_t internal_tar_handler(httpd_req_t *req);
