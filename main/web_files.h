#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "esp_http_server.h"

/* The Files page: the SD card and the internal flash, plus the uploads and
 * the format button. All of their URIs start with /sdcard or /fs. */
esp_err_t sdcard_get_handler(httpd_req_t *req);
esp_err_t sdcard_download_handler(httpd_req_t *req);
esp_err_t sdcard_upload_handler(httpd_req_t *req);
esp_err_t sdcard_delete_handler(httpd_req_t *req);
esp_err_t sdcard_format_handler(httpd_req_t *req);
esp_err_t sdcard_mount_handler(httpd_req_t *req);
esp_err_t rsu_upload_post_handler(httpd_req_t *req);
esp_err_t rsu_upload_status_handler(httpd_req_t *req);
esp_err_t internal_get_handler(httpd_req_t *req);
esp_err_t internal_download_handler(httpd_req_t *req);
esp_err_t partimg_download_handler(httpd_req_t *req);

/* True if the string contains a byte below 0x20, which has no business in a
 * file name and would break a header line. Also used by web_tar.c. */
bool has_control_char(const char *s);

/* Byte count with a unit. 64-bit, because SD sizes exceed the 32-bit range. */
void format_bytes64(uint64_t bytes, char *out, size_t out_size);
