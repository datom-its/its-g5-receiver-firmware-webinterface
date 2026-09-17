#pragma once

#include "esp_http_server.h"

/* /system: chip, memory, per-task CPU load, the stability counters and the loss
 * table, plus the buttons that erase the core dump and zero the NVS counters. */
esp_err_t system_get_handler(httpd_req_t *req);
esp_err_t system_json_get_handler(httpd_req_t *req);
esp_err_t coredump_clear_post_handler(httpd_req_t *req);
esp_err_t stats_clear_post_handler(httpd_req_t *req);
