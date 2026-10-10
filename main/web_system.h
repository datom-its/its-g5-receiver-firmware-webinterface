#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_http_server.h"

/* /system: chip, memory, per-task CPU load, the stability counters, radio reception
 * and the loss tables, plus the buttons that erase the core dump and zero the NVS counters. */
esp_err_t system_get_handler(httpd_req_t *req);
esp_err_t system_json_get_handler(httpd_req_t *req);
esp_err_t coredump_clear_post_handler(httpd_req_t *req);
esp_err_t stats_clear_post_handler(httpd_req_t *req);

/* Reads the flash once, at webserver start. */
void web_coredump_scan(void);
/* True while a crash dump waits in flash. The delete button on /system clears it. */
bool web_coredump_present(void);
/* The delete button on /system was used this boot. */
bool web_coredump_cleared(void);

/* One rule for the crash cell on / and /system: amber for a crash in the last 7 days or
 * right before this boot. Writes how long ago the last crash was into `ago` and returns true
 * for amber. */
bool web_crash_summary(char *ago, size_t cap);
/* Why this boot happened, in the language of the request. */
const char *web_reset_reason(void);

/* True while the Ethernet address is an AutoIP fallback: 169.254.0.0/16 with DHCP configured. */
bool web_autoip_active(void);

/* The notice for such an address, naming the .local host. `id` may be NULL. With `hidden` the
 * notice starts hidden, and the page's poll of /status.json or /system.json shows it. */
void web_autoip_note(char *out, size_t cap, bool hidden, const char *id);

/* The /status.json fields eth_autoip, rx_nf_avg, rx_broken and warn_active, each after a
 * comma. Only the httpd task may call it, because the warning copy is static. */
void web_status_extra_json(char *out, size_t cap);

#define WEB_WARN_UNKNOWN (-1)   /* no SD support, or the warning store is busy */
#define WEB_WARN_NOCLOCK (-2)   /* the clock is not set: no warning can be active */
/* Active DENM warnings now, or WEB_WARN_*. httpd task only: the copy is static. */
int web_warn_active(void);
