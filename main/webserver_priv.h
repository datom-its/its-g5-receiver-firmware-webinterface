#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_http_server.h"

#include "web_strings.h"

/* Shared internals for the page modules split out of webserver.c. The public
 * interface stays in webserver.h. */

/* Mount point of the internal FAT storage, browsed read-only under /fs. */
#define DATA_MOUNT "/data"

/* True when no web password is set, or the request carries the right one. */
bool check_update_auth(httpd_req_t *req);

/* Answers 401 with the Basic-Auth challenge. */
esp_err_t send_auth_required(httpd_req_t *req);

/* Longest path the file pages accept, mount point included. */
#define SD_PATH_MAX 320

/* Decodes %XX and + in place. The result is never longer than the input. */
void url_decode(char *s);

/* ---- shared HTML chrome, for the page modules ---------------------- */

/* snprintf that logs when it truncated: cut markup drops closing tags and the
 * browser swallows the rest of the page. -Wformat-truncation can't see runtime strings. */
/* Needs a `TAG` in the including file, so the message names the module. */
#define HTML_PRINTF(buf, ...)                                                  \
    do {                                                                       \
        int _hp_n = snprintf((buf), sizeof(buf), __VA_ARGS__);                 \
        if (_hp_n < 0 || (size_t)_hp_n >= sizeof(buf))                         \
            ESP_LOGE(TAG, "%s:%d: markup truncated, need %d of %u bytes",      \
                     __func__, __LINE__, _hp_n, (unsigned)sizeof(buf));        \
    } while (0)

/* The language this task is serving in. */
lang_t web_lang(void);

/* One text, in the language of this request. A macro, so no one-letter
 * global symbol enters the link. */
#define T(id) web_str((id), web_lang())

void html_escape(const char *in, char *out, size_t out_size);
void format_uptime(uint64_t total_sec, char *out, size_t out_size);
void resolve_language(httpd_req_t *req);
void send_page_header(httpd_req_t *req, const char *heading);
extern const char PAGE_FOOTER[];

/* ---- shared with the file pages ----------------------------------- */

/* One predicate for the SD state, so '/', /sdcard and /status.json cannot
 * disagree. A failed usage query is NOT the same as a missing card. */
typedef enum {
    SDST_OK,         /* mounted, size readable */
    SDST_NO_USAGE,   /* mounted, but esp_vfs_fat_info failed or reported 0 */
    SDST_NO_FS,      /* not mounted: answered, carries no usable FAT */
    SDST_NO_CARD,    /* not mounted: never answered */
    SDST_UNMOUNTED,  /* not mounted on purpose (/poweroff, console unmount) */
    SDST_WRITE_FAILED /* not mounted: taken out after failed writes */
} sd_state_t;

sd_state_t sd_state(uint64_t *total, uint64_t *freeb);

/* CSS class for a value against warn and alarm thresholds, green through red. */
const char *lvl_class(unsigned v, unsigned warn, unsigned alarm);

void format_bytes(uint32_t bytes, char *out, size_t out_size);

/* True when the capture up to `to_sec` is on the card. A window too old for the
 * ring to still hold part of it counts as written, without forcing a flush. */
bool pcap_window_on_card(uint32_t to_sec);

/* Set by the MQTT event handler. */
extern bool mqtt_connected_state;

/* ---- shared with the system page --------------------------------- */

void format_clockline(char *out, size_t cap, const char *sep);
void send_page_header_refresh(httpd_req_t *req, const char *heading,
                              const char *json_url);
