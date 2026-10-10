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

/* Answers 401 with the Basic-Auth challenge: the short text for fetch(), POSTs and the slow
 * worker, the 401 page of web_auth.c for a page load on the httpd task. */
esp_err_t send_auth_required(httpd_req_t *req);

/* Longest path the file pages accept, mount point included. */
#define SD_PATH_MAX 320

/* Decodes %XX and + in place. The result is never longer than the input. */
void url_decode(char *s);

/* ---- shared HTML chrome, for the page modules ---------------------- */

/* A comment like "276 of 320" over a buffer gives the longest text the code can write into it
 * against the buffer's size, worked out from the format and the longest strings of both
 * languages. Brackets after it name the case that gives that length. Whoever makes the format
 * or one of those strings longer has to make sure it still fits. HTML_PRINTF logs a cut. */

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

/* json_esc for the modules: web_glance.c writes names heard over the air into /status.json. */
void web_json_esc(const char *in, char *out, size_t cap);

/* Appends at `at` and returns the new end, never past the buffer. `at += snprintf(...)` adds
 * what snprintf WANTED to write, so after one cut the next call writes into foreign memory.
 * When the text comes from a sender, that write is triggered over the air. A cut is logged
 * like HTML_PRINTF. */
int web_addf(char *buf, size_t cap, int at, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));

/* Sends each string as its own chunk, up to the NULL. For long table texts: a fixed buffer
 * cuts them as soon as their wording grows. Empty strings are skipped, because a chunk of
 * length 0 ends the whole response. */
void web_send_parts(httpd_req_t *req, ...) __attribute__((sentinel));
/* A table text with its <a> tags left out, the words kept: for builds without SD, where some
 * pages a text links to do not exist. Sends nothing for an empty text. */
void web_send_unlinked(httpd_req_t *req, const char *text);
void format_uptime(uint64_t total_sec, char *out, size_t out_size);
void resolve_language(httpd_req_t *req);
void send_page_header(httpd_req_t *req, const char *heading);
extern const char PAGE_FOOTER[];
/* The fault bar of /map and /messages, because their WebSocket carries no faults. */
extern const char FAULT_POLL_JS[];

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

/* True when the capture up to `to_sec` is on the card. A window too old for the
 * ring to still hold part of it counts as written, without forcing a flush. */
bool pcap_window_on_card(uint32_t to_sec);

/* Set by the MQTT event handler. */
extern bool mqtt_connected_state;

/* ---- shared with the system page --------------------------------- */

void send_page_header_refresh(httpd_req_t *req, const char *heading,
                              const char *json_url);

/* For pages that stream or re-fetch themselves; their script must call itsWatch(). */
void send_page_header_live(httpd_req_t *req, const char *heading);

/* A live page with the pause switch in the header; every_s is the poll interval it names,
 * 0 for a stream. Its script must call itsWatch() and follow itsLive. */
void send_page_header_pausable(httpd_req_t *req, const char *heading, uint32_t every_s);

/* The period picker of the search, the playback and the re-send: caption above two date
 * fields. Static buffer, valid until the next call; httpd task only; SD builds only. */
const char *web_range_html(const char *idf, const char *idt);

/* Two minutes without a frame while receiving. The start page, the fault bar and the peer
 * table all use this limit. */
#define WEB_RX_QUIET_SEC 120

/* Seconds without a frame while reception runs, from the later of the last frame and the
 * start of reception; -1 while stopped. */
long web_rx_quiet_s(void);

/* Frames came in every minute for at least 10 minutes before the silence. */
bool web_rx_steady(void);

/* Seconds since the first address, 0 without one. */
uint32_t web_ip_age_sec(void);

/* The clock state as one HTML line. on_system adds the NTP server, the time zone and, while
 * the clock is unset, the link to the setting. */
void web_clock_state(char *out, size_t cap, bool on_system);

/* Sets the configured time zone for every task. Called at boot, after a /settings save that
 * changed it and after an import that applied anything. */
void web_tz_reload(void);
