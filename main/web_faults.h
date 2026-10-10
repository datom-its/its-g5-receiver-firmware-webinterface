#pragma once

/* Faults of the whole device, as one bar under every page heading and as the probs fields of
 * /status.json and /system.json. Only states that need someone to act show. A state chosen on
 * purpose, such as stopped reception or an unmounted card, never shows. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_http_server.h"

typedef enum { FLT_SD, FLT_RX, FLT_CLOCK, FLT_CRASH, FLT_MQTT, FLT_COUNT } flt_id_t;

/* One SD case at a time, by priority: taken out, no file system, full, refusing writes. */
typedef enum { FSD_NONE, FSD_OUT, FSD_NOFS, FSD_FULL, FSD_WRITE } flt_sd_t;

/* Every input as a plain value, so web_faults_decide() runs on the host. */
typedef struct {
    bool     sd_build;       /* built with SD support */
    bool     sd_mounted;
    bool     sd_taken_out;   /* taken out after failed writes */
    bool     sd_no_fs;       /* the last mount found no usable FAT */
    uint32_t sd_dead_ms;     /* since the first failed write that no good write followed */
    uint32_t sd_dead_n;      /* failed writes in that span */
    bool     sd_errno_full;  /* the last test write failed with ENOSPC */
    long     rx_idle_s;      /* seconds without a frame while receiving, -1 while stopped */
    bool     rx_steady;      /* frames came in steadily before the silence */
    int64_t  now_unix;
    uint32_t ip_age_s;       /* seconds since the first address, 0 without one */
    bool     dump;           /* a crash dump waits in flash */
    bool     dump_cleared;   /* deleted on /system this boot */
    bool     boot_crash;     /* this boot followed a crash */
    uint32_t uptime_s;
    bool     mqtt_wanted;    /* a URI is set */
    bool     mqtt_connected;
    uint32_t mqtt_down_s;
} flt_in_t;

typedef struct {
    uint32_t mask;           /* bit (1u << flt_id_t) per active fault */
    flt_sd_t sd;
    uint32_t sd_bad_s, rx_idle_s, mqtt_down_s;
    bool     dump;
} flt_state_t;

/* What a polling page shows itself stays out of its HTML: the rate tile on '/', the crash
 * banner on /system (drawn only with a dump). The JSON keys never skip anything. */
#define FLT_SKIP_STATUS (1u << FLT_RX)
#define FLT_SKIP_SYSTEM (1u << FLT_CRASH)

void web_faults_decide(const flt_in_t *in, flt_state_t *st);

/* Reads the inputs (RAM flags only) and decides. */
void web_faults_get(flt_state_t *st);

/* One <p> per active fault not in skip, with the link to the page that fixes it. Returns the
 * length written. */
int web_faults_html(const flt_state_t *st, uint32_t skip, char *out, size_t cap);

/* Sends the bar under the page heading. When all is well it is an empty hidden container. */
void web_faults_send(httpd_req_t *req);

/* ,"probs":[keys],"probs_html":"lines" for a JSON answer. Static buffer: httpd task only. */
const char *web_faults_json(uint32_t skip);

/* The skip set of /system: FLT_SKIP_SYSTEM while a dump waits (its banner is drawn), else 0,
 * so a crash without a dump still shows in the bar there. */
uint32_t web_faults_skip_system(void);

/* Class of the crash cell on '/' and /system: alarm while the bar shows the crash (24 h or a
 * dump), then a warning while `recent` (web_crash_summary, 7 days). */
const char *web_faults_crash_cls(bool recent);

/* GET /faults.json: {"ok":true,"probs":[...],"probs_html":"..."} for the 30 s bar poll of
 * /map and /messages. Skips nothing: neither page shows a fault topic itself. */
esp_err_t web_faults_json_get_handler(httpd_req_t *req);

/* The SD write rule alone, for the SD tiles on '/' and /sdcard: mounted and refusing writes for
 * the time the take-out rule waits. bad_s gets the seconds, may be NULL. */
bool web_faults_sd_dead(uint32_t *bad_s);
