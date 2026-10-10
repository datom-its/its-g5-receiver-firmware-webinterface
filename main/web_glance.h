#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "esp_http_server.h"

/* The start page at a glance: the street row with its tiles, and the entries of the type
 * line as links. httpd task only: the buffers behind all four calls are static. */

/* What the street row shows. amp holds the lamp classes of the newest intersection, space
 * separated, "" for none. ampd and ptd are finished detail lines (HTML). pt_state is the answer
 * of ptlog_latest(): 1 a line, 0 none yet, -1 table busy. warn is web_warn_active()'s count or
 * WEB_WARN_*.
 * Worst measured (German): amp 127 (32 groups), ampd 304 (a name of 39 quotes), pt 11 ("Linie 65535"), ptd 57. */
typedef struct {
    char amp[136];
    char ampd[384];
    char pt[16];
    char ptd[160];
    int  pt_state;
    int  warn;
} gl_view_t;

/* Reads the traffic-light cache, the line table and the warning count. RAM only. */
void web_glance_view(gl_view_t *v);

/* The street row: lights, trams and buses, warnings (SD builds only) and, with `peers`, the
 * other receivers, whose values the peer block fills in through window.glPeer. */
void web_glance_send(httpd_req_t *req, const gl_view_t *v, const char *lc, bool peers);

/* After the poll script: the type line as links, window.glApply and window.glPeer. */
void web_glance_script(httpd_req_t *req, const char *lc);

/* The key "gl" of /status.json, with its leading comma, from a fresh web_glance_view().
 * At most 543 bytes (German, a name of 39 quotes). */
void web_glance_json(char *out, size_t cap);
