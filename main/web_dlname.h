#pragma once

#include <stddef.h>
#include <time.h>

/* The Content-Disposition value of web_dl_disp: 162 bytes with a 63-byte node id and a
 * 63-byte what (22 + 4 + 63 + 1 + 63 + 1 + 7 + 1). */
#define WEB_DL_DISP_MAX 192

/* Local time as YYYYMMDD-HHMM in the device zone, the shape of the hourly files on the SD
 * card, whatever the page date format is. Empty while the clock is not set. */
void web_dl_stamp(char *out, size_t cap, time_t t);

/* attachment; filename="its-<node id>-<what>.<ext>" for a download. httpd keeps the pointer
 * until the first chunk, so out must live that long. Returns out. */
const char *web_dl_disp(char *out, size_t cap, const char *what, const char *ext);
