#pragma once

#include <stddef.h>

#include "cmd_sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Upper bound the log budget is clamped to. Exported so the settings page can
 * refuse a larger value instead of echoing it back and quietly using this one. */
#define SDLOG_MAX_MB 512

/* Size of the RAM console (sdlog_recent, sdlog_previous): lines, and bytes per line with its
 * terminator. A full copy of either needs SDLOG_CONSOLE_LINES * SDLOG_CONSOLE_LEN + 1 bytes.
 * A start writes more than 64 lines before the network is up. */
#define SDLOG_CONSOLE_LINES 256
#define SDLOG_CONSOLE_LEN   160

/* Starts the RAM console: keeps the lines it held when the device last restarted (see
 * sdlog_previous) and puts the system-log hook in. Call once, first thing in app_main, so the
 * console sees everything app_main logs. No-op without CONFIG_ENABLE_SD. */
void sdlog_console_start(void);

/* Initialise the SD logger (ring buffer, writer task; the system-log hook too if
 * sdlog_console_start was not called). Call once at boot AFTER the mount attempt.
 * No-op without CONFIG_ENABLE_SD. */
void sdlog_init(void);

/* Writes the system-log ring to the card immediately rather than waiting for
 * the next 2 s writer cycle. Used before a planned restart or power-off. */
void sdlog_flush_now(void);

/* Copies the last console lines (newline-separated) into out, returns the
 * length. Filled even without a card, which is the point of it. */
size_t sdlog_recent(char *out, size_t cap);

/* Same for the lines the console held when the device last restarted, crash included. Empty
 * after a power cut, on the first start, after most firmware updates (the ring then sits at
 * another PSRAM address) and without PSRAM. */
size_t sdlog_previous(char *out, size_t cap);

#ifdef __cplusplus
}
#endif
