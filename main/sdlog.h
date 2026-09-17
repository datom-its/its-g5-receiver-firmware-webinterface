#pragma once

#include <stddef.h>

#include "cmd_sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Upper bound the log budget is clamped to. Exported so the settings page can
 * refuse a larger value instead of echoing it back and quietly using this one. */
#define SDLOG_MAX_MB 512

/* Initialise the SD logger (ring buffer, writer task, system-log hook). Call
 * once at boot AFTER the mount attempt. No-op without CONFIG_ENABLE_SD. */
void sdlog_init(void);

/* Writes the system-log ring to the card immediately rather than waiting for
 * the next 2 s writer cycle. Used before a planned restart or power-off. */
void sdlog_flush_now(void);

/* Copies the last console lines (newline-separated) into out, returns the
 * length. Filled even without a card, which is the point of it. */
size_t sdlog_recent(char *out, size_t cap);

#ifdef __cplusplus
}
#endif
