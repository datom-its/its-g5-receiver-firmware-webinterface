#pragma once

#include "cmd_sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Upper bound the log budget is clamped to. Exported so the settings page can
 * refuse a larger value instead of echoing it back and quietly using this one. */
#define SDLOG_MAX_MB 512

/* Initialise the SD logger (ring buffers, writer task, system-log hook). Call
 * once at boot AFTER the mount attempt; no-op without CONFIG_ENABLE_SD. */
void sdlog_init(void);

/* Writes the system-log ring to the card immediately rather than waiting for
 * the next 2 s writer cycle. Used by the prepare-for-power-off path. */
void sdlog_flush_now(void);

#ifdef __cplusplus
}
#endif
