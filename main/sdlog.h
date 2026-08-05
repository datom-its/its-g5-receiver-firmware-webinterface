#pragma once

#include "cmd_sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Initialise the SD logger: allocates PSRAM ring buffers, starts the writer
 * task, and installs the system-log hook. Call once at boot, after the SD card
 * mount has been attempted. Safe to call when CONFIG_ENABLE_SD is off (no-op).
 * Logging only actually happens when enabled in config and the card is mounted. */
void sdlog_init(void);

/* Feed a received frame into the CSV frame log. No-op when frame logging is
 * disabled or the SD card is unavailable. Safe to call from the sniffer task;
 * only enqueues into a buffer, never touches the SD card directly. */
void sdlog_handle_packet(sniffer_packet_info_t *packet);

/* Writes both ring buffers (system log, frame log) to the card immediately
 * rather than waiting for the next 2 s writer cycle. Used by the
 * prepare-for-power-off path; safe to call any time. */
void sdlog_flush_now(void);

#ifdef __cplusplus
}
#endif
