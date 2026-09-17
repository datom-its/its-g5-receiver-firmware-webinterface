#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "cmd_sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

void mqtt_init(void);
void mqtt_handle_packet(sniffer_packet_info_t *packet);

/* Queues a raw frame for publishing and waits briefly for queue space. Used by
 * the manual PCAP re-send, where a silent drop would falsify the "N sent"
 * report. Returns false when disconnected or the queue stayed full. */
bool mqtt_replay_frame(const uint8_t *data, size_t length);

/* Replay frames queued but not yet handled by the tx worker. The queue is
 * shared with the live feed, so only these counters track the re-send. */
uint32_t mqtt_replay_pending(void);

/* Live-feed frames dropped because the publish queue was full, since boot. */
uint32_t mqtt_tx_dropped(void);

/* Total replay frames the tx worker could not publish, counted at dequeue.
 * Cumulative. Callers diff against a sample taken at their start. */
uint32_t mqtt_replay_dropped(void);

#ifdef __cplusplus
}
#endif
