#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

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

/* Why the link is down, as far as esp-mqtt reports it. The web side maps each to a text. */
typedef enum {
    MQTT_WHY_NONE = 0,
    MQTT_WHY_DNS,
    MQTT_WHY_UNREACH,
    MQTT_WHY_TLS,
    MQTT_WHY_AUTH,
    MQTT_WHY_REFUSED,
    MQTT_WHY_LOST,
    MQTT_WHY_NONET,
    MQTT_WHY_COUNT
} mqtt_why_t;

typedef struct {
    bool connected;
    bool ever;          /* connected at least once since boot */
    bool wanted;        /* a URI is set */
    int64_t since_us;   /* uptime of the last change, 0 before the first start */
    mqtt_why_t why;
    char host[64];      /* host of the URI the client runs with, without user or password */
} mqtt_state_t;

/* Copy of what the pages show: target host, since when, last reason. */
void mqtt_get_state(mqtt_state_t *out);

#ifdef __cplusplus
}
#endif
