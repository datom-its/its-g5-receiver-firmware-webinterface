#pragma once

#include "cmd_sniffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the HTTP server on port 80. Call once at boot. */
void webserver_init(void);

/* Feed a received sniffer packet into the web message log ring buffer.
 * Safe to call from the sniffer task. Only the decoded fields are kept, not
 * the raw payload, so the ring stays bounded. */
void webserver_handle_packet(sniffer_packet_info_t *packet);

#ifdef __cplusplus
}
#endif
