#pragma once

/* BLE live stream of received ITS-G5 frames (NimBLE peripheral).
 *
 * Ported from the V2Xtend fork (main/bt_stream.h), MIT licence,
 * Copyright (c) Peter Holzhauser and githubapache2. V2Xtend is a sibling fork
 * of the same upstream; see NOTICE for this tree's provenance.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Starts the BLE peripheral. No-op when CONFIG_INDEX_BT_ENABLE is off — then
 * neither NimBLE's heap nor the duty-cycled sniffer is paid for. */
void bt_stream_init(void);

/* Hands one captured frame to the BLE stream. Cheap no-op while bt_stream_init
 * has not succeeded. Called from the sniffer packet path. */
void bt_stream_publish_packet(const uint8_t *payload, uint16_t len, uint32_t sec, uint32_t usec);

/* Frames dropped since boot: notify failed on the connection / publish queue
 * was full. Both stay 0 while the BLE stream is off. */
uint32_t bt_stream_dropped_notify(void);
uint32_t bt_stream_dropped_enqueue(void);

#ifdef __cplusplus
}
#endif
