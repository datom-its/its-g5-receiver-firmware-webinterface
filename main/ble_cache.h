#pragma once

/* Taken from the V2Xtend fork (MIT, Copyright Peter Holzhauser and
 * githubapache2), adapted here: the ring lives in PSRAM and DENMs are
 * recognised with its_peek_message_id() from its_decode.h. */

#include <stdbool.h>
#include <stdint.h>

/* Backlog for the stretches without a BLE client: frames that
 * bt_stream_publish_packet() drops are kept here and replayed DENM-first when a
 * client (re)subscribes. Only the BLE stream is affected. */

/* Ring sits in PSRAM, so the bound is usefulness, not memory -- more slots would
 * mostly bury a freshly connected client under stale CAMs. */
#define BLE_CACHE_CAPACITY  64
/* Keep in step with the recording path's frame bound (PCAP_MAX_FRAME, sdpcap.c):
 * a frame the live path would send must not be dropped here for being long. */
#define BLE_CACHE_SLOT_MAX  2048

/* Idempotent; must run before the first ble_cache_store(). bt_stream_init()
 * does this, and nothing publishes frames before that. */
void ble_cache_init(void);

/* Store one frame (only while BLE is disconnected / not subscribed -- bt_stream.c
 * owns that check). Over-long frames are ignored; a full ring evicts the oldest
 * non-DENM first, so hazards outlive routine traffic. */
void ble_cache_store(const uint8_t *payload, uint16_t len, uint32_t sec, uint32_t usec);

/* Number of frames currently held (logging/diagnostics, read without the lock). */
int ble_cache_count(void);

typedef void (*ble_cache_emit_fn)(const uint8_t *payload, uint16_t len,
                                  uint32_t sec, uint32_t usec, void *ctx);

/* Drain through `emit`, DENMs first, oldest first within each group. `emit` runs
 * synchronously in the caller's task with the lock released, so pacing stays with
 * the caller; only one drain runs at a time, a concurrent call returns at once. */
void ble_cache_drain(ble_cache_emit_fn emit, void *ctx);
