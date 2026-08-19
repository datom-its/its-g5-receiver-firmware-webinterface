#pragma once

#include "cmd_sniffer.h"
#include "its_decode.h"   /* its_decoded_t, handed to the playback callback */

#ifdef __cplusplus
extern "C" {
#endif

/* Continuous rolling PCAP capture to SD (hourly-rotated, age+size-pruned) --
 * tshark-readable, independent of the console-oriented cmd_pcap.c debug tool. */
void sdpcap_init(void);

/* Called from the sniffer's hot path for every received packet; no-ops
 * internally if capture is disabled or not yet initialized. */
void sdpcap_handle_packet(sniffer_packet_info_t *packet);

/* Flushes the ring to the card now. Returns the bytes that LEFT THE RING; `ok`
 * is the separate question of whether they arrived -- test `ok`, not the count. */
size_t sdpcap_flush_now(bool *ok);

/* Bytes captured but not yet on the card. Zero after a flush is the honest test
 * for "everything is on the card"; the flush's return value cannot tell. */
size_t sdpcap_buffered(void);

/* Configured flush interval in seconds. A window that ended longer ago than
 * this is on the card by construction -- callers use it instead of guessing. */
uint32_t sdpcap_flush_sec(void);

/* Frames the recorder lost (ring full or oversized) and frames it dropped on
 * purpose via the thinning filter, since boot. */
uint32_t sdpcap_dropped(void);
uint32_t sdpcap_filtered(void);

/* Hands over the whole decode result (a hand-picked subset silently lagged
 * behind the live map). Return false to abort the walk (client hung up). */
typedef bool (*sdpcap_position_cb_t)(uint32_t seconds, uint32_t microseconds,
                                      const its_decoded_t *decoded, void *ctx);

/* Reads stored PCAPs covering [from_sec, to_sec] chronologically. Read-only.
 * Returns false when the range could NOT be fully read -- do not claim coverage. */
bool sdpcap_read_positions(uint32_t from_sec, uint32_t to_sec, sdpcap_position_cb_t cb, void *ctx);

/* Raw-frame variant: cb also gets the frame bytes and sees EVERY decoded frame,
 * not just those with a position. Return false to abort. */
typedef bool (*sdpcap_frame_cb_t)(uint32_t seconds, uint32_t microseconds,
                                  const uint8_t *frame, size_t frame_len,
                                  const its_decoded_t *decoded, void *ctx);
bool sdpcap_read_frames(uint32_t from_sec, uint32_t to_sec, sdpcap_frame_cb_t cb, void *ctx);

#ifdef __cplusplus
}
#endif
