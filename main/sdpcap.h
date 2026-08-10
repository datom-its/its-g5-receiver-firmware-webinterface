#pragma once

#include "cmd_sniffer.h"
#include "its_decode.h"   /* its_decoded_t, handed to the playback callback */

#ifdef __cplusplus
extern "C" {
#endif

/* Continuous rolling PCAP capture of received raw frames to the SD card
 * (config-toggleable, hourly-rotated, age+size-pruned) -- a real,
 * tshark-readable capture, independent of the JTAG/console-oriented
 * cmd_pcap.c debug tool. See main/sdpcap.c for the on-disk layout. */
void sdpcap_init(void);

/* Called from the sniffer's hot path for every received packet; no-ops
 * internally if capture is disabled or not yet initialized. */
void sdpcap_handle_packet(sniffer_packet_info_t *packet);

/* Writes whatever is currently buffered in the ring to the card immediately,
 * instead of waiting for the next scheduled flush (which can be minutes
 * away). Used by the prepare-for-power-off path; safe to call any time.
 * Returns the number of bytes written. */
size_t sdpcap_flush_now(void);

/* Hands over the whole decode result (a hand-picked subset silently lagged
 * behind the live map). Return false to abort the walk (client hung up). */
typedef bool (*sdpcap_position_cb_t)(uint32_t seconds, uint32_t microseconds,
                                      const its_decoded_t *decoded, void *ctx);

/* Reads stored PCAPs covering [from_sec, to_sec], decoding each frame's
 * position via its_decode_frame and invoking cb chronologically. Read-only. */
void sdpcap_read_positions(uint32_t from_sec, uint32_t to_sec, sdpcap_position_cb_t cb, void *ctx);

#ifdef __cplusplus
}
#endif
