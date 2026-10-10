#pragma once

#include "cmd_sniffer.h"
#include "its_decode.h"   /* its_decoded_t, handed to the playback callback */

#ifdef __cplusplus
extern "C" {
#endif

/* Continuous rolling PCAP capture to SD (hourly-rotated, age+size-pruned). The
 * files are tshark-readable. Separate from the console debug tool in cmd_pcap.c. */
void sdpcap_init(void);

/* Called from the sniffer's hot path for every received packet. Does nothing if
 * capture is disabled or not yet initialized. */
void sdpcap_handle_packet(sniffer_packet_info_t *packet);

/* Flushes the ring now, or only the bytes still owed to the previous hour. Returns the bytes
 * that LEFT THE RING. `ok` says whether they reached the card, so test `ok`, not the count. */
size_t sdpcap_flush_now(bool *ok);

/* Bytes captured but not yet on the card. Zero after a flush is the only reliable test
 * for "everything is on the card". The flush's return value cannot tell. */
size_t sdpcap_buffered(void);

/* Configured flush interval in seconds. The writer empties the ring on this
 * interval, so callers use it to judge whether a past window is on the card. */
uint32_t sdpcap_flush_sec(void);

/* Frames the recorder lost since boot: oversized, ring full, or dropped at an
 * hour boundary (estimated from bytes). Thinned frames are not counted here. */
uint32_t sdpcap_dropped(void);
/* Mid-hour flushes by the writer task that failed or wrote only part. */
uint32_t sdpcap_flush_fails(void);
/* Frames the thinning filter dropped on purpose, since boot. */
uint32_t sdpcap_filtered(void);

/* Hands over the whole decode result. Return false to abort the walk (client
 * hung up). */
typedef bool (*sdpcap_position_cb_t)(uint32_t seconds, uint32_t microseconds,
                                      const its_decoded_t *decoded, void *ctx);

/* Reads stored PCAPs covering [from_sec, to_sec] in order, read-only, skipping missing hours.
 * False means the card was busy or gone and the rest went unread, so do not claim coverage. */
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
