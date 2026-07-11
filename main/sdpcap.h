#pragma once

#include "cmd_sniffer.h"

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

typedef void (*sdpcap_position_cb_t)(uint32_t seconds, uint32_t microseconds,
                                      uint32_t station_id, int32_t lat_e7, int32_t lon_e7,
                                      bool has_speed, int32_t speed_cmps,
                                      const char *label, void *ctx);

/* Reads back stored PCAP files covering [from_sec, to_sec] (device
 * wall-clock epoch seconds), decoding each frame's position (and speed, for
 * vehicles) via its_decode_frame() and invoking cb for each one found, in
 * chronological order. Read-only, independent of whether capture is
 * currently enabled; no-ops if CONFIG_ENABLE_SD is off or the SD card isn't
 * mounted. */
void sdpcap_read_positions(uint32_t from_sec, uint32_t to_sec, sdpcap_position_cb_t cb, void *ctx);

#ifdef __cplusplus
}
#endif
