#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Vehicle track log: where vehicles actually drove, kept for a few days so
 * the map can draw the routes they took. Deliberately NOT derived from the
 * PCAP archive on demand -- three days of recordings is about a gigabyte,
 * which would take minutes to walk and would hammer the SD bus (the very
 * path behind this project's unsolved write faults). Instead a few hundred
 * bytes per hour are appended as they arrive: measured on real traffic,
 * 49-279 vehicle positions an hour from 14-25 distinct vehicles, so three
 * days come to roughly 10,000 points -- well under half a megabyte.
 *
 * Off by default; the map layer and the recording are enabled together in
 * the settings page. RSUs are skipped: they never move. */

typedef struct {
    uint32_t seconds;
    uint32_t station_id;
    int32_t  lat_e7, lon_e7;
    uint8_t  station_type;
} track_pt_t;

void tracklog_init(void);

/* Hot path: offer one decoded vehicle position. No-op when disabled, when
 * the sender is stationary infrastructure, or when this station has not
 * moved far enough since its last recorded point. Never touches the SD card
 * itself -- points are buffered for tracklog_tick(). */
void tracklog_note(uint32_t seconds, uint32_t station_id, uint8_t station_type,
                   int32_t lat_e7, int32_t lon_e7);

/* Periodic (sysmon): append buffered points to SD, prune rows older than the
 * configured retention. */
void tracklog_tick(void);

/* Reads points from the last `days` into `out`, oldest first (the order the
 * file already has, which is what drawing a path needs). Returns the count
 * written. */
int tracklog_read(uint32_t days, track_pt_t *out, int max);
