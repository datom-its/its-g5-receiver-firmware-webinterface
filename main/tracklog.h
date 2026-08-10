#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Vehicle track log, appended live (~150 points/h) -- deriving it from the PCAP
 * archive would walk a gigabyte over the fragile SD bus. Off by default; RSUs skipped. */

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
