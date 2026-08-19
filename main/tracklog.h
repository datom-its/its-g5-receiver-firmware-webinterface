#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Vehicle track log, appended live -- deriving it from the PCAP archive would
 * walk a gigabyte over the fragile SD bus. Off by default; RSUs skipped. */

typedef struct {
    uint32_t seconds;
    uint32_t station_id;
    int32_t  lat_e7, lon_e7;
    uint8_t  station_type;
} track_pt_t;

void tracklog_init(void);

/* Hot path: offer one decoded vehicle position. No-op when disabled, for
 * infrastructure senders, or below the move/gap threshold. Never touches SD. */
void tracklog_note(uint32_t seconds, uint32_t station_id, uint8_t station_type,
                   int32_t lat_e7, int32_t lon_e7);

/* Periodic (sysmon): append buffered points to SD, prune rows older than the
 * configured retention. */
void tracklog_tick(void);

/* Losses since boot: queue full, could not queue at all, and batches that did
 * not reach the card (retried, so a rate rather than a total loss). */
void tracklog_losses(uint32_t *evicted, uint32_t *dropped, uint32_t *write_fail);

/* Reads points from the last `days` into `out`, oldest first -- the order a
 * drawn path needs. Returns the count written. */
/* `wrapped` (optional): the ring really did overwrite points. A return of
 * exactly `max` does NOT imply that by itself. */
int tracklog_read(uint32_t days, track_pt_t *out, int max, bool *wrapped);
