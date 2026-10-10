#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Vehicle track log, appended live. Deriving it from the PCAP archive would
 * walk a gigabyte over the fragile SD bus. Off by default. RSUs are skipped. */

typedef struct {
    uint32_t seconds;
    uint32_t station_id;
    int32_t  lat_e7, lon_e7;
    uint8_t  station_type;
    /* Appended to the end of the row. A point stored before these fields existed reads the
     * sentinels, so a track drawn from old rows still works, only without a direction. */
    uint16_t heading_ddeg;   /* 0.1 degree, its_gn_heading: the CAM's, else the GN position
                              * vector's. 0xFFFF = none */
    uint16_t len_dm;         /* vehicle length in decimetres, 0 = not sent */
    uint8_t  role;           /* VehicleRole, 0xFF = not sent */
    int8_t   lane;           /* LanePosition, 127 = not sent */
} track_pt_t;

/* The sentinels, in the header because the reader and every caller need the same ones. */
#define TRACK_NO_HEADING 0xFFFFu
#define TRACK_NO_ROLE    0xFFu
#define TRACK_NO_LANE    127

/* What a point holds beyond position, handed over as one struct so the hot path keeps
 * a readable call. Every field may be its sentinel. */
typedef struct {
    uint16_t heading_ddeg;   /* 0.1 degree, its_gn_heading: the CAM's, else the GN position
                              * vector's. 0xFFFF = none */
    uint16_t len_dm;
    uint8_t  role;
    int8_t   lane;
} track_extra_t;

void tracklog_init(void);

/* Hot path: offer one decoded vehicle position. No-op when disabled, for
 * infrastructure senders, or below the move/gap threshold. Never touches SD. */
void tracklog_note(uint32_t seconds, uint32_t station_id, uint8_t station_type,
                   int32_t lat_e7, int32_t lon_e7, const track_extra_t *x);

/* Periodic (sysmon): append buffered points to SD, prune rows older than the
 * configured retention. */
void tracklog_tick(void);

/* Losses since boot: queue full, could not queue at all, and appends that failed. The points
 * a failed append did not write stay queued, so they are not lost. */
void tracklog_losses(uint32_t *evicted, uint32_t *dropped, uint32_t *write_fail);

/* Reads points from the last `days` into `out`, oldest first. That is the
 * order a drawn path needs. Returns the count written. */
/* `wrapped` (optional): the ring really did overwrite points. A return of
 * exactly `max` does NOT imply that by itself. */
int tracklog_read(uint32_t days, track_pt_t *out, int max, bool *wrapped);
