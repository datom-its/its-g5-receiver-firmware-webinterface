#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Warning-event log: every DENM (decentralized environmental notification --
 * i.e. a hazard/traffic warning) is recorded with time, sender station type
 * and position to /sdcard/logs/events.csv, so a 24 h..30 d history survives
 * reboots. The "Verkehr" web page lists them. The `cause` field is reserved
 * carries the decoded DENM cause category (0 = unknown). */

/* One row per WARNING EVENT, not per message. A hazard is re-broadcast for
 * as long as it lasts -- one real event produced 71 messages in a capture --
 * so repeats carrying the same ActionID are folded into a single record with
 * a count and a last-seen time. Listing every message instead made the page
 * both endless and misleading about how much was actually happening. */
typedef struct {
    uint32_t seconds;       /* unix time first seen */
    uint32_t last_seen;     /* unix time of the most recent repeat */
    uint32_t action_station;/* ActionID: originating station ... */
    uint16_t action_seq;    /* ... and sequence number */
    uint16_t count;         /* messages folded into this event */
    uint8_t  station_type;  /* ETSI ITS-S type of the sender */
    uint8_t  cause;         /* DENM cause code, 0 = unspecified */
    uint8_t  subcause;      /* detail within that cause, 0 = unspecified */
    int32_t  lat_e7;        /* event position (0 if none) */
    int32_t  lon_e7;
} event_rec_t;

void events_init(void);

/* Hot path: record a warning if message_id is a DENM (1). Cheap; queues for
 * the sysmon tick to write (SD I/O stays off the sniffer path). */
void events_note(uint32_t seconds, uint8_t station_type, uint8_t message_id,
                 uint8_t cause, uint8_t subcause,
                 uint32_t action_station, uint16_t action_seq,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7);

/* Periodic (sysmon): flush queued events to SD, prune old rows. */
void events_tick(void);

/* Reads the most-recent events within the last `hours` into `out`
 * (newest-first). Returns the count written. */
int events_read(uint32_t hours, event_rec_t *out, int max);
