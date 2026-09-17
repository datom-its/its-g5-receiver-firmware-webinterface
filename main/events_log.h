#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Warning-event log: DENMs are recorded (time, sender type, position, cause)
 * to /sdcard/logs/events.csv. The traffic page lists them. */

/* One row per warning EVENT, not per message: repeats with the same ActionID
 * fold into one record with count + last-seen. */
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
    /* Appended, never inserted: a row from an older CSV leaves these at 0. */
    uint32_t sender_id;     /* ITS station id of the message (originator when
                             * forwarded), 0 = unknown */
    int8_t   rssi_min;      /* dBm, frames of sender_id only. 0 = no reading. Narrower
                             * than inventory's int16_t because the filter keeps (-128, 0). */
    int8_t   rssi_max;      /* span of the stretch observed here, not of the whole warning:
                             * a slot is closed after 120 s of silence and reopens later. */
    bool     multi_sender;  /* the same ActionID also arrived from another station id */
    /* Appended, never inserted. Only the MAC shows a relay: a re-broadcasting
     * RSU keeps the originator's stationId, so multi_sender stays blind to it. */
    uint8_t  mac_a[6];      /* radio source of the first frame heard */
    uint8_t  mac_b[6];      /* first DIFFERENT radio source, all-zero = none */
    uint16_t count_b;       /* broadcasts attributed to mac_b */
    uint16_t b_after_s;     /* seconds from the event's first frame to the first mac_b one */
    uint8_t  n_macs;        /* 0 = no radio source, 1 = one, 2 = mac_a and mac_b.
                             * Above 2 it counts FRAMES from further sources. */
} event_rec_t;

void events_init(void);

/* Hot path: record a warning if message_id is a DENM (1). Cheap; queues for
 * the sysmon tick to write (SD I/O stays off the sniffer path). */
/* `rssi` in dBm as the driver gave it, 0 = no reading (wired path); it is only
 * kept while it can be attributed to `sender_id`. */
/* `src_mac` is the 802.11 sender address or NULL (wired path): two different
 * ones on one ActionID mean the warning was re-broadcast. */
void events_note(uint32_t seconds, uint8_t station_type, uint32_t sender_id, int rssi,
                 uint8_t message_id,
                 uint8_t cause, uint8_t subcause,
                 uint32_t action_station, uint16_t action_seq,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7,
                 const uint8_t *src_mac);

/* Periodic (sysmon): flush queued events to SD, prune old rows. */
void events_tick(void);

/* Queued warnings displaced before they reached the card, since boot. */
uint32_t events_evicted(void);

/* Reads events of the last `hours` into `out`, newest first; returns the count.
 * Includes still-broadcast warnings, which reach the card only once quiet. */
/* `history_ok` (optional) goes false when the stored events could not be read.
 * The caller must say so, not pass the RAM-only remainder off as complete. */
/* `capped` (optional): rows were actually displaced. A return of exactly
 * `max` does NOT imply that by itself. */
int events_read(uint32_t hours, event_rec_t *out, int max, bool *history_ok,
                bool *capped);
