#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_decode.h"
#include "its_gn.h"

/* Warning-event log: DENMs are recorded to /sdcard/logs/events.csv, one row per warning with
 * the fields of event_rec_t. The traffic page lists them. */

/* The rest of the DENM, as its newest version sent it. 0 is a real value in 8 of the 12 fields,
 * so "not sent" has its own value in each: see EVENT_DENM_UNSENT. */
typedef struct {
    uint8_t  aware_dist;    /* ITS_DENM_DIST_*, the warning range */
    uint8_t  traffic_dir;   /* ITS_DENM_DIR_* */
    uint8_t  road_type;     /* ITS_DENM_ROAD_* */
    uint8_t  info_quality;  /* 0..7, ITS_DENM_QUALITY_NONE = no situation container */
    uint16_t tx_interval_ms;/* how often the sender repeats it, 0 = not sent */
    uint8_t  n_traces;      /* 1..7, 0 = no location container */
    uint8_t  path_len;      /* points of the first trace as sent, 0..40; belongs to n_traces */
    uint16_t speed_cms;     /* at the spot, EVENT_SPEED_NONE = not sent */
    uint16_t heading_ddeg;  /* at the spot, EVENT_HEADING_NONE = not sent */
    int32_t  alt_cm;        /* of the event position, EVENT_ALT_NONE = not sent */
    uint8_t  origin_type;   /* StationType of who raised it, ITS_DENM_STATION_NONE = not sent */
    uint8_t  n_hist;        /* points of eventZone/eventHistory, the extent; 0 = not sent */
} event_denm_t;             /* 20 B, 2 free (riscv32 measured) */

/* One row per warning EVENT, not per message: repeats with the same ActionID
 * fold into one record with count + last-seen. */
typedef struct {
    uint32_t seconds;       /* unix time first seen */
    uint32_t last_seen;     /* unix time of the most recent repeat */
    uint32_t action_station;/* ActionID: originating station ... */
    uint16_t action_seq;    /* ... and sequence number */
    uint16_t count;         /* messages folded into this event */
    uint8_t  station_type;  /* ETSI ITS-S type of the sender */
    uint8_t  cause;         /* DENM cause code, 0 = unspecified. A newer version of the
                             * warning that carries a cause replaces it and the subcause. */
    uint8_t  subcause;      /* detail within that cause, 0 = unspecified */
    int32_t  lat_e7;        /* event position (0 if none) */
    int32_t  lon_e7;
    /* Appended, never inserted: a row from an older CSV leaves these at 0. */
    uint32_t sender_id;     /* ITS station id of the message (originator when
                             * forwarded), 0 = unknown */
    int8_t   rssi_min;      /* dBm, frames of sender_id heard straight from it only
                             * (its_gn_hops <= 0, not from relay_mac). 0 = no reading. Narrower
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
    /* Appended, never inserted. They describe the newest version of the warning,
     * the one with the latest referenceTime. ev_state_fold() in events_log.c has the rule. */
    uint64_t detection_ms;  /* TimestampIts: ms since 2004-01-01 UTC, leap seconds counted */
    uint64_t reference_ms;
    uint32_t validity_s;    /* seconds after detection_ms */
    uint8_t  validity_src;  /* EVENT_VALIDITY_*. NONE means the three fields above are unknown. */
    uint8_t  termination;   /* ITS_DENM_TERM_* */
    uint8_t  area_shape;    /* ITS_GN_AREA_*, NONE = no GeoBroadcast area heard */
    uint16_t area_a_m;      /* distance a in metres, the radius of a circle */
    uint16_t area_b_m;
    uint16_t area_angle_deg;/* degrees from north */
    int32_t  area_lat_e7;   /* centre of the area */
    int32_t  area_lon_e7;
    /* Appended, never inserted: the rest of the DENM as its newest version sent it. A frame
     * that leaves a field out keeps the known value. */
    event_denm_t denm;
    /* Appended, never inserted: how this stretch travelled (its_gn.h). Only frames with a readable
     * hop count set the three hop fields, and gn_mhl 0 means none came. Like the level, these
     * fields are not inherited by a reopened slot. */
    uint8_t  gn_mhl;        /* maximum hop limit of the newest such frame, unless it does not
                             * exceed gn_hops_max (events_read wants hops below it) */
    uint8_t  gn_hops_min;   /* fewest forwarders a frame had passed, 0 = heard directly */
    uint8_t  gn_hops_max;   /* most forwarders */
    uint16_t gn_got;        /* packets of the source, each sequence number once */
    uint16_t gn_relayed;    /* of those, first heard through a forwarder */
    uint16_t gn_missing;    /* numbers of the source skipped, found on this stretch's frames */
    /* Appended, never inserted: who the stretch came from and through whom. Only frames of
     * sender_id count, like the level, and nothing is inherited. All-zero address = none came. */
    uint8_t  orig_mac[6];   /* radio source of the first 0-hop frame, unless it relayed first */
    uint8_t  relay_mac[6];  /* radio source of the first frame of it that a forwarder passed on */
    int8_t   relay_rssi_min;/* dBm, only frames that came through relay_mac; 0 = no reading */
    int8_t   relay_rssi_max;
    uint8_t  gn_src_mid[6]; /* MID of the first readable GN source address; forwarders keep it */
} event_rec_t;              /* 152 B, orig_mac at 126, gn_src_mid at 140 (riscv32 measured) */

/* ETSI's own "unavailable": 0 is a real value. */
#define EVENT_SPEED_NONE   16383
#define EVENT_HEADING_NONE 3601
#define EVENT_ALT_NONE     800001
#define EVENT_TX_MAX_MS    16384   /* 14 bits plus 1, what the decoder can pass */

/* Every literal of an event_rec_t sets .denm to this. Left at zero, it would claim 50 m, all
 * directions, built-up area, standstill, north and sea level. */
#define EVENT_DENM_UNSENT { .aware_dist = ITS_DENM_DIST_NONE, .traffic_dir = ITS_DENM_DIR_NONE, \
    .road_type = ITS_DENM_ROAD_NONE, .info_quality = ITS_DENM_QUALITY_NONE, \
    .speed_cms = EVENT_SPEED_NONE, .heading_ddeg = EVENT_HEADING_NONE, \
    .alt_cm = EVENT_ALT_NONE, .origin_type = ITS_DENM_STATION_NONE }

/* The widest row, every column at its type's widest, is 394 characters with '\n'.
 * 53 bytes are left with the NUL: a column that needs more raises it. */
#define EVENTS_LINE_MAX 448

/* One row with '\n', 0 when it does not fit. */
size_t events_format_row(const event_rec_t *e, char *out, size_t cap);

#define EVENT_VALIDITY_NONE    0
#define EVENT_VALIDITY_DEFAULT 1   /* the DENM left the field out, so 600 s apply */
#define EVENT_VALIDITY_SENT    2

/* Timestamps below this are seconds since boot, not a set clock. */
#define EVENTS_CLOCK_MIN 1600000000u

typedef enum {
    EVENT_STATE_UNKNOWN = 0,   /* no set clock, or the DENM's times were not read */
    EVENT_STATE_ACTIVE,
    EVENT_STATE_EXPIRED,
    EVENT_STATE_CANCELLED,     /* ended by the station that raised it */
    EVENT_STATE_NEGATED,       /* declared over by another station */
} event_state_t;

/* TimestampIts in Unix milliseconds. */
uint64_t events_its_to_unix_ms(uint64_t its_ms);

/* Unix second from which the warning is no longer valid, 0 when unknown. */
uint32_t events_valid_until(const event_rec_t *e);

/* A termination decides without a clock. Otherwise `now` (Unix seconds) must be at
 * least EVENTS_CLOCK_MIN. Without known times only a long silence proves expiry. */
event_state_t events_state(const event_rec_t *e, uint32_t now);

void events_init(void);

/* Hot path: record a warning if message_id is a DENM (1). Cheap, because it only
 * updates RAM. The sysmon tick writes the row once the warning has gone quiet, so
 * SD I/O stays off the sniffer path. */
/* `rssi` in dBm as the driver gave it, 0 = no reading (wired path). It is only
 * kept while it can be attributed to `sender_id`. */
/* `src_mac` is the 802.11 sender address or NULL (wired path): two different
 * ones on one ActionID mean the warning was re-broadcast. It also names who the
 * stretch came from and through whom (orig_mac, relay_mac; see `gn`). */
/* `d` (NULL allowed) supplies termination, times, validity, the GeoBroadcast area and the
 * rest of the DENM (event_denm_t). It also lets a newer version of the warning replace the
 * cause. */
/* `gn` (NULL allowed) tells how the frame travelled. Only frames straight from the source give
 * the level. A hop count of 0 gives the first address, and a forwarded frame gives the first
 * forwarder and its level. A readable header gives the source's own address, its MID, which
 * forwarders keep. A header that does not say or contradicts itself counts as straight for the
 * level but gives no address. Hop counts and sequence numbers come from every frame of the
 * warning. */
void events_note(uint32_t seconds, uint8_t station_type, uint32_t sender_id, int rssi,
                 uint8_t message_id,
                 uint8_t cause, uint8_t subcause,
                 uint32_t action_station, uint16_t action_seq,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7,
                 const uint8_t *src_mac, const its_decoded_t *d, const its_gn_t *gn);

/* Periodic (sysmon): flush queued events to SD, prune old rows. */
void events_tick(void);

/* Before a planned restart or power-off: the warnings still being sent are queued as if they
 * had gone quiet now, and events_tick writes them. One still sent afterwards gets a second row. */
void events_flush_now(void);

/* Queued warnings displaced before they reached the card, since boot. */
uint32_t events_evicted(void);

/* Reads events of the last `hours` into `out`, newest first, and returns the count.
 * Includes still-broadcast warnings, which reach the card only once quiet. */
/* `history_ok` (optional) goes false when the stored events could not be read.
 * The caller must say so, not pass the RAM-only remainder off as complete. */
/* `capped` (optional): rows were actually displaced. A return of exactly
 * `max` does NOT imply that by itself. */
int events_read(uint32_t hours, event_rec_t *out, int max, bool *history_ok,
                bool *capped);

/* Most records events_current can return: every open slot plus the closed ones kept in RAM. */
#define EVENTS_CURRENT_MAX 40

/* The warnings held in RAM, without touching the card: those still being
 * repeated and the most recently closed ones. One record per ActionID. */
/* Returns -1 when the lock was busy. `capped` (optional) goes true when `max`
 * cut the list, or while a displaced record might still be valid. */
int events_current(event_rec_t *out, int max, bool *capped);
