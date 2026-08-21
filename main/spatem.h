#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "its_decode.h"

/* Live traffic-light cache: current phase per signal group, purely in-RAM
 * (a "right now" view, nothing persisted). Sized for a handful of intersections. */

#define SPATEM_MAX_INT 8   /* distinct intersections cached (most-recent wins) */

typedef struct {
    uint16_t region;                     /* RoadRegulatorID (0 = absent) */
    uint16_t id;                         /* IntersectionID */
    uint16_t status;                     /* ITS_ISTAT_* controller mode/fault flags */
    uint8_t  revision;
    uint8_t  n;                          /* signal groups populated */
    uint8_t  sg[ITS_SPAT_MAX_SG];
    uint8_t  phase[ITS_SPAT_MAX_SG];
    /* Unix second the current phase is expected to end (0 = unknown). Absolute,
     * not a countdown; carried forward until that group's phase flips. */
    uint32_t change_at[ITS_SPAT_MAX_SG];
    /* Last time ANYTHING was heard, SPATEM or MAPEM: an RSU whose SPATEM we
     * cannot decode is still alive and must not be evicted first. */
    uint32_t last_seen;
    /* Last time PHASES were decoded -- the age beside the phase dots must use
     * this; last_seen there made stale phases read as fresh. 0 = never. */
    uint32_t phase_seen;
    uint32_t station_id;                 /* ItsPduHeader.stationId (map-marker key) */
    char     name[ITS_MAP_NAME_LEN];     /* from MAPEM, "" until one arrives */
    uint16_t lane_width_cm;              /* from MAPEM, 0 = not sent */
    uint16_t speed_max_kmh, speed_min_kmh;
    /* What each signal group controls, from the MAPEM lane geometry.
     * Indexed independently of sg[]/phase[] above -- look up by group id. */
    uint8_t  map_n;
    uint8_t  map_sg[ITS_SPAT_MAX_SG];
    uint16_t map_man[ITS_SPAT_MAX_SG];
    bool     map_ped[ITS_SPAT_MAX_SG];
    bool     has_pos;
    int32_t  lat_e7, lon_e7;             /* RSU position (0 if unknown) */
} spatem_intersection_t;

/* Measured phase durations per signal group -- the controller never states them.
 * Kept out of the cache entry: display data, four internal-RAM copies cost ~28 KB. */
typedef struct {
    /* 0 = green, 1 = red-amber (pre-movement), 2 = amber, 3 = red. Red-amber
     * kept apart: mixed in, the amber column is a blend, not a duration. */
    uint32_t secs[ITS_SPAT_MAX_SG][4];
    uint32_t cnt[ITS_SPAT_MAX_SG][4];    /* never scaled: halving it made the
                                          * shown observation count a lie */
    uint32_t max[ITS_SPAT_MAX_SG][4];    /* seconds; 16 bit overflowed at a
                                          * light resting in one phase */
    /* Start of the running phase on the MONOTONIC clock (uptime seconds), not
     * wall clock: an NTP step must not lengthen or shorten a measured phase. */
    uint32_t since[ITS_SPAT_MAX_SG];
    /* Bit r: row r's phase start is KNOWN (flip watched without a gap); after a
     * gap it must not be counted. ITS_SPAT_MAX_SG is 32, exactly the width. */
    uint32_t armed;
    /* Rows keyed by SIGNAL GROUP ID, never by position in the message: by
     * position, an omitted group lost its history and a doubled one counted twice. */
    uint8_t  sg[ITS_SPAT_MAX_SG];
    uint8_t  n_rows;
    uint8_t  phase[ITS_SPAT_MAX_SG];      /* eventState when last seen */
    uint32_t last_mono[ITS_SPAT_MAX_SG];  /* monotonic time of that sighting */
    /* mono_now() at the instant of the copy: the caller cannot read that clock
     * and would otherwise time a running phase against the wall clock. */
    uint32_t now_mono;
} spatem_phases_t;

/* Reception gap that voids a running phase measurement: beyond this we cannot
 * tell whether the light flipped while we were not listening. */
#define SPAT_GAP_SEC 10

/* Copies the phase tallies for one cached intersection (by region+id) under
 * the module lock. False = that intersection is not cached. */
bool spatem_phases(uint16_t region, uint16_t id, spatem_phases_t *out);

void spatem_init(void);

/* Hot path: fold a decoded SPATEM into the cache (find-or-insert by region+id).
 * No-op if `s` is invalid; safe from the sniffer/web packet path. */
void spatem_note(const its_spat_t *s, uint32_t station_id, uint32_t seconds,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7);

/* Attach a MAPEM's name and group-to-movement map to the region+id entry;
 * creates one if the phases have not been seen yet. */
void spatem_note_name(const its_map_t *m, uint32_t seconds);

/* Looks up what signal group `sg` of the given intersection controls.
 * Returns false when the MAPEM for it hasn't been seen yet. */
bool spatem_movement(const spatem_intersection_t *e, uint8_t sg,
                     uint16_t *maneuvers, bool *pedestrian);

/* Copy the cached intersections (most-recently-seen first) into `out`.
 * Returns the count written (<= max). */
int spatem_snapshot(spatem_intersection_t *out, int max);

/* Decodes a MAPEM's lane geometry only on first sight of an intersection or of
 * a new revision -- the layout repeats in every message. ~5.5 KB each, in PSRAM. */
void spatem_note_geometry(const uint8_t *frame, size_t len, const its_map_t *m);

/* Cached geometry or NULL. Re-decoded IN PLACE on a new revision -- hold
 * spatem_geometry_lock() while using the pointer, unlock on every path. */
/* Bounded variant for the packet path: it runs with msg_ring_mutex held, so
 * waiting forever here would stall reception behind any reader. */
bool spatem_geometry_lock_timeout(uint32_t ms);
void spatem_geometry_lock(void);
void spatem_geometry_unlock(void);
const its_map_geom_t *spatem_geometry(uint16_t region, uint16_t id);
