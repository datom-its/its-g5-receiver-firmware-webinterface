#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "its_decode.h"

/* Live traffic-light state cache. Every decoded SPATEM (SAE J2735 SPAT)
 * updates the current phase per signal group for its intersection; the
 * "Verkehr" web page renders them as coloured indicators. Purely in-RAM and
 * ephemeral -- phases are a "right now" view, not a history, so nothing is
 * persisted to SD. Sized for a handful of intersections (one RSU controller
 * each) within reception range. */

#define SPATEM_MAX_INT 8   /* distinct intersections cached (most-recent wins) */

typedef struct {
    uint16_t region;                     /* RoadRegulatorID (0 = absent) */
    uint16_t id;                         /* IntersectionID */
    uint16_t status;                     /* ITS_ISTAT_* controller mode/fault flags */
    uint8_t  revision;
    uint8_t  n;                          /* signal groups populated */
    uint8_t  sg[ITS_SPAT_MAX_SG];
    uint8_t  phase[ITS_SPAT_MAX_SG];
    /* Unix second at which the current phase is expected to end (0 = unknown).
     * Absolute, not a countdown, so it stays correct between the sparse
     * messages that actually carry timing; carried forward while the phase
     * for that group is unchanged, cleared when it flips. */
    uint32_t change_at[ITS_SPAT_MAX_SG];
    uint32_t last_seen;                  /* unix seconds of last update */
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

void spatem_init(void);

/* Hot path: fold a decoded SPATEM snapshot into the cache (find-or-insert by
 * region+id, most-recently-seen evicts the oldest slot when full). No-op if
 * `s` is invalid. Cheap; safe to call from the sniffer/web packet path. */
void spatem_note(const its_spat_t *s, uint32_t station_id, uint32_t seconds,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7);

/* Attach a MAPEM's intersection name and its signal-group-to-movement map to
 * the matching cache entry (same region+id key as the SPATEM phases). No-op
 * if `m` is invalid; creates an entry if the phases haven't been seen yet. */
void spatem_note_name(const its_map_t *m, uint32_t seconds);

/* Looks up what signal group `sg` of the given intersection controls.
 * Returns false when the MAPEM for it hasn't been seen yet. */
bool spatem_movement(const spatem_intersection_t *e, uint8_t sg,
                     uint16_t *maneuvers, bool *pedestrian);

/* Copy the cached intersections (most-recently-seen first) into `out`.
 * Returns the count written (<= max). */
int spatem_snapshot(spatem_intersection_t *out, int max);

/* Decodes and caches a MAPEM's lane geometry, but only the first time an
 * intersection (or a new revision of it) is seen -- the layout is identical
 * in every message, so re-decoding ~2x per second would be pure waste. The
 * ~5.5 KB per intersection lives in PSRAM, allocated on first use. */
void spatem_note_geometry(const uint8_t *frame, size_t len, const its_map_t *m);

/* The cached geometry for an intersection, or NULL if none is held.
 * The returned pointer aims into a buffer the packet path re-decodes IN
 * PLACE when the intersection publishes a new revision, so a caller that
 * walks the lanes must hold spatem_geometry_lock() for as long as it uses
 * the pointer -- otherwise it can observe a half-old, half-new mixture.
 * Always pair with spatem_geometry_unlock(), including on early returns. */
void spatem_geometry_lock(void);
void spatem_geometry_unlock(void);
const its_map_geom_t *spatem_geometry(uint16_t region, uint16_t id);
