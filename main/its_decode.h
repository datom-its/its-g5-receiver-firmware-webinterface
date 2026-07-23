#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ITS_SPAT_MAX_SG 32  /* signal groups (movements) decoded per intersection */

/* SPATEM decode result (scope B: intersection identity + current phase per
 * signal group; no timing). `phase` is the SAE J2735 MovementPhaseState enum
 * of the first movement-event: 3=stop/RED, 5/6=go/GREEN, 7/8=clearance/AMBER,
 * 4=pre-movement, 0=unavailable, 1=dark, 2/9=flashing. Bit layout validated
 * against real captured SPATEM -- see reference-its-decode in project memory. */
/* IntersectionStatusObject, a BIT STRING(16) whose bit 0 is the MSB -- so the
 * standard's bit n is (1 << (15 - n)) here. Cross-checked against real
 * traffic: the Graz controller sends 0x0200 = TRAFFIC_DEPENDENT, constant. */
#define ITS_ISTAT_MANUAL         (1u << 15)  /* manual control (police box open) */
#define ITS_ISTAT_STOPTIME       (1u << 14)
#define ITS_ISTAT_FAILURE_FLASH  (1u << 13)  /* flashing amber */
#define ITS_ISTAT_PREEMPT        (1u << 12)  /* emergency vehicle preemption */
#define ITS_ISTAT_PRIORITY       (1u << 11)  /* public-transport priority active */
#define ITS_ISTAT_FIXED_TIME     (1u << 10)
#define ITS_ISTAT_TRAFFIC_DEP    (1u << 9)
#define ITS_ISTAT_STANDBY        (1u << 8)
#define ITS_ISTAT_FAILURE        (1u << 7)
#define ITS_ISTAT_OFF            (1u << 6)   /* signals switched off entirely */
#define ITS_ISTAT_NO_MAP         (1u << 3)
#define ITS_ISTAT_NO_SPAT        (1u << 2)

typedef struct {
    bool     valid;                     /* false = not a SPATEM, or decode failed */
    uint16_t region;                    /* RoadRegulatorID (0 = absent) */
    uint16_t id;                        /* IntersectionID */
    uint16_t status;                    /* ITS_ISTAT_* flags, 0 = none set */
    uint8_t  revision;
    uint8_t  n;                         /* number of signal groups populated */
    uint8_t  sg[ITS_SPAT_MAX_SG];       /* SignalGroupID per movement */
    uint8_t  phase[ITS_SPAT_MAX_SG];    /* MovementPhaseState per movement */
    /* Seconds until this phase ends (from TimeChangeDetails.minEndTime),
     * -1 when the RSU sent no timing for that group or the value was
     * implausible. Most messages carry no timing at all. */
    int16_t  secs[ITS_SPAT_MAX_SG];
} its_spat_t;

#define ITS_MAP_NAME_LEN 40  /* DescriptiveName is SIZE(1..63); 40 covers real names */

/* MAPEM decode result (stage 1: intersection identity + human-readable name).
 * The name is what turns "Kreuzung 43/840" into "Kärntner Straße - Busgarage".
 * The lane geometry / signal-group-to-lane mapping that follows it in the
 * message is deliberately NOT decoded (far larger job, see project memory). */
/* AllowedManeuvers bits, MSB-first in the 12-bit BIT STRING. */
#define ITS_MAN_STRAIGHT (1u << 11)
#define ITS_MAN_LEFT     (1u << 10)
#define ITS_MAN_RIGHT    (1u << 9)
#define ITS_MAN_UTURN    (1u << 8)

typedef struct {
    bool     valid;                  /* false = not a MAPEM, or decode failed */
    uint16_t region;                 /* RoadRegulatorID (0 = absent) */
    uint16_t id;                     /* IntersectionID -- keys the SPATEM cache */
    uint8_t  revision;               /* bumps when the operator changes the layout */
    char     name[ITS_MAP_NAME_LEN]; /* "" when the MAPEM carried no name */

    /* Optional intersection-wide values; 0 = the MAPEM didn't carry them.
     * Only the plain vehicle limits are kept -- SpeedLimitType also covers
     * school zones, construction zones and truck/night variants. */
    uint16_t lane_width_cm;
    uint16_t speed_max_kmh, speed_min_kmh;

    /* What each signal group actually controls, from the lane geometry:
     * every ingress lane names the signal group for its movement, so the
     * maneuver bits of all lanes sharing a group are OR-ed together. `ped`
     * marks groups whose controlling lanes are crosswalks -- those are the
     * pedestrian signals. Empty (n_sg 0) if the lane walk didn't complete. */
    uint8_t  n_sg;
    uint8_t  sg[ITS_SPAT_MAX_SG];
    uint16_t maneuvers[ITS_SPAT_MAX_SG];
    bool     ped[ITS_SPAT_MAX_SG];
} its_map_t;

/* AccelerationControl, a BIT STRING(7); ExteriorLights, a BIT STRING(8).
 * Bit 0 is the MSB in both, so the standard's bit n is (1 << (width-1-n)). */
#define ITS_ACC_BRAKE      (1u << 6)
#define ITS_ACC_GAS        (1u << 5)
#define ITS_ACC_EMERGENCY  (1u << 4)
#define ITS_ACC_COLLWARN   (1u << 3)
#define ITS_ACC_ACC        (1u << 2)   /* adaptive cruise control engaged */
#define ITS_ACC_CRUISE     (1u << 1)
#define ITS_ACC_LIMITER    (1u << 0)

#define ITS_LIGHT_LOWBEAM  (1u << 7)
#define ITS_LIGHT_HIGHBEAM (1u << 6)
#define ITS_LIGHT_LEFT     (1u << 5)
#define ITS_LIGHT_RIGHT    (1u << 4)
#define ITS_LIGHT_DRL      (1u << 3)
#define ITS_LIGHT_REVERSE  (1u << 2)
#define ITS_LIGHT_FOG      (1u << 1)
#define ITS_LIGHT_PARKING  (1u << 0)

/* How many PathHistory points are kept. The standard allows 40; a short
 * trail is all the map draws, and this struct rides the packet path. */
#define ITS_PATH_MAX 8

/* What the CAM container walk yields beyond position and dimensions. Every
 * field is optional in the message, hence a presence flag for each. */
typedef struct {
    bool     has_heading;
    uint16_t heading_ddeg;      /* 0.1 degree from true north */
    bool     has_accel_ctrl;
    uint8_t  accel_ctrl;        /* ITS_ACC_* */
    bool     has_lights;
    uint8_t  ext_lights;        /* ITS_LIGHT_* */
    uint8_t  role;              /* VehicleRole, 0xFF = not sent */
    /* Where the vehicle has just been: absolute positions, already summed
     * from the deltas the message carries. Oldest first. */
    uint8_t  n_path;
    int32_t  path_lat_e7[ITS_PATH_MAX], path_lon_e7[ITS_PATH_MAX];
} its_cam_detail_t;

/* CAM vehicle dimensions, from BasicVehicleContainerHighFrequency. Both are
 * in decimetres as sent; the ETSI "unavailable" sentinels (1023 / 62) are
 * mapped to 0 here so callers only have to check for zero. */
typedef struct {
    bool     valid;      /* false = not a CAM, or no vehicle container */
    uint16_t length_dm;  /* 0 = unavailable */
    uint8_t  width_dm;   /* 0 = unavailable */
} its_veh_t;

/* --- MAPEM lane geometry -------------------------------------------------
 * The node coordinates behind each lane, so the intersection can actually be
 * drawn. Kept out of its_decoded_t on purpose: that one lives on the packet
 * path's stack, and this is kilobytes. Decode it separately, into a buffer
 * the caller placed in PSRAM (see spatem.c), and only when the intersection
 * or its revision is new -- the geometry never changes between messages. */

#define ITS_GEOM_MAX_LANES 40
#define ITS_GEOM_MAX_NODES 16

typedef struct {
    uint8_t  lane_id;
    uint8_t  lane_type;                    /* 0 = vehicle, 1 = crosswalk, ... */
    uint8_t  signal_group;                 /* 0xFF = none (egress lane) */
    uint16_t maneuvers;                    /* AllowedManeuvers of its connection */
    uint8_t  n_nodes;
    int32_t  lat_e7[ITS_GEOM_MAX_NODES];   /* absolute WGS84, already offset
                                            * from the intersection refPoint */
    int32_t  lon_e7[ITS_GEOM_MAX_NODES];
} its_lane_geom_t;

typedef struct {
    bool     valid;
    uint16_t region, id;
    uint8_t  revision;                     /* re-decode when this changes */
    int32_t  ref_lat_e7, ref_lon_e7;       /* intersection reference point */
    uint8_t  n_lanes;
    its_lane_geom_t lane[ITS_GEOM_MAX_LANES];
} its_map_geom_t;

/* Decodes a MAPEM's full lane geometry. Separate from its_decode_frame()
 * because of the size; safe to call rarely (once per intersection revision).
 * Returns false if the frame isn't a MAPEM or the walk hit a construct we
 * don't handle -- `out` is then left invalid rather than half-filled. */
bool its_decode_map_geometry(const uint8_t *frame, size_t len, its_map_geom_t *out);

/* Identifies the facility-layer message type in a raw 802.11p frame (walks
 * LLC/SNAP -> GeoNetworking -> BTP-B to the message's ITS PDU header) and
 * prefixes it with the sender's station type when known, e.g. "Bus CAM",
 * "RSU SPATEM", "Signed" (secured, envelope not decoded), "?" (not GeoNet).
 * `out` is always a valid non-empty string.
 *
 * Position: prefers the GeoNetworking extended header's own Source Position
 * Vector (present for every facility message, so RSUs get a position too);
 * for CAM specifically, the message body's own (UPER-encoded)
 * referencePosition overrides it as the more precise value. `station_id` is
 * ItsPduHeader.stationId (the map-marker tracking key), not the GN source
 * address used for the station-type label. `has_speed`/`speed_cmps` come
 * from the same Source Position Vector (cm/s), skipped for RSUs (stationary).
 * Byte offsets validated against real captured traffic -- see
 * reference-its-decode in the project's memory before changing any of them.
 *
 * `station_type_code` (ETSI ITS-S type, 0 = unknown) and `message_id`
 * (ItsPduHeader.messageId, 0 = none/unknown) are the raw numeric forms of
 * what's already in `out`, for callers that aggregate by type (stats) or
 * branch on the message (e.g. DENM). Pass NULL to skip either.
 *
 * `spat`: when non-NULL and the frame is a SPATEM, filled with the decoded
 * traffic-light phases (`spat->valid` reports success); NULL to skip.
 * `map`: likewise for a MAPEM's intersection name/id; NULL to skip.
 * `veh`: likewise for a CAM's vehicle dimensions; NULL to skip. */

#define ITS_LABEL_LEN 32

/* Everything one frame can yield, in one struct. This replaced a parameter
 * list that had grown to fifteen out-pointers -- every new decoded field
 * meant touching every call site, and two same-typed pointers swapped by
 * accident would have compiled silently. */
typedef struct {
    char     label[ITS_LABEL_LEN]; /* e.g. "Bus CAM", "RSU SPATEM", "?" -- never empty */
    uint8_t  message_id;           /* ItsPduHeader.messageId, 0 = unknown */
    uint8_t  station_type;         /* ETSI ITS-S type, 0 = unknown */
    uint32_t station_id;           /* ItsPduHeader.stationId (map-marker key) */

    bool     has_position;
    int32_t  lat_e7, lon_e7;       /* WGS84, 1e-7 degree units */
    bool     has_speed;
    int32_t  speed_cmps;           /* cm/s */

    its_spat_t spat;               /* SPATEM traffic-light phases */
    its_map_t  map;                /* MAPEM intersection name/id */
    its_veh_t  veh;                /* CAM vehicle dimensions */
    its_cam_detail_t cam;          /* heading, pedals, lights, role, path */

    uint8_t  pt_line;              /* public-transport line number, 0 = none */
    bool     pt_container;         /* CAM carried a publicTransportContainer */
    /* EmbarkationStatus: passengers boarding/alighting right now. Decoded but
     * never yet observed true in real traffic -- treat as unverified. */
    bool     pt_embarking;
    uint8_t  denm_cause;           /* DENM cause code, 0 = none/unknown */
    uint8_t  denm_subcause;        /* detail within that cause, 0 = unspecified */
    /* DENM ActionID -- identifies the EVENT, not the message. A hazard is
     * re-broadcast many times (71x for one event in a real capture), all
     * sharing this pair, so it is what the warning list groups by. */
    uint32_t denm_station;
    uint16_t denm_seq;
    /* Where the hazard is, from the DENM's own eventPosition -- distinct from
     * lat_e7/lon_e7 above, which is where the SENDER is. An RSU warns about a
     * jam further down the road, so the marker belongs here, not at the mast. */
    bool     has_denm_pos;
    int32_t  denm_lat_e7, denm_lon_e7;
} its_decoded_t;

void its_decode_frame(const uint8_t *frame, size_t len, its_decoded_t *out);

/* Just the facility message type (ItsPduHeader.messageId, 0 = unknown), for
 * callers that only need to know what kind of message this is -- the PCAP
 * recorder's thinning filter. Implemented on top of its_decode_frame rather
 * than as a second copy of the header walk: that walk has been wrong before
 * (the 44-vs-40-byte extended header), and two copies would eventually
 * disagree. The extra work is affordable at the ~30 messages a second this
 * device actually receives. */
uint8_t its_peek_message_id(const uint8_t *frame, size_t len);

#ifdef __cplusplus
}
#endif
