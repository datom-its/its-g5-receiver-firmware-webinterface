#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ITS_SPAT_MAX_SG 32  /* signal groups (movements) decoded per intersection */

/* SPATEM decode result (identity + phase per signal group; no timing). `phase`
 * is the SAE J2735 MovementPhaseState enum, validated against captured frames. */
/* IntersectionStatusObject, a BIT STRING(16) whose bit 0 is the MSB -- so the
 * standard's bit n is (1 << (15 - n)) here. Cross-checked against real
 * traffic: controllers seen here send 0x0200 = TRAFFIC_DEPENDENT, constant. */
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

/* What a SPATEM carries beside its phases, for SSP bits 1 and 2 (TS 103 301 table 7). */
#define ITS_SPAT_ASSIST    0x01  /* a maneuverAssistList, of the intersection or a movement */
#define ITS_SPAT_PRIO      0x02  /* activePrioritizations (IntersectionState-addGrpC) */
#define ITS_SPAT_WHOLE     0x04  /* one intersection, read to its end: nothing was missed */

typedef struct {
    bool     valid;                     /* false = not a SPATEM, or decode failed */
    uint8_t  items;                     /* ITS_SPAT_*, only meaningful with valid */
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

/* MAPEM decode result: intersection identity, name, speed limits and what each
 * signal group controls. The name is what turns a bare "Kreuzung <region>/<id>"
 * into something readable. The full lane geometry goes into its_map_geom_t,
 * which only its_decode_map_geometry() fills. */
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

    /* Optional intersection-wide values. 0 means not carried, or a speed sent as unavailable
     * (8191). Only the plain vehicle limits are kept. SpeedLimitType also covers school zones,
     * construction zones and truck/night variants. */
    uint16_t lane_width_cm;
    uint16_t speed_max_kmh, speed_min_kmh;

    /* What each signal group controls, OR-ed over the lanes that name it; `ped`
     * marks crosswalk groups. Empty (n_sg 0) if the lane walk didn't complete. */
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

/* StandardLength3b: how far from the hazard the warning is meant to be relevant. */
#define ITS_DENM_DIST_50M    0
#define ITS_DENM_DIST_100M   1
#define ITS_DENM_DIST_200M   2
#define ITS_DENM_DIST_500M   3
#define ITS_DENM_DIST_1KM    4
#define ITS_DENM_DIST_5KM    5
#define ITS_DENM_DIST_10KM   6
#define ITS_DENM_DIST_OVER   7
#define ITS_DENM_DIST_NONE   0xFF

/* TrafficDirection: which traffic the warning is meant for, relative to the event position and a
 * reference direction. Upstream traffic comes towards the event, downstream traffic leaves it. */
#define ITS_DENM_DIR_ALL        0
#define ITS_DENM_DIR_UPSTREAM   1
#define ITS_DENM_DIR_DOWNSTREAM 2
#define ITS_DENM_DIR_OPPOSITE   3
#define ITS_DENM_DIR_NONE       0xFF

/* RoadType: inside or outside a built-up area, and whether the opposite lanes are
 * separated by something solid. */
#define ITS_DENM_ROAD_URBAN_OPEN   0
#define ITS_DENM_ROAD_URBAN_SEP    1
#define ITS_DENM_ROAD_RURAL_OPEN   2
#define ITS_DENM_ROAD_RURAL_SEP    3
#define ITS_DENM_ROAD_NONE         0xFF

/* Not read: InformationQuality runs 0..7, and StationType assigns nothing above 15. */
#define ITS_DENM_QUALITY_NONE 0xFF
#define ITS_DENM_STATION_NONE 0xFF

/* RTCM-Revision of an RTCMEM: which edition of the RTCM standard the corrections follow.
 * The ASN.1 leaves the meaning of the corrections themselves to the GNSS receiver. */
#define ITS_RTCM_REV_UNKNOWN  0
#define ITS_RTCM_REV_2        1
#define ITS_RTCM_REV_3        2
#define ITS_RTCM_REV_RESERVED 3
/* One value with two meanings. The detail line shows it only after an RTCMEM was read, so
 * there it always means the second one. */
#define ITS_RTCM_REV_NONE     0xFF   /* no RTCMEM read, or a value beyond the four above */

/* GNSSstatus, a BIT STRING of 8. Bit 0 of the standard is the first bit on the wire and
 * therefore the highest bit of the byte. */
#define ITS_GNSS_UNAVAILABLE   (1u << 7)
#define ITS_GNSS_HEALTHY       (1u << 6)
#define ITS_GNSS_MONITORED     (1u << 5)
#define ITS_GNSS_BASESTATION   (1u << 4)
#define ITS_GNSS_PDOP_UNDER5   (1u << 3)
#define ITS_GNSS_INVIEW_UNDER5 (1u << 2)
#define ITS_GNSS_LOCAL_CORR    (1u << 1)
#define ITS_GNSS_NETWORK_CORR  (1u << 0)

/* CpmContainerId: which container of a CPM. Bit (id - 1) of cpm_containers marks each one
 * the message carried. Ids 6..16 are not defined yet but are still counted and marked. */
#define ITS_CPM_ORIG_VEHICLE  1
#define ITS_CPM_ORIG_RSU      2
#define ITS_CPM_SENSOR_INFO   3
#define ITS_CPM_REGION        4
#define ITS_CPM_OBJECTS       5

/* Which reading of the CPM container list fitted the message: with the extension bit of
 * SIZE(1..8, ...), as the ASN.1 says, or without it, as Wireshark reads by default. */
#define ITS_CPM_LIST_EXT      1
#define ITS_CPM_LIST_NOEXT    2

/* ChargingSpotType of an EVCSN, a BIT STRING with named bits. evcsn_modes keeps bit n of the
 * message as (1 << n), named or not, so the numbers are the ones the ASN.1 gives. */
#define ITS_EVCS_MODE1          0   /* standardChargeMode1 */
#define ITS_EVCS_MODE2          1   /* standardChargeMode2 */
#define ITS_EVCS_MODE3          2   /* standardOrFastChargeMode3 */
#define ITS_EVCS_FAST_EXT       3   /* fastChargeWithExternalCharger */
#define ITS_EVCS_QUICKDROP      8   /* quickDrop */
#define ITS_EVCS_INDUCT_STAND  12   /* inductiveChargeWhileStationary */
#define ITS_EVCS_INDUCT_DRIVE  14   /* inductiveChargeWhileDriving */

/* How many bytes of a text out of an EVCSN are kept: whole UTF-8 characters, as many as
 * fit. The texts can be longer. The page only needs the start, and a cut one ends in U+2026. */
#define ITS_EVCSN_TEXT 32

/* How many PathHistory points are kept. The standard allows 40; a short
 * trail is all the map draws, and this struct rides the packet path. */
#define ITS_PATH_MAX 8

/* Which SpecialVehicleContainer a CAM carried. UNREAD has to be the zero value: a struct that
 * was only cleared must not claim that the CAM carried nothing. The seven containers follow
 * the ASN.1 CHOICE order, and the SSP of PSID 36 grants them one bit each in the same order,
 * so the bit number of a container is its value minus one. */
#define ITS_CAM_SVC_UNREAD     0  /* The walk never reached the choice. */
#define ITS_CAM_SVC_NONE       1  /* The CAM carried no special container. */
#define ITS_CAM_SVC_PT         2  /* publicTransportContainer */
#define ITS_CAM_SVC_SPECIAL    3  /* specialTransportContainer */
#define ITS_CAM_SVC_DANGEROUS  4  /* dangerousGoodsContainer */
#define ITS_CAM_SVC_ROADWORKS  5  /* roadWorksContainerBasic */
#define ITS_CAM_SVC_RESCUE     6  /* rescueContainer */
#define ITS_CAM_SVC_EMERGENCY  7  /* emergencyContainer */
#define ITS_CAM_SVC_SAFETYCAR  8  /* safetyCarContainer */
#define ITS_CAM_SVC_EXT        9  /* An extension alternative, which has no bit of its own. */

/* What the CAM container walk yields beyond position and dimensions. Every
 * field is optional in the message, hence a presence flag for each. */
typedef struct {
    bool     has_heading;
    uint16_t heading_ddeg;      /* 0.1 degree from true north */
    /* Altitude of the reference position. AltitudeValue counts centimetres from the
     * reference ellipsoid and reserves 800001 for "unavailable". */
    bool     has_alt;
    int32_t  alt_cm;
    /* LongitudinalAccelerationValue in 0.1 m/s^2, negative while braking. 161 is the
     * "unavailable" of the standard and never reaches this field. */
    bool     has_long_accel;
    int16_t  long_accel;
    /* DriveDirection: 0 forward, 1 backward, 2 unavailable. Kept raw, because only
     * "backward" is worth a word on the page and 2 must not read as forward. */
    uint8_t  drive_dir;
    /* LanePosition counts the driving lanes 1..13 from the inside, the left in right-hand
     * traffic. 0 and 14 are the inner and outer hard shoulder, -1 is off the road. The 4 bits
     * encode -1..14 with -1 as the offset. */
    bool     has_lane;
    int8_t   lane;
    bool     has_accel_ctrl;
    uint8_t  accel_ctrl;        /* ITS_ACC_* */
    bool     has_lights;
    uint8_t  ext_lights;        /* ITS_LIGHT_* */
    uint8_t  role;              /* VehicleRole, 0xFF = not sent */
    /* Where the vehicle has just been: absolute positions, already summed
     * from the deltas the message carries. Nearest the vehicle first, as sent. */
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

/* MAPEM lane geometry -- kilobytes, so kept out of its_decoded_t (packet-path
 * stack); decoded separately into a caller-provided PSRAM buffer, only when new. */

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

/* its_decode_frame() labels the message ("Bus CAM", "RSU SPATEM", "Signed", "?") and fills
 * what the frame carries. The offsets were checked against real traffic, so recheck any change. */

#define ITS_LABEL_LEN 32

/* DENM Termination, stored as the ASN.1 value plus one so that 0 means absent. */
#define ITS_DENM_TERM_NONE         0
#define ITS_DENM_TERM_CANCELLATION 1
#define ITS_DENM_TERM_NEGATION     2

/* GeoBroadcast and GeoAnycast area shape, stored as the header sub-type plus one. */
#define ITS_GN_AREA_NONE    0
#define ITS_GN_AREA_CIRCLE  1
#define ITS_GN_AREA_RECT    2
#define ITS_GN_AREA_ELLIPSE 3

/* Everything one frame can yield, in one struct. This replaced a parameter
 * list that had grown to fifteen out-pointers -- every new decoded field
 * meant touching every call site, and two same-typed pointers swapped by
 * accident would have compiled silently. */
typedef struct {
    char     label[ITS_LABEL_LEN]; /* e.g. "Bus CAM", "RSU SPATEM", "?" -- never empty */
    uint8_t  message_id;           /* ItsPduHeader.messageId, 0 = unknown */
    uint8_t  station_type;         /* ETSI ITS-S type, 0 = unknown */
    /* An SAEM is read no further than this header, so its version check is kept here too,
     * in the two padding bytes before station_id. */
    bool     saem_wrong_version;   /* an SAEM whose header is not version 1 */
    uint8_t  saem_other_version;   /* its protocolVersion, 0 included */
    uint32_t station_id;           /* ItsPduHeader.stationId (map-marker key) */

    bool     has_position;
    bool     has_speed;
    uint8_t  pdu_version;          /* ItsPduHeader.protocolVersion, in the padding before lat_e7 */
    int32_t  lat_e7, lon_e7;       /* WGS84, 1e-7 degree units */
    int32_t  speed_cmps;           /* cm/s */

    its_spat_t spat;               /* SPATEM traffic-light phases */
    its_map_t  map;                /* MAPEM intersection name/id */
    its_veh_t  veh;                /* CAM vehicle dimensions */
    its_cam_detail_t cam;          /* heading, pedals, lights, role, path */

    /* RTCMEM (messageId 13): GNSS corrections that a roadside unit forwards, so a
     * vehicle can position itself to the centimetre. The corrections themselves are RTCM
     * SC-104 messages, a foreign format. The ASN.1 explicitly leaves their numbering to
     * the GNSS receiver, so only their count and their length are reported here. */
    uint8_t  rtcm_msg_cnt;         /* the sender's rolling counter, 0..127 */
    uint8_t  rtcm_rev;             /* ITS_RTCM_REV_* */
    uint8_t  rtcm_n_msgs;          /* 1..5 corrections in this message, 0 = none read */
    uint16_t rtcm_bytes;           /* how many bytes of corrections all of them add up to */
    bool     rtcm_has_minute;
    uint32_t rtcm_minute;          /* MinuteOfTheYear, 0..527040 */
    /* The reference point the corrections belong to. It is the base station, not the sender.
     * Same encoding as every other position, but longitude comes FIRST in this message. */
    bool     rtcm_has_anchor;
    int32_t  rtcm_lat_e7, rtcm_lon_e7;
    bool     rtcm_has_elev;        /* false also for -4096, which DSRC sends for "unknown" */
    int32_t  rtcm_elev_dm;         /* decimetres above the reference ellipsoid */
    bool     rtcm_has_status;
    uint8_t  rtcm_status;          /* ITS_GNSS_* bits */

    /* CPM (messageId 14): what a station's sensors see right now. This part reads the outline
     * of the message (when, where, which containers) and how many objects, sensors and
     * regions it describes. its_cpm.c reads the contents from the places kept at the end. */
    bool     cpm_read;             /* the management container was read */
    bool     cpm_has_pos;          /* next to cpm_read, in the padding before cpm_ref_ms */
    uint64_t cpm_ref_ms;           /* referenceTime, TimestampIts */
    int32_t  cpm_lat_e7, cpm_lon_e7;
    uint8_t  cpm_seg_this, cpm_seg_total;  /* 1..8 each; both 0 when the CPM is not split */
    uint8_t  cpm_n_containers;
    uint16_t cpm_containers;       /* bit (id - 1) for every container id that came */
    /* A defined container whose bytes did not hold what its shape needs. Its count says
     * nothing, so the page names the container instead of showing a number. */
    uint16_t cpm_cont_bad;
    /* numberOfPerceivedObjects counts what the station knows. A split CPM carries only part
     * of them, and that part is the second number. The lists may hold more than their root
     * size allows, so the counts are as wide as the length they are read from. */
    uint8_t  cpm_n_objects;
    uint16_t cpm_n_objects_here;
    uint16_t cpm_n_sensors;        /* 1..128 in the root, more behind the extension */
    uint16_t cpm_n_regions;        /* 1..256 in the root, more behind the extension */
    bool     cpm_has_heading;
    uint16_t cpm_heading_ddeg;     /* orientation of an originating vehicle, 0.1 degree */
    uint8_t  cpm_list_form;        /* ITS_CPM_LIST_*, 0 when the list could not be read */
    bool     cpm_wrong_version;    /* a CPM that is not version 2, so it was not read */
    uint8_t  cpm_other_version;    /* its protocolVersion, 0 included */
    /* messageRateRange, mantissa x 10^exponent per second. The mantissa is kept as sent,
     * 1..128. The ASN.1 allows 1..100, but its 7 bits carry more. The exponent is -5..2. */
    bool     cpm_has_rate;
    uint8_t  cpm_rate_min_m, cpm_rate_max_m;
    int8_t   cpm_rate_min_e, cpm_rate_max_e;
    /* Places for its_cpm.c. cpm_pdu_at is the byte offset of the ItsPduHeader, for the
     * stationId. For each container id 1..5 the last such container gives its content as a
     * bit offset in the frame and a length in bytes, 0 bytes = nothing to read. A bad last
     * one still gives its place, and cpm_cont_bad marks it. */
    uint16_t cpm_pdu_at;
    uint16_t cpm_cont_at[ITS_CPM_OBJECTS];
    uint16_t cpm_cont_bytes[ITS_CPM_OBJECTS];

    /* EVCSN (messageId 11, or 3 at protocolVersion 0: message_id stays raw, so test evcsn_read).
     * The first station is kept, the others only counted. The three texts are valid UTF-8
     * with nothing its_utf8_unshown() names, see read_utf8. */
    bool     evcsn_read;
    bool     evcsn_relay;          /* relayCapable: the sender can relay reservation messages */
    uint16_t evcsn_poi_type;       /* 1 is "EV charging station" in the standard */
    uint64_t evcsn_ts_ms;          /* TimestampIts */
    uint16_t evcsn_n_total;        /* stations the sender knows, 1..256 */
    uint16_t evcsn_n_stations;     /* stations in this message, 1..256 */
    uint32_t evcsn_st_id;
    bool     evcsn_has_pos;
    int32_t  evcsn_lat_e7, evcsn_lon_e7;
    uint8_t  evcsn_n_spots;        /* charging spots of the first station, 1..16 */
    uint16_t evcsn_modes;          /* (1 << ITS_EVCS_*) over all its spots */
    char     evcsn_access[ITS_EVCSN_TEXT + 1];
    char     evcsn_hours[ITS_EVCSN_TEXT + 1];
    char     evcsn_price[ITS_EVCSN_TEXT + 1];

    /* 802.11 sender address (Addr2). Always at offset 10 for the frames this
     * decoder accepts (ToDS=0, FromDS=0), so no ambiguity. */
    uint8_t  src_mac[6];
    bool     has_src_mac;

    /* VDV R09.16 telegram out of the CAM's publicTransportContainer, with the standard's
     * own field names. All of them stay 0 when the CAM carried no telegram. */
    uint16_t pt_line;              /* LN Liniennummer  (0..999, 0 = none) */
    uint8_t  pt_course;            /* KN Kursnummer    (0..99) */
    uint16_t pt_dest;              /* ZN Zielnummer    (0..999) */
    uint16_t pt_point;             /* MP Meldepunktnummer */
    uint8_t  pt_train_len;         /* ZL Zuglänge */
    uint8_t  pt_priority;          /* PR Priorität */
    uint8_t  pt_request;           /* HA 0=keine, 1=gerade, 2=links, 3=rechts */
    int16_t  pt_deviation;         /* ZW mit Vorzeichen aus ZV: + = Verspätung */
    bool     pt_telegram;          /* the R09 fields above are valid */
    bool     pt_container;         /* CAM carried a publicTransportContainer */
    /* EmbarkationStatus: passengers boarding/alighting right now. Decoded but
     * never yet observed true in real traffic -- treat as unverified. */
    bool     pt_embarking;
    uint8_t  denm_cause;           /* DENM cause code, 0 = none/unknown */
    uint8_t  denm_subcause;        /* detail within that cause, 0 = unspecified */
    uint8_t  denm_termination;     /* ITS_DENM_TERM_*: whether this DENM cancels or negates the event */
    /* What the CAM container walk found beyond the line telegram, for the permission check:
     * the SSP of PSID 36 grants each special container and the zones their own bit. They are
     * kept here and not in its_cam_detail_t, where they belong, because the field check that
     * tests this struct cannot express a nested name.
     * cam_zone is an RSU sending protectedCommunicationZonesRSU or a vehicle sending a
     * cenDsrcTollingZone. The standard puts both on the same bit, so they are not told apart. */
    uint8_t  cam_special;          /* ITS_CAM_SVC_* */
    bool     cam_zone;
    /* The MapData of a MAPEM carried a roadSegments list, which the SSP of PSID 138 grants on
     * bit 1 while bit 0 grants the intersections. It comes out of the option bitmap, but it is
     * only set once that walk has settled whether intersections came at all. Reporting it
     * earlier would let a MAPEM whose intersection list was never read pass on bit 1 while no
     * bit was ever held against that list. It is also false when the bitmap itself could not
     * be read, and then nothing is claimed.
     * It is kept here instead of in its_map_t for the same reason as the two above. */
    bool     map_road_segments;
    /* MAPEM refPoint altitude, cm like the CAM's: elevation, or in the EU profile the
     * Position3D-addGrpC in regional. With map_alt_cm below, in the 4-byte hole before a uint64. */
    bool     map_has_alt;
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
    int32_t  map_alt_cm;           /* with map_has_alt; in a hole, its_decoded_t stays 904 B */
    /* Both are 0 when the ManagementContainer could not be read. TimestampIts counts
     * the milliseconds since 2004-01-01 00:00:00 UTC with leap seconds included. */
    uint64_t denm_detection_ms, denm_reference_ms;
    /* Seconds after detectionTime at which the event expires. A DENM that leaves the
     * field out gets the standard's default of 600. Both are 0 when nothing was read. */
    uint32_t denm_validity_s;
    bool     denm_validity_sent;
    /* The rest of the ManagementContainer. 0xFF is "not sent" for the three enumerations,
     * because 0 is a real value in each of them (lessThan50m, allTrafficDirections,
     * unknown station type). */
    uint8_t  denm_station_type;    /* originator's StationType, ITS_DENM_STATION_NONE = not read */
    uint8_t  denm_aware_dist;      /* StandardLength3b, ITS_DENM_DIST_* */
    uint8_t  denm_traffic_dir;     /* TrafficDirection, ITS_DENM_DIR_* */
    uint16_t denm_tx_interval_ms;  /* how often the sender repeats it, 0 = not sent */
    /* Altitude of the eventPosition, same encoding as the CAM's. */
    bool     denm_has_alt;
    int32_t  denm_alt_cm;
    /* SituationContainer: how sure the sender is, 0..7, ITS_DENM_QUALITY_NONE = no situation
     * container. */
    uint8_t  denm_info_quality;
    /* Points of eventZone (eventHistory before 2.x), which show how far the spot reaches.
     * 0 = not sent or not read whole. */
    uint8_t  denm_n_hist;
    /* LocationContainer: how fast and in which direction things move AT the hazard, and
     * what kind of road it is. All three are optional in the message. */
    uint16_t denm_speed_cms;       /* centimetres per second, as sent */
    bool     denm_has_speed;
    bool     denm_has_heading;
    uint16_t denm_heading_ddeg;    /* 0.1 degree from true north */
    uint8_t  denm_road_type;       /* RoadType, ITS_DENM_ROAD_*, 0xFF = not sent */
    /* The detection zone: the stretch of road that leads to the hazard. The message may
     * carry up to seven such traces. The points of the FIRST one are kept as sent, nearest the
     * event first, already summed from the deltas into absolute positions. */
    uint8_t  denm_n_traces;
    uint8_t  denm_n_path;          /* points kept of the first trace, at most ITS_PATH_MAX */
    uint8_t  denm_path_len;        /* points of the first trace as sent, 0..40 */
    int32_t  denm_path_lat_e7[ITS_PATH_MAX], denm_path_lon_e7[ITS_PATH_MAX];

    /* Target area of a GeoBroadcast or GeoAnycast packet. A circle carries its
     * radius in a, and the sender sets b and the angle to 0. */
    uint8_t  gn_area_shape;        /* ITS_GN_AREA_*, 0 = no area in this packet */
    uint16_t gn_area_a_m, gn_area_b_m;         /* distance a and distance b, metres */
    uint16_t gn_area_angle_deg;                /* degrees from north */
    int32_t  gn_area_lat_e7, gn_area_lon_e7;   /* centre, WGS84, 1e-7 degree units */

    /* DCC-MCO field of a single-hop broadcast (TS 102 636-4-2 clause 6.3.3). A
     * sender that does not use the field sets all of it to 0. */
    bool     has_dcc;              /* the packet was a single-hop broadcast and carried the field */
    uint8_t  dcc_cbr_r0_hop;       /* sender's measured channel busy ratio, times 255 and rounded down */
    uint8_t  dcc_cbr_r1_hop;       /* sender's 1-hop ratio from its neighbours' reports, same scale */
    uint8_t  dcc_tx_power_dbm;     /* EIRP of this packet, capped at 31 dBm */

    /* Where the GeoNetworking headers of this frame lie, 0 = not found. its_gn.c reads them.
     * gn_end bounds a Common Header behind a signed envelope. */
    uint16_t gn_basic_at;          /* Basic Header */
    uint16_t gn_common_at;         /* Common Header, plain or inside the signed payload */
    uint16_t gn_pv_at;             /* Source Long Position Vector, as the GN walk found it */
    uint16_t gn_end;               /* end of the bytes the Common Header belongs to */
} its_decoded_t;

void its_decode_frame(const uint8_t *frame, size_t len, its_decoded_t *out);

/* Just the messageId (0 = unknown), built on its_decode_frame rather than a
 * second copy of the header walk that would eventually disagree. */
uint8_t its_peek_message_id(const uint8_t *frame, size_t len);

/* The message type behind a raw header: 11 (EVCSN) for id 3 at version 0, else the id itself. */
uint8_t its_msg_kind(uint8_t version, uint8_t id);

/* The name of a kind from its_msg_kind as /messages labels it ("CPM"), NULL for an unnamed one. */
const char *its_msgid_name(uint8_t kind);

#ifdef __cplusplus
}
#endif
