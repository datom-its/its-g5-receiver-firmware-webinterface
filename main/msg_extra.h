#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_certcache.h"
#include "its_cpm.h"
#include "its_decode.h"
#include "events_log.h"
#include "its_security.h"
#include "its_msgsig.h"
#include "its_poim.h"
#include "its_srem.h"
#include "its_sechdr.h"
#include "its_gn.h"

#ifdef __cplusplus
extern "C" {
#endif

/* What a listed message shows beyond its_decode_frame. That is the signer, the two permission
 * answers (service and content) with the rule that decided, the DCC field, the rest of a DENM,
 * the target area and a short SREM or SSEM summary. It also covers what an RTCMEM, CPM, EVCSN
 * or POIM carries, the version of an SAEM, the MAPEM altitude, the signature header, the
 * signature of the message itself and how the frame travelled (GeoNetworking). */

#define MSG_PRIO_ITEMS 3

/* Whether the certificate that signed a message lists its service: the PSID of the message
 * against the appPermissions of the certificate. What the message carries is its own answer
 * (its_perm_cont_t), and neither goes into the chain verdict. */
typedef enum
{
    ITS_PERM_UNKNOWN = 0,
    ITS_PERM_OK      = 1,
    ITS_PERM_BAD     = 2,
} its_perm_t;

/* Whether the bits beside that PSID (a bitmap SSP) allow what the message carries. There is no
 * such answer before the service answer is ITS_PERM_OK. The first three share their values
 * with its_perm_t. */
typedef enum
{
    ITS_PERM_CONT_UNKNOWN = 0,   /* The bits do not settle it, or the service answer was not OK. */
    ITS_PERM_CONT_OK      = 1,   /* A bit allowed exactly what the message carried. */
    ITS_PERM_CONT_BAD     = 2,   /* A bit said no, and the standard assigns that bit clearly. */
    ITS_PERM_CONT_FREE    = 3,   /* No bit to hold it against: no SSP, or none governs it. */
} its_perm_cont_t;

/* Which rule decided. NONE and PSID belong to the service answer, every other rule to the
 * content answer, so the page can name what was missing instead of a bare answer. */
typedef enum
{
    ITS_PERM_BY_NONE       = 0,  /* Nothing was checked: no envelope, no PSID or no signer. */
    ITS_PERM_BY_PSID       = 1,  /* The PSID against appPermissions; nothing finer applied. */
    ITS_PERM_BY_SSP_NONE   = 2,  /* The entry carries no SSP, so the service is the whole grant. */
    ITS_PERM_BY_SSP_VER    = 3,  /* The SSP version is not the one this service defines. */
    ITS_PERM_BY_SSP_FORM   = 4,  /* The SSP is no bitmap, or its bytes are not at hand. */
    ITS_PERM_BY_DENM_CAUSE = 5,  /* detail holds the causeCode. */
    ITS_PERM_BY_CAM_CONT   = 6,  /* detail holds ITS_CAM_SVC_*. */
    ITS_PERM_BY_CAM_ZONE   = 7,  /* A tolling zone or an RSU zone list. */
    ITS_PERM_BY_SREM_ROLE  = 8,  /* detail holds the BasicVehicleRole. */
    ITS_PERM_BY_CONTENT    = 9,  /* What the message carries against the bits the service
                                  * gives it: SPATEM bits 0 to 2, MAPEM bits 0 and 1, and SREM
                                  * bit 0 or an SREM without a role. */
    ITS_PERM_BY_SERVICE    = 10, /* Only the SSP version applied: either the service has no
                                  * rule this build can check, or no bit of it governs this
                                  * message. */
} its_perm_by_t;

/* One SREM request or one SSEM answer. */
typedef struct
{
    uint32_t requester_id;       /* SSEM only, valid unless requester_kind is ITS_SREM_ID_NONE. */
    uint16_t region;             /* It is only valid when has_region is set. */
    uint16_t id;                 /* IntersectionID */
    bool     has_region;
    uint8_t  requester_kind;     /* ITS_SREM_ID_*, which an SREM item leaves at NONE. */
    uint8_t  request_id;         /* An SSEM answer only has one with a requester. */
    uint8_t  code;               /* PriorityRequestType or PrioritizationResponseStatus. */
    its_srem_access_t in;
    its_srem_access_t out;       /* The kind is ITS_SREM_AP_NONE when it was not sent. */
} msg_prio_item_t;

typedef struct
{
    uint8_t  message_id;         /* 9 for an SREM, 10 for an SSEM, 0 when none was decoded. */
    uint8_t  n_items;
    bool     more;               /* The message held more items than are kept here. */
    bool     has_role;           /* SREM only: role is valid. */
    uint8_t  role;               /* A BasicVehicleRole or ITS_SREM_ENUM_EXT. */
    uint8_t  requestor_kind;     /* SREM only: ITS_SREM_ID_ENTITY or ITS_SREM_ID_STATION. */
    uint32_t requestor_id;
    char     name[ITS_SREM_NAME_LEN];    /* "" when not sent */
    char     route[ITS_SREM_ROUTE_LEN];  /* "" when not sent */
    msg_prio_item_t item[MSG_PRIO_ITEMS];
} msg_prio_t;

typedef struct
{
    its_sig_summary_t sig;
    uint8_t  message_id;         /* ItsPduHeader.messageId, 0 when unknown. */
    /* SAEM (messageId 12) only. Next to message_id, the two bytes fit the padding in front of
     * denm_alt_cm. */
    bool     saem_wrong_version; /* an SAEM whose header is not version 1 */
    uint8_t  saem_other_version; /* its protocolVersion, 0 included */
    /* The DCC field was sent with a value other than zero. Zero means the sender does not use it. */
    bool     has_dcc;
    uint8_t  dcc_cbr_r0;         /* Both channel busy ratios count 255 as 100 %. */
    uint8_t  dcc_cbr_r1;
    uint8_t  dcc_tx_power_dbm;   /* Many senders fill the ratios but leave this at 0. */
    uint8_t  denm_termination;   /* ITS_DENM_TERM_* */
    bool     denm_validity_sent;
    /* The rest of the DENM. In the five code fields 0xFF means left out, because 0 is a real
     * value there. The three counts and the interval use 0 for it. Only a DENM fills them, and
     * only with values the decoder read. */
    uint8_t  denm_aware_dist;    /* ITS_DENM_DIST_* */
    uint8_t  denm_traffic_dir;   /* ITS_DENM_DIR_* */
    uint8_t  denm_road_type;     /* ITS_DENM_ROAD_* */
    uint8_t  denm_station_type;  /* what the station that raised it says it is */
    uint8_t  denm_quality;       /* 0..7, how sure the sender is */
    uint8_t  denm_n_traces;      /* how many detection zones the message carried */
    uint8_t  denm_path_len;      /* points of the first one as sent */
    uint8_t  denm_n_hist;        /* points of the extent of the spot, 0 = not sent */
    bool     denm_has_alt, denm_has_speed, denm_has_heading;
    int32_t  denm_alt_cm;
    uint16_t denm_speed_cms;     /* speed AT the hazard, centimetres per second */
    uint16_t denm_heading_ddeg;  /* 0.1 degree from true north */
    uint16_t denm_tx_interval_ms;/* how often the sender repeats it, 0 = not sent */
    uint8_t  area_shape;         /* ITS_GN_AREA_* */
    uint8_t  perm_svc;           /* The service answer, its_perm_t. */
    uint8_t  perm_cont;          /* The content answer, its_perm_cont_t; only with perm_svc OK. */
    uint8_t  perm_by;            /* Values come from its_perm_by_t. */
    /* The number behind the rule: a causeCode, an ITS_CAM_SVC_* or a BasicVehicleRole. It is 0
     * for none or when the message did not say. With ITS_PERM_BY_CONTENT, 1 marks a SPATEM that
     * was only read in part. */
    uint8_t  perm_detail;
    bool     map_has_alt;        /* MAPEM refPoint altitude (map_alt_cm, near the end) */
    uint32_t denm_validity_s;    /* 0 when the DENM could not be read. */
    /* RTCMEM (messageId 13) only. n_msgs stays 0 for every other message type, which is
     * what the detail line tests before it prints any of this. */
    uint8_t  rtcm_msg_cnt;
    uint8_t  rtcm_rev;           /* ITS_RTCM_REV_* */
    uint8_t  rtcm_n_msgs;
    uint8_t  rtcm_status;        /* ITS_GNSS_* bits, only with rtcm_has_status */
    bool     rtcm_has_status, rtcm_has_minute, rtcm_has_anchor, rtcm_has_elev;
    uint16_t rtcm_bytes;
    uint32_t rtcm_minute;
    int32_t  rtcm_lat_e7, rtcm_lon_e7, rtcm_elev_dm;
    /* CPM (messageId 14) only. cpm_read stays false for every other type, and the detail line
     * tests it before it prints the counts. The two version fields are set without a reading. */
    bool     cpm_read, cpm_has_heading;
    uint8_t  cpm_n_containers, cpm_n_objects;
    uint16_t cpm_n_objects_here, cpm_n_sensors;
    uint8_t  cpm_seg_this, cpm_seg_total;
    uint16_t cpm_containers;     /* bit (id - 1) for every container id that came */
    uint16_t cpm_cont_bad;       /* of those, the ones whose content did not fit its shape */
    uint16_t cpm_n_regions;
    uint16_t cpm_heading_ddeg;
    uint8_t  cpm_list_form;      /* ITS_CPM_LIST_* */
    bool     cpm_wrong_version;  /* a CPM that is not version 2 */
    uint8_t  cpm_other_version;  /* its protocolVersion, 0 included */
    /* EVCSN (messageId 11, or 3 with protocolVersion 0). The texts are what its_decode kept:
     * whole UTF-8 characters, not yet escaped for HTML. */
    bool     evcsn_read, evcsn_relay, evcsn_has_pos;
    uint8_t  evcsn_n_spots;
    uint16_t evcsn_n_total, evcsn_n_stations, evcsn_modes;
    uint32_t evcsn_st_id;
    int32_t  evcsn_lat_e7, evcsn_lon_e7;
    char     evcsn_access[ITS_EVCSN_TEXT + 1];
    char     evcsn_hours[ITS_EVCSN_TEXT + 1];
    char     evcsn_price[ITS_EVCSN_TEXT + 1];
    /* POIM (messageId 3, protocolVersion 1): parking places, as its_poim.c read them. */
    its_poim_t poim;
    /* What the CPM containers hold, as its_cpm.c read them. The cpm_* fields above are the counts
     * that its_decode.c read. cpm.read is false for every other message. */
    its_cpm_t cpm;
    uint32_t perm_psid;          /* The PSID the message declares, 0 when none was read. */
    uint16_t area_a_m;
    uint16_t area_b_m;
    uint16_t area_angle_deg;     /* degrees from north, EN 302 931 */
    msg_prio_t prio;
    /* The signature header, judged by its_sechdr.c. sechdr.read is false for every frame whose
     * header was not read, and msg_extra_from_event leaves it false. */
    its_sechdr_t sechdr;
    /* How the frame travelled (its_gn.c): gn.has_basic is false when no GeoNetworking header was
     * found, and gn.sn_cls stays GN_SN_NONE outside the receive task. */
    its_gn_t gn;
    int32_t  map_alt_cm;         /* MAPEM refPoint altitude, valid with map_has_alt */
    /* The signature of the message itself (its_msgsig.c). Only the receive path of webserver.c
     * fills it, so msg_extra_from_frame and the archive leave it NONE. With it, msg_extra_t takes
     * 864 bytes. */
    its_msgsig_t msgsig;
} msg_extra_t;

/* How often the permission check gave each answer since the device started. Only the receive
 * path counts.
 *
 * The first three count the service answer (msg_extra_t.perm_svc), one per security envelope.
 * The four content counters count perm_cont. They split `ok` and add up to it, which a test
 * can assert. */
typedef struct
{
    uint32_t ok;
    uint32_t bad;
    uint32_t unknown;
    uint32_t content_ok;       /* A bit of the SSP allowed exactly what the message carried. */
    uint32_t content_bad;      /* A bit said no, and the standard assigns that bit clearly. */
    uint32_t content_unknown;  /* A version, form, cause or role the SSP does not settle. */
    uint32_t content_none;     /* ITS_PERM_CONT_FREE: no SSP, or no bit governs the message. */
} msg_perm_stats_t;

/* Working memory for one call: 3832 bytes on esp32c5, measured with riscv32-esp-elf-gcc. 3072
 * of them are cpm_all and 272 the certificate entry. Measure again when those grow. The caller
 * keeps it off the stack. */
typedef struct
{
    its_sec_info_t        sec;
    its_certcache_entry_t cert;
    its_srem_t            srem;
    its_ssem_t            ssem;
    /* The objects of this call's CPM in message order, the first ITS_CPM_ALL_MAX of them, for
     * whoever needs more than the two in msg_extra_t. cpm_all_n is 0 for any other frame. */
    its_cpm_obj_t         cpm_all[ITS_CPM_ALL_MAX];
    uint16_t              cpm_all_n;
    /* The ItsPduHeader stationId of this call's frame, 0 when the header was not found. It gives
     * the sender of a frame without a GN position, where its_decoded_t.station_id is 0. */
    uint32_t              pdu_station;
} msg_extra_scratch_t;

/* Fill `x` from a received frame whose its_decode_frame result is `d`. Only the receive task
 * may pass `note_cache`, which feeds the certificate cache, counts the permission answers and
 * tracks the sequence numbers. */
void msg_extra_from_frame(msg_extra_t *x, const uint8_t *frame, size_t len,
                          const its_decoded_t *d, bool note_cache, uint32_t now_sec,
                          msg_extra_scratch_t *scratch);

/* Fill `x` from a recorded warning, so /traffic words it as /messages does. Only DENM fields are
 * set, and not termination, validity or area, which /traffic shows in their own cells. Everything
 * else stays empty. */
void msg_extra_from_event(msg_extra_t *x, const event_rec_t *e);

/* Copy the permission counters. Any task may call it. */
void msg_extra_perm_stats(msg_perm_stats_t *out);

#ifdef __cplusplus
}
#endif
