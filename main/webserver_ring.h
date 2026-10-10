#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sdkconfig.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "its_decode.h"
#include "inventory.h"
#include "msg_extra.h"

/* The received-message ring of webserver.c and the counters beside it, for the start page
 * (web_start.c), the message list (web_messages.c) and the map (web_map.c). */

#define WEB_MSG_RING_SIZE   20

#define WEB_MSG_TYPE_LEN 32

typedef struct {
    uint32_t seconds;
    uint32_t microseconds;
    uint32_t length;

    int      rssi;
    char     msgtype[WEB_MSG_TYPE_LEN];
    bool     has_position; /* true if lat_e7/lon_e7/station_id below are valid (CAM's own
                             * referencePosition, or a GN-layer fallback for anything else
                             * that reached an ITS PDU header -- see its_decode_frame) */
    int32_t  lat_e7;       /* WGS84 latitude,  1e-7 degree units */
    int32_t  lon_e7;       /* WGS84 longitude, 1e-7 degree units */
    uint32_t station_id;   /* ItsPduHeader.stationId; stable per sender, only meaningful if has_position */
    bool     has_speed;    /* true if speed_cmps below is valid (vehicles only, not RSUs) */
    int32_t  speed_cmps;   /* speed in cm/s (0.01 m/s units, matches the wire encoding) */
    uint16_t length_dm;    /* CAM vehicle size, decimetres; 0 = not sent/unavailable */
    uint8_t  width_dm;
    uint8_t  src_mac[6];   /* 802.11 sender address (Addr2) */
    bool     has_src_mac;
    /* VDV R09.16 telegram out of a public-transport CAM, 0 = not carried. */
    uint16_t pt_line;      /* LN Liniennummer */
    uint8_t  pt_course;    /* KN Kursnummer */
    uint16_t pt_dest;      /* ZN Zielnummer */
    /* For MP and ZL, 0 can mean "not sent" or a real 0. R09.16 cannot tell the two apart,
     * so the page leaves a zero out instead of printing it as a value. */
    uint16_t pt_point;     /* MP Meldepunktnummer */
    uint8_t  pt_train_len; /* ZL Zuglaenge */
    uint8_t  pt_request;   /* HA 0=none, 1=straight, 2=left, 3=right */
    uint8_t  pt_priority;  /* PR */
    int16_t  pt_deviation; /* ZW, signed: positive = running late */
    bool     pt_telegram;
    /* CAM detail (see its_cam_detail_t). The path history costs 64 bytes an
     * entry, i.e. 1.3 KB across this 20-slot ring in PSRAM -- cheap enough
     * to carry rather than re-derive. */
    /* CAM: altitude, longitudinal acceleration and drive direction. */
    bool     has_alt;
    int32_t  alt_cm;
    bool     has_long_accel;
    int16_t  long_accel;      /* 0.1 m/s^2, negative when braking */
    uint8_t  drive_dir;       /* 0 forward, 1 backward, 2 unavailable */
    bool     has_lane;
    int8_t   lane;            /* LanePosition: 1..13 driving lanes from the inside,
                               * 0 and 14 hard shoulders, -1 off the road */
    uint8_t  n_path;
    int32_t  path_lat_e7[ITS_PATH_MAX], path_lon_e7[ITS_PATH_MAX];
    uint16_t heading_ddeg; /* 0.1 deg, its_gn_heading: the CAM's, else the GN position
                            * vector's. 0xFFFF = none */
    uint8_t  accel_ctrl;   /* ITS_ACC_*, only valid if has_accel_ctrl */
    bool     has_accel_ctrl;
    uint8_t  ext_lights;   /* ITS_LIGHT_*, only valid if has_lights */
    bool     has_lights;
    uint8_t  role;         /* VehicleRole, 0xFF = not sent */
    bool     embarking;    /* public transport: doors open */
    /* SPATEM: signal groups sent and how many show green. Both are 0 for other messages. */
    uint8_t  spat_n, spat_green;
    msg_extra_t extra;     /* everything msg_extra.h lists beyond its_decode_frame */
} web_msg_entry_t;

extern web_msg_entry_t msg_ring[WEB_MSG_RING_SIZE];
extern size_t msg_ring_head;
extern size_t msg_ring_count;
extern uint32_t msg_total_count;
extern uint32_t msg_last_sec1;
extern SemaphoreHandle_t msg_ring_mutex;

/* Message-type breakdown for the small stats block on the status page. The
 * labels come from its_decode: the message type, prefixed with the station type
 * when that is known, e.g. "CAM", "Bus CAM" or "RSU GeoNet:2004". Those
 * combinations are why the table has this many slots. A linear scan over a
 * fixed table needs no dynamic allocation. */
#define MSG_TYPE_STATS_SLOTS 24
typedef struct {
    char     label[WEB_MSG_TYPE_LEN];
    uint32_t count;
} msg_type_stat_t;
extern msg_type_stat_t msg_type_stats[MSG_TYPE_STATS_SLOTS];
extern uint32_t msg_type_stats_other;

/* Packet-rate tracking: per-second buckets in a 60-second ring. */
#define RATE_WINDOW_SECS 60
typedef struct {
    uint64_t sec;
    uint32_t count;
} rate_bucket_t;
extern rate_bucket_t rate_buckets[RATE_WINDOW_SECS];
uint32_t rate_packets_last_minute(void);

/* Minute history behind the two one-hour sparklines: one writer (hist_tick, on
 * the esp_timer task), one reader (httpd). Ordering is spelled out at both ends. */
#define HIST_MINUTES    60
#define HIST_TEMP_NONE  INT16_MIN
/* Compiler-only barrier. The part is single-core, so no CPU fence is needed. Not
 * __atomic_signal_fence: that orders atomics, and clang sinks plain loads past it. */
#define HIST_BARRIER()  __asm__ __volatile__("" ::: "memory")

typedef struct {
    uint32_t stamp;     /* sample number held here; 0 = empty or being written */
    uint32_t rate;      /* frames counted in that minute */
    int16_t  temp_dc;   /* 0.1 C, HIST_TEMP_NONE if the sensor did not answer */
    int16_t  pad;
} hist_slot_t;
extern hist_slot_t hist_ring[HIST_MINUTES];
extern uint32_t hist_count;

void entry_from_decoded(web_msg_entry_t *e, const its_decoded_t *d);

/* Two parts share this buffer: the fields webserver.c decodes, and whatever web_msgdetail
 * appends behind them. The second part is measured with every field filled: 4045 bytes for a
 * German POIM parking message whose two texts stop at 40 bytes of escaped output (1416 of it
 * the signature header, 379 how the frame travelled, 111 the message signature and 140 the two
 * permission items). A CPM reaches 4019, an EVCSN whose texts are nothing but quotes 3899.
 * The first part, with every number at its type's widest and every
 * field set needs 747 (English; German 743), plus 30
 * for the dash and the div of the signature line. That plus 225 bytes of margin, 1002 in all,
 * stays free, so 5048 is the least and 4992 too small. */
#define MSG_DETAIL_MAX 5120

/* Names of roadside units for the sender column. inventory_note only tries the list's lock,
 * so each lookup may cost the inventory a frame. An answer is therefore kept for 30 s, but a
 * busy list is asked again next time. httpd task only. The archive search keeps its own memo. */
typedef struct {
    uint8_t  mac[6];
    bool     hit;
    uint32_t at;        /* uptime second + 1 of the answer, 0 = empty slot */
    char     name[INV_NAME_LEN];
} snd_name_t;
#define SND_CACHE_N   16
extern snd_name_t s_snd_cache[SND_CACHE_N];
const char *snd_name(snd_name_t *tab, int n, const uint8_t mac[6], uint32_t now_s);

void msg_detail_text(const web_msg_entry_t *e, uint32_t now, char *out, size_t cap);
size_t denm_json(uint32_t station_id, uint32_t now, char *out, size_t cap);
size_t cam_json_extra(const web_msg_entry_t *e, char *out, size_t cap);
#if CONFIG_HTTPD_WS_SUPPORT || CONFIG_ENABLE_SD
size_t build_msg_json(char *out, size_t out_size);
#endif
