#pragma once

/* What the CPMs of the last seconds say, per sender: the perceived objects, the sensor
 * coverage areas and the perception regions (TS 103 324). The sniffer task notes every read
 * CPM with a usable reference position, and the page handler of /cpm.json copies one sender
 * at a time. Raw values only: cpm_geo.c checks and places them when the page is built. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_cpm.h"
#include "its_decode.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CPM_STORE_SENDERS   8
#define CPM_STORE_OBJS      64   /* ITS_CPM_ALL_MAX: what one message hands over */
#define CPM_STORE_SENS      8
#define CPM_STORE_REGS      8    /* MaxPerceptionRegions of TS 103 324 annex F */
/* Objects, sensor areas and regions go 3 s after they were last heard, a sender 3 s after its
 * last CPM: three T_GenCpmMax (1 s), and the sensor container comes at least once a second. */
#define CPM_STORE_STALE_MS  3000

/* kind of a sender: from the last message that named exactly one of containers 1 and 2. One
 * naming both makes it unknown, one naming neither keeps it. */
#define CPM_STORE_KIND_UNKNOWN  0
#define CPM_STORE_KIND_VEHICLE  1
#define CPM_STORE_KIND_RSU      2

/* x of a sender: a bit stays 3 s after the last message that set it, so an object-only CPM
 * does not hide the cut of the one before. Bit 4 (an area not placeable) is web_cpm.c's. */
#define CPM_STORE_X_OBJ   1   /* an object was not kept */
#define CPM_STORE_X_AREA  2   /* a shape, a point or an entry was not kept */

typedef struct {
    its_cpm_obj_t o;
    int32_t  ref_lat_e7, ref_lon_e7;  /* the reference position of the CPM it came in */
    int64_t  seen_ms;                 /* cpm_store_now_ms() when it came */
    uint64_t ref_ms;                  /* referenceTime of that CPM, TimestampIts */
} cpm_store_obj_t;                    /* 72 B */

typedef struct {
    its_cpm_area_t a;
    int32_t ref_lat_e7, ref_lon_e7;   /* its CPM's reference position, used to place regions */
    /* A region's segment (cpm_seg_this, 0 = not split) and its place in that segment's list. */
    uint8_t seg, idx;
    int64_t seen_ms;
} cpm_store_area_t;                   /* 136 B */

/* One sender. Only obj[0 .. n_obj - 1], sens[0 .. n_sens - 1] and reg[0 .. n_reg - 1] hold
 * entries. The slots past them hold stale data, which a copy includes. */
typedef struct {
    int64_t  last_ms;                 /* its last CPM */
    uint64_t ref_ms;                  /* referenceTime of its last CPM, TimestampIts */
    uint64_t reg_gen;                 /* referenceTime of the regions in reg[] */
    int64_t  x_ms[2];                 /* when CPM_STORE_X_OBJ and CPM_STORE_X_AREA were last set */
    uint32_t station_id;
    int32_t  ref_lat_e7, ref_lon_e7;  /* reference position of its last CPM */
    /* The last orientationAngle a readable vehicle container gave, 0.1 degree clockwise from
     * north. A readable one with 3600 or 3601 clears it, a message without one keeps it. */
    uint16_t heading_ddeg;
    bool     has_heading;
    uint8_t  kind;                    /* CPM_STORE_KIND_* */
    uint8_t  edition;                 /* ITS_CPM_CDD_* of its last proven message, 0 = none yet */
    uint8_t  n_obj, n_sens, n_reg;
    uint8_t  x;                       /* CPM_STORE_X_* */
    bool     used;                    /* false for a free slot, placed in a padding byte */
    cpm_store_obj_t  obj[CPM_STORE_OBJS];
    cpm_store_area_t sens[CPM_STORE_SENS];
    cpm_store_area_t reg[CPM_STORE_REGS];
} cpm_store_sender_t;                 /* header 64 + 4608 + 2176 = 6848 B */

/* What one CPM says about its sender. has_heading only from a readable container 1 (a bad
 * one leaves cpm_has_heading false), edition only when its_cpm.c proved it. */
typedef struct {
    uint32_t station_id;
    uint8_t  kind;                    /* CPM_STORE_KIND_*, UNKNOWN when it names none or both */
    bool     has_heading;
    uint16_t heading_ddeg;
    uint8_t  edition;                 /* ITS_CPM_CDD_*, 0 when not proven */
    bool     has_ref_pos;
    bool     veh_read;                /* container 1 came and was readable, with a heading or not */
    bool     both;                    /* it named containers 1 and 2 */
    uint16_t n_walked;                /* objects read completely, more than n if all[] was full */
    uint8_t  seg;                     /* cpm_seg_this of the message, 0 = not split */
    int32_t  ref_lat_e7, ref_lon_e7;
    uint64_t ref_ms;
} cpm_store_msg_t;                    /* 32 B */

void cpm_store_init(void);

/* Sniffer task only, for a CPM its_cpm_decode read into `sum` and `all` (n objects). Walks the
 * shapes into a static scratch when containers 3 or 4 came, then calls cpm_store_note. */
void cpm_store_note_frame(const uint8_t *frame, size_t len, const its_decoded_t *d,
                          const its_cpm_t *sum, const its_cpm_obj_t *all, uint16_t n);

/* The merge, with the clock given. `areas` is NULL when the message had neither container 3
 * nor 4. Takes the lock itself and waits at most one tick (10 ms at 100 Hz, the 5 ms asked for
 * rounded up). If the lock stays busy, the message is skipped. */
void cpm_store_note(int64_t now_ms, const cpm_store_msg_t *m, const its_cpm_obj_t *all,
                    uint16_t n, const its_cpm_areas_t *areas);

/* One sender under the lock, expired entries removed first. False for a free slot or a
 * lock that stayed busy for 100 ms. */
bool cpm_store_copy(unsigned slot, int64_t now_ms, cpm_store_sender_t *out);

/* True when a sender was pushed out of the full store within the last 3 s. */
bool cpm_store_dropped(int64_t now_ms);

/* esp_timer_get_time() / 1000: monotonic, never the wall clock, which NTP can move. */
int64_t cpm_store_now_ms(void);

#ifdef __cplusplus
}
#endif
