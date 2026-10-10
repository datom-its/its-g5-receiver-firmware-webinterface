#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_cpm.h"
#include "its_decode.h"
#include "its_poim.h"
#include "msg_extra.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The newest CPM, EVCSN, POIM and RTCMEM per sender: RAM for /traffic (so the page works without
 * a card), summed up into logs/cpm.csv, evcsn.csv, poim.csv, rtcmem.csv, never read back. */

#define INFOLOG_SLOTS     64          /* keys in RAM, LRU by the newest message */
#define INFOLOG_SHOW      16          /* rows the /traffic section shows, newest first */
#define INFOLOG_EVERY_S   60          /* CPM, RTCMEM: a window is due this long after its first message */
#define INFOLOG_GAP_S     60          /* EVCSN, POIM: a change waits this long after the last row */
#define INFOLOG_HOUR_S    3600        /* EVCSN, POIM: a row this often without a change */
#define INFOLOG_APPEND_S  30          /* one append per file at most this often */
#define INFOLOG_FILE_CAP  (1024u * 1024u)
/* Widest row / header with its '\n', every column at its type's widest and texts all '"'
 * (measured): cpm 301/428, evcsn 370/166, poim 571/555, rtcmem 159/134 bytes. */
#define INFOLOG_LINE_MAX  640
#define INFOLOG_BACKOFF_MIN 6         /* ticks after a failure, doubling up to */
#define INFOLOG_BACKOFF_MAX 96
#define INFOLOG_WHY_MINUTE 1
#define INFOLOG_WHY_NEW    2
#define INFOLOG_WHY_CHANGE 3
#define INFOLOG_WHY_HOUR   4

/* The CPM of a slot: the counts its_decode.c read (msg_extra_t cpm_*) and what its_cpm.c read. */
typedef struct {
    bool     wrong_version;
    uint8_t  other_version;
    bool     has_heading;
    uint8_t  n_containers, n_objects, seg_this, seg_total, list_form;
    uint16_t containers, cont_bad, n_objects_here, n_sensors, n_regions, heading_ddeg;
    its_cpm_t c;
} infolog_cpm_t;   /* 184 B */

/* The EVCSN of a slot: msg_extra_t evcsn_* plus poiType and timeStamp from its_decoded_t. */
typedef struct {
    bool     relay, has_pos;
    uint8_t  n_spots;
    uint16_t poi_type, n_total, n_stations, modes;
    uint32_t st_id;
    int32_t  lat_e7, lon_e7;
    uint64_t ts_ms;
    char     access[ITS_EVCSN_TEXT + 1], hours[ITS_EVCSN_TEXT + 1], price[ITS_EVCSN_TEXT + 1];
} infolog_evcsn_t;   /* 136 B */

/* The RTCMEM of a slot: msg_extra_t rtcm_*, all zero unless corrections were read. */
typedef struct {
    uint8_t  msg_cnt, rev, n_msgs, status;
    bool     has_status, has_minute, has_anchor, has_elev;
    uint16_t bytes;
    uint32_t minute;
    int32_t  lat_e7, lon_e7, elev_dm;
} infolog_rtcm_t;   /* 28 B */

/* One key (kind, station, sub). first_s and win describe the open window: its start and the
 * messages since the last row. row_wr_s and row_fp belong to the last row taken for the card,
 * and row_wr_s is 0 when there was none this boot. obj_seen says a CPM of the window was read,
 * so obj_max counts even when the newest was not. */
typedef struct {
    uint32_t station, sub;
    uint32_t first_s, last_s;
    uint32_t row_wr_s;
    uint32_t total;
    uint32_t win;
    uint32_t fp, row_fp;
    uint16_t obj_max;
    int8_t   rssi, rssi_min, rssi_max;
    uint8_t  kind, version, why;
    bool     used, read, has_mac, obj_seen;
    uint8_t  mac[6];
    union {
        infolog_cpm_t   cpm;
        infolog_evcsn_t evcsn;
        its_poim_t      poim;
        infolog_rtcm_t  rtcm;
    } u;
} infolog_slot_t;   /* 280 B, u at 56 (riscv32-esp-elf-gcc 15.2), asserted in infolog.c */

/* Column types. A number prints plain, _NZ leaves 0 empty. _ITSMS: u64 TimestampIts as Unix ms;
 * _TXTZ: NUL-terminated text, aux = its size; _TXTN: aux = offset of the u8 length. */
#define INFOLOG_T_U8       1
#define INFOLOG_T_U16      2
#define INFOLOG_T_U32      3
#define INFOLOG_T_I8       4
#define INFOLOG_T_I32      5
#define INFOLOG_T_BOOL     6          /* 0/1 */
#define INFOLOG_T_ITSMS    7
#define INFOLOG_T_TXTZ     8
#define INFOLOG_T_TXTN     9
#define INFOLOG_T_HHMM     10         /* u8 hour at off, minute at off + 1 */
#define INFOLOG_T_RATE     11         /* u8 mantissa at off, i8 exponent at aux, exact decimal */
#define INFOLOG_T_LIST3    12         /* int32[3] at off, u8 count at aux, joined by spaces, "'" before a leading '-' */
#define INFOLOG_T_VCLASS   13         /* char at off, u8 at aux: "N3", a letter alone when 0 */
#define INFOLOG_T_MAPKIND  14         /* has_map at off, map_intersection at aux: 1 or 2 */
#define INFOLOG_T_MAC      15         /* 6 bytes, aa:bb:cc:dd:ee:ff */
#define INFOLOG_T_WHY      16         /* minute, new, change, hour */
#define INFOLOG_T_MASK     0x1F
#define INFOLOG_T_NZ       0x80
#define INFOLOG_ALWAYS     0xFFFFu    /* pres: the column has no presence byte */

typedef struct {
    const char *name;
    uint16_t off;
    uint16_t aux;
    uint16_t pres;
    uint8_t  pres_mask;
    uint8_t  type;
} infolog_col_t;   /* off/pres: offsetof(infolog_slot_t, ...); pres INFOLOG_ALWAYS = none; type INFOLOG_T_* | INFOLOG_T_NZ (empty when 0) */

void infolog_init(void);
void infolog_note(uint32_t seconds, int rssi, const uint8_t *mac, const its_decoded_t *d,
                  const msg_extra_t *x, uint32_t pdu_station);   /* sniffer task only; lock timeout 0 */
void infolog_tick(void);   /* sysmon task only */
int infolog_snapshot(infolog_slot_t *out, int max);   /* newest first by last_s (ties: slot order); -1 when the lock stayed busy 100 ms */
uint32_t infolog_lost(void);   /* rows since boot that did not or, after a failed fclose, may not have reached the card */
void infolog_to_extra(const infolog_slot_t *s, msg_extra_t *x);   /* what the page's detail line needs */
const infolog_col_t *infolog_cols(uint8_t kind, size_t *n);   /* head columns included */
size_t infolog_header(uint8_t kind, char *out, size_t cap);   /* the names joined by ',' with '\n'; 0 when it does not fit */
size_t infolog_format(const infolog_slot_t *s, char *out, size_t cap);   /* one row with '\n', 0 when it does not fit */

#ifdef __cplusplus
}
#endif
