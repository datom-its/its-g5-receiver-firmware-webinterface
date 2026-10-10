#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_decode.h"

#ifdef __cplusplus
extern "C" {
#endif

/* How one frame travelled: its GeoNetworking headers, EN 302 636-4-1 V1.4.1 clause 9.
 * its_decode.c finds where they lie (gn_*_at), this module reads and judges them. */

/* What a sequence number says against the earlier ones of the same source (Annex A). */
typedef enum
{
    GN_SN_NONE  = 0,   /* no number, or not tracked (archive search, playback) */
    GN_SN_FIRST = 1,   /* first of a run: nothing before it to compare with */
    GN_SN_NEW   = 2,   /* newer than every number before; `gap` numbers were skipped */
    GN_SN_DUP   = 3,   /* heard before: a copy, mostly through a forwarder */
    GN_SN_LATE  = 4,   /* counted in a gap of this run and heard only now: it fills that gap */
    GN_SN_OLD   = 5,   /* below the window or the run's first number: neither counted nor kept */
} gn_sn_t;

/* A reception this far from the position time is a clock that does not match, not an age. */
#define GN_AGE_MAX_MS 600000

typedef struct
{
    uint32_t tst;            /* LPV timestamp as sent: TAI ms since 2004 mod 2^32, with has_lpv */
    int32_t  age_ms;         /* reception minus tst, with has_age; below 0 a clock is off */
    uint16_t sn;             /* sequence number, with has_sn */
    uint16_t gap;            /* numbers skipped right before this one, with GN_SN_NEW */
    uint16_t heading_ddeg;   /* LPV heading as sent, 0.1 degree from north, with has_lpv */
    uint8_t  addr[8];        /* GN_ADDR of the source, which a forwarder does not change */
    uint8_t  lt;             /* LT: multiplier in bits 7..2, base in bits 1..0 */
    uint8_t  rhl;            /* remaining hop limit, as the last forwarder left it */
    uint8_t  mhl;            /* maximum hop limit, as the source set it */
    uint8_t  tc;             /* TC: 0x80 store-carry-forward, 0x40 channel offload, 0x3F TC ID */
    uint8_t  flags;          /* 0x80: the source says it is mobile */
    uint8_t  ht;             /* header type in the high nibble, sub-type in the low one */
    uint8_t  sn_cls;         /* gn_sn_t */
    /* 0 is a real value in every field above, hence the flags. */
    bool     has_basic, has_common, has_sn, has_lpv;
    bool     has_age;        /* age_ms is valid */
    bool     age_off;        /* the timestamp lies more than GN_AGE_MAX_MS from reception */
} its_gn_t;                  /* 36 B on riscv32 (riscv32-esp-elf-gcc 15.2) */

/* What the sequence numbers of one roadside unit said, for inventory.c and senders.csv. */
typedef struct
{
    uint32_t got;            /* numbers heard, each once in a run */
    uint32_t missing;        /* numbers skipped and not heard later */
    uint32_t relayed;        /* of `got`, the ones first heard through a forwarder */
    uint32_t dup;            /* copies of a number already heard */
} its_gn_unit_t;             /* 16 B */

#define GN_TRACK_SOURCES   64    /* the least recently heard gives way: that invents no gap */
#define GN_TRACK_SILENCE_S 120   /* after a longer silence the gap is unknown: a new run */
#define GN_TRACK_STEP_MAX  1024  /* a longer jump is a restart, not a loss */
#define GN_TRACK_WINDOW    32    /* numbers below the newest that are still remembered */

/* Read the headers `d` located in `frame`. It clears `g` first, and `frame` may be NULL. It
 * keeps no state and uses no floating point, so every task may call it, the 4 KB receive task
 * included. */
void its_gn_fill(its_gn_t *g, const uint8_t *frame, size_t len, const its_decoded_t *d);

/* Set the position's age at reception. Nothing is set when `sec` is below EVENTS_CLOCK_MIN,
 * `usec` is above 999999, the LPV is missing or its timestamp is 0 (unknown, clause 8.2.3).
 * Beyond GN_AGE_MAX_MS only age_off is set. */
void its_gn_note_rx(its_gn_t *g, uint32_t sec, uint32_t usec);

/* Sets sn_cls and gap against the earlier numbers of the same source. Only the receive task
 * calls it, once per frame and in reception order. `now_s` only has to count seconds. */
void its_gn_track(its_gn_t *g, uint32_t now_s);

/* Forgets every source, for the host tests. */
void its_gn_track_reset(void);

/* Forwarders the frame passed, 0 when it came straight from the source. Returns -1 when the
 * headers do not say or contradict each other (RHL 0 or above MHL, clause 10.3.2 table 18). */
int its_gn_hops(const its_gn_t *g);

/* LT in milliseconds, clause 9.6.4 table 6: 0 to 6300000. */
uint32_t its_gn_lifetime_ms(uint8_t lt);

/* The heading for the list, the map and the tracks. A CAM gives its own heading, or none if it
 * has none. Any other message gives the LPV heading of a mobile station that is no roadside
 * unit, if it is 1 to 3599, because senders without a heading write 0. 0xFFFF means no
 * heading. With `g` NULL only a CAM can give one. */
uint16_t its_gn_heading(const its_decoded_t *d, const its_gn_t *g);

/* Fold one frame's verdict into `u`. The counts saturate, and a frame classed GN_SN_NONE or
 * GN_SN_OLD changes nothing. */
void its_gn_unit_fold(its_gn_unit_t *u, const its_gn_t *g);

#ifdef __cplusplus
}
#endif
