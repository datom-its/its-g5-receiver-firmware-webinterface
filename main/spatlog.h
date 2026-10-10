#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Phase history of the traffic lights, appended to the card, so the measured green and red
 * times survive a restart. A row is written when a phase ENDS and its length was measured
 * without a reception gap, so the file holds facts, never estimates. */

typedef struct {
    uint32_t seconds;     /* when the phase ended */
    uint16_t region;      /* IntersectionID, region 0 when the message left it out */
    uint16_t id;
    uint16_t dur_sec;     /* how long the ended phase ran */
    uint8_t  sg;          /* signal group */
    uint8_t  phase;       /* the eventState that ended */
    uint8_t  next;        /* the eventState that started */
} spat_row_t;

/* Rows kept on the card, about 80 KB at ~40 bytes a row. Each ended phase is one row, so the
 * time this covers depends on the intersection: the more signal groups and the shorter the
 * phases, the shorter the history. */
#define SPATLOG_KEEP 2000

void spatlog_init(void);

/* One ended phase. Called from spatem_note, only where the duration was really measured. */
void spatlog_note(uint32_t seconds, uint16_t region, uint16_t id, uint8_t sg,
                  uint8_t phase, uint16_t dur_sec, uint8_t next);

/* Appends what is waiting and trims the file. A delete that waited for the card goes first.
 * Called from the sysmon tick and from sysmon_flush_persistent. */
void spatlog_tick(void);

/* Reads up to `max` newest rows, newest first. Returns how many were written. */
int spatlog_read(spat_row_t *out, int max);

/* Rows the queue could not take. */
uint32_t spatlog_dropped(void);

/* Drops the queue at once, and the file too when the card is free within 2 s. Otherwise the
 * next tick or the restart flush deletes it. The reader shows nothing meanwhile. */
void spatlog_clear(void);

#ifdef __cplusplus
}
#endif
