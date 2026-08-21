#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "its_decode.h"

/* Public-transport stats from VDV R09.16 telegrams inside CAMs, one "sighting"
 * per vehicle. Deviation is 3-bit: saturates at +/-7 min, 0 = on time OR unsent. */

#define PT_MAX_LINES 64

typedef struct {
    uint16_t line;
    uint32_t sightings;
    int32_t  dev_sum;        /* over non-zero deviations only */
    uint32_t dev_count;      /* how many of those there were */
    uint32_t dev_zero;       /* on time or not transmitted -- unknowable */
    uint16_t saturated;      /* sightings pinned at the +/-7 minute limit */
    int8_t   worst_late, worst_early;
    uint32_t first_seen, last_seen;
} pt_line_t;

void ptlog_init(void);

/* Hot path: fold one decoded frame in. Cheap, RAM only, never blocks. */
void ptlog_note(uint32_t seconds, uint32_t station_id, const its_decoded_t *d);

/* Periodic (sysmon): close passages that went quiet, load/persist the table. */
void ptlog_tick(void);

/* Folds open passages and persists everything -- call before a planned restart. */
void ptlog_flush_now(void);

/* Copies the per-line table for rendering (room for PT_MAX_LINES needed).
 * Returns the count written, most sightings first. */
int ptlog_snapshot(pt_line_t *out);

/* Vehicles currently being tracked as an ongoing passage. */
int ptlog_open_count(void);

/* Completed passages the append queue could not take, since boot. */
uint32_t ptlog_passages_dropped(void);

/* One completed passage, newest first, read back from the log on the card. */
typedef struct {
    uint32_t seconds;
    uint16_t line, dest;
    uint8_t  course;
    int8_t   deviation;
    uint16_t secs_in_range;
} pt_pass_t;

/* Passage rows kept on the card; ~40 bytes per row, so ~80 KB. In the header
 * because a caller sizing its array smaller only throws rows away. */
#define PT_PASS_KEEP 2000

/* Reads up to `max` most recent passages. Returns the count written. */
int ptlog_read_passages(pt_pass_t *out, int max);

void ptlog_clear(void);
