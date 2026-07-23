#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Per-hour traffic statistics: how many messages of each road-user category
 * were received, plus vehicle speed. Accumulated in RAM per UTC hour and
 * appended one line per completed hour to /sdcard/logs/traffic.csv, so the
 * history survives reboots. The "Verkehr" web page reads it back. */

/* Road-user categories the per-hour counts are bucketed into. */
enum {
    STAT_CAT_CAR = 0,
    STAT_CAT_BUS,
    STAT_CAT_TRUCK,
    STAT_CAT_TWOWHEEL,   /* cyclist, moped, motorcycle */
    STAT_CAT_PED,
    STAT_CAT_RSU,        /* traffic lights / roadside units */
    STAT_CAT_OTHER,
    STAT_NCAT
};

/* One hour's aggregated counters (also the on-disk CSV row shape). Speed is
 * tracked per category so the web page can show km/h per vehicle type. */
typedef struct {
    uint32_t hour;              /* UTC hour bucket = unix_seconds / 3600 */
    uint32_t total;
    uint32_t cat[STAT_NCAT];
    uint32_t sp_sum[STAT_NCAT]; /* km/h sum per category (for the average) */
    uint32_t sp_cnt[STAT_NCAT];
    uint32_t sp_max[STAT_NCAT];
} stat_hour_t;

void tstat_init(void);

/* Hot path (sniffer task): fold one decoded frame into the current hour.
 * Cheap; no SD I/O. station_type is the ETSI ITS-S type (0 = unknown). */
void tstat_note(uint8_t station_type, uint8_t message_id,
                bool has_speed, int32_t speed_cmps);

/* Periodic (sysmon): once wall-clock time is set, flush a completed hour to
 * SD when the hour rolls over, and prune rows older than the retention. */
void tstat_tick(void);

/* Reads up to `max` most-recent hourly rows spanning the last `hours` into
 * `out` (oldest-first). Returns the count written. Includes the in-RAM
 * current hour as the newest row. */
int tstat_read(uint32_t hours, stat_hour_t *out, int max);
