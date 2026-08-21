#pragma once

#include <stdbool.h>
#include <stdint.h>

/* Per-hour traffic statistics per road-user category, plus speed. Accumulated in
 * RAM per UTC hour, appended to /sdcard/logs/traffic.csv so it survives reboots. */

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
    /* Distinct sender identities per category. Pseudonyms rotate every few
     * minutes, so this is an estimate of the vehicle count -- never call it exact. */
    uint32_t senders[STAT_NCAT];
    bool     senders_capped;    /* counts are a lower bound: table full, or hour merged from parts */
    /* Row predates the rule that counts standing vehicles towards the average;
     * its sums follow the older, higher-reading definition. */
    bool     speed_legacy;
} stat_hour_t;

void tstat_init(void);

/* Hot path (sniffer task): fold one decoded frame into the current hour.
 * Cheap; no SD I/O. station_type is the ETSI ITS-S type (0 = unknown). */
void tstat_note(uint8_t station_type, uint32_t station_id, uint8_t message_id,
                bool has_speed, int32_t speed_cmps);

/* Periodic (sysmon): once wall-clock time is set, flush a completed hour to
 * SD when the hour rolls over, and prune rows older than the retention. */
void tstat_tick(void);

/* Persists the hour still being accumulated -- call before a planned restart. */
void tstat_flush_now(void);

/* Reads up to `max` hourly rows spanning the last `hours` into `out`
 * (oldest-first), including the in-RAM current hour as the newest. */
/* `history_ok` (optional) is false when the stored history could not be read
 * because the card was busy -- the caller must then NOT present what it got
 * as the full window. */
int tstat_read(uint32_t hours, stat_hour_t *out, int max, bool *history_ok);
