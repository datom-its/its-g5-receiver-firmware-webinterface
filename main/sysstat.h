#pragma once

#include <stdint.h>

/* Small NVS-backed stability counters shown on /system, so the device
 * reports its own crash history instead of us pulling SD logs. Own NVS
 * namespace ("sysstat"), separate from user config. */

/* Call once per boot, right after config_init() (NVS ready). Bumps the boot
 * counter. After a hard crash (panic, watchdog, brownout, lockup) it also bumps
 * the crash counter. sysstat_tick() then fills in the crash time once the clock
 * is valid. */
void sysstat_record_boot(void);

/* Periodic tick (from sysmon) with the current uptime in seconds. Tracks
 * the all-time longest uptime and, once NTP has set the clock, records when
 * the last crash reboot happened. */
void sysstat_tick(uint32_t uptime_sec);

uint32_t sysstat_boot_count(void);
uint32_t sysstat_crash_count(void);
uint32_t sysstat_max_uptime_sec(void);
/* Unix seconds of the last crash reboot, or 0 if none recorded yet. */
int64_t  sysstat_last_crash_time(void);

/* SD losses that outlive a reboot. A wedged card can trigger a restart, which
 * zeroes the per-boot counters just when the history matters most.
 *   lost      -- estimated frames that never reached the card
 *   flushfail -- flushes that failed or wrote only part of what was owed
 *   unmounts  -- cards sysmon took out after failed writes */
void sysstat_sd_add(uint32_t lost, uint32_t flushfail, uint32_t unmounts);
void sysstat_sd_get(uint32_t *lost, uint32_t *flushfail, uint32_t *unmounts);

/* Forces the paced SD counters to NVS. For a planned restart or power cut, where
 * the next paced write would never happen. */
void sysstat_flush(void);

/* Zeroes all counters (NVS + RAM) to start measuring a freshly-flashed
 * version from scratch. */
void sysstat_reset(void);
