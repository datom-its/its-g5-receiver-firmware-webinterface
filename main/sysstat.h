#pragma once

#include <stdint.h>

/* Small NVS-backed stability counters shown on /system, so the device
 * reports its own crash history instead of us pulling SD logs. Own NVS
 * namespace ("sysstat"), separate from user config. */

/* Once per boot, right after config_init() (NVS ready). Bumps the boot
 * counter and, if the reset reason is a hard crash (panic/watchdog/
 * brownout/lockup), the crash counter -- and remembers to backfill the
 * crash timestamp once wall-clock time is valid. */
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

/* Zeroes all counters (NVS + RAM) to start measuring a freshly-flashed
 * version from scratch. */
void sysstat_reset(void);
