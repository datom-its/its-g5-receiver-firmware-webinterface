#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* System monitor: a low-priority supervisory task plus a couple of event
 * hooks. Started once from app_main after the rest of the system is up.
 * Handles:
 *   - watchdog-style auto-recovery if the sniffer pipeline wedges,
 *   - auto-remount of the SD card if it wasn't ready at boot,
 *   - a controlled reboot if internal heap stays critically low,
 *   - mDNS so the device is reachable as its-<nodeid>.local. */
void sysmon_init(void);

#ifdef __cplusplus
}
#endif
