#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Call EARLY in app_main, before initialize_ethernet() -- a static-IP config
 * posts APP_ETHERNET_MGMT_INTERFACE_GOT_IP synchronously from inside that
 * call, so registering later can miss the one-shot event and skip mDNS for
 * that boot. DHCP is unaffected (lease acquisition takes much longer). */
void sysmon_register_events(void);

/* System monitor: a low-priority supervisory task. Handles:
 *   - watchdog-style auto-recovery if the sniffer pipeline wedges,
 *   - auto-remount of the SD card if it wasn't ready at boot,
 *   - a controlled reboot if internal heap stays critically low.
 * Call once the rest of the system is up; unlike sysmon_register_events(),
 * this has no boot-order sensitivity of its own. */
void sysmon_init(void);

#ifdef __cplusplus
}
#endif
