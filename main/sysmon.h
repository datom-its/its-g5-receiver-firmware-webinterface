#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Registers the event handler that triggers mDNS startup on
 * APP_ETHERNET_MGMT_INTERFACE_GOT_IP. Call this EARLY in app_main, before
 * initialize_ethernet() -- a static-IP configuration posts that event
 * synchronously from within initialize_ethernet() itself, so registering
 * any later risks the default event loop dispatching (and losing) that
 * one-shot event before this handler exists, permanently skipping mDNS for
 * that boot. DHCP is safe either way since lease acquisition takes far
 * longer than the rest of app_main's init sequence, but static IP is not. */
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
