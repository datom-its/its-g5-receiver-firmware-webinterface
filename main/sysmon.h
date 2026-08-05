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

/* Writes every buffered-but-unwritten SD sink out NOW: the PCAP ring (which
 * holds minutes of capture in PSRAM between scheduled flushes), both logs,
 * the vehicle-track queue and the warning-event queue. The card stays
 * mounted.
 *
 * Call before any DELIBERATE restart -- a plain esp_restart() is exactly as
 * abrupt for the card as pulling the plug, and without this every reboot
 * silently costs whatever the ring had not written yet.
 *
 * Deliberately NOT called from the watchdog reboot path: that one fires
 * because something is already wedged, quite possibly the SD writer itself,
 * and getting out fast matters more there than the last few minutes of
 * capture. Every step inside is bounded and never blocks indefinitely. */
void sysmon_flush_persistent(void);

#ifdef __cplusplus
}
#endif
