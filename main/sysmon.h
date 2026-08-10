#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Call EARLY in app_main, before initialize_ethernet() -- a static-IP config
 * posts APP_ETHERNET_MGMT_INTERFACE_GOT_IP synchronously from inside that
 * call, so registering later can miss the one-shot event and skip mDNS for
 * that boot. DHCP is unaffected (lease acquisition takes much longer). */
void sysmon_register_events(void);

/* System monitor task: sniffer watchdog, SD auto-remount, low-heap reboot.
 * Call once the rest of the system is up. */
void sysmon_init(void);

/* Flushes every buffered SD sink NOW (PCAP ring, logs, queues); the card stays
 * mounted. For DELIBERATE restarts only -- the watchdog path skips it on purpose. */
void sysmon_flush_persistent(void);

#ifdef __cplusplus
}
#endif
