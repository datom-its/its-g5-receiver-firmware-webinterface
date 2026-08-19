#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/* Call EARLY in app_main, BEFORE initialize_ethernet(): with a static IP the
 * one-shot GOT_IP event is posted synchronously inside that call and is missed. */
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
