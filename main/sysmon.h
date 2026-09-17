#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Call EARLY in app_main, BEFORE initialize_ethernet(). With a static IP that
 * call already posts GOT_IP, and a handler registered afterwards can miss it. */
void sysmon_register_events(void);

/* System monitor task: sniffer watchdog, SD auto-remount, low-heap reboot.
 * Call once the rest of the system is up. */
void sysmon_init(void);

/* Flushes every buffered SD sink NOW (PCAP ring, logs, queues). The card stays
 * mounted. For deliberate restarts and power-off only. The watchdog path skips
 * it on purpose. Returns the PCAP bytes still in RAM if writing failed, else 0. */
size_t sysmon_flush_persistent(void);

#ifdef __cplusplus
}
#endif
