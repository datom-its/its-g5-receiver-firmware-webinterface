#pragma once

#include <stddef.h>

/* sysmon takes a card out after a minute with at least this many failed writes and none that
 * landed. A healthy card fails only now and then. The values are here so that the fault bar
 * uses the same rule. */
#define SYSMON_SD_DEAD_MS    60000
#define SYSMON_SD_DEAD_MIN   3

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

/* errno of the last failed test write while writes keep failing. 0 once a write lands, and
 * always 0 without SD support. ENOSPC means the card is full. */
int sysmon_sd_probe_errno(void);

/* Builds the mDNS host name: "its-" and the node ID in lower case, with every character
 * outside [a-z0-9] turned into '-'. The result is cut to fit `cap`, and its length is returned. */
size_t sysmon_mdns_hostname(const char *nodeid, char *out, size_t cap);

#ifdef __cplusplus
}
#endif
