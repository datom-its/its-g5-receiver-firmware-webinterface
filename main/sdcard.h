#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

void sdcard_register_commands(void);

/* Mount the SD card. In SPI mode it shares the bus with Ethernet. Safe to call
 * when already mounted (returns ESP_OK). */
esp_err_t sdcard_mount(void);

/* Unmount the SD card. */
esp_err_t sdcard_unmount(void);

/* Mount for sysmon's retry loop: refuses while the auto-remount is inhibited. */
esp_err_t sdcard_mount_auto(void);

/* Stops the system monitor's auto-remount from undoing a deliberate unmount
 * (/poweroff, a give-up after failed writes, a format that did not mount back). Cleared
 * by a restart, a manual mount, a format from the web page or a failed /poweroff unmount. */
void sdcard_inhibit_auto_remount(void);
void sdcard_allow_auto_remount(void);
bool sdcard_auto_remount_inhibited(void);

/* True while the card is mounted. */
bool sdcard_is_mounted(void);

/* Base mount path, e.g. "/sdcard" (always valid, even when unmounted). */
const char *sdcard_mount_point(void);

/* Reformat the card as FAT. Requires the card to be mounted. */
esp_err_t sdcard_format(void);

/* Guards file I/O against unmount and format (same lock). Returns false, with the lock
 * NOT held, when not mounted or a take-out is waiting. Skip the work then. Not recursive. */
bool sdcard_io_begin(void);
void sdcard_io_end(void);

/* Same with a timeout, for paths that must stay responsive when SD is wedged
 * (above all flush-before-restart). False = lock NOT held. */
bool sdcard_io_begin_timeout(uint32_t timeout_ms);

/* Consecutive failed lock attempts, and the age of the hold in progress (not a
 * maximum). Both read 0 during a long op, so sysmon can tell wedged from busy. */
uint32_t sdcard_io_fail_streak(void);
uint32_t sdcard_io_held_ms(void);

/* The same two as peaks since boot, for the loss table: the live pair reads 0
 * almost always, so a poll would never catch the warning signs. */
uint32_t sdcard_io_fail_max(void);
uint32_t sdcard_io_held_max_ms(void);

/* Marks a legitimately long hold (archive walk, mount, format) so the stall
 * watchdog does not mistake it for a wedged writer. Must be paired. */
void sdcard_io_long_begin(void);
void sdcard_io_long_end(void);

/* The PCAP and system-log writers report every flush. A success clears the record, and a
 * failure starts or extends it. Mount, unmount and format clear it too. */
void sdcard_note_write(bool ok);
/* Milliseconds since the first failed write with no success after it, 0 if
 * the last write landed. count receives the failures in that span. */
uint32_t sdcard_write_dead_ms(uint32_t *count);

/* Takes a card out that stopped taking writes. Re-checks the record under the lock and
 * tries a small synced test write first. Returns ESP_OK when it took the card out,
 * ESP_ERR_NOT_FINISHED when a write landed or it is backing off after an earlier test
 * write, ESP_ERR_NO_MEM when the test write failed without proving the card dead (full,
 * out of memory or file handles, volume lock, denied), ESP_ERR_TIMEOUT while a download
 * streams, ESP_ERR_NOT_FOUND when nothing was mounted, otherwise the reason it could not
 * unmount. *probe_err gets the test write errno, 0 if it landed or did not run. *gave_up
 * is set on a later take-out with no write since the remount, or on the third within 30
 * minutes. The auto-remount then stays off. */
esp_err_t sdcard_take_out_if_dead(uint32_t min_ms, uint32_t min_fails, bool *gave_up,
                                  int *probe_err);
/* True from a take-out until a mount succeeds or a manual mount is tried.
 * Automatic retries keep it, so their mount errors do not replace the reason. */
bool sdcard_taken_out(void);
/* Take-outs since boot. */
uint32_t sdcard_takeouts(void);

/* Streaming readers (web transfers) holding a file open. They run WITHOUT the writer lock,
 * so unmount, format AND anything that UNLINKS must check this. FATFS has FS_LOCK=0 and will
 * not refuse. sdcard_read_begin() fails when not mounted or an unmount or format waits. */
int sdcard_read_active(void);

bool sdcard_read_begin(void);
void sdcard_read_end(void);

/* Total and free bytes of the mounted filesystem. */
esp_err_t sdcard_usage(uint64_t *total_bytes, uint64_t *free_bytes);

/* Why the last mount failed, ESP_OK if none did. ESP_FAIL means the card has no usable
 * FAT. Any other error means it never answered or did not mount back after a format. */
esp_err_t sdcard_last_mount_error(void);

#ifdef __cplusplus
}
#endif
