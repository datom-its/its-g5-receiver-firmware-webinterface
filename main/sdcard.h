#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

void sdcard_register_commands(void);

/* Mount the SD card (SPI mode, shares the bus with Ethernet). Safe to call
 * when already mounted (returns ESP_OK). */
esp_err_t sdcard_mount(void);

/* Unmount the SD card. */
esp_err_t sdcard_unmount(void);

/* Stops the system monitor's auto-remount from undoing a deliberate unmount
 * (/poweroff). Cleared by a manual mount and by a restart. */
void sdcard_inhibit_auto_remount(void);
void sdcard_allow_auto_remount(void);
bool sdcard_auto_remount_inhibited(void);

/* True while the card is mounted. */
bool sdcard_is_mounted(void);

/* Base mount path, e.g. "/sdcard" (always valid, even when unmounted). */
const char *sdcard_mount_point(void);

/* Reformat the card as FAT. Requires the card to be mounted. */
esp_err_t sdcard_format(void);

/* Guards file I/O against unmount/format (same lock). Returns false when not
 * mounted -- lock NOT held then, skip the work. Not recursive. */
bool sdcard_io_begin(void);
void sdcard_io_end(void);

/* Same with a timeout, for paths that must stay responsive when SD is wedged
 * (above all flush-before-restart). False = lock NOT held. */
bool sdcard_io_begin_timeout(uint32_t timeout_ms);

/* Consecutive failed lock attempts, and the age of the hold in progress (not a
 * maximum). Both read 0 during a long op; sysmon tells wedged from busy. */
uint32_t sdcard_io_fail_streak(void);
uint32_t sdcard_io_held_ms(void);

/* Marks a legitimately long hold (archive walk, mount, format) so the stall
 * watchdog does not mistake it for a wedged writer. Must be paired. */
void sdcard_io_long_begin(void);
void sdcard_io_long_end(void);

/* Streaming readers (web transfers) holding a file open; they run WITHOUT the
 * writer lock, so unmount/format AND anything that UNLINKS must consult this --
 * FATFS is built with FS_LOCK=0 and will not refuse. begin false = unavailable. */
int sdcard_read_active(void);

bool sdcard_read_begin(void);
void sdcard_read_end(void);

/* Total and free bytes of the mounted filesystem. */
esp_err_t sdcard_usage(uint64_t *total_bytes, uint64_t *free_bytes);

#ifdef __cplusplus
}
#endif
