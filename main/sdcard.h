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

/* True while the card is mounted. */
bool sdcard_is_mounted(void);

/* Base mount path, e.g. "/sdcard" (always valid, even when unmounted). */
const char *sdcard_mount_point(void);

/* Reformat the card as FAT. Requires the card to be mounted. */
esp_err_t sdcard_format(void);

/* Total and free bytes of the mounted filesystem. */
esp_err_t sdcard_usage(uint64_t *total_bytes, uint64_t *free_bytes);

#ifdef __cplusplus
}
#endif
