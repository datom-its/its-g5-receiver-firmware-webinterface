#include "sdkconfig.h"

#if CONFIG_ENABLE_SD
#include <string.h>

#include "esp_console.h"
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "argtable3/argtable3.h"
#include "driver/sdmmc_host.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"

#include "sdcard.h"

#if CONFIG_SNIFFER_SD_SPI_MODE
#define PIN_NUM_MISO CONFIG_SNIFFER_PIN_MISO
#define PIN_NUM_MOSI CONFIG_SNIFFER_PIN_MOSI
#define PIN_NUM_CLK  CONFIG_SNIFFER_PIN_CLK
#define PIN_NUM_CS   CONFIG_SNIFFER_PIN_CS
#endif  // CONFIG_SNIFFER_SD_SPI_MODE

#define MOUNT_POINT CONFIG_SNIFFER_MOUNT_POINT

static const char TAG[] = "SDCARD";

static sdmmc_card_t *card = NULL;

/* ================================================================== */
/*  Public API                                                        */
/* ================================================================== */

const char *sdcard_mount_point(void)
{
    return MOUNT_POINT;
}

bool sdcard_is_mounted(void)
{
    return card != NULL;
}

esp_err_t sdcard_mount(void)
{
    if (card != NULL)
        return ESP_OK;  /* already mounted */

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        .format_if_mount_failed = true,
        .max_files = 4,
        .allocation_unit_size = 16 * 1024
    };

    esp_err_t ret;
#if CONFIG_SNIFFER_SD_SPI_MODE
    /* The SPI bus is initialised elsewhere (shared with Ethernet). */
    ESP_LOGI(TAG, "Mounting SD card (SPI)");
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot_config.gpio_cs = PIN_NUM_CS;
    slot_config.host_id = host.slot;
    ret = esp_vfs_fat_sdspi_mount(MOUNT_POINT, &host, &slot_config, &mount_config, &card);
#else
    ESP_LOGI(TAG, "Mounting SD card (SDMMC)");
    sdmmc_host_t host = SDMMC_HOST_DEFAULT();
    sdmmc_slot_config_t slot_config = SDMMC_SLOT_CONFIG_DEFAULT();
    gpio_set_pull_mode(15, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(2, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(4, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(12, GPIO_PULLUP_ONLY);
    gpio_set_pull_mode(13, GPIO_PULLUP_ONLY);
    ret = esp_vfs_fat_sdmmc_mount(MOUNT_POINT, &host, &slot_config, &mount_config, &card);
#endif

    if (ret != ESP_OK) {
        if (ret == ESP_FAIL)
            ESP_LOGE(TAG, "Failed to mount filesystem (card present and FAT-formatted?)");
        else
            ESP_LOGE(TAG, "Failed to initialize the card (%s). Check pull-ups / card inserted.",
                     esp_err_to_name(ret));
        card = NULL;
        return ret;
    }
    ESP_LOGI(TAG, "SD card mounted at %s", MOUNT_POINT);
    return ESP_OK;
}

esp_err_t sdcard_unmount(void)
{
    if (card == NULL)
        return ESP_OK;

    esp_err_t ret = esp_vfs_fat_sdcard_unmount(MOUNT_POINT, card);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Card unmount failed: %s", esp_err_to_name(ret));
        return ret;
    }
    card = NULL;
    ESP_LOGI(TAG, "Card unmounted");
    return ESP_OK;
}

esp_err_t sdcard_format(void)
{
    if (card == NULL)
        return ESP_ERR_INVALID_STATE;

    ESP_LOGW(TAG, "Formatting SD card...");
    esp_err_t ret = esp_vfs_fat_sdcard_format(MOUNT_POINT, card);
    if (ret != ESP_OK)
        ESP_LOGE(TAG, "Format failed: %s", esp_err_to_name(ret));
    else
        ESP_LOGI(TAG, "Format done");
    return ret;
}

esp_err_t sdcard_usage(uint64_t *total_bytes, uint64_t *free_bytes)
{
    if (card == NULL)
        return ESP_ERR_INVALID_STATE;
    return esp_vfs_fat_info(MOUNT_POINT, total_bytes, free_bytes);
}

/* ================================================================== */
/*  Console commands (thin wrappers around the API)                   */
/* ================================================================== */

static struct {
    struct arg_str *device;
    struct arg_end *end;
} mount_args;

static int cmd_mount(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&mount_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, mount_args.end, argv[0]);
        return 1;
    }
    if (strncmp(mount_args.device->sval[0], "sd", 2) != 0)
        return 1;

    if (sdcard_mount() != ESP_OK)
        return 1;
    if (card)
        sdmmc_card_print_info(stdout, card);
    return 0;
}

void register_mount(void)
{
    mount_args.device = arg_str1(NULL, NULL, "<sd>", "choose a proper device to mount/unmount");
    mount_args.end = arg_end(1);
    const esp_console_cmd_t cmd = {
        .command = "mount",
        .help = "mount the filesystem",
        .hint = NULL,
        .func = &cmd_mount,
        .argtable = &mount_args
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

static int cmd_unmount(int argc, char **argv)
{
    int nerrors = arg_parse(argc, argv, (void **)&mount_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, mount_args.end, argv[0]);
        return 1;
    }
    if (strncmp(mount_args.device->sval[0], "sd", 2) != 0)
        return 1;

    return sdcard_unmount() == ESP_OK ? 0 : -1;
}

void register_unmount(void)
{
    mount_args.device = arg_str1(NULL, NULL, "<sd>", "choose a proper device to mount/unmount");
    mount_args.end = arg_end(1);
    const esp_console_cmd_t cmd = {
        .command = "unmount",
        .help = "unmount the filesystem",
        .hint = NULL,
        .func = &cmd_unmount,
        .argtable = &mount_args
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

void sdcard_register_commands(void)
{
    register_mount();
    register_unmount();
}

#endif // CONFIG_ENABLE_SD
