#include "sdkconfig.h"

#if CONFIG_ENABLE_SD
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_console.h"
#include "esp_log.h"
#include "esp_timer.h"
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

/* One lock for mount/unmount/format AND all writer I/O (sdcard_io_begin/end):
 * an unmount during an in-flight fwrite frees FATFS structures still in use. */
static SemaphoreHandle_t sd_lock;

static void sd_lock_take(void)
{
    if (!sd_lock)
        sd_lock = xSemaphoreCreateMutex();
    if (sd_lock)
        xSemaphoreTake(sd_lock, portMAX_DELAY);
}

static void sd_lock_give(void)
{
    if (sd_lock)
        xSemaphoreGive(sd_lock);
}

/* Health of the writer lock: a wedged SPI transaction is otherwise invisible,
 * because every user just returns quietly on timeout. */
static volatile uint32_t s_fail_streak;
static volatile int64_t  s_held_since_us;
/* Peaks, because both live values read 0 whenever anyone looks: every
 * successful acquire clears the streak, every release clears the hold. */
static volatile uint32_t s_fail_max;
static volatile uint32_t s_held_max_ms;

static void sd_mark_held(void) { s_held_since_us = esp_timer_get_time(); }

/* Mount, format and archive reads hold the lock for minutes; masked from the
 * watchdog, but only bounded -- a wedge inside one must not disable it for good. */
#define LONG_OP_MAX_US (10 * 60 * 1000000LL)
static portMUX_TYPE s_long_mux = portMUX_INITIALIZER_UNLOCKED;
static volatile int s_long_op;
static volatile int64_t s_long_since_us;

static bool long_op_active(void)
{
    if (!s_long_op)
        return false;
    int64_t since = s_long_since_us;
    return since && (esp_timer_get_time() - since) < LONG_OP_MAX_US;
}

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

bool sdcard_io_begin(void)
{
    sd_lock_take();
    if (card == NULL)
    {
        sd_lock_give();
        return false;
    }
    /* Stamped here too: the pcap and log writers use this variant, and the
     * stall detector would otherwise never see the very tasks it watches. */
    sd_mark_held();
    return true;
}


bool sdcard_io_begin_timeout(uint32_t timeout_ms)
{
    if (!sd_lock)
        sd_lock = xSemaphoreCreateMutex();
    if (!sd_lock)
        return false;
    if (xSemaphoreTake(sd_lock, pdMS_TO_TICKS(timeout_ms)) != pdTRUE)
    {
        uint32_t st = ++s_fail_streak;
        /* Same mask long_end applies: misses behind an archive walk, mount or
         * format are expected and must not latch a peak for the whole uptime. */
        if (!long_op_active() && st > s_fail_max)
            s_fail_max = st;
        return false;
    }
    if (card == NULL)
    {
        xSemaphoreGive(sd_lock);
        return false;
    }
    s_fail_streak = 0;
    sd_mark_held();
    return true;
}

void sdcard_io_end(void)
{
    /* Peak first: the stamp is cleared below, and long_end has already re-stamped
     * a hold that spanned a long op, so only the short remainder is measured. */
    int64_t since = s_held_since_us;
    if (since && !long_op_active())
    {
        int64_t d = esp_timer_get_time() - since;
        uint32_t ms = d > 0 ? (uint32_t)(d / 1000) : 0;
        if (ms > s_held_max_ms)
            s_held_max_ms = ms;
    }
    /* A completed transaction proves the bus is alive. Clearing here and not only
     * in begin_timeout() also covers the blocking sdcard_io_begin() path. */
    s_fail_streak = 0;
    s_held_since_us = 0;
    sd_lock_give();
}

void sdcard_io_long_begin(void)
{
    /* Counted as a precaution: sd_lock serialises every long operation today,
     * but a caller without that lock would unmask the others too early. */
    portENTER_CRITICAL(&s_long_mux);
    if (s_long_op++ == 0)
        s_long_since_us = esp_timer_get_time();
    portEXIT_CRITICAL(&s_long_mux);
}

void sdcard_io_long_end(void)
{
    portENTER_CRITICAL(&s_long_mux);
    bool last = (s_long_op > 0 && --s_long_op == 0);
    portEXIT_CRITICAL(&s_long_mux);
    if (!last)
        return;
    s_fail_streak = 0;   /* the misses during it were expected, not a wedge */
    /* Re-stamp only an existing writer hold, so held_ms does not report the whole
     * masked span. NOT for mount/format (stamp 0): a stamp would outlive the hold. */
    if (s_held_since_us)
        sd_mark_held();
}

uint32_t sdcard_io_fail_streak(void) { return long_op_active() ? 0 : s_fail_streak; }

uint32_t sdcard_io_fail_max(void)    { return s_fail_max; }
uint32_t sdcard_io_held_max_ms(void) { return s_held_max_ms; }

uint32_t sdcard_io_held_ms(void)
{
    int64_t since = s_held_since_us;
    if (!since || long_op_active())
        return 0;
    int64_t d = esp_timer_get_time() - since;
    return d > 0 ? (uint32_t)(d / 1000) : 0;
}

/* Streaming readers run WITHOUT sd_lock, only counted. No timeout or reaper on
 * the count on purpose; an unbalanced begin/end therefore latches forever. */
static portMUX_TYPE rd_mux = portMUX_INITIALIZER_UNLOCKED;
static int rd_count;
static bool rd_closing;

bool sdcard_read_begin(void)
{
    portENTER_CRITICAL(&rd_mux);
    if (card == NULL || rd_closing)
    {
        portEXIT_CRITICAL(&rd_mux);
        return false;
    }
    rd_count++;
    portEXIT_CRITICAL(&rd_mux);
    return true;
}

void sdcard_read_end(void)
{
    portENTER_CRITICAL(&rd_mux);
    if (rd_count > 0)
        rd_count--;
    portEXIT_CRITICAL(&rd_mux);
}

/* Plain query, no lock required: how many streaming readers hold a file open.
 * Anything that UNLINKS must consult it -- FATFS runs with FS_LOCK=0. */
int sdcard_read_active(void)
{
    portENTER_CRITICAL(&rd_mux);
    int n = rd_count;
    portEXIT_CRITICAL(&rd_mux);
    return n;
}

/* Called with sd_lock held. True: no readers left, rd_closing stays set (new
 * readers refused) until the caller clears it after its operation. */
static bool sd_wait_readers(void)
{
    rd_closing = true;
    for (int waited = 0; ; waited += 100)
    {
        portENTER_CRITICAL(&rd_mux);
        int n = rd_count;
        portEXIT_CRITICAL(&rd_mux);
        if (n == 0)
            return true;
        if (waited >= 3000)
        {
            rd_closing = false;
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

/* format_if_failed = true is reserved for the user's explicit format request
 * on a card that never mounted (e.g. factory exFAT) -- never automatic. */
static esp_err_t sdcard_mount_internal(bool format_if_failed)
{
    sd_lock_take();
    if (card != NULL) {
        sd_lock_give();
        return ESP_OK;  /* already mounted */
    }

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        /* An unreadable filesystem is usually a stumbled-over or foreign card, not one
         * that wants erasing -- auto-format would destroy the archive. /sdcard can format. */
        .format_if_mount_failed = format_if_failed,
        /* Must cover every concurrent opener (all SD writers plus a web download);
         * too low shows up only as a sporadic fopen failure in a random writer. */
        .max_files = 8,
        .allocation_unit_size = 16 * 1024
    };

    esp_err_t ret;
    sdcard_io_long_begin();
#if CONFIG_SNIFFER_SD_SPI_MODE
    /* The SPI bus is initialised elsewhere (shared with Ethernet). */
    ESP_LOGI(TAG, "Mounting SD card (SPI)");
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    /* The 20 MHz default; if SPI bus errors ever reappear in the log,
     * lowering this was the old mitigation. */
    host.max_freq_khz = 20000;
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

    sdcard_io_long_end();
    if (ret != ESP_OK) {
        if (ret == ESP_FAIL)
            ESP_LOGE(TAG, "Failed to mount filesystem (card present and FAT-formatted?)");
        else
            ESP_LOGE(TAG, "Failed to initialize the card (%s). Check pull-ups / card inserted.",
                     esp_err_to_name(ret));
        card = NULL;
        sd_lock_give();
        return ret;
    }
    ESP_LOGI(TAG, "SD card mounted at %s", MOUNT_POINT);
    sd_lock_give();
    return ESP_OK;
}

esp_err_t sdcard_mount(void)
{
    return sdcard_mount_internal(false);
}

/* Set by /poweroff so sysmon's auto-remount does not undo it -- deliberately
 * NOT cleared by sdcard_mount(), which sysmon itself calls. */
static volatile bool s_no_auto_remount;

void sdcard_inhibit_auto_remount(void) { s_no_auto_remount = true; }
void sdcard_allow_auto_remount(void)   { s_no_auto_remount = false; }
bool sdcard_auto_remount_inhibited(void) { return s_no_auto_remount; }

esp_err_t sdcard_unmount(void)
{
    sd_lock_take();
    if (card == NULL) {
        sd_lock_give();
        return ESP_OK;
    }

    if (!sd_wait_readers()) {
        ESP_LOGW(TAG, "Unmount refused: a download is still streaming");
        sd_lock_give();
        return ESP_ERR_TIMEOUT;
    }

    esp_err_t ret = esp_vfs_fat_sdcard_unmount(MOUNT_POINT, card);
    rd_closing = false;
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Card unmount failed: %s", esp_err_to_name(ret));
        sd_lock_give();
        return ret;
    }
    card = NULL;
    ESP_LOGI(TAG, "Card unmounted");
    sd_lock_give();
    return ESP_OK;
}

esp_err_t sdcard_format(void)
{
    /* Held for the whole (multi-second) format so a concurrent unmount (e.g.
     * from the console) can't free `card` mid-operation. */
    sd_lock_take();
    if (card == NULL) {
        sd_lock_give();
        /* A merely unmounted card mounts here and falls through to the real
         * format; only an unreadable one takes the format-on-mount path. */
        if (sdcard_mount_internal(false) != ESP_OK) {
            ESP_LOGW(TAG, "Formatting unreadable SD card via mount...");
            return sdcard_mount_internal(true);
        }
        sd_lock_take();
        if (card == NULL) {
            sd_lock_give();
            return ESP_ERR_INVALID_STATE;
        }
    }

    if (!sd_wait_readers()) {
        ESP_LOGW(TAG, "Format refused: a download is still streaming");
        sd_lock_give();
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGW(TAG, "Formatting SD card...");
    sdcard_io_long_begin();
    esp_err_t ret = esp_vfs_fat_sdcard_format(MOUNT_POINT, card);
    sdcard_io_long_end();
    rd_closing = false;
    if (ret != ESP_OK)
        ESP_LOGE(TAG, "Format failed: %s", esp_err_to_name(ret));
    else
        ESP_LOGI(TAG, "Format done");
    sd_lock_give();
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

/* mount and unmount each need their OWN argtable: sharing one makes the second
 * esp_console_cmd_register() repoint both commands and leak the first pair. */
static struct {
    struct arg_str *device;
    struct arg_end *end;
} mount_args;

static struct {
    struct arg_str *device;
    struct arg_end *end;
} unmount_args;

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
    int nerrors = arg_parse(argc, argv, (void **)&unmount_args);
    if (nerrors != 0) {
        arg_print_errors(stderr, unmount_args.end, argv[0]);
        return 1;
    }
    if (strncmp(unmount_args.device->sval[0], "sd", 2) != 0)
        return 1;

    return sdcard_unmount() == ESP_OK ? 0 : -1;
}

void register_unmount(void)
{
    unmount_args.device = arg_str1(NULL, NULL, "<sd>", "choose a proper device to mount/unmount");
    unmount_args.end = arg_end(1);
    const esp_console_cmd_t cmd = {
        .command = "unmount",
        .help = "unmount the filesystem",
        .hint = NULL,
        .func = &cmd_unmount,
        .argtable = &unmount_args
    };
    ESP_ERROR_CHECK(esp_console_cmd_register(&cmd));
}

void sdcard_register_commands(void)
{
    register_mount();
    register_unmount();
}

#endif // CONFIG_ENABLE_SD
