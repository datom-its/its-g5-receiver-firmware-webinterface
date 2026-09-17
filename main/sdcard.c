#include "sdkconfig.h"

#if CONFIG_ENABLE_SD
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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
#include "sysstat.h"

#if CONFIG_SNIFFER_SD_SPI_MODE
#define PIN_NUM_MISO CONFIG_SNIFFER_PIN_MISO
#define PIN_NUM_MOSI CONFIG_SNIFFER_PIN_MOSI
#define PIN_NUM_CLK  CONFIG_SNIFFER_PIN_CLK
#define PIN_NUM_CS   CONFIG_SNIFFER_PIN_CS
#endif  // CONFIG_SNIFFER_SD_SPI_MODE

#define MOUNT_POINT CONFIG_SNIFFER_MOUNT_POINT

/* Long enough that a busy writer finishes, short enough that /poweroff still
 * answers inside the caller's timeout. Applies to both bus modes. */
#define SD_UNMOUNT_LOCK_MS 10000

/* After a test write that did not prove the card dead, the next one waits this
 * long, doubling up to the maximum. A writer success or a mount starts over. */
#define PROBE_GAP_MIN_MS  (60 * 1000)
#define PROBE_GAP_MAX_MS  (30 * 60 * 1000)
/* Three take-outs within this window give up even if writes landed in between. */
#define TAKEOUT_BURST_US  (30 * 60 * 1000000LL)

static const char TAG[] = "SDCARD";

static sdmmc_card_t *card = NULL;

/* Set while sysmon waits to take a failing card out. The two periodic writers
 * (sdcard_io_begin) skip their turn, or on a card that fails slowly they would
 * keep winning the lock. Flush and page paths use the timeout variant and wait. */
static volatile bool s_takeout_pending;

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

/* Bounded variant for unmount: sd_lock_take() waits forever, so a wedged SPI
 * transaction would leave /poweroff unable to answer at all. */
static bool sd_lock_take_timeout(uint32_t ms)
{
    if (!sd_lock)
        sd_lock = xSemaphoreCreateMutex();
    return sd_lock && xSemaphoreTake(sd_lock, pdMS_TO_TICKS(ms)) == pdTRUE;
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
/* Peaks, because both live values are almost always 0 when read. Every release
 * clears both, and a successful sdcard_io_begin_timeout() clears the streak. */
static volatile uint32_t s_fail_max;
static volatile uint32_t s_held_max_ms;

static void sd_mark_held(void) { s_held_since_us = esp_timer_get_time(); }

/* Mount, format, prunes and archive reads can hold the lock for minutes. The
 * stall watchdog ignores them for at most 10 min, so a wedge in one is still caught. */
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
    if (s_takeout_pending)
        return false;
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
        /* Same mask as sdcard_io_fail_streak(). Misses behind a mount, format, prune
         * or archive walk are expected and must not latch a peak for the whole uptime. */
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

/* Write health, separate from the lock health above: a card that rejects every
 * write quickly never holds the lock long. sdlog and sdpcap report, sysmon reads. */
static portMUX_TYPE s_wr_mux = portMUX_INITIALIZER_UNLOCKED;
static int64_t  s_wr_bad_since_us;   /* first failure after the last success, 0 = healthy */
static uint32_t s_wr_bad_count;
static int64_t  s_probe_hold_until_us; /* no test write before this */
static uint32_t s_probe_gap_ms;
/* Only written with sd_lock held, like every report. */
static bool     s_landed_since_mount; /* a write landed since the last mount */
static bool     s_took_out_before;    /* this boot already took a card out */
static int64_t  s_takeout_us[3];      /* the last three take-outs, ring by count */
static uint32_t s_takeouts_boot;
/* Read by the status pages without the lock. Cleared by a successful mount or a
 * manual mount attempt, not by the automatic retries. */
static volatile bool s_taken_out;

static void wr_reset(void)
{
    portENTER_CRITICAL(&s_wr_mux);
    s_wr_bad_since_us = 0;
    s_wr_bad_count = 0;
    s_probe_hold_until_us = 0;
    s_probe_gap_ms = 0;
    portEXIT_CRITICAL(&s_wr_mux);
}

void sdcard_note_write(bool ok)
{
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_wr_mux);
    if (ok)
    {
        s_wr_bad_since_us = 0;
        s_wr_bad_count = 0;
        s_landed_since_mount = true;
        s_probe_hold_until_us = 0;
        s_probe_gap_ms = 0;
    }
    else
    {
        if (!s_wr_bad_since_us)
            s_wr_bad_since_us = now;
        s_wr_bad_count++;
    }
    portEXIT_CRITICAL(&s_wr_mux);
}

uint32_t sdcard_write_dead_ms(uint32_t *count)
{
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_wr_mux);
    int64_t since = s_wr_bad_since_us;
    uint32_t n = s_wr_bad_count;
    portEXIT_CRITICAL(&s_wr_mux);
    if (count)
        *count = n;
    if (!since || now <= since)
        return 0;
    int64_t ms = (now - since) / 1000;
    return ms > (int64_t)UINT32_MAX ? UINT32_MAX : (uint32_t)ms;
}

/* Streaming readers run WITHOUT sd_lock, only counted. The count has no timeout
 * or reaper on purpose. A begin without a matching end leaves it stuck. */
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
 * Anything that UNLINKS must check it. FATFS with FS_LOCK=0 unlinks open files too. */
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

/* ESP_OK until a mount has failed. The mount path writes it and the httpd
 * task reads it, so it has to be volatile. */
static volatile esp_err_t s_last_mount_err = ESP_OK;

/* Set by /poweroff, by a give-up in sdcard_take_out_if_dead and by a format
 * that could not mount back, so sysmon's auto-remount does not undo them. A
 * manual mount or format clears it. sdcard_mount_auto() refuses while it is set. */
static volatile bool s_no_auto_remount;

/* IDF left a stale context behind after a format that could not mount back.
 * Another mount or format could reach freed memory through it, so both wait
 * for a restart. */
static volatile bool s_needs_restart;

/* format_if_failed = true is reserved for the user's explicit format request
 * on a card that never mounted (e.g. factory exFAT). Never set it automatically. */
static esp_err_t sdcard_mount_internal(bool format_if_failed, bool auto_retry)
{
    sd_lock_take();
    if (card != NULL) {
        sd_lock_give();
        return ESP_OK;  /* already mounted */
    }
    /* Checked under the lock: /poweroff or a give-up can set the inhibit
     * between sysmon's own check and this call. */
    if ((auto_retry && s_no_auto_remount) || s_needs_restart) {
        sd_lock_give();
        return ESP_ERR_INVALID_STATE;
    }

    esp_vfs_fat_sdmmc_mount_config_t mount_config = {
        /* An unreadable filesystem is usually a stumbled-over or foreign card, not one
         * that wants erasing. Auto-format would destroy the archive. /sdcard can format. */
        .format_if_mount_failed = format_if_failed,
        /* Must cover every concurrent opener (all SD writers plus a web download).
         * Too low a value shows up only as a sporadic fopen failure in a random writer. */
        .max_files = 8,
        .allocation_unit_size = 16 * 1024
    };

    esp_err_t ret;
    sdcard_io_long_begin();
#if CONFIG_SNIFFER_SD_SPI_MODE
    /* The SPI bus is initialised elsewhere (shared with Ethernet). */
    ESP_LOGI(TAG, "Mounting SD card (SPI)");
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    /* The IDF default of 20 MHz. If SPI bus errors show up in the log, lowering
     * this has helped before. */
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
        /* Kept for the web page. ESP_FAIL means the card answered but has no usable
         * FAT. Any other error means it never answered at all. */
        s_last_mount_err = ret;
        /* An automatic retry keeps "taken out" as the report. Its mount error on
         * a failing card would read as "not answering" or even "format it". */
        if (!auto_retry)
            s_taken_out = false;
        if (ret == ESP_FAIL)
            ESP_LOGE(TAG, "Failed to mount filesystem (card present and FAT-formatted?)");
        else
            ESP_LOGE(TAG, "Failed to initialize the card (%s). Check pull-ups / card inserted.",
                     esp_err_to_name(ret));
        card = NULL;
        sd_lock_give();
        return ret;
    }
    s_last_mount_err = ESP_OK;
    wr_reset();
    s_landed_since_mount = false;
    s_taken_out = false;
    ESP_LOGI(TAG, "SD card mounted at %s", MOUNT_POINT);
    sd_lock_give();
    return ESP_OK;
}

esp_err_t sdcard_last_mount_error(void) { return s_last_mount_err; }

esp_err_t sdcard_mount(void)
{
    return sdcard_mount_internal(false, false);
}

esp_err_t sdcard_mount_auto(void)
{
    return sdcard_mount_internal(false, true);
}

bool sdcard_taken_out(void)     { return s_taken_out; }
uint32_t sdcard_takeouts(void)  { return s_takeouts_boot; }

void sdcard_inhibit_auto_remount(void) { s_no_auto_remount = true; }
void sdcard_allow_auto_remount(void)   { s_no_auto_remount = false; }
bool sdcard_auto_remount_inhibited(void) { return s_no_auto_remount; }

esp_err_t sdcard_unmount(void)
{
    /* ESP_ERR_INVALID_STATE, not TIMEOUT, because the caller tells them apart.
     * TIMEOUT means a busy reader and is worth a retry. INVALID_STATE means a wedged writer. */
    if (!sd_lock_take_timeout(SD_UNMOUNT_LOCK_MS))
        return ESP_ERR_INVALID_STATE;
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
    wr_reset();
    ESP_LOGI(TAG, "Card unmounted");
    sd_lock_give();
    return ESP_OK;
}

/* 0 = the test write landed, otherwise errno. Truncating keeps it to one
 * cluster, and fsync makes the card take the sector instead of a cache. */
static int write_probe(void)
{
    char path[64];
    snprintf(path, sizeof(path), "%s/.wrprobe", MOUNT_POINT);
    errno = 0;
    FILE *f = fopen(path, "w");
    if (!f)
        return errno ? errno : EIO;
    int err = 0;
    if (fputs("probe\n", f) < 0 || fflush(f) != 0 || fsync(fileno(f)) != 0)
        err = errno ? errno : EIO;
    if (fclose(f) != 0 && !err)
        err = errno ? errno : EIO;
    return err;
}

static void probe_back_off(void)
{
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_wr_mux);
    s_probe_gap_ms = !s_probe_gap_ms ? PROBE_GAP_MIN_MS
                   : s_probe_gap_ms >= PROBE_GAP_MAX_MS / 2 ? PROBE_GAP_MAX_MS
                   : s_probe_gap_ms * 2;
    s_probe_hold_until_us = now + (int64_t)s_probe_gap_ms * 1000;
    portEXIT_CRITICAL(&s_wr_mux);
}

esp_err_t sdcard_take_out_if_dead(uint32_t min_ms, uint32_t min_fails, bool *gave_up,
                                  int *probe_err)
{
    if (gave_up)
        *gave_up = false;
    if (probe_err)
        *probe_err = 0;
    int64_t now = esp_timer_get_time();
    portENTER_CRITICAL(&s_wr_mux);
    bool hold = now < s_probe_hold_until_us;
    portEXIT_CRITICAL(&s_wr_mux);
    if (hold)
        return ESP_ERR_NOT_FINISHED;
    /* A streaming download would refuse the unmount anyway. Not probing now
     * keeps it and the writers undisturbed. */
    if (sdcard_read_active() > 0)
        return ESP_ERR_TIMEOUT;
    s_takeout_pending = true;
    bool locked = sd_lock_take_timeout(SD_UNMOUNT_LOCK_MS);
    s_takeout_pending = false;
    if (!locked)
        return ESP_ERR_INVALID_STATE;
    if (card == NULL) {
        sd_lock_give();
        return ESP_ERR_NOT_FOUND;
    }
    /* Again under the lock: a write may have landed while this waited. */
    uint32_t n = 0;
    if (sdcard_write_dead_ms(&n) < min_ms || n < min_fails) {
        sd_lock_give();
        return ESP_ERR_NOT_FINISHED;
    }
    /* One broken file must not cost the whole card. Neither must a full card,
     * a lack of memory or file handles, the FATFS volume lock held by a lock-free
     * user (ETIMEDOUT) or a denied directory entry (EACCES). Only a card that fails
     * a fresh write for another reason is taken out, typically with EIO or ENODEV. */
    int err = write_probe();
    if (probe_err)
        *probe_err = err;
    if (err == 0 || err == ENOSPC || err == ENOMEM || err == ENFILE || err == EMFILE ||
        err == ETIMEDOUT || err == EACCES) {
        if (err == 0)
            s_landed_since_mount = true;
        probe_back_off();
        sd_lock_give();
        return err == 0 ? ESP_ERR_NOT_FINISHED : ESP_ERR_NO_MEM;
    }
    if (!sd_wait_readers()) {
        ESP_LOGW(TAG, "Take-out refused: a download is still streaming");
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
    wr_reset();
    s_taken_out = true;
    /* Out a second time with no write since the remount, or three times within
     * 30 minutes: mounting it again would only flap, and an outside watchdog that
     * waits for several bad minutes in a row would never act. */
    int64_t t = esp_timer_get_time();
    uint32_t count = s_takeouts_boot;
    bool burst = count >= 2 && t - s_takeout_us[(count + 1) % 3] < TAKEOUT_BURST_US;
    s_takeout_us[count % 3] = t;
    s_takeouts_boot++;
    sysstat_sd_add(0, 0, 1);
    if ((s_took_out_before && !s_landed_since_mount) || burst) {
        s_no_auto_remount = true;
        if (gave_up)
            *gave_up = true;
    }
    s_took_out_before = true;
    ESP_LOGI(TAG, "Card taken out, the test write failed: %s", strerror(err));
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
         * format. Only an unreadable one takes the format-on-mount path. */
        if (sdcard_mount_internal(false, false) != ESP_OK) {
            ESP_LOGW(TAG, "Formatting unreadable SD card via mount...");
            return sdcard_mount_internal(true, false);
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
    /* IDF returns ESP_OK even when mounting back failed, after it has freed the
     * card. Unmounting that pointer later would free it a second time. */
    if (ret == ESP_OK && esp_vfs_fat_info(MOUNT_POINT, NULL, NULL) == ESP_ERR_INVALID_STATE) {
        ESP_LOGE(TAG, "The card did not mount back after the format. Restart the device "
                      "before mounting or formatting it again");
        card = NULL;
        s_last_mount_err = ESP_ERR_INVALID_RESPONSE;
        s_needs_restart = true;
        s_no_auto_remount = true;
        ret = ESP_FAIL;
    }
    else if (ret == ESP_OK)
        wr_reset();   /* failures from before the format say nothing now */
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

/* mount and unmount each need their OWN argtable. With a shared one, the second
 * register_*() call overwrites the args of both commands and leaks the first pair. */
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

    /* Same as the web button: mounting by hand ends a give-up or /poweroff. */
    sdcard_allow_auto_remount();
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
