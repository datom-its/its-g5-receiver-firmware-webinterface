#include "sysstat.h"

#include <stdbool.h>
#include <sys/time.h>

#include "freertos/FreeRTOS.h"

#include "esp_log.h"
#include "esp_system.h"
#include "nvs.h"

static const char TAG[] = "SYSSTAT";

#define NS "sysstat"

/* Live copies so the /system getters never touch NVS. Loaded at boot. */
static uint32_t s_boots;
static uint32_t s_crashes;
static uint32_t s_max_uptime;      /* all-time longest uptime, seconds */
static int64_t  s_last_crash;      /* unix seconds, 0 = none */

/* This boot followed a hard crash but the clock wasn't set yet, so the
 * crash timestamp still needs writing once NTP has synced. */
static bool s_crash_pending;
/* Last max-uptime value actually written to NVS, to throttle flash writes. */
static uint32_t s_max_uptime_nvs;

/* SD losses across reboots. A tired card only shows over days, and the
 * per-boot counters start again at zero after every restart. */
static uint32_t s_sd_lost;       /* estimated frames that never reached the card */
static uint32_t s_sd_flushfail;  /* flushes that failed or wrote only part */
static uint32_t s_sd_unmounts;   /* cards taken out after failed writes, not
                                  * manual unmounts */
static bool     s_sd_dirty;
static uint32_t s_sd_written_up; /* uptime at the last SD-counter write */
/* sysmon adds the deltas and card take-outs. Web, console and OTA tasks add a
 * failed final flush. Without the lock, two concurrent adds can lose one of them. */
static portMUX_TYPE s_sd_mux = portMUX_INITIALIZER_UNLOCKED;

/* NVS writes disable the flash cache, so these are paced. */
#define SD_WRITE_EVERY_SEC 600

/* Only unexpected hard resets count as crashes. A clean reboot, a flash and the
 * sysmon auto-recovery (esp_restart -> ESP_RST_SW) deliberately do not. */
static bool reason_is_crash(esp_reset_reason_t r)
{
    switch (r)
    {
    case ESP_RST_PANIC:
    case ESP_RST_INT_WDT:
    case ESP_RST_TASK_WDT:
    case ESP_RST_WDT:
    case ESP_RST_CPU_LOCKUP:
    case ESP_RST_BROWNOUT:
        return true;
    default:
        return false;
    }
}

void sysstat_record_boot(void)
{
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK)
    {
        ESP_LOGW(TAG, "nvs_open failed; stats disabled this boot");
        return;
    }

    nvs_get_u32(h, "boots", &s_boots);
    nvs_get_u32(h, "crashes", &s_crashes);
    nvs_get_u32(h, "maxup", &s_max_uptime);
    nvs_get_i64(h, "lastcrash", &s_last_crash);
    nvs_get_u32(h, "sdlost", &s_sd_lost);
    nvs_get_u32(h, "sdflush", &s_sd_flushfail);
    nvs_get_u32(h, "sdtakeout", &s_sd_unmounts);
    s_max_uptime_nvs = s_max_uptime;

    s_boots++;
    nvs_set_u32(h, "boots", s_boots);

    if (reason_is_crash(esp_reset_reason()))
    {
        s_crashes++;
        nvs_set_u32(h, "crashes", s_crashes);
        s_crash_pending = true;   /* timestamp backfilled in sysstat_tick */
    }

    nvs_commit(h);
    nvs_close(h);
}

void sysstat_tick(uint32_t uptime_sec)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);
    bool time_valid = tv.tv_sec > 1600000000;   /* ~2020-09, i.e. NTP set */

    bool write_crash = false;
    if (s_crash_pending && time_valid)
    {
        /* The crash happened at the reboot, about uptime_sec seconds ago. */
        s_last_crash = tv.tv_sec - (int64_t)uptime_sec;
        s_crash_pending = false;
        write_crash = true;
    }

    /* Track the live max always, persist at most hourly: an NVS write disables
     * the flash cache and stalls flash/PSRAM code. That makes an open BLE link stutter. */
    bool write_max = false;
    if (uptime_sec > s_max_uptime)
    {
        s_max_uptime = uptime_sec;
        if (s_max_uptime - s_max_uptime_nvs >= 3600)
            write_max = true;
    }

    bool write_sd = s_sd_dirty &&
                    (uptime_sec < s_sd_written_up ||
                     uptime_sec - s_sd_written_up >= SD_WRITE_EVERY_SEC);

    if (!write_crash && !write_max && !write_sd)
        return;

    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK)
        return;
    if (write_crash)
        nvs_set_i64(h, "lastcrash", s_last_crash);
    if (write_max)
    {
        nvs_set_u32(h, "maxup", s_max_uptime);
        s_max_uptime_nvs = s_max_uptime;
    }
    if (write_sd)
    {
        /* Snapshot under the lock, write outside it: flash operations must
         * never happen with interrupts disabled. */
        uint32_t l, f, u;
        portENTER_CRITICAL(&s_sd_mux);
        l = s_sd_lost; f = s_sd_flushfail; u = s_sd_unmounts;
        s_sd_dirty = false;
        portEXIT_CRITICAL(&s_sd_mux);
        nvs_set_u32(h, "sdlost", l);
        nvs_set_u32(h, "sdflush", f);
        nvs_set_u32(h, "sdtakeout", u);
        s_sd_written_up = uptime_sec;
    }
    nvs_commit(h);
    nvs_close(h);
}

void sysstat_sd_add(uint32_t lost, uint32_t flushfail, uint32_t unmounts)
{
    if (!lost && !flushfail && !unmounts)
        return;
    portENTER_CRITICAL(&s_sd_mux);
    s_sd_lost      += lost;
    s_sd_flushfail += flushfail;
    s_sd_unmounts  += unmounts;
    s_sd_dirty = true;
    portEXIT_CRITICAL(&s_sd_mux);
}

void sysstat_sd_get(uint32_t *lost, uint32_t *flushfail, uint32_t *unmounts)
{
    portENTER_CRITICAL(&s_sd_mux);
    uint32_t l = s_sd_lost, f = s_sd_flushfail, u = s_sd_unmounts;
    portEXIT_CRITICAL(&s_sd_mux);
    if (lost)      *lost      = l;
    if (flushfail) *flushfail = f;
    if (unmounts)  *unmounts  = u;
}

void sysstat_flush(void)
{
    /* Called before a planned restart or power cut. The paced write would
     * otherwise lose up to ten minutes of counting. */
    uint32_t l, f, u;
    portENTER_CRITICAL(&s_sd_mux);
    bool dirty = s_sd_dirty;
    l = s_sd_lost; f = s_sd_flushfail; u = s_sd_unmounts;
    s_sd_dirty = false;
    portEXIT_CRITICAL(&s_sd_mux);
    if (!dirty)
        return;
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK)
        return;
    nvs_set_u32(h, "sdlost", l);
    nvs_set_u32(h, "sdflush", f);
    nvs_set_u32(h, "sdtakeout", u);
    nvs_commit(h);
    nvs_close(h);
}

uint32_t sysstat_boot_count(void)      { return s_boots; }
uint32_t sysstat_crash_count(void)     { return s_crashes; }
uint32_t sysstat_max_uptime_sec(void)  { return s_max_uptime; }
int64_t  sysstat_last_crash_time(void) { return s_last_crash; }

void sysstat_reset(void)
{
    /* Counting restarts from now. The max uptime grows back from the current
     * uptime at the next sysstat_tick. */
    s_boots = 0;
    s_crashes = 0;
    s_max_uptime = 0;
    s_max_uptime_nvs = 0;
    s_last_crash = 0;
    s_crash_pending = false;
    s_sd_lost = 0;
    s_sd_flushfail = 0;
    s_sd_unmounts = 0;
    s_sd_dirty = false;
    s_sd_written_up = 0;

    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK)
        return;
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
}
