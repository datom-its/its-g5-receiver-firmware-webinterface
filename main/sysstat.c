#include "sysstat.h"

#include <sys/time.h>

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

/* Only unexpected hard downs count -- a clean reboot, a flash or the sysmon
 * auto-recovery (esp_restart -> ESP_RST_SW) is deliberately not a crash. */
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
        /* The reboot happened ~uptime_sec ago; that's when the crash was. */
        s_last_crash = tv.tv_sec - (int64_t)uptime_sec;
        s_crash_pending = false;
        write_crash = true;
    }

    /* Track the live max always, persist at most hourly: an NVS write disables
     * the flash cache and stalls flash/PSRAM code -- a hiccup on an open BLE link. */
    bool write_max = false;
    if (uptime_sec > s_max_uptime)
    {
        s_max_uptime = uptime_sec;
        if (s_max_uptime - s_max_uptime_nvs >= 3600)
            write_max = true;
    }

    if (!write_crash && !write_max)
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
    nvs_commit(h);
    nvs_close(h);
}

uint32_t sysstat_boot_count(void)      { return s_boots; }
uint32_t sysstat_crash_count(void)     { return s_crashes; }
uint32_t sysstat_max_uptime_sec(void)  { return s_max_uptime; }
int64_t  sysstat_last_crash_time(void) { return s_last_crash; }

void sysstat_reset(void)
{
    /* Counting restarts from now; max_uptime re-grows from the running
     * session at the next sysstat_tick. */
    s_boots = 0;
    s_crashes = 0;
    s_max_uptime = 0;
    s_max_uptime_nvs = 0;
    s_last_crash = 0;
    s_crash_pending = false;

    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK)
        return;
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
}
