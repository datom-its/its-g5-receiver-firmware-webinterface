#include "web_system.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "esp_chip_info.h"
#include "esp_core_dump.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_app_desc.h"
#include "esp_ota_ops.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "bt_stream.h"
#include "ethernet.h"
#include "events_log.h"
#include "inventory.h"
#include "mqtt.h"
#include "ptlog.h"
#include "sdpcap.h"
#include "cmd_sniffer.h"
#include "tracklog.h"
#include "sdcard.h"
#include "sysstat.h"
#include "webserver_priv.h"

static const char TAG[] = "WEBSERVER";

/* ================================================================== */
/*  /system  -- chip, memory, per-task CPU load                       */
/* ================================================================== */

/* CSS class for internal RAM by the used share of the total. The byte count
 * alone says little, because the total differs per chip variant. */
static const char *ram_int_class(void)
{
    size_t tot = heap_caps_get_total_size(MALLOC_CAP_INTERNAL);
    size_t fre = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    if (!tot || fre > tot) return "";
    return lvl_class((unsigned)(((uint64_t)(tot - fre) * 100) / tot), 85, 92);
}

static const char *reset_reason_str(esp_reset_reason_t r)
{
    bool de = (web_lang() == LANG_DE);
    switch (r)
    {
    case ESP_RST_POWERON:   return de ? "Kaltstart (Strom angelegt)" : "Power-on (cold boot)";
    case ESP_RST_EXT:       return de ? "Externer Reset (Pin/Taste)" : "External reset (pin/button)";
    case ESP_RST_SW:        return de ? "Software (Neustart/Update)"  : "Software (restart/update)";
    case ESP_RST_PANIC:     return de ? "Absturz (Exception)"        : "Panic / exception";
    case ESP_RST_INT_WDT:   return de ? "Interrupt-Watchdog"         : "Interrupt watchdog";
    case ESP_RST_TASK_WDT:  return de ? "Task-Watchdog"              : "Task watchdog";
    case ESP_RST_WDT:       return de ? "Watchdog"                   : "Other watchdog";
    case ESP_RST_DEEPSLEEP: return de ? "Deep-Sleep-Aufwachen"       : "Deep-sleep wake";
    case ESP_RST_BROWNOUT:  return de ? "Unterspannung (Brownout)"   : "Brownout (undervoltage)";
    case ESP_RST_SDIO:      return "SDIO";
    case ESP_RST_USB:       return de ? "USB-Reset"                  : "USB reset";
    case ESP_RST_JTAG:      return de ? "JTAG-Reset"                 : "JTAG reset";
    case ESP_RST_EFUSE:     return de ? "eFuse-Fehler"               : "eFuse error";
    case ESP_RST_PWR_GLITCH:return de ? "Spannungs-Glitch"          : "Power glitch";
    case ESP_RST_CPU_LOCKUP:return de ? "CPU-Lockup (Doppelfehler)"  : "CPU lockup (double fault)";
    default:                return de ? "Unbekannt"                  : "Unknown";
    }
}

/* No password check, like /system/stats/clear. The /system page is open too,
 * and this only erases diagnostic data, not user data. */
esp_err_t coredump_clear_post_handler(httpd_req_t *req)
{
    esp_err_t e = esp_core_dump_image_erase();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, e == ESP_OK ? "OK" : "Error");
    return e == ESP_OK ? ESP_OK : ESP_FAIL;
}

/* Zeroes the stability counters and the SD losses across restarts. No password
 * check, like /system/coredump/clear, because this is only diagnostic data. */
esp_err_t stats_clear_post_handler(httpd_req_t *req)
{
    sysstat_reset();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

static const char *task_state_str(eTaskState s)
{
    switch (s)
    {
    case eRunning:   return "run";
    case eReady:     return "ready";
    case eBlocked:   return "blocked";
    case eSuspended: return "susp";
    case eDeleted:   return "deleted";
    default:         return "?";
    }
}

/* Per-task CPU rows for /system and /system.json. Two snapshots 300 ms apart
 * give the current load. Unsigned deltas stay correct across a counter wrap. */
static void build_task_rows_html(char *out, size_t out_size, int *idle_x10_out)
{
    out[0] = '\0';
    size_t o = 0;
    /* Idle share in tenths of a percent, -1 until measured: a failed
     * snapshot must not read as "no idle left" and show 100 % load. */
    if (idle_x10_out) *idle_x10_out = -1;

    UBaseType_t n1 = uxTaskGetNumberOfTasks();
    if (n1 > 64) n1 = 64;
    TaskStatus_t *a1 = malloc(n1 * sizeof(TaskStatus_t));
    TaskStatus_t *a2 = malloc(n1 * sizeof(TaskStatus_t));
    if (a1 && a2)
    {
        uint32_t rt1 = 0, rt2 = 0;
        UBaseType_t c1 = uxTaskGetSystemState(a1, n1, &rt1);
        vTaskDelay(pdMS_TO_TICKS(300));
        UBaseType_t c2 = uxTaskGetSystemState(a2, n1, &rt2);
        uint32_t total_delta = rt2 - rt1;
        if (idle_x10_out) *idle_x10_out = 0;

        for (UBaseType_t i = 0; i < c2 && o < out_size; i++)
        {
            uint32_t prev = 0;
            for (UBaseType_t j = 0; j < c1; j++)
                if (a1[j].xHandle == a2[i].xHandle) { prev = a1[j].ulRunTimeCounter; break; }
            uint32_t delta = a2[i].ulRunTimeCounter - prev;
            unsigned cpu_x10 = total_delta ? (unsigned)(((uint64_t)delta * 1000) / total_delta) : 0;

            /* Every IDLE* task counts: a multi-core part has one per core. */
            if (idle_x10_out && strncmp(a2[i].pcTaskName, "IDLE", 4) == 0)
                *idle_x10_out += (int)cpu_x10;

            char nameesc[48];
            html_escape(a2[i].pcTaskName, nameesc, sizeof(nameesc));
            /* Single quotes only: this fragment is embedded unescaped in
             * /system.json, where a double quote would break the response. */
            /* The high-water mark is in bytes on this port, not in words. The 512
             * and 1024 byte limits were checked against the running tasks. */
            const char *scls = a2[i].usStackHighWaterMark < 512  ? "v-bad"
                             : a2[i].usStackHighWaterMark < 1024 ? "v-warn" : "";
            o += snprintf(out + o, out_size - o,
                "<tr><td>%s</td><td>%s</td><td>%u</td><td>%u.%u</td><td class='%s'>%u</td></tr>",
                nameesc, task_state_str(a2[i].eCurrentState),
                (unsigned)a2[i].uxCurrentPriority,
                cpu_x10 / 10, cpu_x10 % 10, scls,
                (unsigned)a2[i].usStackHighWaterMark);
        }
    }
    else
        ESP_LOGE(TAG, "task snapshot alloc failed, table stays empty");
    free(a1);
    free(a2);
}

/* Load = what the idle tasks did not take. Rendered here (not in the
 * caller) so page and JSON cannot disagree about the wording. */
static void format_cpu_load(int idle_x10, int cores, char *out, size_t out_size)
{
    if (idle_x10 < 0 || cores < 1)
    {
        snprintf(out, out_size, "&ndash;");
        return;
    }
    int busy = 1000 * cores - idle_x10;
    if (busy < 0) busy = 0;
    busy /= cores;
    /* Single quotes: cpu_str is also embedded in /system.json. */
    snprintf(out, out_size, "%d%s%d<span class='e'>%%</span>", busy / 10,
             web_lang() == LANG_DE ? "," : ".", busy % 10);
}

esp_err_t system_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* The poll URL carries the language. Without it the JSON handler falls back
     * to German, and an English page would switch to German formatting. */
    send_page_header_refresh(req, T(S_TITLE_SYSTEM),
                             web_lang() == LANG_EN ? "/system.json?lang=en"
                                                     : "/system.json?lang=de");

    /* image_check validates the SHA256, so this can't false-positive on
     * stale flash content. Reuses the generic partition download below
     * (/fs/part?label=coredump) rather than a new route. */
    if (esp_core_dump_image_check() == ESP_OK)
    {
        esp_core_dump_summary_t *sum = malloc(sizeof(esp_core_dump_summary_t));
        char detail[96] = "";
        if (sum && esp_core_dump_get_summary(sum) == ESP_OK)
            snprintf(detail, sizeof(detail), "<br><small>Task %s &middot; PC 0x%08lx</small>",
                     sum->exc_task, (unsigned long)sum->exc_pc);
        free(sum);

        char banner[640];
        snprintf(banner, sizeof(banner),
            "<div class='warn'><p>%s%s</p>"
            "<a href='/fs/part?label=coredump'>&#8595; %s</a> "
            "<button class='dngr' onclick=\"if(confirm('%s'))fetch('/system/coredump/clear',{method:'POST'}).then(()=>location.reload());\">%s</button>"
            "</div>",
            T(S_SYS_COREDUMP), detail, T(S_SYS_COREDUMP_DOWNLOAD),
            T(S_SYS_COREDUMP_CLEAR_CONFIRM), T(S_SYS_COREDUMP_CLEAR));
        httpd_resp_send_chunk(req, banner, HTTPD_RESP_USE_STRLEN);
    }

    /* The jump links come after the crash banner, which must stay first on the
     * page. The task table and the loss table below are long. */
    char sysjump[320];
    HTML_PRINTF(sysjump,
        "<p class='jump'>%s: <a href='#s-dev'>%s</a> &middot; <a href='#s-stab'>%s</a>"
        " &middot; <a href='#s-load'>%s</a> &middot; <a href='#s-loss'>%s</a></p>",
        T(S_TRF_JUMP), T(S_SYS_GRP_DEVICE), T(S_SYS_GRP_STABILITY),
        T(S_SYS_GRP_LOAD), T(S_LOSS_TITLE));
    httpd_resp_send_chunk(req, sysjump, HTTPD_RESP_USE_STRLEN);

    /* chip.revision is major*100 + minor, so 102 means v1.2. Printed that way
     * because the raw number reads like a placeholder. */
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    const esp_app_desc_t *app = esp_app_get_description();

    char feat[64] = "";
    if (chip.features & CHIP_FEATURE_WIFI_BGN) strlcat(feat, "WiFi ", sizeof(feat));
    if (chip.features & CHIP_FEATURE_BT)       strlcat(feat, "BT ", sizeof(feat));
    if (chip.features & CHIP_FEATURE_BLE)      strlcat(feat, "BLE ", sizeof(feat));
    if (chip.features & CHIP_FEATURE_EMB_PSRAM) strlcat(feat, "PSRAM ", sizeof(feat));

    uint32_t flash_sz = 0;
    esp_flash_get_size(NULL, &flash_sz);
    char flash_str[24];
    format_bytes(flash_sz, flash_str, sizeof(flash_str));

    char uptime_str[48];
    format_uptime(esp_timer_get_time() / 1000000ull, uptime_str, sizeof(uptime_str));

    /* Current IP and link speed. The IP comes from ethernet_get_status(), like
     * the "currently in effect" line on /settings. */
    ethernet_status_t eth_now;
    ethernet_get_status(&eth_now);
    char eth_line[128];
    if (eth_now.up)
    {
        eth_speed_t spd = ethernet_get_mgmt_if_link_speed();
        snprintf(eth_line, sizeof(eth_line), "%s &middot; %s",
                 eth_now.ip, spd == ETH_SPEED_100M ? "100 MBit/s" : "10 MBit/s");
    }
    else
    {
        snprintf(eth_line, sizeof(eth_line), "%s", T(S_ETH_CUR_NOT_UP));
    }

    char ri_f[24], ri_m[24], ri_t[24], rp_f[24], rp_m[24], rp_t[24];
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_INTERNAL), ri_f, sizeof(ri_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL), ri_m, sizeof(ri_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_INTERNAL), ri_t, sizeof(ri_t));
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_SPIRAM), rp_f, sizeof(rp_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM), rp_m, sizeof(rp_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_SPIRAM), rp_t, sizeof(rp_t));

    /* Device facts. All rows except the IP row change only with a reboot. The
     * firmware row shows app->idf_ver, so there is no separate ESP-IDF row. */
    char devblk[1024];
    HTML_PRINTF(devblk,
        "<div class='grp top' id='s-dev'><h2>%s</h2><table class='kv'>"
        "<tr><th>%s</th><td>%s v%d.%d, %s</td></tr>"
        "<tr><th>%s</th><td>%d</td></tr>"
        "<tr><th>%s</th><td>%d MHz</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s <small>(IDF %s &middot; %s %s)</small></td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "</table></div>",
        T(S_SYS_GRP_DEVICE),
        T(S_SYS_CHIP), CONFIG_IDF_TARGET, chip.revision / 100, chip.revision % 100, feat,
        T(S_SYS_CORES), chip.cores,
        T(S_SYS_CPU_FREQ), CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        T(S_SYS_FLASH), flash_str,
        T(S_FW_VERSION), app->version, app->idf_ver, app->date, app->time,
        T(S_SYS_RESET), reset_reason_str(esp_reset_reason()),
        T(S_ETH_IP), eth_line);
    httpd_resp_send_chunk(req, devblk, HTTPD_RESP_USE_STRLEN);

    /* Stability counters (NVS-persisted, survive crash + power loss). */
    char maxup_str[48];
    format_uptime(sysstat_max_uptime_sec(), maxup_str, sizeof(maxup_str));
    char lastcrash_str[64];
    bool crash_recent = false;
    int64_t lc = sysstat_last_crash_time();
    if (lc > 0)
    {
        struct timeval now;
        gettimeofday(&now, NULL);
        int64_t ago = now.tv_sec - lc;
        char ago_str[48];
        format_uptime(ago > 0 ? (uint64_t)ago : 0, ago_str, sizeof(ago_str));
        /* Only a crash in the last 7 days is coloured as a warning. An older one
         * is history, and the hint under this card says so. */
        crash_recent = ago > 0 && ago < 7 * 24 * 3600;
        snprintf(lastcrash_str, sizeof(lastcrash_str), "%s %s",
                 web_lang() == LANG_DE ? "vor" : "", ago_str);
    }
    else
    {
        snprintf(lastcrash_str, sizeof(lastcrash_str), "%s", T(S_STAT_NEVER));
    }

    /* The crash card's sub-line shows the boot count and the time since the last
     * crash. A crash count on its own would look incomplete. */
    uint32_t crashes = sysstat_crash_count();
    char stabblk[1152];
    HTML_PRINTF(stabblk,
        "<div class='grp' id='s-stab'><h2>%s</h2><div class='grid'>"
        "<div class='cell'><div class='l %s'>%s</div><div class='v'>%lu</div>"
        "<div class='d'>%s: %lu &middot; %s: %s</div></div>"
        "<div class='cell'><div class='l'>%s</div><div class='v'>%s</div></div>"
        "<div class='cell'><div class='l'>%s</div><div class='v' id='sys-uptime'>%s</div></div>"
        "</div><p class='note'>%s</p>",
        T(S_SYS_GRP_STABILITY),
        crash_recent ? "v-warn" : "", T(S_STAT_CRASHES), (unsigned long)crashes,
        T(S_STAT_BOOTS), (unsigned long)sysstat_boot_count(),
        T(S_STAT_LASTCRASH), lastcrash_str,
        T(S_STAT_MAXUP), maxup_str,
        T(S_UPTIME), uptime_str,
        T(S_SYS_CRASH_HINT));
    httpd_resp_send_chunk(req, stabblk, HTTPD_RESP_USE_STRLEN);

    char statsbtn[384];
    snprintf(statsbtn, sizeof(statsbtn),
        "<p class='btnrow'><button class='dngr' onclick=\"if(confirm('%s'))fetch('/system/stats/clear',{method:'POST'}).then(()=>location.reload());\">%s</button></p>",
        T(S_STAT_RESET_CONFIRM), T(S_STAT_RESET));
    httpd_resp_send_chunk(req, statsbtn, HTTPD_RESP_USE_STRLEN);
    /* Closes the stability section opened above. */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);

    /* Load group: the task table is built first because its idle share is
     * the CPU figure shown above it. */
    static EXT_RAM_BSS_ATTR char task_rows[16384];
    int idle_x10 = -1;
    build_task_rows_html(task_rows, sizeof(task_rows), &idle_x10);
    char cpu_str[48];
    format_cpu_load(idle_x10, chip.cores, cpu_str, sizeof(cpu_str));

    char loadblk[1024];
    HTML_PRINTF(loadblk,
        "<div class='grp' id='s-load'><h2>%s</h2><div class='grid'>"
        "<div class='cell'><div class='l'>%s</div><div class='v' id='sys-cpu'>%s</div></div>"
        "</div><table class='kv'>"
        "<tr><th>%s (%s)</th><td class='%s' id='sys-ram-i'>%s / %s / %s</td></tr>"
        "<tr><th>%s (%s)</th><td id='sys-ram-p'>%s / %s / %s</td></tr>"
        "</table>",
        T(S_SYS_GRP_LOAD),
        T(S_SYS_LOAD), cpu_str,
        T(S_SYS_RAM_INT), T(S_SYS_TRIPLE), ram_int_class(), ri_f, ri_m, ri_t,
        T(S_SYS_RAM_PSRAM), T(S_SYS_TRIPLE), rp_f, rp_m, rp_t);
    httpd_resp_send_chunk(req, loadblk, HTTPD_RESP_USE_STRLEN);

    char taskhdr[64];
    snprintf(taskhdr, sizeof(taskhdr), "<h3>%s</h3>", T(S_SYS_TASKS));
    httpd_resp_send_chunk(req, taskhdr, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req,
        "<div class='scroll'><table><thead><tr><th>Task</th><th>", HTTPD_RESP_USE_STRLEN);
    char hdr[192];
    snprintf(hdr, sizeof(hdr), "%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody id='sys-tasks'>",
             T(S_SYS_COL_STATE), T(S_SYS_COL_PRIO), T(S_SYS_COL_CPU), T(S_SYS_COL_STACK));
    httpd_resp_send_chunk(req, hdr, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, task_rows, HTTPD_RESP_USE_STRLEN);
    /* Last </div> closes the load section opened above. */
    httpd_resp_send_chunk(req, "</tbody></table></div></div>", HTTPD_RESP_USE_STRLEN);

    /* Recorder health: losses and SD trouble that a device can have while it
     * otherwise looks fine. */
    {
        /* Track write failures are not added. Those points stay queued for a
         * retry, so they are not lost. Only evicted and dropped points count. */
        uint32_t trk_evicted = 0, trk_dropped = 0;
        uint32_t life_lost = 0, life_flush = 0, life_unmnt = 0;
#if CONFIG_ENABLE_SD
        tracklog_losses(&trk_evicted, &trk_dropped, NULL);
        sysstat_sd_get(&life_lost, &life_flush, &life_unmnt);
#endif
        /* Shown as seconds with three decimals and a unit, so it cannot be
         * mistaken for one of the counters in the other rows. */
        uint64_t paused_ms = (uint64_t)sniffer_paused_ms();
        char paused_str[32];
        snprintf(paused_str, sizeof(paused_str), "%llu%s%03llu s",
                 (unsigned long long)(paused_ms / 1000),
                 web_lang() == LANG_DE ? "," : ".",
                 (unsigned long long)(paused_ms % 1000));
        /* 2560: the German worst case is 2084 with every counter at ten digits.
         * HTML_PRINTF only logs a truncation, so headroom is cheap. */
        char loss[2560];
        HTML_PRINTF(loss,
            "<div class='grp' id='s-loss'><h2>%s</h2><div class='scroll'><table class='kv'>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%s</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
#if CONFIG_ENABLE_SD
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu ms</td></tr>"
            "<tr><th>%s</th><td>%lu</td></tr>"
            "<tr><th>%s</th><td>%lu / %lu / %lu</td></tr>"
#endif
            "</table></div><details class='dtl'><summary>%s</summary>"
            "<p class='note'>%s</p></details></div>",
            T(S_LOSS_TITLE),
            T(S_LOSS_SNIFFER), (unsigned long)sniffer_dropped(),
            T(S_LOSS_MQTT), (unsigned long)mqtt_tx_dropped(),
            T(S_LOSS_BT_PAUSED), paused_str,
            T(S_LOSS_BT_NOTIFY), (unsigned long)bt_stream_dropped_notify(),
            T(S_LOSS_BT_QUEUE), (unsigned long)bt_stream_dropped_enqueue(),
#if CONFIG_ENABLE_SD
            T(S_LOSS_PCAP), (unsigned long)sdpcap_dropped(),
            T(S_LOSS_THINNED), (unsigned long)sdpcap_filtered(),
            T(S_LOSS_TRACKS), (unsigned long)(trk_evicted + trk_dropped),
            T(S_LOSS_PASSAGES), (unsigned long)ptlog_passages_dropped(),
            T(S_LOSS_EVENTS), (unsigned long)events_evicted(),
            T(S_LOSS_SD_FAILS), (unsigned long)sdcard_io_fail_max(),
            T(S_LOSS_SD_HELD), (unsigned long)sdcard_io_held_max_ms(),
            T(S_LOSS_FLUSHFAIL), (unsigned long)sdpcap_flush_fails(),
            T(S_LOSS_LIFETIME), (unsigned long)life_lost, (unsigned long)life_flush,
            (unsigned long)life_unmnt,
#endif
            T(S_LOSS_SUM), T(S_LOSS_HINT));
        httpd_resp_send_chunk(req, loss, HTTPD_RESP_USE_STRLEN);
    }

    /* Applies a /system.json response. Uptime and RAM are set as plain text.
     * The task rows are replaced via innerHTML, so rows can come and go. */
    /* Every lookup is guarded. A missing id would otherwise throw on the first
     * poll and skip the rest of the function, including the task table. */
    httpd_resp_send_chunk(req,
        "<script>window.arApply=function(d){"
        "var e;"
        "var ck=document.getElementById('st-clk');"
        "if(ck&&d.clk!==undefined)ck.textContent=d.clk;"
        "if((e=document.getElementById('sys-uptime')))e.textContent=d.uptime;"
        "if((e=document.getElementById('sys-cpu'))&&d.cpu!==undefined)e.innerHTML=d.cpu;"
        "if((e=document.getElementById('sys-ram-i'))){e.textContent=d.ram_i;"
        "if(d.ram_icl!==undefined)e.className=d.ram_icl;}"
        "if((e=document.getElementById('sys-ram-p')))e.textContent=d.ram_p;"
        "if((e=document.getElementById('sys-tasks')))e.innerHTML=d.tasks_html;"
        "};</script>", HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* GET /system.json: uptime, CPU load, RAM, tasks and the clock line for the
 * poll script from send_page_header_refresh(). Chip info, reset reason and
 * the coredump banner change only with a reboot and are not polled. */
esp_err_t system_json_get_handler(httpd_req_t *req)
{
    resolve_language(req);

    char uptime_str[48];
    format_uptime(esp_timer_get_time() / 1000000ull, uptime_str, sizeof(uptime_str));

    char ri_f[24], ri_m[24], ri_t[24], rp_f[24], rp_m[24], rp_t[24];
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_INTERNAL), ri_f, sizeof(ri_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL), ri_m, sizeof(ri_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_INTERNAL), ri_t, sizeof(ri_t));
    format_bytes(heap_caps_get_free_size(MALLOC_CAP_SPIRAM), rp_f, sizeof(rp_f));
    format_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM), rp_m, sizeof(rp_m));
    format_bytes(heap_caps_get_total_size(MALLOC_CAP_SPIRAM), rp_t, sizeof(rp_t));

    static EXT_RAM_BSS_ATTR char task_rows[16384];
    int idle_x10 = -1;
    build_task_rows_html(task_rows, sizeof(task_rows), &idle_x10);
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    char cpu_str[48];
    format_cpu_load(idle_x10, chip.cores, cpu_str, sizeof(cpu_str));

    char clkj[80];
    format_clockline(clkj, sizeof(clkj), "\u00b7");

    static EXT_RAM_BSS_ATTR char json[17408];
    snprintf(json, sizeof(json),
        "{\"uptime\":\"%s\",\"cpu\":\"%s\",\"ram_i\":\"%s / %s / %s\",\"ram_icl\":\"%s\","
        /* clk holds a literal UTF-8 middle dot, not an entity. arApply() writes
         * it with textContent, which would show an entity as plain text. */
        "\"ram_p\":\"%s / %s / %s\",\"clk\":\"%s\",\"tasks_html\":\"%s\"}",
        uptime_str, cpu_str, ri_f, ri_m, ri_t, ram_int_class(),
        rp_f, rp_m, rp_t, clkj, task_rows);
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

