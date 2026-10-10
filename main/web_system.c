#include "web_system.h"

#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

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
#include "its_castore.h"
#include "its_certcache.h"
#include "its_crl.h"
#include "its_msgsig.h"
#include "its_verify.h"
#include "mqtt.h"
#include "msg_extra.h"
#include "ptlog.h"
#include "sdpcap.h"
#include "cmd_sniffer.h"
#include "tracklog.h"
#include "sdcard.h"
#include "settings_apply.h"
#include "sysmon.h"
#include "sysstat.h"
#include "web_faults.h"
#include "web_fmt.h"
#include "web_msgdetail.h"
#include "web_msgsig.h"
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

/* The words come from the text table (S_RST_*), so both languages have them. */
static const char *reset_reason_str(esp_reset_reason_t r)
{
    switch (r)
    {
    case ESP_RST_POWERON:    return T(S_RST_POWERON);
    case ESP_RST_EXT:        return T(S_RST_EXT);
    case ESP_RST_SW:         return T(S_RST_SW);
    case ESP_RST_PANIC:      return T(S_RST_PANIC);
    case ESP_RST_INT_WDT:    return T(S_RST_INT_WDT);
    case ESP_RST_TASK_WDT:   return T(S_RST_TASK_WDT);
    case ESP_RST_WDT:        return T(S_RST_WDT);
    case ESP_RST_DEEPSLEEP:  return T(S_RST_DEEPSLEEP);
    case ESP_RST_BROWNOUT:   return T(S_RST_BROWNOUT);
    case ESP_RST_SDIO:       return T(S_RST_SDIO);
    case ESP_RST_USB:        return T(S_RST_USB);
    case ESP_RST_JTAG:       return T(S_RST_JTAG);
    case ESP_RST_EFUSE:      return T(S_RST_EFUSE);
    case ESP_RST_PWR_GLITCH: return T(S_RST_PWR_GLITCH);
    case ESP_RST_CPU_LOCKUP: return T(S_RST_CPU_LOCKUP);
    default:                 return T(S_UNKNOWN);
    }
}

const char *web_reset_reason(void) { return reset_reason_str(esp_reset_reason()); }

/* One rule for the crash cell on / and /system: amber for a crash in the last 7 days or right
 * before this boot, red while the bar shows it (web_faults_crash_cls). The age of a boot crash
 * is the uptime, so it needs no clock. */
bool web_crash_summary(char *ago, size_t cap)
{
    uint64_t sec;
    /* Its time is stored only once sysstat_tick sees a set clock. After a counter reset the
     * stored side answers, like the crash count beside this cell. */
    if (sysstat_boot_was_crash() && sysstat_crash_count() > 0)
    {
        sec = (uint64_t)esp_timer_get_time() / 1000000ull;
    }
    else
    {
        int64_t lc = sysstat_last_crash_time();
        if (lc <= 0)
        {
            snprintf(ago, cap, "%s", T(S_STAT_NEVER));
            return false;
        }
        int64_t now = (int64_t)time(NULL);
        /* Without a clock the age is unknown; "vor 0 s" would be a false claim. */
        if (!web_clock_set((uint32_t)now))
        {
            snprintf(ago, cap, "%s", T(S_CLOCK_UNSET));
            return false;
        }
        /* A crash stamped after now (the clock went back) reads as 0 s and stays uncoloured. */
        sec = now > lc ? (uint64_t)(now - lc) : 0;
    }
    /* "vor 3 d 4 h" / "3 d 4 h ago", 20 bytes at most. An age past 136 years stays at the
     * uint32_t end. */
    fmt_age(sec > UINT32_MAX ? UINT32_MAX : (uint32_t)sec, FMT_DUR_TWO, web_lang(), ago, cap);
    /* Only a crash in the last 7 days is coloured as a warning. An older one
     * is history, and the hint under this card says so. */
    return sec > 0 && sec < 7 * 24 * 3600;
}

/* Read once at start: the dump only changes with a crash, which restarts the device, or with
 * the delete button. The page head may then ask without touching the flash. */
static bool s_coredump;
/* The delete button was used this boot: the fault bar then drops a crash before this boot. */
static bool s_coredump_cleared;

void web_coredump_scan(void)
{
    /* image_check validates the SHA256, so stale flash content does not count. */
    s_coredump = esp_core_dump_image_check() == ESP_OK;
}

bool web_coredump_present(void) { return s_coredump; }

bool web_coredump_cleared(void) { return s_coredump_cleared; }

/* No password check, like /system/stats/clear. The /system page is open too,
 * and this only erases diagnostic data, not user data. */
esp_err_t coredump_clear_post_handler(httpd_req_t *req)
{
    esp_err_t e = esp_core_dump_image_erase();
    /* The only caller of the erase, so the flag cannot go stale another way. */
    if (e == ESP_OK)
    {
        s_coredump = false;
        s_coredump_cleared = true;
    }
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

bool web_autoip_active(void)
{
    ethernet_status_t st;
    ethernet_get_status(&st);
    if (!st.up || strncmp(st.ip, "169.254.", 8) != 0)
        return false;
    /* A static address in that range was chosen on purpose. */
    char dhcp[2];
    set_read(SET_DHCP, dhcp, sizeof(dhcp));
    return dhcp[0] == '1';
}

void web_autoip_note(char *out, size_t cap, bool hidden, const char *id)
{
    char nodeid[CONFIG_NODEID_BUFFER_SIZE];
    set_read(SET_NODEID, nodeid, sizeof(nodeid));
    char host[8 + CONFIG_NODEID_BUFFER_SIZE];
    size_t h = sysmon_mdns_hostname(nodeid, host, sizeof(host));

    /* Without a node ID sysmon.c registers no name, and a DNS label ends at 63 characters. */
    char reach[256] = "";
    if (nodeid[0] && h <= 63)
        snprintf(reach, sizeof(reach), " %s <a href='http://%s.local/'>%s.local</a>.",
                 T(S_AUTOIP_HOST), host, host);
    /* No sign in the text: s.css sets it before the first <p> of every box. */
    snprintf(out, cap, "<div class='warn'%s%s%s%s><p>%s%s %s</p></div>",
             id ? " id='" : "", id ? id : "", id ? "'" : "", hidden ? " hidden" : "",
             T(S_AUTOIP), reach, T(S_AUTOIP_HINT));
}

int web_warn_active(void)
{
#if CONFIG_ENABLE_SD
    uint32_t now = (uint32_t)time(NULL);
    if (now < EVENTS_CLOCK_MIN)
        return WEB_WARN_NOCLOCK;
    static EXT_RAM_BSS_ATTR event_rec_t cur[EVENTS_CURRENT_MAX];
    int n = events_current(cur, EVENTS_CURRENT_MAX, NULL);
    if (n < 0)
        return WEB_WARN_UNKNOWN;
    int active = 0;
    for (int i = 0; i < n; i++)
        active += events_state(&cur[i], now) == EVENT_STATE_ACTIVE;
    return active;
#else
    return WEB_WARN_UNKNOWN;
#endif
}

void web_status_extra_json(char *out, size_t cap)
{
    sniffer_rx_quality_t q;
    sniffer_get_rx_quality(&q);
    /* null without a frame in the last minute, as in /system.json. */
    char nf[12] = "null";
    if (q.nf_frames)
        snprintf(nf, sizeof(nf), "%d", q.nf_avg);

    /* null without SD support, without a set clock, or while the warning lock is busy. */
    char warn[12] = "null";
    int wa = web_warn_active();
    if (wa >= 0)
        snprintf(warn, sizeof(warn), "%d", wa);
    snprintf(out, cap, ",\"eth_autoip\":%s,\"rx_nf_avg\":%s,\"rx_broken\":%lu,\"warn_active\":%s",
             web_autoip_active() ? "true" : "false", nf, (unsigned long)q.broken, warn);
}

/* The certificate cache as the detail line of its cell, for the page and /system.json. */
static void format_certcache(const its_certcache_stats_t *s, char *out, size_t cap)
{
    uint64_t total = (uint64_t)s->digests_known + s->digests_missing;
    if (!total)
    {
        snprintf(out, cap, "%s &middot; %s", T(S_CERTCACHE_NONE), T(S_SINCE_BOOT));
        return;
    }
    /* Rounded down, so a single unknown certificate never shows as 100 %. */
    snprintf(out, cap, "%s: %u&nbsp;%% (%lu/%llu) &middot; %s", T(S_CERTCACHE_SHARE),
             (unsigned)(s->digests_known * 100ull / total), (unsigned long)s->digests_known,
             (unsigned long long)total, T(S_SINCE_BOOT));
}

/* Checks made since power-on. One check lands in exactly one of these four states, while the
 * expired count is a part of the invalid ones and must not be added again. */
static uint64_t trust_checks(const its_verify_stats_t *v)
{
    return (uint64_t)v->checked + v->unavailable + v->invalid + v->revoked;
}

/* The authority certificates compiled into the firmware, as a note under the certificate
 * group. A sender whose authority never sends its own certificate can only be checked from
 * this store, so its size and its day belong on the page. The label is the heading of the
 * table on /trust and links there. */
static void format_castore(char *out, size_t cap)
{
    char day[WEB_DAY_MAX];
    const char *lc = web_lang() == LANG_EN ? "en" : "de";
    size_t n = its_castore_count();
    if (!n)
    {
        snprintf(out, cap, "%s", T(S_CASTORE_NONE));
        return;
    }
    web_day_str(its_castore_fetched(), web_lang(), day, sizeof(day));
    const char *unit = n == 1 ? T(S_CASTORE_CERT) : T(S_CASTORE_CERTS);
    /* A store without a day says nothing about how old it is, so the words stop earlier. */
    if (!day[0])
    {
        snprintf(out, cap, "<a href='/trust?lang=%s#t-ca'>%s</a>: %lu %s", lc, T(S_TRUST_H_CAS),
                 (unsigned long)n, unit);
        return;
    }
    snprintf(out, cap, "<a href='/trust?lang=%s#t-ca'>%s</a>: %lu %s &middot; %s %s", lc,
             T(S_TRUST_H_CAS), (unsigned long)n, unit, T(S_TRUSTLIST_DATE), day);
}

/* What the built-in revocation lists cover, as a note under the certificate group. Without a
 * list the device checks nothing, and then this says exactly that: a line that claimed a
 * check nobody made would be worse than no line at all. The label is the heading of the
 * table on /trust and links there. Returns true when lists are built in and dated: only then
 * does S_CRL_GAP apply. */
static bool format_crl(uint32_t now, char *out, size_t cap)
{
    char day[WEB_DAY_MAX], newest[WEB_DAY_MAX], due[WEB_DAY_MAX];
    int k;
    web_day_str(its_crl_oldest_update(), web_lang(), day, sizeof(day));
    web_day_str(its_crl_newest_update(), web_lang(), newest, sizeof(newest));
    /* A list nobody can date must not be dated, so the sentence without a date takes over. */
    if (!its_crl_lists() || !day[0])
    {
        snprintf(out, cap, "%s", T(S_CRL_NONE));
        return false;
    }
    /* Both ends of the span. Naming only the oldest would let one list abandoned years ago
     * speak for the lists renewed this year, and what a list knows ends at its own date,
     * not at the day the firmware was built. */
    k = snprintf(out, cap, "<a href='/trust?lang=%s#t-crl'>%s</a>: %lu &middot; %s %s",
                 web_lang() == LANG_EN ? "en" : "de", T(S_TRUST_H_CRLS),
                 (unsigned long)its_crl_lists(), T(S_TRUSTLIST_DATE), day);
    if (k < 0 || (size_t)k >= cap)
        return true;
    /* One list, or a set that shares one day: then the second date would say nothing. */
    if (newest[0] && strcmp(day, newest) != 0)
    {
        int n = snprintf(out + k, cap - (size_t)k, " %s %s", T(S_CRL_TO), newest);
        if (n < 0 || (size_t)n >= cap - (size_t)k)
            return true;
        k += n;
    }
    {
        int n = snprintf(out + k, cap - (size_t)k, " &middot; %lu %s",
                         (unsigned long)its_crl_count(), T(S_CRL_ENTRIES));
        if (n < 0 || (size_t)n >= cap - (size_t)k)
            return true;
        k += n;
    }
    /* An unset clock cannot tell a stale list from a fresh one, so it stays quiet. */
    if (!web_clock_set(now))
        return true;
    /* Count them: one list of a PKI that shut down years ago would otherwise put the whole
     * set in the past, because the renewal date below is the earliest of all lists. */
    unsigned long late = (unsigned long)its_crl_overdue(web_unix_to_time32(now));
    if (!late)
        return true;
    web_day_str(its_crl_next_update(), web_lang(), due, sizeof(due));
    /* Information, not a warning: only a newer firmware brings new lists, so a sign here
     * could never be cleared. It gets its own line, because the count of late lists is news
     * and the figures before it are not. */
    snprintf(out + k, cap - (size_t)k, "<br>%lu %s %lu %s %s &ndash; %s", late, T(S_CRL_OF),
             (unsigned long)its_crl_lists(), T(S_CRL_OVERDUE), due, T(S_CRL_NEWFW));
    return true;
}

/* Radio reception as HTML, one function for the page and /system.json. Single
 * quotes only: the JSON embeds these fragments unescaped. */
typedef struct {
    char nf_v[96];     /* average noise floor, or a dash: 37 measured */
    char nf_d[192];    /* min and max with the frame count, or why there is none: 67 */
    char bad_d[192];   /* since power-on, with the average per minute: 89 */
} rx_html_t;

static void format_rx(const sniffer_rx_quality_t *q, rx_html_t *o)
{
    /* The last minute still counts right after the sniffer stopped. */
    if (q->nf_frames)
    {
        /* The plain hyphen-minus, like the levels on /messages, /senders and /traffic. */
        snprintf(o->nf_v, sizeof(o->nf_v), "%d<span class='e'>dBm</span>", q->nf_avg);
        snprintf(o->nf_d, sizeof(o->nf_d), "min %d &middot; max %d &middot; %lu Frames",
                 q->nf_min, q->nf_max, (unsigned long)q->nf_frames);
    }
    else
    {
        snprintf(o->nf_v, sizeof(o->nf_v), "&ndash;");
        snprintf(o->nf_d, sizeof(o->nf_d), "%s",
                 sniffer_get_channel() ? T(S_RX_NONE) : T(S_RX_OFF));
    }

    /* The average per minute appears once a whole minute has passed, rounded to one decimal.
     * Divided by seconds: whole minutes cut 1m59s down to 1 and doubled the figure. */
    uint64_t sec = (uint64_t)esp_timer_get_time() / 1000000ull;
    if (sec < 60)
    {
        snprintf(o->bad_d, sizeof(o->bad_d), "%s", T(S_SINCE_BOOT));
        return;
    }
    /* broken * 60 * 10 / sec, rounded half up. sec is at least 60 here. */
    uint64_t x10 = ((uint64_t)q->broken * 600 + sec / 2) / sec;
    /* A value takes the unit symbol. Only running text writes the unit out. */
    snprintf(o->bad_d, sizeof(o->bad_d), "%s &middot; &oslash; %llu%s%llu/min", T(S_SINCE_BOOT),
             (unsigned long long)(x10 / 10), web_lang() == LANG_DE ? "," : ".",
             (unsigned long long)(x10 % 10));
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
            /* The decimal mark follows the language, like format_cpu_load below. A comma
             * is safe in the JSON string of /system.json, which carries these rows. */
            o = (size_t)web_addf(out, out_size, (int)o,
                "<tr><td>%s</td><td>%s</td><td>%u</td><td>%u%s%u</td><td class='%s'>%u</td></tr>",
                nameesc, task_state_str(a2[i].eCurrentState),
                (unsigned)a2[i].uxCurrentPriority,
                cpu_x10 / 10, web_lang() == LANG_DE ? "," : ".", cpu_x10 % 10, scls,
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

/* The BLE pause goes through fmt_us like every short span (ms, then "9,3 s"). The unit sets
 * it apart from the counters of the loss rows. One function for the page and /system.json. */
static void format_paused(uint64_t ms, char *out, size_t cap)
{
    fmt_us(ms * 1000u, web_lang(), out, cap);
}

/* The compiler stamp ('Sep  5 2026', '00:31:07') in the shape of fmt_when. It is the build
 * machine's local time, not the device zone, so it carries no zone letters. */
static void build_stamp(const char *date, const char *tim, char *out, size_t cap)
{
    static const char MON[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    char m[4] = "";
    unsigned d = 0, y = 0, hh = 0, mm = 0;
    const char *p = NULL;
    if (sscanf(date, "%3s %u %u", m, &d, &y) == 3 && strlen(m) == 3 &&
        sscanf(tim, "%u:%u", &hh, &mm) == 2)
        p = strstr(MON, m);
    /* Anything else prints as the compiler wrote it. */
    if (!p || (p - MON) % 3 || d < 1 || d > 31 || y < 2000 || y > 9999 || hh > 23 || mm > 59)
    {
        snprintf(out, cap, "%s %s", date, tim);
        return;
    }
    unsigned mon = (unsigned)(p - MON) / 3 + 1;
    if (web_lang() == LANG_EN)
        snprintf(out, cap, "%04u-%02u-%02u %02u:%02u", y, mon, d, hh, mm);
    else
        snprintf(out, cap, "%02u.%02u.%04u %02u:%02u", d, mon, y, hh, mm);
}

/* A real loss above 0 takes the warning colour and its dot (s.css level 2). arApply below
 * applies the same rule, so the colour follows the poll. */
static const char *loss_cls(unsigned long v)
{
    return v ? " class='v-warn'" : "";
}

esp_err_t system_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* The poll URL carries the language. Without it the JSON handler falls back
     * to German, and an English page would switch to German formatting. */
    send_page_header_refresh(req, T(S_TITLE_SYSTEM),
                             web_lang() == LANG_EN ? "/system.json?lang=en"
                                                     : "/system.json?lang=de");

    /* Reuses the generic partition download below (/fs/part?label=coredump)
     * rather than a new route. */
    if (web_coredump_present())
    {
        esp_core_dump_summary_t *sum = malloc(sizeof(esp_core_dump_summary_t));
        char detail[96] = "";
        if (sum && esp_core_dump_get_summary(sum) == ESP_OK)
            snprintf(detail, sizeof(detail), "<br><small>Task %s &middot; PC 0x%08lx</small>",
                     sum->exc_task, (unsigned long)sum->exc_pc);
        free(sum);

        /* 1024 against 738 measured (German, SD build); HTML_PRINTF because a cut
         * onclick would silently kill the delete button. Alarm level: broken now (s.css). */
        static EXT_RAM_BSS_ATTR char banner[1024];
        HTML_PRINTF(banner,
            "<div class='alarm'><p>%s%s</p>"
            /* webserver.c registers /fs/part only with SD support, so without it the link
             * would answer 404. The warning itself belongs on the page either way. */
#if CONFIG_ENABLE_SD
            /* The hint says what the file is for: without it most people delete it. */
            "<p>%s</p>"
            "<a class='dlb' href='/fs/part?label=coredump'>&#8595; %s</a> "
#endif
            "<button class='dngr' onclick=\"if(confirm('%s'))"
            /* ?lang=: a bare POST would answer a 403 in German on an English page. */
            "fetch('/system/coredump/clear?lang='+document.documentElement.lang,{method:'POST'})"
            ".then(function(r){"
            "if(r.status==403)return r.text().then(alert);location.reload();});\">%s</button>"
            "</div>",
            T(S_SYS_COREDUMP), detail,
#if CONFIG_ENABLE_SD
            T(S_SYS_COREDUMP_HINT), T(S_SYS_COREDUMP_DOWNLOAD),
#endif
            T(S_SYS_COREDUMP_CLEAR_CONFIRM), T(S_SYS_COREDUMP_CLEAR));
        httpd_resp_send_chunk(req, banner, HTTPD_RESP_USE_STRLEN);
    }

    /* Rendered hidden when not needed, because a DHCP server can still answer
     * later and the poll then hides or shows it. 768 against 441 (reach at its 255). */
    static EXT_RAM_BSS_ATTR char autoip[768];
    web_autoip_note(autoip, sizeof(autoip), !web_autoip_active(), "sys-autoip");
    httpd_resp_send_chunk(req, autoip, HTTPD_RESP_USE_STRLEN);

    /* The jump links come after the crash banner, which must stay first on the
     * page. The task table and the loss table below are long. 384 against 301 measured. */
    char sysjump[384];
    HTML_PRINTF(sysjump,
        "<p class='jump'>%s: <a href='#s-dev'>%s</a> &middot; <a href='#s-stab'>%s</a>"
        " &middot; <a href='#s-load'>%s</a> &middot; <a href='#s-rx'>%s</a>"
        " &middot; <a href='#s-cert'>%s</a> &middot; <a href='#s-loss'>%s</a></p>",
        T(S_TRF_JUMP), T(S_SYS_GRP_CHIP), T(S_SYS_GRP_STABILITY),
        T(S_SYS_GRP_LOAD), T(S_SYS_GRP_RX), T(S_SYS_GRP_CERT), T(S_LOSS_TITLE));
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
    fmt_bytes(flash_sz, web_lang(), flash_str, sizeof(flash_str));

    uint64_t up = (uint64_t)esp_timer_get_time() / 1000000ull;
    char uptime_str[FMT_DUR_MAX];
    fmt_dur(up > UINT32_MAX ? UINT32_MAX : (uint32_t)up, FMT_DUR_TWO, uptime_str,
            sizeof(uptime_str));

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
    fmt_bytes(heap_caps_get_free_size(MALLOC_CAP_INTERNAL), web_lang(), ri_f, sizeof(ri_f));
    fmt_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL), web_lang(), ri_m, sizeof(ri_m));
    fmt_bytes(heap_caps_get_total_size(MALLOC_CAP_INTERNAL), web_lang(), ri_t, sizeof(ri_t));
    fmt_bytes(heap_caps_get_free_size(MALLOC_CAP_SPIRAM), web_lang(), rp_f, sizeof(rp_f));
    fmt_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM), web_lang(), rp_m, sizeof(rp_m));
    fmt_bytes(heap_caps_get_total_size(MALLOC_CAP_SPIRAM), web_lang(), rp_t, sizeof(rp_t));

    /* 32 against 31: the raw date and time of esp_app_desc_t (15 each) on a parse failure. */
    char stamp[32];
    build_stamp(app->date, app->time, stamp, sizeof(stamp));
    /* Chip and firmware facts. All rows but the IP and clock rows change only with a reboot.
     * The firmware row shows app->idf_ver, so there is no ESP-IDF row. 1024 against 766
     * measured (every field at its size, each text in its longer language). Not named
     * "Geraet": the start page keeps that word for its own summary group. */
    char devblk[1024];
    HTML_PRINTF(devblk,
        "<div class='grp top' id='s-dev'><h2>%s</h2><table class='kv'>"
        "<tr><th>%s</th><td>%s v%d.%d, %s</td></tr>"
        "<tr><th>%s</th><td>%d</td></tr>"
        "<tr><th>%s</th><td>%d MHz</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s <small>(IDF %s &middot; %s)</small></td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>"
        "<tr><th>%s</th><td>%s</td></tr>",
        T(S_SYS_GRP_CHIP),
        T(S_SYS_CHIP), CONFIG_IDF_TARGET, chip.revision / 100, chip.revision % 100, feat,
        T(S_SYS_CORES), chip.cores,
        T(S_SYS_CPU_FREQ), CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ,
        T(S_SYS_FLASH), flash_str,
        T(S_FW_VERSION), app->version, app->idf_ver, stamp,
        T(S_SYS_RESET), web_reset_reason(),
        T(S_ETH_IP), eth_line);
    httpd_resp_send_chunk(req, devblk, HTTPD_RESP_USE_STRLEN);

    /* Own chunk: the NTP server name is user text and escapes to 378 bytes. cst 640 against
     * 613 with the zone label, clkrow 1024 against 687 with cst at its 639 (measured). */
    static EXT_RAM_BSS_ATTR char cst[640];
    static EXT_RAM_BSS_ATTR char clkrow[1024];
    web_clock_state(cst, sizeof(cst), true);
    HTML_PRINTF(clkrow, "<tr><th>%s</th><td>%s</td></tr></table></div>", T(S_CLOCK), cst);
    httpd_resp_send_chunk(req, clkrow, HTTPD_RESP_USE_STRLEN);

    /* Stability counters (NVS-persisted, survive crash + power loss). */
    char maxup_str[FMT_DUR_MAX];
    fmt_dur(sysstat_max_uptime_sec(), FMT_DUR_TWO, maxup_str, sizeof(maxup_str));
    /* 64 against 20: fmt_age, or one word of the table. */
    char lastcrash_str[64];
    bool crash_recent = web_crash_summary(lastcrash_str, sizeof(lastcrash_str));

    /* The crash card's sub-line shows the boot count and the time since the last
     * crash. A crash count on its own would look incomplete. */
    uint32_t crashes = sysstat_crash_count();
    /* 1152 against 754 measured. All three cells are wide: a half tile would break
     * "12 d 3 h" mid-word, and the crash line needs the room. */
    char stabblk[1152];
    HTML_PRINTF(stabblk,
        "<div class='grp' id='s-stab'><h2>%s</h2><div class='grid'>"
        "<div class='cell wide'><div class='l %s'>%s</div><div class='v'>%lu</div>"
        "<div class='d'>%s: %lu &middot; %s: %s</div></div>"
        "<div class='cell wide'><div class='l'>%s</div><div class='v'>%s</div></div>"
        "<div class='cell wide'><div class='l'>%s</div><div class='v' id='sys-uptime'>%s</div></div>"
        "</div><p class='note hlp'>%s</p>",
        T(S_SYS_GRP_STABILITY),
        web_faults_crash_cls(crash_recent), T(S_STAT_CRASHES), (unsigned long)crashes,
        T(S_STAT_BOOTS), (unsigned long)sysstat_boot_count(),
        T(S_STAT_LASTCRASH), lastcrash_str,
        T(S_STAT_MAXUP), maxup_str,
        T(S_UPTIME), uptime_str,
        T(S_SYS_CRASH_HINT));
    httpd_resp_send_chunk(req, stabblk, HTTPD_RESP_USE_STRLEN);

    /* 384 against 373 measured (German). */
    char statsbtn[384];
    snprintf(statsbtn, sizeof(statsbtn),
        "<p class='btnrow'><button class='dngr' onclick=\"if(confirm('%s'))"
        /* ?lang=: a bare POST would answer a 403 in German on an English page. */
        "fetch('/system/stats/clear?lang='+document.documentElement.lang,{method:'POST'})"
        ".then(function(r){"
        "if(r.status==403)return r.text().then(alert);location.reload();});\">%s</button></p>",
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

    /* 1024 against 554, the six sizes counted at their 23 (fmt_bytes writes 13 at most). */
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
    /* 192 against 108. */
    char hdr[192];
    snprintf(hdr, sizeof(hdr), "%s</th><th>%s</th><th>%s</th><th>%s</th></tr></thead><tbody id='sys-tasks'>",
             T(S_SYS_COL_STATE), T(S_SYS_COL_PRIO), T(S_SYS_COL_CPU), T(S_SYS_COL_STACK));
    httpd_resp_send_chunk(req, hdr, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, task_rows, HTTPD_RESP_USE_STRLEN);
    /* Last </div> closes the load section opened above. */
    httpd_resp_send_chunk(req, "</tbody></table></div></div>", HTTPD_RESP_USE_STRLEN);

    /* Radio reception has its own group. A noisy channel or a broken frame is
     * nothing the firmware lost, so it does not belong under losses. */
    {
        sniffer_rx_quality_t q;
        sniffer_get_rx_quality(&q);
        static EXT_RAM_BSS_ATTR rx_html_t rx;
        format_rx(&q, &rx);
        /* 2048: the German worst case is 1335 with every runtime string full (nf_v 95, the
         * two detail lines 382). The fixed sub-line has no id, so the poll never replaces it. */
        static EXT_RAM_BSS_ATTR char rxblk[2048];
        HTML_PRINTF(rxblk,
            "<div class='grp' id='s-rx'><h2>%s</h2><div class='grid'>"
            "<div class='cell'><div class='l'>%s</div><div class='v' id='sys-nf'>%s</div>"
            "<div class='d' id='sys-nf-d'>%s</div></div>"
            "<div class='cell'><div class='l'>%s</div><div class='v' id='sys-bad'>%lu</div>"
            "<div class='d'>%s</div><div class='d' id='sys-bad-d'>%s</div></div>"
            "</div><p class='note hlp'>%s</p></div>",
            T(S_SYS_GRP_RX), T(S_RX_NOISE), rx.nf_v, rx.nf_d,
            T(S_RX_BROKEN), (unsigned long)q.broken, T(S_RX_BROKEN_SUB), rx.bad_d, T(S_RX_HINT));
        httpd_resp_send_chunk(req, rxblk, HTTPD_RESP_USE_STRLEN);
    }

    /* The certificates and what the chain check made of them. The second cell counts checks
     * and not certificates: a newly learned issuer sends waiting certificates through again.
     * The third cell counts the service answers, one per signed envelope, and the fourth the
     * content answers, one per allowed service. Neither is mixed into the chain. The notes below
     * name what the firmware itself brings along: roots, authority certificates and
     * revocation lists, each with the day it is from. */
    {
        its_certcache_stats_t cs;
        its_certcache_stats(&cs);
        its_verify_stats_t vs;
        its_verify_stats(&vs);
        msg_perm_stats_t ps;
        msg_extra_perm_stats(&ps);
        its_msgsig_stats_t ms;
        its_msgsig_stats(&ms);
        /* The /trust links carry the language; without ?lang= it would follow the browser,
         * not this page. */
        const char *lcode = web_lang() == LANG_EN ? "en" : "de";
        /* permd and permcd: the service line and the content line, every counter at its widest:
         * 134 and 175 of 256 (DE). */
        static EXT_RAM_BSS_ATTR char certd[256], trustd[512], permd[256], permcd[256], lists[384];
        /* msigd: the counter line with both curves, every counter and time at its widest: 370 of
         * 512 (DE). */
        static EXT_RAM_BSS_ATTR char msigd[512];
        /* store: 111 of 160; crl: 512, S_CRL_NONE with its /update link is 400 (German); with
         * lists, every counter at ten digits and the overdue line, 289. */
        static EXT_RAM_BSS_ATTR char store[160], crl[512];
        /* The limit of the lists as a help paragraph under their line, the same whatever the
         * counts: 136 of 192 (German). */
        static EXT_RAM_BSS_ATTR char crlgap[192];
        /* Last paragraph inside the folded box, and only when something is built in:
         * without a single certificate it would explain what this build does not have.
         * 560: measured 506 -- the German text at 482 bytes, the paragraph around it 24. */
        static EXT_RAM_BSS_ATTR char storenote[560];
        format_certcache(&cs, certd, sizeof(certd));
        web_msgdetail_trust_counts(&vs, web_lang(), trustd, sizeof(trustd));
        web_msgdetail_perm_counts(&ps, web_lang(), permd, sizeof(permd));
        web_msgdetail_perm_cont_counts(&ps, web_lang(), permcd, sizeof(permcd));
        web_msgsig_counts(&ms, web_lang(), msigd, sizeof(msigd));
        web_msgdetail_trustlists(web_lang(), lists, sizeof(lists));
        format_castore(store, sizeof(store));
        storenote[0] = '\0';
        if (its_castore_count())
            snprintf(storenote, sizeof(storenote), "<p class='note hlp'>%s</p>", T(S_CASTORE_HINT));
        crlgap[0] = '\0';
        if (format_crl((uint32_t)time(NULL), crl, sizeof(crl)))
            HTML_PRINTF(crlgap, "<p class='note hlp'>%s</p>", T(S_CRL_GAP));
        uint64_t checks = trust_checks(&vs);
        uint64_t perms = (uint64_t)ps.ok + ps.bad + ps.unknown;
        /* Messages whose signature was really computed: the cell counts those, its line the
         * rest. */
        uint64_t msigs = (uint64_t)ms.ok + ms.bad;
        /* 8192: the worst case is 7610 bytes (6915 before the content tile and the longer notes),
         * the buffers counted at their sizes, the /trust links included. The five tiles have
         * long detail lines, so they take the full width on a phone. */
        static EXT_RAM_BSS_ATTR char certblk[8192];
        HTML_PRINTF(certblk,
            "<div class='grp' id='s-cert'><h2>%s</h2><div class='grid'>"
            "<div class='cell wide'><div class='l'><a href='/trust?lang=%s#t-seen'>%s</a></div><div class='v' id='sys-cert'>%lu</div>"
            "<div class='d' id='sys-cert-d'>%s</div></div>"
            "<div class='cell wide'><div class='l'><a href='/trust?lang=%s#t-seen'>%s</a></div><div class='v' id='sys-trust'>%llu</div>"
            "<div class='d' id='sys-trust-d'>%s</div></div>"
            "<div class='cell wide'><div class='l'>%s</div><div class='v' id='sys-perm'>%llu</div>"
            "<div class='d' id='sys-perm-d'>%s</div></div>"
            "<div class='cell wide'><div class='l'>%s</div><div class='v' id='sys-permc'>%lu</div>"
            "<div class='d' id='sys-permc-d'>%s</div></div>"
            "<div class='cell wide'><div class='l'><a href='/trust?lang=%s#t-msig'>%s</a></div>"
            "<div class='v' id='sys-msig'>%llu</div>"
            "<div class='d' id='sys-msig-d'>%s</div></div>"
            "</div><p class='note'>%s</p><p class='note'>%s</p><p class='note'>%s</p>%s"
            "<details class='dtl'><summary>%s</summary>"
            "<p class='note'>%s</p><p class='note'>%s</p><p class='note'>%s</p>"
            "<p class='note'>%s</p><p class='note'>%s</p><p class='note'>%s</p>%s</details></div>",
            T(S_SYS_GRP_CERT),
            lcode, T(S_TRUST_H_SEEN), (unsigned long)cs.entries, certd,
            lcode, T(S_TRUST_CHECKS), (unsigned long long)checks, trustd,
            T(S_PERM_TITLE), (unsigned long long)perms, permd,
            T(S_PERM_CONT_TITLE), (unsigned long)ps.ok, permcd,
            lcode, T(S_MSIG_TITLE), (unsigned long long)msigs, msigd,
            /* What the firmware carries stays visible, because those are numbers and dates
             * the reader came for. The six explanations fold away behind one line: they
             * answer a question nobody has on every visit. */
            lists, store, crl, crlgap,
            T(S_CERT_SUM),
            T(S_CERTCACHE_HINT), T(S_TRUST_MEANS), T(S_PERM_HINT), T(S_PERM_HINT2),
            T(S_MSIG_HINT), T(S_MSIG_HINT2),
            storenote);
        httpd_resp_send_chunk(req, certblk, HTTPD_RESP_USE_STRLEN);
    }

    /* Recorder health: losses and SD trouble that a device can have while it
     * otherwise looks fine. */
    {
#if CONFIG_ENABLE_SD
        /* Track write failures are not added. Those points stay queued for a
         * retry, so they are not lost. Only evicted and dropped points count. */
        uint32_t trk_evicted = 0, trk_dropped = 0;
        uint32_t life_lost = 0, life_flush = 0, life_unmnt = 0;
        tracklog_losses(&trk_evicted, &trk_dropped, NULL);
        sysstat_sd_get(&life_lost, &life_flush, &life_unmnt);
#endif
        char paused_str[32];
        format_paused((uint64_t)sniffer_paused_ms(), paused_str, sizeof(paused_str));
        /* Read once: class and number must come from one sample. */
        unsigned long v_sniff = (unsigned long)sniffer_dropped();
        unsigned long v_mqtt = (unsigned long)mqtt_tx_dropped();
        unsigned long v_notify = (unsigned long)bt_stream_dropped_notify();
        unsigned long v_queue = (unsigned long)bt_stream_dropped_enqueue();
#if CONFIG_ENABLE_SD
        unsigned long v_pcap = (unsigned long)sdpcap_dropped();
        unsigned long v_trk = (unsigned long)(trk_evicted + trk_dropped);
        unsigned long v_pass = (unsigned long)ptlog_passages_dropped();
        unsigned long v_evt = (unsigned long)events_evicted();
        unsigned long v_sdfail = (unsigned long)sdcard_io_fail_max();
        unsigned long v_flush = (unsigned long)sdpcap_flush_fails();
#endif
        /* 1536 against 1316 (German, SD build: twelve labels, thirteen class slots of 15,
         * thirteen counters at ten digits). */
        char loss[1536];
        HTML_PRINTF(loss,
            "<div class='grp' id='s-loss'><h2>%s</h2><div class='scroll'><table class='kv'>"
            /* Every cell carries an id, so arApply() below can follow the counters while
             * the page stays open. The unit and the separators stay outside the ids. */
            "<tr><th>%s</th><td id='l-sniff'%s>%lu</td></tr>"
            "<tr><th>%s</th><td id='l-mqtt'%s>%lu</td></tr>"
            "<tr><th>%s</th><td id='l-btnotify'%s>%lu</td></tr>"
            "<tr><th>%s</th><td id='l-btqueue'%s>%lu</td></tr>"
#if CONFIG_ENABLE_SD
            "<tr><th>%s</th><td id='l-pcap'%s>%lu</td></tr>"
            "<tr><th>%s</th><td id='l-trk'%s>%lu</td></tr>"
            "<tr><th>%s</th><td id='l-pass'%s>%lu</td></tr>"
            "<tr><th>%s</th><td id='l-evt'%s>%lu</td></tr>"
            "<tr><th>%s</th><td id='l-sdfail'%s>%lu</td></tr>"
            "<tr><th>%s</th><td id='l-flush'%s>%lu</td></tr>"
            "<tr><th>%s</th><td><span id='l-life1'%s>%lu</span> / <span id='l-life2'%s>%lu</span>"
            " / <span id='l-life3'%s>%lu</span></td></tr>"
#endif
            "</table></div>",
            T(S_LOSS_TITLE),
            T(S_LOSS_SNIFFER), loss_cls(v_sniff), v_sniff,
            T(S_LOSS_MQTT), loss_cls(v_mqtt), v_mqtt,
            T(S_LOSS_BT_NOTIFY), loss_cls(v_notify), v_notify,
            T(S_LOSS_BT_QUEUE), loss_cls(v_queue), v_queue
            /* The SD rows end the list, so their block opens with the comma. */
#if CONFIG_ENABLE_SD
            , T(S_LOSS_PCAP), loss_cls(v_pcap), v_pcap,
            T(S_LOSS_TRACKS), loss_cls(v_trk), v_trk,
            T(S_LOSS_PASSAGES), loss_cls(v_pass), v_pass,
            T(S_LOSS_EVENTS), loss_cls(v_evt), v_evt,
            T(S_LOSS_SD_FAILS), loss_cls(v_sdfail), v_sdfail,
            T(S_LOSS_FLUSHFAIL), loss_cls(v_flush), v_flush,
            T(S_LOSS_LIFETIME), loss_cls(life_lost), (unsigned long)life_lost,
            loss_cls(life_flush), (unsigned long)life_flush,
            loss_cls(life_unmnt), (unsigned long)life_unmnt
#endif
            );
        httpd_resp_send_chunk(req, loss, HTTPD_RESP_USE_STRLEN);

#if CONFIG_ENABLE_SD
        /* The hold with its unit, from a second on "1,3 s". */
        char sdheld[FMT_US_MAX];
        fmt_us((uint64_t)sdcard_io_held_max_ms() * 1000u, web_lang(), sdheld, sizeof sdheld);
#endif
        /* Counts that are not losses, in their own table, so the largest number is no longer
         * read as the worst loss. 512 against 351 (each text in its longer language: heading,
         * three labels, paused_str 31, sdheld 15). */
        char lossinfo[512];
        HTML_PRINTF(lossinfo,
            "<h3>%s</h3><div class='scroll'><table class='kv' id='loss-info'>"
            "<tr><th>%s</th><td id='l-btpause'>%s</td></tr>"
#if CONFIG_ENABLE_SD
            "<tr><th>%s</th><td id='l-thin'>%lu</td></tr>"
            "<tr><th>%s</th><td id='l-sdheld'>%s</td></tr>"
#endif
            "</table></div>",
            T(S_LOSS_INFO), T(S_LOSS_BT_PAUSED), paused_str
#if CONFIG_ENABLE_SD
            , T(S_LOSS_THINNED), (unsigned long)sdpcap_filtered(),
            T(S_LOSS_SD_HELD), sdheld
#endif
            );
        httpd_resp_send_chunk(req, lossinfo, HTTPD_RESP_USE_STRLEN);

        /* The 2 KB hint goes out without a buffer that its next wording could outgrow. Without
         * SD it names the same rows, but the settings fields and /traffic it links to do not
         * exist, so it goes out without links. */
#if CONFIG_ENABLE_SD
        web_send_parts(req, "<details class='dtl'><summary>", T(S_LOSS_SUM),
                       "</summary><p class='note'>", T(S_LOSS_HINT), "</p></details></div>", NULL);
#else
        web_send_parts(req, "<details class='dtl'><summary>", T(S_LOSS_SUM),
                       "</summary><p class='note'>", NULL);
        web_send_unlinked(req, T(S_LOSS_HINT));
        web_send_parts(req, "</p></details></div>", NULL);
#endif
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
        "if((e=document.getElementById('sys-uptime')))e.textContent=itsDur(d.up_s,0);"
        "if((e=document.getElementById('sys-cpu'))&&d.cpu!==undefined)e.innerHTML=d.cpu;"
        "if((e=document.getElementById('sys-ram-i'))){e.textContent=d.ram_i;"
        "if(d.ram_icl!==undefined)e.className=d.ram_icl;}"
        "if((e=document.getElementById('sys-ram-p')))e.textContent=d.ram_p;"
        "if((e=document.getElementById('sys-tasks')))e.innerHTML=d.tasks_html;"
        "if((e=document.getElementById('sys-nf'))&&d.rx_nf_html!==undefined)e.innerHTML=d.rx_nf_html;"
        "if((e=document.getElementById('sys-nf-d'))&&d.rx_nf_sub!==undefined)e.innerHTML=d.rx_nf_sub;"
        "if((e=document.getElementById('sys-bad'))&&d.rx_broken!==undefined)e.textContent=d.rx_broken;"
        "if((e=document.getElementById('sys-bad-d'))&&d.rx_bad_sub!==undefined)e.innerHTML=d.rx_bad_sub;"
        "if((e=document.getElementById('sys-autoip'))&&d.eth_autoip!==undefined)e.hidden=!d.eth_autoip;"
        "if((e=document.getElementById('sys-cert'))&&d.cert_entries!==undefined)e.textContent=d.cert_entries;"
        "if((e=document.getElementById('sys-cert-d'))&&d.cert_sub!==undefined)e.innerHTML=d.cert_sub;"
        "if((e=document.getElementById('sys-trust'))&&d.trust_checks!==undefined)e.textContent=d.trust_checks;"
        "if((e=document.getElementById('sys-trust-d'))&&d.trust_sub!==undefined)e.innerHTML=d.trust_sub;"
        "if((e=document.getElementById('sys-perm'))&&d.perm_total!==undefined)e.textContent=d.perm_total;"
        "if((e=document.getElementById('sys-perm-d'))&&d.perm_sub!==undefined)e.innerHTML=d.perm_sub;"
        /* Every service yes gets a content answer, so perm_ok is the number of that tile. */
        "if((e=document.getElementById('sys-permc'))&&d.perm_ok!==undefined)"
        "e.textContent=d.perm_ok;"
        "if((e=document.getElementById('sys-permc-d'))&&d.perm_content_sub!==undefined)"
        "e.innerHTML=d.perm_content_sub;"
        "if((e=document.getElementById('sys-msig'))&&d.msgsig_total!==undefined)"
        "e.textContent=d.msgsig_total;"
        "if((e=document.getElementById('sys-msig-d'))&&d.msgsig_sub!==undefined)"
        "e.innerHTML=d.msgsig_sub;"
        /* The loss cells as one map: sixteen near-identical lines would only be longer.
         * textContent throughout, because none of these values carries an entity. */
        "var L={'l-sniff':d.loss_sniffer,'l-mqtt':d.loss_mqtt,'l-btpause':d.loss_bt_paused,"
        "'l-btnotify':d.loss_bt_notify,'l-btqueue':d.loss_bt_queue,'l-pcap':d.loss_pcap,"
        "'l-thin':d.loss_thinned,'l-trk':d.loss_tracks,'l-pass':d.loss_passages,"
        "'l-evt':d.loss_events,'l-sdfail':d.loss_sd_fails,'l-sdheld':d.loss_sd_held,"
        "'l-flush':d.loss_flushfail,'l-life1':d.loss_life_lost,'l-life2':d.loss_life_flush,"
        "'l-life3':d.loss_life_unmnt};"
        "for(var k in L)if((e=document.getElementById(k))&&L[k]!==undefined){e.textContent=L[k];"
        /* Same rule as loss_cls(); the info table never turns. */
        "if(!e.closest('#loss-info'))e.classList.toggle('v-warn',L[k]>0);}"
        "};</script>", HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* GET /system.json: uptime, CPU load, RAM, tasks, radio reception, the AutoIP state, the
 * certificate, permission and signature counters, the losses, the fault bar and the clock
 * line, for the poll script from send_page_header_refresh(). Chip info, reset reason and the
 * coredump banner change only with a reboot (the banner also with its delete button, which
 * reloads the page), so they are not polled. Neither is the clock row. */
esp_err_t system_json_get_handler(httpd_req_t *req)
{
    resolve_language(req);

    /* uptime keeps the spelling of format_uptime, because programs that read this JSON parse
     * it and the README promises it. up_s is the same in seconds, for the page's itsDur. */
    uint64_t up = (uint64_t)esp_timer_get_time() / 1000000ull;
    char uptime_str[48];
    format_uptime(up, uptime_str, sizeof(uptime_str));

    char ri_f[24], ri_m[24], ri_t[24], rp_f[24], rp_m[24], rp_t[24];
    fmt_bytes(heap_caps_get_free_size(MALLOC_CAP_INTERNAL), web_lang(), ri_f, sizeof(ri_f));
    fmt_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL), web_lang(), ri_m, sizeof(ri_m));
    fmt_bytes(heap_caps_get_total_size(MALLOC_CAP_INTERNAL), web_lang(), ri_t, sizeof(ri_t));
    fmt_bytes(heap_caps_get_free_size(MALLOC_CAP_SPIRAM), web_lang(), rp_f, sizeof(rp_f));
    fmt_bytes(heap_caps_get_minimum_free_size(MALLOC_CAP_SPIRAM), web_lang(), rp_m, sizeof(rp_m));
    fmt_bytes(heap_caps_get_total_size(MALLOC_CAP_SPIRAM), web_lang(), rp_t, sizeof(rp_t));

    static EXT_RAM_BSS_ATTR char task_rows[16384];
    int idle_x10 = -1;
    build_task_rows_html(task_rows, sizeof(task_rows), &idle_x10);
    esp_chip_info_t chip;
    esp_chip_info(&chip);
    char cpu_str[48];
    format_cpu_load(idle_x10, chip.cores, cpu_str, sizeof(cpu_str));

    /* 80 against 47: a weekday of 15 bytes, the zone after the time, two middle dots of 2. */
    char clkj[80];
    fmt_clockline(clkj, sizeof(clkj), "\u00b7", web_lang());

    sniffer_rx_quality_t q;
    sniffer_get_rx_quality(&q);
    static EXT_RAM_BSS_ATTR rx_html_t rx;
    format_rx(&q, &rx);
    /* null without a frame in the last minute, because 0 dBm would read as a measurement. */
    char nf_min[12] = "null", nf_avg[12] = "null", nf_max[12] = "null";
    if (q.nf_frames)
    {
        snprintf(nf_min, sizeof(nf_min), "%d", q.nf_min);
        snprintf(nf_avg, sizeof(nf_avg), "%d", q.nf_avg);
        snprintf(nf_max, sizeof(nf_max), "%d", q.nf_max);
    }

    its_certcache_stats_t cs;
    its_certcache_stats(&cs);
    static EXT_RAM_BSS_ATTR char certd[256];
    format_certcache(&cs, certd, sizeof(certd));
    /* null until a digest arrived, because 0 % would claim that none matched. */
    char share[12] = "null";
    uint64_t dtot = (uint64_t)cs.digests_known + cs.digests_missing;
    if (dtot)
        snprintf(share, sizeof(share), "%u", (unsigned)(cs.digests_known * 100ull / dtot));

    its_verify_stats_t vs;
    its_verify_stats(&vs);
    static EXT_RAM_BSS_ATTR char trustd[512];
    web_msgdetail_trust_counts(&vs, web_lang(), trustd, sizeof(trustd));
    uint64_t checks = trust_checks(&vs);

    msg_perm_stats_t ps;
    msg_extra_perm_stats(&ps);
    /* 256 each, the same two lines and the same worst cases as the copies in the page above. */
    static EXT_RAM_BSS_ATTR char permd[256], permcd[256];
    web_msgdetail_perm_counts(&ps, web_lang(), permd, sizeof(permd));
    web_msgdetail_perm_cont_counts(&ps, web_lang(), permcd, sizeof(permcd));
    uint64_t perms = (uint64_t)ps.ok + ps.bad + ps.unknown;

    its_msgsig_stats_t ms;
    its_msgsig_stats(&ms);
    /* 512, the same line and the same worst case as the copy in the page above. */
    static EXT_RAM_BSS_ATTR char msigd[512];
    web_msgsig_counts(&ms, web_lang(), msigd, sizeof(msigd));
    /* Averages in whole microseconds over the matches, 0 before the first one of a curve. */
    unsigned long msig_avg[ITS_MSGSIG_CURVES];
    for (int c = 0; c < ITS_MSGSIG_CURVES; c++)
        msig_avg[c] = ms.n[c] ? (unsigned long)(ms.us_sum[c] / ms.n[c]) : 0;

    /* The loss table of the page. Every getter here is a plain read without a reset, so the
     * page handler and this one may both call them. */
#if CONFIG_ENABLE_SD
    uint32_t trk_evicted = 0, trk_dropped = 0;
    uint32_t life_lost = 0, life_flush = 0, life_unmnt = 0;
    tracklog_losses(&trk_evicted, &trk_dropped, NULL);
    sysstat_sd_get(&life_lost, &life_flush, &life_unmnt);
    /* Read once: the number and its text must come from one sample. */
    uint32_t held = sdcard_io_held_max_ms();
    char sdheld[FMT_US_MAX];
    fmt_us((uint64_t)held * 1000u, web_lang(), sdheld, sizeof sdheld);
#endif
    uint64_t paused_ms = (uint64_t)sniffer_paused_ms();
    char paused_str[32];
    format_paused(paused_ms, paused_str, sizeof(paused_str));

    /* 24576: the longest answer is 23255 bytes (23234 before perm_content_sub), 16383 of them the
     * task rows and 2047 the fault lines at their cap. A silent cut here would hand readers half a
     * JSON object, so the return value is checked below. */
    static EXT_RAM_BSS_ATTR char json[24576];
    int jn = snprintf(json, sizeof(json),
        "{\"uptime\":\"%s\",\"up_s\":%llu,\"cpu\":\"%s\",\"ram_i\":\"%s / %s / %s\",\"ram_icl\":\"%s\","
        /* clk holds a literal UTF-8 middle dot, not an entity. arApply() writes
         * it with textContent, which would show an entity as plain text. */
        "\"ram_p\":\"%s / %s / %s\",\"clk\":\"%s\",\"tasks_html\":\"%s\","
        "\"rx_on\":%s,\"rx_broken\":%lu,\"rx_nf_frames\":%lu,"
        "\"rx_nf_min\":%s,\"rx_nf_avg\":%s,\"rx_nf_max\":%s,"
        "\"rx_nf_html\":\"%s\",\"rx_nf_sub\":\"%s\",\"rx_bad_sub\":\"%s\",\"eth_autoip\":%s,"
        "\"cert_entries\":%lu,\"cert_capacity\":%lu,\"cert_digests_known\":%lu,"
        "\"cert_digests_missing\":%lu,\"cert_digest_share\":%s,\"cert_sub\":\"%s\","
        "\"trust_checks\":%llu,\"trust_checked\":%lu,\"trust_unavailable\":%lu,"
        "\"trust_invalid\":%lu,\"trust_expired\":%lu,\"trust_revoked\":%lu,"
        "\"trust_dropped\":%lu,\"trust_issuers\":%lu,"
        "\"trust_us_max\":%lu,\"trust_selftest\":%u,\"trust_selftest_us\":%lu,"
        "\"trust_stack_left\":%lu,\"trust_sub\":\"%s\","
        "\"perm_ok\":%lu,\"perm_bad\":%lu,\"perm_unknown\":%lu,\"perm_total\":%llu,"
        /* The content answers, counted and as the line of their tile (perm_content_sub).
         * perm_sub is the line of the service tile alone. */
        "\"perm_content_ok\":%lu,\"perm_content_bad\":%lu,\"perm_content_unknown\":%lu,"
        "\"perm_content_none\":%lu,\"perm_sub\":\"%s\",\"perm_content_sub\":\"%s\","
        /* The message signature (its_msgsig.c), the cost per curve included. msgsig_total
         * counts the computed ones, ok plus bad. msgsig_untrusted counts the checks of chains
         * not trusted. */
        "\"msgsig_total\":%llu,\"msgsig_ok\":%lu,\"msgsig_bad\":%lu,\"msgsig_nocheck\":%lu,"
        "\"msgsig_refused\":%lu,\"msgsig_sample\":%lu,\"msgsig_busy\":%lu,"
        "\"msgsig_started\":%lu,\"msgsig_untrusted\":%lu,\"msgsig_certs\":%lu,"
        "\"msgsig_hash_us_max\":%lu,"
        "\"msgsig_note_us_max\":%lu,"
        "\"msgsig_p256_n\":%lu,\"msgsig_p256_us_avg\":%lu,\"msgsig_p256_us_max\":%lu,"
        "\"msgsig_p256_us_last\":%lu,\"msgsig_bp256_n\":%lu,\"msgsig_bp256_us_avg\":%lu,"
        "\"msgsig_bp256_us_max\":%lu,\"msgsig_bp256_us_last\":%lu,\"msgsig_sub\":\"%s\","
        /* Only added fields, never a renamed or dropped one, because other programs read this.
         * The pause and the SD hold come twice on purpose: milliseconds to compute with, and the
         * cell text. */
        /* The SD numbers are the same counters as the loss object of /status.json, under
         * flat names: loss_pcap is its lost_boot, loss_flushfail its flushfail_boot, and
         * loss_life_* its bare lost/flushfail/unmounts. Both spellings stay. */
        "\"loss_sniffer\":%lu,\"loss_mqtt\":%lu,\"loss_bt_paused_ms\":%llu,"
        "\"loss_bt_paused\":\"%s\",\"loss_bt_notify\":%lu,\"loss_bt_queue\":%lu"
#if CONFIG_ENABLE_SD
        ",\"loss_pcap\":%lu,\"loss_thinned\":%lu,\"loss_tracks\":%lu,"
        "\"loss_passages\":%lu,\"loss_events\":%lu,\"loss_sd_fails\":%lu,"
        "\"loss_sd_held_ms\":%lu,\"loss_sd_held\":\"%s\",\"loss_flushfail\":%lu,"
        "\"loss_life_lost\":%lu,\"loss_life_flush\":%lu,\"loss_life_unmnt\":%lu"
#endif
        /* probs and probs_html of the fault bar, last and after a comma of their own. */
        "%s}",
        uptime_str, (unsigned long long)up, cpu_str, ri_f, ri_m, ri_t, ram_int_class(),
        rp_f, rp_m, rp_t, clkj, task_rows,
        sniffer_get_channel() ? "true" : "false", (unsigned long)q.broken,
        (unsigned long)q.nf_frames, nf_min, nf_avg, nf_max,
        rx.nf_v, rx.nf_d, rx.bad_d, web_autoip_active() ? "true" : "false",
        (unsigned long)cs.entries, (unsigned long)cs.capacity, (unsigned long)cs.digests_known,
        (unsigned long)cs.digests_missing, share, certd,
        (unsigned long long)checks, (unsigned long)vs.checked, (unsigned long)vs.unavailable,
        (unsigned long)vs.invalid, (unsigned long)vs.expired, (unsigned long)vs.revoked,
        (unsigned long)vs.dropped, (unsigned long)vs.issuers,
        (unsigned long)vs.us_max, (unsigned)vs.selftest, (unsigned long)vs.selftest_us,
        (unsigned long)vs.stack_left, trustd,
        (unsigned long)ps.ok, (unsigned long)ps.bad, (unsigned long)ps.unknown,
        (unsigned long long)perms,
        (unsigned long)ps.content_ok, (unsigned long)ps.content_bad,
        (unsigned long)ps.content_unknown, (unsigned long)ps.content_none, permd, permcd,
        (unsigned long long)((uint64_t)ms.ok + ms.bad), (unsigned long)ms.ok,
        (unsigned long)ms.bad, (unsigned long)ms.nocheck, (unsigned long)ms.refused,
        (unsigned long)ms.sample, (unsigned long)ms.busy, (unsigned long)ms.started,
        (unsigned long)ms.untrusted, (unsigned long)ms.certs, (unsigned long)ms.hash_us_max,
        (unsigned long)ms.note_us_max,
        (unsigned long)ms.n[0], msig_avg[0], (unsigned long)ms.us_max[0],
        (unsigned long)ms.us_last[0], (unsigned long)ms.n[1], msig_avg[1],
        (unsigned long)ms.us_max[1], (unsigned long)ms.us_last[1], msigd,
        (unsigned long)sniffer_dropped(), (unsigned long)mqtt_tx_dropped(),
        (unsigned long long)paused_ms, paused_str,
        (unsigned long)bt_stream_dropped_notify(), (unsigned long)bt_stream_dropped_enqueue()
#if CONFIG_ENABLE_SD
        , (unsigned long)sdpcap_dropped(), (unsigned long)sdpcap_filtered(),
        (unsigned long)(trk_evicted + trk_dropped), (unsigned long)ptlog_passages_dropped(),
        (unsigned long)events_evicted(), (unsigned long)sdcard_io_fail_max(),
        (unsigned long)held, sdheld, (unsigned long)sdpcap_flush_fails(),
        (unsigned long)life_lost, (unsigned long)life_flush, (unsigned long)life_unmnt
#endif
        , web_faults_json(web_faults_skip_system()));
    /* A cut answer is not JSON any more, and a reader's parser would throw on the half
     * object. Better one log line and a 500 than silent garbage. */
    if (jn < 0 || (size_t)jn >= sizeof(json))
    {
        ESP_LOGE(TAG, "system.json truncated: %d of %u bytes", jn, (unsigned)sizeof(json));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "system.json too long");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}

