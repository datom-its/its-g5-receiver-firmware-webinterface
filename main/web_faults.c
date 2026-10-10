#include "sdkconfig.h"

#include "web_faults.h"

#include <errno.h>
#include <string.h>
#include <time.h>

#include "esp_attr.h"
#include "esp_timer.h"

#include "mqtt.h"
#include "sysmon.h"
#include "sysstat.h"
#include "web_fmt.h"
#include "web_system.h"
#include "webserver_priv.h"
#if CONFIG_ENABLE_SD
#include "sdcard.h"
#endif

/* The fault bar waits this long after the first address before it calls the clock unset:
 * NTP needs a moment to answer. */
#define FLT_CLOCK_GRACE_S 300
/* A crash of this boot stays in the bar for a day, unless its dump was deleted. */
#define FLT_CRASH_SHOW_S  86400
/* The first tries and a short broker restart are no fault. */
#define FLT_MQTT_GRACE_S  300

void web_faults_decide(const flt_in_t *in, flt_state_t *st)
{
    memset(st, 0, sizeof(*st));
    /* Never an SD fault: no card at all, or unmounted on purpose (/poweroff, console). */
    if (in->sd_build)
    {
        if (!in->sd_mounted && in->sd_taken_out)
            st->sd = FSD_OUT;
        else if (!in->sd_mounted && in->sd_no_fs)
            st->sd = FSD_NOFS;
        else if (in->sd_mounted && in->sd_dead_ms >= SYSMON_SD_DEAD_MS &&
                 in->sd_dead_n >= SYSMON_SD_DEAD_MIN)
        {
            st->sd = in->sd_errno_full ? FSD_FULL : FSD_WRITE;
            st->sd_bad_s = in->sd_dead_ms / 1000;
        }
        if (st->sd != FSD_NONE)
            st->mask |= 1u << FLT_SD;
    }
    /* Only after steady reception: a place that never receives is no fault. */
    if (in->rx_idle_s >= WEB_RX_QUIET_SEC && in->rx_steady)
    {
        st->mask |= 1u << FLT_RX;
        st->rx_idle_s = (uint32_t)in->rx_idle_s;
    }
    if (!web_clock_set((uint32_t)in->now_unix) && in->ip_age_s > FLT_CLOCK_GRACE_S)
        st->mask |= 1u << FLT_CLOCK;
    st->dump = in->dump;
    if (in->dump || (in->boot_crash && in->uptime_s < FLT_CRASH_SHOW_S && !in->dump_cleared))
        st->mask |= 1u << FLT_CRASH;
    if (in->mqtt_wanted && !in->mqtt_connected && in->mqtt_down_s > FLT_MQTT_GRACE_S)
    {
        st->mask |= 1u << FLT_MQTT;
        st->mqtt_down_s = in->mqtt_down_s;
    }
}

/* Flags only: this runs in every page head and every poll. sd_state() would query the card
 * over the SPI bus it shares with Ethernet. esp_core_dump_image_check would hash the whole
 * dump. */
void web_faults_get(flt_state_t *st)
{
    flt_in_t in;
    memset(&in, 0, sizeof(in));
#if CONFIG_ENABLE_SD
    in.sd_build = true;
    in.sd_mounted = sdcard_is_mounted();
    in.sd_taken_out = sdcard_taken_out();
    in.sd_no_fs = sdcard_last_mount_error() == ESP_FAIL;
    in.sd_dead_ms = sdcard_write_dead_ms(&in.sd_dead_n);
    in.sd_errno_full = sysmon_sd_probe_errno() == ENOSPC;
#endif
    in.rx_idle_s = web_rx_quiet_s();
    in.rx_steady = web_rx_steady();
    in.now_unix = (int64_t)time(NULL);
    in.ip_age_s = web_ip_age_sec();
    in.dump = web_coredump_present();
    in.dump_cleared = web_coredump_cleared();
    in.boot_crash = sysstat_boot_was_crash();
    int64_t now_us = esp_timer_get_time();
    in.uptime_s = (uint32_t)(now_us / 1000000);
    mqtt_state_t m;
    mqtt_get_state(&m);
    in.mqtt_wanted = m.wanted;
    in.mqtt_connected = m.connected;
    in.mqtt_down_s = m.since_us ? (uint32_t)((now_us - m.since_us) / 1000000) : 0;
    web_faults_decide(&in, st);
}

bool web_faults_sd_dead(uint32_t *bad_s)
{
    bool dead = false;
    uint32_t ms = 0;
#if CONFIG_ENABLE_SD
    uint32_t n = 0;
    ms = sdcard_write_dead_ms(&n);
    dead = sdcard_is_mounted() && ms >= SYSMON_SD_DEAD_MS && n >= SYSMON_SD_DEAD_MIN;
#endif
    if (bad_s)
        *bad_s = dead ? ms / 1000 : 0;
    return dead;
}

/* One row per fault: where it is fixed. The texts contain no double quote, backslash or control
 * character, so probs_html carries them without escaping. */
typedef struct {
    const char *key;      /* JSON key; SD takes it from SD_ROWS */
    str_id_t    text;     /* SD takes it from SD_ROWS */
    const char *path;
    const char *anchor;
    str_id_t    nav;      /* link text: the menu name of the page */
    bool        alarm;    /* broken now; the rest is a warning */
} flt_row_t;

static const flt_row_t ROWS[] = {
    [FLT_SD]    = { NULL,          S_COUNT,     "/sdcard",   "",        S_NAV_SD,       true  },
    [FLT_RX]    = { "rx_lost",     S_FLT_RX,    "/settings", "#g-rx",   S_NAV_SETTINGS, true  },
    [FLT_CLOCK] = { "clock_unset", S_FLT_CLOCK, "/settings", "#g-net",  S_NAV_SETTINGS, false },
    [FLT_CRASH] = { "crash",       S_FLT_CRASH, "/system",   "#s-stab", S_NAV_SYSTEM,   true  },
    [FLT_MQTT]  = { "mqtt_down",   S_FLT_MQTT,  "/settings", "#g-mqtt", S_NAV_SETTINGS, false },
};
_Static_assert(sizeof(ROWS) / sizeof(ROWS[0]) == FLT_COUNT, "one row per fault");

static const struct {
    const char *key;
    str_id_t    text;
    bool        alarm;
} SD_ROWS[] = {
    [FSD_NONE]  = { "",                S_COUNT,        false },
    [FSD_OUT]   = { "sd_write_failed", S_SD_TAKEN_OUT, true  },
    [FSD_NOFS]  = { "sd_no_fs",        S_FLT_SD_NOFS,  false },
    [FSD_FULL]  = { "sd_full",         S_FLT_SD_FULL,  true  },
    [FSD_WRITE] = { "sd_write_errors", S_FLT_SD_WRITE, true  },
};
_Static_assert(sizeof(SD_ROWS) / sizeof(SD_ROWS[0]) == FSD_WRITE + 1, "one row per SD case");

static const char *flt_key(const flt_state_t *st, unsigned i)
{
    return i == FLT_SD ? SD_ROWS[st->sd].key : ROWS[i].key;
}

int web_faults_html(const flt_state_t *st, uint32_t skip, char *out, size_t cap)
{
    if (!out || !cap)
        return 0;
    out[0] = '\0';
    const char *lc = web_lang() == LANG_DE ? "de" : "en";
    int n = 0;
    for (unsigned i = 0; i < FLT_COUNT; i++)
    {
        uint32_t bit = 1u << i;
        if (!(st->mask & bit) || (skip & bit))
            continue;
        const flt_row_t *r = &ROWS[i];
        bool alarm = i == FLT_SD ? SD_ROWS[st->sd].alarm : r->alarm;
        /* Only the three texts with exactly one %s serve as a format. */
        uint32_t dur_s = 0;
        str_id_t id = r->text;
        bool timed = false;
        if (i == FLT_SD)
        {
            id = SD_ROWS[st->sd].text;
            timed = st->sd == FSD_WRITE;
            dur_s = st->sd_bad_s;
        }
        else if (i == FLT_RX || i == FLT_MQTT)
        {
            timed = true;
            dur_s = i == FLT_RX ? st->rx_idle_s : st->mqtt_down_s;
        }
        else if (i == FLT_CRASH && st->dump)
            id = S_FLT_CRASH_DUMP;
        char t[320];
        int tn;
        if (timed)
        {
            char dur[FMT_DUR_MAX];
            fmt_dur(dur_s, FMT_DUR_TWO, dur, sizeof dur);
            tn = snprintf(t, sizeof(t), T(id), dur);
        }
        else
            tn = snprintf(t, sizeof(t), "%s", T(id));
        if (i == FLT_SD)
            web_addf(t, sizeof(t), tn, " %s", T(S_FLT_SD_LOST));
        n = web_addf(out, cap, n, "<p%s>%s <a href='%s?lang=%s%s'>%s&nbsp;&rarr;</a></p>",
                     alarm ? " class='al'" : "", t, r->path, lc, r->anchor, T(r->nav));
    }
    return n;
}

uint32_t web_faults_skip_system(void)
{
    return web_coredump_present() ? FLT_SKIP_SYSTEM : 0;
}

const char *web_faults_crash_cls(bool recent)
{
    flt_state_t st;
    web_faults_get(&st);
    return (st.mask & (1u << FLT_CRASH)) ? "v-bad" : recent ? "v-warn" : "";
}

/* A page leaves out of its bar what it shows itself, further down or in its own box. */
static uint32_t skip_for(const char *uri, const flt_state_t *st)
{
    size_t len = strcspn(uri, "?#");
    static const struct { const char *path; uint32_t skip; } OWN[] = {
        { "/",        FLT_SKIP_STATUS },   /* the rate tile, same set as /status.json */
        { "/system",  FLT_SKIP_SYSTEM },   /* the crash banner, same set as /system.json */
        { "/sdcard",  1u << FLT_SD },      /* its box for a card taken out or without FAT */
        { "/trust",   1u << FLT_CLOCK },   /* its own no-clock box */
    };
    /* Only what the page really draws: the banner exists only with a dump, the /sdcard box only
     * for an unmounted card, so a full or refusing card keeps its line there. */
    uint32_t drawn = ~0u;
    if (!st->dump)
        drawn &= ~FLT_SKIP_SYSTEM;
    if (st->sd != FSD_OUT && st->sd != FSD_NOFS)
        drawn &= ~(1u << FLT_SD);
    for (size_t i = 0; i < sizeof(OWN) / sizeof(OWN[0]); i++)
        if (strlen(OWN[i].path) == len && memcmp(uri, OWN[i].path, len) == 0)
            return OWN[i].skip & drawn;
    return 0;
}

/* An empty hidden container when all is well, so the polls and the /traffic swap can fill it.
 * 2048 against 936 measured with every fault, durations at 15 bytes (German; English 871). */
void web_faults_send(httpd_req_t *req)
{
    static EXT_RAM_BSS_ATTR char s_bar[2048];
    static const char END[] = "</div>";
    flt_state_t st;
    web_faults_get(&st);
    uint32_t skip = skip_for(req->uri, &st);
    int n = web_addf(s_bar, sizeof(s_bar), 0, "<div class='probs' id='probs' role='status'%s>",
                     (st.mask & ~skip) ? "" : " hidden");
    /* The closing tag always fits, even if a line was cut. */
    n += web_faults_html(&st, skip, s_bar + n, sizeof(s_bar) - (size_t)n - sizeof(END) + 1);
    web_addf(s_bar, sizeof(s_bar), n, "%s", END);
    httpd_resp_send_chunk(req, s_bar, HTTPD_RESP_USE_STRLEN);
}

/* Keys for machines (collectors, other receivers), never skipped; the HTML skips what the
 * polling page shows itself. 2048 against 967 measured with every fault, no skip (German). */
const char *web_faults_json(uint32_t skip)
{
    static EXT_RAM_BSS_ATTR char s_json[2048];
    flt_state_t st;
    web_faults_get(&st);
    int n = web_addf(s_json, sizeof(s_json), 0, ",\"probs\":[");
    const char *comma = "";
    for (unsigned i = 0; i < FLT_COUNT; i++)
        if (st.mask & (1u << i))
        {
            n = web_addf(s_json, sizeof(s_json), n, "%s\"%s\"", comma, flt_key(&st, i));
            comma = ",";
        }
    n = web_addf(s_json, sizeof(s_json), n, "],\"probs_html\":\"");
    /* Room for the closing quote, so a cut line still leaves valid JSON. */
    n += web_faults_html(&st, skip, s_json + n, sizeof(s_json) - (size_t)n - 1);
    web_addf(s_json, sizeof(s_json), n, "\"");
    return s_json;
}

/* Three chunks around the static s_json: no buffer of its own on the httpd stack. */
esp_err_t web_faults_json_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_send_chunk(req, "{\"ok\":true", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, web_faults_json(0), HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "}", HTTPD_RESP_USE_STRLEN);
    return httpd_resp_send_chunk(req, NULL, 0);
}
