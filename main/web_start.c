#include "sdkconfig.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_timer.h"

#include "cmd_sniffer.h"
#include "config.h"
#include "ethernet.h"
#include "mqtt.h"
#if CONFIG_ENABLE_SD
#include "sdcard.h"
#include "sdpcap.h"
#endif
#ifdef CONFIG_ENABLE_TEMPERATURE
#include "temperature.h"
#endif
#include "sysstat.h"

#include "web_start.h"
#include "webserver_priv.h"
#include "webserver_ring.h"
#include "web_faults.h"
#include "web_fmt.h"
#include "web_glance.h"
#include "web_mqtt.h"
#include "web_system.h"

static const char TAG[] = "WEBSERVER";

#if CONFIG_ENABLE_SD
/* The same states as the /status.json reasons. "not_mounted" means the card
 * never answered, "unmounted" means somebody unmounted it on purpose. */
static const char *sd_state_reason(sd_state_t st)
{
    switch (st) {
    case SDST_NO_USAGE:  return "usage_error";
    case SDST_NO_FS:     return "no_fs";
    case SDST_UNMOUNTED: return "unmounted";
    case SDST_WRITE_FAILED: return "write_failed";
    default:             return "not_mounted";
    }
}
#endif

/* The SD cell of the start page as the page draws it. /status.json sends it as sdui. Outside
 * #if, so the page compiles without SD and shows the dash. */
typedef struct {
    const char *cls;     /* label class: '', v-warn, v-bad or v-off */
    const char *title;   /* tooltip of the label */
    char val[48];        /* 34 at most: 100 and the percent span */
    char txt[256];       /* 217 at most (German): S_SD_TILE_UNMOUNTED, the break, the write errors */
} sd_tile_t;

/* One sd_state() call per request feeds the cell and the JSON, so a poll cannot paint a state
 * the page would not. st_out, tot and fre may be NULL. */
static void sd_tile(sd_tile_t *o, sd_state_t *st_out, uint64_t *tot, uint64_t *fre)
{
    o->cls = "";
    o->title = "";
    snprintf(o->val, sizeof(o->val), "&ndash;");
    /* Empty, not a dash: the detail line then renders blank instead of putting a second
     * dash under the one in the value. */
    o->txt[0] = '\0';
    if (st_out) *st_out = SDST_NO_CARD;
    if (tot) *tot = 0;
    if (fre) *fre = 0;
#if CONFIG_ENABLE_SD
    uint64_t t = 0, f = 0;
    sd_state_t st = sd_state(&t, &f);
    if (st_out) *st_out = st;
    if (tot) *tot = t;
    if (fre) *fre = f;
    switch (st)
    {
    case SDST_OK:
    {
        /* The share is the cell's value, the byte text its detail line: kept apart, because
         * T(S_SD_USED_OF) is itself the format and no span can be appended to it. */
        char u[24], ts[24], fs[24];
        unsigned pct = (unsigned)(((t - f) * 100ull) / t);
        fmt_bytes(t - f, web_lang(), u, sizeof(u));
        fmt_bytes(t, web_lang(), ts, sizeof(ts));
        fmt_bytes(f, web_lang(), fs, sizeof(fs));
        snprintf(o->txt, sizeof(o->txt), T(S_SD_USED_OF), u, ts, fs);
        /* %% is a literal percent sign in the value, not a conversion. */
        snprintf(o->val, sizeof(o->val), "%u<span class='e'>%%</span>", pct);
        /* Threshold colour and its tooltip go on the label, which is where the state dot is. */
        o->cls = lvl_class(pct, 80, 92);
        o->title = strcmp(o->cls, "v-bad") == 0  ? T(S_TH_ALARM)
                 : strcmp(o->cls, "v-warn") == 0 ? T(S_TH_WARN) : "";
        /* Writes fail right now: the same rule the fault bar uses. */
        if (web_faults_sd_dead(NULL))
        {
            o->cls = "v-bad";
            o->title = "";
        }
        break;
    }
    case SDST_NO_CARD:
        /* Grey only for no card at all, because a device without one must not look alarmed. */
        o->cls = "v-off";
        snprintf(o->txt, sizeof(o->txt), "%s", T(S_SD_NOT_MOUNTED));
        break;
    case SDST_UNMOUNTED:
        o->cls = "v-warn";
        snprintf(o->txt, sizeof(o->txt), "%s", T(S_SD_TILE_UNMOUNTED));
        break;
    case SDST_NO_FS:
        o->cls = "v-warn";
        snprintf(o->txt, sizeof(o->txt), "%s", T(S_SD_TILE_NOFS));
        break;
    case SDST_NO_USAGE:
        /* The card is there, but its size is unknown. */
        o->cls = "v-warn";
        snprintf(o->txt, sizeof(o->txt), "%s", T(S_SD_ERR_USAGE));
        break;
    case SDST_WRITE_FAILED:
        /* The device took it out because writes failed. */
        o->cls = "v-bad";
        snprintf(o->txt, sizeof(o->txt), "%s", T(S_SD_TAKEN_OUT));
        break;
    }
    /* The count covers the time since the restart and takes the colour. The label says the
     * state now, so the tile keeps its own colour. */
    uint32_t ff = sdpcap_flush_fails();
    if (ff)
        web_addf(o->txt, sizeof(o->txt), (int)strlen(o->txt), "%s%s: <span class='v-warn'>%lu</span>",
                 o->txt[0] ? "<br>" : "", T(S_SD_FAILS_BOOT), (unsigned long)ff);
#endif
}

#ifdef CONFIG_ENABLE_TEMPERATURE
/* Enclosure temperature, not a chip limit: the LM75 is on the board next to
 * the chip, so these are the numbers the operator should watch. */
static const char *temp_class(float tc)
{
    if (tc != tc) return "v-off"; /* NaN = sensor not answering */
    if (tc < 0.0f) return "";
    return lvl_class((unsigned)tc, 60, 75);
}
#endif

#define HIST_RATE_MIN   60          /* msgs/min floor, so a quiet hour stays flat */
#define HIST_TEMP_SPAN  5           /* K, narrowest band, so noise cannot fill the box */

/* One sample per completed second; the 60th ring slot is the second still
 * being counted, so only 59 of them can ever be shown. */
#define SPARK_POINTS    (RATE_WINDOW_SECS - 1)
#define SPARK_PEAK_MIN  10  /* msgs/s floor, so a quiet minute stays flat */
#define SPARK_DECAY_SEC 30

/* Fixed y-scale: rescaling to the window maximum flattened nearly every sample
 * and moved the axis between polls. Lockless: only the httpd task renders. */
static uint32_t spark_peak = SPARK_PEAK_MIN;
static uint64_t spark_decay_at;

static uint32_t spark_scale(const uint32_t *counts, size_t n, uint64_t now_sec)
{
    uint32_t wmax = 0;
    for (size_t i = 0; i < n; i++)
        if (counts[i] > wmax) wmax = counts[i];

    if (!spark_decay_at) spark_decay_at = now_sec;
    if (wmax > spark_peak)
    {
        spark_peak = wmax;
        spark_decay_at = now_sec;
    }
    else if (now_sec - spark_decay_at >= SPARK_DECAY_SEC)
    {
        /* Whole steps, capped: a tab left closed for a day must not repeat
         * the decay thousands of times. */
        uint32_t steps = (uint32_t)((now_sec - spark_decay_at) / SPARK_DECAY_SEC);
        if (steps > 64) steps = 64;
        while (steps-- && spark_peak > SPARK_PEAK_MIN)
            spark_peak -= (spark_peak / 4) ? (spark_peak / 4) : 1;
        if (spark_peak < SPARK_PEAK_MIN) spark_peak = SPARK_PEAK_MIN;
        /* Never below what the window holds: a lower peak would clip the top
         * of the line flat and make the label flicker by one. */
        if (spark_peak < wmax) spark_peak = wmax;
        spark_decay_at = now_sec;
    }
    return spark_peak;
}

/* Builds the sparkline as a polyline "points" list; the <svg>/<polyline> shell
 * is emitted once and later polls only setAttribute('points'). */
static void build_spark_points(char *out, size_t out_size, uint32_t *peak_out)
{
    uint64_t now_sec = esp_timer_get_time() / 1000000ull;
    uint32_t counts[SPARK_POINTS];
    if (msg_ring_mutex && xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
    {
        for (size_t i = 0; i < SPARK_POINTS; i++)
        {
            /* Ends at now_sec - 1: the current second is still filling up and
             * as a line endpoint it twitched downwards on every poll. */
            uint64_t sec = now_sec - SPARK_POINTS + i;
            rate_bucket_t *b = &rate_buckets[sec % RATE_WINDOW_SECS];
            counts[i] = (b->sec == sec) ? b->count : 0;
        }
        xSemaphoreGive(msg_ring_mutex);
    }
    else
    {
        memset(counts, 0, sizeof(counts));
    }

    uint32_t peak = spark_scale(counts, SPARK_POINTS, now_sec);
    if (peak_out) *peak_out = peak;

    out[0] = '\0';
    size_t o = 0;
    for (size_t i = 0; i < SPARK_POINTS && o + 12 < out_size; i++)
    {
        /* h stays in 1..36 so the 2 px stroke never clips at the viewBox edge.
         * A silent second drops to the baseline, which is the right reading. */
        uint32_t h = counts[i] ? 4 + (counts[i] * 32) / peak : 1;
        if (h > 36) h = 36;
        o += (size_t)snprintf(out + o, out_size - o, "%s%u,%u",
                              o ? " " : "", (unsigned)(i * 4), (unsigned)(40 - h));
    }
}

/* What one pass over the minute ring found; peak and band have to come from the
 * same pass as the points, or a label names a scale the line was not drawn to. */
typedef struct {
    uint32_t peak;      /* msgs/min the rate line was scaled against */
    uint32_t nvalid;    /* minutes the ring actually holds */
    uint32_t nrate;     /* of those, minutes with at least one frame */
    int      tlo, thi;  /* whole-degree band the temperature line was scaled to */
    bool     ttemp;     /* any usable temperature sample in the window */
} hist_view_t;

/* Snapshots the minute ring into two polyline point lists. Lock-free by
 * design: taking msg_ring_mutex here could make the sniffer drop a frame. */
static void build_hour_points(char *rout, size_t rsize, char *tout, size_t tsize,
                              hist_view_t *v)
{
    uint32_t n = hist_count;
    uint32_t r[HIST_MINUTES];
    int16_t  t[HIST_MINUTES];
    bool     ok[HIST_MINUTES];
    int lo = 0, hi = 0;

    memset(v, 0, sizeof(*v));
    v->peak = HIST_RATE_MIN;

    for (uint32_t k = 0; k < HIST_MINUTES; k++)
    {
        ok[k] = false;
        /* k = 59 is the newest minute. k = 0 is also the slot the writer takes
         * next, which is why the stamp is read again below the values. */
        if (n + k < HIST_MINUTES)
            continue;
        uint32_t m = n + k - (HIST_MINUTES - 1);
        hist_slot_t *s = &hist_ring[(m - 1) % HIST_MINUTES];
        uint32_t st = s->stamp;
        if (st != m)
            continue;
        HIST_BARRIER();
        uint32_t rv = s->rate;
        int16_t  tv = s->temp_dc;
        HIST_BARRIER();
        /* The stamp is read again after the values: a reader preempted here
         * comes back to a slot that already holds a minute from an hour later. */
        if (s->stamp != st)
            continue;
        r[k] = rv;
        t[k] = tv;
        ok[k] = true;
        v->nvalid++;
        if (rv)
        {
            v->nrate++;
            if (rv > v->peak) v->peak = rv;
        }
        if (tv != HIST_TEMP_NONE)
        {
            if (!v->ttemp) { lo = hi = tv; v->ttemp = true; }
            else { if (tv < lo) lo = tv; if (tv > hi) hi = tv; }
        }
    }

    /* Whole degrees outwards, then widened to HIST_TEMP_SPAN: a fixed 0..100
     * scale would be a straight line, an exact one would magnify sensor noise. */
    if (v->ttemp)
    {
        v->tlo = (lo >= 0 ? lo : lo - 9) / 10;
        v->thi = (hi >= 0 ? hi + 9 : hi) / 10;
        if (v->thi - v->tlo < HIST_TEMP_SPAN)
        {
            int mid = (v->tlo + v->thi) / 2;
            v->tlo = mid - HIST_TEMP_SPAN / 2;
            v->thi = v->tlo + HIST_TEMP_SPAN;
        }
    }

    rout[0] = tout[0] = '\0';
    size_t ro = 0, to = 0;
    unsigned rn = 0, tn = 0, ry = 0, ty = 0, tk = 0;
    int span_dc = (v->thi - v->tlo) * 10;
    for (uint32_t k = 0; k < HIST_MINUTES; k++)
    {
        if (!ok[k])
            continue;   /* only ever at the left, while the first hour fills */
        /* h stays in 1..36 like the minute line, so the 2 px stroke never
         * clips at the viewBox edge and a silent minute sits on the floor. */
        uint32_t h = r[k] ? 4 + (r[k] * 32) / v->peak : 1;
        if (h > 36) h = 36;
        ry = (unsigned)(40 - h);
        if (ro + 12 < rsize)
        {
            ro += (size_t)snprintf(rout + ro, rsize - ro, "%s%u,%u",
                                   ro ? " " : "", (unsigned)(k * 4), ry);
            rn++;
        }
        if (t[k] == HIST_TEMP_NONE || span_dc <= 0)
            continue;
        int th = 4 + ((t[k] - v->tlo * 10) * 32) / span_dc;
        if (th < 1) th = 1;
        if (th > 36) th = 36;
        ty = (unsigned)(40 - th);
        tk = k;
        if (to + 12 < tsize)
        {
            to += (size_t)snprintf(tout + to, tsize - to, "%s%u,%u",
                                   to ? " " : "", (unsigned)(k * 4), ty);
            tn++;
        }
    }
    /* A polyline with one point draws nothing, so the first minute after a
     * boot would show an empty box -- repeat it as a short dash instead. */
    if (rn == 1) snprintf(rout, rsize, "232,%u 236,%u", ry, ry);
    /* At the sample's own x, not at the right edge: a lone temperature reading
     * can sit anywhere in the hour, and a dash on the right claims "now". */
    if (tn == 1)
    {
        unsigned x = tk * 4;
        snprintf(tout, tsize, "%u,%u %u,%u", x >= 4 ? x - 4 : 0, ty, x, ty);
    }
}

/* One place decides which of the three states the hour label reports, so the
 * page and /status.json can never disagree about it. */
static void hist_scale_text(const hist_view_t *v, char *out, size_t size)
{
    if (!v->nvalid)     snprintf(out, size, "%s", T(S_HIST_WAIT));
    /* Not S_ACTIVITY_NONE: that one says "none since boot" and would contradict
     * the message counter right above it. Goes to textContent, so no entities. */
    else if (!v->nrate) snprintf(out, size, "%s", T(S_HIST_IDLE));
    else snprintf(out, size, "%s %lu/min", T(S_ACTIVITY_SCALE),
                  (unsigned long)v->peak);
}

#ifdef CONFIG_ENABLE_TEMPERATURE
/* The dash and the degree sign come from the caller: the page needs HTML
 * entities, /status.json the literal UTF-8 that arApply writes as text. */
static void hist_band_text(const hist_view_t *v, char *out, size_t size,
                           const char *dash, const char *deg)
{
    if (v->ttemp)       snprintf(out, size, "%d%s%d%s", v->tlo, dash, v->thi, deg);
    else if (v->nvalid) snprintf(out, size, "%s", dash);
    else                snprintf(out, size, "%s", T(S_HIST_WAIT));
}
#endif

/* One place decides, so the page and /status.json cannot disagree. The formats come from the
 * table like S_SD_USED_OF, so -Wformat-truncation cannot size them. Their worst case is
 * counted by hand instead. */
static long rx_quiet_view(char *rxq, size_t qcap, char *rxw, size_t wcap,
                          const char *chan_str, const char *lc)
{
    rxq[0] = '\0';
    rxw[0] = '\0';
    long quiet = web_rx_quiet_s();
    if (quiet < WEB_RX_QUIET_SEC)
        return quiet;
    char dur[FMT_DUR_MAX];
    fmt_dur((uint32_t)quiet, FMT_DUR_TWO, dur, sizeof(dur));
    snprintf(rxq, qcap, "%s %s", T(S_PEER_NODATA), dur);
    /* Ethernet capture has no radio to describe. */
    if (sniffer_get_channel() == 0)
        return quiet;
    sniffer_rx_quality_t q;
    sniffer_get_rx_quality(&q);
    /* 68 of 96 at worst. The channel is set in the reception group. */
    char ch[96];
    snprintf(ch, sizeof(ch), "<a href='/settings?lang=%s#g-rx'>%s</a>", lc, chan_str);
    if (q.nf_frames)
    {
        /* The plain hyphen-minus of every dBm value: 4 at most, 11 with %d at its widest. */
        char nf[24];
        snprintf(nf, sizeof(nf), "%d", q.nf_avg);
        snprintf(rxw, wcap, T(S_RX_QUIET_HEARS), ch, (unsigned long)q.broken, nf);
    }
    else
        snprintf(rxw, wcap, T(S_RX_QUIET_DEAF), ch);
    return quiet;
}

/* Builds the per-type count breakdown text, e.g. "CAM 812 &middot; RSU
 * SPATEM 449" (empty if nothing received yet -- caller substitutes the
 * "no activity" string). Shared between the page and /status.json. */
static void build_typeline_html(char *out, size_t out_size)
{
    static msg_type_stat_t type_snapshot[MSG_TYPE_STATS_SLOTS];
    uint32_t other = 0;
    if (msg_ring_mutex && xSemaphoreTake(msg_ring_mutex, pdMS_TO_TICKS(100)) == pdTRUE)
    {
        memcpy(type_snapshot, msg_type_stats, sizeof(type_snapshot));
        other = msg_type_stats_other;
        xSemaphoreGive(msg_ring_mutex);
    }
    else
    {
        memset(type_snapshot, 0, sizeof(type_snapshot));
    }

    out[0] = '\0';
    size_t tl = 0;
    for (size_t i = 0; i < MSG_TYPE_STATS_SLOTS; i++)
    {
        if (type_snapshot[i].label[0] == '\0')
            continue;
        char typeesc[WEB_MSG_TYPE_LEN * 6];
        html_escape(type_snapshot[i].label, typeesc, sizeof(typeesc));
        int n = snprintf(out + tl, out_size - tl, "%s%s %lu",
            tl ? " &middot; " : "", typeesc, (unsigned long)type_snapshot[i].count);
        if (n > 0 && (size_t)n < out_size - tl)
            tl += (size_t)n;
        else
            out[tl] = '\0';   /* snprintf left a cut piece there, a half "&midd" on the page */
    }
    /* Last, and only when it happened: with all 24 slots on distinct labels
     * every further type would vanish from the row while still counting
     * towards the total above it. */
    if (other)
    {
        int n = snprintf(out + tl, out_size - tl, "%s%s %lu",
            tl ? " &middot; " : "", T(S_CAT_OTHER), (unsigned long)other);
        if (n > 0 && (size_t)n < out_size - tl)
            tl += (size_t)n;
        else
            out[tl] = '\0';
    }
}

/* The status page's "Activity" sparklines and message-type breakdown, from
 * the counters webserver_handle_packet already fills in. */
/* The hour line arrives finished: its caller draws the temperature line from
 * the SAME snapshot, and a second pass here could disagree with it. */
static void render_activity_stats(httpd_req_t *req, const char *hourpts,
                                  const char *hourscale)
{
    /* Sent as separate chunks: the point list is built before the label,
     * because the label has to name the scale it was drawn against. */
    uint32_t peak = 0;
    static EXT_RAM_BSS_ATTR char spark[512];
    build_spark_points(spark, sizeof(spark), &peak);

    /* The two halves below cover DIFFERENT periods, so each names its own.
     * Under a single heading the type totals read as a 60 s snapshot. */
    char scaletxt[48];
    snprintf(scaletxt, sizeof(scaletxt), "%s %lu/s", T(S_ACTIVITY_SCALE),
             (unsigned long)peak);
    /* Opens the section. The matching </div> goes out with the type hint at the
     * end of this function, so everything in between belongs to the group. */
    char sparklbl[320];
    HTML_PRINTF(sparklbl,
        "<div class='grp' id='sec-act'><h2>%s</h2>"
        "<div class='lbl'>%s &middot; <span id='st-sparkmax'>%s</span></div>",
        T(S_ACTIVITY_TITLE), T(S_ACTIVITY_SPARK), scaletxt);
    httpd_resp_send_chunk(req, sparklbl, HTTPD_RESP_USE_STRLEN);

    /* id='st-spark' kept though unused: an older tab still polling would throw
     * on a null element. vector-effect: else the stroke stretches with x. */
    char svgopen[320];
    HTML_PRINTF(svgopen,
        "<div class='spark'>"
        "<svg id='st-spark' viewBox='0 0 %d 40' width='100%%' height='40' preserveAspectRatio='none'>"
        "<polyline id='st-sparkl' fill='none' stroke='#f2b134' stroke-width='2'"
        " vector-effect='non-scaling-stroke' points='",
        (SPARK_POINTS - 1) * 4);
    httpd_resp_send_chunk(req, svgopen, HTTPD_RESP_USE_STRLEN);
    /* Same guard as the hour list below: today this one always fills, but an
     * empty string here would silently truncate the page. */
    if (spark[0])
        httpd_resp_send_chunk(req, spark, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "'/></svg></div>", HTTPD_RESP_USE_STRLEN);

    /* Same quantity one window up: the minute line answers "is it receiving
     * now", the hour line "has it been receiving all along". */
    char hourlbl[512];
    HTML_PRINTF(hourlbl,
        "<div class='lbl sp'>%s &middot; <span id='st-hourmax'>%s</span></div>"
        "<div class='spark sm'>"
        "<svg viewBox='0 0 %d 40' width='100%%' height='40' preserveAspectRatio='none'>"
        "<polyline id='st-hourl' fill='none' stroke='#f2b134' stroke-width='2'"
        " vector-effect='non-scaling-stroke' points='",
        T(S_HIST_HOUR), hourscale, (HIST_MINUTES - 1) * 4);
    httpd_resp_send_chunk(req, hourlbl, HTTPD_RESP_USE_STRLEN);
    /* Never send this one blind: a zero-length chunk ENDS the response, and the
     * list is empty for the first minute after a boot, before any sample. */
    if (hourpts[0])
        httpd_resp_send_chunk(req, hourpts, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "'/></svg></div>", HTTPD_RESP_USE_STRLEN);

    static EXT_RAM_BSS_ATTR char typeline[1024];
    build_typeline_html(typeline, sizeof(typeline));
    char typeblock[1408];
    snprintf(typeblock, sizeof(typeblock),
        "<div class='lbl sp'>%s</div><div class='types' id='st-type'>%s</div>",
        T(S_ACTIVITY_TYPES), typeline[0] ? typeline : T(S_ACTIVITY_NONE));
    httpd_resp_send_chunk(req, typeblock, HTTPD_RESP_USE_STRLEN);

    /* Pieces, not a buffer, because S_TYPE_HINT grows with every message type. It once
     * reached 751 of 768 bytes. */
    web_send_parts(req, "<p class='note hlp'>", T(S_TYPE_HINT), "</p></div>", NULL);
}

/* ================================================================== */
/*  GET /  -- status dashboard                                        */
/* ================================================================== */

esp_err_t status_page_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* Links and the /poweroff POST carry the language. Without ?lang= a link follows the
     * browser's language, and a POST stays German. */
    const char *lc = web_lang() == LANG_DE ? "de" : "en";

    char nodeid[CONFIG_NODEID_BUFFER_SIZE] = {0};
    size_t nodeid_size = sizeof(nodeid);
    config_get_str(CONFIG_INDEX_NODEID, nodeid, &nodeid_size);
    char nodeid_esc[CONFIG_NODEID_BUFFER_SIZE * 6];
    html_escape(nodeid, nodeid_esc, sizeof(nodeid_esc));

    uint8_t mac[6];
    ethernet_get_mac(mac);

    const esp_app_desc_t *app_desc = esp_app_get_description();
    uint64_t uptime_s = esp_timer_get_time() / 1000000ull;
    char uptime_str[FMT_DUR_MAX];
    fmt_dur(uptime_s > UINT32_MAX ? UINT32_MAX : (uint32_t)uptime_s, FMT_DUR_TWO,
            uptime_str, sizeof(uptime_str));

    uint32_t channel = sniffer_get_channel();
    bool running = sniffer_is_running();
    uint32_t rate = rate_packets_last_minute();
    /* Memory details are on /system, which is their single source of truth.
     * This page shows operational state only. */

    const char *chan_name;
    switch (channel)
    {
    case 5900: chan_name = "G5CC";  break;
    case 5890: chan_name = "G5SC2"; break;
    case 5880: chan_name = "G5SC1"; break;
    case 5870: chan_name = "G5SC3"; break;
    case 5860: chan_name = "G5SC4"; break;
    default:   chan_name = NULL;    break;
    }
    /* The empty value of every page. /status.json keeps '-', which external readers expect. */
    char chan_str[32];
    if (channel && chan_name)
        snprintf(chan_str, sizeof(chan_str), "%s (%lu MHz)", chan_name, (unsigned long)channel);
    else
        snprintf(chan_str, sizeof(chan_str), "&ndash;");
    /* Silence while receiving: the tile text and the state line under the top row.
     * 32 of 96 and 234 of 512 (German). */
    char rxq[96];
    static EXT_RAM_BSS_ATTR char rxw[512];
    rx_quiet_view(rxq, sizeof(rxq), rxw, sizeof(rxw), chan_str, lc);
    const char *ratecls = !running ? "v-off" : rxq[0] ? "v-bad" : "v-ok";

    send_page_header_refresh(req, T(S_TITLE_STATUS),
                             web_lang() == LANG_EN ? "/status.json?lang=en"
                                                     : "/status.json?lang=de");
    /* What the device is, for a first visit. It is an explanation, so the switch hides it. */
    web_send_parts(req, "<p class='note hlp' id='st-lead'>", T(S_START_LEAD), "</p>", NULL);

    /* The AutoIP notice from /system, hidden when not needed. The poll shows or hides it. */
    static EXT_RAM_BSS_ATTR char autoip[768];
    web_autoip_note(autoip, sizeof(autoip), !web_autoip_active(), "st-autoip");
    httpd_resp_send_chunk(req, autoip, HTTPD_RESP_USE_STRLEN);

    bool has_peers = false;
    {
        /* Two charts stand between the top of the page and the device group,
         * so the figures most often looked up sit below a screenful. */
        char peers_probe[CONFIG_PEERS_BUFFER_SIZE] = "";
        size_t pp = sizeof(peers_probe);
        config_get_str(CONFIG_INDEX_PEERS, peers_probe, &pp);
        has_peers = peers_probe[0] != '\0';
        /* Always sent: the road, activity, device and control groups are on every start page,
         * so there are four targets even without peers, and a jump row needs three. The peer
         * link only with peers: 55 of 64; the row 251 of 320 (German), 259 with the peer link at
         * its buffer size. */
        char peerjump[64] = "";
        if (has_peers)
            HTML_PRINTF(peerjump, " &middot; <a href='#sec-peer'>%s</a>", T(S_PEER_TITLE));
        char stjump[320];
        HTML_PRINTF(stjump,
            "<p class='jump'>%s: <a href='#sec-road'>%s</a> &middot; "
            "<a href='#sec-act'>%s</a> &middot; <a href='#sec-dev'>%s</a>%s &middot; "
            "<a href='#sec-ctl'>%s</a></p>",
            T(S_TRF_JUMP), T(S_NAV_G_ROAD), T(S_ACTIVITY_TITLE), T(S_SYS_GRP_DEVICE), peerjump,
            T(S_CTRL_TITLE));
        httpd_resp_send_chunk(req, stjump, HTTPD_RESP_USE_STRLEN);
    }

    /* SD usage answers "is the card filling up" at a glance, and its state says whether
     * anything is recorded. Static like hourr: only the httpd task runs this handler. */
    static EXT_RAM_BSS_ATTR sd_tile_t sdt;
    sd_tile(&sdt, NULL, NULL, NULL);
    /* The crash tile, with the same rule as the cell on /system: red while the fault bar shows
     * the crash, then amber up to 7 days (web_faults_crash_cls). 51 of 64 at most. */
    char lastcrash[64];
    bool crash_recent = web_crash_summary(lastcrash, sizeof(lastcrash));
    /* MQTT target and, while down, since when and why: 67 and 106 at most.
     * MQTT down is amber like its fault-bar line, a warning and not an alarm. */
    mqtt_state_t mst;
    mqtt_get_state(&mst);
    char mqtgt[96];
    web_mqtt_target(&mst, mqtgt, sizeof(mqtgt));
    char mqdet[160];
    web_mqtt_detail(&mst, "&middot;", mqdet, sizeof(mqdet));

#ifdef CONFIG_ENABLE_TEMPERATURE
    /* Read once: the class and the number must not come from two samples,
     * and a failed read prints "nan" unless it is caught here. */
    float tc = temperature_get();
    char tstr[64];
    /* Range check, not just NaN: a wild reading would push the closing tag out
     * of the buffer, and a cut </span> swallows the rest of the page. */
    if (tc == tc && tc > -100.0f && tc < 200.0f)
    {
        /* The page's decimal separator, rounded like the poll's toFixed. */
        char tn[16];
        fmt_dec(tc, 1, false, web_lang(), tn, sizeof(tn));
        snprintf(tstr, sizeof(tstr), "%s<span class='e'>&deg;C</span>", tn);
    }
    else
        snprintf(tstr, sizeof(tstr), "&ndash;");
#endif

    /* id='st-*' on every cell that /status.json can update. See arApply below. */
    /* One buffer for both halves: the second call only runs once the first
     * chunk is out, and the httpd task's stack is 16 KB in total. */
    /* 3584 against measured worst cases of 717 (top row) and 1597 (device group: SD text 202,
     * MQTT target, detail and last crash at their buffers), German. */
    char body[3584];
    /* No heading on the top row, because its position says enough. The rate depends on
     * reception, so channel, silence and sniffer state go under the rate. The uptime takes
     * no colour. A stop is deliberate, so it is grey like the label (v-off). There is no
     * start-failure flag and no red. */
    HTML_PRINTF(body,
        "<div class='grid'>"
        "<div class='cell'><div class='l'>%s</div>"
        "<div class='v' id='st-msgs'>%lu</div><div class='d'>%s</div></div>"
        "<div class='cell'><div class='l %s' id='st-ratel'>%s</div>"
        "<div class='v' id='st-rate'>%lu</div>"
        "<div class='d'><span id='st-quiet'>%s%s</span>%s <span id='st-chan'>%s</span>"
        "<br>%s <span class='%s' id='st-sniff'>%s</span></div></div>"
        "<div class='cell wide'><div class='l' id='st-upl'>%s</div>"
        "<div class='v' id='st-uptime'>%s</div></div>"
        "</div>",
        T(S_MSGS_RECEIVED), (unsigned long)msg_total_count, T(S_SINCE_BOOT),
        ratecls, T(S_RATE), (unsigned long)rate,
        rxq, rxq[0] ? " &middot; " : "", T(S_CHANNEL), chan_str,
        T(S_SNIFFER), running ? "v-ok" : "v-off",
        running ? T(S_RUNNING) : T(S_STOPPED),
        T(S_UPTIME), uptime_str);
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);
    /* A state, not an explanation, so no hlp. Hidden instead of absent, so the poll can show
     * it. The sign comes from s.css. */
    web_send_parts(req, "<div class='warn' id='st-rx'", rxw[0] ? "" : " hidden",
                   "><p><span id='st-rxt'>", rxw, "</span></p></div>", NULL);

    /* The street at a glance: what the lights, trams and warnings are doing now. */
    static EXT_RAM_BSS_ATTR gl_view_t glv;
    web_glance_view(&glv);
    web_glance_send(req, &glv, lc, has_peers);

    /* ONE snapshot for both hour charts: the rate line below and the
     * temperature line further down have to describe the same minute. */
    /* Only the httpd task ever runs this handler (no defer_to_worker), so
     * static is safe here and keeps 1 KB off its 16 KB stack. */
    static EXT_RAM_BSS_ATTR char hourr[512], hourt[512];
    hist_view_t hv;
    build_hour_points(hourr, sizeof(hourr), hourt, sizeof(hourt), &hv);
    char hscale[64];
    hist_scale_text(&hv, hscale, sizeof(hscale));
#ifdef CONFIG_ENABLE_TEMPERATURE
    char hband[48];
    hist_band_text(&hv, hband, sizeof(hband), "&ndash;", "&nbsp;&deg;C");
#endif

    render_activity_stats(req, hourr, hscale);

    /* /sdcard exists only with SD support. Without it the label stays plain text.
     * 38 of 64 at worst: the longer text plus the two-letter language code. */
    char sdlabel[64];
#if CONFIG_ENABLE_SD
    HTML_PRINTF(sdlabel, "<a href='/sdcard?lang=%s'>%s</a>", lc, T(S_SD_CARD));
#else
    HTML_PRINTF(sdlabel, "%s", T(S_SD_CARD));
#endif

    /* The labels link to the page with the remedy. The <a> is inside the label div,
     * so cls() in arApply replaces the class without touching it. The SD ids are on inner
     * spans, because a fallback regex of an external reader needs <div class='v'> and
     * <div class='d'> bare. */
    HTML_PRINTF(body,
        "<div class='grp' id='sec-dev'><h2>%s</h2><div class='grid'>"
        "<div class='cell'><div class='l %s' id='st-sdl' title='%s'>%s</div>"
        "<div class='v'><span id='st-sdv'>%s</span></div>"
        "<div class='d'><span id='st-sdd'>%s</span></div></div>"
#ifdef CONFIG_ENABLE_TEMPERATURE
        "<div class='cell'><div class='l %s' id='st-templ'>%s</div>"
        "<div class='v %s' id='st-temp'>%s</div></div>"
#endif
        "<div class='cell wide'><div class='l %s' id='st-mqttl'><a href='/settings?lang=%s#g-mqtt'>%s</a></div>"
        "<div class='v' id='st-mqtt'>%s</div>%s%s%s"
        "<div class='d' id='st-mqttd'%s>%s</div></div>"
        "<div class='cell'><div class='l %s'><a href='/system?lang=%s#s-stab'>%s</a></div>"
        "<div class='v'>%lu</div><div class='d'>%s: %s</div><div class='d'>%s: %s</div></div>"
        /* Closes .grid only. The group stays open past this chunk so the
         * temperature strip below can still land inside it. */
        "</div>",
        T(S_SYS_GRP_DEVICE),
        sdt.cls, sdt.title, sdlabel, sdt.val, sdt.txt,
#ifdef CONFIG_ENABLE_TEMPERATURE
        temp_class(tc), T(S_TEMPERATURE), temp_class(tc), tstr,
#endif
        mqtt_connected_state ? "v-ok" : "v-warn", lc, T(S_MQTT),
        mqtt_connected_state ? T(S_CONNECTED) : T(S_DISCONNECTED),
        mqtgt[0] ? "<div class='d'>" : "", mqtgt, mqtgt[0] ? "</div>" : "",
        mqdet[0] ? "" : " hidden", mqdet,
        web_faults_crash_cls(crash_recent), lc, T(S_STAT_CRASHES),
        (unsigned long)sysstat_crash_count(),
        T(S_STAT_LASTCRASH), lastcrash, T(S_SYS_RESET), web_reset_reason());
    httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);

#ifdef CONFIG_ENABLE_TEMPERATURE
    /* Own chunk, and only when there is something to draw: a sensor that never
     * answers would leave a labelled 56px box with nothing in it. */
    if (hv.ttemp || !hv.nvalid)
    {
        /* Reuses body: it went out as a chunk a few lines up, and a second
         * kilobyte on the httpd stack would buy nothing. */
        HTML_PRINTF(body,
            "<div class='lbl sp'>%s &middot; <span id='st-tempband'>%s</span></div>"
            "<div class='spark sm'>"
            "<svg viewBox='0 0 %d 40' width='100%%' height='40' preserveAspectRatio='none'>"
            /* Link blue, not --warn: a permanently orange curve reads as a
             * standing warning about the temperature. */
            "<polyline id='st-temphl' fill='none' stroke='#4fb8e0' stroke-width='2'"
            " vector-effect='non-scaling-stroke' points='%s'/></svg></div>",
            T(S_HIST_TEMP), hband, (HIST_MINUTES - 1) * 4, hourt);
        httpd_resp_send_chunk(req, body, HTTPD_RESP_USE_STRLEN);
    }
#endif
    /* Node ID, MAC and version change only with a save or an update, so they are one small
     * line instead of two tiles of fixed values. The links lead to the node ID setting and
     * to the firmware update. */
    /* 580 of 768 (node id escaped 378). Static: only the httpd task runs this handler. */
    static EXT_RAM_BSS_ATTR char devid[768];
    HTML_PRINTF(devid,
        "<div class='sub devid'><a href='/settings?lang=%s#g-gen'>%s</a> %s &middot; "
        "%s %02x:%02x:%02x:%02x:%02x:%02x &middot; <a href='/update?lang=%s'>%s</a> %s</div>",
        lc, T(S_NODEID), nodeid_esc[0] ? nodeid_esc : "&ndash;",
        T(S_MAC), mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
        lc, T(S_FW_VERSION), app_desc->version);
    httpd_resp_send_chunk(req, devid, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);

    /* Applies /status.json to the cells; innerHTML because labels can carry
     * entities, and the Start/Stop button swaps label+action in the same pass. */
    /* className REPLACES the class list, so every id that also carries a layout
     * class ('v', 'l') has to get that class written back with it. */
    /* Off the stack and grown: a truncated script would take the whole poll down, not just
     * one cell. 2896 of 3072 (German). */
    static EXT_RAM_BSS_ATTR char applyscript[3072];
    HTML_PRINTF(applyscript,
        "<script>(function(){"
        /* The page's decimal separator, as the server wrote the tile. */
        "var DS=document.documentElement.lang=='de'?',':'.';"
        "var RUN='%s',STOP='%s',CONN='%s',DISC='%s',BSTART='%s',BSTOP='%s',SCL='%s';"
        "function cls(i,c){var e=document.getElementById(i);if(e)e.className=c;}"
        /* q = silent while receiving. A Stop click turns the label and the state grey and
         * drops the silence at once, not after the next poll. Pills belong in table cells. */
        "window.stSetSniff=function(r,q){"
        "var sn=document.getElementById('st-sniff');sn.className=r?'v-ok':'v-off';sn.innerHTML=r?RUN:STOP;"
        "cls('st-ratel','l '+(!r?'v-off':q?'v-bad':'v-ok'));"
        "if(!r||!q){var x=document.getElementById('st-quiet');if(x)x.innerHTML='';"
        "x=document.getElementById('st-rx');if(x)x.hidden=true;}"
        "var sb=document.getElementById('st-sniffbtn');"
        "if(sb){sb.textContent=r?BSTOP:BSTART;sb.setAttribute('data-action',r?'stop':'start');}"
        "};"
        "window.arApply=function(d){"
        /* Otherwise the clock freezes on the minute the page was loaded. */
        "var ck=document.getElementById('st-clk');"
        "if(ck&&d.clk!==undefined)ck.textContent=d.clk;"
        "var ai=document.getElementById('st-autoip');"
        "if(ai&&d.eth_autoip!==undefined)ai.hidden=!d.eth_autoip;"
        "document.getElementById('st-msgs').textContent=d.msgs;"
        "document.getElementById('st-rate').textContent=d.rate;"
        /* up_s in the page's duration format. uptime keeps its spelling for other readers. */
        "document.getElementById('st-uptime').textContent=itsDur(d.up_s,0);"
        /* '-' is the JSON's empty channel for other readers. The page shows an en dash. */
        "document.getElementById('st-chan').textContent=d.chan==='-'?'\u2013':d.chan;"
        /* setAttribute, not innerHTML: the polyline is one SVG element. */
        "var sl=document.getElementById('st-sparkl');"
        "if(sl&&d.sparkp!==undefined)sl.setAttribute('points',d.sparkp);"
        "var sm=document.getElementById('st-sparkmax');"
        "if(sm&&d.smax!==undefined)sm.textContent=SCL+' '+d.smax+'/s';"
        /* The hour label arrives finished -- it has three forms, and picking
         * between them in JS would need the texts a second time. */
        "var hl=document.getElementById('st-hourl');"
        "if(hl&&d.hrp!==undefined)hl.setAttribute('points',d.hrp);"
        "var hm=document.getElementById('st-hourmax');"
        "if(hm&&d.hrs!==undefined)hm.textContent=d.hrs;"
        "var tl=document.getElementById('st-temphl');"
        "if(tl&&d.htp!==undefined)tl.setAttribute('points',d.htp);"
        "var tb=document.getElementById('st-tempband');"
        "if(tb&&d.htb!==undefined)tb.textContent=d.htb;"
        "document.getElementById('st-type').innerHTML=d.types;"
        /* The silence text and the state line come finished from rx_quiet_view(). */
        "var qe=document.getElementById('st-quiet');"
        "if(qe&&d.rxq!==undefined)qe.innerHTML=d.rxq?d.rxq+' &middot; ':'';"
        "var rw=document.getElementById('st-rx'),rt=document.getElementById('st-rxt');"
        "if(rw&&rt&&d.rxw!==undefined){rw.hidden=!d.rxw;rt.innerHTML=d.rxw;}"
        "window.stSetSniff(d.sniff,!!d.rxq);"
        "document.getElementById('st-mqtt').innerHTML=d.mqtt?CONN:DISC;"
        /* textContent: mqtt_d is raw UTF-8. A node without the field leaves the line alone. */
        "var md=document.getElementById('st-mqttd');"
        "if(md&&d.mqtt_d!==undefined){md.textContent=d.mqtt_d;md.hidden=!d.mqtt_d;}"
        "cls('st-mqttl','l '+(d.mqtt?'v-ok':'v-warn'));"
        /* The SD cell as sd_tile() drew it; cls() keeps the link inside the label. */
        "var su=d.sdui;if(su){cls('st-sdl','l '+su.c);var se=document.getElementById('st-sdl');"
        "if(se)se.title=su.t;se=document.getElementById('st-sdv');if(se)se.innerHTML=su.v;"
        "se=document.getElementById('st-sdd');if(se)se.innerHTML=su.d;}"
        /* null = sensor not answering; the class has to follow the value,
         * or the colour freezes on whatever the page was loaded with. */
        "var te=document.getElementById('st-temp');"
        "if(te&&d.temp!==undefined&&d.temp!==null){"
        "te.innerHTML=d.temp.toFixed(1).replace('.',DS)+'<span class=e>\\u00b0C</span>';"
        "te.className='v '+(d.tcl||'');cls('st-templ','l '+(d.tcl||''));}"
        /* The type line as links (web_glance.c). */
        "if(window.glApply)window.glApply(d);"
        /* Defined by the peer block below, which is skipped without peers. It draws the own
         * row from this answer. */
        "if(window.peerPoll)window.peerPoll(d);"
        "};})();</script>",
        T(S_RUNNING), T(S_STOPPED), T(S_CONNECTED), T(S_DISCONNECTED),
        T(S_SNIFF_START), T(S_SNIFF_STOP), T(S_ACTIVITY_SCALE));
    httpd_resp_send_chunk(req, applyscript, HTTPD_RESP_USE_STRLEN);
    /* The entries of the type line become links to their pages. This defines glApply. */
    web_glance_script(req, lc);

    /* Neighbours at a glance: without this table every receiver needs its own
     * browser tab, and the comparison between them is the actual information. The own
     * device is the first row, so the comparison needs no scrolling back to the tiles. */
    {
        char peers_cfg[CONFIG_PEERS_BUFFER_SIZE] = "";
        size_t psz = sizeof(peers_cfg);
        config_get_str(CONFIG_INDEX_PEERS, peers_cfg, &psz);
        if (peers_cfg[0])
        {
            char plist[CONFIG_PEERS_BUFFER_SIZE * 2] = {0};
            size_t o = 0;
            bool first = true, open_q = false;
            for (const char *p = peers_cfg; *p && o + 4 < sizeof(plist); p++)
            {
                bool ok = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                          (*p >= '0' && *p <= '9') || *p == '.' || *p == '-' || *p == ':';
                if (ok)
                {
                    if (!open_q)
                    {
                        if (!first) plist[o++] = ',';
                        plist[o++] = '"';
                        open_q = true; first = false;
                    }
                    plist[o++] = *p;
                }
                else if (open_q) { plist[o++] = '"'; open_q = false; }
            }
            if (open_q && o + 1 < sizeof(plist)) plist[o++] = '"';
            plist[o] = '\0';

            /* 4067 of 5120 (a full peer list of 319, the street tile's gp()): a cut
             * script kills the whole table. Static, because only the httpd task runs this. */
            static EXT_RAM_BSS_ATTR char peerblk[5120];
            /* The literal %% below is a percent sign, not a conversion. */
            HTML_PRINTF(peerblk,
                /* Still a table, because rows compare across peers better than tiles would.
                 * The small line under the first head is the legend of the one in every row. */
                "<div class='grp' id='sec-peer'><h2>%s</h2>"
                "<div class='scroll'><table id='peertbl'><thead><tr>"
                "<th>%s<div class='sub'>%s &middot; %s &middot; %s</div></th>"
                "<th>%s</th><th>%s</th><th>%s</th></tr></thead>"
                "<tbody id='peerbody'></tbody></table></div>"
                "<script>(function(){var P=[%s];var B=document.getElementById('peerbody');"
                "if(!P.length){return;}"
                "var ND='%s',OLD='%s',OFF='%s',LAST='%s',AP='%s',AS='%s',SELF='%s',STOP='%s',"
                /* LQ: links to the other receivers keep this page's language. DS: the
                 * page's decimal separator. Durations come from itsDur. */
                "WT='%s',IDLE=%d,R={},T={},A={},busy=false,LQ=document.documentElement.lang,"
                "DS=document.documentElement.lang=='de'?',':'.';"
                /* Everything a peer sends goes through esc() or a number cast: a foreign server
                 * on the list must not write markup into this page. */
                "function esc(s){return String(s).replace(/[&<>\"']/g,"
                "function(c){return '&#'+c.charCodeAt(0)+';';});}"
                /* Only the four firmware classes get through. */
                "function kl(c){return /^v-(ok|warn|bad|off)$/.test(c)?c:'';}"
                /* SELF and the host are our own text and are not escaped again. s: a state line
                 * for a row without data; the first cell is the one a phone always shows. */
                "function nm(h,d,s){var n=d&&d.node?esc(d.node):(h||SELF),"
                "a=h?\"<a href='http://\"+h+\"/?lang=\"+LQ+\"'>\"+n+'</a>':n;"
                "if(!d)return '<td>'+a+(s?\"<div class='sub'>\"+s+'</div>':'')+'</td>';"
                "var o=h||(d.node?SELF:'');return '<td>'+a+\"<div class='sub'>\""
                /* A peer on older firmware sends no up_s, only its uptime text. */
                "+(o?o+' &middot; ':'')+(d.up_s!==undefined?itsDur(+d.up_s,0):esc(d.uptime))+' &middot; '"
                "+(d.mqtt?\"<span class='v-ok'>MQTT &#10003;</span>\":\"<span class='v-warn'>MQTT &#10007;</span>\")"
                "+'</div></td>';}"
                /* quiet (new firmware) counts from the start of reception. d.msgs===0 also
                 * catches peers still on firmware without idle: the deaf-since-boot case. */
                "function qs(d){return d.quiet!==undefined?(d.quiet>=IDLE?itsDur(d.quiet,0):''):"
                "(((d.idle!==undefined)?(d.idle<0||d.idle>=IDLE):(d.msgs===0))?"
                "(d.idle>0?itsDur(d.idle,0):(d.up_s!==undefined?itsDur(+d.up_s,0):esc(d.uptime))):'');}"
                "function rt(d){if(d.sniff===false)return \"<td class='st'><span class='v-off'>\"+STOP+'</span></td>';"
                "var s=qs(d);"
                "return s?\"<td><span class='bad'>\"+ND+' '+s+'</span></td>':'<td>'+(+d.rate)+'</td>';}"
                /* warn_active counts the peer's active DENM warnings, so it is named as such
                 * and links there. */
                "function st(h,d){var p=[];if(d.sd&&d.sd.reason!=='no_sd_build')"
                "p.push(\"<span class='\"+kl(d.sdui?d.sdui.c:'')+\"'>SD \""
                "+(d.sd.ok?(+d.sd.pct)+'&nbsp;%%':'&ndash;')+'</span>');"
                "if(typeof d.temp==='number')p.push(\"<span class='\"+kl(d.tcl)+\"'>\""
                "+d.temp.toFixed(1).replace('.',DS)+'&nbsp;&deg;C</span>');"
                "if(d.warn_active>0)p.push(\"<a href='\"+(h?'http://'+h:'')+\"/traffic?lang=\"+LQ+\"#denm'>\""
                "+WT+': '+(+d.warn_active)+'</a>');"
                "return '<td>'+p.join(' &middot; ')+'</td>';}"
                "function row(h,d){return nm(h,d)+rt(d)+st(h,d)+'<td>'+(d.fw?esc(d.fw):'&ndash;')+'</td>';}"
                "function one(h){var tr=R[h];"
                "return fetch('http://'+h+'/status.json',{cache:'no-store'})"
                ".then(function(r){return r.json();}).then(function(d){"
                "T[h]=Date.now();A[h]=d;tr.innerHTML=row(h,d);})"
                /* A blocked cross-origin read and a dead host both land in
                 * catch(). A no-cors probe tells them apart, so an older peer
                 * is not reported as offline. */
                ".catch(function(){"
                "return fetch('http://'+h+'/status.json',{mode:'no-cors',cache:'no-store'})"
                /* The state goes under the name: a sentence in the colspan cell took the 17px
                 * figure face and ran off a phone screen, where .sub lines wrap. */
                ".then(function(){A[h]=1;tr.innerHTML=nm(h,null,\"<span class='v-warn'>\"+OLD+'</span>')"
                "+'<td colspan=3>&ndash;</td>';})"
                /* The request runs in this browser, so the text says whose view it is. It is a
                 * warning, not an alarm. The last good answer stays only while the page is open. */
                ".catch(function(){A[h]=0;tr.innerHTML=nm(h,null,\"<span class='v-warn'>\"+OFF+'</span>'"
                "+(T[h]?' &middot; '+LAST+' '+(AP?AP+' ':'')+itsDur(Math.round((Date.now()-T[h])/1000),1)"
                "+(AS?' '+AS:''):''))+'<td colspan=3>&ndash;</td>';});"
                "});}"
                /* Re-polled from arApply: the idle time is a DURATION, and a frozen one still
                 * claims 12s of silence hours later. The own row comes from the answer
                 * arApply already has. */
                /* The street row's tile: n of m answer, q of them do not receive. An old
                 * firmware (no-cors answer) counts as answering. */
                "function gp(){if(!window.glPeer)return;var n=0,q=0;P.forEach(function(h){var d=A[h];"
                "if(d){n++;if(d!==1&&(d.sniff===false||qs(d)))q++;}});window.glPeer(n,P.length,q);}"
                "window.peerPoll=function(d){if(d)R[''].innerHTML=row('',d);if(busy)return;busy=true;"
                "Promise.all(P.map(function(h){return one(h);})).then(function(){busy=false;gp();},"
                "function(){busy=false;gp();});};"
                "[''].concat(P).forEach(function(h){var tr=document.createElement('tr');"
                "tr.innerHTML=nm(h)+'<td colspan=3>&hellip;</td>';B.appendChild(tr);R[h]=tr;});"
                /* Only a paused page fetches its own row once. */
                "if(window.itsLive&&itsLive.paused())fetch('/status.json',{cache:'no-store'})"
                ".then(function(r){return r.json();}).then(function(d){R[''].innerHTML=row('',d);})"
                ".catch(function(){});"
                "window.peerPoll();})();</script></div>",
                T(S_PEER_TITLE), T(S_PEER_NODE), T(S_ETH_IP), T(S_PEER_UPTIME), T(S_PEER_MQTT),
                T(S_RATE), T(S_SYS_COL_STATE), T(S_FW_VERSION), plist,
                T(S_PEER_NODATA), T(S_PEER_OLDFW), T(S_PEER_OFFLINE), T(S_PEER_LASTOK),
                T(S_AGO_PRE), T(S_WARN_AGO), T(S_PEER_SELF), T(S_STOPPED), T(S_EVT_TITLE),
                WEB_RX_QUIET_SEC);
            httpd_resp_send_chunk(req, peerblk, HTTPD_RESP_USE_STRLEN);
        }
    }

    /* The controls go at the end of the page: stopping is rare and must not be where the eye
     * lands. A click does not reload the page. It fetches the toggle, and window.stSetSniff
     * (defined in applyscript above) updates the button and the status span, as a poll would. */
    /* 2048 against 1643 measured. The host buffer check recomputes the worst case on every
     * run and reads the size from the declaration below. HTML_PRINTF, not snprintf, because
     * a cut onclick would silently leave a dead button. Static: only the httpd task calls
     * this. */
    static EXT_RAM_BSS_ATTR char buttons[2048];
    HTML_PRINTF(buttons,
        /* .btnrow keeps these buttons quiet without touching the global amber
         * button, which /settings' own savebar still relies on. */
        "<div class='grp' id='sec-ctl'><h2>%s</h2><p class='btnrow'>"
        "<button id='st-sniffbtn' data-action='%s' onclick=\"var a=this.getAttribute('data-action'),m='%s';"
        /* Only the stop asks: data-action is read at the click, stSetSniff swaps it. */
        "if(a==='stop'&&!confirm('%s'))return;"
        /* r.ok, not "it returned": /sniffer is password-gated, and a rejected
         * request must not flip the label. The status poll re-asserts the truth. */
        /* Without the alert the button would look dead whenever a web password is
         * set. The status number stands in for the generic text (401/500). A 403 of
         * web_csrf.c names its cause, so its text is shown, and ?lang= picks its language. */
        "fetch('/sniffer?lang='+document.documentElement.lang+'&action='+a,{method:'POST'})"
        ".then(function(r){"
        "if(r.status==403)return r.text().then(alert);"
        "if(!r.ok){alert(m+' ('+r.status+')');return;}"
        "if(window.stSetSniff)window.stSetSniff(a==='start');})"
        ".catch(function(){alert(m);})\">%s</button> "
        "<button class='pwr' onclick=\"itsReboot('%s','%s','%s','%s')\">%s</button>"
#if CONFIG_ENABLE_SD
        /* Result goes into its own span rather than replacing the page: if the
         * unmount fails the operator has to stay on the page and see why. */
        " <button class='pwr' onclick=\"if(!confirm('%s'))return;"
        "var s=document.getElementById('po-res');s.innerText='%s';"
        /* 401 is the only status whose body is the httpd default ("Unauthorized", in
         * English, with no hint about the password), because only a page load gets the 401
         * page, not a fetch. Every other outcome already answers a translated sentence, so
         * only this one is replaced. The null hand-off has the same shape as in the /confirm
         * button. */
        "fetch('/poweroff?lang=%s',{method:'POST'}).then(function(r){"
        "if(r.status===401){s.innerText='%s';return null;}return r.text();})"
        ".then(function(t){if(t===null)return;s.innerText=t;})"
        ".catch(function(){s.innerText='%s';})\">%s</button>"
        " <span id='po-res'></span>"
#endif
        "</p></div>",
        T(S_CTRL_TITLE),
        running ? "stop" : "start",
        T(S_SD_ACTION_FAILED), T(S_SNIFF_ASK),
        running ? T(S_SNIFF_STOP) : T(S_SNIFF_START),
        T(S_REBOOT_CONFIRM), T(S_REBOOTING), T(S_REBOOT_SLOW), T(S_REBOOT_DENIED), T(S_REBOOT)
#if CONFIG_ENABLE_SD
        , T(S_POWEROFF_CONFIRM), T(S_POWEROFF_BUSY), lc,
          T(S_POWEROFF_DENIED), T(S_POWEROFF_FAIL), T(S_POWEROFF)
#endif
        );
    httpd_resp_send_chunk(req, buttons, HTTPD_RESP_USE_STRLEN);

    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* GET /status.json -- the dynamic subset of the status page, polled by the
 * script send_page_header_refresh() injects. Keeps the same field set the
 * page itself computes, just as compact JSON instead of HTML. */
esp_err_t status_json_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    bool running = sniffer_is_running();
    uint32_t rate = rate_packets_last_minute();
    uint64_t uptime_s = esp_timer_get_time() / 1000000ull;
    char uptime_str[48];
    format_uptime(uptime_s, uptime_str, sizeof(uptime_str));

    uint32_t channel = sniffer_get_channel();
    const char *chan_name;
    switch (channel)
    {
    case 5900: chan_name = "G5CC";  break;
    case 5890: chan_name = "G5SC2"; break;
    case 5880: chan_name = "G5SC1"; break;
    case 5870: chan_name = "G5SC3"; break;
    case 5860: chan_name = "G5SC4"; break;
    default:   chan_name = NULL;    break;
    }
    char chan_str[32];
    if (channel && chan_name)
        snprintf(chan_str, sizeof(chan_str), "%s (%lu MHz)", chan_name, (unsigned long)channel);
    else
        snprintf(chan_str, sizeof(chan_str), "-");

    /* Middle dot as raw UTF-8: this one goes through textContent, not markup. */
    char clkj[80];
    fmt_clockline(clkj, sizeof(clkj), "\u00b7", web_lang());

    /* The start page's silence text and state line, from the same helper as the page.
     * 32 of 96 and 234 of 512 (German). */
    char rxq[96];
    static EXT_RAM_BSS_ATTR char rxw[512];
    long quiet = rx_quiet_view(rxq, sizeof(rxq), rxw, sizeof(rxw), chan_str,
                               web_lang() == LANG_EN ? "en" : "de");

    /* Exactly one sd_state() call per poll: sdui and sd below come from it. */
    static EXT_RAM_BSS_ATTR sd_tile_t sv;
    sd_state_t sdst;
    uint64_t sdt = 0, sdf = 0;
    sd_tile(&sv, &sdst, &sdt, &sdf);
    /* The SD cell as the start page draws it; sd below stays the machine view. 297 of 512
     * (German), 370 with val and txt full; the texts hold no double quote or backslash
     * (host-tested). */
    static EXT_RAM_BSS_ATTR char sduij[512];
    snprintf(sduij, sizeof(sduij), ",\"sdui\":{\"c\":\"%s\",\"t\":\"%s\",\"v\":\"%s\",\"d\":\"%s\"}",
             sv.cls, sv.title, sv.val, sv.txt);

    /* The node ID for the peer tables of other receivers, and the bare version. json_esc
     * doubles at most a quote or backslash, so twice the input always fits. */
    char node[CONFIG_NODEID_BUFFER_SIZE] = "";
    size_t ns = sizeof(node);
    config_get_str(CONFIG_INDEX_NODEID, node, &ns);
    static EXT_RAM_BSS_ATTR char node_j[CONFIG_NODEID_BUFFER_SIZE * 2];
    static EXT_RAM_BSS_ATTR char fw_j[sizeof(((esp_app_desc_t *)0)->version) * 2];
    web_json_esc(node, node_j, sizeof(node_j));
    web_json_esc(esp_app_get_description()->version, fw_j, sizeof(fw_j));

    /* Raw UTF-8 middle dot: arApply writes mqtt_d with textContent. */
    mqtt_state_t mst;
    mqtt_get_state(&mst);
    char mqdj[160];     /* 100 at most */
    web_mqtt_detail(&mst, "\u00b7", mqdj, sizeof(mqdj));

#ifdef CONFIG_ENABLE_TEMPERATURE
    /* "nan" is not valid JSON and would kill the whole poll, not just this
     * one field, so a failed read goes out as null. */
    float tc = temperature_get();
    /* A JSON number with a point in every language, because other readers and the peers
     * compute with it. Rounded like the tile, so the poll never repaints 46,3 as 46,2. */
    char tval[24];
    if (tc == tc) fmt_dec(tc, 1, false, LANG_EN, tval, sizeof(tval));
    else          snprintf(tval, sizeof(tval), "null");
#endif

    uint32_t peak = 0;
    static EXT_RAM_BSS_ATTR char spark[512];
    build_spark_points(spark, sizeof(spark), &peak);
    static EXT_RAM_BSS_ATTR char typeline[1024];
    build_typeline_html(typeline, sizeof(typeline));

    /* Only the httpd task answers this route, so static is safe here too. */
    static EXT_RAM_BSS_ATTR char hourr[512], hourt[512];
    hist_view_t hv;
    build_hour_points(hourr, sizeof(hourr), hourt, sizeof(hourt), &hv);
    char hscale[64];
    hist_scale_text(&hv, hscale, sizeof(hscale));
#ifdef CONFIG_ENABLE_TEMPERATURE
    /* Literal UTF-8, not entities: arApply writes this one with textContent. */
    char hband[48];
    hist_band_text(&hv, hband, sizeof(hband), "\u2013", " \u00b0C");
#endif

    /* -1 = nothing ever received (0 would read as "just now"); clamped at 0
     * because a frame arriving between the two reads would underflow. */
    uint32_t last1 = msg_last_sec1, now32 = (uint32_t)uptime_s;
    long idle = last1 ? (long)(now32 > last1 - 1 ? now32 - (last1 - 1) : 0) : -1;

    /* Machine-readable SD state, same states the file page names. 176 carries
     * the worst case GCC assumes: 61 literal + 10 + 20 + 20 + 10 + 10 + NUL. */
    char sdj[176] = ",\"sd\":{\"ok\":false,\"reason\":\"no_sd_build\"}";
#if CONFIG_ENABLE_SD
    {
        if (sdst == SDST_OK)
            snprintf(sdj, sizeof(sdj),
                ",\"sd\":{\"ok\":true,\"pct\":%u,\"used\":%llu,\"total\":%llu,"
                "\"fails\":%lu,\"held_ms\":%lu}",
                (unsigned)(((sdt - sdf) * 100ull) / sdt),
                (unsigned long long)(sdt - sdf), (unsigned long long)sdt,
                /* Both peaks since boot, like the loss table: the live streak
                 * reads 0 during long ops, so a poll would never see it. */
                (unsigned long)sdcard_io_fail_max(),
                (unsigned long)sdcard_io_held_max_ms());
        else
            /* usage_error = mounted but unreadable size, no_fs = no FAT,
             * not_mounted = never answered, unmounted = on purpose,
             * write_failed = taken out after failed writes. retry = sysmon
             * keeps trying to mount it. */
            snprintf(sdj, sizeof(sdj), ",\"sd\":{\"ok\":false,\"reason\":\"%s\"%s}",
                     sd_state_reason(sdst),
                     sdst == SDST_NO_USAGE ? ""   /* mounted: nothing to retry */
                     : sdcard_auto_remount_inhibited() ? ",\"retry\":false" : ",\"retry\":true");
    }
#endif

    /* Losses that outlive a reboot, next to the per-boot values: the lifetime
     * figure says "this card is tired", the jump inside one boot is the alarm.
     * 192 carries the worst case: 90 literal + six 10-digit values + NUL. */
    /* /system.json serves five of these values under flat names: loss_life_* for the three
     * lifetime counts, loss_pcap for lost_boot and loss_flushfail for flushfail_boot. Neither
     * set is renamed, because other readers use both. */
    char lossj[192] = "";
#if CONFIG_ENABLE_SD
    {
        uint32_t lst = 0, flf = 0, unm = 0;
        sysstat_sd_get(&lst, &flf, &unm);
        snprintf(lossj, sizeof(lossj),
            ",\"loss\":{\"lost\":%lu,\"flushfail\":%lu,\"unmounts\":%lu,"
            "\"lost_boot\":%lu,\"flushfail_boot\":%lu,\"unmounts_boot\":%lu}",
            (unsigned long)lst, (unsigned long)flf, (unsigned long)unm,
            (unsigned long)sdpcap_dropped(), (unsigned long)sdpcap_flush_fails(),
            (unsigned long)sdcard_takeouts());
    }
#endif

    char extj[128];
    web_status_extra_json(extj, sizeof(extj));

    /* The street row, from the same view as the page. */
    static EXT_RAM_BSS_ATTR char glj[1536];
    web_glance_json(glj, sizeof(glj));

    /* A half JSON breaks other readers and every peer table, so a cut answers 500. 8697 of 12288
     * with every field at its buffer (faults 2047, gl 1535). */
    static EXT_RAM_BSS_ATTR char json[12288];
    int jn = snprintf(json, sizeof(json),
        /* up_s for the pages and the peer tables. uptime keeps its spelling for other readers. */
        "{\"msgs\":%lu,\"rate\":%lu,\"uptime\":\"%s\",\"up_s\":%llu,\"sniff\":%s,\"chan\":\"%s\",\"mqtt\":%s,"
        /* sparkp, not spark: the old field carried <rect> markup, this one
         * carries polyline coordinates -- a renamed field breaks louder. */
        "\"sparkp\":\"%s\",\"smax\":%lu,\"idle\":%ld,\"types\":\"%s\""
        /* Literal UTF-8, not an entity: arApply writes it with textContent,
         * which would show "&middot;" verbatim. */
        ",\"clk\":\"%s\""
        ",\"hrp\":\"%s\",\"hrs\":\"%s\""
#ifdef CONFIG_ENABLE_TEMPERATURE
        ",\"temp\":%s,\"tcl\":\"%s\""
        ",\"htp\":\"%s\",\"htb\":\"%s\""
#endif
        "%s%s%s"
        /* quiet: seconds without a frame while receiving, from the later of the last frame
         * and the start, -1 while stopped. idle keeps its meaning for other readers and older
         * peers. */
        ",\"quiet\":%ld,\"rxq\":\"%s\",\"rxw\":\"%s\""
        "%s"
        /* node for the peer tables. fw is the bare version that other readers use and that
         * /update compares after a restart. The host is not in here. */
        ",\"node\":\"%s\",\"fw\":\"%s\",\"mqtt_d\":\"%s\""
        /* gl: the street row of the start page, keys amp, ampd, pt, ptd. */
        "%s"
        /* probs are keys for machines, probs_html the bar lines. All added, nothing renamed. */
        "%s}",
        (unsigned long)msg_total_count, (unsigned long)rate, uptime_str,
        (unsigned long long)uptime_s, running ? "true" : "false", chan_str,
        mqtt_connected_state ? "true" : "false",
        spark, (unsigned long)peak, idle,
        typeline[0] ? typeline : T(S_ACTIVITY_NONE),
        clkj, hourr, hscale
#ifdef CONFIG_ENABLE_TEMPERATURE
        , tval, temp_class(tc), hourt, hband
#endif
        /* Last, so the temperature block above keeps its argument order. */
        , sdj, lossj, extj, quiet, rxq, rxw, sduij, node_j, fw_j, mqdj, glj,
        web_faults_json(FLT_SKIP_STATUS)
    );
    /* The peer row on another node's status page reads this cross-origin,
     * exactly like /markers.json and /tracks.json already allow. */
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");
    if (jn < 0 || (size_t)jn >= sizeof(json))
    {
        ESP_LOGE(TAG, "status.json cut: need %d of %u bytes", jn, (unsigned)sizeof(json));
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "status too long");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    return httpd_resp_send(req, json, HTTPD_RESP_USE_STRLEN);
}
