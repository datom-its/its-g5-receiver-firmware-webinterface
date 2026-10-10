#include "web_backup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "esp_app_desc.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

#include "settings_backup.h"
#include "web_dlname.h"
#include "webserver_priv.h"

static const char TAG[] = "WEBSERVER";

/* The worst case is about 4.5 KB, with every text setting full of characters
 * that JSON escapes to six bytes. */
#define EXPORT_CAP 8192

/* The multipart framing and the checkbox part around the file stay well below this. */
#define IMPORT_BODY_MAX (SETTINGS_FILE_MAX + 2048)

/* A body up to this size is read and dropped before the error page, so the
 * browser still gets to see the page instead of a reset connection. */
#define IMPORT_DRAIN_MAX (1024 * 1024)

/* PSRAM first. The buffers live for one request only. */
static void *big_calloc(size_t n)
{
    void *p = heap_caps_calloc(1, n, MALLOC_CAP_SPIRAM);
    return p ? p : calloc(1, n);
}

/* ================================================================== */
/*  GET /settings/export.json                                         */
/* ================================================================== */

esp_err_t settings_export_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    sb_work_t *w = big_calloc(sizeof(*w));
    char *json = big_calloc(EXPORT_CAP);
    if (!w || !json)
    {
        free(w);
        free(json);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "out of memory");
        return ESP_FAIL;
    }

    /* A clock more than a year past 1970 has been set, the same test as web_dl_stamp. */
    time_t now = time(NULL);
    bool clock_set = now > 31536000;
    char iso[32] = "";
    if (clock_set)
    {
        struct tm tm;
        gmtime_r(&now, &tm);
        strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", &tm);
    }
    size_t n = settings_export(esp_app_get_description()->version, clock_set ? iso : NULL,
                               w, json, EXPORT_CAP);
    free(w);
    if (!n)
    {
        free(json);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "export too large");
        return ESP_FAIL;
    }

    /* its-node001-settings-20260924-1914.json, the pattern of every generated download. The
     * import reads only the content. what 22 of 32. */
    char stamp[16] = "", what[32], disp[WEB_DL_DISP_MAX];
    if (clock_set)
        web_dl_stamp(stamp, sizeof(stamp), now);
    snprintf(what, sizeof(what), "settings%s%s", stamp[0] ? "-" : "", stamp);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Content-Disposition", web_dl_disp(disp, sizeof(disp), what, "json"));
    /* The file carries the MQTT credentials, so no cache keeps a copy. */
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    esp_err_t r = httpd_resp_send(req, json, (ssize_t)n);
    free(json);
    return r;
}

/* ================================================================== */
/*  POST /settings/import                                             */
/* ================================================================== */

/* Every setting needs its entry: a missing one would be 0, which is a real text id. */
static const str_id_t LABEL[SET_COUNT] = {
    [SET_NODEID] = S_NODEID,           [SET_CHAN] = S_AUTOSTART_CHAN,
    [SET_BROADCASTONLY] = S_BROADCAST_ONLY, [SET_LED] = S_LED_BRIGHTNESS,
    [SET_LEDOVERRIDE] = S_LED_OVERRIDE, [SET_REFRESHSEC] = S_REFRESH_SEC,
    [SET_MAPSTALE] = S_MAP_STALE_SEC,  [SET_PEERS] = S_PEERS,
    [SET_BTEN] = S_BT_ENABLE,          [SET_DHCP] = S_ETH_DHCP,
    [SET_ETHIP] = S_ETH_IP,            [SET_ETHNM] = S_ETH_NETMASK,
    [SET_ETHGW] = S_ETH_GATEWAY,       [SET_ETHDNS0] = S_ETH_DNS,
    [SET_ETHDNS1] = S_ETH_DNS,         [SET_ETHDNS2] = S_ETH_DNS,
    [SET_NTPSERVER] = S_NTP_SERVER,    [SET_TZ] = S_TZ,
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
    [SET_ETHLEDS] = S_ETH_LEDS,
#endif
    [SET_MQTTURI] = S_MQTT_URI,
#if CONFIG_ENABLE_SD
    [SET_LOGSYS] = S_LOG_SYS,          [SET_LOGMAXMB] = S_LOG_BUDGET,
    [SET_PCAPEN] = S_PCAP_ENABLE,      [SET_PCAPHOURS] = S_PCAP_RETAIN_HOURS,
    [SET_PCAPMAXMB] = S_PCAP_MAX_MB,   [SET_PCAPBUFMB] = S_PCAP_BUF_MB,
    [SET_PCAPFLUSHSEC] = S_PCAP_FLUSH_SEC, [SET_PCAPFILT] = S_PCAP_FILTER,
    [SET_TRKON] = S_TRACKS_ENABLE,     [SET_TRKDAYS] = S_TRACKS_DAYS,
    [SET_STATSDAYS] = S_STATS_RETAIN_DAYS, [SET_EVENTDAYS] = S_EVENT_RETAIN_DAYS,
#endif
};

/* Why a value was refused, as HTML. */
static void reject_reason(const sb_item_t *it, char *out, size_t cap)
{
    const set_def_t *d = it->id < SET_COUNT ? &SET_DEFS[it->id] : NULL;
    str_id_t s = S_IMP_WHY_STORE;
    switch (it->err)
    {
    case SET_ERR_TYPE:
    case SET_ERR_NUMBER:
        s = !d ? S_IMP_WHY_TYPE_STR
          : (d->kind == SET_KIND_BOOL || d->kind == SET_KIND_DHCP) ? S_IMP_WHY_TYPE_BOOL
          : (d->kind == SET_KIND_UINT || d->kind == SET_KIND_CHAN) ? S_IMP_WHY_TYPE_NUM
          : d->kind == SET_KIND_COLOR ? S_IMP_WHY_COLOR : S_IMP_WHY_TYPE_STR;
        break;
    case SET_ERR_RANGE:
        if (d && d->kind == SET_KIND_UINT)
        {
            snprintf(out, cap, "%s (%lu-%lu)", T(S_IMP_WHY_RANGE),
                     (unsigned long)d->lo, (unsigned long)d->hi);
            return;
        }
        s = S_IMP_WHY_RANGE;
        break;
    case SET_ERR_LONG:
        if (d && d->kind == SET_KIND_STR)
        {
            snprintf(out, cap, "%s (max. %u)", T(S_IMP_WHY_LONG), (unsigned)(d->cap - 1));
            return;
        }
        s = S_IMP_WHY_LONG;
        break;
    case SET_ERR_EMPTY:     s = S_IMP_WHY_EMPTY;  break;
    case SET_ERR_CHARS:     s = S_IMP_WHY_CHARS;  break;
    case SET_ERR_CHOICE:    s = S_IMP_WHY_CHOICE; break;
    case SET_ERR_IPV4:      s = S_IMP_WHY_IPV4;   break;
    case SET_ERR_COLOR:     s = S_IMP_WHY_COLOR;  break;
    case SET_ERR_STATIC_IP: s = S_IMP_WHY_STATIC; break;
    case SET_ERR_MASK:      s = S_IMP_WHY_MASK;   break;
    case SET_OK:
    case SET_ERR_STORE:     s = S_IMP_WHY_STORE;  break;
    }
    snprintf(out, cap, "%s", T(s));
}

static const char *ignore_reason(sb_why_t why)
{
    switch (why)
    {
    case SB_WHY_PASSWORD:    return T(S_IMP_WHY_PASSWORD);
    case SB_WHY_DEVICE:      return T(S_IMP_WHY_DEVICE);
    case SB_WHY_NOT_BUILT:   return T(S_IMP_WHY_NOT_BUILT);
    case SB_WHY_DHCP_UNUSED: return T(S_IMP_WHY_DHCP_UNUSED);
    case SB_WHY_NEEDS_DHCP:  return T(S_IMP_WHY_NEEDS_DHCP);
    default:                 return T(S_IMP_WHY_UNKNOWN);
    }
}

static void send_import_error(httpd_req_t *req, const char *status, str_id_t msg)
{
    httpd_resp_set_status(req, status);
    send_page_header(req, T(S_BAK_IMPORT_H));
    char html[768];
    HTML_PRINTF(html,
        "<div class='warn'><p>%s</p></div>"
        "<p><a href='/settings?lang=%s#g-bak'>%s</a></p>",
        T(msg), web_lang() == LANG_DE ? "de" : "en", T(S_IMP_BACK));
    httpd_resp_send_chunk(req, html, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
}

/* One table per outcome. Unchanged settings are only named, in one line. */
static void send_group(httpd_req_t *req, const sb_result_t *res, sb_outcome_t want,
                       str_id_t heading, unsigned count)
{
    if (!count)
        return;
    char row[896];
    HTML_PRINTF(row, "<h3>%s (%u)</h3>%s", T(heading), count,
                want == SB_UNCHANGED ? "<p class='note'>" : "<div class='scroll'><table class='kv'>");
    httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);

    bool first = true;
    for (size_t i = 0; i < res->n; i++)
    {
        const sb_item_t *it = &res->items[i];
        if (it->outcome != want)
            continue;
        /* The key came from the uploaded file. */
        char key[SJ_KEY_LEN * 6];
        html_escape(it->key, key, sizeof(key));
        const char *label = it->id < SET_COUNT ? T(LABEL[it->id]) : NULL;
        char detail[384];
        if (want == SB_REJECTED)
            reject_reason(it, detail, sizeof(detail));
        else if (want == SB_IGNORED)
            snprintf(detail, sizeof(detail), "%s", ignore_reason(it->why));
        else
            detail[0] = '\0';

        if (want == SB_UNCHANGED)
            HTML_PRINTF(row, "%s%s%s<code>%s</code>", first ? "" : " &middot; ",
                        label ? label : "", label ? " " : "", key);
        else if (want == SB_APPLIED)
            HTML_PRINTF(row, "<tr><th>%s</th><td><code>%s</code></td></tr>", label ? label : "", key);
        else
            HTML_PRINTF(row, "<tr><th>%s%s<code>%s</code></th><td>%s</td></tr>",
                        label ? label : "", label ? " " : "", key, detail);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        first = false;
    }
    httpd_resp_send_chunk(req, want == SB_UNCHANGED ? "</p>" : "</table></div>",
                          HTTPD_RESP_USE_STRLEN);
}

esp_err_t settings_import_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    const char *lc = web_lang() == LANG_DE ? "de" : "en";

    size_t total = req->content_len;
    if (total > IMPORT_BODY_MAX)
    {
        bool drained = total <= IMPORT_DRAIN_MAX;
        char sink[512];
        for (size_t left = total, retries = 0; drained && left > 0; )
        {
            int r = httpd_req_recv(req, sink, left < sizeof(sink) ? left : sizeof(sink));
            if (r == HTTPD_SOCK_ERR_TIMEOUT && ++retries <= 5)
                continue;
            if (r <= 0)
                drained = false;
            else
            {
                left -= (size_t)r;
                retries = 0;
            }
        }
        send_import_error(req, "413 Content Too Large", S_IMP_FILE_BIG);
        /* Failing closes the connection, so httpd does not read the rest in 32-byte pieces. */
        return drained ? ESP_OK : ESP_FAIL;
    }

    char ct[256];
    char boundary[80];
    if (total == 0 ||
        httpd_req_get_hdr_value_str(req, "Content-Type", ct, sizeof(ct)) != ESP_OK ||
        !multipart_boundary(ct, boundary, sizeof(boundary)))
    {
        send_import_error(req, "400 Bad Request", S_IMP_FILE_NONE);
        return ESP_OK;
    }

    char *body = big_calloc(total + 1);
    sb_work_t *w = big_calloc(sizeof(*w));
    sb_result_t *res = big_calloc(sizeof(*res));
    if (!body || !w || !res)
    {
        free(body);
        free(w);
        free(res);
        send_import_error(req, "500 Internal Server Error", S_IMP_FILE_MEM);
        return ESP_FAIL;
    }

    /* The same receive loop as the /settings POST: one recv may return only part of the body. */
    size_t got = 0;
    int retries = 0;
    while (got < total)
    {
        int r = httpd_req_recv(req, body + got, total - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT)
        {
            if (++retries > 5) break;
            continue;
        }
        if (r <= 0) break;
        retries = 0;
        got += (size_t)r;
    }

    const char *file = NULL, *dev = NULL;
    size_t file_len = 0, dev_len = 0;
    bool with_device = false;
    esp_err_t ret = ESP_OK;
    if (got < total)
    {
        send_import_error(req, "400 Bad Request", S_IMP_FILE_NONE);
        ret = ESP_FAIL;
        goto out;
    }
    if (!multipart_part(body, total, boundary, "file", &file, &file_len) || file_len == 0)
    {
        send_import_error(req, "400 Bad Request", S_IMP_FILE_NONE);
        goto out;
    }
    if (file_len > SETTINGS_FILE_MAX)
    {
        send_import_error(req, "413 Content Too Large", S_IMP_FILE_BIG);
        goto out;
    }
    with_device = multipart_part(body, total, boundary, "device", &dev, &dev_len) &&
                  dev_len == 1 && dev[0] == '1';

    settings_import(file, file_len, with_device, w, res);
    if (res->file_err != SB_FILE_OK)
    {
        str_id_t msg = S_IMP_FILE_JSON;
        switch (res->file_err)
        {
        case SB_FILE_EMPTY:    msg = S_IMP_FILE_NONE;   break;
        case SB_FILE_NOMEM:    msg = S_IMP_FILE_MEM;    break;
        case SB_FILE_TOO_MANY: msg = S_IMP_FILE_MANY;   break;
        case SB_FILE_FORMAT:   msg = S_IMP_FILE_FORMAT; break;
        case SB_FILE_NEWER:    msg = S_IMP_FILE_NEWER;  break;
        default:               break;
        }
        send_import_error(req, "400 Bad Request", msg);
        goto out;
    }
    ESP_LOGI(TAG, "settings import: %u applied, %u unchanged, %u rejected, %u ignored%s",
             res->applied, res->unchanged, res->rejected, res->ignored,
             with_device ? ", with node ID and address" : "");
    /* The zone may have come in, and it applies at once: reloaded before the header, so the
     * clock of this page shows it. Cheap, so no check which keys came. */
    if (res->applied)
        web_tz_reload();

    send_page_header(req, T(S_BAK_IMPORT_H));
    {
        char head[1024];
        /* The address bar goes back to /settings. A reload, also the one after the
         * restart below, then shows the settings and never posts the file again. */
        HTML_PRINTF(head,
            "<script>history.replaceState(null,'','/settings?lang=%s');</script>"
            "<div class='grp top'><h2>%s</h2>"
            "<p>%s: %u &middot; %s: %u &middot; %s: %u &middot; %s: %u</p>%s%s%s",
            lc, T(S_IMP_RESULT),
            T(S_IMP_APPLIED), res->applied, T(S_IMP_UNCHANGED), res->unchanged,
            T(S_IMP_REJECTED), res->rejected, T(S_IMP_IGNORED), res->ignored,
            res->applied + res->unchanged == 0 ? "<p class='note'>" : "",
            res->applied + res->unchanged == 0 ? T(S_IMP_NOTHING) : "",
            res->applied + res->unchanged == 0 ? "</p>" : "");
        httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);
    }
    if (res->reboot)
    {
        /* itsReboot() comes with PAGE_FOOTER, the same call as on /settings. */
        char rb[768];
        HTML_PRINTF(rb,
            "<div class='warn'><p>%s</p>"
            "<p><button class='pwr' onclick=\"itsReboot('%s','%s','%s','%s')\">%s</button></p></div>",
            T(S_IMP_REBOOT), T(S_REBOOT_CONFIRM), T(S_REBOOTING), T(S_REBOOT_SLOW),
            T(S_REBOOT_DENIED), T(S_REBOOT));
        httpd_resp_send_chunk(req, rb, HTTPD_RESP_USE_STRLEN);
    }
    send_group(req, res, SB_APPLIED, S_IMP_APPLIED, res->applied);
    send_group(req, res, SB_REJECTED, S_IMP_REJECTED, res->rejected);
    send_group(req, res, SB_IGNORED, S_IMP_IGNORED, res->ignored);
    send_group(req, res, SB_UNCHANGED, S_IMP_UNCHANGED, res->unchanged);
    {
        char tail[256];
        HTML_PRINTF(tail, "</div><p><a href='/settings?lang=%s'>%s</a></p>", lc, T(S_IMP_BACK));
        httpd_resp_send_chunk(req, tail, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);

out:
    free(body);
    free(w);
    free(res);
    return ret;
}
