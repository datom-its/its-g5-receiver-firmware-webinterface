#include "web_csrf.h"

#include <stdint.h>
#include <string.h>
#include <strings.h>

#include "esp_log.h"
#include "esp_timer.h"

#include "webserver_priv.h"

static const char TAG[] = "web_csrf";

/* /ws is checked in its handshake. Without the option any page would get a WebSocket. */
#if CONFIG_HTTPD_WS_SUPPORT && !CONFIG_HTTPD_WS_PRE_HANDSHAKE_CB_SUPPORT
#error "/ws needs CONFIG_HTTPD_WS_PRE_HANDSHAKE_CB_SUPPORT=y for web_csrf_ws_gate"
#endif

/* One line a minute at most: a foreign page may post or open /ws in a loop, and the log goes to
 * the card. */
#define CSRF_LOG_S 60
static uint32_t s_log_sec1;   /* uptime second + 1 of the last line, 0 before the first */
static unsigned s_quiet;      /* refusals since that line; httpd task only */

/* http_parser passes control bytes inside a header value (ESC, DEL measured): a '?' each keeps
 * terminal sequences off the UART and the card's system log. */
static void log_safe(char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20 || *s == 0x7f)
            *s = '?';
}

/* from and host are other_site's buffers, already compared: changing them is free. */
static void log_refused(httpd_req_t *req, bool referer, char *from, char *host)
{
    uint32_t now1 = (uint32_t)(esp_timer_get_time() / 1000000) + 1;
    if (s_log_sec1 && now1 - s_log_sec1 < CSRF_LOG_S)
    {
        s_quiet++;
        return;
    }
    log_safe(from);
    log_safe(host);
    ESP_LOGW(TAG, "%s %.48s refused: %s %.80s, Host %.80s (%u more since the last line)",
             req->method == HTTP_POST ? "POST" : "GET", req->uri,
             referer ? "Referer" : "Origin", from, host, s_quiet);
    s_log_sec1 = now1;
    s_quiet = 0;
}

/* The scheme, then exactly the Host: an Origin ends there, a Referer goes on with its path. */
static bool names_host(const char *from, const char *host, bool referer)
{
    const char *p = from;
    if (strncmp(p, "http://", 7) == 0)
        p += 7;
    else if (strncmp(p, "https://", 8) == 0)
        p += 8;
    else
        return false;   /* "null": a sandboxed page, a file, a form under no-referrer */
    size_t n = strlen(host);
    return strncasecmp(p, host, n) == 0 && p[n] == (referer ? '/' : '\0');
}

/* A Host of up to 127 bytes. The own names need at most 73 (its- + 63-byte node id + .local). */
#define HOST_MAX 128
#define FROM_MAX 160
/* So a cut value is never judged wrong. A cut Origin is longer than any Host that fits and
 * never matches. A cut Referer still holds the whole "https://<host>/". */
_Static_assert(FROM_MAX > 8 + HOST_MAX, "a cut Origin could match a Host");

/* noinline: the two buffers must not stay in web_csrf_gate's frame while the route runs. */
static __attribute__((noinline)) bool other_site(httpd_req_t *req)
{
    char host[HOST_MAX] = "";
    char from[FROM_MAX] = "";
    bool referer = false;
    esp_err_t e = httpd_req_get_hdr_value_str(req, "Origin", from, sizeof(from));
    if (e == ESP_ERR_NOT_FOUND)
    {
        referer = true;
        e = httpd_req_get_hdr_value_str(req, "Referer", from, sizeof(from));
        if (e == ESP_ERR_NOT_FOUND)
            return false;
    }
    /* httpd hands back a value of exactly sizeof(host) bytes as ESP_OK, cut by one
     * (httpd_parse.c), so the length decides first. */
    size_t hl = httpd_req_get_hdr_value_len(req, "Host");
    bool same = (e == ESP_OK || e == ESP_ERR_HTTPD_RESULT_TRUNC) && hl > 0 && hl < sizeof(host) &&
                httpd_req_get_hdr_value_str(req, "Host", host, sizeof(host)) == ESP_OK &&
                names_host(from, host, referer);
    if (!same)
        log_refused(req, referer, from, host);
    return !same;
}

esp_err_t web_csrf_gate(httpd_req_t *req)
{
    const httpd_uri_t *route = req->user_ctx;
    if (!other_site(req))
        return route->handler(req);
    resolve_language(req);
    httpd_resp_set_status(req, "403 Forbidden");
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, T(S_POST_FOREIGN));
    /* ESP_FAIL closes the connection, as a refused password does: the body stays unread. */
    return ESP_FAIL;
}

esp_err_t web_csrf_ws_gate(httpd_req_t *req)
{
    /* A browser sends Origin on every handshake. Command-line clients and scripts send none
     * and pass. */
    if (!other_site(req))
        return ESP_OK;
    httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, NULL);
    /* ESP_FAIL: httpd_uri.c skips the 101 and httpd_main.c closes the socket. */
    return ESP_FAIL;
}
