#include "web_auth.h"

#include "esp_attr.h"

#include "webserver_priv.h"

static const char TAG[] = "WEB_AUTH";

/* After Cancel the browser shows this body instead of an empty page. */
esp_err_t web_auth_page(httpd_req_t *req)
{
    resolve_language(req);
    /* esp-idf-v6.1 has no HTTPD_401 macro. Set before the header, which sends the first chunk. */
    httpd_resp_set_status(req, "401 Unauthorized");
    send_page_header(req, T(S_AUTH_TITLE));
    /* 640 against 500 measured (German; English 462). Static: send_auth_required
     * calls this only on the httpd task. */
    static EXT_RAM_BSS_ATTR char authpg[640];
    /* The reset hint is a visible note, not hlp: hidden by default it would hide the only way
     * back in. location.reload() makes the browser ask for the password again. */
    HTML_PRINTF(authpg,
                "<p>%s</p><p class='note'>%s</p>"
                "<p><button type='button' onclick=\"location.reload()\">%s</button></p>",
                T(S_AUTH_TEXT), T(S_AUTH_FORGOT), T(S_AUTH_RETRY));
    httpd_resp_send_chunk(req, authpg, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    /* ESP_FAIL makes httpd close the connection after the refusal. */
    return ESP_FAIL;
}
