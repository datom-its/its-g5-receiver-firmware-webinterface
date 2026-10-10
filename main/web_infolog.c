#include "sdkconfig.h"

#include "web_infolog.h"

#if CONFIG_ENABLE_SD

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#include "esp_attr.h"

#include "events_log.h"
#include "infolog.h"
#include "its_decode.h"
#include "sdcard.h"
#include "web_fmt.h"
#include "web_msgdetail.h"
#include "webserver_priv.h"
#include "webserver_ring.h"

static const char TAG[] = "WEBSERVER";

/* The newest rows, one of them rebuilt for the detail line, and that line. Static: only the
 * httpd task renders /traffic. PSRAM: 16 x 280 B, sizeof(msg_extra_t) and MSG_DETAIL_MAX. */
static EXT_RAM_BSS_ATTR infolog_slot_t s_rows[INFOLOG_SHOW];
static EXT_RAM_BSS_ATTR msg_extra_t s_x;
static EXT_RAM_BSS_ATTR char s_detail[MSG_DETAIL_MAX];

/* This runs on top of traffic_get_handler's 5232-byte frame. So it is noinline, and every
 * buffer but when[24] is static (six of them, 1536 B of PSRAM). */
__attribute__((noinline)) void web_infolog_emit(httpd_req_t *req)
{
    /* 103 of 192 bytes (like every buffer here). */
    static EXT_RAM_BSS_ATTR char head[192];
    HTML_PRINTF(head, "<div class='grp' id='inf'><h2 class='ico'>&#128225; %s</h2>",
                T(S_INF_TITLE));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);
    /* The fold and its paragraph go out in one call. The long intro needs no buffer this way. */
    web_send_parts(req, "<details class='dtl'><summary>", T(S_PRIO_SUM),
                   "</summary><p class='note'>", T(S_INF_INTRO), "</p></details>", NULL);

    int n = infolog_snapshot(s_rows, INFOLOG_SHOW);
    if (n < 0)
    {
        /* The table stayed busy for 100 ms. Leave the list out rather than claim it is empty,
         * and let the next refresh show it. */
        httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
        return;
    }

    if (n == 0)
    {
        /* infolog.c notes nothing before the clock is set. Then the page says that, instead of
         * claiming that nothing came. 123 of 256. */
        bool unset = time(NULL) < EVENTS_CLOCK_MIN;
        static EXT_RAM_BSS_ATTR char none[256];
        HTML_PRINTF(none, "<p class='note'>%s%s%s</p>", unset ? "<span class='v-warn'>" : "",
                    unset ? T(S_INF_CLOCK) : T(S_INF_NONE), unset ? "</span>" : "");
        httpd_resp_send_chunk(req, none, HTTPD_RESP_USE_STRLEN);
    }
    else
    {
        /* 132 of 384. */
        static EXT_RAM_BSS_ATTR char th[384];
        HTML_PRINTF(th,
            "<div class='scroll'><table><thead><tr><th>%s</th><th>%s</th><th>%s</th>"
            "<th>%s</th><th>%s</th></tr></thead><tbody>",
            T(S_COL_TIME), T(S_COL_TYPE), T(S_COL_SENDER), T(S_INF_MSGS), T(S_COL_PREVIEW));
        httpd_resp_send_chunk(req, th, HTTPD_RESP_USE_STRLEN);

        for (int i = 0; i < n; i++)
        {
            const infolog_slot_t *s = &s_rows[i];
            char when[FMT_WHEN_MAX];
            fmt_when(s->last_s, 0, FMT_SEC, web_lang(), when, sizeof(when));
            /* The table only holds named kinds. The guard still keeps a NULL out of %s. */
            const char *nm = its_msgid_name(s->kind);
            if (!nm)
                nm = "?";

            /* 123 of 256, 117 of it without the name. RTCMEM is the longest name (6). */
            static EXT_RAM_BSS_ATTR char row[256];
            HTML_PRINTF(row,
                "<tr><td>%s</td><td>%s</td><td class='mono'>%lu</td><td>%lu</td>"
                "<td class='wrapcell'>",
                when, nm, (unsigned long)s->station, (unsigned long)s->total);

            /* The same words as /messages: the slot rebuilt into a msg_extra_t. */
            infolog_to_extra(s, &s_x);
            size_t dl = web_msgdetail_append_content(&s_x, web_lang(), s_detail, 0,
                                                     MSG_DETAIL_MAX);
            web_send_parts(req, row, dl ? s_detail : "&ndash;", "</td></tr>", NULL);
        }
        httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
    }

    if (!sdcard_is_mounted())
    {
        /* The list stays in RAM, but nothing goes to the card. A mounted card whose
         * size cannot be read (SDST_NO_USAGE) still takes the rows. 73 of 192. */
        static EXT_RAM_BSS_ATTR char nosd[192];
        HTML_PRINTF(nosd, "<p class='note'>%s</p>", T(S_PRIO_NOSD));
        httpd_resp_send_chunk(req, nosd, HTTPD_RESP_USE_STRLEN);
    }

    uint32_t nlost = infolog_lost();
    if (nlost)
    {
        /* Rows missing from the files are a warning (s.css). 99 of 256. */
        static EXT_RAM_BSS_ATTR char lost[256];
        HTML_PRINTF(lost, "<div class='warn'><p>%lu %s</p></div>", (unsigned long)nlost,
                    T(S_INF_LOST));
        httpd_resp_send_chunk(req, lost, HTTPD_RESP_USE_STRLEN);
    }
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
}

#endif /* CONFIG_ENABLE_SD */
