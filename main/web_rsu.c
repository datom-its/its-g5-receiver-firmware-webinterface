#include "sdkconfig.h"

#include "web_rsu.h"

#include "esp_attr.h"

#include "webserver_priv.h"

#if CONFIG_ENABLE_SD

static const char TAG[] = "web_rsu";

/* The re-send section below the list of /senders. It reads the recording, not that list. */
void web_rsu_section(httpd_req_t *req)
{
    /* The hint is 643 bytes in German. It goes out in pieces, so there is no buffer to outgrow. */
    web_send_parts(req, "<div class='grp' id='snd-rsu'><h2>", T(S_RSU_UP_TITLE),
                   "</h2><p class='note hlp'>", T(S_RSU_UP_HINT), "</p>", NULL);

    /* Only the httpd task serves /senders, so static is safe. 1553 of 2048 with the period
     * picker at its buffer size (319). */
    static EXT_RAM_BSS_ATTR char form[2048];
    HTML_PRINTF(form,
        "<p class='tools'>%s "
        "<span class='fld'><label class='cap' for='rth'>%s</label>"
        "<select id='rth'><option value='0' selected>%s</option>"
        "<option value='3600'>1/h</option>"
        "<option value='600'>1/10 min</option></select></span> "
        "<button onclick='rsuup()'>%s</button></p>"
        "<pre id='rr' class='logpre'></pre></div>"
        "<script>"
        /* The pickers hold the device's wall time, not the browser's (itsTz, page header):
         * the recording is named and searched in the device zone. */
        "(function(){var n=Date.now();"
        "document.getElementById('rt').value=itsTz.inp(n);"
        "document.getElementById('rf').value=itsTz.inp(n-864e5);})();"
        "var RS='%s';"
        "function rsuup(){"
        "var f=itsTz.parse(document.getElementById('rf').value);"
        "var t=itsTz.parse(document.getElementById('rt').value);"
        "if(!f||!t)return;"
        "var o=document.getElementById('rr');o.textContent=RS;"
        "fetch('/sdcard/upload_rsu?from='+f+'&to='+t+'&thin='+document.getElementById('rth').value+'&lang=%s',{method:'POST'})"
        ".then(function(r){return r.text();}).then(function(x){"
        "if(x!=='OK'){o.textContent=x;return;}"
        "var iv=setInterval(function(){"
        "fetch('/sdcard/upload_rsu/status',{cache:'no-store'}).then(function(r){return r.json();})"
        ".then(function(s){if(s.run){o.textContent=RS+' '+s.sent;}"
        "else{o.textContent=s.msg;clearInterval(iv);}})"
        ".catch(function(){});},1500);})"
        ".catch(function(){o.textContent='%s';});}"
        "</script>",
        web_range_html("rf", "rt"), T(S_RSU_UP_THIN), T(S_RSU_UP_ONCE), T(S_RSU_UP_BTN),
        /* The fetch carries the page's language along. Without it the upload status
         * comes back German on ?lang=en. */
        /* The error texts land in textContent: no entities, no apostrophe. */
        T(S_RSU_UP_RUN), web_lang() == LANG_EN ? "en" : "de", T(S_ERR_GENERIC));
    httpd_resp_send_chunk(req, form, HTTPD_RESP_USE_STRLEN);
}

#endif /* CONFIG_ENABLE_SD */
