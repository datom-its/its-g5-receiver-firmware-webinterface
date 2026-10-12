#include "web_files.h"

#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "esp_core_dump.h"
#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_vfs_fat.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "config.h"
#include "mqtt.h"
#include "sdcard.h"
#include "sdpcap.h"
#include "web_dlname.h"
#include "web_faults.h"
#include "web_fmt.h"
#include "web_system.h"
#include "web_tar.h"
#include "webserver_priv.h"

#if CONFIG_ENABLE_SD

/* Inside the block: HTML_PRINTF and the log lines use it, and a build without SD has none. */
static const char TAG[] = "WEBSERVER";

/* ================================================================== */
/*  /sdcard  -- browse, upload, format the SD card                    */
/* ================================================================== */

/* Percent-encode a path for safe use in an href/query. */
static void url_encode(const char *in, char *out, size_t out_size)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;
    for (; *in && o + 4 < out_size; in++)
    {
        unsigned char c = (unsigned char)*in;
        bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                          (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                          c == '.' || c == '~' || c == '/';
        if (unreserved)
            out[o++] = (char)c;
        else { out[o++] = '%'; out[o++] = hex[c >> 4]; out[o++] = hex[c & 0xF]; }
    }
    out[o] = '\0';
}

/* True if any byte is a control character (CR, LF, ...). Used to reject paths
 * that could otherwise inject extra HTTP response headers (e.g. via
 * Content-Disposition) or other control-character trickery. */
bool has_control_char(const char *s)
{
    for (; *s; s++)
        if ((unsigned char)*s < 0x20)
            return true;
    return false;
}

/* Replaces '"' with '_' so a filename cannot break out of the quoted
 * Content-Disposition value. The upload handler already rejects '"', but files
 * on the card or in /data can also come from elsewhere. */
static void sanitize_disp_filename(const char *name, char *out, size_t out_size)
{
    size_t o = 0;
    for (; *name && o + 1 < out_size; name++)
        out[o++] = (*name == '"') ? '_' : *name;
    out[o] = '\0';
}

/* Read the ?p= query into rel (relative to the mount point). Rejects any path
 * containing ".." so a request can never escape the mount point. */
static bool sd_get_relpath(httpd_req_t *req, char *rel, size_t rel_size)
{
    rel[0] = '\0';
    char query[SD_PATH_MAX];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char val[SD_PATH_MAX];
        if (httpd_query_key_value(query, "p", val, sizeof(val)) == ESP_OK)
        {
            url_decode(val);
            if (strstr(val, "..") != NULL || has_control_char(val))
                return false;
            strlcpy(rel, val, rel_size);
        }
    }
    return true;
}

static void sd_full_path(const char *rel, char *out, size_t out_size)
{
    if (rel && rel[0])
        snprintf(out, out_size, "%s/%s", sdcard_mount_point(), rel);
    else
        snprintf(out, out_size, "%s", sdcard_mount_point());
}

/* The chip's flash comes last and folded: people open this page for the card. Open when
 * no card is mounted. Class fold, not dtl, because the help switch hides details.dtl. */
static void send_fs_overview(httpd_req_t *req, bool open)
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    const char *lq = web_lang() == LANG_EN ? "en" : "de";
    uint64_t dtot = 0, dfree = 0;
    bool data_ok = esp_vfs_fat_info(DATA_MOUNT, &dtot, &dfree) == ESP_OK;

    web_send_parts(req, "<div class='grp'><h2>", T(S_FS_FLASH), "</h2>", NULL);
    if (data_ok)
    {
        /* The way to /fs stays visible while the fold is closed. 96 against a measured 70. */
        char fsl[96];
        HTML_PRINTF(fsl, "<p class='lnk'><a href='/fs?lang=%s'>%s (/data)</a></p>", lq, T(S_FS_INTERNAL));
        httpd_resp_send_chunk(req, fsl, HTTPD_RESP_USE_STRLEN);
    }
    /* In pieces, not one buffer: S_FS_NOTE alone is over 400 bytes, and a cut <details>
     * would fold away the rest of the page. */
    web_send_parts(req, open ? "<details class='fold' open><summary>" : "<details class='fold'><summary>",
                   T(S_FS_PARTITIONS), "</summary><p class='note hlp'>", T(S_FS_NOTE), "</p>", NULL);
    /* thead/tbody, not the implicit one: only a real thead gets the group's
     * underline from .grp thead th. 192 against a measured 140. */
    char hdr[192];
    HTML_PRINTF(hdr,
        "<div class='scroll'><table><thead><tr><th>%s</th><th>%s</th><th>%s</th>"
        "<th aria-label='%s'></th></tr></thead><tbody>",
        T(S_SD_NAME), T(S_COL_TYPE), T(S_SD_SIZE), T(S_A11Y_ACTIONS));
    httpd_resp_send_chunk(req, hdr, HTTPD_RESP_USE_STRLEN);

    esp_partition_iterator_t it = esp_partition_find(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, NULL);
    while (it != NULL)
    {
        const esp_partition_t *p = esp_partition_get(it);
        char sz[24];
        fmt_bytes(p->size, web_lang(), sz, sizeof(sz));
        char info[128] = "";
        char namecell[96];
        snprintf(namecell, sizeof(namecell), "%s", p->label);
        if (running && p->address == running->address)
        {
            /* Reuses the "active" text of /traffic, which saves a table entry. */
            snprintf(info, sizeof(info), "<span class='ok'>%s</span>", T(S_WARN_ACTIVE));
        }
        else if (p->type == ESP_PARTITION_TYPE_DATA && p->subtype == ESP_PARTITION_SUBTYPE_DATA_FAT)
        {
            if (data_ok)
            {
                /* The internal FAT filesystem can be browsed, like the SD card above.
                 * Link the label to the read-only /fs browser. */
                char u[24], t[24];
                fmt_bytes(dtot - dfree, web_lang(), u, sizeof(u));
                fmt_bytes(dtot, web_lang(), t, sizeof(t));
                snprintf(namecell, sizeof(namecell), "<a href='/fs?lang=%s'>%s</a>", lq, p->label);
                snprintf(info, sizeof(info), "%s /data (%s / %s)", T(S_FS_MOUNT_AT), u, t);
            }
        }
        /* Action cell: any status/mount info, plus a raw-image download of the
         * partition bytes (esp_partition_read). */
        char dl[96];
        snprintf(dl, sizeof(dl), "<a href='/fs/part?label=%s'>&#8595; .img</a>", p->label);
        char act[256];
        if (info[0]) snprintf(act, sizeof(act), "%s &middot; %s", info, dl);
        else         snprintf(act, sizeof(act), "%s", dl);
        /* wrapcell: the mount line wraps on a phone instead of widening the table.
         * 512 against a measured 439. */
        char row[512];
        snprintf(row, sizeof(row),
            "<tr><td>%s</td><td>%s</td><td>%s</td><td class='wrapcell'>%s</td></tr>",
            namecell, p->type == ESP_PARTITION_TYPE_APP ? "app" : "data", sz, act);
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        it = esp_partition_next(it);
    }
    /* Closes the table, the fold and the flash group. */
    httpd_resp_send_chunk(req, "</tbody></table></div></details></div>", HTTPD_RESP_USE_STRLEN);
}

/* Sends the path as clickable steps, one chunk per step. A buffer for the whole
 * line would grow with the square of the path depth. With lq == NULL the links carry no
 * lang=. A set up_text puts a step back to another page at the start of the line, so that
 * step needs no row of its own. */
static void send_path_crumbs(httpd_req_t *req, const char *base,
                             const char *lq, const char *rel,
                             const char *up_href, const char *up_text)
{
    static EXT_RAM_BSS_ATTR char crumb[SD_PATH_MAX * 9 + 192];
    static EXT_RAM_BSS_ATTR char segesc[SD_PATH_MAX * 6], prefenc[SD_PATH_MAX * 3];
    char prefix[SD_PATH_MAX];

    httpd_resp_send_chunk(req, "<p class='crumbs'>", HTTPD_RESP_USE_STRLEN);
    if (up_text)
    {
        HTML_PRINTF(crumb, "<a href='%s%s%s'>&larr; %s</a> &middot; ",
                    up_href, lq ? "?lang=" : "", lq ? lq : "", up_text);
        httpd_resp_send_chunk(req, crumb, HTTPD_RESP_USE_STRLEN);
    }
    HTML_PRINTF(crumb, "<a href='%s%s%s'>/</a>",
                base, lq ? "?lang=" : "", lq ? lq : "");
    httpd_resp_send_chunk(req, crumb, HTTPD_RESP_USE_STRLEN);

    size_t pl = 0;
    const char *seg = rel;
    while (*seg)
    {
        const char *end = strchr(seg, '/');
        size_t sl = end ? (size_t)(end - seg) : strlen(seg);
        if (pl && pl + 1 < sizeof(prefix)) prefix[pl++] = '/';
        for (size_t k = 0; k < sl && pl + 1 < sizeof(prefix); k++) prefix[pl++] = seg[k];
        prefix[pl] = '\0';
        char segbuf[SD_PATH_MAX];
        strlcpy(segbuf, seg, sl + 1 < sizeof(segbuf) ? sl + 1 : sizeof(segbuf));
        html_escape(segbuf, segesc, sizeof(segesc));
        url_encode(prefix, prefenc, sizeof(prefenc));
        /* The last step stays unlinked because the page already lists that directory. */
        if (end)
            HTML_PRINTF(crumb, "<a href='%s?p=%s%s%s'>%s</a>/", base, prefenc,
                        lq ? "&amp;lang=" : "", lq ? lq : "", segesc);
        else
            HTML_PRINTF(crumb, "%s", segesc);
        httpd_resp_send_chunk(req, crumb, HTTPD_RESP_USE_STRLEN);
        seg = end ? end + 1 : seg + sl;
    }
    httpd_resp_send_chunk(req, "</p>", HTTPD_RESP_USE_STRLEN);
}

/* Sorts in the browser, because readdir returns the entries unsorted. Both
 * listings provide <tbody id='dbody'>, data-c on sortable <th>, data-fix on fixed rows. */
static void send_dir_sort_script(httpd_req_t *req)
{
    httpd_resp_send_chunk(req,
        "<script>(function(){var tb=document.getElementById('dbody');if(!tb)return;var dir={};"
        "function srt(c){dir[c]=!dir[c];var s=dir[c]?1:-1;"
        /* Fixed rows are marked with data-fix. A class named "pin" would clash with
         * the unrelated .pin glyph rule in s.css. */
        "var r=[].slice.call(tb.rows).filter(function(x){return !x.hasAttribute('data-fix');});"
        "r.sort(function(a,b){"
        /* Directories stay on top in both directions. */
        "var da=+(a.getAttribute('data-d')||0),db=+(b.getAttribute('data-d')||0);"
        "if(da!==db)return db-da;"
        "if(c===2)return s*((+a.getAttribute('data-sz'))-(+b.getAttribute('data-sz')));"
        /* numeric:true compares digit runs as numbers, so "x9" sorts before "x10". */
        "return s*a.cells[1].textContent.localeCompare(b.cells[1].textContent,"
        "undefined,{numeric:true,sensitivity:'base'});});"
        "r.forEach(function(x){tb.appendChild(x);});}"
        /* The heads become clickable only here, after the last row has arrived.
         * A click during streaming could not sort the rows that are still missing. */
        "document.querySelectorAll('th[data-c]').forEach(function(h){"
        "h.className='srt';h.tabIndex=0;"
        "h.onclick=function(){srt(+h.getAttribute('data-c'));};"
        "h.onkeydown=function(e){if(e.key==='Enter'||e.key===' '){e.preventDefault();h.onclick();}};"
        "});})();</script>", HTTPD_RESP_USE_STRLEN);
}

esp_err_t sdcard_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    /* SD contents can be arbitrary/sensitive (whatever got uploaded), so
     * browsing is gated by the same web password as write actions. */
    if (!check_update_auth(req))
        return send_auth_required(req);

    /* Parse/validate the path BEFORE sending any output, so a rejected path can
     * still return a clean HTTP error instead of a half-streamed page. */
    /* Empty unless mounted here: the card can mount before sd_state() below. */
    char rel[SD_PATH_MAX] = "";
    if (sdcard_is_mounted() && !sd_get_relpath(req, rel, sizeof(rel)))
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }

    /* As on /settings (web_settings.c): same-origin keeps the real Origin on the mount form's
     * POST, which web_csrf.c checks, and sends no Referer to other sites. */
    httpd_resp_set_hdr(req, "Referrer-Policy", "same-origin");
    send_page_header(req, T(S_TITLE_SD));

    /* The card comes first. The chip's flash follows at the end (send_fs_overview).
     * 96 against a measured 38. */
    char sdhdr[96];
    snprintf(sdhdr, sizeof(sdhdr), "<div class='grp top'><h2>%s</h2>", T(S_FS_SDCARD));
    httpd_resp_send_chunk(req, sdhdr, HTTPD_RESP_USE_STRLEN);

    /* One state read for both halves of this page, so the reason text and the
     * usage tile below cannot come from two different samples. */
    uint64_t total = 0, freeb = 0;
    sd_state_t sdst = sd_state(&total, &freeb);

    if (sdst != SDST_OK && sdst != SDST_NO_USAGE)   /* i.e. not mounted */
    {
        const char *lc = web_lang() == LANG_EN ? "en" : "de";
        /* A card that answers but cannot be used is a fault. No card or a deliberate unmount
         * can be normal, and a device without a card must not look alarmed. */
        bool fault = (sdst == SDST_NO_FS || sdst == SDST_WRITE_FAILED);
        /* Show the actual reason, not a guess. A deliberate unmount leaves no
         * mount error, so it must not be reported as a dead card. */
        /* No file system is a warning (a fresh card needs one format), failed writes an alarm
         * (s.css). 512 against a measured 389 (alarm box, S_SD_ERR_WRITEFAIL) and 251 (note). */
        char why[512];
        if (fault)
            HTML_PRINTF(why, "<p>%s</p><div class='%s'><p>%s</p></div>",
                        T(S_SD_NOT_MOUNTED), sdst == SDST_WRITE_FAILED ? "alarm" : "warn",
                        sdst == SDST_NO_FS                ? T(S_SD_ERR_NOFS)
                        : sdcard_auto_remount_inhibited() ? T(S_SD_ERR_WRITEFAIL_OUT)
                                                          : T(S_SD_ERR_WRITEFAIL));
        else
            HTML_PRINTF(why, "<p>%s</p><p class='note'>%s</p>",
                        T(S_SD_NOT_MOUNTED),
                        sdst == SDST_UNMOUNTED ? T(S_SD_ERR_UNMOUNTED) : T(S_SD_ERR_NOCARD));
        httpd_resp_send_chunk(req, why, HTTPD_RESP_USE_STRLEN);

        /* 256 against a measured 151. */
        char mnt[256];
        HTML_PRINTF(mnt,
            /* A div, not a p: a <form> inside a <p> makes the parser close the
             * paragraph early, and the row would fall apart. */
            "<div class='btnrow tools'>"
            /* lang= so the handler's refusal comes back in the page's language: a bare
             * POST carries nothing resolve_language() could go on. */
            "<form method='post' action='/sdcard/mount?lang=%s' style='display:inline-block'>"
            /* .act keeps the amber fill that the quiet .btnrow would otherwise remove.
             * Mounting is the main action of this branch. */
            "<button class='act'>%s</button></form>",
            lc, T(S_SD_MOUNT));
        httpd_resp_send_chunk(req, mnt, HTTPD_RESP_USE_STRLEN);

        /* The format button must be reachable HERE for a fault: an unreadable card never
         * mounts, and nothing formats it automatically. */
        /* Only where formatting can change something: NO_FS (its text recommends it) and
         * WRITE_FAILED (the last resort before a new card). sdcard_format() mounts first. */
        if (fault)
        {
            /* Same guard as sdreq() on the mounted page: the handler answers "Error" on a
             * failed format, and a torn connection never reaches onload at all. */
            /* 640 against a measured 564. A truncated onclick loses the button. */
            char fbtn[640];
            HTML_PRINTF(fbtn,
                "<button class='dngr' onclick=\"if(confirm('%s')){"
                /* ?lang=: a bare POST would answer a 403 in German on an English page. */
                "var b=this;var x=new XMLHttpRequest();"
                "x.open('POST','/sdcard/format?lang='+document.documentElement.lang);"
                "x.onload=function(){if(x.status==403)alert(x.responseText);"
                "else if(x.status!==200||x.responseText==='Error')"
                "alert('%s ('+x.status+')');location.reload();};"
                "x.onerror=function(){alert('%s');b.innerText='%s';};"
                "b.innerText='%s';x.send();}\">%s</button>",
                T(S_SD_FORMAT_CONFIRM), T(S_SD_ACTION_FAILED), T(S_SD_ACTION_FAILED),
                T(S_SD_FORMAT), T(S_SD_FORMATTING), T(S_SD_FORMAT));
            httpd_resp_send_chunk(req, fbtn, HTTPD_RESP_USE_STRLEN);
        }
        /* Closes the button row and the SD group opened above, because this branch
         * returns early. The flash group follows with its fold open. */
        httpd_resp_send_chunk(req, "</div></div>", HTTPD_RESP_USE_STRLEN);
        send_fs_overview(req, true);
        httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
        httpd_resp_send_chunk(req, NULL, 0);
        return ESP_OK;
    }

    /* Usage tile, upload form and the tar and delete buttons. The format button comes at the
     * end of the group. */
    /* 384 against a measured 287 for the tile and 144 for the box. */
    char usage[384] = "";
    /* SDST_OK already means total != 0, so the percentage cannot divide by zero. */
    if (sdst == SDST_OK)
    {
        char t[24], u[24], f[24];
        unsigned pct = (unsigned)(((total - freeb) * 100ull) / total);
        fmt_bytes(total, web_lang(), t, sizeof(t));
        fmt_bytes(total - freeb, web_lang(), u, sizeof(u));
        fmt_bytes(freeb, web_lang(), f, sizeof(f));
        char used_of[128];
        snprintf(used_of, sizeof(used_of), T(S_SD_USED_OF), u, t, f);
        /* The rules of sd_tile() on '/': red while writes are refused, else the 80/92
         * thresholds. %% is a literal percent sign in the value, not a conversion. */
        snprintf(usage, sizeof(usage),
                 "<div class='grid'><div class='cell'><div class='l %s'>%s</div>"
                 "<div class='v'>%u<span class='e'>%%</span></div>"
                 "<div class='d'>%s</div></div></div>",
                 web_faults_sd_dead(NULL) ? "v-bad" : lvl_class(pct, 80, 92), T(S_SD_USAGE),
                 pct, used_of);
    }
    else
        /* A warning box instead of silently dropping the tile: it is a card problem.
         * /status.json reports this case as "usage_error". */
        snprintf(usage, sizeof(usage), "<div class='warn'><p>%s</p></div>", T(S_SD_ERR_USAGE));

    /* Large scratch buffers would overflow the httpd stack, so they are static.
     * Only the httpd task runs this handler, one request at a time, so one instance
     * is safe. EXT_RAM_BSS_ATTR places them in PSRAM to spare the scarce internal SRAM. */
    static EXT_RAM_BSS_ATTR char relenc[SD_PATH_MAX * 3];
    url_encode(rel, relenc, sizeof(relenc));

    /* 4096 against a measured 3520, with the usage slot full and relenc at 959. */
    static EXT_RAM_BSS_ATTR char top[4096];
    snprintf(top, sizeof(top),
        "%s"
        /* Label above its field in one .fld, so a wrapping row cannot part them. */
        "<p class='tools'><span class='fld'><label class='cap' for='fw'>%s</label><input type='file' id='fw'></span>"
        "<button onclick='up()'>%s</button> "
        "<span id='ur'></span></p>"
        "<p class='btnrow tools'><button onclick='seltar()'>&#8595; %s</button> "
        "<button class='dngr' onclick='seldel()'>%s</button></p>"
        "<p class='note hlp'>%s</p>"
        "<script>"
        "var P='%s';var ITS_SD_FAIL='%s';"
        /* sdreq() alerts on a non-200 status or an "Error" body before reloading.
         * Otherwise a 414 from a long selection or a 500 would look like success. A 403
         * of web_csrf.c names its cause, so its text is shown. lang= goes first, where
         * resolve_language() finds it even after a long ?sel=; a bare POST answers German. */
        "function sdreq(u,go){var i=u.indexOf('?'),l='lang='+document.documentElement.lang;"
        "u=i<0?u+'?'+l:u.slice(0,i+1)+l+'&'+u.slice(i+1);"
        "var x=new XMLHttpRequest();x.open('POST',u);"
        "x.onload=function(){if(x.status==403)alert(x.responseText);"
        "else if(x.status!==200||x.responseText==='Error')"
        "alert(ITS_SD_FAIL+' ('+x.status+')');location.reload();};"
        /* A torn connection does not reload the page, so the progress words are cleared by
         * hand. Otherwise the page keeps saying "uploading" or "formatting" for good. */
        "x.onerror=function(){alert(ITS_SD_FAIL);"
        "document.getElementById('ur').innerText='';"
        "document.getElementById('fr').innerText='';};x.send(go);}"
        /* P and the del() paths arrive url-encoded from the server. Encoding them again
         * would turn a space into %2520. Only raw DOM values still need encoding. */
        /* Through sdreq() as well: the upload answers 400 ("bad name", "empty") or 500
         * ("write failed", the part-written file is removed), never a body of "Error". */
        "function up(){var f=document.getElementById('fw').files[0];if(!f){return;}"
        "document.getElementById('ur').innerText='%s';"
        "sdreq('/sdcard/upload?p='+P+'&name='+encodeURIComponent(f.name),f);}"
        "function fmt(){if(!confirm('%s'))return;"
        "document.getElementById('fr').innerText='%s';sdreq('/sdcard/format');}"
        "function del(p){if(!confirm('%s'))return;"
        "sdreq('/sdcard/delete?p='+p);}"
        "function selall(c){document.querySelectorAll('.sel').forEach(function(x){x.checked=c.checked;});}"
        "function seltar(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}location.href='/sdcard/tar?sel='+s.join('|');}"
        "function seldel(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}if(!confirm('%s'))return;"
        "sdreq('/sdcard/delete?sel='+s.join('|'));}"
        "</script>",
        usage,
        T(S_SD_UP_HERE), T(S_SD_UP_BTN),
        T(S_TAR_SELECTED), T(S_SD_DELETE_SELECTED),
        T(S_TAR_HINT),
        relenc, T(S_SD_ACTION_FAILED),
        T(S_UPLOADING),
        T(S_SD_FORMAT_CONFIRM), T(S_SD_FORMATTING),
        T(S_SD_DELETE_CONFIRM),
        T(S_TAR_NONE), T(S_TAR_NONE), T(S_SD_DELETE_SEL_CONFIRM));
    httpd_resp_send_chunk(req, top, HTTPD_RESP_USE_STRLEN);


    /* Same language as /fs: a link without lang= falls back to the browser's language,
     * not to the one this page shows. */
    const char *lq = web_lang() == LANG_EN ? "en" : "de";
    send_path_crumbs(req, "/sdcard", lq, rel, NULL, NULL);

    /* The sorter only moves rows inside <tbody id='dbody'>, and without it
     * the page cannot sort. The header row stays outside it in <thead>. */
    /* 512 against a measured 263. */
    char tblopen[512];
    HTML_PRINTF(tblopen,
        "<div class='scroll'><table><thead><tr>"
        "<th><label><input type='checkbox' onclick='selall(this)' aria-label='%s'></label></th>"
        "<th data-c='1'>%s</th>"
        "<th data-c='2'>%s</th>"
        "<th aria-label='%s'></th></tr></thead><tbody id='dbody'>",
        T(S_A11Y_SELECT_ALL), T(S_SD_NAME), T(S_SD_SIZE), T(S_A11Y_ACTIONS));
    httpd_resp_send_chunk(req, tblopen, HTTPD_RESP_USE_STRLEN);

    /* Parent-directory link */
    if (rel[0])
    {
        char parent[SD_PATH_MAX];
        strlcpy(parent, rel, sizeof(parent));
        char *slash = strrchr(parent, '/');
        if (slash) *slash = '\0'; else parent[0] = '\0';
        char penc[SD_PATH_MAX * 3];
        url_encode(parent, penc, sizeof(penc));
        /* data-fix keeps this row out of the sort, so it always stays on top. The
         * attribute adds 13 bytes to a row buffer with a thin percent-encoding margin. */
        char row[SD_PATH_MAX * 3 + 192];
        snprintf(row, sizeof(row),
            "<tr data-fix='1'><td></td><td><a href='/sdcard?p=%s&amp;lang=%s'>%s</a></td>"
            "<td></td><td></td></tr>",
            penc, lq, T(S_SD_PARENT));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    /* Directory entries */
    char full[SD_PATH_MAX];
    sd_full_path(rel, full, sizeof(full));
    /* Counted reader: the DIR handle stays open across client-paced chunk
     * sends, and a console/MQTT "unmount" must not free FATFS under it. */
    bool rd = sdcard_read_begin();
    DIR *dir = rd ? opendir(full) : NULL;
    size_t entries = 0;
    if (dir)
    {
        struct dirent *de;
        while ((de = readdir(dir)) != NULL)
        {
            if (de->d_name[0] == '.')
                continue;
            entries++;

            char childrel[SD_PATH_MAX + 256];
            if (rel[0]) snprintf(childrel, sizeof(childrel), "%s/%s", rel, de->d_name);
            else        snprintf(childrel, sizeof(childrel), "%s", de->d_name);

            char childfull[SD_PATH_MAX + 288];
            sd_full_path(childrel, childfull, sizeof(childfull));
            struct stat st;
            bool is_dir = (stat(childfull, &st) == 0) && S_ISDIR(st.st_mode);

            /* nameesc is the escaped display name, relenc2 the url-encoded path for
             * hrefs. relhtml is the escaped raw path for the checkbox value. JS reads it
             * back and url-encodes it for the tar and delete selections. */
            static EXT_RAM_BSS_ATTR char nameesc[256], relenc2[SD_PATH_MAX * 3];
            static EXT_RAM_BSS_ATTR char relhtml[SD_PATH_MAX * 6];
            html_escape(de->d_name, nameesc, sizeof(nameesc));
            url_encode(childrel, relenc2, sizeof(relenc2));
            html_escape(childrel, relhtml, sizeof(relhtml));

            /* data-d/data-sz feed the client-side sorter: the displayed size is
             * already formatted ("1,0 MB") and cannot be compared numerically. */
            /* 16x holds the path once escaped (checkbox value) and twice url-encoded (link
             * and delete button), plus the name twice, once in the checkbox's aria-label.
             * Worst case 4648 of 5120 (file row). */
            static EXT_RAM_BSS_ATTR char row[SD_PATH_MAX * 16];
            if (is_dir)
            {
                snprintf(row, sizeof(row),
                    "<tr data-d='1' data-sz='0'><td><label><input type='checkbox' class='sel'"
                    " aria-label='%s: %s' value='%s'></label></td>"
                    "<td><a href='/sdcard?p=%s&amp;lang=%s'>%s/</a></td><td></td><td></td></tr>",
                    T(S_A11Y_SELECT_ROW), nameesc, relhtml, relenc2, lq, nameesc);
            }
            else
            {
                char sz[32];
                fmt_bytes((uint64_t)st.st_size, web_lang(), sz, sizeof(sz));
                snprintf(row, sizeof(row),
                    "<tr data-d='0' data-sz='%llu'><td><label><input type='checkbox' class='sel'"
                    " aria-label='%s: %s' value='%s'></label></td>"
                    "<td><a href='/sdcard/download?p=%s'>%s</a></td><td>%s</td>"
                    "<td><button class='dngr' onclick=\"del('%s')\">%s</button></td></tr>",
                    (unsigned long long)st.st_size,
                    T(S_A11Y_SELECT_ROW), nameesc, relhtml, relenc2, nameesc, sz,
                    relenc2, T(S_SD_DELETE));
            }
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        closedir(dir);
    }
    if (rd)
        sdcard_read_end();

    if (entries == 0)
    {
        char row[128];
        snprintf(row, sizeof(row), "<tr data-fix='1'><td colspan='4'>%s</td></tr>", T(S_SD_EMPTY));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
    send_dir_sort_script(req);
    /* Formatting last, away from upload and selection, because it erases the whole card:
     * the same danger at the end as on /transit. fmt() and sdreq() at the top write #fr. */
    web_send_parts(req, "<p class='btnrow'><button class='dngr' onclick='fmt()'>", T(S_SD_FORMAT),
                   "</button> <span id='fr'></span></p>", NULL);
    /* Closes the SD group opened above. The chip's flash follows, folded. */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    send_fs_overview(req, false);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* A file that is missing answers 404. Any other failed open is a read error of the card and gets
 * a log line, so a failing card does not look like a wrong link. err is errno right after fopen. */
static esp_err_t send_open_failed(httpd_req_t *req, const char *full, int err)
{
    if (err == ENOENT || err == ENOTDIR || err == EISDIR)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "not found");
        return ESP_FAIL;
    }
    ESP_LOGW(TAG, "download: cannot open %s (errno %d)", full, err);
    httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "read error");
    return ESP_FAIL;
}

esp_err_t sdcard_download_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    if (!sdcard_is_mounted())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)) || rel[0] == '\0')
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }
    char full[SD_PATH_MAX];
    sd_full_path(rel, full, sizeof(full));
    /* Counted reader: without it, a concurrent unmount or format could free FATFS
     * under the open FILE, and the next fread would be a use-after-free. */
    if (!sdcard_read_begin())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    FILE *f = fopen(full, "rb");
    if (!f)
    {
        int err = errno;
        sdcard_read_end();
        return send_open_failed(req, full, err);
    }
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    char basesafe[SD_PATH_MAX];
    sanitize_disp_filename(base, basesafe, sizeof(basesafe));
    char disp[SD_PATH_MAX + 64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", basesafe);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        if (httpd_resp_send_chunk(req, buf, n) != ESP_OK)
        {
            fclose(f);
            sdcard_read_end();
            return ESP_FAIL;
        }
    }
    /* A read error ends the loop like the end of the file. Without the last chunk a short
     * file cannot pass for a whole one. */
    bool rd_err = ferror(f) != 0;
    fclose(f);
    sdcard_read_end();
    if (rd_err)
    {
        ESP_LOGW(TAG, "download: read error in %s, aborted", full);
        return ESP_FAIL;
    }
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

esp_err_t sdcard_upload_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    if (!sdcard_is_mounted())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }

    char reldir[SD_PATH_MAX] = "", name[128] = "";
    char query[SD_PATH_MAX];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char v[SD_PATH_MAX];
        if (httpd_query_key_value(query, "p", v, sizeof(v)) == ESP_OK)
        {
            url_decode(v);
            if (strstr(v, "..")) { httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path"); return ESP_FAIL; }
            strlcpy(reldir, v, sizeof(reldir));
        }
        if (httpd_query_key_value(query, "name", v, sizeof(v)) == ESP_OK)
        {
            url_decode(v);
            strlcpy(name, v, sizeof(name));
        }
    }
    /* A single path component only. '"' is rejected too, because a download later
     * puts the name into a quoted Content-Disposition value. */
    if (name[0] == '\0' || strchr(name, '/') || strstr(name, "..") ||
        strchr(name, '"') || has_control_char(name))
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad name");
        return ESP_FAIL;
    }
    if (req->content_len == 0)
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "empty");
        return ESP_FAIL;
    }

    char full[SD_PATH_MAX * 2];
    if (reldir[0]) snprintf(full, sizeof(full), "%s/%s/%s", sdcard_mount_point(), reldir, name);
    else           snprintf(full, sizeof(full), "%s/%s", sdcard_mount_point(), name);

    /* Counted "reader", meaning any streaming FS user. The FILE stays open during the
     * client-paced recv loop, and a console/MQTT unmount must not free FATFS under it. */
    if (!sdcard_read_begin())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    FILE *f = fopen(full, "wb");
    if (!f)
    {
        sdcard_read_end();
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "open failed");
        return ESP_FAIL;
    }

    char buf[1024];
    size_t remaining = req->content_len;
    int retries = 0;
    bool ok = true;
    while (remaining > 0)
    {
        int to_read = remaining < sizeof(buf) ? (int)remaining : (int)sizeof(buf);
        int r = httpd_req_recv(req, buf, to_read);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) { if (++retries > 5) { ok = false; break; } continue; }
        if (r <= 0) { ok = false; break; }
        retries = 0;
        if (fwrite(buf, 1, r, f) != (size_t)r) { ok = false; break; }
        remaining -= r;
    }
    /* picolibc's fclose hides a failed last write-out: an "OK" would stand for a short file. */
    if (ok && (fflush(f) != 0 || ferror(f)))
        ok = false;
    if (fclose(f) != 0)
        ok = false;
    if (!ok)
    {
        remove(full);
        sdcard_read_end();
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "write failed");
        return ESP_FAIL;
    }
    sdcard_read_end();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* Unlinks under the SD writer lock: with FS_LOCK=0, removing a file a writer has open
 * corrupts its handle. Lock per entry: a lock around the whole walk starves writers. */
static bool sd_rm_locked(const char *path, bool is_dir, bool *lock_busy)
{
    /* Other streaming readers hold a FILE open without any lock (see sdcard.h). A count
     * of 1 is our own guard. Leave *lock_busy unset, so a bulk walk goes on. */
    if (sdcard_read_active() > 1)
        return false;
    if (!sdcard_io_begin_timeout(2000))
    {
        /* A busy lock is transient, not a bad entry. Each further attempt would cost
         * another 2 s on the httpd task, so the caller abandons the walk instead. */
        *lock_busy = true;
        return false;
    }
    bool ok = is_dir ? (rmdir(path) == 0) : (remove(path) == 0);
    sdcard_io_end();
    return ok;
}

/* Recursive delete on ONE caller-owned buffer (append, recurse, truncate). The 16 KB
 * httpd stack cannot afford a buffer per level. `depth` limits recursion on corrupt cards. */
static bool sd_rm_tree(char *path, size_t size, int depth, bool *lock_busy)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return false;
    if (!S_ISDIR(st.st_mode))
        return sd_rm_locked(path, false, lock_busy);
    if (depth <= 0)
        return false;

    size_t len = strlen(path);
    /* Deleting entries while readdir() walks the same directory can make
     * FATFS skip some, so repeat passes until one makes no more progress. */
    for (;;)
    {
        DIR *d = opendir(path);
        if (!d)
            return false;
        int removed = 0, left = 0;
        struct dirent *e;
        while ((e = readdir(d)) != NULL)
        {
            if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                continue;
            int n = snprintf(path + len, size - len, "/%s", e->d_name);
            if (n <= 0 || (size_t)n >= size - len)
                left++;
            else if (sd_rm_tree(path, size, depth - 1, lock_busy))
                removed++;
            else
                left++;
            path[len] = '\0';
            /* Writer lock busy: every further entry would wait its own 2 s. */
            if (*lock_busy)
                break;
        }
        closedir(d);
        if (*lock_busy)
            return false;
        if (left == 0)
            break;
        if (removed == 0)
            return false;
    }
    return sd_rm_locked(path, true, lock_busy);
}

esp_err_t sdcard_delete_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* Counted reader for the whole delete walk, which can be deep. A console/MQTT
     * unmount must not free FATFS under the open DIR handles of sd_rm_tree. */
    if (!sdcard_read_begin())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }

    /* Bulk path: ?sel=a|b|c, same encoding as /sdcard/tar's ?sel= (percent-
     * encoded '|' folded back first). Directories are removed recursively
     * (see sd_rm_tree). A bad path counts as failed, and the rest is still tried. */
    /* Static, not stack: 8 KB of scratch would halve the httpd task's stack.
     * tar_download keeps its own copies because it runs on the worker task. */
    static EXT_RAM_BSS_ATTR char query[4096];
    static EXT_RAM_BSS_ATTR char sel[4096];
    sel[0] = '\0';
    bool have_sel = false;
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
        have_sel = httpd_query_key_value(query, "sel", sel, sizeof(sel)) == ESP_OK;

    httpd_resp_set_type(req, "text/plain; charset=utf-8");

    if (have_sel)
    {
        char *r = sel, *w = sel;
        while (*r)
        {
            if (r[0] == '%' && r[1] == '7' && (r[2] == 'C' || r[2] == 'c'))
            {
                *w++ = '|';
                r += 3;
            }
            else
                *w++ = *r++;
        }
        *w = '\0';

        int failed = 0;
        bool lock_busy = false;
        char *save = NULL;
        for (char *tok = strtok_r(sel, "|", &save); tok; tok = strtok_r(NULL, "|", &save))
        {
            url_decode(tok);
            if (tok[0] == '\0' || strstr(tok, "..") || has_control_char(tok)) { failed++; continue; }
            char full[SD_PATH_MAX];
            sd_full_path(tok, full, sizeof(full));
            if (!sd_rm_tree(full, sizeof(full), 8, &lock_busy)) failed++;
            /* The entry that set lock_busy already counted as failed. Stop here so a
             * whole selection cannot pile up 2 s waits on the httpd task. */
            if (lock_busy) break;
        }
        sdcard_read_end();
        if (failed)
            httpd_resp_set_status(req, "500 Internal Server Error");
        httpd_resp_sendstr(req, failed == 0 ? "OK" : "Error");
        return failed == 0 ? ESP_OK : ESP_FAIL;
    }

    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)) || rel[0] == '\0')
    {
        sdcard_read_end();
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }
    char full[SD_PATH_MAX];
    sd_full_path(rel, full, sizeof(full));
    bool lock_busy = false;
    bool removed = sd_rm_tree(full, sizeof(full), 8, &lock_busy);
    sdcard_read_end();
    if (removed)
    {
        httpd_resp_sendstr(req, "OK");
        return ESP_OK;
    }
    httpd_resp_set_status(req, "500 Internal Server Error");
    httpd_resp_sendstr(req, "Error");
    return ESP_FAIL;
}

/* POST /sdcard/upload_rsu re-sends only positively-identified RSU frames. A separate
 * task collects them under the SD lock and sends them after releasing it. */

#define RSU_BATCH_BYTES (256 * 1024)
#define RSU_BATCH_MAX   256

typedef struct {
    volatile bool running;
    volatile uint32_t sent;
    uint32_t thinned, stations;
    bool pairs_overflow;
    bool de;                     /* language captured at request time */
    uint32_t from, to, thin;     /* thin 0 = one frame per station+type, total */
    char result[256];            /* final line for the status poll; worst 222 (German) */
} rsu_job_t;
static rsu_job_t rsu_job;

typedef struct {
    uint8_t *buf;
    size_t used, n;
    struct { uint32_t off; uint16_t len; } items[RSU_BATCH_MAX];
    bool full;
    /* Thinning table, persistent across the whole run. */
    struct { uint32_t station; uint8_t msgid; uint32_t last_sec; } seen[64];
    size_t n_seen;
} rsu_batch_t;

/* Runs under the SD writer lock: filter + copy ONLY, no sleeping, no I/O. */
static bool rsu_collect_cb(uint32_t sec, uint32_t usec, const uint8_t *frame,
                           size_t frame_len, const its_decoded_t *d, void *vctx)
{
    (void)usec;
    rsu_batch_t *b = (rsu_batch_t *)vctx;

    /* The kind, so an old EVCSN (id 3 at version 0) and a POIM count as two types. */
    uint8_t kind = its_msg_kind(d->pdu_version, d->message_id);
    if (d->station_type != 15 || kind == 0)
        return true;                    /* skip: not an RSU, or message type unknown */

    for (size_t i = 0; i < b->n_seen; i++)
    {
        if (b->seen[i].station != d->station_id || b->seen[i].msgid != kind)
            continue;
        if (rsu_job.thin == 0 || sec - b->seen[i].last_sec < rsu_job.thin)
        {
            rsu_job.thinned++;
            return true;
        }
        b->seen[i].last_sec = sec;
        goto keep;
    }
    if (b->n_seen >= sizeof(b->seen) / sizeof(b->seen[0]))
    {
        /* Table full: skip the frame and flag it in the result. Sending it untracked
         * would bypass the thinning, and skipping it silently would hide the gap. */
        rsu_job.pairs_overflow = true;
        rsu_job.thinned++;
        return true;
    }
    {
        bool station_known = false;
        for (size_t i = 0; i < b->n_seen; i++)
            if (b->seen[i].station == d->station_id) { station_known = true; break; }
        if (!station_known)
            rsu_job.stations++;
    }
    b->seen[b->n_seen].station = d->station_id;
    b->seen[b->n_seen].msgid = kind;
    b->seen[b->n_seen].last_sec = sec;
    b->n_seen++;

keep:
    if (b->n >= RSU_BATCH_MAX || b->used + frame_len > RSU_BATCH_BYTES ||
        frame_len > UINT16_MAX)
    {
        b->full = true;                 /* capacity hit -- reported as partial */
        return false;
    }
    memcpy(b->buf + b->used, frame, frame_len);
    b->items[b->n].off = (uint32_t)b->used;
    b->items[b->n].len = (uint16_t)frame_len;
    b->n++;
    b->used += frame_len;
    return true;
}

/* Runs in task context without any lock. Sends paced with retries and reports
 * the actual cause when a frame cannot be queued. */
static bool rsu_drain_batch(rsu_batch_t *b)
{
    /* web_str with the language of the request, never T(): this task has no request. */
    const lang_t l = rsu_job.de ? LANG_DE : LANG_EN;
    for (size_t i = 0; i < b->n; i++)
    {
        bool ok = false;
        for (int attempt = 0; attempt < 3 && !ok; attempt++)
        {
            ok = mqtt_replay_frame(b->buf + b->items[i].off, b->items[i].len);
            if (!ok && !mqtt_connected_state)
                break;                  /* MQTT disconnected, retrying won't help */
            if (!ok)
                vTaskDelay(pdMS_TO_TICKS(150));
        }
        if (!ok)
        {
            snprintf(rsu_job.result, sizeof(rsu_job.result), "%s",
                     web_str(mqtt_connected_state ? S_RSU_R_QFULL : S_RSU_R_LOST, l));
            return false;
        }
        rsu_job.sent++;
        vTaskDelay(pdMS_TO_TICKS(40)); /* pace: live feed keeps priority */
    }
    b->n = 0;
    b->used = 0;
    return true;
}

static void rsu_upload_task(void *arg)
{
    (void)arg;
    /* web_str with the language of the request, never T(): this task has no request. */
    const lang_t l = rsu_job.de ? LANG_DE : LANG_EN;
    bool truncated = false, failed = false;
    uint32_t replay_drop0 = mqtt_replay_dropped();

    rsu_batch_t *b = heap_caps_calloc(1, sizeof(*b), MALLOC_CAP_SPIRAM);
    uint8_t *buf = b ? heap_caps_malloc(RSU_BATCH_BYTES, MALLOC_CAP_SPIRAM) : NULL;
    if (!b || !buf)
    {
        snprintf(rsu_job.result, sizeof(rsu_job.result), "%s", web_str(S_RSU_R_NOMEM, l));
        goto out;
    }
    b->buf = buf;

    /* The newest minutes are still in the PSRAM ring. Without this check the last
     * window before "now" would be re-sent short but reported as complete. The
     * search and the export check this for the same reason. A window that ended
     * earlier is complete on the card, and a false alarm invites a second re-send. */
    if (!pcap_window_on_card(rsu_job.to))
        truncated = true;

    /* Hour by hour: each walk covers exactly one file. The batch is drained between
     * walks, while the SD lock is released. */
    for (uint32_t h = rsu_job.from - rsu_job.from % 3600;
         h <= rsu_job.to && !failed; h += 3600)
    {
        uint32_t f = h > rsu_job.from ? h : rsu_job.from;
        uint32_t t = (h + 3599 < rsu_job.to) ? h + 3599 : rsu_job.to;
        b->full = false;
        bool complete = sdpcap_read_frames(f, t, rsu_collect_cb, b);
        if (!rsu_drain_batch(b))
            failed = true;
        if (!complete || b->full)
            truncated = true;
    }

    if (!failed)
    {
        /* "sent" only means queued. Wait for our frames to leave the shared queue,
         * then report exactly how many were not published. */
        for (int w = 0; mqtt_replay_pending() > 0 && w < 5000; w += 100)
            vTaskDelay(pdMS_TO_TICKS(100));
        uint32_t undelivered = (mqtt_replay_dropped() - replay_drop0)
                             + mqtt_replay_pending();
        char und[80] = "";
        if (undelivered)
            snprintf(und, sizeof(und), web_str(S_RSU_R_UNDELIV, l), (unsigned long)undelivered);

        snprintf(rsu_job.result, sizeof(rsu_job.result), web_str(S_RSU_R_DONE, l),
                 (unsigned long)rsu_job.sent, (unsigned long)rsu_job.stations,
                 (unsigned long)rsu_job.thinned,
                 truncated ? web_str(S_RSU_R_PARTIAL, l) : "",
                 rsu_job.pairs_overflow ? web_str(S_RSU_R_PAIRS, l) : "",
                 und);
    }

out:
    free(buf);
    free(b);
    rsu_job.running = false;
    vTaskDelete(NULL);
}

esp_err_t rsu_upload_post_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    if (rsu_job.running)
    {
        httpd_resp_sendstr(req, T(S_RSU_UP_BUSY));
        return ESP_OK;
    }
    if (!mqtt_connected_state)
    {
        httpd_resp_sendstr(req, T(S_RSU_UP_NOMQTT));
        return ESP_OK;
    }

    time_t now = time(NULL);
    long from = (long)now - 24 * 3600, to = (long)now, thin = 0;
    char query[96];
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        char val[16];
        if (httpd_query_key_value(query, "from", val, sizeof(val)) == ESP_OK)
            from = strtol(val, NULL, 10);
        if (httpd_query_key_value(query, "to", val, sizeof(val)) == ESP_OK)
            to = strtol(val, NULL, 10);
        if (httpd_query_key_value(query, "thin", val, sizeof(val)) == ESP_OK)
            thin = strtol(val, NULL, 10);
    }
    if (to > (long)now) to = (long)now;
    if (from < 0)       from = 0;
    if (to <= from)     to = from + 3600;
    if (to - from > 24L * 3600)         /* hard cap: one day per upload */
        from = to - 24L * 3600;
    if (thin < 0) thin = 0;
    if (thin > 0 && thin < 600) thin = 600;  /* finer thinning overfills the hourly batch */

    memset(&rsu_job, 0, sizeof(rsu_job));
    rsu_job.from = (uint32_t)from;
    rsu_job.to = (uint32_t)to;
    rsu_job.thin = (uint32_t)thin;
    rsu_job.de = web_lang() == LANG_DE;
    rsu_job.running = true;
    if (xTaskCreate(rsu_upload_task, "rsuup", 12288, NULL, 2, NULL) != pdPASS)
    {
        rsu_job.running = false;
        httpd_resp_sendstr(req, "Error");
        return ESP_OK;
    }
    httpd_resp_sendstr(req, "OK");
    return ESP_OK;
}

/* GET /sdcard/upload_rsu/status -- progress for the page's poll. Read-only. */
esp_err_t rsu_upload_status_handler(httpd_req_t *req)
{
    char out[320];
    if (rsu_job.running)
        snprintf(out, sizeof(out), "{\"run\":1,\"sent\":%lu}",
                 (unsigned long)rsu_job.sent);
    else
        /* result holds only numbers and texts from the table (S_RSU_R_*). The table forbids
         * quotes and backslashes in those texts, so result can be embedded unescaped. */
        snprintf(out, sizeof(out), "{\"run\":0,\"msg\":\"%s\"}", rsu_job.result);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return httpd_resp_sendstr(req, out);
}

esp_err_t sdcard_format_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* Formatting means the card is meant to be in use again. */
    sdcard_allow_auto_remount();
    esp_err_t e = sdcard_format();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, e == ESP_OK ? "OK" : "Error");
    return e == ESP_OK ? ESP_OK : ESP_FAIL;
}

esp_err_t sdcard_mount_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* Mounting by hand takes the device out of the prepared-for-power-off
     * state, so let sysmon look after the card again. */
    sdcard_allow_auto_remount();
    /* A manual mount (auto_retry=false) is refused in practice only by the needs-restart
     * latch sdcard.c sets when a format did not mount back. The IDF returns the same code
     * for a double registration. Redirecting would show the same page with the same button
     * again, and nothing would ever say why it does nothing. */
    if (sdcard_mount() == ESP_ERR_INVALID_STATE)
    {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, T(S_SD_NEEDS_RESTART));
        return ESP_FAIL;
    }
    httpd_resp_set_status(req, "303 See Other");
    /* lang= goes into the target, because the redirected GET is a new request and
     * resolve_language() would fall back to the browser's language. The targets are
     * literals because set_hdr keeps the pointer. */
    httpd_resp_set_hdr(req, "Location",
                       web_lang() == LANG_EN ? "/sdcard?lang=en" : "/sdcard?lang=de");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  /fs  -- read-only browser for the internal FAT storage (/data)    */
/*  Reached from the flash group at the end of the file-management    */
/*  page. Deliberately view+download only: /data is system storage,   */
/*  no upload/delete/format like the removable SD card.               */
/* ================================================================== */


static void data_full_path(const char *rel, char *out, size_t out_size)
{
    if (rel && rel[0])
        snprintf(out, out_size, "%s/%s", DATA_MOUNT, rel);
    else
        snprintf(out, out_size, "%s", DATA_MOUNT);
}

esp_err_t internal_get_handler(httpd_req_t *req)
{
    resolve_language(req);
    if (!check_update_auth(req))
        return send_auth_required(req);

    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)))
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }

    const char *lq = web_lang() == LANG_EN ? "en" : "de";
    /* Its own title, not the one of /sdcard. The step back to /sdcard is in the path line, and
     * under the same title that link would look as if it led to this page. */
    send_page_header(req, T(S_FS_INTERNAL));

    /* The path is not in here (send_path_crumbs escapes it per step), so a small
     * stack buffer is enough: 1024 against a measured 821. */
    char head[1024];
    HTML_PRINTF(head,
        /* Path in a span, because the heading is uppercased. A mount point is
         * case-sensitive, and "/DATA" names something that does not exist. */
        "<div class='grp top'><h2>%s &middot; <span class='path'>/data</span></h2>"
        "<p class='btnrow tools'><button onclick='seltar()'>&#8595; %s</button></p>"
        "<p class='note hlp'>%s</p>"
        "<script>function selall(c){document.querySelectorAll('.sel').forEach(function(x){x.checked=c.checked;});}"
        "function seltar(){var s=[];document.querySelectorAll('.sel:checked').forEach("
        "function(c){s.push(encodeURIComponent(c.value));});"
        "if(!s.length){alert('%s');return;}location.href='/fs/tar?sel='+s.join('|');}</script>",
        T(S_FS_INTERNAL),
        T(S_TAR_SELECTED),
        T(S_TAR_HINT),
        T(S_TAR_NONE));
    httpd_resp_send_chunk(req, head, HTTPD_RESP_USE_STRLEN);

    send_path_crumbs(req, "/fs", lq, rel, "/sdcard", T(S_TITLE_SD));

    /* The sorter only moves rows inside <tbody id='dbody'>, and without it
     * the page cannot sort. The header row stays outside it in <thead>. */
    /* 512 against a measured 232. */
    char tblopen[512];
    HTML_PRINTF(tblopen,
        "<div class='scroll'><table><thead><tr>"
        "<th><label><input type='checkbox' onclick='selall(this)' aria-label='%s'></label></th>"
        "<th data-c='1'>%s</th>"
        "<th data-c='2'>%s</th></tr></thead><tbody id='dbody'>",
        T(S_A11Y_SELECT_ALL), T(S_SD_NAME), T(S_SD_SIZE));
    httpd_resp_send_chunk(req, tblopen, HTTPD_RESP_USE_STRLEN);

    /* Parent-directory link */
    if (rel[0])
    {
        char parent[SD_PATH_MAX];
        strlcpy(parent, rel, sizeof(parent));
        char *slash = strrchr(parent, '/');
        if (slash) *slash = '\0'; else parent[0] = '\0';
        char penc[SD_PATH_MAX * 3];
        url_encode(parent, penc, sizeof(penc));
        /* data-fix keeps this row out of the sort, hence always on top. */
        char row[SD_PATH_MAX * 3 + 192];
        snprintf(row, sizeof(row),
            "<tr data-fix='1'><td></td><td><a href='/fs?p=%s&amp;lang=%s'>%s</a></td><td></td></tr>",
            penc, lq, T(S_SD_PARENT));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    char full[SD_PATH_MAX];
    data_full_path(rel, full, sizeof(full));
    DIR *dir = opendir(full);
    size_t entries = 0;
    if (dir)
    {
        struct dirent *de;
        while ((de = readdir(dir)) != NULL)
        {
            if (de->d_name[0] == '.')
                continue;
            entries++;

            char childrel[SD_PATH_MAX + 256];
            if (rel[0]) snprintf(childrel, sizeof(childrel), "%s/%s", rel, de->d_name);
            else        snprintf(childrel, sizeof(childrel), "%s", de->d_name);

            char childfull[SD_PATH_MAX + 288];
            data_full_path(childrel, childfull, sizeof(childfull));
            struct stat st;
            bool is_dir = (stat(childfull, &st) == 0) && S_ISDIR(st.st_mode);

            static EXT_RAM_BSS_ATTR char nameesc[256], relenc2[SD_PATH_MAX * 3];
            static EXT_RAM_BSS_ATTR char relhtml[SD_PATH_MAX * 6];
            html_escape(de->d_name, nameesc, sizeof(nameesc));
            url_encode(childrel, relenc2, sizeof(relenc2));
            html_escape(childrel, relhtml, sizeof(relhtml));

            /* 16x holds the path once escaped (checkbox value) and once url-encoded (link),
             * plus the name twice, once in the checkbox's aria-label. Worst case 3616 of 5120. */
            static EXT_RAM_BSS_ATTR char row[SD_PATH_MAX * 16];
            if (is_dir)
            {
                snprintf(row, sizeof(row),
                    "<tr data-d='1' data-sz='0'><td><label><input type='checkbox' class='sel'"
                    " aria-label='%s: %s' value='%s'></label></td>"
                    "<td><a href='/fs?p=%s&amp;lang=%s'>%s/</a></td><td></td></tr>",
                    T(S_A11Y_SELECT_ROW), nameesc, relhtml, relenc2, lq, nameesc);
            }
            else
            {
                char sz[32];
                fmt_bytes((uint64_t)st.st_size, web_lang(), sz, sizeof(sz));
                /* data-d/data-sz feed the sorter: the displayed size is already
                 * formatted ("1,0 MB") and cannot be compared numerically. */
                snprintf(row, sizeof(row),
                    "<tr data-d='0' data-sz='%llu'><td><label><input type='checkbox' class='sel'"
                    " aria-label='%s: %s' value='%s'></label></td>"
                    "<td><a href='/fs/download?p=%s'>%s</a></td><td>%s</td></tr>",
                    (unsigned long long)st.st_size,
                    T(S_A11Y_SELECT_ROW), nameesc, relhtml, relenc2, nameesc, sz);
            }
            httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
        }
        closedir(dir);
    }

    if (entries == 0)
    {
        char row[128];
        snprintf(row, sizeof(row), "<tr data-fix='1'><td colspan='3'>%s</td></tr>", T(S_SD_EMPTY));
        httpd_resp_send_chunk(req, row, HTTPD_RESP_USE_STRLEN);
    }

    httpd_resp_send_chunk(req, "</tbody></table></div>", HTTPD_RESP_USE_STRLEN);
    send_dir_sort_script(req);
    /* Closes the /data group opened above. */
    httpd_resp_send_chunk(req, "</div>", HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, PAGE_FOOTER, HTTPD_RESP_USE_STRLEN);
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

esp_err_t internal_download_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    char rel[SD_PATH_MAX];
    if (!sd_get_relpath(req, rel, sizeof(rel)) || rel[0] == '\0')
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
        return ESP_FAIL;
    }
    char full[SD_PATH_MAX];
    data_full_path(rel, full, sizeof(full));
    FILE *f = fopen(full, "rb");
    if (!f)
        return send_open_failed(req, full, errno);
    const char *base = strrchr(rel, '/');
    base = base ? base + 1 : rel;
    char basesafe[SD_PATH_MAX];
    sanitize_disp_filename(base, basesafe, sizeof(basesafe));
    char disp[SD_PATH_MAX + 64];
    snprintf(disp, sizeof(disp), "attachment; filename=\"%s\"", basesafe);
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", disp);

    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0)
    {
        if (httpd_resp_send_chunk(req, buf, n) != ESP_OK)
        {
            fclose(f);
            return ESP_FAIL;
        }
    }
    /* As on the card: a read error must break the download, not end it short. */
    bool rd_err = ferror(f) != 0;
    fclose(f);
    if (rd_err)
    {
        ESP_LOGW(TAG, "download: read error in %s, aborted", full);
        return ESP_FAIL;
    }
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

/* ================================================================== */
/*  Raw partition image download  (/fs/part?label=...)                */
/* ================================================================== */

/* The part of an image's file name that says what it holds. An app slot is named by its
 * version, the crash dump by the firmware that crashed, anything else by label and time. */
static void part_what(const esp_partition_t *p, char *out, size_t cap)
{
    esp_app_desc_t d;
    if (p->type == ESP_PARTITION_TYPE_APP && esp_ota_get_partition_description(p, &d) == ESP_OK)
    {
        snprintf(out, cap, "%s-%.31s", p->label, d.version);
        return;
    }
#if CONFIG_ESP_COREDUMP_ENABLE_TO_FLASH
    /* The dump belongs to the firmware that crashed, which after an update is the one in the
     * other slot. Its summary holds the start of that firmware's ELF hash, the one esp-coredump
     * checks. */
    if (p->type == ESP_PARTITION_TYPE_DATA && p->subtype == ESP_PARTITION_SUBTYPE_DATA_COREDUMP &&
        web_coredump_present())
    {
        /* About 1.1 KB with the stack copy in it, so PSRAM first. Zeroed: a dump without its
         * version note leaves the hash unwritten, and "" then names nothing. */
        esp_core_dump_summary_t *sum = heap_caps_calloc(1, sizeof(*sum), MALLOC_CAP_SPIRAM);
        if (!sum)
            sum = calloc(1, sizeof(*sum));
        bool named = false;
        if (sum && esp_core_dump_get_summary(sum) == ESP_OK)
        {
            char *h = (char *)sum->app_elf_sha256;
            h[sizeof(sum->app_elf_sha256) - 1] = '\0';
            size_t n = strlen(h);
            /* Nine hex digits with CONFIG_APP_RETRIEVE_LEN_ELF_SHA=9. Fewer than eight
             * would match by chance. Every slot is walked, so the iterator ends released. */
            if (n >= 8 && n <= 64)
            {
                esp_partition_iterator_t it =
                    esp_partition_find(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_ANY, NULL);
                for (; it != NULL; it = esp_partition_next(it))
                {
                    char hex[65];
                    if (named ||
                        esp_ota_get_partition_description(esp_partition_get(it), &d) != ESP_OK)
                        continue;
                    for (size_t i = 0; i < sizeof(d.app_elf_sha256); i++)
                        snprintf(hex + 2 * i, 3, "%02x", d.app_elf_sha256[i]);
                    if (strncmp(hex, h, n) == 0)
                    {
                        snprintf(out, cap, "%s-%.31s", p->label, d.version);
                        named = true;
                    }
                }
                if (!named)
                {
                    snprintf(out, cap, "%s-elf-%s", p->label, h);
                    named = true;
                }
            }
        }
        free(sum);
        if (named)
            return;
    }
#endif
    char stamp[16];
    web_dl_stamp(stamp, sizeof(stamp), time(NULL));
    snprintf(out, cap, "%s%s%s", p->label, stamp[0] ? "-" : "", stamp);
}

esp_err_t partimg_download_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    char query[128], label[24] = "";
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
        httpd_query_key_value(query, "label", label, sizeof(label));
    url_decode(label);
    if (label[0] == '\0')
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no label");
        return ESP_FAIL;
    }
    /* Look the label up in the partition table. Only a real partition can match,
     * so this cannot be used to read arbitrary flash. */
    const esp_partition_t *p =
        esp_partition_find_first(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, label);
    if (!p)
    {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "no partition");
        return ESP_FAIL;
    }
    /* its-<node id>-ota_1-0.38.16-webui.img: what 48 of 64 (label 16, version 31). */
    char what[64], disp[WEB_DL_DISP_MAX];
    part_what(p, what, sizeof(what));
    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition", web_dl_disp(disp, sizeof(disp), what, "img"));

    static EXT_RAM_BSS_ATTR uint8_t partbuf[4096];
    for (size_t off = 0; off < p->size; off += sizeof(partbuf))
    {
        size_t n = (p->size - off) < sizeof(partbuf) ? (p->size - off) : sizeof(partbuf);
        esp_err_t e = esp_partition_read(p, off, partbuf, n);
        if (e != ESP_OK)
        {
            /* A flash fault, not a browser that left, and nothing else logs it: the worker only
             * closes the socket. */
            ESP_LOGW(TAG, "%s: read at 0x%x failed (%s), download cut", p->label, (unsigned)off,
                     esp_err_to_name(e));
            return ESP_FAIL;
        }
        if (httpd_resp_send_chunk(req, (const char *)partbuf, n) != ESP_OK)
            return ESP_FAIL;
    }
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

#endif /* CONFIG_ENABLE_SD */
