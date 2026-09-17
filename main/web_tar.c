#include "web_tar.h"

#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "esp_log.h"

#include "sdcard.h"
#include "web_files.h"
#include "webserver_priv.h"

#if CONFIG_ENABLE_SD

/* ================================================================== */
/*  Streaming tar (ustar) writer. Sends a whole folder or a multi-file */
/*  selection as one .tar download. No compression, no external lib.   */
/*  Used by both /sdcard/tar and /fs/tar.                              */
/* ================================================================== */

#define TAR_BLOCK     512
#define TAR_MAX_DEPTH 12

static EXT_RAM_BSS_ATTR char tar_hdr[TAR_BLOCK];
static EXT_RAM_BSS_ATTR char tar_full[SD_PATH_MAX * 2];

/* Write `val` as a NUL-terminated, zero-padded octal string into a header
 * field of the given width (tar numeric fields). */
static void tar_num(char *field, size_t width, uint64_t val)
{
    for (int i = (int)width - 2; i >= 0; i--) { field[i] = '0' + (char)(val & 7); val >>= 3; }
    field[width - 1] = '\0';
}

/* Place the archive member name into the 100-byte name field, using the
 * 155-byte prefix field for long paths (ustar). If the path cannot be split
 * to fit both fields, only its last 100 bytes are kept. */
static void tar_put_name(char *hdr, const char *arc)
{
    size_t len = strlen(arc);
    if (len <= 100) { memcpy(hdr, arc, len); return; }
    size_t split = 0;
    for (size_t i = 0; i < len; i++)
        if (arc[i] == '/' && i <= 155 && (len - i - 1) <= 100) { split = i; break; }
    if (split > 0)
    {
        memcpy(hdr + 345, arc, split);
        memcpy(hdr, arc + split + 1, len - split - 1);
    }
    else
    {
        memcpy(hdr, arc + (len - 100), 100);
    }
}

/* Emit one regular file (header + data + padding). Opens first so a failed
 * open never leaves a dangling header in the stream. Returns false only on a
 * transport error (abort the whole archive). */
static bool tar_send_file(httpd_req_t *req, const char *full, const char *arc, uint64_t size)
{
    FILE *f = fopen(full, "rb");
    if (!f) return true;   /* skip unreadable entry, archive stays valid */

    memset(tar_hdr, 0, TAR_BLOCK);
    tar_put_name(tar_hdr, arc);
    tar_num(tar_hdr + 100, 8, 0644);   /* mode */
    tar_num(tar_hdr + 108, 8, 0);      /* uid  */
    tar_num(tar_hdr + 116, 8, 0);      /* gid  */
    tar_num(tar_hdr + 124, 12, size);  /* size */
    tar_num(tar_hdr + 136, 12, 0);     /* mtime (unknown) */
    tar_hdr[156] = '0';                /* typeflag: regular file */
    memcpy(tar_hdr + 257, "ustar", 5); /* magic "ustar\0" */
    tar_hdr[263] = '0'; tar_hdr[264] = '0';  /* version "00" */
    memset(tar_hdr + 148, ' ', 8);     /* checksum field = spaces while summing */
    unsigned sum = 0;
    for (int i = 0; i < TAR_BLOCK; i++) sum += (unsigned char)tar_hdr[i];
    char cs[8];
    snprintf(cs, sizeof(cs), "%06o", sum & 0777777);
    memcpy(tar_hdr + 148, cs, 6);
    tar_hdr[154] = '\0';
    tar_hdr[155] = ' ';

    if (httpd_resp_send_chunk(req, tar_hdr, TAR_BLOCK) != ESP_OK) { fclose(f); return false; }

    uint64_t remaining = size;
    char buf[TAR_BLOCK];
    while (remaining > 0)
    {
        size_t want = remaining < TAR_BLOCK ? (size_t)remaining : TAR_BLOCK;
        size_t n = fread(buf, 1, want, f);
        if (n < want) memset(buf + n, 0, want - n);  /* honour declared size */
        if (httpd_resp_send_chunk(req, buf, want) != ESP_OK) { fclose(f); return false; }
        remaining -= want;
    }
    fclose(f);

    size_t pad = (size_t)(size % TAR_BLOCK);
    if (pad)
    {
        pad = TAR_BLOCK - pad;
        memset(buf, 0, pad);
        if (httpd_resp_send_chunk(req, buf, pad) != ESP_OK) return false;
    }
    return true;
}

/* Recurse the directory whose absolute path currently occupies tar_full[0..len).
 * `skip` bytes are stripped to form the archive-relative member name. */
static bool tar_walk(httpd_req_t *req, size_t len, size_t skip, int depth)
{
    DIR *d = opendir(tar_full);
    if (!d) return true;
    struct dirent *de;
    bool ok = true;
    while (ok && (de = readdir(d)) != NULL)
    {
        if (de->d_name[0] == '.') continue;
        int add = snprintf(tar_full + len, sizeof(tar_full) - len, "/%s", de->d_name);
        if (add < 0 || (size_t)add >= sizeof(tar_full) - len) { tar_full[len] = '\0'; continue; }
        struct stat st;
        if (stat(tar_full, &st) == 0)
        {
            if (S_ISDIR(st.st_mode))
            {
                if (depth > 0) ok = tar_walk(req, len + (size_t)add, skip, depth - 1);
            }
            else if (S_ISREG(st.st_mode))
            {
                ok = tar_send_file(req, tar_full, tar_full + skip, (uint64_t)st.st_size);
            }
        }
        tar_full[len] = '\0';
    }
    closedir(d);
    return ok;
}

/* Shared handler body: ?sel=a|b|c (pipe-separated, url-encoded members) OR
 * ?p=<dir> (a single directory, default = mount root). */
static esp_err_t tar_download(httpd_req_t *req, const char *mount)
{
    size_t skip = strlen(mount) + 1;
    httpd_resp_set_type(req, "application/x-tar");
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=\"download.tar\"");

    /* Own static buffers, not shared with sdcard_delete_handler. That handler runs
     * on the httpd task and this one on the worker, so both can run at once. */
    static EXT_RAM_BSS_ATTR char query[4096];
    static EXT_RAM_BSS_ATTR char sel[4096];
    sel[0] = '\0';
    char pdir[SD_PATH_MAX] = "";
    bool have_sel = false;
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK)
    {
        if (httpd_query_key_value(query, "sel", sel, sizeof(sel)) == ESP_OK)
            have_sel = true;
        else
            httpd_query_key_value(query, "p", pdir, sizeof(pdir));
    }

    bool ok = true;
    if (have_sel)
    {
        /* Some browsers and proxies percent-encode the '|' separator. FAT
         * filenames can never contain '|', so folding %7C/%7c back into '|'
         * before splitting is unambiguous. */
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

        char *save = NULL;
        for (char *tok = strtok_r(sel, "|", &save); tok && ok; tok = strtok_r(NULL, "|", &save))
        {
            url_decode(tok);
            if (tok[0] == '\0' || strstr(tok, "..") || has_control_char(tok)) continue;
            int fl = snprintf(tar_full, sizeof(tar_full), "%s/%s", mount, tok);
            if (fl < 0 || (size_t)fl >= sizeof(tar_full)) continue;
            struct stat st;
            if (stat(tar_full, &st) != 0) continue;
            if (S_ISDIR(st.st_mode))       ok = tar_walk(req, (size_t)fl, skip, TAR_MAX_DEPTH);
            else if (S_ISREG(st.st_mode))  ok = tar_send_file(req, tar_full, tar_full + skip, (uint64_t)st.st_size);
        }
    }
    else
    {
        url_decode(pdir);
        if (strstr(pdir, "..") || has_control_char(pdir))
        {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "bad path");
            return ESP_FAIL;
        }
        int fl = pdir[0] ? snprintf(tar_full, sizeof(tar_full), "%s/%s", mount, pdir)
                         : snprintf(tar_full, sizeof(tar_full), "%s", mount);
        if (fl > 0 && (size_t)fl < sizeof(tar_full))
            ok = tar_walk(req, (size_t)fl, skip, TAR_MAX_DEPTH);
    }

    if (ok)  /* two zero blocks terminate the archive */
    {
        memset(tar_hdr, 0, TAR_BLOCK);
        httpd_resp_send_chunk(req, tar_hdr, TAR_BLOCK);
        httpd_resp_send_chunk(req, tar_hdr, TAR_BLOCK);
    }
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

esp_err_t sdcard_tar_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    /* Hold a counted reader for the whole archive walk. See sdcard_download_handler. */
    if (!sdcard_read_begin())
    {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "no card");
        return ESP_FAIL;
    }
    esp_err_t r = tar_download(req, sdcard_mount_point());
    sdcard_read_end();
    return r;
}

esp_err_t internal_tar_handler(httpd_req_t *req)
{
    if (!check_update_auth(req))
        return send_auth_required(req);
    return tar_download(req, DATA_MOUNT);
}

#endif /* CONFIG_ENABLE_SD */
