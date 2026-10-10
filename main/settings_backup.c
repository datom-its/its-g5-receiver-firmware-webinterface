#include "settings_backup.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

/* ================================================================== */
/*  Import                                                            */
/* ================================================================== */

/* Settings that other builds of this firmware have. A file from such a build is not wrong,
 * so these keys are reported as left out of this build instead of unknown. */
static const char *const OPTIONAL_KEYS[] = {
    "ethleds", "logsys", "logmaxmb", "pcapen", "pcaphours", "pcapmaxmb", "pcapbufmb",
    "pcapflushsec", "pcapfilt", "trkon", "trkdays", "statsdays", "eventdays",
};

static const char *const META_KEYS[] = {
    "format", "format_version", "firmware", "node_id", "exported_at", "settings",
};

static bool in_list(const char *key, const char *const *list, size_t n)
{
    for (size_t i = 0; i < n; i++)
        if (strcmp(key, list[i]) == 0)
            return true;
    return false;
}

static const sj_member_t *find_member(const sj_member_t *m, size_t n, const char *key)
{
    for (size_t i = 0; i < n; i++)
        if (!m[i].key_cut && strcmp(m[i].key, key) == 0)
            return &m[i];
    return NULL;
}

static void add_item(sb_result_t *res, const char *key, set_id_t id, sb_outcome_t outcome,
                     set_err_t err, sb_why_t why)
{
    switch (outcome)
    {
    case SB_APPLIED:   res->applied++;   break;
    case SB_UNCHANGED: res->unchanged++; break;
    case SB_REJECTED:  res->rejected++;  break;
    case SB_IGNORED:   res->ignored++;   break;
    }
    if (outcome == SB_APPLIED && id < SET_COUNT && SET_DEFS[id].reboot)
        res->reboot = true;
    if (res->n >= sizeof(res->items) / sizeof(res->items[0]))
        return;
    sb_item_t *it = &res->items[res->n++];
    snprintf(it->key, sizeof(it->key), "%s", key);
    it->id = id;
    it->outcome = outcome;
    it->err = err;
    it->why = why;
}

static void add_applied(sb_result_t *res, const char *key, set_id_t id, set_err_t err, bool changed)
{
    add_item(res, key, id, err != SET_OK ? SB_REJECTED : changed ? SB_APPLIED : SB_UNCHANGED,
             err, SB_WHY_NONE);
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Turns a JSON value into the text the form would send for this setting. Only the JSON type
 * and the conversion are checked here. Whether the value is allowed is set_apply()'s job. */
static set_err_t form_value(const set_def_t *d, const sj_member_t *m, char *out, size_t cap)
{
    switch (d->kind)
    {
    case SET_KIND_BOOL:
        if (m->type != SJ_BOOL)
            return SET_ERR_TYPE;
        snprintf(out, cap, "%s", m->b ? "1" : "0");
        return SET_OK;
    case SET_KIND_UINT:
    case SET_KIND_CHAN:
        if (m->type != SJ_INT)
            return SET_ERR_TYPE;
        snprintf(out, cap, "%lld", m->num);
        return SET_OK;
    case SET_KIND_COLOR:
    {
        /* The file shows the colour the way the colour picker does, as #rrggbb. */
        if (m->type != SJ_STR)
            return SET_ERR_TYPE;
        if (m->str_nul || strlen(m->str) != 7 || m->str[0] != '#')
            return SET_ERR_COLOR;
        unsigned long rgb = 0;
        for (int i = 1; i < 7; i++)
        {
            int h = hex_digit(m->str[i]);
            if (h < 0)
                return SET_ERR_COLOR;
            rgb = rgb * 16 + (unsigned long)h;
        }
        snprintf(out, cap, "%lu", rgb);
        return SET_OK;
    }
    case SET_KIND_STR:
    case SET_KIND_IPV4:
    case SET_KIND_ADDR:
        if (m->type != SJ_STR)
            return SET_ERR_TYPE;
        if (m->str_nul)
            return SET_ERR_CHARS;
        if (m->str_cut)
            return SET_ERR_LONG;
        snprintf(out, cap, "%s", m->str);
        return SET_OK;
    default:
        return SET_ERR_TYPE;
    }
}

/* "dhcp" and the three static address parts are judged together, like the form does. */
static void import_address(const sb_work_t *w, size_t set_n, sb_result_t *res)
{
    static const set_id_t part_id[3] = { SET_ETHIP, SET_ETHNM, SET_ETHGW };
    const sj_member_t *dhcp = find_member(w->set, set_n, SET_DEFS[SET_DHCP].key);
    const sj_member_t *part[3];
    for (int i = 0; i < 3; i++)
        part[i] = find_member(w->set, set_n, SET_DEFS[part_id[i]].key);

    if (!dhcp)
    {
        for (int i = 0; i < 3; i++)
            if (part[i])
                add_item(res, part[i]->key, part_id[i], SB_IGNORED, SET_OK, SB_WHY_NEEDS_DHCP);
        return;
    }
    if (dhcp->type != SJ_BOOL)
    {
        add_item(res, dhcp->key, SET_DHCP, SB_REJECTED, SET_ERR_TYPE, SB_WHY_NONE);
        for (int i = 0; i < 3; i++)
            if (part[i])
                add_item(res, part[i]->key, part_id[i], SB_IGNORED, SET_OK, SB_WHY_NEEDS_DHCP);
        return;
    }

    bool changed = false;
    if (dhcp->b)
    {
        add_applied(res, dhcp->key, SET_DHCP, set_apply_address("1", "", "", "", &changed), changed);
        /* The export writes the empty parts too. Only a filled one is worth a line. */
        for (int i = 0; i < 3; i++)
            if (part[i] && !(part[i]->type == SJ_STR && part[i]->str[0] == '\0'))
                add_item(res, part[i]->key, part_id[i], SB_IGNORED, SET_OK, SB_WHY_DHCP_UNUSED);
        return;
    }

    char val[3][SJ_STR_LEN];
    set_err_t part_err[3];
    bool type_bad = false;
    for (int i = 0; i < 3; i++)
    {
        val[i][0] = '\0';
        part_err[i] = part[i] ? form_value(&SET_DEFS[part_id[i]], part[i], val[i], sizeof(val[i]))
                              : SET_OK;
        if (part_err[i] != SET_OK)
            type_bad = true;
    }
    set_err_t e = type_bad ? SET_ERR_STATIC_IP
                           : set_apply_address("0", val[0], val[1], val[2], &changed);
    add_applied(res, dhcp->key, SET_DHCP, e, changed);
    for (int i = 0; i < 3; i++)
        if (part[i])
            add_applied(res, part[i]->key, part_id[i],
                        part_err[i] != SET_OK ? part_err[i] : e, changed);
}

void settings_import(const char *json, size_t len, bool with_device,
                     sb_work_t *w, sb_result_t *res)
{
    memset(res, 0, sizeof(*res));
    size_t top_n = 0, set_n = 0;
    switch (settings_json_parse(json, len, w->top, SB_TOP_MAX, &top_n,
                                w->set, SB_SET_MAX, &set_n))
    {
    case SJ_PARSE_OK:       break;
    case SJ_PARSE_EMPTY:    res->file_err = SB_FILE_EMPTY;    return;
    case SJ_PARSE_NOMEM:    res->file_err = SB_FILE_NOMEM;    return;
    case SJ_PARSE_TOO_MANY: res->file_err = SB_FILE_TOO_MANY; return;
    default:                res->file_err = SB_FILE_JSON;     return;
    }

    const sj_member_t *fmt = find_member(w->top, top_n, "format");
    const sj_member_t *ver = find_member(w->top, top_n, "format_version");
    const sj_member_t *st  = find_member(w->top, top_n, "settings");
    if (!fmt || fmt->type != SJ_STR || fmt->str_cut || fmt->str_nul ||
        strcmp(fmt->str, SETTINGS_FILE_FORMAT) != 0 ||
        !ver || ver->type != SJ_INT || ver->num < 1)
    {
        res->file_err = SB_FILE_FORMAT;
        return;
    }
    if (ver->num > SETTINGS_FILE_VERSION)
    {
        res->file_err = SB_FILE_NEWER;
        return;
    }
    if (!st || st->type != SJ_OBJECT)
    {
        res->file_err = SB_FILE_FORMAT;
        return;
    }

    for (size_t i = 0; i < top_n; i++)
    {
        const sj_member_t *m = &w->top[i];
        if (m->key_cut || !in_list(m->key, META_KEYS, sizeof(META_KEYS) / sizeof(META_KEYS[0])))
            add_item(res, m->key, SET_COUNT, SB_IGNORED, SET_OK, SB_WHY_UNKNOWN);
    }

    for (size_t i = 0; i < set_n; i++)
    {
        const sj_member_t *m = &w->set[i];
        set_id_t id = m->key_cut ? SET_COUNT : set_find(m->key);
        if (id == SET_COUNT)
        {
            sb_why_t why = SB_WHY_UNKNOWN;
            if (!m->key_cut && (strcmp(m->key, "webpasswd") == 0 || strcmp(m->key, "webpwclear") == 0))
                why = SB_WHY_PASSWORD;
            else if (!m->key_cut &&
                     in_list(m->key, OPTIONAL_KEYS, sizeof(OPTIONAL_KEYS) / sizeof(OPTIONAL_KEYS[0])))
                why = SB_WHY_NOT_BUILT;
            add_item(res, m->key, SET_COUNT, SB_IGNORED, SET_OK, why);
            continue;
        }
        const set_def_t *d = &SET_DEFS[id];
        if (d->device && !with_device)
        {
            add_item(res, m->key, id, SB_IGNORED, SET_OK, SB_WHY_DEVICE);
            continue;
        }
        if (d->kind == SET_KIND_DHCP || d->kind == SET_KIND_ADDR)
            continue;

        char val[SJ_STR_LEN];
        bool changed = false;
        set_err_t e = form_value(d, m, val, sizeof(val));
        if (e == SET_OK)
            e = set_apply(id, val, &changed);
        add_applied(res, m->key, id, e, changed);
    }

    if (with_device)
        import_address(w, set_n, res);
}

/* ================================================================== */
/*  Export                                                            */
/* ================================================================== */

size_t settings_export(const char *firmware, const char *exported_at,
                       sb_work_t *w, char *out, size_t cap)
{
    memset(w, 0, sizeof(*w));
    sj_member_t *t = w->top;

    snprintf(t[0].key, SJ_KEY_LEN, "format");
    t[0].type = SJ_STR;
    snprintf(t[0].str, SJ_STR_LEN, "%s", SETTINGS_FILE_FORMAT);
    snprintf(t[1].key, SJ_KEY_LEN, "format_version");
    t[1].type = SJ_INT;
    t[1].num = SETTINGS_FILE_VERSION;
    snprintf(t[2].key, SJ_KEY_LEN, "firmware");
    t[2].type = SJ_STR;
    snprintf(t[2].str, SJ_STR_LEN, "%s", firmware ? firmware : "");
    snprintf(t[3].key, SJ_KEY_LEN, "node_id");
    t[3].type = SJ_STR;
    set_read(SET_NODEID, t[3].str, SJ_STR_LEN);
    snprintf(t[4].key, SJ_KEY_LEN, "exported_at");
    t[4].type = exported_at ? SJ_STR : SJ_NULL;
    if (exported_at)
        snprintf(t[4].str, SJ_STR_LEN, "%s", exported_at);

    for (int id = 0; id < SET_COUNT; id++)
    {
        const set_def_t *d = &SET_DEFS[id];
        sj_member_t *m = &w->set[id];
        snprintf(m->key, SJ_KEY_LEN, "%s", d->key);
        switch (d->kind)
        {
        case SET_KIND_BOOL:
            m->type = SJ_BOOL;
            m->b = set_read_num((set_id_t)id) != 0;
            break;
        case SET_KIND_DHCP:
        {
            char v[2];
            set_read((set_id_t)id, v, sizeof(v));
            m->type = SJ_BOOL;
            m->b = (v[0] == '1');
            break;
        }
        case SET_KIND_UINT:
        case SET_KIND_CHAN:
            m->type = SJ_INT;
            m->num = set_read_num((set_id_t)id);
            break;
        case SET_KIND_COLOR:
            m->type = SJ_STR;
            snprintf(m->str, SJ_STR_LEN, "#%06lx",
                     (unsigned long)(set_read_num((set_id_t)id) & 0xFFFFFFUL));
            break;
        default:
            m->type = SJ_STR;
            set_read((set_id_t)id, m->str, SJ_STR_LEN);
            break;
        }
    }
    return settings_json_write(w->top, 5, w->set, SET_COUNT, out, cap);
}

/* ================================================================== */
/*  multipart/form-data                                               */
/* ================================================================== */

static size_t mem_find(const char *hay, size_t hay_len, size_t from,
                       const char *needle, size_t n)
{
    if (n == 0 || from > hay_len || hay_len - from < n)
        return SIZE_MAX;
    for (size_t i = from; i + n <= hay_len; i++)
        if (hay[i] == needle[0] && memcmp(hay + i, needle, n) == 0)
            return i;
    return SIZE_MAX;
}

bool multipart_boundary(const char *ct, char *out, size_t cap)
{
    if (!ct || strncasecmp(ct, "multipart/form-data", 19) != 0)
        return false;
    for (const char *p = ct + 19; *p; p++)
    {
        if (strncasecmp(p, "boundary=", 9) != 0 || (p[-1] != ';' && p[-1] != ' ' && p[-1] != '\t'))
            continue;
        p += 9;
        bool quoted = (*p == '"');
        if (quoted)
            p++;
        size_t n = 0;
        while (p[n] && (quoted ? p[n] != '"' : (p[n] != ';' && p[n] != ' ' && p[n] != '\t')))
            n++;
        /* RFC 2046 allows 1 to 70 characters. */
        if (n == 0 || n > 70 || n + 1 > cap)
            return false;
        memcpy(out, p, n);
        out[n] = '\0';
        return true;
    }
    return false;
}

/* True when the part headers carry Content-Disposition with name="<name>". */
static bool part_named(const char *h, size_t hl, const char *name)
{
    static const char CD[] = "content-disposition:";
    size_t nl = strlen(name);
    for (size_t line = 0; line < hl; )
    {
        size_t end = mem_find(h, hl, line, "\r\n", 2);
        if (end == SIZE_MAX)
            end = hl;
        if (end - line >= sizeof(CD) - 1 && strncasecmp(h + line, CD, sizeof(CD) - 1) == 0)
        {
            for (size_t i = line + sizeof(CD) - 1; i + 6 + nl + 1 <= end; i++)
            {
                /* name=, not the tail of filename= */
                if (memcmp(h + i, "name=\"", 6) != 0 ||
                    (h[i - 1] != ';' && h[i - 1] != ' ' && h[i - 1] != '\t'))
                    continue;
                return memcmp(h + i + 6, name, nl) == 0 && h[i + 6 + nl] == '"';
            }
        }
        line = end + 2;
    }
    return false;
}

bool multipart_part(const char *body, size_t len, const char *boundary,
                    const char *name, const char **data, size_t *data_len)
{
    char delim[2 + 2 + 70 + 1];
    int dl = snprintf(delim, sizeof(delim), "\r\n--%s", boundary);
    if (dl < 5 || (size_t)dl >= sizeof(delim))
        return false;

    /* The first delimiter may open the body, without the CRLF in front of it. */
    size_t pos;
    if (len >= (size_t)dl - 2 && memcmp(body, delim + 2, (size_t)dl - 2) == 0)
        pos = (size_t)dl - 2;
    else if ((pos = mem_find(body, len, 0, delim, (size_t)dl)) != SIZE_MAX)
        pos += (size_t)dl;
    else
        return false;

    for (;;)
    {
        if (len - pos >= 2 && body[pos] == '-' && body[pos + 1] == '-')
            return false;
        while (pos < len && (body[pos] == ' ' || body[pos] == '\t'))
            pos++;
        if (len - pos < 2 || body[pos] != '\r' || body[pos + 1] != '\n')
            return false;
        pos += 2;

        size_t hdr_end, dstart;
        if (len - pos >= 2 && body[pos] == '\r' && body[pos + 1] == '\n')
        {
            hdr_end = pos;
            dstart = pos + 2;
        }
        else
        {
            hdr_end = mem_find(body, len, pos, "\r\n\r\n", 4);
            if (hdr_end == SIZE_MAX)
                return false;
            dstart = hdr_end + 4;
        }
        size_t next = mem_find(body, len, dstart, delim, (size_t)dl);
        if (next == SIZE_MAX)
            return false;
        if (part_named(body + pos, hdr_end - pos, name))
        {
            *data = body + dstart;
            *data_len = next - dstart;
            return true;
        }
        pos = next + (size_t)dl;
    }
}
