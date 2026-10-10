#include "mqtt_uri.h"

#include <string.h>

#define MASK_LEN (sizeof(MQTT_URI_MASK) - 1)

/* Byte offsets into the URI. auth == 0 means there is no "://" and so no userinfo. */
typedef struct {
    size_t auth;    /* first byte after "://" */
    size_t end;     /* end of the authority: the first '/', '?' or '#' */
    size_t host;    /* first byte after the last '@', or auth */
    size_t pw;      /* first byte of a non-empty password, 0 when there is none */
    size_t pw_end;  /* the '@' that ends it */
} uri_parts_t;

static bool uri_split(const char *uri, uri_parts_t *p)
{
    memset(p, 0, sizeof(*p));
    const char *sep = strstr(uri, "://");
    if (!sep)
        return false;
    p->auth = (size_t)(sep - uri) + 3;
    p->end = p->auth + strcspn(uri + p->auth, "/?#");
    p->host = p->auth;
    for (size_t i = p->auth; i < p->end; i++)
        if (uri[i] == '@')
            p->host = i + 1;
    if (p->host > p->auth)
    {
        /* The first ':' of the userinfo, because esp-mqtt splits there (strchr). */
        size_t at = p->host - 1;
        const char *colon = memchr(uri + p->auth, ':', at - p->auth);
        if (colon && (size_t)(colon - uri) + 1 < at)
        {
            p->pw = (size_t)(colon - uri) + 1;
            p->pw_end = at;
        }
    }
    return true;
}

bool mqtt_uri_mask(const char *uri, char *out, size_t cap)
{
    if (!out || !cap)
        return false;
    out[0] = '\0';
    if (!uri)
        uri = "";
    uri_parts_t p;
    size_t len = strlen(uri);
    bool pw = uri_split(uri, &p) && p.pw;
    size_t need = pw ? len - (p.pw_end - p.pw) + MASK_LEN : len;
    if (need >= cap)
        return false;
    if (!pw)
    {
        memcpy(out, uri, len + 1);
        return true;
    }
    memcpy(out, uri, p.pw);
    memcpy(out + p.pw, MQTT_URI_MASK, MASK_LEN);
    memcpy(out + p.pw + MASK_LEN, uri + p.pw_end, len - p.pw_end + 1);
    return true;
}

bool mqtt_uri_has_mask(const char *uri)
{
    uri_parts_t p;
    if (!uri || !uri_split(uri, &p) || !p.pw)
        return false;
    /* One U+2022 is enough: a mask with a typed character next to it must not be stored. */
    for (size_t i = p.pw; i + 3 <= p.pw_end; i++)
        if (memcmp(uri + i, "\xE2\x80\xA2", 3) == 0)
            return true;
    return false;
}

static bool host_char(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
           c == '.' || c == '_' || c == '-';
}

static bool ipv6_char(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F') ||
           c == ':' || c == '.';
}

void mqtt_uri_host(const char *uri, char *out, size_t cap)
{
    if (!out || !cap)
        return;
    out[0] = '\0';
    uri_parts_t p;
    if (!uri || !uri_split(uri, &p))
        return;
    size_t i = p.host, n = 0;
    if (i < p.end && uri[i] == '[')
    {
        size_t j = i + 1;
        while (j < p.end && ipv6_char(uri[j]))
            j++;
        /* Kept whole with its brackets. Only a port may follow. */
        if (j >= p.end || uri[j] != ']' || j == i + 1)
            return;
        n = j + 1 - i;
        if (i + n < p.end && uri[i + n] != ':')
            return;
    }
    else
    {
        while (i + n < p.end && uri[i + n] != ':')
        {
            if (!host_char(uri[i + n]))
                return;
            n++;
        }
    }
    if (n == 0 || n > MQTT_URI_HOST_MAX || n >= cap)
        return;
    memcpy(out, uri + i, n);
    out[n] = '\0';
}
