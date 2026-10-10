#include "web_dlname.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "config.h"

/* Kept out of web_fmt.c: this file needs config.h, which the host suites of web_fmt.c lack. */

void web_dl_stamp(char *out, size_t cap, time_t t)
{
    struct tm lt;

    if (!out || !cap)
        return;
    out[0] = '\0';
    /* The clock test used across the firmware: before NTP, t counts from boot. */
    if (t <= 31536000 || !localtime_r(&t, &lt))
        return;
    if (!strftime(out, cap, "%Y%m%d-%H%M", &lt))
        out[0] = '\0';
}

static bool name_char(char c)
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' ||
           c == '_' || c == '-';
}

const char *web_dl_disp(char *out, size_t cap, const char *what, const char *ext)
{
    /* 'attachment; filename="' up to and including the opening quote: 22 bytes. */
    enum { NAME_AT = 22 };
    char node[CONFIG_NODEID_BUFFER_SIZE];
    size_t size = sizeof(node);

    if (!out || !cap)
        return "attachment";
    if (config_get_str(CONFIG_INDEX_NODEID, node, &size) != ESP_OK)
        node[0] = '\0';
    node[sizeof(node) - 1] = '\0';
    int k = snprintf(out, cap, "attachment; filename=\"its-%s%s%.63s.%.7s\"", node, node[0] ? "-" : "",
                     what ? what : "", ext ? ext : "");
    /* Without a name the browser takes it from the URL, better than a cut one. */
    if (k < 0 || (size_t)k >= cap)
    {
        snprintf(out, cap, "attachment");
        return out;
    }
    /* The node id is user text: the whole name keeps only letters, digits, '.', '_' and '-',
     * so nothing can leave the quotes or start a header of its own. */
    for (char *p = out + NAME_AT; p < out + k - 1; p++)
        if (!name_char(*p))
            *p = '_';
    return out;
}
