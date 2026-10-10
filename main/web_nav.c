#include "sdkconfig.h"

#include "web_nav.h"

#include <string.h>

#include "webserver_priv.h"

/* Four groups instead of twelve equal entries. Status stands alone. */
enum { NAV_STATUS, NAV_ROAD, NAV_RADIO, NAV_DEVICE, NAV_GROUPS };

static const str_id_t GROUP_NAME[NAV_GROUPS] = {
    [NAV_STATUS] = S_NAV_STATUS, [NAV_ROAD] = S_NAV_G_ROAD,
    [NAV_RADIO] = S_NAV_G_RADIO, [NAV_DEVICE] = S_NAV_G_DEVICE,
};

/* Menu order. The first page of a group is where the group's link leads, so it must exist
 * without SD. `also` names a page without a tab of its own that marks this one as active. */
typedef struct {
    const char *path;
    const char *also;
    str_id_t    name;
    uint8_t     group;
} nav_page_t;

static const nav_page_t PAGES[] = {
    { "/",         NULL,  S_NAV_STATUS,   NAV_STATUS },
    { "/map",      NULL,  S_NAV_MAP,      NAV_ROAD   },
#if CONFIG_ENABLE_SD
    { "/traffic",  NULL,  S_NAV_TRAFFIC,  NAV_ROAD   },
#endif
    { "/transit",  NULL,  S_NAV_TRANSIT,  NAV_ROAD   },
    { "/senders",  NULL,  S_NAV_SENDERS,  NAV_ROAD   },
    { "/messages", NULL,  S_NAV_MESSAGES, NAV_RADIO  },
    { "/trust",    NULL,  S_NAV_TRUST,    NAV_RADIO  },
    { "/system",   NULL,  S_NAV_SYSTEM,   NAV_DEVICE },
#if CONFIG_ENABLE_SD
    { "/logs",     NULL,  S_NAV_LOGS,     NAV_DEVICE },
    { "/sdcard",   "/fs", S_NAV_SD,       NAV_DEVICE },
#endif
    { "/settings", NULL,  S_NAV_SETTINGS, NAV_DEVICE },
    { "/update",   NULL,  S_NAV_UPDATE,   NAV_DEVICE },
};
#define NAV_PAGES (sizeof(PAGES) / sizeof(PAGES[0]))

/* The request path (n bytes) is p or lies below it: /settings/import belongs to /settings,
 * /settingsx does not. "/" matches only itself. */
static bool nav_hit(const char *uri, size_t n, const char *p)
{
    size_t k = strlen(p);
    if (k == 1)
        return n == 1 && uri[0] == '/';
    return n >= k && memcmp(uri, p, k) == 0 && (n == k || uri[k] == '/');
}

const char *web_nav_build(char *out, size_t cap, const char *uri, const char *lc)
{
    size_t n = strcspn(uri, "?#");
    int here = -1;
    for (size_t i = 0; i < NAV_PAGES && here < 0; i++)
        if (nav_hit(uri, n, PAGES[i].path) || (PAGES[i].also && nav_hit(uri, n, PAGES[i].also)))
            here = (int)i;
    int grp = here >= 0 ? PAGES[here].group : -1;

    int at = web_addf(out, cap, 0, "<div class='navlinks'>");
    for (int g = 0; g < NAV_GROUPS; g++)
        for (size_t i = 0; i < NAV_PAGES; i++)
            if (PAGES[i].group == g)
            {
                at = web_addf(out, cap, at, "<a href='%s?lang=%s'%s>%s</a>", PAGES[i].path, lc,
                              g == grp ? " class='active'" : "", T(GROUP_NAME[g]));
                break;
            }
    at = web_addf(out, cap, at, "</div>");

    /* The row of the group's pages. A group of one page (Status) has none. */
    int in_grp = 0;
    for (size_t i = 0; i < NAV_PAGES; i++)
        in_grp += grp >= 0 && PAGES[i].group == grp;
    if (in_grp > 1)
    {
        at = web_addf(out, cap, at, "<div class='subnav'><div>");
        for (size_t i = 0; i < NAV_PAGES; i++)
            if (PAGES[i].group == grp)
                at = web_addf(out, cap, at, "<a href='%s?lang=%s'%s>%s</a>", PAGES[i].path, lc,
                              (int)i == here ? " class='active'" : "", T(PAGES[i].name));
        web_addf(out, cap, at, "</div></div>");
    }
    return grp >= 0 ? T(GROUP_NAME[grp]) : "";
}
