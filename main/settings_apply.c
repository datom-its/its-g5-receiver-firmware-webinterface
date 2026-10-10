#include "settings_apply.h"

#include <stdio.h>
#include <string.h>

#include "config.h"
#include "ethernet.h"
#include "mqtt_uri.h"
#include "sdlog.h"

const set_def_t SET_DEFS[SET_COUNT] = {
    [SET_NODEID]        = { .key = "nodeid", .kind = SET_KIND_STR, .idx = CONFIG_INDEX_NODEID,
                            .cap = CONFIG_NODEID_BUFFER_SIZE, .reboot = true, .device = true },
    /* .reboot, although stopping and starting reception would do as well. A restart is the
     * one advice that is always right, even when nothing is running. */
    [SET_CHAN]          = { .key = "chan", .kind = SET_KIND_CHAN, .idx = CONFIG_INDEX_AUTOSTART_CHAN,
                            .width = 32, .dflt = 0, .reboot = true },
    [SET_BROADCASTONLY] = { .key = "broadcastonly", .kind = SET_KIND_BOOL, .idx = CONFIG_INDEX_BROADCAST_ONLY,
                            .width = 8, .dflt = 1, .reboot = true },
    [SET_LED]           = { .key = "led", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_LED_BRIGHTNESS,
                            .width = 8, .lo = 0, .hi = 255, .dflt = 0 },
    [SET_LEDOVERRIDE]   = { .key = "ledoverride", .kind = SET_KIND_COLOR, .idx = CONFIG_INDEX_LED_OVERRIDE_COLOR,
                            .width = 32, .dflt = 0 },
    [SET_REFRESHSEC]    = { .key = "refreshsec", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_REFRESH_SEC,
                            .width = 32, .lo = 0, .hi = 3600, .dflt = 5 },
    [SET_MAPSTALE]      = { .key = "mapstale", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_MAP_STALE_SEC,
                            .width = 32, .lo = 10, .hi = 3600, .dflt = 60 },
    [SET_PEERS]         = { .key = "peers", .kind = SET_KIND_STR, .idx = CONFIG_INDEX_PEERS,
                            .cap = CONFIG_PEERS_BUFFER_SIZE, .empty_ok = true },
    [SET_BTEN]          = { .key = "bten", .kind = SET_KIND_BOOL, .idx = CONFIG_INDEX_BT_ENABLE,
                            .width = 8, .dflt = 0, .reboot = true },
    [SET_DHCP]          = { .key = "dhcp", .kind = SET_KIND_DHCP, .reboot = true, .device = true, .net = true },
    [SET_ETHIP]         = { .key = "ethip", .kind = SET_KIND_ADDR, .idx = CONFIG_INDEX_ETH_IP,
                            .cap = CONFIG_IPV4_BUFFER_SIZE, .reboot = true, .device = true, .net = true },
    [SET_ETHNM]         = { .key = "ethnm", .kind = SET_KIND_ADDR, .idx = CONFIG_INDEX_ETH_NETMASK,
                            .cap = CONFIG_IPV4_BUFFER_SIZE, .reboot = true, .device = true, .net = true },
    [SET_ETHGW]         = { .key = "ethgw", .kind = SET_KIND_ADDR, .idx = CONFIG_INDEX_ETH_GATEWAY,
                            .cap = CONFIG_IPV4_BUFFER_SIZE, .reboot = true, .device = true, .net = true },
    [SET_ETHDNS0]       = { .key = "ethdns0", .kind = SET_KIND_IPV4, .idx = CONFIG_INDEX_ETH_DNS0,
                            .cap = CONFIG_IPV4_BUFFER_SIZE, .reboot = true, .net = true },
    [SET_ETHDNS1]       = { .key = "ethdns1", .kind = SET_KIND_IPV4, .idx = CONFIG_INDEX_ETH_DNS1,
                            .cap = CONFIG_IPV4_BUFFER_SIZE, .reboot = true, .net = true },
    [SET_ETHDNS2]       = { .key = "ethdns2", .kind = SET_KIND_IPV4, .idx = CONFIG_INDEX_ETH_DNS2,
                            .cap = CONFIG_IPV4_BUFFER_SIZE, .reboot = true, .net = true },
    [SET_NTPSERVER]     = { .key = "ntpserver", .kind = SET_KIND_STR, .idx = CONFIG_INDEX_NTP_SERVER,
                            .cap = CONFIG_NTP_SERVER_BUFFER_SIZE, .reboot = true },
    /* No .reboot: the /settings POST and the import reload the zone at once. */
    [SET_TZ]            = { .key = "tz", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_TIMEZONE,
                            .width = 8, .lo = 0, .hi = 4, .dflt = 2 },
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
    [SET_ETHLEDS]       = { .key = "ethleds", .kind = SET_KIND_BOOL, .idx = CONFIG_INDEX_ETH_LEDS,
                            .width = 8, .dflt = 1 },
#endif
    [SET_MQTTURI]       = { .key = "mqtturi", .kind = SET_KIND_STR, .idx = CONFIG_INDEX_MQTT_URI,
                            .cap = CONFIG_MQTT_URI_BUFFER_SIZE, .reboot = true },
#if CONFIG_ENABLE_SD
    [SET_LOGSYS]        = { .key = "logsys", .kind = SET_KIND_BOOL, .idx = CONFIG_INDEX_LOG_SYS,
                            .width = 8, .dflt = 0 },
    /* The same bound sdlog enforces, so the form never shows a value the device is not using. */
    [SET_LOGMAXMB]      = { .key = "logmaxmb", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_LOG_MAX_MB,
                            .width = 32, .lo = 1, .hi = SDLOG_MAX_MB, .dflt = 50 },
    [SET_PCAPEN]        = { .key = "pcapen", .kind = SET_KIND_BOOL, .idx = CONFIG_INDEX_PCAP_ENABLE,
                            .width = 8, .dflt = 0 },
    [SET_PCAPHOURS]     = { .key = "pcaphours", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_PCAP_RETAIN_HOURS,
                            .width = 32, .lo = 1, .hi = 720, .dflt = 24 },
    [SET_PCAPMAXMB]     = { .key = "pcapmaxmb", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_PCAP_MAX_MB,
                            .width = 32, .lo = 1, .hi = 100000, .dflt = 300 },
    /* The capture buffer is allocated once at boot. */
    [SET_PCAPBUFMB]     = { .key = "pcapbufmb", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_PCAP_BUF_MB,
                            .width = 32, .lo = 1, .hi = 4, .dflt = 1, .reboot = true },
    [SET_PCAPFLUSHSEC]  = { .key = "pcapflushsec", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_PCAP_FLUSH_SEC,
                            .width = 32, .lo = 8, .hi = 3600, .dflt = 300 },
    [SET_PCAPFILT]      = { .key = "pcapfilt", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_PCAP_FILTER,
                            .width = 8, .lo = 0, .hi = 2, .dflt = 0 },
    [SET_TRKON]         = { .key = "trkon", .kind = SET_KIND_BOOL, .idx = CONFIG_INDEX_TRACKS_ENABLE,
                            .width = 8, .dflt = 0 },
    [SET_TRKDAYS]       = { .key = "trkdays", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_TRACKS_DAYS,
                            .width = 32, .lo = 1, .hi = 7, .dflt = 2 },
    [SET_STATSDAYS]     = { .key = "statsdays", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_STATS_RETAIN_DAYS,
                            .width = 32, .lo = 1, .hi = 30, .dflt = 30 },
    [SET_EVENTDAYS]     = { .key = "eventdays", .kind = SET_KIND_UINT, .idx = CONFIG_INDEX_EVENT_RETAIN_DAYS,
                            .width = 32, .lo = 1, .hi = 30, .dflt = 30 },
#endif
};

/* The options of the channel select on /settings. */
static const uint32_t CHANNELS[] = { 0, 5900, 5890, 5880, 5870, 5860 };

set_id_t set_find(const char *key)
{
    for (int i = 0; i < SET_COUNT; i++)
        if (strcmp(SET_DEFS[i].key, key) == 0)
            return (set_id_t)i;
    return SET_COUNT;
}

/* Loose IPv4 dotted-quad check (4 octets, each 0-255). Empty string is NOT
 * valid here; callers treat empty separately (clear/DHCP). */
bool set_is_ipv4(const char *s)
{
    int parts = 0, val = 0, digits = 0;
    for (const char *p = s; ; p++)
    {
        if (*p >= '0' && *p <= '9') { val = val * 10 + (*p - '0'); if (++digits > 3 || val > 255) return false; }
        else if (*p == '.' || *p == '\0') { if (digits == 0) return false; parts++; if (*p == '\0') break; val = 0; digits = 0; }
        else return false;
    }
    return parts == 4;
}

/* Well-formed UTF-8? A string setting reaches the web-app manifest, the JSON
 * endpoints and the mDNS instance name, and all of them must be UTF-8. A stray
 * byte makes the whole document unparseable for the client. A browser form can
 * only send valid UTF-8, but a hand-made POST can send anything. */
bool set_is_utf8(const char *s)
{
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
    {
        if (*p < 0x80)
            continue;
        /* Length from the lead byte, then the continuation bytes must follow.
         * The lower bounds reject overlong forms and surrogates the same way
         * the standard does. */
        int need;
        unsigned cp;
        if ((*p & 0xE0) == 0xC0) { need = 1; cp = *p & 0x1Fu; }
        else if ((*p & 0xF0) == 0xE0) { need = 2; cp = *p & 0x0Fu; }
        else if ((*p & 0xF8) == 0xF0) { need = 3; cp = *p & 0x07u; }
        else return false;
        for (int i = 0; i < need; i++)
        {
            /* Also catches the end of the string: the NUL is no continuation. */
            if ((p[1] & 0xC0) != 0x80)
                return false;
            cp = (cp << 6) | (unsigned)(*++p & 0x3F);
        }
        if (cp < (need == 1 ? 0x80u : need == 2 ? 0x800u : 0x10000u) ||
            cp > 0x10FFFFu || (cp >= 0xD800u && cp <= 0xDFFFu))
            return false;
    }
    return true;
}

/* Decimal digits only. A leading minus is a number below every lower bound. */
static set_err_t parse_uint(const char *s, uint32_t *out)
{
    bool neg = (*s == '-');
    if (neg)
        s++;
    if (*s == '\0')
        return SET_ERR_NUMBER;
    uint64_t v = 0;
    for (; *s; s++)
    {
        if (*s < '0' || *s > '9')
            return SET_ERR_NUMBER;
        if (v <= UINT32_MAX)
            v = v * 10 + (uint64_t)(*s - '0');
    }
    if (neg || v > UINT32_MAX)
        return SET_ERR_RANGE;
    *out = (uint32_t)v;
    return SET_OK;
}

uint32_t set_read_num(set_id_t id)
{
    const set_def_t *d = &SET_DEFS[id];
    if (d->width == 8)
    {
        uint8_t v;
        return config_get_u8(d->idx, &v) == ESP_OK ? v : d->dflt;
    }
    uint32_t v;
    return config_get_u32(d->idx, &v) == ESP_OK ? v : d->dflt;
}

void set_read(set_id_t id, char *out, size_t cap)
{
    const set_def_t *d = &SET_DEFS[id];
    switch (d->kind)
    {
    case SET_KIND_STR:
    case SET_KIND_IPV4:
    case SET_KIND_ADDR:
    {
        size_t sz = cap;
        if (config_get_str(d->idx, out, &sz) != ESP_OK)
            out[0] = '\0';
        return;
    }
    case SET_KIND_DHCP:
    {
        /* No static IP stored means DHCP. */
        char ip[CONFIG_IPV4_BUFFER_SIZE];
        set_read(SET_ETHIP, ip, sizeof(ip));
        snprintf(out, cap, "%s", ip[0] ? "0" : "1");
        return;
    }
    case SET_KIND_BOOL:
        snprintf(out, cap, "%s", set_read_num(id) ? "1" : "0");
        return;
    default:
        snprintf(out, cap, "%lu", (unsigned long)set_read_num(id));
        return;
    }
}

static set_err_t store_str(const set_def_t *d, const char *val, bool *changed)
{
    char cur[CONFIG_MQTT_URI_BUFFER_SIZE];
    size_t sz = sizeof(cur);
    if (changed)
        *changed = config_get_str(d->idx, cur, &sz) != ESP_OK || strcmp(cur, val) != 0;
    return config_set_str(d->idx, val) == ESP_OK ? SET_OK : SET_ERR_STORE;
}

/* A masked URI passes only if it masks the stored URI unchanged. This keeps the mask out of
 * NVS and the stored password away from a new host (form and import). noinline keeps the
 * 560-byte frame of this check out of set_apply(). */
static __attribute__((noinline)) set_err_t check_masked_uri(const set_def_t *d, const char *val)
{
    char cur[CONFIG_MQTT_URI_BUFFER_SIZE];
    char curm[CONFIG_MQTT_URI_BUFFER_SIZE + 16];   /* the mask adds up to 11 bytes */
    size_t sz = sizeof cur;
    if (config_get_str(d->idx, cur, &sz) != ESP_OK || !mqtt_uri_mask(cur, curm, sizeof curm) ||
        strcmp(val, curm) != 0)
        return SET_ERR_MASK;
    return SET_OK;
}

set_err_t set_apply(set_id_t id, const char *val, bool *changed)
{
    if (changed)
        *changed = false;
    if ((int)id < 0 || id >= SET_COUNT)
        return SET_ERR_TYPE;
    const set_def_t *d = &SET_DEFS[id];
    uint32_t num = 0;
    set_err_t e;

    switch (d->kind)
    {
    case SET_KIND_BOOL:
        if (strcmp(val, "1") == 0)
            num = 1;
        else if (strcmp(val, "0") != 0)
            return SET_ERR_TYPE;
        break;
    case SET_KIND_UINT:
        if ((e = parse_uint(val, &num)) != SET_OK)
            return e;
        if (num < d->lo || num > d->hi)
            return SET_ERR_RANGE;
        break;
    case SET_KIND_CHAN:
    {
        if ((e = parse_uint(val, &num)) != SET_OK)
            return e;
        bool offered = false;
        for (size_t i = 0; i < sizeof(CHANNELS) / sizeof(CHANNELS[0]); i++)
            offered |= (CHANNELS[i] == num);
        if (!offered)
            return SET_ERR_CHOICE;
        break;
    }
    case SET_KIND_COLOR:
        if ((e = parse_uint(val, &num)) != SET_OK)
            return e;
        if (num > 0xFFFFFFUL)
            return SET_ERR_RANGE;
        break;
    case SET_KIND_STR:
    {
        /* The unchanged masked URI counts as saved and changes nothing (*changed stays false). */
        if (id == SET_MQTTURI && mqtt_uri_has_mask(val))
            return check_masked_uri(d, val);
        size_t n = strlen(val);
        if (n >= d->cap)
            return SET_ERR_LONG;
        if (n == 0 && !d->empty_ok)
            return SET_ERR_EMPTY;
        for (const unsigned char *p = (const unsigned char *)val; *p; p++)
            if (*p < 0x20 || *p == 0x7F)
                return SET_ERR_CHARS;
        if (!set_is_utf8(val))
            return SET_ERR_CHARS;
        return store_str(d, val, changed);
    }
    case SET_KIND_IPV4:
        /* Empty clears the server. */
        if (val[0] && !set_is_ipv4(val))
            return SET_ERR_IPV4;
        return store_str(d, val, changed);
    default:
        return SET_ERR_TYPE;
    }

    if (changed)
    {
        uint32_t cur = set_read_num(id);
        *changed = (d->kind == SET_KIND_BOOL) ? ((cur != 0) != (num != 0)) : (cur != num);
    }
    esp_err_t r = (d->width == 8) ? config_set_u8(d->idx, (uint8_t)num)
                                  : config_set_u32(d->idx, num);
    if (r != ESP_OK)
        return SET_ERR_STORE;
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
    /* Unlike the other network settings this one needs no restart. */
    if (id == SET_ETHLEDS)
        ethernet_apply_led_setting();
#endif
    return SET_OK;
}

set_err_t set_apply_address(const char *dhcp, const char *ip, const char *nm,
                            const char *gw, bool *changed)
{
    if (changed)
        *changed = false;
    char cur[3][CONFIG_IPV4_BUFFER_SIZE];
    set_read(SET_ETHIP, cur[0], sizeof(cur[0]));
    set_read(SET_ETHNM, cur[1], sizeof(cur[1]));
    set_read(SET_ETHGW, cur[2], sizeof(cur[2]));

    const char *want[3];
    if (strcmp(dhcp, "1") == 0)
    {
        /* DHCP: clearing the static trio makes the boot code run a DHCP client. */
        want[0] = want[1] = want[2] = "";
    }
    else if (strcmp(dhcp, "0") == 0)
    {
        /* The boot code falls back to DHCP unless all three are valid, so none is stored alone. */
        if (!set_is_ipv4(ip) || !set_is_ipv4(nm) || !set_is_ipv4(gw))
            return SET_ERR_STATIC_IP;
        want[0] = ip;
        want[1] = nm;
        want[2] = gw;
    }
    else
        return SET_ERR_TYPE;

    static const config_index_t idx[3] = {
        CONFIG_INDEX_ETH_IP, CONFIG_INDEX_ETH_NETMASK, CONFIG_INDEX_ETH_GATEWAY
    };
    set_err_t res = SET_OK;
    for (int i = 0; i < 3; i++)
    {
        if (changed && strcmp(cur[i], want[i]) != 0)
            *changed = true;
        if (config_set_str(idx[i], want[i]) != ESP_OK)
            res = SET_ERR_STORE;
    }
    return res;
}
