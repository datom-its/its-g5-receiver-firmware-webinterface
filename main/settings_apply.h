#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "sdkconfig.h"

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The one place that checks and stores a setting. The /settings form and the
 * settings import both go through it, so the two can never accept different values. */

typedef enum {
    SET_KIND_BOOL,   /* form "1" or "0" */
    SET_KIND_UINT,   /* form decimal digits within lo..hi */
    SET_KIND_CHAN,   /* form decimal, one of the channels the form offers */
    SET_KIND_COLOR,  /* form decimal 24-bit RGB, shown as #rrggbb */
    SET_KIND_STR,    /* text without control characters */
    SET_KIND_IPV4,   /* dotted quad, or empty to clear */
    SET_KIND_DHCP,   /* "1" or "0", stored as an empty or filled static address */
    SET_KIND_ADDR,   /* static IP, netmask or gateway, only with SET_KIND_DHCP */
} set_kind_t;

typedef enum {
    SET_NODEID,
    SET_CHAN,
    SET_BROADCASTONLY,
    SET_LED,
    SET_LEDOVERRIDE,
    SET_REFRESHSEC,
    SET_MAPSTALE,
    SET_PEERS,
    SET_BTEN,
    SET_DHCP,
    SET_ETHIP,
    SET_ETHNM,
    SET_ETHGW,
    SET_ETHDNS0,
    SET_ETHDNS1,
    SET_ETHDNS2,
    SET_NTPSERVER,
    SET_TZ,
#if CONFIG_ETHERNET_SPI_DEV0_KSZ8851SNL
    SET_ETHLEDS,
#endif
    SET_MQTTURI,
#if CONFIG_ENABLE_SD
    SET_LOGSYS,
    SET_LOGMAXMB,
    SET_PCAPEN,
    SET_PCAPHOURS,
    SET_PCAPMAXMB,
    SET_PCAPBUFMB,
    SET_PCAPFLUSHSEC,
    SET_PCAPFILT,
    SET_TRKON,
    SET_TRKDAYS,
    SET_STATSDAYS,
    SET_EVENTDAYS,
#endif
    SET_COUNT
} set_id_t;

typedef struct {
    const char *key;       /* form field id and JSON key */
    set_kind_t kind;
    config_index_t idx;    /* unused for SET_KIND_DHCP */
    uint8_t width;         /* 8 or 32 bit store for BOOL, UINT, CHAN and COLOR */
    uint16_t cap;          /* SET_KIND_STR: config buffer size, NUL included */
    uint32_t lo, hi;       /* SET_KIND_UINT bounds */
    uint32_t dflt;         /* what the form shows when reading the value fails */
    bool empty_ok;         /* SET_KIND_STR only */
    bool reboot;           /* takes effect only after a restart */
    bool device;           /* identifies one device: node ID and static address */
    bool net;              /* the form sends it only inside the network block */
} set_def_t;

extern const set_def_t SET_DEFS[SET_COUNT];

typedef enum {
    SET_OK = 0,
    SET_ERR_TYPE,       /* not "1" or "0" for a checkbox, or a JSON value of the wrong type */
    SET_ERR_NUMBER,     /* not a whole decimal number */
    SET_ERR_RANGE,
    SET_ERR_EMPTY,
    SET_ERR_LONG,
    SET_ERR_CHARS,      /* control character, embedded NUL or broken UTF-8 */
    SET_ERR_CHOICE,
    SET_ERR_IPV4,
    SET_ERR_COLOR,
    SET_ERR_STATIC_IP,  /* static address needs IP, netmask and gateway, all valid */
    SET_ERR_STORE,
    SET_ERR_MASK,       /* the password mask came back with a changed URI */
} set_err_t;

/* Finds a setting by its key, or returns SET_COUNT. */
set_id_t set_find(const char *key);

/* Checks `val` exactly as the form sends it and stores it. `changed` (may be
 * NULL) tells whether the stored value differed. Not for SET_KIND_DHCP and SET_KIND_ADDR. */
set_err_t set_apply(set_id_t id, const char *val, bool *changed);

/* The static address block. dhcp "1" clears the static trio, "0" stores ip, nm
 * and gw, which must all be valid. Nothing is stored when one of them is not. */
set_err_t set_apply_address(const char *dhcp, const char *ip, const char *nm,
                            const char *gw, bool *changed);

/* The current value as the form shows it: "1"/"0", decimal, or text. */
void set_read(set_id_t id, char *out, size_t cap);

/* The current number of a BOOL, UINT, CHAN or COLOR setting, or its default. */
uint32_t set_read_num(set_id_t id);

bool set_is_ipv4(const char *s);
bool set_is_utf8(const char *s);

#ifdef __cplusplus
}
#endif
