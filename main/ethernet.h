#pragma once

#include <stdint.h>

#include <stdbool.h>

#include "esp_err.h"
#include "hal/eth_types.h"

#ifdef __cplusplus
extern "C" {
#endif

void initialize_ethernet(void);

eth_speed_t ethernet_get_mgmt_if_link_speed(void);
void ethernet_get_mac(uint8_t mac[6]);

/* Current live network status of the management interface, as dotted-quad
 * strings (empty if not (yet) known). `up` is true once an IP is bound
 * (static: right after start; DHCP: once a lease was obtained). Reflects
 * what's actually in effect, not just what's configured in NVS. */
typedef struct {
    bool up;
    char ip[16];
    char netmask[16];
    char gateway[16];
    char dns[3][16];
} ethernet_status_t;

void ethernet_get_status(ethernet_status_t *out);

/* Fault counters of the Ethernet chip since the start, for /system and /system.json. Only the
 * KSZ8851SNL has them; with another chip, or before the driver runs, the call returns false. */
typedef struct {
    uint64_t tx_pause;          /* PAUSE frames sent: the receive buffer ran nearly full, and free again */
    uint64_t rx_crc_errors;
    uint64_t rx_symbol_errors;
    uint64_t rx_long;           /* frames of 1522 to 2000 bytes */
    uint32_t rx_overruns;       /* the receive buffer overflowed and frames were lost */
    uint32_t spi_bus_errors;
    uint32_t bad_lengths;       /* times a byte count was outside 64..2000 or not the frame header's */
} ethernet_stats_t;

bool ethernet_get_stats(ethernet_stats_t *out);

/* Pushes CONFIG_INDEX_ETH_LEDS to the port's link/activity LEDs. Runs at
 * startup and on link-up. Call again after changing the setting. */
esp_err_t ethernet_apply_led_setting(void);

#ifdef __cplusplus
}
#endif
