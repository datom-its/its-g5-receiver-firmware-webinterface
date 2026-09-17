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

/* Pushes CONFIG_INDEX_ETH_LEDS to the port's link/activity LEDs. Runs at
 * startup and on link-up. Call again after changing the setting. */
esp_err_t ethernet_apply_led_setting(void);

#ifdef __cplusplus
}
#endif
