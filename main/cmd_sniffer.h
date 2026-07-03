/* cmd_sniffer example — declarations of command registration functions.

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "esp_eth_driver.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void *payload;
    uint32_t length;
    uint32_t seconds;
    uint32_t microseconds;
    int rssi;
} sniffer_packet_info_t;

/**
 * @brief Supported Sniffer Interface
 *
 */
typedef enum {
    SNIFFER_INTF_UNKNOWN = 0,
    SNIFFER_INTF_WLAN, /*!< WLAN interface */
    SNIFFER_INTF_ETH, /*!< Ethernet interface */
} sniffer_intf_t;

/**
 * @brief WLAN Sniffer Filter
 *
 */
typedef enum {
    SNIFFER_WLAN_FILTER_MGMT = 0, /*!< MGMT */
    SNIFFER_WLAN_FILTER_CTRL,     /*!< CTRL */
    SNIFFER_WLAN_FILTER_DATA,     /*!< DATA */
    SNIFFER_WLAN_FILTER_MISC,     /*!< MISC */
    SNIFFER_WLAN_FILTER_MPDU,     /*!< MPDU */
    SNIFFER_WLAN_FILTER_AMPDU,    /*!< AMPDU */
    SNIFFER_WLAN_FILTER_FCSFAIL,  /*!< When this bit is set, the hardware will receive packets for which frame check sequence failed */
    SNIFFER_WLAN_FILTER_MAX
} sniffer_wlan_filter_t;

void sniffer_init(void);
void register_sniffer_cmd(void);
esp_err_t sniffer_reg_eth_intf(esp_eth_handle_t eth_handle);

void sniffer_autostart(void);

/* Current sniffer channel frequency in MHz (e.g. 5900 for G5CC), or 0 if the
 * sniffer is not running on a WLAN channel. */
uint32_t sniffer_get_channel(void);

/* True while the sniffer task is capturing. */
bool sniffer_is_running(void);


#ifdef __cplusplus
}
#endif
