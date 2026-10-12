/*
 * SPDX-FileCopyrightText: 2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: MIT
 *
 */

#pragma once

#include "esp_eth_com.h"
#include "esp_eth_mac_spi.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief KSZ8851SNL specific configuration
 *
 */
typedef struct {
    int int_gpio_num;                                   /*!< Interrupt GPIO number, set -1 to not use interrupt and to poll rx status periodically */
    uint32_t poll_period_ms;                            /*!< Period in ms to poll rx status when interrupt mode is not used */
    spi_host_device_t spi_host_id;                      /*!< SPI peripheral (this field is invalid when custom SPI driver is defined) */
    spi_device_interface_config_t *spi_devcfg;          /*!< SPI device configuration (this field is invalid when custom SPI driver is defined) */
    eth_spi_custom_driver_config_t custom_spi_driver;   /*!< Custom SPI driver definitions */
} eth_ksz8851snl_config_t;

/**
 * @brief Default KSZ8851SNL specific configuration
 *
 */
#define ETH_KSZ8851SNL_DEFAULT_CONFIG(spi_host, spi_devcfg_p) \
    {                                           \
        .int_gpio_num = 4,                      \
        .poll_period_ms = 0,                    \
        .spi_host_id = spi_host,                \
        .spi_devcfg = spi_devcfg_p,             \
        .custom_spi_driver = ETH_DEFAULT_SPI,   \
    }

/**
 * @brief Counters for esp_eth_ioctl(ETH_KSZ8851SNL_CMD_G_STATS), all since the driver was initialised
 *
 * Changed for its-g5-receiver-firmware: added. The first four are MIB counters (DS00002381C, table 4-77), added up
 * because each read clears them; init clears them once, as an ESP restart does not reset the chip.
 */
typedef struct {
    uint64_t tx_pause;          /*!< MIB TxPausePkts: PAUSE frames sent, XOFF when the RXQ ran nearly full and XON after */
    uint64_t rx_crc_errors;     /*!< MIB RxCRCError */
    uint64_t rx_symbol_errors;  /*!< MIB RxSymbolError */
    uint64_t rx_long;           /*!< MIB Rx1522to2000Octets: frames of 1522 to 2000 bytes */
    uint32_t rx_overruns;       /*!< RXOIS interrupts: the RXQ overflowed and frames were lost */
    uint32_t spi_bus_errors;    /*!< SPIBEIS interrupts */
    uint32_t bad_lengths;       /*!< times a byte count was outside 64..2000 or not the one in the frame header */
} eth_ksz8851snl_stats_t;

/** Changed for its-g5-receiver-firmware: fills an eth_ksz8851snl_stats_t; the MIB part needs a started driver. */
#define ETH_KSZ8851SNL_CMD_G_STATS ETH_CMD_CUSTOM_MAC_CMDS_OFFSET

/**
* @brief Create KSZ8851SNL Ethernet MAC instance
*
* @param ksz8851snl_config: KSZ8851SNL specific configuration
* @param mac_config: Ethernet MAC configuration
*
* @return
*      - instance: create MAC instance successfully
*      - NULL: create MAC instance failed because some error occurred
*/
esp_eth_mac_t *esp_eth_mac_new_ksz8851snl(const eth_ksz8851snl_config_t *ksz8851snl_config, const eth_mac_config_t *mac_config);

#ifdef __cplusplus
}
#endif
