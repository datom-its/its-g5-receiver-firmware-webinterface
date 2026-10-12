/*
 * SPDX-FileCopyrightText: 2021 Vladimir Chistyakov
 *
 * SPDX-License-Identifier: MIT
 *
 * SPDX-FileContributor: 2025-2026 Espressif Systems (Shanghai) CO LTD
 */

#include <string.h>
#include <inttypes.h>
#include "esp_eth_mac_spi.h"
#include "esp_eth_mac_ksz8851snl.h"
#include "esp_log.h"
#include "esp_check.h"
#include "esp_cpu.h"
#include "driver/gpio.h"
#include "esp_private/gpio.h"
#include "soc/io_mux_reg.h"
#include "driver/spi_master.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "ksz8851.h"
#include "esp_timer.h"
#include "esp_rom_crc.h"

#define KSZ8851_ETH_MAC_RX_BUF_SIZE_AUTO (0)
#define KSZ8851_HASH_FILTER_TABLE_SIZE (64)

typedef struct {
    spi_device_handle_t hdl;
} eth_spi_info_t;

typedef struct {
    void *ctx;
    void *(*init)(const void *spi_config);
    esp_err_t (*deinit)(void *spi_ctx);
    esp_err_t (*read)(void *spi_ctx, uint32_t cmd, uint32_t addr, void *data, uint32_t data_len);
    esp_err_t (*write)(void *spi_ctx, uint32_t cmd, uint32_t addr, const void *data, uint32_t data_len);
} eth_spi_custom_driver_t;

typedef struct {
    esp_eth_mac_t parent;
    esp_eth_mediator_t *eth;
    eth_spi_custom_driver_t spi;
    SemaphoreHandle_t spi_lock;
    TaskHandle_t rx_task_hdl;
    uint32_t sw_reset_timeout_ms;
    int int_gpio_num;
    esp_timer_handle_t poll_timer;
    uint32_t poll_period_ms;
    uint8_t *rx_buffer;
    uint8_t *tx_buffer;
    uint8_t hash_filter_cnt[KSZ8851_HASH_FILTER_TABLE_SIZE];
    // Changed for its-g5-receiver-firmware: true from a finished init to deinit, the time in which the
    // RX task may set IER and RXQCR back and write RXCR1 and TXCR from their copies (ksz8851_irq_reassert).
    // Before init the copies are not filled yet.
    volatile bool irq_ready;
    // Changed for its-g5-receiver-firmware: SPI bus errors the chip reported since the driver was created,
    // and when the last log line about them was written.
    uint32_t spi_bus_errors;
    TickType_t spi_bus_error_logged;
    // Changed for its-g5-receiver-firmware: the counters behind ETH_KSZ8851SNL_CMD_G_STATS. The MIB totals add up
    // what each read clears in the chip; rx_overruns and bad_lengths the driver counts itself.
    uint64_t mib_total[4];
    uint32_t rx_overruns;
    uint32_t bad_lengths;
    // Changed for its-g5-receiver-firmware: the values RXCR1 and TXCR should hold. Unlike IER and RXQCR they
    // change at run time (promiscuous, all multicast, flow control, start and stop), so the driver keeps them
    // here and writes them whole, as it does with the fixed values below.
    uint16_t rxcr1;
    uint16_t txcr;
    TickType_t bad_header_logged;   // Changed for its-g5-receiver-firmware: 0 = not logged yet, see emac_ksz8851_receive
} emac_ksz8851snl_t;

// Changed for its-g5-receiver-firmware: what init_set_defaults() writes to IER, RXQCR and RXFDPR, as
// fixed values. Outside a transfer the chip holds exactly these, so the driver writes them whole and
// never writes back a value read over the shared bus, where a misread bit would stay for good.
#define KSZ8851_IER_NORMAL    (IER_TXIE | IER_RXIE | IER_LDIE | IER_SPIBEIE | IER_RXOIE)
#define KSZ8851_RXQCR_NORMAL  (RXQCR_RXFCTE | RXQCR_ADRFE)
#define KSZ8851_RXFDPR_NORMAL RXFDPR_RXFPAI
// Changed for its-g5-receiver-firmware: PMECR in normal operation, bits [1:0] = 00, with auto wake-up and
// wake-up to normal operation (bits 7 and 6). Written whole for the same reason: a misread value written back
// could select energy detect mode, in which the MAC is off (datasheet DS00002381C, section 3.1). Bits 7 and 6
// bring the chip back to normal operation on its own once the cable carries a signal (section 3.1.2).
// The PHY driver's init writes power saving mode (11) right after mac init; the MAC stays on in that mode
// (section 3.1.3), and the driver writes this value again when the chip reports a link-up wake-up (LDIS).
#define KSZ8851_PMECR_NORMAL  (PMECR_AUTO_WAKEUP_ENABLE | PMECR_WAKEUP_TO_NORMAL)

typedef struct {
    uint32_t copy_len;
    uint32_t byte_cnt;
} __attribute__((packed)) ksz8851_auto_buf_info_t;

typedef enum {
    KSZ8851_SPI_COMMAND_READ_REG   = 0x0U,
    KSZ8851_SPI_COMMAND_WRITE_REG  = 0x1U,
    KSZ8851_SPI_COMMAND_READ_FIFO  = 0x2U,
    KSZ8851_SPI_COMMAND_WRITE_FIFO = 0x3U,
} ksz8851_spi_commands_t;

typedef enum {
    KSZ8851_QMU_PACKET_LENGTH  = 2000U,
    KSZ8851_QMU_PACKET_PADDING = 16U,
} ksz8851_qmu_packet_size_t;

static const char *TAG = "ksz8851snl-mac";

static const unsigned KSZ8851_SPI_COMMAND_BITS    = 2U;
static const unsigned KSZ8851_SPI_ADDR_SHIFT      = 2U;
static const unsigned KSZ8851_SPI_BYTE_MASK_SHIFT = 8U + KSZ8851_SPI_ADDR_SHIFT;
static const unsigned KSZ8851_SPI_LOCK_TIMEOUT_MS = 500U;

static const uint16_t RXDTTR_INIT_VALUE  = 0x03E8U;
static const uint16_t RXDBCTR_INIT_VALUE = 0x1000U;
static const uint16_t RXFCT_INIT_VALUE   = 0X0001U;

IRAM_ATTR static void ksz8851_isr_handler(void *arg)
{
    emac_ksz8851snl_t *emac     = (emac_ksz8851snl_t *)arg;
    BaseType_t high_task_wakeup = pdFALSE;
    vTaskNotifyGiveFromISR(emac->rx_task_hdl, &high_task_wakeup);
    if (high_task_wakeup != pdFALSE) {
        portYIELD_FROM_ISR();
    }
}

static void ksz8851_poll_timer(void *arg)
{
    emac_ksz8851snl_t *emac = (emac_ksz8851snl_t *)arg;
    xTaskNotifyGive(emac->rx_task_hdl);
}

static void *ksz8851_spi_init(const void *spi_config)
{
    void *ret = NULL;
    eth_ksz8851snl_config_t *ksz8851snl_config = (eth_ksz8851snl_config_t *)spi_config;
    eth_spi_info_t *spi = calloc(1, sizeof(eth_spi_info_t));
    ESP_GOTO_ON_FALSE(spi, NULL, err, TAG, "no memory for SPI context data");

    // SPI device init
    ESP_GOTO_ON_FALSE(spi_bus_add_device(ksz8851snl_config->spi_host_id, ksz8851snl_config->spi_devcfg, &spi->hdl) == ESP_OK, NULL,
                      err, TAG, "adding device to SPI host #%i failed", ksz8851snl_config->spi_host_id + 1);
    ret = spi;
    return ret;
err:
    if (spi) {
        free(spi);
    }
    return ret;
}

static esp_err_t ksz8851_spi_deinit(void *spi_ctx)
{
    esp_err_t ret = ESP_OK;
    eth_spi_info_t *spi = (eth_spi_info_t *)spi_ctx;

    // Changed for its-g5-receiver-firmware: the result is logged. A refused removal keeps the
    // device slot on the bus, and after a few retries of a failed start no slot would be left.
    ret = spi_bus_remove_device(spi->hdl);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "spi_bus_remove_device failed: %s", esp_err_to_name(ret));
    }

    free(spi);
    return ret;
}

static esp_err_t ksz8851_spi_read(void *spi_ctx, uint32_t cmd, uint32_t addr, void *value, uint32_t len)
{
    eth_spi_info_t *spi = (eth_spi_info_t *)spi_ctx;

    spi_transaction_ext_t trans = {
        .base.flags = SPI_TRANS_VARIABLE_CMD | SPI_TRANS_VARIABLE_ADDR | SPI_TRANS_VARIABLE_DUMMY | (len <= 4 ? SPI_TRANS_USE_RXDATA : 0),
             .base.cmd = cmd,
             .base.addr = addr,
             .base.length = 8 * len,
             .base.rx_buffer = value,
             .command_bits = KSZ8851_SPI_COMMAND_BITS
    };
    if (cmd >= KSZ8851_SPI_COMMAND_READ_FIFO) {
        trans.address_bits = 8 - KSZ8851_SPI_COMMAND_BITS;
    } else {
        trans.address_bits = 16 - KSZ8851_SPI_COMMAND_BITS;
    }

    // No need for mutex here since SPI access is protected at higher layer of this driver
    // Changed for its-g5-receiver-firmware: interrupt-driven instead of polling. The SD card shares
    // this bus. On one device the SD driver stopped at the assert "Cannot release bus when a polling
    // transaction is in progress": the bus lock had let both drivers in at once, most likely the
    // race reported as ESP-IDF #18527, and the polling flag came from a transfer started here.
    ESP_RETURN_ON_ERROR(spi_device_transmit(spi->hdl, &trans.base), TAG, "spi transmit failed");

    if ((trans.base.flags & SPI_TRANS_USE_RXDATA) && len <= 4) {
        memcpy(value, trans.base.rx_data, len);  // copy register values to output
    }
    return ESP_OK;
}

static esp_err_t ksz8851_spi_write(void *spi_ctx, uint32_t cmd, uint32_t addr, const void *value, uint32_t len)
{
    eth_spi_info_t *spi = (eth_spi_info_t *)spi_ctx;

    spi_transaction_ext_t trans = {
        .base.flags = SPI_TRANS_VARIABLE_CMD | SPI_TRANS_VARIABLE_ADDR | SPI_TRANS_VARIABLE_DUMMY,
        .base.cmd = cmd,
        .base.addr = addr,
        .base.length = 8 * len,
        .base.tx_buffer = value,
        .command_bits = KSZ8851_SPI_COMMAND_BITS
    };
    if (cmd >= KSZ8851_SPI_COMMAND_READ_FIFO) {
        trans.address_bits = 8 - KSZ8851_SPI_COMMAND_BITS;
    } else {
        trans.address_bits = 16 - KSZ8851_SPI_COMMAND_BITS;
    }

    // No need for mutex here since SPI access is protected at higher layer of this driver
    // Changed for its-g5-receiver-firmware: interrupt-driven, see ksz8851_spi_read().
    ESP_RETURN_ON_ERROR(spi_device_transmit(spi->hdl, &trans.base), TAG, "spi transmit failed");

    return ESP_OK;
}

static inline bool ksz8851_mutex_lock(emac_ksz8851snl_t *emac)
{
    return xSemaphoreTakeRecursive(emac->spi_lock, pdMS_TO_TICKS(KSZ8851_SPI_LOCK_TIMEOUT_MS)) == pdTRUE;
}

static inline bool ksz8851_mutex_unlock(emac_ksz8851snl_t *emac)
{
    return xSemaphoreGiveRecursive(emac->spi_lock) == pdTRUE;
}

static esp_err_t ksz8851_read_reg(emac_ksz8851snl_t *emac, uint32_t reg_addr, uint16_t *value)
{
    esp_err_t ret = ESP_OK;
    ESP_GOTO_ON_FALSE(value != NULL, ESP_ERR_INVALID_ARG, err, TAG, "out pointer must not be null");
    ESP_GOTO_ON_FALSE((reg_addr & ~KSZ8851_VALID_ADDRESS_MASK) == 0U, ESP_ERR_INVALID_ARG, err, TAG, "address is out of bounds");

    // NOTE(v.chistyakov): select upper or lower word inside a dword
    const unsigned byte_mask = 0x3U << (KSZ8851_SPI_BYTE_MASK_SHIFT + (reg_addr & 0x2U));
    reg_addr <<= KSZ8851_SPI_ADDR_SHIFT;

    // Need to protect SPI access at higher layer of the driver since once packet transmit/receive is started (`SDA Start DMA Access` bit is set),
    // all registers access are disabled.
    if (ksz8851_mutex_lock(emac)) {
        ret = emac->spi.read(emac->spi.ctx, KSZ8851_SPI_COMMAND_READ_REG, reg_addr | byte_mask, value, 2);
    } else {
        ret = ESP_ERR_TIMEOUT;
    }
    ksz8851_mutex_unlock(emac);
    ESP_LOGV(TAG, "reading reg 0x%02" PRIx32 " = 0x%02" PRIx16, reg_addr, *value);

err:
    return ret;
}

static esp_err_t ksz8851_write_reg(emac_ksz8851snl_t *emac, uint32_t reg_addr, uint16_t value)
{
    esp_err_t ret = ESP_OK;
    ESP_GOTO_ON_FALSE((reg_addr & ~KSZ8851_VALID_ADDRESS_MASK) == 0U, ESP_ERR_INVALID_ARG, err, TAG, "address is out of bounds");
    ESP_LOGV(TAG, "writing reg 0x%02" PRIx32 " = 0x%02" PRIx16, reg_addr, value);

    // NOTE(v.chistyakov): select upper or lower word inside a dword
    const unsigned byte_mask = 0x3U << (KSZ8851_SPI_BYTE_MASK_SHIFT + (reg_addr & 0x2U));
    reg_addr <<= KSZ8851_SPI_ADDR_SHIFT;

    // Need to protect SPI access at higher layer of the driver since once packet transmit/receive is started (`SDA Start DMA Access` bit is set),
    // all registers access are disabled.
    if (ksz8851_mutex_lock(emac)) {
        ret = emac->spi.write(emac->spi.ctx, KSZ8851_SPI_COMMAND_WRITE_REG, reg_addr | byte_mask, &value, 2);
    } else {
        ret = ESP_ERR_TIMEOUT;
    }
    ksz8851_mutex_unlock(emac);

err:
    return ret;
}

static esp_err_t ksz8851_set_bits(emac_ksz8851snl_t *emac, uint32_t address, uint16_t value)
{
    esp_err_t ret = ESP_OK;
    uint16_t old;
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, address, &old), err, TAG, "failed to read reg 0x%" PRIx32, address);
    old |= value;
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, address, old), err, TAG, "failed to write reg 0x%" PRIx32, address);
err:
    return ret;
}

static esp_err_t ksz8851_clear_bits(emac_ksz8851snl_t *emac, uint32_t address, uint16_t value)
{
    esp_err_t ret = ESP_OK;
    uint16_t old;
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, address, &old), err, TAG, "failed to read reg 0x%" PRIx32, address);
    old &= ~value;
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, address, old), err, TAG, "failed to write reg 0x%" PRIx32, address);
err:
    return ret;
}

static esp_err_t emac_ksz8851_set_mediator(esp_eth_mac_t *mac, esp_eth_mediator_t *eth)
{
    esp_err_t ret = ESP_OK;
    ESP_GOTO_ON_FALSE(eth, ESP_ERR_INVALID_ARG, err, TAG, "mediator can not be null");
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    emac->eth               = eth;
    return ESP_OK;
err:
    return ret;
}

static esp_err_t init_soft_reset(emac_ksz8851snl_t *emac)
{
    esp_err_t ret           = ESP_OK;
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_PMECR, KSZ8851_PMECR_NORMAL), err, TAG, "PMECR write failed");   // Changed for its-g5-receiver-firmware: written whole

    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_GRR, GRR_GLOBAL_SOFT_RESET), err, TAG, "GRR write failed");
    vTaskDelay(pdMS_TO_TICKS(emac->sw_reset_timeout_ms));

    ESP_GOTO_ON_ERROR(ksz8851_clear_bits(emac, KSZ8851_GRR, GRR_GLOBAL_SOFT_RESET), err, TAG, "GRR write failed");
    vTaskDelay(pdMS_TO_TICKS(emac->sw_reset_timeout_ms));
    return ESP_OK;
err:
    return ret;
}

static esp_err_t init_verify_chipid(emac_ksz8851snl_t *emac)
{
    uint16_t id;
    esp_err_t ret           = ESP_OK;
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, KSZ8851_CIDER, &id), err, TAG, "CIDER read failed");
    uint8_t family_id = (id & CIDER_FAMILY_ID_MASK) >> CIDER_FAMILY_ID_SHIFT;
    uint8_t chip_id   = (id & CIDER_CHIP_ID_MASK) >> CIDER_CHIP_ID_SHIFT;
    uint8_t revision  = (id & CIDER_REVISION_ID_MASK) >> CIDER_REVISION_ID_SHIFT;
    ESP_LOGI(TAG, "Family ID = 0x%" PRIx8 "\t Chip ID = 0x%" PRIx8 "\t Revision ID = 0x%" PRIx8, family_id, chip_id, revision);
    ESP_GOTO_ON_FALSE(family_id == CIDER_KSZ8851SNL_FAMILY_ID, ESP_FAIL, err, TAG, "wrong family id");
    ESP_GOTO_ON_FALSE(chip_id == CIDER_KSZ8851SNL_CHIP_ID, ESP_FAIL, err, TAG, "wrong chip id");
    return ESP_OK;
err:
    return ret;
}

// Changed for its-g5-receiver-firmware: changes bits in the driver's copy of RXCR1 or TXCR and writes the result
// whole, under the lock. Reading the register back over the shared bus and writing that could keep a misread
// bit for good: a cleared RXE stops receiving, a cleared TXCE sends every frame without its CRC. The copy follows
// the intended value even when the write fails, and ksz8851_irq_reassert writes it again about once a second. A
// lock timeout changes neither.
static esp_err_t ksz8851_copy_update(emac_ksz8851snl_t *emac, uint32_t reg, uint16_t *copy, uint16_t clear,
                                     uint16_t set)
{
    if (!ksz8851_mutex_lock(emac)) {
        return ESP_ERR_TIMEOUT;
    }
    *copy = (uint16_t)((*copy & ~clear) | set);
    esp_err_t ret = ksz8851_write_reg(emac, reg, *copy);
    ksz8851_mutex_unlock(emac);
    return ret;
}

static esp_err_t init_set_defaults(emac_ksz8851snl_t *emac)
{
    esp_err_t ret           = ESP_OK;
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_TXFDPR, TXFDPR_TXFPAI), err, TAG, "TXFDPR write failed");
    // Changed for its-g5-receiver-firmware: no checksum generation in the chip. Errata DS80000716D item 2: it
    // stops for good after a sender MAC with 0x06 in its fifth byte meets a checksum ending in 06, until the
    // QMU is reset. lwIP computes all checksums itself (CHECKSUM_GEN_* = 1), so nothing is lost.
    // Changed for its-g5-receiver-firmware: written whole from the copy; the reset value is 0x0000.
    ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_TXCR, &emac->txcr, 0xFFFFU, TXCR_TXFCE | TXCR_TXPE | TXCR_TXCE), err, TAG, "TXCR write failed");
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_RXFDPR, KSZ8851_RXFDPR_NORMAL), err, TAG, "RXFDPR write failed");
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_RXFCTR, RXFCT_INIT_VALUE), err, TAG, "RXFCTR write failed");
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_RXDTTR, RXDTTR_INIT_VALUE), err, TAG, "RXDTTR write failed");
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_RXDBCTR, RXDBCTR_INIT_VALUE), err, TAG, "RXDBCTR write failed");
    // Changed for its-g5-receiver-firmware: written whole. The reset value 0x0800 (RXPAFMA) is part of it.
    ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_RXCR1, &emac->rxcr1, 0xFFFFU,
                                           RXCR1_RXUDPFCC | RXCR1_RXTCPFCC | RXCR1_RXIPFCC | RXCR1_RXPAFMA | RXCR1_RXFCE | RXCR1_RXUE | RXCR1_RXME | RXCR1_RXAE | RXCR1_RXBE), err, TAG, "RXCR1 write failed");
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_RXCR2,
                                       (4 << RXCR2_SRDBL_SHIFT) | RXCR2_IUFFP | RXCR2_RXIUFCEZ | RXCR2_UDPLFE | RXCR2_RXICMPFCC), err, TAG, "RXCR2 write failed");
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL), err, TAG, "RXQCR write failed");
    ESP_GOTO_ON_ERROR(ksz8851_clear_bits(emac, KSZ8851_P1CR, P1CR_FORCE_DUPLEX), err, TAG, "P1CR write failed");
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_P1CR, P1CR_RESTART_AN), err, TAG, "P1CR write failed");
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_ISR, ISR_ALL), err, TAG, "ISR write failed");
    ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_IER, KSZ8851_IER_NORMAL), err, TAG, "IER write failed");
    // Changed for its-g5-receiver-firmware: no auto-enqueue (AETFE). Errata DS80000716D item 1 says sending
    // several frames per transmit operation is not reliable and should stay off. Transmit queues each frame
    // with METFE instead.
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_TXQCR, 0), err, TAG, "TXQCR write failed");
    memset(emac->hash_filter_cnt, 0, sizeof(emac->hash_filter_cnt));
    return ESP_OK;
err:
    return ret;
}

// Changed for its-g5-receiver-firmware: reads one of the four MIB counters behind ETH_KSZ8851SNL_CMD_G_STATS: its
// offset with read enable and MIB select to IACR, then IADHR, then IADLR (DS00002381C, p. 71). Why large values
// are dropped, see emac_ksz8851_custom_ioctl.
static const uint8_t KSZ8851_MIB_OFFSET[4] = { 0x17, 0x07, 0x06, 0x14 };   // TxPausePkts, RxCRCError, RxSymbolError, Rx1522to2000Octets
static esp_err_t ksz8851_mib_read(emac_ksz8851snl_t *emac, unsigned i, uint32_t *value)
{
    uint16_t hi = 0, lo = 0;
    esp_err_t ret = ksz8851_write_reg(emac, KSZ8851_IACR, IACR_READ_ENABLE | IACR_MIB_COUNTER_SELECT | KSZ8851_MIB_OFFSET[i]);
    if (ret == ESP_OK) {
        ret = ksz8851_read_reg(emac, KSZ8851_IADHR, &hi);
    }
    if (ret == ESP_OK) {
        ret = ksz8851_read_reg(emac, KSZ8851_IADLR, &lo);
    }
    *value = (ret == ESP_OK && hi < 0x0100U) ? (((uint32_t)hi << 16) | lo) : 0U;
    return ret;
}

static esp_err_t emac_ksz8851_init(esp_eth_mac_t *mac)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    esp_eth_mediator_t *eth = emac->eth;
    if (emac->int_gpio_num >= 0) {
        gpio_func_sel(emac->int_gpio_num, PIN_FUNC_GPIO);
        gpio_input_enable(emac->int_gpio_num);
        gpio_pullup_en(emac->int_gpio_num);
        gpio_set_intr_type(emac->int_gpio_num, GPIO_INTR_NEGEDGE); // NOTE(v.chistyakov): active low
        gpio_intr_enable(emac->int_gpio_num);
        gpio_isr_handler_add(emac->int_gpio_num, ksz8851_isr_handler, emac);
    }
    ESP_GOTO_ON_ERROR(eth->on_state_changed(eth, ETH_STATE_LLINIT, NULL), err, TAG, "lowlevel init failed");

    // NOTE(v.chistyakov): soft reset
    ESP_GOTO_ON_ERROR(init_soft_reset(emac), err, TAG, "soft reset failed");

    // NOTE(v.chistyakov): verify chip id
    ESP_GOTO_ON_ERROR(init_verify_chipid(emac), err, TAG, "verify chip id failed");

    // NOTE(v.chistyakov): set default values
    ESP_GOTO_ON_ERROR(init_set_defaults(emac), err, TAG, "set defaults after init failed");

    ESP_LOGD(TAG, "MAC initialized");
    // Changed for its-g5-receiver-firmware: whether the global soft reset clears the MIB counters, the datasheet
    // does not say, and a restart of the ESP does not reset the chip (its RST pin is not wired to the ESP). One
    // read clears them, so ETH_KSZ8851SNL_CMD_G_STATS counts from here.
    for (unsigned i = 0; i < 4U; i++) {
        uint32_t v;
        ksz8851_mib_read(emac, i, &v);
    }
    emac->irq_ready = true;   // Changed for its-g5-receiver-firmware: see ksz8851_irq_reassert
    return ESP_OK;
err:
    ESP_LOGD(TAG, "MAC initialization failed");
    if (emac->int_gpio_num >= 0) {
        gpio_isr_handler_remove(emac->int_gpio_num);
    }
    eth->on_state_changed(eth, ETH_STATE_DEINIT, NULL);
    return ret;
}

static esp_err_t emac_ksz8851_deinit(esp_eth_mac_t *mac)
{
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    esp_eth_mediator_t *eth = emac->eth;
    emac->irq_ready = false;   // Changed for its-g5-receiver-firmware: see ksz8851_irq_reassert
    mac->stop(mac);
    if (emac->int_gpio_num >= 0) {
        gpio_isr_handler_remove(emac->int_gpio_num);
    }
    if (emac->poll_timer && esp_timer_is_active(emac->poll_timer)) {
        esp_timer_stop(emac->poll_timer);
    }
    eth->on_state_changed(eth, ETH_STATE_DEINIT, NULL);
    ESP_LOGD(TAG, "MAC deinitialized");
    return ESP_OK;
}

static esp_err_t emac_ksz8851_start(esp_eth_mac_t *mac)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_TXCR, &emac->txcr, 0, TXCR_TXE), err, TAG, "TXCR write failed");   // Changed for its-g5-receiver-firmware
    ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_RXCR1, &emac->rxcr1, 0, RXCR1_RXE), err, TAG, "RXCR1 write failed");   // Changed for its-g5-receiver-firmware
    ESP_LOGD(TAG, "MAC started");
err:
    return ret;
}

static esp_err_t emac_ksz8851_stop(esp_eth_mac_t *mac)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_TXCR, &emac->txcr, TXCR_TXE, 0), err, TAG, "TXCR write failed");   // Changed for its-g5-receiver-firmware
    ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_RXCR1, &emac->rxcr1, RXCR1_RXE, 0), err, TAG, "RXCR1 write failed");   // Changed for its-g5-receiver-firmware
    ESP_LOGD(TAG, "MAC stopped");
err:
    return ret;
}

// Changed for its-g5-receiver-firmware: transmit and receive set IER to 0 and SDA for a moment. A
// failed SPI access can leave IER at 0 or SDA set, and then the chip never raises INT again.
// Register access is disabled while SDA is set; only RXQCR, through which the driver clears SDA,
// stays reachable. The RX task calls this once a second. Under the lock no transfer runs, so the
// fixed values are always right. RXCR1 and TXCR follow from their copies, so a write that failed or was
// bent on the bus lasts until the next call, one or two seconds.
static void ksz8851_irq_reassert(emac_ksz8851snl_t *emac)
{
    if (!emac->irq_ready || !ksz8851_mutex_lock(emac)) {
        return;
    }
    ksz8851_write_reg(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL);
    ksz8851_write_reg(emac, KSZ8851_IER, KSZ8851_IER_NORMAL);
    ksz8851_write_reg(emac, KSZ8851_RXCR1, emac->rxcr1);
    ksz8851_write_reg(emac, KSZ8851_TXCR, emac->txcr);
    ksz8851_mutex_unlock(emac);
}

// Changed for its-g5-receiver-firmware: METFE queues one frame and clears itself once it is sent; the datasheet
// (DS00002381C, pp. 24 and 53) asks to wait for that before the next frame. A 1518-byte frame takes 1.2 ms at
// 10 Mbit/s, longer after a collision or a pause frame. So the bound is a time, 20 ms, which also keeps a
// disturbed bus from holding the lock for long.
#define KSZ8851_TX_DONE_WAIT_US 20000
static esp_err_t ksz8851_wait_tx_done(emac_ksz8851snl_t *emac)
{
    const int64_t start_us = esp_timer_get_time();
    do {
        uint16_t txqcr;
        esp_err_t ret = ksz8851_read_reg(emac, KSZ8851_TXQCR, &txqcr);
        if (ret != ESP_OK) {
            return ret;
        }
        if (!(txqcr & TXQCR_METFE)) {
            return ESP_OK;
        }
    } while (esp_timer_get_time() - start_us < KSZ8851_TX_DONE_WAIT_US);
    return ESP_ERR_TIMEOUT;
}

static esp_err_t emac_ksz8851snl_transmit(esp_eth_mac_t *mac, uint8_t *buf, uint32_t length)
{
    static unsigned s_frame_id = 0U;

    ESP_LOGV(TAG, "transmitting frame of size %" PRIu32, length);
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    // Changed for its-g5-receiver-firmware: declared before the first goto, which would skip its
    // initialisation and leave err: to read a random value.
    bool ier_off = false;
    // Lock SPI since once `SDA Start DMA Access` bit is set, all registers access are disabled.
    if (!ksz8851_mutex_lock(emac)) {
        return ESP_ERR_TIMEOUT;
    }

    ESP_GOTO_ON_FALSE(length <= KSZ8851_QMU_PACKET_LENGTH, ESP_ERR_INVALID_ARG, err,
                      TAG, "frame size is too big (actual %" PRIu32 ", maximum %d)", length, ETH_MAX_PACKET_SIZE);
    // NOTE(v.chistyakov): 4 bytes header + length aligned to 4 bytes
    unsigned transmit_length = 4U + ((length + 3U) & ~0x3U);

    ESP_GOTO_ON_ERROR(ksz8851_wait_tx_done(emac), err, TAG, "previous frame not sent yet");   // Changed for its-g5-receiver-firmware
    uint16_t free_space;
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, KSZ8851_TXMIR, &free_space), err, TAG, "TXMIR read failed");
    free_space &= TXMIR_TXMA_MASK;   // Changed for its-g5-receiver-firmware: bits 15-13 are reserved (DS00002381C, TXMIR)
    // Changed for its-g5-receiver-firmware: the 6 KB TXQ (section 3.5) holds at most one frame here, so at least
    // 4 KB are free, yet TXMIR was seen to read exactly 0 a few times a day. That is a disturbed read, or SDA left
    // set, which hides every register but RXQCR (p. 54). The driver writes RXQCR without SDA and reads TXMIR once
    // more; the second value decides, and both go to the log. "0, then 0" points to something lasting.
    if (transmit_length > free_space) {
        uint16_t again;
        ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL), err, TAG, "RXQCR write failed");
        ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, KSZ8851_TXMIR, &again), err, TAG, "TXMIR read failed");
        again &= TXMIR_TXMA_MASK;
        ESP_LOGW(TAG, "TXQ free space read as %" PRIu16 ", then %" PRIu16 " (send length %u)", free_space, again,
                 transmit_length);
        free_space = again;
    }
    ESP_GOTO_ON_FALSE(transmit_length <= free_space, ESP_FAIL, err, TAG, "TXQ free space (%" PRIu16 ") < send length (%" PRIu16 ")", free_space,
                      transmit_length);

    emac->tx_buffer[0] = ++s_frame_id & TXSR_TXFID_MASK;
    emac->tx_buffer[1] = 0x80U;
    emac->tx_buffer[2] = length & 0xFFU;
    emac->tx_buffer[3] = (length >> 8U) & 0xFFU;
    memcpy(emac->tx_buffer + 4U, buf, length);

    // Changed for its-g5-receiver-firmware: IER goes back to KSZ8851_IER_NORMAL, not to a value read
    // here, which the shared bus could have bent.
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_IER, 0), err, TAG, "IER write failed");
    ier_off = true;

    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL | RXQCR_SDA), err, TAG, "RXQCR write failed");
    ret = emac->spi.write(emac->spi.ctx, KSZ8851_SPI_COMMAND_WRITE_FIFO, 0, emac->tx_buffer, transmit_length);
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL), err, TAG, "RXQCR write failed");
    // Changed for its-g5-receiver-firmware: queue this one frame right after SDA is off, as in the datasheet's
    // transmit flow (p. 25, figure 3-9), and only if the FIFO write went through (see ksz8851_wait_tx_done).
    if (ret == ESP_OK) {
        ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_TXQCR, TXQCR_METFE), err, TAG, "TXQCR write failed");
    }

    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_IER, KSZ8851_IER_NORMAL), err, TAG, "IER write failed");
    ier_off = false;
err:
    // Changed for its-g5-receiver-firmware: an error after IER went to 0 must not leave it there. SDA
    // goes first, because register access is disabled while it is set. What still fails here,
    // ksz8851_irq_reassert() repairs within a second.
    if (ier_off) {
        ksz8851_write_reg(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL);
        ksz8851_write_reg(emac, KSZ8851_IER, KSZ8851_IER_NORMAL);
    }
    ksz8851_mutex_unlock(emac);
    return ret;
}

// Changed for its-g5-receiver-firmware: releases the frame at the head of the RXQ with RRXEF. The datasheet
// (DS00002381C, p. 54) documents RRXEF for error frames. It clears itself once the frame memory is free, and the
// driver is to wait for that before it handles the next frame. The wait is bounded, so a disturbed bus cannot
// hold the RX task here. The lock is recursive and held across, so no transmit writes RXQCR in between.
static esp_err_t ksz8851_release_rx_frame(emac_ksz8851snl_t *emac)
{
    if (!ksz8851_mutex_lock(emac)) {
        return ESP_ERR_TIMEOUT;
    }
    esp_err_t ret = ksz8851_write_reg(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL | RXQCR_RRXEF);
    bool cleared = false;
    for (unsigned i = 0; ret == ESP_OK && i < 10U; i++) {
        uint16_t rxqcr;
        if (ksz8851_read_reg(emac, KSZ8851_RXQCR, &rxqcr) != ESP_OK) {
            break;
        }
        if (!(rxqcr & RXQCR_RRXEF)) {
            cleared = true;
            break;
        }
    }
    ksz8851_mutex_unlock(emac);
    if (ret == ESP_OK && !cleared) {
        ESP_LOGW(TAG, "RRXEF not seen cleared after the frame release");
    }
    return ret;
}

// Changed for its-g5-receiver-firmware: a frame is 64 bytes at least (the Ethernet minimum) and 2000 bytes at
// most, CRC included (datasheet pp. 1, 27). Runt and too long frames reach the host only with the "pass bad frame"
// bit (p. 52); this driver sets none, RXEFE (p. 49) stays clear. RXFHBCR has 12 bits, so a disturbed read can
// report any count up to 4095.
static bool ksz8851_byte_count_ok(uint32_t byte_count)
{
    return byte_count >= ETH_MIN_PACKET_SIZE && byte_count <= KSZ8851_QMU_PACKET_LENGTH;
}

static esp_err_t emac_ksz8851_get_recv_byte_count(emac_ksz8851snl_t *emac, uint16_t *size)
{
    esp_err_t ret = ESP_OK;
    *size = 0;
    uint16_t header_status;
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, KSZ8851_RXFHSR, &header_status), err, TAG, "RXFHSR read failed");
    uint16_t byte_count;
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, KSZ8851_RXFHBCR, &byte_count), err, TAG, "RXFHBCR read failed");
    if (header_status & RXFHSR_RXFV) {
        *size = byte_count & RXFHBCR_RXBC_MASK;
    } else if (header_status & (RXFHSR_RXCE | RXFHSR_RXRF | RXFHSR_RXFTL | RXFHSR_RXMR | RXFHSR_RXUDPFCS | RXFHSR_RXTCPFCS |
                                RXFHSR_RXIPFCS | RXFHSR_RXICMPFCS)) {
        // NOTE(v.chistyakov): RRXEF is a self-clearing bit
        ESP_GOTO_ON_ERROR(ksz8851_release_rx_frame(emac), err, TAG, "RXQCR write failed");   // Changed for its-g5-receiver-firmware: written whole, then waited for
    }
err:
    return ret;
}

static esp_err_t emac_ksz8851_alloc_recv_buf(emac_ksz8851snl_t *emac, uint8_t **buf, uint32_t *length)
{
    esp_err_t ret = ESP_OK;
    uint16_t rx_len = 0;
    uint16_t byte_count;
    *buf = NULL;

    ESP_GOTO_ON_ERROR(emac_ksz8851_get_recv_byte_count(emac, &byte_count), err, TAG, "get receive frame byte count failed");
    // silently return when no frame is waiting
    if (!byte_count) {
        goto err;
    }
    // Changed for its-g5-receiver-firmware: reading RXFHSR and RXFHBCR has already moved the header registers on
    // to the next frame (datasheet p. 28, step 3). A frame left half read or unread would pair the next header
    // with this frame's data, so a count that is no frame is released and the RX task ends its round.
    if (!ksz8851_byte_count_ok(byte_count)) {
        ESP_LOGE(TAG, "byte count %" PRIu16 " is no frame length, frame released", byte_count);
        emac->bad_lengths++;   // Changed for its-g5-receiver-firmware: see ETH_KSZ8851SNL_CMD_G_STATS
        ksz8851_release_rx_frame(emac);
        ret = ESP_ERR_INVALID_SIZE;
        goto err;
    }
    // do not include 4 bytes CRC at the end
    rx_len = byte_count - ETH_CRC_LEN;
    // frames larger than expected will be truncated
    uint16_t copy_len = rx_len > *length ? *length : rx_len;
    // runt frames are not forwarded, but check the length anyway since it could be corrupted at SPI bus
    ESP_GOTO_ON_FALSE(copy_len >= ETH_MIN_PACKET_SIZE - ETH_CRC_LEN, ESP_ERR_INVALID_SIZE, err, TAG, "invalid frame length %" PRIu16, copy_len);
    *buf = malloc(copy_len);
    if (*buf != NULL) {
        ksz8851_auto_buf_info_t *buff_info = (ksz8851_auto_buf_info_t *)*buf;
        buff_info->copy_len = copy_len;
        buff_info->byte_cnt = byte_count;
    } else {
        ret = ESP_ERR_NO_MEM;
        goto err;
    }
err:
    *length = rx_len;
    return ret;
}

static esp_err_t emac_ksz8851_flush_recv_queue(emac_ksz8851snl_t *emac);   // Changed for its-g5-receiver-firmware: receive uses it

static esp_err_t emac_ksz8851_receive(esp_eth_mac_t *mac, uint8_t *buf, uint32_t *length)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    uint16_t copy_len       = 0;
    uint16_t rx_len;
    uint16_t byte_count;
    bool locked             = false;
    bool sda_set            = false;

    ESP_GOTO_ON_FALSE(buf, ESP_ERR_INVALID_ARG, err, TAG, "receive buffer can not be null");
    ESP_GOTO_ON_FALSE(length, ESP_ERR_INVALID_ARG, err, TAG, "receive buffer length can not be null");
    if (*length != KSZ8851_ETH_MAC_RX_BUF_SIZE_AUTO) {
        ESP_GOTO_ON_ERROR(emac_ksz8851_get_recv_byte_count(emac, &byte_count), err, TAG, "get receive frame byte count failed");
        // silently return when no frame is waiting
        if (!byte_count) {
            goto err;
        }
        // do not include 4 bytes CRC at the end
        rx_len = byte_count - ETH_CRC_LEN;
        // frames larger than expected will be truncated
        copy_len = rx_len > *length ? *length : rx_len;
    } else {
        ksz8851_auto_buf_info_t *buff_info = (ksz8851_auto_buf_info_t *)buf;
        copy_len = buff_info->copy_len;
        byte_count = buff_info->byte_cnt;
    }

    // NOTE(v.chistyakov): 4 dummy + 4 header + alignment
    const unsigned receive_size = 8U + ((byte_count + 3U) & ~0x3U);
    // Changed for its-g5-receiver-firmware: the FIFO read below writes 8 bytes plus the count, rounded up, into
    // the 2016-byte rx_buffer. The allocation path has checked the count; this keeps the buffer safe for a caller
    // with its own buffer. Such a frame has not been read, so releasing it is enough; a flush would drop the
    // good frames behind it too.
    if (!ksz8851_byte_count_ok(byte_count)) {
        ESP_LOGE(TAG, "byte count %" PRIu16 " is no frame length, frame released", byte_count);
        emac->bad_lengths++;   // Changed for its-g5-receiver-firmware: see ETH_KSZ8851SNL_CMD_G_STATS
        ksz8851_release_rx_frame(emac);
        *length = 0U;
        return ESP_ERR_INVALID_SIZE;
    }
    // Lock SPI since once `SDA Start DMA Access` bit is set, all registers access are disabled.
    if (!ksz8851_mutex_lock(emac)) {
        return ESP_ERR_TIMEOUT;
    }
    locked = true;
    // Changed for its-g5-receiver-firmware: RXFDPR and RXQCR are written whole (see KSZ8851_IER_NORMAL);
    // the frame pointer is write-only and starts at 0.
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_RXFDPR, KSZ8851_RXFDPR_NORMAL), err, TAG, "RXFDPR write failed");
    sda_set = true;
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL | RXQCR_SDA), err, TAG, "RXQCR write failed");
    ret = emac->spi.read(emac->spi.ctx, KSZ8851_SPI_COMMAND_READ_FIFO, 0, emac->rx_buffer, receive_size);
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL), err, TAG, "RXQCR write failed");
    ksz8851_mutex_unlock(emac);
    // Changed for its-g5-receiver-firmware: the frame in the RXQ starts with its status word and byte count,
    // low byte first (DS00002381C, table 3-10). It must name the count RXFHBCR gave. If not, a read was
    // disturbed, or the queue is a frame out of step with the header registers (a count read as 0 is skipped
    // without a release), and it is unknown where the frame pointer stands, so the whole queue is flushed. The
    // log line, with the status word, comes at most every 10 s; the counter takes every case.
    if (ret == ESP_OK) {
        const uint16_t queue_count = (uint16_t)(emac->rx_buffer[6] | (emac->rx_buffer[7] << 8)) & RXFHBCR_RXBC_MASK;
        if (queue_count != byte_count) {
            const uint16_t queue_status = (uint16_t)(emac->rx_buffer[4] | (emac->rx_buffer[5] << 8));
            const bool flushed = emac_ksz8851_flush_recv_queue(emac) == ESP_OK;
            emac->bad_lengths++;
            const TickType_t now_ticks = xTaskGetTickCount();
            if (!emac->bad_header_logged || now_ticks - emac->bad_header_logged >= pdMS_TO_TICKS(10000)) {
                emac->bad_header_logged = now_ticks ? now_ticks : 1;
                ESP_LOGE(TAG, "frame header says %" PRIu16 " bytes (status 0x%04" PRIx16 "), RXFHBCR %" PRIu16 ", RX queue %s",
                         queue_count, queue_status, byte_count, flushed ? "flushed" : "flush failed");
            }
            *length = 0U;
            return ESP_ERR_INVALID_SIZE;
        }
    }
    // NOTE(v.chistyakov): skip 4 dummy, 4 header
    memcpy(buf, emac->rx_buffer + 8U, copy_len);
    *length = copy_len;
    return ret;
err:
    // Changed for its-g5-receiver-firmware: give the lock back here too. Before, one SPI error while
    // it was held kept it with the RX task, and from then on every transmit and link check of other
    // tasks ran into ESP_ERR_TIMEOUT (ESP-IDF #18869).
    if (locked) {
        // Changed for its-g5-receiver-firmware: a failed SDA clear would leave register access
        // disabled, for the coming IER write too.
        if (sda_set) {
            ksz8851_write_reg(emac, KSZ8851_RXQCR, KSZ8851_RXQCR_NORMAL);
        }
        ksz8851_mutex_unlock(emac);
    }
    *length = 0U;
    return ret;
}

// Changed for its-g5-receiver-firmware: the four steps write emac->rxcr1 whole instead of reading RXCR1 back
// four times, and the lock is held across, so no other task changes RXCR1 between them. The last write puts
// back the intended value, RXE included.
static esp_err_t emac_ksz8851_flush_recv_queue(emac_ksz8851snl_t *emac)
{
    esp_err_t ret = ESP_OK;
    if (!ksz8851_mutex_lock(emac)) {
        return ESP_ERR_TIMEOUT;
    }
    const uint16_t off = emac->rxcr1 & ~RXCR1_RXE;
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_RXCR1, off), err, TAG, "RXCR1 write failed");
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_RXCR1, off | RXCR1_FRXQ), err, TAG, "RXCR1 write failed");
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_RXCR1, off), err, TAG, "RXCR1 write failed");
err:
    if (ksz8851_write_reg(emac, KSZ8851_RXCR1, emac->rxcr1) != ESP_OK && ret == ESP_OK) {
        ret = ESP_FAIL;
        ESP_LOGE(TAG, "RXCR1 write failed");
    }
    ksz8851_mutex_unlock(emac);
    return ret;
}

static esp_err_t emac_ksz8851_read_phy_reg(esp_eth_mac_t *mac, uint32_t phy_addr, uint32_t phy_reg, uint32_t *reg_value)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    ESP_GOTO_ON_FALSE(reg_value, ESP_ERR_INVALID_ARG, err, TAG, "reg_value can not be null");
    uint16_t tmp_val;
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, phy_reg, &tmp_val), err, TAG, "read PHY register failed");
    *reg_value = tmp_val;
err:
    return ret;
}

static esp_err_t emac_ksz8851_write_phy_reg(esp_eth_mac_t *mac, uint32_t phy_addr, uint32_t phy_reg, uint32_t reg_value)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, phy_reg, (uint16_t)reg_value), err, TAG, "write PHY register failed");
err:
    return ret;
}

static esp_err_t emac_ksz8851_set_addr(esp_eth_mac_t *mac, uint8_t *addr)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    ESP_GOTO_ON_FALSE(addr, ESP_ERR_INVALID_ARG, err, TAG, "addr can not be null");
    uint16_t MARL = addr[5] | ((uint16_t)(addr[4]) << 8);
    uint16_t MARM = addr[3] | ((uint16_t)(addr[2]) << 8);
    uint16_t MARH = addr[1] | ((uint16_t)(addr[0]) << 8);
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_MARL, MARL), err, TAG, "MARL write failed");
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_MARM, MARM), err, TAG, "MARM write failed");
    ESP_GOTO_ON_ERROR(ksz8851_write_reg(emac, KSZ8851_MARH, MARH), err, TAG, "MARH write failed");
    ESP_LOGD(TAG, "set MAC address to %02x:%02x:%02x:%02x:%02x:%02x", addr[0], addr[1], addr[2], addr[3], addr[4],
             addr[5]);
err:
    return ret;
}

static esp_err_t emac_ksz8851_get_addr(esp_eth_mac_t *mac, uint8_t *addr)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    ESP_GOTO_ON_FALSE(addr, ESP_ERR_INVALID_ARG, err, TAG, "addr can not be null");
    uint16_t MARL, MARM, MARH;
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, KSZ8851_MARL, &MARL), err, TAG, "MARL read failed");
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, KSZ8851_MARM, &MARM), err, TAG, "MARM read failed");
    ESP_GOTO_ON_ERROR(ksz8851_read_reg(emac, KSZ8851_MARH, &MARH), err, TAG, "MARH read failed");
    addr[0] = (MARH >> 8) & 0xFF;
    addr[1] = MARH & 0xFF;
    addr[2] = (MARM >> 8) & 0xFF;
    addr[3] = MARM & 0xFF;
    addr[4] = (MARL >> 8) & 0xFF;
    addr[5] = MARL & 0xFF;
err:
    return ret;
}

static inline __attribute__((always_inline)) uint32_t ksz8851_reflect32(uint32_t x)
{
    x = ((x >> 1) & 0x55555555u) | ((x & 0x55555555u) << 1);
    x = ((x >> 2) & 0x33333333u) | ((x & 0x33333333u) << 2);
    x = ((x >> 4) & 0x0F0F0F0Fu) | ((x & 0x0F0F0F0Fu) << 4);
    x = ((x >> 8) & 0x00FF00FFu) | ((x & 0x00FF00FFu) << 8);
    x = (x >> 16) | (x << 16);
    return x;
}

static esp_err_t ksz8851_hash_filter_modify(emac_ksz8851snl_t *emac, uint8_t *addr, bool add)
{
    esp_err_t ret = ESP_OK;

    // calculate crc32 value of mac address
    uint32_t crc = ksz8851_reflect32(~esp_rom_crc32_le(0, addr, ETH_ADDR_LEN));

    uint8_t hash_value = (crc >> 26) & 0x3F;
    uint8_t hash_group = hash_value / 16;
    uint8_t hash_bit = hash_value % 16;

    uint16_t mar_reg = KSZ8851_MAHTR0 + hash_group * 2;
    if (add) {
        // add address to hash table
        ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, mar_reg, 1 << hash_bit), err, TAG, "hash table set bits failed");
        emac->hash_filter_cnt[hash_value]++;
    } else {
        if (emac->hash_filter_cnt[hash_value] > 0) {
            emac->hash_filter_cnt[hash_value]--;
            if (emac->hash_filter_cnt[hash_value] == 0) {
                // remove address from hash table
                ESP_GOTO_ON_ERROR(ksz8851_clear_bits(emac, mar_reg, 1 << hash_bit), err, TAG, "hash table clear bits failed");
            }
        }
    }
err:
    return ret;
}

static esp_err_t emac_ksz8851_add_mac_filter(esp_eth_mac_t *mac, uint8_t *addr)
{
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    return ksz8851_hash_filter_modify(emac, addr, true);
}

static esp_err_t emac_ksz8851_rm_mac_filter(esp_eth_mac_t *mac, uint8_t *addr)
{
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    return ksz8851_hash_filter_modify(emac, addr, false);
}

static esp_err_t emac_ksz8851_set_speed(esp_eth_mac_t *mac, eth_speed_t speed)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    switch (speed) {
    case ETH_SPEED_100M:
        ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_P1CR, P1CR_FORCE_SPEED), err, TAG, "P1CR write failed");
        ESP_LOGD(TAG, "set speed to 100M");
        break;
    case ETH_SPEED_10M:
        ESP_GOTO_ON_ERROR(ksz8851_clear_bits(emac, KSZ8851_P1CR, P1CR_FORCE_SPEED), err, TAG, "P1CR write failed");
        ESP_LOGD(TAG, "set speed to 10M");
        break;
    default: ESP_GOTO_ON_FALSE(false, ESP_ERR_INVALID_ARG, err, TAG, "unknown speed"); break;
    }
err:
    return ret;
}

static esp_err_t emac_ksz8851_set_duplex(esp_eth_mac_t *mac, eth_duplex_t duplex)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    switch (duplex) {
    case ETH_DUPLEX_FULL:
        ESP_GOTO_ON_ERROR(ksz8851_set_bits(emac, KSZ8851_P1CR, P1CR_FORCE_DUPLEX), err, TAG, "P1CR write failed");
        ESP_LOGD(TAG, "set duplex to full");
        break;
    case ETH_DUPLEX_HALF:
        ESP_GOTO_ON_ERROR(ksz8851_clear_bits(emac, KSZ8851_P1CR, P1CR_FORCE_DUPLEX), err, TAG, "P1CR write failed");
        ESP_LOGD(TAG, "set duplex to half");
        break;
    default: ESP_GOTO_ON_FALSE(false, ESP_ERR_INVALID_ARG, err, TAG, "unknown duplex"); break;
    }
err:
    return ret;
}

static esp_err_t emac_ksz8851_set_link(esp_eth_mac_t *mac, eth_link_t link)
{
    esp_err_t ret = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    switch (link) {
    case ETH_LINK_UP:
        ESP_GOTO_ON_ERROR(mac->start(mac), err, TAG, "ksz8851 start failed");
        if (emac->poll_timer) {
            ESP_GOTO_ON_ERROR(esp_timer_start_periodic(emac->poll_timer, emac->poll_period_ms * 1000),
                              err, TAG, "start poll timer failed");
        }
        ESP_LOGD(TAG, "link is up");
        break;
    case ETH_LINK_DOWN:
        ESP_GOTO_ON_ERROR(mac->stop(mac), err, TAG, "ksz8851 stop failed");
        if (emac->poll_timer) {
            ESP_GOTO_ON_ERROR(esp_timer_stop(emac->poll_timer),
                              err, TAG, "stop poll timer failed");
        }
        ESP_LOGD(TAG, "link is down");
        break;
    default: ESP_GOTO_ON_FALSE(false, ESP_ERR_INVALID_ARG, err, TAG, "unknown link status"); break;
    }
err:
    return ret;
}

static esp_err_t emac_ksz8851_set_promiscuous(esp_eth_mac_t *mac, bool enable)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    // Changed for its-g5-receiver-firmware: through emac->rxcr1, see ksz8851_copy_update.
    if (enable) {
        ESP_LOGD(TAG, "setting promiscuous mode");
        ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_RXCR1, &emac->rxcr1, RXCR1_RXPAFMA | RXCR1_RXMAFMA, RXCR1_RXAE | RXCR1_RXINVF), err, TAG, "RXCR1 write failed");
    } else {
        ESP_LOGD(TAG, "setting hash perfect");
        ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_RXCR1, &emac->rxcr1, RXCR1_RXAE | RXCR1_RXINVF | RXCR1_RXMAFMA, RXCR1_RXPAFMA), err, TAG, "RXCR1 write failed");
    }
err:
    return ret;
}

static esp_err_t emac_ksz8851_set_all_multicast(esp_eth_mac_t *mac, bool enable)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    // Changed for its-g5-receiver-firmware: through emac->rxcr1, see ksz8851_copy_update.
    if (enable) {
        ESP_LOGD(TAG, "setting perfect with multicast passed");
        ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_RXCR1, &emac->rxcr1, RXCR1_RXINVF, RXCR1_RXAE | RXCR1_RXPAFMA | RXCR1_RXMAFMA), err, TAG, "RXCR1 write failed");
    } else {
        ESP_LOGD(TAG, "setting hash perfect");
        ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_RXCR1, &emac->rxcr1, RXCR1_RXAE | RXCR1_RXINVF | RXCR1_RXMAFMA, RXCR1_RXPAFMA), err, TAG, "RXCR1 write failed");
    }
err:
    return ret;
}

static esp_err_t emac_ksz8851_enable_flow_ctrl(esp_eth_mac_t *mac, bool enable)
{
    esp_err_t ret           = ESP_OK;
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    if (enable) {
        ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_TXCR, &emac->txcr, 0, TXCR_TXFCE), err, TAG, "TXCR write failed");   // Changed for its-g5-receiver-firmware
        ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_RXCR1, &emac->rxcr1, 0, RXCR1_RXFCE), err, TAG, "RXCR write failed");   // Changed for its-g5-receiver-firmware
        ESP_LOGD(TAG, "flow control enabled");
    } else {
        ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_TXCR, &emac->txcr, TXCR_TXFCE, 0), err, TAG, "TXCR write failed");   // Changed for its-g5-receiver-firmware
        ESP_GOTO_ON_ERROR(ksz8851_copy_update(emac, KSZ8851_RXCR1, &emac->rxcr1, RXCR1_RXFCE, 0), err, TAG, "RXCR write failed");   // Changed for its-g5-receiver-firmware
        ESP_LOGD(TAG, "flow control disabled");
    }
err:
    return ret;
}

static esp_err_t emac_ksz8851_set_peer_pause_ability(esp_eth_mac_t *mac, uint32_t ability)
{
    // NOTE(v.chistyakov): peer's pause ability is determined with auto-negotiation
    return ESP_ERR_NOT_SUPPORTED;
}

static void emac_ksz8851snl_task(void *arg)
{
    emac_ksz8851snl_t *emac = (emac_ksz8851snl_t *)arg;
    esp_err_t ret;
    TickType_t last_reassert = xTaskGetTickCount();
    while (1) {
        // Changed for its-g5-receiver-firmware: about once a second, with traffic or without, IER and RXQCR
        // are set back and RXCR1 and TXCR written from their copies (ksz8851_irq_reassert). Here at the top,
        // so the quiet branch below reaches it too.
        TickType_t now = xTaskGetTickCount();
        if (now - last_reassert >= pdMS_TO_TICKS(1000)) {
            last_reassert = now;
            ksz8851_irq_reassert(emac);
        }
        if (emac->int_gpio_num >= 0) {                                   // if in interrupt mode
            if (ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(1000)) == 0 &&   // if no notification ...
                    gpio_get_level(emac->int_gpio_num) != 0) {               // ...and no interrupt asserted
                continue;                                                // -> just continue to check again
            }
        } else {
            ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        }

        // Changed for its-g5-receiver-firmware: without a valid status nothing is acknowledged. An
        // unchecked failed read would clear pending events unhandled or start the RX block for
        // nothing. The next try comes after the next wait.
        uint16_t interrupt_status = 0;
        if (ksz8851_read_reg(emac, KSZ8851_ISR, &interrupt_status) != ESP_OK) {
            continue;
        }
        ksz8851_write_reg(emac, KSZ8851_ISR, interrupt_status);

        if (interrupt_status & ISR_TXIS) {
            ESP_LOGD(TAG, "TX Interrupt");
        }
        if (interrupt_status & ISR_RXOIS) {
            ESP_LOGD(TAG, "RX Overrun Interrupt");
            emac->rx_overruns++;   // Changed for its-g5-receiver-firmware: see ETH_KSZ8851SNL_CMD_G_STATS
        }
        if (interrupt_status & ISR_TXPSIS) {
            ESP_LOGD(TAG, "TX Process Stopped Interrupt");
        }
        if (interrupt_status & ISR_RXPSIS) {
            ESP_LOGD(TAG, "RX Process Stopped Interrupt");
        }
        if (interrupt_status & ISR_TXSAIS) {
            ESP_LOGD(TAG, "TX Space Available Interrupt");
        }
        if (interrupt_status & ISR_RXWFDIS) {
            ESP_LOGD(TAG, "RX Wakeup Frame Detect Interrupt");
        }
        if (interrupt_status & ISR_RXMPDIS) {
            ESP_LOGD(TAG, "RX Magic Packet Detect Interrupt");
        }
        if (interrupt_status & ISR_LDIS) {
            ESP_LOGD(TAG, "Linkup Detect Interrupt");
            // Changed for its-g5-receiver-firmware: written whole; the wake-up event bits clear on a 1.
            ksz8851_write_reg(emac, KSZ8851_PMECR, KSZ8851_PMECR_NORMAL | PMECR_WAKEUP_LINK);
        }
        if (interrupt_status & ISR_EDIS) {
            ESP_LOGD(TAG, "Energy Detect Interrupt");
        }
        if (interrupt_status & ISR_SPIBEIS) {
            // Changed for its-g5-receiver-firmware: a warning with a count instead of a debug line, as evidence
            // for or against errors on the bus shared with the SD card. The datasheet (p. 57) does not say
            // what the chip counts as one. At most one line per 10 s, so a burst cannot flood the log.
            emac->spi_bus_errors++;
            TickType_t now_ticks = xTaskGetTickCount();
            if (emac->spi_bus_errors == 1U || now_ticks - emac->spi_bus_error_logged >= pdMS_TO_TICKS(10000)) {
                emac->spi_bus_error_logged = now_ticks;
                ESP_LOGW(TAG, "the chip reported an SPI bus error (%" PRIu32 " since start)", emac->spi_bus_errors);
            }
        }
        if (interrupt_status & ISR_RXIS) {
            ESP_LOGD(TAG, "RX Interrupt");

            // Changed for its-g5-receiver-firmware: IER goes back to KSZ8851_IER_NORMAL below, not to a
            // value read here. A transmit in this window sets it back early; that only brings the next
            // notification forward, because frame_count is fixed below and a pending notification is
            // taken in the next round.
            ksz8851_write_reg(emac, KSZ8851_IER, 0);

            uint16_t frame_count = 0;
            ksz8851_read_reg(emac, KSZ8851_RXFCTR, &frame_count);
            frame_count = (frame_count & RXFCTR_RXFC_MASK) >> RXFCTR_RXFC_SHIFT;

            while (frame_count--) {
                /* define max expected frame len */
                uint32_t frame_len = ETH_MAX_PACKET_SIZE;
                uint8_t *buffer;
                if ((ret = emac_ksz8851_alloc_recv_buf(emac, &buffer, &frame_len)) == ESP_OK) {
                    if (buffer != NULL) {
                        /* we have memory to receive the frame of maximal size previously defined */
                        uint32_t buf_len = KSZ8851_ETH_MAC_RX_BUF_SIZE_AUTO;
                        esp_err_t rx_ret = emac->parent.receive(&emac->parent, buffer, &buf_len);   // Changed for its-g5-receiver-firmware: kept for the branch below
                        if (rx_ret == ESP_OK) {
                            if (buf_len == 0) {
                                emac_ksz8851_flush_recv_queue(emac);
                                free(buffer);
                            } else if (frame_len > buf_len) {
                                // Changed for its-g5-receiver-firmware: with both lengths. Counts outside
                                // 64..2000 are turned away before, and receive has matched the count against
                                // the frame header, so this is a real frame of 1527 to 2000 bytes (the log
                                // shows 1523 to 1996, without the CRC).
                                ESP_LOGE(TAG, "received frame was truncated (%" PRIu32 " of %" PRIu32 " bytes)",
                                         buf_len, frame_len);
                                free(buffer);
                            } else {
                                ESP_LOGD(TAG, "receive len=%" PRIu32, buf_len);
                                /* pass the buffer to stack (e.g. TCP/IP layer) */
                                emac->eth->stack_input(emac->eth, buffer, buf_len);
                            }
                        } else if (rx_ret == ESP_ERR_INVALID_SIZE) {
                            // Changed for its-g5-receiver-firmware: receive has released that frame or
                            // flushed the queue. The frame count was read on the same bus and may be disturbed
                            // as well, so the round ends here. The next frame that arrives raises the interrupt again, and
                            // that round reads the frame count anew.
                            free(buffer);
                            break;
                        } else {
                            ESP_LOGE(TAG, "frame read from module failed");
                            emac_ksz8851_flush_recv_queue(emac);
                            free(buffer);
                        }
                    } else if (frame_len) {
                        ESP_LOGE(TAG, "invalid combination of frame_len(%" PRIu32 ") and buffer pointer(%p)", frame_len, buffer);
                    }
                } else if (ret == ESP_ERR_INVALID_SIZE) {
                    // Changed for its-g5-receiver-firmware: the allocation path has released a frame whose
                    // count was no frame length. As after a refused receive above, the round ends here.
                    break;
                } else if (ret == ESP_ERR_NO_MEM) {
                    ESP_LOGE(TAG, "no mem for receive buffer");
                    emac_ksz8851_flush_recv_queue(emac);
                } else {
                    ESP_LOGE(TAG, "unexpected error 0x%x", ret);
                }
            }
            ksz8851_write_reg(emac, KSZ8851_IER, KSZ8851_IER_NORMAL);
        }
    }
    vTaskDelete(NULL);
}

// Changed for its-g5-receiver-firmware: ETH_KSZ8851SNL_CMD_G_STATS. Each MIB read clears the counter in the chip
// (DS00002381C, p. 71), so the driver adds up. These four grow slowly, so reading on request is enough. A value of
// 2^24 or more in one interval is taken for a bent high word and dropped, since a read cannot be repeated.
static esp_err_t emac_ksz8851_custom_ioctl(esp_eth_mac_t *mac, int cmd, void *data)
{
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    ESP_RETURN_ON_FALSE(cmd == ETH_KSZ8851SNL_CMD_G_STATS, ESP_ERR_NOT_SUPPORTED, TAG, "unknown command %d", cmd);
    ESP_RETURN_ON_FALSE(data != NULL, ESP_ERR_INVALID_ARG, TAG, "stats pointer must not be null");
    esp_err_t ret = ESP_OK;
    // The lock also covers the copy below: a uint64_t is two words on this CPU and could tear beside a second
    // caller adding to it.
    if (!ksz8851_mutex_lock(emac)) {
        return ESP_ERR_TIMEOUT;
    }
    if (emac->irq_ready) {
        for (unsigned i = 0; i < 4U && ret == ESP_OK; i++) {
            uint32_t v;
            ret = ksz8851_mib_read(emac, i, &v);
            emac->mib_total[i] += v;
        }
    }
    eth_ksz8851snl_stats_t *s = (eth_ksz8851snl_stats_t *)data;
    s->tx_pause = emac->mib_total[0];
    s->rx_crc_errors = emac->mib_total[1];
    s->rx_symbol_errors = emac->mib_total[2];
    s->rx_long = emac->mib_total[3];
    s->rx_overruns = emac->rx_overruns;
    s->spi_bus_errors = emac->spi_bus_errors;
    s->bad_lengths = emac->bad_lengths;
    ksz8851_mutex_unlock(emac);
    return ret;
}

static esp_err_t emac_ksz8851_del(esp_eth_mac_t *mac)
{
    emac_ksz8851snl_t *emac = __containerof(mac, emac_ksz8851snl_t, parent);
    if (emac->poll_timer) {
        esp_timer_delete(emac->poll_timer);
    }
    // Changed for its-g5-receiver-firmware: the firmware now retries a failed start instead of
    // rebooting, so this runs on a live system. The ISR handler goes first, because a failed
    // esp_eth_driver_install() after a good mac->init leaves it in place, and it would notify the
    // deleted RX task. The lock is taken before the task is deleted: every SPI transfer of the RX
    // task runs under it, and since the transfers are interrupt-driven the task waits inside them.
    // Deleted there, its finished transfer would be written to freed memory.
    if (emac->int_gpio_num >= 0) {
        gpio_isr_handler_remove(emac->int_gpio_num);
    }
    xSemaphoreTakeRecursive(emac->spi_lock, portMAX_DELAY);
    vTaskDelete(emac->rx_task_hdl);
    emac->spi.deinit(emac->spi.ctx);
    xSemaphoreGiveRecursive(emac->spi_lock);
    vSemaphoreDelete(emac->spi_lock);
    heap_caps_free(emac->rx_buffer);
    heap_caps_free(emac->tx_buffer);
    free(emac);
    return ESP_OK;
}

esp_eth_mac_t *esp_eth_mac_new_ksz8851snl(const eth_ksz8851snl_config_t *ksz8851snl_config,
                                          const eth_mac_config_t *mac_config)
{
    esp_eth_mac_t *ret      = NULL;
    emac_ksz8851snl_t *emac = NULL;

    ESP_GOTO_ON_FALSE(ksz8851snl_config && mac_config, NULL, err, TAG, "arguments can not be null");
    ESP_GOTO_ON_FALSE((ksz8851snl_config->int_gpio_num >= 0) != (ksz8851snl_config->poll_period_ms > 0), NULL, err, TAG, "invalid configuration argument combination");

    emac = calloc(1, sizeof(emac_ksz8851snl_t));
    ESP_GOTO_ON_FALSE(emac, NULL, err, TAG, "no mem for MAC instance");

    emac->sw_reset_timeout_ms           = mac_config->sw_reset_timeout_ms;
    emac->int_gpio_num                  = ksz8851snl_config->int_gpio_num;
    emac->poll_period_ms                = ksz8851snl_config->poll_period_ms;
    emac->parent.set_mediator           = emac_ksz8851_set_mediator;
    emac->parent.init                   = emac_ksz8851_init;
    emac->parent.deinit                 = emac_ksz8851_deinit;
    emac->parent.start                  = emac_ksz8851_start;
    emac->parent.stop                   = emac_ksz8851_stop;
    emac->parent.transmit               = emac_ksz8851snl_transmit;
    emac->parent.receive                = emac_ksz8851_receive;
    emac->parent.read_phy_reg           = emac_ksz8851_read_phy_reg;
    emac->parent.write_phy_reg          = emac_ksz8851_write_phy_reg;
    emac->parent.set_addr               = emac_ksz8851_set_addr;
    emac->parent.get_addr               = emac_ksz8851_get_addr;
    emac->parent.add_mac_filter         = emac_ksz8851_add_mac_filter;
    emac->parent.rm_mac_filter          = emac_ksz8851_rm_mac_filter;
    emac->parent.set_speed              = emac_ksz8851_set_speed;
    emac->parent.set_duplex             = emac_ksz8851_set_duplex;
    emac->parent.set_link               = emac_ksz8851_set_link;
    emac->parent.set_promiscuous        = emac_ksz8851_set_promiscuous;
    emac->parent.set_all_multicast      = emac_ksz8851_set_all_multicast;
    emac->parent.enable_flow_ctrl       = emac_ksz8851_enable_flow_ctrl;
    emac->parent.set_peer_pause_ability = emac_ksz8851_set_peer_pause_ability;
    emac->parent.del                    = emac_ksz8851_del;
    emac->parent.custom_ioctl           = emac_ksz8851_custom_ioctl;   // Changed for its-g5-receiver-firmware
    emac->rx_buffer = NULL;
    emac->tx_buffer = NULL;
    emac->rx_buffer = heap_caps_malloc(KSZ8851_QMU_PACKET_LENGTH + KSZ8851_QMU_PACKET_PADDING, MALLOC_CAP_DMA);
    emac->tx_buffer = heap_caps_malloc(KSZ8851_QMU_PACKET_LENGTH + KSZ8851_QMU_PACKET_PADDING, MALLOC_CAP_DMA);
    ESP_GOTO_ON_FALSE(emac->rx_buffer, NULL, err, TAG, "RX buffer allocation failed");
    ESP_GOTO_ON_FALSE(emac->tx_buffer, NULL, err, TAG, "TX buffer allocation failed");

    /* create mutex */
    emac->spi_lock = xSemaphoreCreateRecursiveMutex();
    ESP_GOTO_ON_FALSE(emac->spi_lock, NULL, err, TAG, "create lock failed");

    if (ksz8851snl_config->custom_spi_driver.init != NULL && ksz8851snl_config->custom_spi_driver.deinit != NULL
            && ksz8851snl_config->custom_spi_driver.read != NULL && ksz8851snl_config->custom_spi_driver.write != NULL) {
        ESP_LOGD(TAG, "Using user's custom SPI Driver");
        emac->spi.init = ksz8851snl_config->custom_spi_driver.init;
        emac->spi.deinit = ksz8851snl_config->custom_spi_driver.deinit;
        emac->spi.read = ksz8851snl_config->custom_spi_driver.read;
        emac->spi.write = ksz8851snl_config->custom_spi_driver.write;
        /* Custom SPI driver device init */
        ESP_GOTO_ON_FALSE((emac->spi.ctx = emac->spi.init(ksz8851snl_config->custom_spi_driver.config)) != NULL, NULL, err, TAG, "SPI initialization failed");
    } else {
        ESP_LOGD(TAG, "Using default SPI Driver");
        emac->spi.init = ksz8851_spi_init;
        emac->spi.deinit = ksz8851_spi_deinit;
        emac->spi.read = ksz8851_spi_read;
        emac->spi.write = ksz8851_spi_write;
        /* SPI device init */
        ESP_GOTO_ON_FALSE((emac->spi.ctx = emac->spi.init(ksz8851snl_config)) != NULL, NULL, err, TAG, "SPI initialization failed");
    }

    BaseType_t core_num = tskNO_AFFINITY;
    if (mac_config->flags & ETH_MAC_FLAG_PIN_TO_CORE) {
        core_num = esp_cpu_get_core_id();
    }
    BaseType_t xReturned = xTaskCreatePinnedToCore(emac_ksz8851snl_task, "ksz8851snl_tsk", mac_config->rx_task_stack_size,
                                                   emac, mac_config->rx_task_prio, &emac->rx_task_hdl, core_num);
    ESP_GOTO_ON_FALSE(xReturned == pdPASS, NULL, err, TAG, "create ksz8851 task failed");

    if (emac->int_gpio_num < 0) {
        const esp_timer_create_args_t poll_timer_args = {
            .callback = ksz8851_poll_timer,
            .name = "emac_spi_poll_timer",
            .arg = emac,
            .skip_unhandled_events = true
        };
        ESP_GOTO_ON_FALSE(esp_timer_create(&poll_timer_args, &emac->poll_timer) == ESP_OK, NULL, err, TAG, "create poll timer failed");
    }

    return &(emac->parent);

err:
    if (emac) {
        if (emac->poll_timer) {
            esp_timer_delete(emac->poll_timer);
        }
        if (emac->rx_task_hdl) {
            vTaskDelete(emac->rx_task_hdl);
        }
        if (emac->spi_lock) {
            vSemaphoreDelete(emac->spi_lock);
        }
        if (emac->spi.ctx) {
            emac->spi.deinit(emac->spi.ctx);
        }
        // NOTE(v.chistyakov): safe to call with NULL
        heap_caps_free(emac->rx_buffer);
        heap_caps_free(emac->tx_buffer);
        free(emac);
    }
    return ret;
}
