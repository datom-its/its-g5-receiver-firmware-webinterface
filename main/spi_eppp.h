/*
 * SPI EPPP client — provides IP connectivity via an ESP32 running
 * the EPPP SPI slave (NAT gateway) instead of a hardware Ethernet chip.
 */

#pragma once

#ifdef CONFIG_USE_SPI_EPPP

/* Configures the EPPP SPI master and blocks until the PPP link is up. Its IP
 * handler posts APP_ETHERNET_MGMT_INTERFACE_GOT_IP, so MQTT etc. start normally. */
void initialize_spi_eppp(void);

#endif /* CONFIG_USE_SPI_EPPP */
