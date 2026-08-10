/* cmd_pcap example — declarations of command registration functions.

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#pragma once

#include "pcap.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Append one captured packet to the pcap stream. */
esp_err_t packet_capture(void *payload, uint32_t length, uint32_t seconds, uint32_t microseconds);

/* Start pcap capture/writing for the given link type. */
esp_err_t sniff_packet_start(pcap_link_type_t link_type);

/* Stop pcap capture. */
esp_err_t sniff_packet_stop(void);

/**
 * @brief Register pcap command
 *
 */
void register_pcap_cmd(void);

#ifdef __cplusplus
}
#endif
