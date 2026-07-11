#pragma once

#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CONFIG_NODEID_BUFFER_SIZE 64
#define CONFIG_MQTT_URI_BUFFER_SIZE 256
#define CONFIG_IPV4_BUFFER_SIZE 16
#define CONFIG_WEB_PASSWORD_BUFFER_SIZE 65  /* holds a SHA-256 hex digest (64 chars) + NUL, not the raw password */
#define CONFIG_NTP_SERVER_BUFFER_SIZE 64

void config_init(void);

typedef enum {
    CONFIG_INDEX_NODEID,
    CONFIG_INDEX_MQTT_URI,
    CONFIG_INDEX_ETH_IP,
    CONFIG_INDEX_ETH_NETMASK,
    CONFIG_INDEX_ETH_GATEWAY,
    CONFIG_INDEX_ETH_DNS0,
    CONFIG_INDEX_ETH_DNS1,
    CONFIG_INDEX_ETH_DNS2,
    CONFIG_INDEX_AUTOSTART_CHAN,
    CONFIG_INDEX_BROADCAST_ONLY,
    CONFIG_INDEX_LED_BRIGHTNESS,
    CONFIG_INDEX_LED_OVERRIDE_COLOR,
    CONFIG_INDEX_WEB_PASSWORD,
    CONFIG_INDEX_LOG_SYS,      /* u8  bool: write system log to SD */
    CONFIG_INDEX_LOG_FRAMES,   /* u8  bool: write received-frame CSV log to SD */
    CONFIG_INDEX_LOG_MAX_MB,   /* u32 total SD budget for logs, in MiB */
    CONFIG_INDEX_REFRESH_SEC,  /* u32 web UI auto-refresh interval (0 = off) */
    CONFIG_INDEX_NTP_SERVER,   /* str NTP server hostname (default pool.ntp.org) */
    CONFIG_INDEX_PCAP_ENABLE,       /* u8  bool: rolling raw-frame PCAP capture to SD */
    CONFIG_INDEX_PCAP_RETAIN_HOURS, /* u32 PCAP retention window, hours */
    CONFIG_INDEX_PCAP_MAX_MB,       /* u32 PCAP total SD safety-net budget, MiB */
    CONFIG_INDEX_PCAP_BUF_MB,       /* u32 PSRAM buffer size before flushing to SD, MiB */
    CONFIG_INDEX_PCAP_FLUSH_SEC,    /* u32 flush the PSRAM buffer at least this often, seconds */
} config_index_t;

/* Hashes a raw web-UI password the same salted way CONFIG_INDEX_WEB_PASSWORD
 * is stored -- used by webserver.c's auth check to hash an attempted
 * password identically before comparing against the stored hash. */
void config_hash_web_password(const char *raw, char out_hex[65]);

esp_err_t config_get_u8(config_index_t index, uint8_t *out);
esp_err_t config_set_u8(config_index_t index, uint8_t value);
esp_err_t config_get_u16(config_index_t index, uint16_t *out);
esp_err_t config_set_u16(config_index_t index, uint16_t value);
esp_err_t config_get_u32(config_index_t index, uint32_t *out);
esp_err_t config_set_u32(config_index_t index, uint32_t value);
esp_err_t config_get_u64(config_index_t index, uint64_t *out);
esp_err_t config_set_u64(config_index_t index, uint64_t value);
esp_err_t config_get_i8(config_index_t index, int8_t *out);
esp_err_t config_set_i8(config_index_t index, int8_t value);
esp_err_t config_get_i16(config_index_t index, int16_t *out);
esp_err_t config_set_i16(config_index_t index, int16_t value);
esp_err_t config_get_i32(config_index_t index, int32_t *out);
esp_err_t config_set_i32(config_index_t index, int32_t value);
esp_err_t config_get_i64(config_index_t index, int64_t *out);
esp_err_t config_set_i64(config_index_t index, int64_t value);

esp_err_t config_get_str(config_index_t index, char *out, size_t *size);
esp_err_t config_set_str(config_index_t index, const char *value);

esp_err_t config_get_blob(config_index_t index, uint8_t *out, size_t *size);
esp_err_t config_set_blob(config_index_t index, const uint8_t *val, size_t size);

void config_register_commands(void);

#ifdef __cplusplus
}
#endif
