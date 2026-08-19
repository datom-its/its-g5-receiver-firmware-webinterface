#include "sdkconfig.h"

#include <cmath>
#include <cstdlib>
#include <cstring>

#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"

#include "ArduinoJson.h"

#include "esp_app_desc.h"
#include "esp_console.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "mqtt_client.h"

#include "cmd_sniffer.h"
#include "config.h"
#include "ethernet.h"
#include "events.h"
#include "temperature.h"

#include "mqtt.h"

constexpr char TAG[] = "MQTT";

/* `client` is created once and NEVER destroyed -- mqtt_stop() only stops
 * it, mqtt_start() reuses it. Destroying it would race mqtt_handle_packet()
 * on the sniffer task (use-after-free); publishing on a stopped-but-live
 * client is safe, esp-mqtt rejects it internally under its own lock. */
static esp_mqtt_client_handle_t client;
static bool client_running;
static bool connected;

static char topic_prefix[96];
static char command_topic[128];
static char result_topic[128];
static char packet_topic[128];
static char status_topic[128];
static char stats_topic[128];
static char info_topic[128];

static esp_timer_handle_t stats_timer_handle;

/* ------------------------------------------------------------------ *
 * Two worker tasks, both for the same reason: esp-mqtt holds its API
 * lock across the whole receive/dispatch section, so anything that runs
 * inside an event callback and then waits on something which itself
 * needs that lock deadlocks the client permanently.
 *
 *  - cmd worker: `sniffer --stop` waits for the sniffer task to finish,
 *    while the sniffer task is inside esp_mqtt_client_publish() waiting
 *    for the very lock the event callback still holds. Neither ever
 *    wakes up, and because is_running is already false by then sysmon's
 *    heartbeat check skips the sniffer entirely -- no watchdog rescue.
 *  - tx worker: publishing straight from the sniffer hot path blocks
 *    that task for as long as the broker's TCP send takes. A stalled
 *    broker then starves SD capture and the event log too, which is
 *    backwards: MQTT feeds a live map and is the one sink where
 *    dropping is correct (see the QoS0/no-store-and-forward decision).
 * ------------------------------------------------------------------ */
#define MQTT_CMD_QUEUE_LEN   4
#define MQTT_CMD_MAX_LEN   160
#define MQTT_TX_QUEUE_LEN   32

typedef struct {
    uint8_t *payload;      /* heap copy, freed by the tx worker */
    int      length;
    bool     replay;       /* from mqtt_replay_frame -- tracked for honest accounting */
} mqtt_tx_item_t;

static QueueHandle_t cmd_queue;
static QueueHandle_t tx_queue;
static uint32_t tx_dropped;
/* Replay accounting: the shared queue also carries the live feed, so a plain
 * queue count cannot tell whether the RSU re-send's frames were published. */
static uint32_t replay_pending;
static uint32_t replay_dropped_total;

static void mqtt_set_connected(bool new_connected)
{
    if (new_connected != connected)
    {
        connected = new_connected;
        esp_event_post(MQTT_EVENT_BASE, new_connected ? MQTT_CONNECTED : MQTT_DISCONNECTED, NULL, 0, 0);
    }
}

static void publish_node_info(void)
{
    char info[128];
    JsonDocument doc;

    char mac[6*2+5+1];
    {
        uint8_t eth_mac[6];
        ethernet_get_mac(eth_mac);

        snprintf(mac, sizeof(mac), "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                 eth_mac[0], eth_mac[1], eth_mac[2], eth_mac[3], eth_mac[4], eth_mac[5]);
    }

    doc["emac"] = mac;

    const esp_app_desc_t *app_desc = esp_app_get_description();
    doc["ver"] = app_desc->version;

    doc["hwv"] = CONFIG_HW_VARIANT;

    size_t written = serializeJson(doc, info);
    esp_mqtt_client_publish(client, info_topic, info, written, 0, 0);
}

static void publish_stats_timer_cb(void *)
{
    char stats[128];
    JsonDocument doc;

#ifdef CONFIG_ENABLE_TEMPERATURE
    float temp_f = temperature_get();
    if (!isnanf(temp_f))
    {
        temp_f = roundf(temp_f * 10.f) / 10.f;
        doc["temp"] = temp_f;
    }
#endif

    uint64_t seconds_since_boot = esp_timer_get_time() / 1000000ull;
    doc["rbt"] = seconds_since_boot;

    size_t written = serializeJson(doc, stats);
    esp_mqtt_client_publish(client, stats_topic, stats, written, 0, 0);
}

static void mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data) {
    ESP_LOGD(TAG, "Event dispatched from event loop base=%s, event_id=%d", base, event_id);

    esp_mqtt_event_handle_t event = static_cast<esp_mqtt_event_handle_t>(event_data);
    esp_mqtt_client_handle_t client = event->client;
    int msg_id;
    // your_context_t *context = event->context;
    switch (event->event_id) {
        case MQTT_EVENT_CONNECTED:
            mqtt_set_connected(true);
            ESP_LOGI(TAG, "MQTT_EVENT_CONNECTED");
            msg_id = esp_mqtt_client_subscribe(client, command_topic, 0);
            ESP_LOGI(TAG, "sent subscribe to '%s', msg_id=%d", command_topic, msg_id);

            esp_mqtt_client_publish(client, status_topic, "online", sizeof("online") - 1, 0, 1);

            publish_node_info();
            publish_stats_timer_cb(NULL);

            esp_timer_start_periodic(stats_timer_handle, 60000000);

            break;
        case MQTT_EVENT_DISCONNECTED:
            mqtt_set_connected(false);
            ESP_LOGI(TAG, "MQTT_EVENT_DISCONNECTED");
            break;
        case MQTT_EVENT_SUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_UNSUBSCRIBED:
            ESP_LOGI(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_PUBLISHED:
            ESP_LOGI(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event->msg_id);
            break;
        case MQTT_EVENT_DATA:
            ESP_LOGI(TAG, "MQTT_EVENT_DATA");
            ESP_LOGD(TAG, "TOPIC=%.*s\r\n", event->topic_len, event->topic);
            ESP_LOGD(TAG, "DATA=%.*s\r\n", event->data_len, event->data);
            if (strlen(command_topic) == event->topic_len && !strncmp(event->topic, command_topic, event->topic_len))
            {
                /* Handed to the cmd worker instead of run here: this callback
                 * runs with esp-mqtt's API lock held, and a command that waits
                 * on a task which itself wants to publish would deadlock the
                 * client for good (see the note at the top of this file). */
                char cmd[MQTT_CMD_MAX_LEN];
                int n = event->data_len;
                if (n >= (int)sizeof(cmd))
                    n = (int)sizeof(cmd) - 1;
                memcpy(cmd, event->data, n);
                cmd[n] = '\0';
                if (!cmd_queue || xQueueSend(cmd_queue, cmd, 0) != pdTRUE)
                    ESP_LOGW(TAG, "command queue full, dropping '%s'", cmd);
            }
            break;
        case MQTT_EVENT_ERROR:
            mqtt_set_connected(false);
            ESP_LOGI(TAG, "MQTT_EVENT_ERROR");
            if (event->error_handle->error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
                ESP_LOGI(TAG, "Last error code reported from esp-tls: 0x%x", event->error_handle->esp_tls_last_esp_err);
                ESP_LOGI(TAG, "Last tls stack error number: 0x%x", event->error_handle->esp_tls_stack_err);
                ESP_LOGI(TAG, "Last captured errno : %d (%s)",  event->error_handle->esp_transport_sock_errno,
                                                                strerror(event->error_handle->esp_transport_sock_errno));
            } else if (event->error_handle->error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
                ESP_LOGI(TAG, "Connection refused error: 0x%x", event->error_handle->connect_return_code);
            } else {
                ESP_LOGW(TAG, "Unknown error type: 0x%x", event->error_handle->error_type);
            }
            break;
        default:
            ESP_LOGI(TAG, "Other event id:%d", event->event_id);
            break;
    }
}

/* Runs console commands arriving over MQTT, off the mqtt task -- see the
 * deadlock note above. Publishing the result from here is safe: by then the
 * event callback has long returned and released the API lock. */
static void mqtt_cmd_task(void *)
{
    char cmd[MQTT_CMD_MAX_LEN];
    for (;;)
    {
        if (xQueueReceive(cmd_queue, cmd, portMAX_DELAY) != pdTRUE)
            continue;

        ESP_LOGI(TAG, "Running command '%s'", cmd);
        int ret = 0;
        int res = esp_console_run(cmd, &ret);

        char result_buf[128];
        if (res != ESP_OK)
        {
            snprintf(result_buf, sizeof(result_buf), "esp_console_run failed: %s", esp_err_to_name(res));
            ESP_LOGE(TAG, "%s", result_buf);
            continue;
        }
        snprintf(result_buf, sizeof(result_buf), "%d", ret);
        if (client && connected)
            esp_mqtt_client_publish(client, result_topic, result_buf, strlen(result_buf), 0, 0);
    }
}

/* Drains captured frames to the broker. Blocking here costs nothing but MQTT
 * latency; the sniffer task stays free to feed the SD capture and the logs. */
static void mqtt_tx_task(void *)
{
    mqtt_tx_item_t item;
    for (;;)
    {
        if (xQueueReceive(tx_queue, &item, portMAX_DELAY) != pdTRUE)
            continue;
        bool published = false;
        if (client && connected)
            published = esp_mqtt_client_publish(client, packet_topic,
                                    reinterpret_cast<const char *>(item.payload),
                                    item.length, 0, 0) >= 0;
        free(item.payload);
        if (item.replay)
        {
            if (!published)
                __atomic_add_fetch(&replay_dropped_total, 1, __ATOMIC_RELAXED);
            __atomic_sub_fetch(&replay_pending, 1, __ATOMIC_RELAXED);
        }
    }
}

static int make_topic_prefix()
{
    char nodeid[CONFIG_NODEID_BUFFER_SIZE];
    size_t size = sizeof(nodeid);

    esp_err_t res = config_get_str(CONFIG_INDEX_NODEID, nodeid, &size);
    if (res != ESP_OK)
    {
        ESP_LOGE(TAG, "Could not get node ID from config: %s", esp_err_to_name(res));
        return res;
    }

    snprintf(topic_prefix, sizeof(topic_prefix), "its/%.*s/", size, nodeid);

    return ESP_OK;
}

void mqtt_start(void)
{
    if (client_running)
    {
        ESP_LOGW(TAG, "MQTT already started");
        return;
    }

    if (make_topic_prefix() != ESP_OK)
    {
        ESP_LOGW(TAG, "make_topic_prefix failed");
        return;
    }

    strcpy(command_topic, topic_prefix);
    strcat(command_topic, "command");

    strcpy(result_topic, topic_prefix);
    strcat(result_topic, "command_result");

    strcpy(packet_topic, topic_prefix);
    strcat(packet_topic, "packet");

    strcpy(status_topic, topic_prefix);
    strcat(status_topic, "status");

    strcpy(info_topic, topic_prefix);
    strcat(info_topic, "info");

    strcpy(stats_topic, topic_prefix);
    strcat(stats_topic, "stats");

    char mqtt_uri[CONFIG_MQTT_URI_BUFFER_SIZE];
    size_t size = sizeof(mqtt_uri);
    esp_err_t res = config_get_str(CONFIG_INDEX_MQTT_URI, mqtt_uri, &size);
    if (res != ESP_OK)
    {
        ESP_LOGE(TAG, "Could not get MQTT URI from config: %s", esp_err_to_name(res));
        return;
    }

    if (!client)
    {
        /* First start: create the client. It stays alive for the rest of the
         * device's uptime (see the comment at the `client` definition). */
        esp_mqtt_client_config_t mqtt_cfg{};
        mqtt_cfg.broker.address.uri = mqtt_uri;
        mqtt_cfg.broker.verification.crt_bundle_attach = esp_crt_bundle_attach;
        /* Note: the last-will topic is copied by esp-mqtt at init and NOT
         * re-applied on a reuse-start below -- fine, since a nodeid change
         * requires a reboot anyway (like the other network settings). */
        mqtt_cfg.session.last_will = {
            .topic = status_topic,
            .msg = "offline",
            .msg_len = sizeof("offline") - 1,
            .qos = 0,
            .retain = 1
        };

        client = esp_mqtt_client_init(&mqtt_cfg);
        if (!client)
        {
            ESP_LOGE(TAG, "esp_mqtt_client_init failed");
            return;
        }
        esp_mqtt_client_register_event(client, static_cast<esp_mqtt_event_id_t>(ESP_EVENT_ANY_ID), mqtt_event_handler, client);
    }
    else
    {
        /* Reuse after a stop: only the URI may have changed at runtime. */
        esp_mqtt_client_set_uri(client, mqtt_uri);
    }

    esp_mqtt_client_start(client);
    client_running = true;
    ESP_LOGI(TAG, "MQTT started");
}

void mqtt_stop(void)
{
    if (!client_running)
    {
        ESP_LOGW(TAG, "Attempted to stop MQTT while not running");
        return;
    }
    client_running = false;

    esp_timer_stop_blocking(stats_timer_handle, 1000);

    /* Stop only -- never esp_mqtt_client_destroy() (see the comment at the
     * `client` definition for the use-after-free this used to cause). */
    esp_mqtt_client_stop(client);
    mqtt_set_connected(false);

    ESP_LOGI(TAG, "MQTT stopped");
}

static void app_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id, void *event_data)
{
    switch (event_id)
    {
    case APP_ETHERNET_MGMT_INTERFACE_GOT_IP:
        mqtt_start();
        break;
    case APP_ETHERNET_MGMT_INTERFACE_LOST_IP:
        mqtt_stop();
        break;
    }
}

extern "C" void mqtt_handle_packet(sniffer_packet_info_t *packet)
{
    if (!client || !connected || !tx_queue)
        return;

    /* One copy here, handed over to the tx worker which frees it. Dropping
     * when the queue is full is deliberate: this is a live feed on QoS0, and
     * a slow broker must not be able to stall the sniffer (and with it the SD
     * capture and the event log). */
    mqtt_tx_item_t item;
    item.length = packet->length;
    item.replay = false;
    item.payload = static_cast<uint8_t *>(malloc(packet->length));
    if (!item.payload)
        return;
    memcpy(item.payload, packet->payload, packet->length);

    if (xQueueSend(tx_queue, &item, 0) != pdTRUE)
    {
        free(item.payload);
        if ((++tx_dropped % 1000) == 1)
            ESP_LOGW(TAG, "MQTT publish queue full, %lu frame(s) dropped so far",
                     (unsigned long)tx_dropped);
    }
}

extern "C" bool mqtt_replay_frame(const uint8_t *data, size_t length)
{
    if (!client || !connected || !tx_queue || !data || length == 0)
        return false;

    mqtt_tx_item_t item;
    item.length = (int)length;
    item.replay = true;
    item.payload = static_cast<uint8_t *>(malloc(length));
    if (!item.payload)
        return false;
    memcpy(item.payload, data, length);

    /* Counted BEFORE the send: once queued, only the tx worker decrements. */
    __atomic_add_fetch(&replay_pending, 1, __ATOMIC_RELAXED);

    /* Unlike the live path this may wait: the caller paces itself and wants
     * to know about failure rather than lose frames silently. */
    if (xQueueSend(tx_queue, &item, pdMS_TO_TICKS(500)) != pdTRUE)
    {
        __atomic_sub_fetch(&replay_pending, 1, __ATOMIC_RELAXED);
        free(item.payload);
        return false;
    }
    return true;
}

extern "C" uint32_t mqtt_tx_dropped(void)
{
    return tx_dropped;
}

extern "C" uint32_t mqtt_replay_pending(void)
{
    return __atomic_load_n(&replay_pending, __ATOMIC_RELAXED);
}

extern "C" uint32_t mqtt_replay_dropped(void)
{
    return __atomic_load_n(&replay_dropped_total, __ATOMIC_RELAXED);
}

extern "C" void mqtt_init(void)
{
    esp_event_handler_register(APP_EVENT_BASE, ESP_EVENT_ANY_ID, app_event_handler, NULL);

    cmd_queue = xQueueCreate(MQTT_CMD_QUEUE_LEN, MQTT_CMD_MAX_LEN);
    tx_queue = xQueueCreate(MQTT_TX_QUEUE_LEN, sizeof(mqtt_tx_item_t));
    if (!cmd_queue || !tx_queue)
    {
        ESP_LOGE(TAG, "could not create MQTT worker queues");
    }
    else
    {
        /* 4 KB: a console command can reach into sniffer/OTA/config code. */
        xTaskCreate(mqtt_cmd_task, "mqtt_cmd", 4096, NULL, 4, NULL);
        xTaskCreate(mqtt_tx_task, "mqtt_tx", 3072, NULL, 4, NULL);
    }

    esp_timer_create_args_t create_args = {
        .callback = publish_stats_timer_cb,
        .arg = NULL,
        .dispatch_method = ESP_TIMER_TASK,
        .name = "mqtt_stats",
        .skip_unhandled_events = true
    };
    ESP_ERROR_CHECK(esp_timer_create(&create_args, &stats_timer_handle));
}
