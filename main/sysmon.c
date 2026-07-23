#include "sdkconfig.h"

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_event.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "mdns.h"

#include "cmd_sniffer.h"
#include "config.h"
#include "events.h"
#include "sysmon.h"
#include "sysstat.h"
#include "stats.h"
#include "events_log.h"
#include "tracklog.h"
#if CONFIG_ENABLE_SD
#include "sdcard.h"
#endif

static const char TAG[] = "SYSMON";

/* Supervisory loop period. All thresholds below are expressed in wall-clock
 * time and converted to tick counts against this. */
#define SYSMON_INTERVAL_MS   5000

/* (4) Auto-recovery: if the sniffer is running but its heartbeat hasn't moved
 * for this long, a packet handler (MQTT/web/SD) is wedged -> controlled
 * reboot. Generous vs. the ~100 ms heartbeat cadence to avoid false trips. */
#define SYSMON_HANG_MS       30000

/* (6) Low-heap guard: reboot if free INTERNAL heap stays under the floor for
 * this long. The floor is far below normal (post-PSRAM-offload the low-water
 * mark is ~85 KiB), so this only fires on a genuine leak/exhaustion. */
#define SYSMON_HEAP_FLOOR    (8 * 1024)
#define SYSMON_LOWHEAP_MS    60000

/* (5) SD auto-remount retry cadence while the card is not mounted. */
#define SYSMON_SD_RETRY_MS   30000

#define MS_TO_TICKS_COUNT(ms) ((ms) / SYSMON_INTERVAL_MS)

static void reboot_after(const char *reason)
{
    ESP_LOGE(TAG, "%s -- rebooting", reason);
    /* Let the log line flush (also to the SD log's writer task) before we go. */
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_restart();
}

static void sysmon_task(void *arg)
{
    (void)arg;
    uint32_t last_hb = sniffer_get_heartbeat();
    int hb_stall = 0;      /* consecutive intervals with no heartbeat movement */
    int lowheap = 0;       /* consecutive intervals under the heap floor */
    int sd_wait = 0;       /* intervals since the last SD remount attempt */

    for (;;)
    {
        vTaskDelay(pdMS_TO_TICKS(SYSMON_INTERVAL_MS));

        /* Stability stats: track longest uptime + backfill last-crash time. */
        sysstat_tick((uint32_t)(esp_timer_get_time() / 1000000ll));
        /* Traffic statistics: flush a completed hour to SD if one rolled over. */
        tstat_tick();
        /* Warning-event log: flush any queued DENM events to SD. */
        events_tick();
        tracklog_tick();

        /* (4) Sniffer pipeline liveness. */
        if (sniffer_is_running())
        {
            uint32_t hb = sniffer_get_heartbeat();
            if (hb == last_hb)
            {
                if (++hb_stall >= (int)MS_TO_TICKS_COUNT(SYSMON_HANG_MS))
                    reboot_after("Sniffer pipeline stalled");
            }
            else
            {
                hb_stall = 0;
                last_hb = hb;
            }
        }
        else
        {
            hb_stall = 0;
            last_hb = sniffer_get_heartbeat();
        }

        /* (6) Internal heap floor. */
        size_t free_int = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
        if (free_int < SYSMON_HEAP_FLOOR)
        {
            if (++lowheap >= (int)MS_TO_TICKS_COUNT(SYSMON_LOWHEAP_MS))
            {
                char msg[80];
                snprintf(msg, sizeof(msg), "Internal heap critically low (%u B)",
                         (unsigned)free_int);
                reboot_after(msg);
            }
        }
        else
        {
            lowheap = 0;
        }

#if CONFIG_ENABLE_SD
        /* (5) SD auto-remount: retry every SYSMON_SD_RETRY_MS while unmounted
         * (e.g. the card wasn't ready at boot, or was briefly removed). */
        if (!sdcard_is_mounted())
        {
            if (++sd_wait >= (int)MS_TO_TICKS_COUNT(SYSMON_SD_RETRY_MS))
            {
                sd_wait = 0;
                if (sdcard_mount() == ESP_OK)
                    ESP_LOGI(TAG, "SD card mounted on retry");
            }
        }
        else
        {
            sd_wait = 0;
        }
#else
        (void)sd_wait;
#endif
    }
}

/* (10) mDNS: advertise the web UI as http://its-<nodeid>.local. Started once
 * the management interface has an IP (mDNS needs the netif up). */
static bool mdns_started;

static void start_mdns(void)
{
    if (mdns_started)
        return;

    char nodeid[CONFIG_NODEID_BUFFER_SIZE] = {0};
    size_t size = sizeof(nodeid);
    if (config_get_str(CONFIG_INDEX_NODEID, nodeid, &size) != ESP_OK)
        return;

    /* mDNS host labels allow only [a-z0-9-]; sanitise whatever the node id is. */
    char host[8 + CONFIG_NODEID_BUFFER_SIZE] = "its-";
    size_t h = strlen(host);
    for (size_t i = 0; nodeid[i] && h < sizeof(host) - 1; i++)
    {
        char c = nodeid[i];
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
        host[h++] = ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) ? c : '-';
    }
    host[h] = '\0';

    if (mdns_init() != ESP_OK)
    {
        ESP_LOGW(TAG, "mdns_init failed");
        return;
    }
    mdns_hostname_set(host);
    mdns_instance_name_set("ITS-G5 Receiver");
    mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
    mdns_started = true;
    ESP_LOGI(TAG, "mDNS up: http://%s.local", host);
}

static void sysmon_event_handler(void *arg, esp_event_base_t base,
                                 int32_t event_id, void *event_data)
{
    (void)arg; (void)base; (void)event_data;
    if (event_id == APP_ETHERNET_MGMT_INTERFACE_GOT_IP)
        start_mdns();
}

void sysmon_register_events(void)
{
    ESP_ERROR_CHECK(esp_event_handler_register(APP_EVENT_BASE, APP_ETHERNET_MGMT_INTERFACE_GOT_IP,
                                               sysmon_event_handler, NULL));
}

void sysmon_init(void)
{
    /* Low priority: supervision must never starve the sniffer/network tasks. */
    if (xTaskCreate(sysmon_task, "sysmon", 4096, NULL, 2, NULL) != pdPASS)
        ESP_LOGE(TAG, "failed to create sysmon task");
}
