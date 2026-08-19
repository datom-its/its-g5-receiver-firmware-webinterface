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
#include "inventory.h"
#include "ptlog.h"
#if CONFIG_ENABLE_SD
#include "sdcard.h"
#include "sdlog.h"
#include "sdpcap.h"
#endif

static const char TAG[] = "SYSMON";

void sysmon_flush_persistent(void)
{
#if CONFIG_ENABLE_SD
    /* Twice on purpose: the first call only pays an owed hour-boundary debt,
     * the second drains what the ring holds for the current hour. */
    /* The count is bytes that left the RING, not bytes on the card -- ask `ok`. */
    bool pcap_ok1 = true, pcap_ok2 = true;
    size_t pcap_bytes = sdpcap_flush_now(&pcap_ok1);
    pcap_bytes += sdpcap_flush_now(&pcap_ok2);
    tracklog_tick();      /* both drain their queue to the card and return */
    events_tick();
    /* These three keep state in RAM between their periodic writes; without this
     * a planned restart loses the running hour, open passages and the sender table. */
    tstat_flush_now();
    ptlog_flush_now();
    inventory_flush_now();
    /* Either call, not just the second: while a boundary debt is owed, a failed
     * first call is NOT made good by a successful second one. */
    if (!pcap_ok1 || !pcap_ok2)
        ESP_LOGE(TAG, "pcap flush failed -- %u bytes still buffered",
                 (unsigned)sdpcap_buffered());
    else if (pcap_bytes)
        ESP_LOGI(TAG, "flushed %u buffered pcap bytes", (unsigned)pcap_bytes);
    /* Last, not first: the log ring is RAM-only and the caller restarts or
     * unmounts, so the failure lines emitted above reach the card only here. */
    sdlog_flush_now();
#endif
}

/* Supervisory loop period. All thresholds below are expressed in wall-clock
 * time and converted to tick counts against this. */
#define SYSMON_INTERVAL_MS   5000

/* (4) Auto-recovery: sniffer running but heartbeat frozen this long means a
 * packet handler (MQTT/web/SD) is wedged -> controlled reboot. */
#define SYSMON_HANG_MS       30000

/* (6) Low-heap guard: reboot if free INTERNAL heap stays under the floor this
 * long. The floor sits far below the normal low-water mark -- only a real leak trips it. */
#define SYSMON_HEAP_FLOOR    (8 * 1024)
#define SYSMON_LOWHEAP_MS    60000

/* (5) SD auto-remount retry cadence while the card is not mounted. */
#define SYSMON_SD_RETRY_MS   30000

/* (7) SD writer stall: lock held this long in one piece, or this many failed
 * acquisitions, is a wedge -- every other SD user just fails silently. */
#define SYSMON_SD_HELD_MS    60000
#define SYSMON_SD_FAILS      40

#define MS_TO_TICKS_COUNT(ms) ((ms) / SYSMON_INTERVAL_MS)

static void reboot_after(const char *reason)
{
    ESP_LOGE(TAG, "%s -- rebooting", reason);
    /* Lets the UART line drain; deliberately short and WITHOUT flush_persistent:
     * this fires because something is wedged, possibly the SD writer itself. */
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
    int sd_stall = 0;      /* consecutive intervals with a wedged SD writer */

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
        /* Sender inventory: load once the card is up, then persist it. */
        inventory_tick();
        ptlog_tick();

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
        /* (7) SD writer stall detection. Warn first, reboot only if it does not
         * clear -- a false reboot costs the buffered recording. */
        if (sdcard_is_mounted())
        {
            uint32_t held = sdcard_io_held_ms();
            uint32_t fails = sdcard_io_fail_streak();
            if (held > SYSMON_SD_HELD_MS || fails > SYSMON_SD_FAILS)
            {
                if (++sd_stall == 1)
                    ESP_LOGE(TAG, "SD writer stalled (held %lu ms, %lu failed locks)",
                             (unsigned long)held, (unsigned long)fails);
                if (sd_stall >= (int)MS_TO_TICKS_COUNT(SYSMON_SD_HELD_MS))
                    reboot_after("SD writer wedged");
            }
            else
            {
                sd_stall = 0;
            }
        }
        else
        {
            sd_stall = 0;
        }

        /* (5) SD auto-remount: retry every SYSMON_SD_RETRY_MS while unmounted
         * (e.g. the card wasn't ready at boot, or was briefly removed). */
        if (!sdcard_is_mounted() && !sdcard_auto_remount_inhibited())
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
        (void)sd_stall;
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

    /* Instance name must be unique per device too: identical names get a
     * registration-order -2/-3 suffix from Bonjour that shuffles across reboots. */
    char instance[32 + CONFIG_NODEID_BUFFER_SIZE];
    snprintf(instance, sizeof(instance), "ITS-G5 Receiver (%s)", nodeid);
    mdns_instance_name_set(instance);
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
