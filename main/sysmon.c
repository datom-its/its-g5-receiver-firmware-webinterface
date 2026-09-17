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

size_t sysmon_flush_persistent(void)
{
    size_t unsaved = 0;
#if CONFIG_ENABLE_SD
    /* Twice on purpose: while the ring still holds bytes of the previous hour,
     * the first call writes only those. The second drains the rest of the ring. */
    /* The count is bytes that left the RING. `ok` says if they reached the card. */
    bool pcap_ok1 = true, pcap_ok2 = true;
    size_t pcap_bytes = sdpcap_flush_now(&pcap_ok1);
    pcap_bytes += sdpcap_flush_now(&pcap_ok2);
    tracklog_tick();      /* both drain their queue to the card and return */
    events_tick();
    /* These three keep state in RAM between their periodic writes. Without this flush,
     * a planned restart loses the running hour, open passages and unsaved sender data. */
    tstat_flush_now();
    ptlog_flush_now();
    inventory_flush_now();
    /* Test both `ok` flags. While the ring still holds bytes of the previous hour,
     * a failed first call is NOT made good by a successful second one. */
    if (!pcap_ok1 || !pcap_ok2)
    {
        sysstat_sd_add(0, 1, 0);
        unsaved = sdpcap_buffered();
        ESP_LOGE(TAG, "pcap flush failed -- %u bytes still buffered",
                 (unsigned)unsaved);
    }
    else if (pcap_bytes)
        ESP_LOGI(TAG, "flushed %u buffered pcap bytes", (unsigned)pcap_bytes);
    /* Last, not first: the log ring is RAM-only and the caller restarts or
     * unmounts, so the failure lines emitted above reach the card only here. */
    sdlog_flush_now();
    /* sysstat_tick writes the SD loss counters to NVS at most every 10 min. A restart
     * or power cut before that loses the newest counts. */
    sysstat_flush();
#endif
    return unsaved;
}

/* Supervisory loop period. Most *_MS limits below are counted in passes of
 * this length, see MS_TO_TICKS_COUNT. */
#define SYSMON_INTERVAL_MS   5000

/* (4) Auto-recovery: if the sniffer runs but its heartbeat stays frozen this long,
 * a packet handler (MQTT/web/SD) is wedged. The device then reboots. */
#define SYSMON_HANG_MS       30000

/* (6) Low-heap guard: reboot if free INTERNAL heap stays under the floor this
 * long. The floor is far below the normal low-water mark, so only a real leak trips it. */
#define SYSMON_HEAP_FLOOR    (8 * 1024)
#define SYSMON_LOWHEAP_MS    60000

/* (5) SD auto-remount retry cadence while the card is not mounted. */
#define SYSMON_SD_RETRY_MS   30000

/* (7) SD writer stall: the lock held this long in one piece, or this many failed
 * acquisitions in a row, is a wedge. The other SD users only fail silently. */
#define SYSMON_SD_HELD_MS    60000
#define SYSMON_SD_FAILS      40
/* (8) A card is taken out after a minute with at least this many failed writes
 * and none that landed. A healthy card fails a write only now and then. A
 * wedged card fails every one. */
#define SYSMON_SD_DEAD_MS    60000
#define SYSMON_SD_DEAD_MIN   3

#define MS_TO_TICKS_COUNT(ms) ((ms) / SYSMON_INTERVAL_MS)

static void reboot_after(const char *reason)
{
    ESP_LOGE(TAG, "%s -- rebooting", reason);
    /* Pause briefly so the UART can send the log line. Do NOT call
     * sysmon_flush_persistent(): something is wedged, possibly the SD writer itself. */
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
#if CONFIG_ENABLE_SD
    uint32_t sd_prev_dropped = 0, sd_prev_flushfail = 0;
    int sd_dead_wait = 0;          /* intervals the (8) condition has held */
    bool sd_alive_warned = false;  /* (8) already warned that the card stays mounted */
#endif

    for (;;)
    {
        vTaskDelay(pdMS_TO_TICKS(SYSMON_INTERVAL_MS));

        /* Stability stats: track longest uptime + backfill last-crash time. */
        sysstat_tick((uint32_t)(esp_timer_get_time() / 1000000ll));
#if CONFIG_ENABLE_SD
        /* Feed the per-boot SD loss counters into the ones that survive a
         * reboot. Add only the deltas, because the sources restart with the device. */
        {
            uint32_t d = sdpcap_dropped(), f = sdpcap_flush_fails();
            if (d != sd_prev_dropped || f != sd_prev_flushfail)
            {
                sysstat_sd_add(d - sd_prev_dropped, f - sd_prev_flushfail, 0);
                sd_prev_dropped = d;
                sd_prev_flushfail = f;
            }
        }
#endif
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
         * clear. A false reboot costs the buffered recording. */
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

        /* (8) A card that stopped taking writes is taken out, so /status.json
         * says so and (5) retries. sdcard_take_out_if_dead() decides under the
         * lock with a test write. The card stays out if it fails again with no
         * successful write in between, or for the third time within 30 min. */
        if (sdcard_is_mounted())
        {
            uint32_t bad_n = 0;
            uint32_t bad_ms = sdcard_write_dead_ms(&bad_n);
            if (bad_ms < SYSMON_SD_DEAD_MS || bad_n < SYSMON_SD_DEAD_MIN)
            {
                sd_dead_wait = 0;
                sd_alive_warned = false;
            }
            else if (sd_dead_wait++ % (int)MS_TO_TICKS_COUNT(SYSMON_SD_RETRY_MS) == 0)
            {
                bool gave_up = false;
                int probe_err = 0;
                esp_err_t e = sdcard_take_out_if_dead(SYSMON_SD_DEAD_MS, SYSMON_SD_DEAD_MIN,
                                                      &gave_up, &probe_err);
                if (e == ESP_OK)
                {
                    ESP_LOGE(TAG, "SD: no write landed for %lu s (%lu failed), card taken out",
                             (unsigned long)(bad_ms / 1000), (unsigned long)bad_n);
                    if (gave_up)
                        ESP_LOGE(TAG, "SD: the card keeps failing after remounts, it stays out "
                                      "until a manual mount or restart");
                }
                else if (e == ESP_ERR_NOT_FINISHED || e == ESP_ERR_NO_MEM)
                {
                    if (!sd_alive_warned)
                        ESP_LOGW(TAG, "SD: %lu writes failed, but the card is not proven dead "
                                      "(test write: %s), it stays mounted",
                                 (unsigned long)bad_n, probe_err ? strerror(probe_err) : "landed");
                    sd_alive_warned = true;
                }
                else if (e != ESP_ERR_NOT_FOUND && e != ESP_ERR_TIMEOUT)   /* TIMEOUT: a download */
                {
                    ESP_LOGW(TAG, "SD: taking the card out failed (%s), retrying in %d s",
                             esp_err_to_name(e), SYSMON_SD_RETRY_MS / 1000);
                }
            }
        }

        /* (5) SD auto-remount: retry every SYSMON_SD_RETRY_MS while unmounted
         * (e.g. the card wasn't ready at boot, or was briefly removed). */
        if (!sdcard_is_mounted() && !sdcard_auto_remount_inhibited())
        {
            if (++sd_wait >= (int)MS_TO_TICKS_COUNT(SYSMON_SD_RETRY_MS))
            {
                sd_wait = 0;
                if (sdcard_mount_auto() == ESP_OK)
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

    /* mDNS host labels allow only [a-z0-9-], so sanitise whatever the node id is. */
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

    /* The instance name must be unique per device too. Otherwise Bonjour adds
     * a -2 or -3 suffix in registration order, and that order can change on reboot. */
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
    /* Priority 2, the sniffer's default and below the network tasks. sysmon sleeps
     * 5 s between passes, so it cannot starve them. */
    if (xTaskCreate(sysmon_task, "sysmon", 4096, NULL, 2, NULL) != pdPASS)
        ESP_LOGE(TAG, "failed to create sysmon task");
}
