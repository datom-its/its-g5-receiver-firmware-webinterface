/* BLE live stream of received ITS-G5 frames (NimBLE peripheral).
 *
 * Ported from the V2Xtend fork (main/bt_stream.c), MIT licence,
 * Copyright (c) Peter Holzhauser and githubapache2. V2Xtend is a sibling fork
 * of the same upstream; see NOTICE for this tree's provenance.
 */

#include "bt_stream.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_coexist.h"

#include "ble_cache.h"
#include "cmd_sniffer.h"
#include "config.h"
#include "its_decode.h"

/* Private NimBLE API: forces a public address — old Android stacks ignore adv
 * from random-static addresses they have not paired with. */
extern int ble_hs_id_set_pub(const uint8_t *pub_addr);

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_uuid.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_hs_mbuf.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

static const char TAG[] = "BT_STREAM";

#define DEVICE_NAME            "ITS-G5-RX"
#define HEADER_LEN             14
#define MAX_PAYLOAD            2048
/* Live notify jitter buffer — drop-newest when full (keep stream realtime). */
#define FRAME_QUEUE_DEPTH      16
/* Drain backlog: ≥ ble_cache capacity, so a full dump never contends with live. */
#define DRAIN_QUEUE_DEPTH      BLE_CACHE_CAPACITY
/* Pace after each drained frame, or NimBLE runs out of mbufs mid-dump. */
#define DRAIN_FRAME_PACE_MS    30
/* Small gap between MTU chunks of a drain frame (MAPEM ≈ 2–3 chunks). */
#define DRAIN_CHUNK_PACE_MS    15
/* Multi-chunk frames need gaps this large or a chunk is lost, and the reader
 * then swallows the following frame while it waits for the rest. */
#define LIVE_CHUNK_PACE_MS     40
#define LIVE_FRAME_PACE_MS     50
#define LIVE_LARGE_FRAME_EXTRA_MS 100
#define LIVE_LARGE_FRAME_BYTES 500
/* Dedicated live DENM queue — never blocks publisher; writer prefers these
 * after drain backlog, before ordinary live CAM/SPAT/MAPEM. */
#define LIVE_DENM_QUEUE_DEPTH  8
/* Retry notify/mbuf when stack returns BLE_HS_ENOMEM (rc=6). */
#define NOTIFY_ENOMEM_RETRIES  12
#define NOTIFY_ENOMEM_BACKOFF_MS 25

/* Hard bound on the post-connect settle window: without one, a client that
 * connects but never subscribes keeps the sniffer paused indefinitely. */
#define SUBSCRIBE_GRACE_MS     6000
/* The parameter update must be deferred, never sent from the connect event:
 * there it collides with the central's own startup procedures and is refused. */
#define UPD_FIRST_DELAY_MS     1200   /* let the central finish its own LL work */
#define UPD_RETRY_MS            900
#define UPD_MAX_TRIES             4
/* Below this the link cannot survive a sniff window; units of 10 ms. */
#define SUPV_MIN_10MS           300   /* 3.0 s */
/* The settle budget refills this much slower than it drains, so a peer that
 * reconnects in a loop cannot starve the sniffer. */
#define GRACE_REFILL_DIV          5

/* Drops arrive at capture rate and every ESP_LOGW also lands in the SD system
 * log, so they are summarised at this interval instead of logged one by one. */
#define DROP_LOG_INTERVAL_MS   5000

/* Vendor UUIDs b6e57e90-12d8-4a47-9b21-3f00000000NN (01 service, 02 notify,
 * 03 config = 8 B / 4×u16 LE, 04 MAC); bytes below are reversed, NimBLE is LE. */
static const ble_uuid128_t SVC_UUID = BLE_UUID128_INIT(
    0x01, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x21, 0x9b,
    0x47, 0x4a, 0xd8, 0x12, 0x90, 0x7e, 0xe5, 0xb6);

static const ble_uuid128_t CHR_UUID = BLE_UUID128_INIT(
    0x02, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x21, 0x9b,
    0x47, 0x4a, 0xd8, 0x12, 0x90, 0x7e, 0xe5, 0xb6);

static const ble_uuid128_t CFG_UUID = BLE_UUID128_INIT(
    0x03, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x21, 0x9b,
    0x47, 0x4a, 0xd8, 0x12, 0x90, 0x7e, 0xe5, 0xb6);

/* Factory BT MAC, big-endian as printed on the label: iOS hides BLE addresses
 * from apps, so device identity has to travel over a characteristic. */
static const ble_uuid128_t MAC_UUID = BLE_UUID128_INIT(
    0x04, 0x00, 0x00, 0x00, 0x00, 0x3f, 0x21, 0x9b,
    0x47, 0x4a, 0xd8, 0x12, 0x90, 0x7e, 0xe5, 0xb6);

typedef struct {
    uint16_t total_len;        /* HEADER_LEN + payload_len */
    uint8_t  data[];           /* preformatted ITS5 frame */
} qframe_t;

static uint8_t          s_addr_type;
/* volatile: written from the NimBLE host task, read by the coex and writer
 * tasks without a lock. */
static volatile uint16_t s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
/* Bumped on every accepted connect so coex_window_task can tell a fresh link
 * from the one whose settle window it has already spent. */
static volatile uint32_t s_conn_gen;
/* 0 = nothing pending, else the tick at which the next update request is due. */
static volatile TickType_t s_upd_due;
static volatile uint8_t    s_upd_tries;
/* Supervision timeout of the live link, 10 ms units; 0 = unknown. */
static volatile uint16_t   s_supv_10ms;
static uint16_t         s_chr_val_handle;
static uint16_t         s_cfg_val_handle;
static volatile bool    s_notify_enabled;
/* One drain task at a time: without this a client toggling the CCCD spawns a
 * 4 kB-stack task per toggle out of the internal heap. */
static volatile bool    s_drain_active;
static bool             s_ready;
static QueueHandle_t    s_live_queue;      /* realtime CAM/SPAT/MAPEM/… */
static QueueHandle_t    s_live_denm_queue; /* realtime DENM — preferred over live */
static QueueHandle_t    s_drain_queue;     /* cache reconnect backlog — writer prefers first */

/* Coex windows in ms, runtime-tunable via the config characteristic; volatile
 * because the GATT callback writes what coex_window_task reads. */
static volatile uint16_t s_cycle_ms[4] = { 3000, 1000, 500, 400 };
#define CYC_DISC_SNIFF  s_cycle_ms[0]
#define CYC_DISC_BLE    s_cycle_ms[1]
#define CYC_CONN_SNIFF  s_cycle_ms[2]
#define CYC_CONN_BLE    s_cycle_ms[3]


/* Driven from chunked_delay() so it can never fire mid radio transition.
 * Repeating is safe: a request, not an accumulating operation, and bounded. */
static void maybe_request_update(void)
{
    TickType_t due = s_upd_due;
    if (due == 0) return;
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE) { s_upd_due = 0; return; }
    if ((TickType_t)(xTaskGetTickCount() - due) > (TickType_t)(portMAX_DELAY / 2)) return;

    s_upd_due = 0;                 /* clear first: the reply arms the next try */
    s_upd_tries++;
    struct ble_gap_upd_params up = {
        .itvl_min            = 0x18,   /* 30 ms */
        .itvl_max            = 0x28,   /* 50 ms */
        .latency             = 0,
        .supervision_timeout = 500,    /* 5.0 s, inside Apple's 2..6 s range */
        .min_ce_len          = 0,
        .max_ce_len          = 0,
    };
    int rc = ble_gap_update_params(s_conn_handle, &up);
    if (rc != 0) {
        ESP_LOGW(TAG, "update_params try %u: rc=%d", (unsigned)s_upd_tries, rc);
        if (s_upd_tries < UPD_MAX_TRIES) {
            s_upd_due = xTaskGetTickCount() + pdMS_TO_TICKS(UPD_RETRY_MS);
            if (s_upd_due == 0) s_upd_due = 1;
        }
    }
}

static int gap_event_cb(struct ble_gap_event *ev, void *arg);
static void cache_drain_task(void *arg);

typedef struct {
    uint32_t count;      /* frames lost on this path since boot */
    uint32_t last_tick;  /* tick of the last summary line, 0 = never */
} drop_stat_t;

/* Each drop_stat_t belongs to exactly one task (writer / publisher), so the
 * counter needs no lock. */
static void note_drop(drop_stat_t *st, const char *what, unsigned len)
{
    st->count++;
    uint32_t now = xTaskGetTickCount();
    if (st->last_tick != 0 && (now - st->last_tick) < pdMS_TO_TICKS(DROP_LOG_INTERVAL_MS))
        return;
    st->last_tick = now;
    ESP_LOGW(TAG, "%s dropped (len=%u), %u lost on this path since boot",
             what, len, (unsigned)st->count);
}

static drop_stat_t s_drop_notify;   /* writer task only */
static drop_stat_t s_drop_enqueue;  /* publisher (sniffer packet path) only */

static int chr_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                         struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle;
    (void)attr_handle;
    (void)arg;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        return BLE_ATT_ERR_READ_NOT_PERMITTED;
    }
    return BLE_ATT_ERR_WRITE_NOT_PERMITTED;
}

static int cfg_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                         struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle;
    (void)attr_handle;
    (void)arg;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        uint8_t buf[8];
        for (int i = 0; i < 4; i++) {
            uint16_t v = s_cycle_ms[i];
            buf[i*2]     = (uint8_t)(v        & 0xff);
            buf[i*2 + 1] = (uint8_t)((v >> 8) & 0xff);
        }
        int rc = os_mbuf_append(ctxt->om, buf, sizeof(buf));
        return (rc == 0) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    if (ctxt->op == BLE_GATT_ACCESS_OP_WRITE_CHR) {
        uint16_t total = OS_MBUF_PKTLEN(ctxt->om);
        if (total != 8) return BLE_ATT_ERR_INVALID_ATTR_VALUE_LEN;
        uint8_t buf[8];
        if (ble_hs_mbuf_to_flat(ctxt->om, buf, sizeof(buf), NULL) != 0) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        /* Scratch array first, publish in one go: a half-applied write would
         * leave the cycle mismatched. */
        uint16_t next[4];
        for (int i = 0; i < 4; i++) {
            uint16_t v = (uint16_t)buf[i*2] | ((uint16_t)buf[i*2 + 1] << 8);
            /* Clamped per ROLE (even = sniff window, odd = BLE): the write is
             * unauthenticated, a blanket range would allow ~0 % capture. */
            if (i & 1) {                 /* BLE window */
                if (v < 100)   v = 100;
                if (v > 2000)  v = 2000;
            } else {                     /* sniff window -- the product */
                if (v < 500)   v = 500;
                if (v > 10000) v = 10000;
            }
            next[i] = v;
        }
        for (int i = 0; i < 4; i++) s_cycle_ms[i] = next[i];
        /* Deliberately NOT persisted: a hostile duty cycle must not survive a
         * power cycle — that is the operator's only recovery, the UI has none. */
        ESP_LOGI(TAG, "cfg write: %u/%u %u/%u",
                 (unsigned)CYC_DISC_SNIFF, (unsigned)CYC_DISC_BLE,
                 (unsigned)CYC_CONN_SNIFF, (unsigned)CYC_CONN_BLE);
        return 0;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

static int mac_access_cb(uint16_t conn_handle, uint16_t attr_handle,
                         struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle; (void)attr_handle; (void)arg;
    if (ctxt->op == BLE_GATT_ACCESS_OP_READ_CHR) {
        uint8_t mac[6] = {0};
        if (esp_read_mac(mac, ESP_MAC_BT) != ESP_OK) {
            return BLE_ATT_ERR_UNLIKELY;
        }
        int rc = os_mbuf_append(ctxt->om, mac, sizeof(mac));
        return (rc == 0) ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
    }
    return BLE_ATT_ERR_UNLIKELY;
}

static uint16_t s_mac_val_handle;

static const struct ble_gatt_chr_def chr_defs[] = {
    {
        .uuid       = &CHR_UUID.u,
        .access_cb  = chr_access_cb,
        .flags      = BLE_GATT_CHR_F_NOTIFY,
        .val_handle = &s_chr_val_handle,
    },
    {
        .uuid       = &CFG_UUID.u,
        .access_cb  = cfg_access_cb,
        .flags      = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_WRITE,
        .val_handle = &s_cfg_val_handle,
    },
    {
        .uuid       = &MAC_UUID.u,
        .access_cb  = mac_access_cb,
        .flags      = BLE_GATT_CHR_F_READ,
        .val_handle = &s_mac_val_handle,
    },
    { 0 },
};

static const struct ble_gatt_svc_def svc_defs[] = {
    {
        .type            = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid            = &SVC_UUID.u,
        .characteristics = chr_defs,
    },
    { 0 },
};

static void start_advertising(void)
{
    struct ble_hs_adv_fields fields = {0};
    fields.flags = BLE_HS_ADV_F_DISC_GEN | BLE_HS_ADV_F_BREDR_UNSUP;
    fields.name = (uint8_t *)DEVICE_NAME;
    fields.name_len = strlen(DEVICE_NAME);
    fields.name_is_complete = 1;

    int rc = ble_gap_adv_set_fields(&fields);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_set_fields rc=%d", rc);
        return;
    }

    /* Put the 128-bit service UUID in the scan response so the adv packet
     * stays under the 31-byte legacy limit. */
    struct ble_hs_adv_fields scan_rsp = {0};
    scan_rsp.uuids128 = (ble_uuid128_t *)&SVC_UUID;
    scan_rsp.num_uuids128 = 1;
    scan_rsp.uuids128_is_complete = 1;
    rc = ble_gap_adv_rsp_set_fields(&scan_rsp);
    if (rc != 0) {
        ESP_LOGW(TAG, "adv_rsp_set_fields rc=%d", rc);
    }

    struct ble_gap_adv_params p = {0};
    p.conn_mode = BLE_GAP_CONN_MODE_UND;
    p.disc_mode = BLE_GAP_DISC_MODE_GEN;
    /* 30 ms / 50 ms in 0.625 ms units — fast enough that Samsung-S6 BLE
     * scan windows reliably catch us. Defaults are slower. */
    p.itvl_min = 0x30;
    p.itvl_max = 0x50;
    rc = ble_gap_adv_start(s_addr_type, NULL, BLE_HS_FOREVER, &p, gap_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "adv_start rc=%d", rc);
    } else {
        ESP_LOGI(TAG, "advertising as %s", DEVICE_NAME);
    }
}

static int gap_event_cb(struct ble_gap_event *ev, void *arg)
{
    (void)arg;
    switch (ev->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (ev->connect.status == 0) {
            /* Order is load-bearing: notify flag and generation BEFORE the
             * handle — the handle is what the coex task reads as "connected". */
            s_notify_enabled = false;
            s_conn_gen++;
            s_conn_handle = ev->connect.conn_handle;
            /* The host-chosen parameters surface nowhere else (iOS hides them);
             * integer math on the 1.25 ms / 10 ms units keeps float printf out. */
            struct ble_gap_conn_desc desc;
            bool desc_ok = (ble_gap_conn_find(s_conn_handle, &desc) == 0);
            if (desc_ok) {
                ESP_LOGI(TAG, "connect: handle=%u itvl=%u (%u.%02u ms) lat=%u timeout=%u (%u.%02u s)",
                         (unsigned)s_conn_handle,
                         (unsigned)desc.conn_itvl,
                         (unsigned)(desc.conn_itvl * 125u / 100u),
                         (unsigned)(desc.conn_itvl * 125u % 100u),
                         (unsigned)desc.conn_latency,
                         (unsigned)desc.supervision_timeout,
                         (unsigned)(desc.supervision_timeout / 100u),
                         (unsigned)(desc.supervision_timeout % 100u));
            } else {
                ESP_LOGI(TAG, "connect: handle=%u (conn_find failed)", (unsigned)s_conn_handle);
            }
            /* The update request is NOT sent here (see maybe_request_update);
             * this only records what the central chose, for link_fragile. */
            s_supv_10ms = desc_ok ? desc.supervision_timeout : 0;
            s_upd_tries = 0;
            s_upd_due   = xTaskGetTickCount() + pdMS_TO_TICKS(UPD_FIRST_DELAY_MS);
            if (s_upd_due == 0) s_upd_due = 1;   /* 0 is the "nothing due" mark */
        } else {
            ESP_LOGW(TAG, "connect failed status=%d", ev->connect.status);
            start_advertising();
        }
        break;
    case BLE_GAP_EVENT_CONN_UPDATE: {
        /* status==0 → accepted; non-zero → rejected, and the link then keeps
         * the central's short initial supervision timeout. */
        struct ble_gap_conn_desc desc;
        int frc = ble_gap_conn_find(ev->conn_update.conn_handle, &desc);
        if (frc == 0) {
            s_supv_10ms = desc.supervision_timeout;
            ESP_LOGI(TAG, "conn_update status=%d itvl=%u lat=%u timeout=%u (%u.%02u s)",
                     ev->conn_update.status,
                     (unsigned)desc.conn_itvl,
                     (unsigned)desc.conn_latency,
                     (unsigned)desc.supervision_timeout,
                     (unsigned)(desc.supervision_timeout / 100u),
                     (unsigned)(desc.supervision_timeout % 100u));
        } else {
            ESP_LOGW(TAG, "conn_update status=%d (conn_find rc=%d)",
                     ev->conn_update.status, frc);
        }
        /* A refusal is usually just a collision with the central's own
         * procedure — retry, but only while the timeout is still too short. */
        if (ev->conn_update.status != 0 && s_supv_10ms < SUPV_MIN_10MS &&
            s_upd_tries < UPD_MAX_TRIES) {
            s_upd_due = xTaskGetTickCount() + pdMS_TO_TICKS(UPD_RETRY_MS);
            if (s_upd_due == 0) s_upd_due = 1;
        }
        break;
    }
    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "disconnect: reason=0x%x", ev->disconnect.reason);
        s_conn_handle = BLE_HS_CONN_HANDLE_NONE;
        s_notify_enabled = false;
        s_upd_due = 0;
        s_supv_10ms = 0;
        start_advertising();
        break;
    case BLE_GAP_EVENT_SUBSCRIBE:
        if (ev->subscribe.attr_handle == s_chr_val_handle) {
            bool was_enabled = s_notify_enabled;
            s_notify_enabled = ev->subscribe.cur_notify;
            ESP_LOGI(TAG, "notify subscription=%d", s_notify_enabled);
            if (s_notify_enabled && !was_enabled && !s_drain_active) {
                /* Flush the disconnect cache, in its own task: this callback
                 * runs on the NimBLE host task and must not block on sends. */
                s_drain_active = true;
                if (xTaskCreate(cache_drain_task, "ble_drain", 4096, NULL, 4, NULL) != pdPASS) {
                    s_drain_active = false;
                    ESP_LOGW(TAG, "cache drain task create failed, backlog stays cached");
                }
            }
        }
        break;
    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "mtu: handle=%d value=%d",
                 ev->mtu.conn_handle, ev->mtu.value);
        break;
    default:
        break;
    }
    return 0;
}

static void on_sync(void)
{
    /* Advertise from the factory BT MAC as a Public address — random-static is
     * silently dropped by older Android stacks. */
    uint8_t mac_be[6] = {0};
    if (esp_read_mac(mac_be, ESP_MAC_BT) == ESP_OK) {
        uint8_t mac_le[6] = {
            mac_be[5], mac_be[4], mac_be[3],
            mac_be[2], mac_be[1], mac_be[0],
        };
        int prc = ble_hs_id_set_pub(mac_le);
        if (prc != 0) {
            ESP_LOGW(TAG, "ble_hs_id_set_pub rc=%d — advertising with the "
                     "controller address, old Android may not see us", prc);
        }
    } else {
        ESP_LOGW(TAG, "esp_read_mac(ESP_MAC_BT) failed");
    }
    s_addr_type = BLE_OWN_ADDR_PUBLIC;

    uint8_t addr[6] = {0};
    ble_hs_id_copy_addr(s_addr_type, addr, NULL);
    ESP_LOGI(TAG, "BLE addr=%02X:%02X:%02X:%02X:%02X:%02X",
             addr[5], addr[4], addr[3], addr[2], addr[1], addr[0]);
    start_advertising();
}

static void on_reset(int reason)
{
    ESP_LOGW(TAG, "stack reset: %d", reason);
}

static void host_task(void *param)
{
    (void)param;
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/* Single RF transceiver: Wi-Fi promisc and BLE adv cannot coexist, so the radio
 * is time-shared. sniffer_pause() stops only the RX path, not the task. */
/* Sleeps in chunks and returns early on a link state change: sitting out a
 * whole window would starve a link that connected or dropped mid-sniff. */
#define COEX_CHUNK_MS 200
/* Connected-mode interleaving (see coex_window_task): max radio-hold per
 * slice and the BLE breathing gap between slices. */
#define CONN_SNIFF_SLICE_MS 350
#define CONN_SNIFF_GAP_MS   60
static void chunked_delay(uint32_t total_ms, bool was_connected)
{
    uint32_t left = total_ms;
    /* Watch the generation too, not just the flag: a disconnect and reconnect
     * inside one chunk leave the flag unchanged. */
    uint32_t gen_at_entry = s_conn_gen;
    while (left > 0) {
        uint32_t step = (left > COEX_CHUNK_MS) ? COEX_CHUNK_MS : left;
        vTaskDelay(pdMS_TO_TICKS(step));
        left -= step;
        maybe_request_update();
        bool now = (s_conn_handle != BLE_HS_CONN_HANDLE_NONE);
        if (now != was_connected || s_conn_gen != gen_at_entry) return;
    }
}

static void coex_window_task(void *arg)
{
    (void)arg;
    /* Boot-time: give BLE the radio first so a user has a chance to
     * connect before the sniffer takes over. */
    sniffer_pause();
    chunked_delay(CYC_DISC_BLE, false);
    uint32_t grace_gen = s_conn_gen;
    /* Settle budget in ms, per DEVICE and not per link: NEVER reset it on
     * reconnect, or a reconnect loop holds the sniffer paused forever. */
    int32_t grace_ms = SUBSCRIBE_GRACE_MS;
    bool grace_expired_logged = false;
    int n = 0;
    for (;;) {
        bool connected = (s_conn_handle != BLE_HS_CONN_HANDLE_NONE);
        if (s_conn_gen != grace_gen) {
            grace_gen = s_conn_gen;
            grace_expired_logged = false;   /* NOT grace_ms: see above */
        }
        /* Hold the radio on BLE until the link has settled. 0 must count as
         * fragile: it means "not read yet", i.e. when we know least. */
        bool link_fragile = (s_supv_10ms < SUPV_MIN_10MS);
        if (connected && (!s_notify_enabled || link_fragile) && grace_ms > 0) {
            TickType_t t0 = xTaskGetTickCount();
            chunked_delay(CYC_CONN_BLE, connected);
            grace_ms -= (int32_t)((xTaskGetTickCount() - t0) * portTICK_PERIOD_MS);
            continue;
        }
        if (connected && (!s_notify_enabled || link_fragile) && !grace_expired_logged) {
            grace_expired_logged = true;
            /* Prints the budget LEFT, not the constant: after a reconnect the
             * two differ, and the constant would misreport the field case. */
            ESP_LOGW(TAG, "grace exhausted (%d ms left): subscribed=%d supv=%u (10 ms) "
                     "— resuming capture%s", (int)grace_ms,
                     (int)s_notify_enabled, (unsigned)s_supv_10ms,
                     link_fragile ? " with halved windows" : "");
        }
        uint16_t sniff_ms = connected ? CYC_CONN_SNIFF : CYC_DISC_SNIFF;
        /* A fragile link cannot sit out a full window. Halve the WINDOW, not
         * the slice: a smaller slice only adds a gap and lengthens the window. */
        if (connected && link_fragile) sniff_ms /= 2;
        uint16_t ble_ms   = connected ? CYC_CONN_BLE   : CYC_DISC_BLE;
        /* Measured, never the planned window: every path below can cut it
         * short, and the gaps between slices are not capture either. */
        uint32_t sniffed_ms = 0;
        TickType_t t_sniff = xTaskGetTickCount();
        sniffer_resume();
        if (connected) {
            /* Never hold the radio off BLE longer than a slice or the link dies
             * of supervision timeout; split evenly, no starving last slice. */
            uint32_t nslices = (sniff_ms + CONN_SNIFF_SLICE_MS - 1) / CONN_SNIFF_SLICE_MS;
            if (nslices < 1) nslices = 1;
            uint32_t slice = sniff_ms / nslices;
            for (uint32_t i = 0; i < nslices; i++) {
                chunked_delay(slice, connected);
                sniffed_ms += (uint32_t)((xTaskGetTickCount() - t_sniff) * portTICK_PERIOD_MS);
                if ((s_conn_handle != BLE_HS_CONN_HANDLE_NONE) != connected) break;
                if (i + 1 == nslices) break;
                sniffer_pause();
                vTaskDelay(pdMS_TO_TICKS(CONN_SNIFF_GAP_MS));   /* gap: not capture */
                if ((s_conn_handle != BLE_HS_CONN_HANDLE_NONE) != connected) break;
                t_sniff = xTaskGetTickCount();
                sniffer_resume();
            }
        } else {
            chunked_delay(sniff_ms, connected);
            sniffed_ms = (uint32_t)((xTaskGetTickCount() - t_sniff) * portTICK_PERIOD_MS);
        }
        sniffer_pause();
        grace_ms += (int32_t)(sniffed_ms / GRACE_REFILL_DIV);
        if (grace_ms > SUBSCRIBE_GRACE_MS) grace_ms = SUBSCRIBE_GRACE_MS;
        if ((n++ & 0xF) == 0) {
            /* Debug level on purpose: at INFO this would write a line to the
             * SD system log about once a minute, forever. */
            ESP_LOGD(TAG, "cycle %s: sniff=%u ble=%u",
                     connected ? "CONN" : "DISC",
                     (unsigned)sniff_ms, (unsigned)ble_ms);
        }
        chunked_delay(ble_ms, connected);
    }
}

static void writer_send_frame(qframe_t *qf, bool from_drain)
{
    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE || !s_notify_enabled) {
        free(qf);
        return;
    }

    uint16_t mtu = ble_att_mtu(s_conn_handle);
    uint16_t chunk = (mtu > 3) ? (uint16_t)(mtu - 3) : 20;
    uint16_t sent = 0;
    bool aborted = false;

    while (sent < qf->total_len && !aborted) {
        uint16_t n = qf->total_len - sent;
        if (n > chunk) n = chunk;

        bool chunk_ok = false;
        for (int attempt = 0; attempt <= NOTIFY_ENOMEM_RETRIES; attempt++) {
            struct os_mbuf *om = ble_hs_mbuf_from_flat(qf->data + sent, n);
            if (om == NULL) {
                if (attempt < NOTIFY_ENOMEM_RETRIES) {
                    vTaskDelay(pdMS_TO_TICKS(
                        NOTIFY_ENOMEM_BACKOFF_MS * (1 + attempt / 2)));
                    continue;
                }
                aborted = true;
                break;
            }

            int rc = ble_gatts_notify_custom(s_conn_handle, s_chr_val_handle, om);
            if (rc == 0) {
                chunk_ok = true;
                break;
            }

            /* Do NOT free the mbuf on failure — ownership is unclear across
             * NimBLE versions; retry is safe, `sent` advances only on success. */
            if (rc == BLE_HS_ENOMEM && attempt < NOTIFY_ENOMEM_RETRIES) {
                ESP_LOGD(TAG, "notify rc=%d (ENOMEM), retry %d/%d",
                         rc, attempt + 1, NOTIFY_ENOMEM_RETRIES);
                vTaskDelay(pdMS_TO_TICKS(
                    NOTIFY_ENOMEM_BACKOFF_MS * (1 + attempt / 2)));
                continue;
            }

            ESP_LOGD(TAG, "notify rc=%d, giving up on this frame", rc);
            aborted = true;
            break;
        }

        if (!chunk_ok) break;

        sent += n;
        if (sent < qf->total_len) {
            uint32_t pace = from_drain ? DRAIN_CHUNK_PACE_MS : LIVE_CHUNK_PACE_MS;
            if (pace) vTaskDelay(pdMS_TO_TICKS(pace));
        }
    }

    uint16_t wire_len = qf->total_len;
    free(qf);
    if (!aborted) {
        ESP_LOGD(TAG, "%s frame sent (len=%u)",
                 from_drain ? "drain" : "live", (unsigned)wire_len);
        uint32_t pace = from_drain ? DRAIN_FRAME_PACE_MS : LIVE_FRAME_PACE_MS;
        if (!from_drain && wire_len > LIVE_LARGE_FRAME_BYTES) {
            pace += LIVE_LARGE_FRAME_EXTRA_MS;
        }
        if (pace) vTaskDelay(pdMS_TO_TICKS(pace));
    } else {
        /* Aborted mid-frame: the phone's FrameReader resyncs on the next ITS5
         * magic, so only this frame is lost. */
        note_drop(&s_drop_notify, from_drain ? "BLE notify (drain)" : "BLE notify (live)",
                  wire_len);
    }
}

static void writer_task(void *arg)
{
    (void)arg;
    qframe_t *qf = NULL;
    for (;;) {
        /* Priority: cache-drain → live DENM → other live.
         * DENM never blocks the publisher (no HoL wait on enqueue). */
        if (xQueueReceive(s_drain_queue, &qf, 0) == pdTRUE) {
            writer_send_frame(qf, true);
            continue;
        }
        if (xQueueReceive(s_live_denm_queue, &qf, 0) == pdTRUE) {
            writer_send_frame(qf, false);
            continue;
        }
        if (xQueueReceive(s_live_queue, &qf, pdMS_TO_TICKS(20)) == pdTRUE) {
            writer_send_frame(qf, false);
        }
    }
}

void bt_stream_init(void)
{
    if (s_ready) return;

    /* Must stay first, before NimBLE and any task: with BT off the coex task
     * would duty-cycle the sniffer for an unused radio. Unreadable = off. */
    uint8_t bt_enable = 0;
    esp_err_t cerr = config_get_u8(CONFIG_INDEX_BT_ENABLE, &bt_enable);
    if (cerr != ESP_OK) {
        ESP_LOGW(TAG, "BT enable flag unreadable (%s) — Bluetooth stays off",
                 esp_err_to_name(cerr));
        return;
    }
    if (!bt_enable) {
        ESP_LOGI(TAG, "Bluetooth disabled in the configuration — NimBLE not started");
        return;
    }

    ESP_LOGI(TAG, "coex cycle: disc %u/%u ms, conn %u/%u ms",
             (unsigned)CYC_DISC_SNIFF, (unsigned)CYC_DISC_BLE,
             (unsigned)CYC_CONN_SNIFF, (unsigned)CYC_CONN_BLE);

    ble_cache_init();

    /* PREFER_BT lets BLE pre-empt promiscuous Wi-Fi long enough for a whole adv
     * packet. After the enable check on purpose: sniffer-only keeps the default. */
    esp_err_t coex_err = esp_coex_preference_set(ESP_COEX_PREFER_BT);
    if (coex_err != ESP_OK) {
        ESP_LOGW(TAG, "coex_preference_set(PREFER_BT): %s", esp_err_to_name(coex_err));
    }

    esp_err_t err = nimble_port_init();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "nimble_port_init: %s", esp_err_to_name(err));
        return;
    }

    ble_hs_cfg.sync_cb  = on_sync;
    ble_hs_cfg.reset_cb = on_reset;

    int rc = ble_svc_gap_device_name_set(DEVICE_NAME);
    if (rc != 0) ESP_LOGW(TAG, "name_set rc=%d", rc);

    ble_svc_gap_init();
    ble_svc_gatt_init();

    rc = ble_gatts_count_cfg(svc_defs);
    if (rc != 0) {
        ESP_LOGE(TAG, "count_cfg rc=%d", rc);
        return;
    }
    rc = ble_gatts_add_svcs(svc_defs);
    if (rc != 0) {
        ESP_LOGE(TAG, "add_svcs rc=%d", rc);
        return;
    }

    s_live_queue = xQueueCreate(FRAME_QUEUE_DEPTH, sizeof(qframe_t *));
    s_live_denm_queue = xQueueCreate(LIVE_DENM_QUEUE_DEPTH, sizeof(qframe_t *));
    s_drain_queue = xQueueCreate(DRAIN_QUEUE_DEPTH, sizeof(qframe_t *));
    if (s_live_queue == NULL || s_live_denm_queue == NULL || s_drain_queue == NULL) {
        ESP_LOGE(TAG, "queue create failed (live=%p denm=%p drain=%p)",
                 (void *)s_live_queue, (void *)s_live_denm_queue, (void *)s_drain_queue);
        return;
    }
    BaseType_t xrc = xTaskCreate(writer_task, "bt_writer", 4096, NULL, 5, NULL);
    if (xrc != pdPASS) {
        ESP_LOGE(TAG, "writer task create failed");
        return;
    }
    /* Only now, with everything it steers actually in place: this task pauses
     * the sniffer, so it must never exist on a device that has no BLE. */
    if (xTaskCreate(coex_window_task, "bt_coex", 3072, NULL, 4, NULL) != pdPASS) {
        ESP_LOGE(TAG, "coex task create failed");
        return;
    }

    nimble_port_freertos_init(host_task);
    s_ready = true;
    ESP_LOGI(TAG, "initialized, awaiting on_sync");
}

/* Shared by the live publish path and the disconnect-cache drain path —
 * both need the exact same preformatted ITS5 frame. */
static qframe_t *build_qframe(const uint8_t *payload, uint16_t len, uint32_t sec, uint32_t usec)
{
    size_t total = HEADER_LEN + len;
    /* PSRAM, not malloc(): SPIRAM_MALLOC_ALWAYSINTERNAL would put a frame this
     * size in internal RAM, where all three queues compete with NimBLE. */
    qframe_t *qf = heap_caps_malloc(sizeof(qframe_t) + total, MALLOC_CAP_SPIRAM);
    if (qf == NULL) {
        /* Once only: PSRAM exhaustion is sticky and this is the packet path —
         * a per-frame log would stall the capture on UART and SD. */
        static bool oom_told;
        if (!oom_told) {
            oom_told = true;
            ESP_LOGE(TAG, "PSRAM exhausted, BLE frames are being dropped");
        }
        return NULL;
    }
    qf->total_len = (uint16_t)total;

    uint8_t *p = qf->data;
    p[0]  = 'I';  p[1]  = 'T';  p[2]  = 'S';  p[3]  = '5';
    p[4]  = (uint8_t)(sec        & 0xff);
    p[5]  = (uint8_t)((sec >>  8) & 0xff);
    p[6]  = (uint8_t)((sec >> 16) & 0xff);
    p[7]  = (uint8_t)((sec >> 24) & 0xff);
    p[8]  = (uint8_t)(usec        & 0xff);
    p[9]  = (uint8_t)((usec >>  8) & 0xff);
    p[10] = (uint8_t)((usec >> 16) & 0xff);
    p[11] = (uint8_t)((usec >> 24) & 0xff);
    p[12] = (uint8_t)(len        & 0xff);
    p[13] = (uint8_t)((len >>  8) & 0xff);
    if (len > 0) memcpy(p + HEADER_LEN, payload, len);
    return qf;
}

void bt_stream_publish_packet(const uint8_t *payload, uint16_t len, uint32_t sec, uint32_t usec)
{
    if (!s_ready) return;
    if (len > MAX_PAYLOAD) return;

    if (s_conn_handle == BLE_HS_CONN_HANDLE_NONE || !s_notify_enabled) {
        /* No live client to notify — stash the packet in the disconnect cache
         * (DENM-prioritised) instead of dropping it, see ble_cache.h. */
        ble_cache_store(payload, len, sec, usec);
        return;
    }

    /* messageId 1 = DENM. Full decode — keep it at this one call per frame. */
    bool denm = (its_peek_message_id(payload, len) == 1);

    qframe_t *qf = build_qframe(payload, len, sec, usec);
    if (qf == NULL) return;

    /* Non-blocking: DENMs go on their own queue so a full CAM live queue
     * never drops hazards, and we never stall the sniffer/replay task. */
    if (denm) {
        if (xQueueSend(s_live_denm_queue, &qf, 0) != pdTRUE) {
            note_drop(&s_drop_enqueue, "live DENM queue full", len);
            free(qf);
        }
        return;
    }
    if (xQueueSend(s_live_queue, &qf, 0) != pdTRUE) {
        note_drop(&s_drop_enqueue, "live queue full, newest", len);
        free(qf);
    }
}

static void cache_drain_emit(const uint8_t *payload, uint16_t len,
                              uint32_t sec, uint32_t usec, void *ctx)
{
    (void)ctx;
    qframe_t *qf = build_qframe(payload, len, sec, usec);
    if (qf == NULL) return;
    /* Dedicated drain queue (writer prefers it over live). Block rather than
     * drop — this is reconnect backlog, not realtime jitter. */
    if (xQueueSend(s_drain_queue, &qf, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGW(TAG, "cache drain: drain queue still full after 5s, dropping cached frame");
        free(qf);
    }
}

static void cache_drain_task(void *arg)
{
    (void)arg;
    ble_cache_drain(cache_drain_emit, NULL);
    s_drain_active = false;
    vTaskDelete(NULL);
}
