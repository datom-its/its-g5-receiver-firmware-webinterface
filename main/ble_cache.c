/* Taken from the V2Xtend fork (MIT, Copyright Peter Holzhauser and
 * githubapache2), adapted here: the ring lives in PSRAM and DENMs are
 * recognised with its_peek_message_id() from its_decode.h. */

#include "ble_cache.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "esp_attr.h"
#include "esp_log.h"

#include "its_decode.h"

static const char TAG[] = "BLE_CACHE";

typedef struct {
    bool     used;
    bool     is_denm;
    uint32_t seq;
    uint16_t len;
    uint32_t sec;
    uint32_t usec;
    uint8_t  data[BLE_CACHE_SLOT_MAX];
} cache_slot_t;

/* ~130 KB: as internal BSS this starves the NimBLE start into a boot loop. */
static EXT_RAM_BSS_ATTR cache_slot_t s_slots[BLE_CACHE_CAPACITY];

/* Copied under the lock, emitted without it, so a store() reusing the freed slot
 * cannot overwrite what emit() still reads. Static (2 KB off the task stack);
 * s_draining keeps it to one user at a time. */
static EXT_RAM_BSS_ATTR uint8_t s_stage[BLE_CACHE_SLOT_MAX];

static uint32_t          s_next_seq;
static int               s_count;
static bool              s_draining;
static SemaphoreHandle_t s_mutex;

void ble_cache_init(void)
{
    if (s_mutex) return;
    /* Redundant with the .ext_ram.bss zeroing, but does not depend on it. */
    memset(s_slots, 0, sizeof(s_slots));
    s_next_seq = 0;
    s_count    = 0;
    s_draining = false;
    /* Published last: the handle is what every other function tests before it
     * touches the ring. */
    s_mutex = xSemaphoreCreateMutex();
    if (s_mutex == NULL)
        ESP_LOGE(TAG, "mutex alloc failed -- cache stays disabled");
}

/* find_*(): caller holds s_mutex. */
static int find_free_slot(void)
{
    for (int i = 0; i < BLE_CACHE_CAPACITY; i++) {
        if (!s_slots[i].used) return i;
    }
    return -1;
}

/* Index of the oldest (lowest seq) used slot matching want_denm, or -1. */
static int find_oldest(bool want_denm)
{
    int best = -1;
    for (int i = 0; i < BLE_CACHE_CAPACITY; i++) {
        if (!s_slots[i].used || s_slots[i].is_denm != want_denm) continue;
        if (best < 0 || s_slots[i].seq < s_slots[best].seq) best = i;
    }
    return best;
}

void ble_cache_store(const uint8_t *payload, uint16_t len, uint32_t sec, uint32_t usec)
{
    if (payload == NULL || len == 0 || len > BLE_CACHE_SLOT_MAX) return;
    /* No lazy init here -- two tasks racing to create the mutex is exactly the
     * bug it exists to prevent. Warned once, not per frame. */
    if (s_mutex == NULL) {
        static bool warned;
        if (!warned) {
            warned = true;
            ESP_LOGW(TAG, "store before ble_cache_init() -- nothing is cached");
        }
        return;
    }

    /* Classified outside the lock -- its_peek_message_id() decodes the frame
     * header, which has no business inside the critical section. */
    bool is_denm = (its_peek_message_id(payload, len) == 1 /* DENM */);

    xSemaphoreTake(s_mutex, portMAX_DELAY);

    int slot = find_free_slot();
    if (slot < 0) {
        /* Evict the oldest non-DENM so hazards outlive routine traffic; only an
         * all-DENM ring gives up its oldest DENM instead of refusing the frame. */
        slot = find_oldest(false);
        if (slot < 0) slot = find_oldest(true);
        if (slot < 0) {
            /* Unreachable (s_count would be 0), kept as a guard. */
            xSemaphoreGive(s_mutex);
            return;
        }
        s_count--;
    }

    cache_slot_t *s = &s_slots[slot];
    s->used    = true;
    s->is_denm = is_denm;
    s->seq     = s_next_seq++;
    s->len     = len;
    s->sec     = sec;
    s->usec    = usec;
    memcpy(s->data, payload, len);
    s_count++;

    xSemaphoreGive(s_mutex);
}

int ble_cache_count(void)
{
    return s_count;
}

void ble_cache_drain(ble_cache_emit_fn emit, void *ctx)
{
    if (emit == NULL || s_mutex == NULL) return;

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    /* One run at a time: bt_stream starts a drain on every subscribe, and two in
     * parallel would interleave the DENM-first order and fight over s_stage. */
    if (s_draining) {
        xSemaphoreGive(s_mutex);
        return;
    }
    s_draining = true;
    int n = s_count;
    xSemaphoreGive(s_mutex);

    if (n > 0) {
        ESP_LOGI(TAG, "draining %d cached frame(s)", n);

        /* Two passes, DENMs first, each capped at the ring size so frames stored
         * during the drain fall to the next run instead of stretching this one. */
        for (int pass = 0; pass < 2; pass++) {
            bool want_denm = (pass == 0);
            for (int i = 0; i < BLE_CACHE_CAPACITY; i++) {
                uint16_t len = 0;
                uint32_t sec = 0, usec = 0;

                xSemaphoreTake(s_mutex, portMAX_DELAY);
                int idx = find_oldest(want_denm);
                if (idx >= 0) {
                    cache_slot_t *s = &s_slots[idx];
                    len  = s->len;
                    sec  = s->sec;
                    usec = s->usec;
                    memcpy(s_stage, s->data, len);
                    s->used = false;
                    s_count--;
                }
                xSemaphoreGive(s_mutex);

                if (idx < 0) break;
                /* Unlocked: emit() blocks on the BLE queue and must not hold
                 * ble_cache_store() off the ring meanwhile. */
                emit(s_stage, len, sec, usec, ctx);
            }
        }
    }

    xSemaphoreTake(s_mutex, portMAX_DELAY);
    s_draining = false;
    xSemaphoreGive(s_mutex);
}
