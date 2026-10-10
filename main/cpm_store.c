#include "cpm_store.h"

#include <inttypes.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"

static const char TAG[] = "CPMSTORE";

_Static_assert(sizeof(cpm_store_obj_t) == 72, "update the size comments in cpm_store.h");
_Static_assert(sizeof(cpm_store_area_t) == 136, "update the size comments in cpm_store.h");
_Static_assert(sizeof(cpm_store_sender_t) == 6848, "update the size comments here and in cpm_store.h");
_Static_assert(sizeof(cpm_store_msg_t) == 32, "update the size comment in cpm_store.h");

/* 8 x 6848 = 54784 B and the 1978-B shape scratch in PSRAM (riscv32-esp-elf-gcc 15.2).
 * Only the sniffer task uses the scratch, so no area takes room on its 4 KB stack. */
static EXT_RAM_BSS_ATTR cpm_store_sender_t s_store[CPM_STORE_SENDERS];
static EXT_RAM_BSS_ATTR its_cpm_areas_t s_areas;

static SemaphoreHandle_t s_lock;
static bool s_dropped;               /* under the lock */
static int64_t s_dropped_ms;
static uint32_t s_busy;              /* messages skipped at a busy lock; sniffer task only */
static bool s_busy_logged;
static int64_t s_busy_log_ms;

/* The sniffer waits one tick (up to 10 ms at 100 Hz), the page 100 ms: each side holds the lock
 * only for a merge or one copy. pdMS_TO_TICKS(5) is 0 at 100 Hz, a take that would never wait. */
#define WAIT_TICKS(ms) (pdMS_TO_TICKS(ms) > 0 ? pdMS_TO_TICKS(ms) : (TickType_t)1)
#define NOTE_WAIT_MS  5
#define COPY_WAIT_MS  100
#define BUSY_LOG_MS   60000

#define CONT_BIT(id)  (1u << ((id) - 1))

void cpm_store_init(void)
{
    memset(s_store, 0, sizeof s_store);
    s_dropped = false;
    s_busy = 0;
    s_busy_logged = false;
    if (!s_lock)
        s_lock = xSemaphoreCreateMutex();
}

int64_t cpm_store_now_ms(void)
{
    return esp_timer_get_time() / 1000;
}

/* One rule for objects, areas, x bits, the sender slot and the eviction note: 2999 ms stays,
 * 3000 goes. */
static bool stale(int64_t seen_ms, int64_t now_ms)
{
    return now_ms - seen_ms >= CPM_STORE_STALE_MS;
}

/* Expired entries leave, the rest keeps its order (regions are drawn in list order). */
static uint8_t keep_fresh_objs(cpm_store_obj_t *v, uint8_t n, int64_t now_ms)
{
    uint8_t k = 0;
    for (uint8_t i = 0; i < n; i++)
    {
        if (stale(v[i].seen_ms, now_ms))
            continue;
        if (k != i)
            v[k] = v[i];
        k++;
    }
    return k;
}

static uint8_t keep_fresh_areas(cpm_store_area_t *v, uint8_t n, int64_t now_ms)
{
    uint8_t k = 0;
    for (uint8_t i = 0; i < n; i++)
    {
        if (stale(v[i].seen_ms, now_ms))
            continue;
        if (k != i)
            v[k] = v[i];
        k++;
    }
    return k;
}

/* Under the lock. A slot whose sender went quiet is freed: no entry is newer than its last CPM.
 * An x bit goes by the same rule, 3 s after the last message that set it. */
static void sweep(cpm_store_sender_t *s, int64_t now_ms)
{
    if (!s->used)
        return;
    if (stale(s->last_ms, now_ms))
    {
        s->used = false;
        return;
    }
    if ((s->x & CPM_STORE_X_OBJ) && stale(s->x_ms[0], now_ms))
        s->x &= (uint8_t)~CPM_STORE_X_OBJ;
    if ((s->x & CPM_STORE_X_AREA) && stale(s->x_ms[1], now_ms))
        s->x &= (uint8_t)~CPM_STORE_X_AREA;
    s->n_obj = keep_fresh_objs(s->obj, s->n_obj, now_ms);
    s->n_sens = keep_fresh_areas(s->sens, s->n_sens, now_ms);
    s->n_reg = keep_fresh_areas(s->reg, s->n_reg, now_ms);
}

/* Sets CPM_STORE_X_OBJ (time in x_ms[0]) or CPM_STORE_X_AREA (x_ms[1]); sweep() clears it. */
static void mark_x(cpm_store_sender_t *s, uint8_t bit, int64_t now_ms)
{
    s->x |= bit;
    s->x_ms[bit == CPM_STORE_X_AREA] = now_ms;
}

/* The entry heard longest ago, the first of equals: the one a full table gives up. */
static uint8_t stalest_obj(const cpm_store_obj_t *v, uint8_t n)
{
    uint8_t k = 0;
    for (uint8_t i = 1; i < n; i++)
        if (v[i].seen_ms < v[k].seen_ms)
            k = i;
    return k;
}

static uint8_t stalest_area(const cpm_store_area_t *v, uint8_t n)
{
    uint8_t k = 0;
    for (uint8_t i = 1; i < n; i++)
        if (v[i].seen_ms < v[k].seen_ms)
            k = i;
    return k;
}

/* Under the lock, after the sweep. A new station takes a free slot, else the one whose last
 * CPM is oldest, and /cpm.json then says for 3 s that a sender is missing. */
static cpm_store_sender_t *sender_for(uint32_t station_id, int64_t now_ms)
{
    cpm_store_sender_t *free_slot = NULL, *oldest = NULL;
    for (unsigned i = 0; i < CPM_STORE_SENDERS; i++)
    {
        cpm_store_sender_t *s = &s_store[i];
        if (!s->used)
        {
            if (!free_slot)
                free_slot = s;
            continue;
        }
        if (s->station_id == station_id)
            return s;
        if (!oldest || s->last_ms < oldest->last_ms)
            oldest = s;
    }
    cpm_store_sender_t *s = free_slot;
    if (!s)
    {
        s = oldest;
        s_dropped = true;
        s_dropped_ms = now_ms;
    }
    memset(s, 0, sizeof *s);
    s->used = true;
    s->station_id = station_id;
    return s;
}

/* Keyed by objectId, which TS 103 324 7.1.8.1 makes mandatory: an object without one is not
 * kept and counts as cut (x bit 1). Each object keeps the reference position and time of its
 * own CPM; segments merge by the key. */
static void note_objects(cpm_store_sender_t *s, const cpm_store_msg_t *m, const its_cpm_obj_t *all,
                         uint16_t n, int64_t now_ms)
{
    bool cut = m->n_walked > n;          /* more objects came than all[] holds */
    for (uint16_t i = 0; i < n; i++)
    {
        const its_cpm_obj_t *o = &all[i];
        if (!(o->flags & ITS_CPM_OF_ID))
        {
            cut = true;                  /* not kept, so x bit 1 says some objects are missing */
            continue;
        }
        cpm_store_obj_t *e = NULL;
        for (uint8_t j = 0; j < s->n_obj && !e; j++)
            if (s->obj[j].o.id == o->id)
                e = &s->obj[j];
        if (!e && s->n_obj < CPM_STORE_OBJS)
            e = &s->obj[s->n_obj++];
        else if (!e)
        {
            e = &s->obj[stalest_obj(s->obj, s->n_obj)];
            cut = true;
        }
        e->o = *o;
        e->ref_lat_e7 = m->ref_lat_e7;
        e->ref_lon_e7 = m->ref_lon_e7;
        e->seen_ms = now_ms;
        e->ref_ms = m->ref_ms;
    }
    if (cut)
        mark_x(s, CPM_STORE_X_OBJ, now_ms);
}

static void keep_area(cpm_store_area_t *e, const its_cpm_area_t *a, const cpm_store_msg_t *m,
                      int64_t now_ms)
{
    e->a = *a;
    e->ref_lat_e7 = m->ref_lat_e7;
    e->ref_lon_e7 = m->ref_lon_e7;
    e->seen_ms = now_ms;
}

/* A sensor is the same area again when its sensorId comes again. A new one in a full table
 * replaces the one heard longest ago. */
static void note_sensors(cpm_store_sender_t *s, const cpm_store_msg_t *m,
                         const its_cpm_areas_t *areas, int64_t now_ms)
{
    bool cut = areas->sens_shapes > areas->n_sens;
    for (uint8_t i = 0; i < areas->n_sens; i++)
    {
        const its_cpm_area_t *a = &areas->area[i];
        cpm_store_area_t *e = NULL;
        for (uint8_t j = 0; j < s->n_sens && !e; j++)
            if (s->sens[j].a.sensor_id == a->sensor_id)
                e = &s->sens[j];
        if (!e && s->n_sens < CPM_STORE_SENS)
            e = &s->sens[s->n_sens++];
        else if (!e)
        {
            e = &s->sens[stalest_area(s->sens, s->n_sens)];
            cut = true;
        }
        keep_area(e, a, m, now_ms);
        if (a->flags & ITS_CPM_AF_CUT)
            cut = true;
    }
    if (cut)
        mark_x(s, CPM_STORE_X_AREA, now_ms);
}

/* Regions have no id. All regions of one referenceTime form one generation, and a region is
 * known by its segment and its place in that segment's list. A newer generation replaces the
 * stored regions. A segment of the same generation adds its regions and overwrites a place
 * already held. A late segment of an older generation is dropped. */
static void note_regions(cpm_store_sender_t *s, const cpm_store_msg_t *m,
                         const its_cpm_areas_t *areas, int64_t now_ms)
{
    if (areas->n_regs == 0)
        return;                          /* no complete region came: the stored ones stay */
    /* An older referenceTime is a late segment only while newer regions are stored. With
     * none left the sender's clock went back, and its regions start over instead of staying
     * hidden. */
    if (m->ref_ms < s->reg_gen && s->n_reg > 0)
        return;
    if (m->ref_ms != s->reg_gen)
    {
        s->reg_gen = m->ref_ms;
        s->n_reg = 0;
    }
    bool cut = areas->reg_shapes > areas->n_regs;
    for (uint8_t i = 0; i < areas->n_regs; i++)
    {
        const its_cpm_area_t *a = &areas->area[areas->n_sens + i];
        /* Looked up by place, not appended: the same CPM heard twice keeps its 5 regions instead
         * of growing to 8 with x bit 2. */
        cpm_store_area_t *e = NULL;
        for (uint8_t j = 0; j < s->n_reg && !e; j++)
            if (s->reg[j].seg == m->seg && s->reg[j].idx == i)
                e = &s->reg[j];
        if (!e && s->n_reg < CPM_STORE_REGS)
            e = &s->reg[s->n_reg++];
        else if (!e)
        {
            cut = true;                  /* a later place of this list may still be held */
            continue;
        }
        keep_area(e, a, m, now_ms);
        e->seg = m->seg;
        e->idx = i;
        if (a->flags & ITS_CPM_AF_CUT)
            cut = true;
    }
    if (cut)
        mark_x(s, CPM_STORE_X_AREA, now_ms);
}

void cpm_store_note(int64_t now_ms, const cpm_store_msg_t *m, const its_cpm_obj_t *all,
                    uint16_t n, const its_cpm_areas_t *areas)
{
    if (!s_lock || !m->has_ref_pos)
        return;                          /* without the reference position nothing can be placed */
    if (!all)
        n = 0;
    if (xSemaphoreTake(s_lock, WAIT_TICKS(NOTE_WAIT_MS)) != pdTRUE)
    {
        /* Counted, and logged once a minute at most: the receive path must not stall. */
        s_busy++;
        if (!s_busy_logged || now_ms - s_busy_log_ms >= BUSY_LOG_MS)
        {
            s_busy_logged = true;
            s_busy_log_ms = now_ms;
            ESP_LOGW(TAG, "lock busy, %" PRIu32 " CPMs not noted since boot", s_busy);
        }
        return;
    }
    for (unsigned i = 0; i < CPM_STORE_SENDERS; i++)
        sweep(&s_store[i], now_ms);
    cpm_store_sender_t *s = sender_for(m->station_id, now_ms);
    s->last_ms = now_ms;
    s->ref_ms = m->ref_ms;
    s->ref_lat_e7 = m->ref_lat_e7;
    s->ref_lon_e7 = m->ref_lon_e7;
    if (m->both)
        s->kind = CPM_STORE_KIND_UNKNOWN;    /* vehicle and RSU at once: no frame for its sensors */
    else if (m->kind != CPM_STORE_KIND_UNKNOWN)
        s->kind = m->kind;
    if (m->has_heading)
    {
        s->has_heading = true;
        s->heading_ddeg = m->heading_ddeg;
    }
    else if (m->veh_read)
    {
        /* 3600 or 3601 in a readable container 1: the old angle would turn the fans wrong. */
        s->has_heading = false;
        s->heading_ddeg = 0;
    }
    if (m->edition)
        s->edition = m->edition;         /* a proven edition stays until another is proven */
    note_objects(s, m, all, n, now_ms);
    if (areas)
    {
        note_sensors(s, m, areas, now_ms);
        note_regions(s, m, areas, now_ms);
    }
    xSemaphoreGive(s_lock);
}

/* Stack (riscv gcc -Os): 48 here + its_cpm_areas 80 + walk_sensors 96 +
 * read_shape 48 + read_cart3d 32 + read_flag 16 = 320 B deepest. The merge: 48 +
 * cpm_store_note 80 + sweep 64 + keep_fresh_areas 48 = 240 B. */
void cpm_store_note_frame(const uint8_t *frame, size_t len, const its_decoded_t *d,
                          const its_cpm_t *sum, const its_cpm_obj_t *all, uint16_t n)
{
    if (!s_lock || !sum->read || !d->cpm_has_pos)
        return;
    uint16_t c = d->cpm_containers;
    uint16_t veh = CONT_BIT(ITS_CPM_ORIG_VEHICLE), rsu = CONT_BIT(ITS_CPM_ORIG_RSU);
    uint16_t senders = c & (veh | rsu);
    cpm_store_msg_t m = {
        .station_id = sum->station_id,
        .kind = senders == veh ? CPM_STORE_KIND_VEHICLE
              : senders == rsu ? CPM_STORE_KIND_RSU
                               : CPM_STORE_KIND_UNKNOWN,
        .has_heading = d->cpm_has_heading,
        .heading_ddeg = d->cpm_heading_ddeg,
        .edition = sum->dialect_sure ? sum->dialect : 0,
        .has_ref_pos = true,
        .veh_read = (c & veh) && !(d->cpm_cont_bad & veh),
        .both = senders == (veh | rsu),
        .n_walked = sum->n_walked,
        .seg = d->cpm_seg_this,
        .ref_lat_e7 = d->cpm_lat_e7,
        .ref_lon_e7 = d->cpm_lon_e7,
        .ref_ms = d->cpm_ref_ms,
    };
    const its_cpm_areas_t *areas = NULL;
    if ((c & (CONT_BIT(ITS_CPM_SENSOR_INFO) | CONT_BIT(ITS_CPM_REGION))) &&
        its_cpm_areas(frame, len, d, &s_areas))
        areas = &s_areas;
    cpm_store_note(cpm_store_now_ms(), &m, all, n, areas);
}

bool cpm_store_copy(unsigned slot, int64_t now_ms, cpm_store_sender_t *out)
{
    if (slot >= CPM_STORE_SENDERS || !s_lock ||
        xSemaphoreTake(s_lock, WAIT_TICKS(COPY_WAIT_MS)) != pdTRUE)
        return false;
    cpm_store_sender_t *s = &s_store[slot];
    sweep(s, now_ms);
    bool used = s->used;
    if (used)
        memcpy(out, s, sizeof *out);
    xSemaphoreGive(s_lock);
    return used;
}

bool cpm_store_dropped(int64_t now_ms)
{
    if (!s_lock || xSemaphoreTake(s_lock, WAIT_TICKS(COPY_WAIT_MS)) != pdTRUE)
        return false;
    bool r = s_dropped && !stale(s_dropped_ms, now_ms);
    xSemaphoreGive(s_lock);
    return r;
}
