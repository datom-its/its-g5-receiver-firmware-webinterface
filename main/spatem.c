#include "spatem.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"

/* Small fixed cache guarded by a mutex: writes come from the packet path,
 * reads from the httpd task. Both hold the lock only briefly (a memcpy of one
 * slot), so a plain mutex is ample. */
static spatem_intersection_t s_int[SPATEM_MAX_INT];
static int s_count;
static SemaphoreHandle_t s_lock;

/* Lane geometry, one PSRAM slot per intersection; re-decodes happen in place,
 * so readers hold s_geom_lock (separate from s_lock to keep the SPAT hot path free). */
static its_map_geom_t *s_geom[SPATEM_MAX_INT];
static bool s_geom_ready[SPATEM_MAX_INT];
static SemaphoreHandle_t s_geom_lock;
static const char TAG[] = "SPATEM";

void spatem_init(void)
{
    s_count = 0;
    memset(s_int, 0, sizeof(s_int));
    s_lock = xSemaphoreCreateMutex();
    s_geom_lock = xSemaphoreCreateMutex();
}

void spatem_geometry_lock(void)
{
    if (s_geom_lock)
        xSemaphoreTake(s_geom_lock, portMAX_DELAY);
}

void spatem_geometry_unlock(void)
{
    if (s_geom_lock)
        xSemaphoreGive(s_geom_lock);
}

void spatem_note(const its_spat_t *s, uint32_t station_id, uint32_t seconds,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7)
{
    if (!s || !s->valid || !s_lock)
        return;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;  /* never block the packet path; drop this update */

    /* Find existing slot by intersection identity. */
    int slot = -1;
    for (int i = 0; i < s_count; i++)
        if (s_int[i].region == s->region && s_int[i].id == s->id)
        {
            slot = i;
            break;
        }

    /* Only a slot that already held THIS intersection may contribute its old
     * deadlines below; a fresh or evicted slot must not. */
    bool same_intersection = slot >= 0;

    if (slot < 0)
    {
        if (s_count < SPATEM_MAX_INT)
            slot = s_count++;
        else
        {
            /* Full: evict the least-recently-seen slot. */
            slot = 0;
            for (int i = 1; i < s_count; i++)
                if (s_int[i].last_seen < s_int[slot].last_seen)
                    slot = i;
        }
    }

    spatem_intersection_t *e = &s_int[slot];
    /* A slot taken over by a DIFFERENT intersection must start empty -- the previous
     * occupant's MAPEM data would otherwise stay attached to the new one. */
    if (!same_intersection)
        memset(e, 0, sizeof(*e));

    uint8_t n = s->n <= ITS_SPAT_MAX_SG ? s->n : ITS_SPAT_MAX_SG;

    /* Phase-end deadlines: take a fresh one whenever this message carried
     * timing, otherwise keep the previous one as long as the group's phase
     * hasn't flipped (a stale deadline from a past phase would be wrong). */
    uint32_t next_change[ITS_SPAT_MAX_SG];
    for (uint8_t j = 0; j < n; j++)
    {
        if (s->secs[j] >= 0)
        {
            next_change[j] = seconds + (uint32_t)s->secs[j];
            continue;
        }
        next_change[j] = 0;
        if (!same_intersection)
            continue;
        for (uint8_t k = 0; k < e->n; k++)
            if (e->sg[k] == s->sg[j])
            {
                if (e->phase[k] == s->phase[j])
                    next_change[j] = e->change_at[k];
                break;
            }
    }

    e->region = s->region;
    e->id = s->id;
    e->status = s->status;
    e->revision = s->revision;
    e->n = n;
    memcpy(e->sg, s->sg, n);
    memcpy(e->phase, s->phase, n);
    memcpy(e->change_at, next_change, (size_t)n * sizeof(next_change[0]));
    e->last_seen = seconds;
    e->station_id = station_id;
    if (has_pos && (lat_e7 || lon_e7))
    {
        e->has_pos = true;
        e->lat_e7 = lat_e7;
        e->lon_e7 = lon_e7;
    }

    xSemaphoreGive(s_lock);
}

void spatem_note_name(const its_map_t *m, uint32_t seconds)
{
    if (!m || !m->valid || !s_lock)
        return;
    if (m->name[0] == '\0' && m->n_sg == 0)
        return;   /* nothing to attach */
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;

    int slot = -1;
    for (int i = 0; i < s_count; i++)
        if (s_int[i].region == m->region && s_int[i].id == m->id)
        {
            slot = i;
            break;
        }
    /* MAPEM can arrive before the first SPATEM; seed an entry so the name
     * isn't dropped (n stays 0, so no phase chips render for it yet). */
    if (slot < 0 && s_count < SPATEM_MAX_INT)
    {
        slot = s_count++;
        s_int[slot].region = m->region;
        s_int[slot].id = m->id;
        s_int[slot].n = 0;
        s_int[slot].last_seen = seconds;
    }
    if (slot >= 0)
    {
        if (m->name[0])
            strlcpy(s_int[slot].name, m->name, sizeof(s_int[slot].name));
        s_int[slot].lane_width_cm = m->lane_width_cm;
        s_int[slot].speed_max_kmh = m->speed_max_kmh;
        s_int[slot].speed_min_kmh = m->speed_min_kmh;
        if (m->n_sg)
        {
            uint8_t n = m->n_sg <= ITS_SPAT_MAX_SG ? m->n_sg : ITS_SPAT_MAX_SG;
            memcpy(s_int[slot].map_sg, m->sg, n);
            memcpy(s_int[slot].map_man, m->maneuvers, (size_t)n * sizeof(m->maneuvers[0]));
            memcpy(s_int[slot].map_ped, m->ped, (size_t)n * sizeof(m->ped[0]));
            s_int[slot].map_n = n;
        }
    }

    xSemaphoreGive(s_lock);
}

bool spatem_movement(const spatem_intersection_t *e, uint8_t sg,
                     uint16_t *maneuvers, bool *pedestrian)
{
    if (!e) return false;
    for (uint8_t i = 0; i < e->map_n; i++)
        if (e->map_sg[i] == sg)
        {
            if (maneuvers) *maneuvers = e->map_man[i];
            if (pedestrian) *pedestrian = e->map_ped[i];
            return true;
        }
    return false;
}

void spatem_note_geometry(const uint8_t *frame, size_t len, const its_map_t *m)
{
    if (!m || !m->valid || !s_lock)
        return;

    /* Locate (or make) the slot this intersection uses, under the lock. */
    int slot = -1;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;
    for (int i = 0; i < s_count; i++)
        if (s_int[i].region == m->region && s_int[i].id == m->id)
        {
            slot = i;
            break;
        }
    xSemaphoreGive(s_lock);
    if (slot < 0 || slot >= SPATEM_MAX_INT)
        return;

    /* Already have this exact revision? Then there is nothing to do -- this
     * is the common case, hit on nearly every MAPEM. */
    if (s_geom_ready[slot] && s_geom[slot] &&
        s_geom[slot]->region == m->region && s_geom[slot]->id == m->id &&
        s_geom[slot]->revision == m->revision)
        return;

    if (!s_geom[slot])
    {
        s_geom[slot] = heap_caps_malloc(sizeof(*s_geom[slot]), MALLOC_CAP_SPIRAM);
        if (!s_geom[slot])
        {
            ESP_LOGW(TAG, "no PSRAM for lane geometry (%u bytes)",
                     (unsigned)sizeof(*s_geom[slot]));
            return;
        }
    }

    /* Held across the in-place re-decode so a reader iterating this same
     * buffer never sees half of the previous revision and half of this one. */
    spatem_geometry_lock();
    s_geom_ready[slot] = false;
    if (its_decode_map_geometry(frame, len, s_geom[slot]))
        s_geom_ready[slot] = true;
    spatem_geometry_unlock();
}

const its_map_geom_t *spatem_geometry(uint16_t region, uint16_t id)
{
    for (int i = 0; i < SPATEM_MAX_INT; i++)
        if (s_geom_ready[i] && s_geom[i] &&
            s_geom[i]->region == region && s_geom[i]->id == id)
            return s_geom[i];
    return NULL;
}

int spatem_snapshot(spatem_intersection_t *out, int max)
{
    if (!out || max <= 0 || !s_lock)
        return 0;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE)
        return 0;

    int n = s_count < max ? s_count : max;
    memcpy(out, s_int, (size_t)n * sizeof(out[0]));
    xSemaphoreGive(s_lock);

    /* Sort most-recently-seen first (n is tiny; insertion sort). */
    for (int i = 1; i < n; i++)
    {
        spatem_intersection_t tmp = out[i];
        int j = i - 1;
        while (j >= 0 && out[j].last_seen < tmp.last_seen)
        {
            out[j + 1] = out[j];
            j--;
        }
        out[j + 1] = tmp;
    }
    return n;
}
