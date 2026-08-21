#include "spatem.h"

#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_attr.h"

/* Fixed cache under a mutex: packet path writes, httpd task reads; the lock is
 * only ever held for a single slot memcpy. */
static spatem_intersection_t s_int[SPATEM_MAX_INT];
/* Parallel to s_int[], same slot index; in PSRAM because it is bulky
 * display data that no hot path reads. */
static EXT_RAM_BSS_ATTR spatem_phases_t s_ph[SPATEM_MAX_INT];
static int s_count;
static SemaphoreHandle_t s_lock;

/* Lane geometry, one PSRAM slot per intersection; re-decodes happen in place,
 * so readers hold s_geom_lock (separate from s_lock to keep the SPAT hot path free). */
static its_map_geom_t *s_geom[SPATEM_MAX_INT];
static bool s_geom_ready[SPATEM_MAX_INT];
static SemaphoreHandle_t s_geom_lock;
static const char TAG[] = "SPATEM";

/* Silence -- neither SPATEM nor MAPEM -- after which a slot may be evicted.
 * NTP sync steps the seconds base once, so older slots look dead for one message. */
#define SPAT_DEAD_SEC 60

/* Durations run on the monotonic clock, never the wall clock the packets carry:
 * an NTP step must not stretch a number presented as measured. Display stays wall clock. */
static uint32_t mono_now(void)
{
    /* +1 so that 0 is never a real instant: the phase rows use last_mono == 0
     * as "never seen", which a row first written in uptime second 0 would hit. */
    return (uint32_t)(esp_timer_get_time() / 1000000) + 1;
}



/* Revision that failed to decode, and how often in a row: stops the ASN.1 walk
 * repeating forever. Counted, not latched -- one clipped frame must not latch it. */
static uint16_t s_geom_failed_rev[SPATEM_MAX_INT];
static uint8_t  s_geom_fail_n[SPATEM_MAX_INT];
#define SPAT_GEOM_MAX_FAIL 5   /* ~5 s of MAPEMs before we stop re-walking */

bool spatem_phases(uint16_t region, uint16_t id, spatem_phases_t *out)
{
    if (!out || !s_lock)
        return false;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE)
        return false;
    bool found = false;
    for (int i = 0; i < SPATEM_MAX_INT; i++)
        if (s_int[i].id == id && s_int[i].region == region && s_int[i].n)
        {
            memcpy(out, &s_ph[i], sizeof(*out));
            out->now_mono = mono_now();
            found = true;
            break;
        }
    xSemaphoreGive(s_lock);
    return found;
}

void spatem_init(void)
{
    s_count = 0;
    memset(s_int, 0, sizeof(s_int));
    s_lock = xSemaphoreCreateMutex();
    s_geom_lock = xSemaphoreCreateMutex();
}

bool spatem_geometry_lock_timeout(uint32_t ms)
{
    if (!s_geom_lock)
        return false;
    return xSemaphoreTake(s_geom_lock, pdMS_TO_TICKS(ms)) == pdTRUE;
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

/* green / red-amber / amber / red, or -1 for anything else (dark, flashing). */
static int spat_phase_class(uint8_t phase)
{
    switch (phase)
    {
    case 5: case 6:          return 0;
    case 4:                  return 1;   /* pre-movement = red+amber */
    case 7: case 8: case 9:  return 2;   /* clearance / caution = amber */
    case 2: case 3:          return 3;
    default:                 return -1;
    }
}

/* Row for this signal group, allocated on first sight. -1 = table full. */
static int ph_row(spatem_phases_t *p, uint8_t sg)
{
    for (int r = 0; r < p->n_rows; r++)
        if (p->sg[r] == sg)
            return r;
    if (p->n_rows >= ITS_SPAT_MAX_SG)
    {
        /* ONCE: runs for every group of every SPATEM and the table never
         * un-fills, so an unconditional warning floods console and SD log. */
        static bool told;
        if (!told)
        {
            told = true;
            ESP_LOGW(TAG, "phase table full (%d groups); further groups are not measured",
                     ITS_SPAT_MAX_SG);
        }
        return -1;
    }
    int r = p->n_rows++;
    p->sg[r] = sg;
    memset(p->secs[r], 0, sizeof(p->secs[r]));
    memset(p->cnt[r], 0, sizeof(p->cnt[r]));
    memset(p->max[r], 0, sizeof(p->max[r]));
    p->since[r] = 0;
    p->last_mono[r] = 0;
    p->phase[r] = 0;
    p->armed &= ~(1u << r);
    return r;
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
            /* Evict a DEAD slot first, among those the one longest without
             * PHASES. Ranking by phase_seen alone throws out a LIVE map-only slot. */
            slot = -1;
            for (int i = 0; i < s_count; i++)
                if (seconds > s_int[i].last_seen &&
                    seconds - s_int[i].last_seen > SPAT_DEAD_SEC &&
                    (slot < 0 || s_int[i].phase_seen < s_int[slot].phase_seen))
                    slot = i;
            /* All alive: fall back to the phase key so a map-only slot yields
             * instead of locking out SPATEM. Its name and lanes stay lost until a slot frees. */
            if (slot < 0)
            {
                slot = 0;
                for (int i = 1; i < s_count; i++)
                    if (s_int[i].phase_seen < s_int[slot].phase_seen)
                        slot = i;
            }
        }
    }

    spatem_intersection_t *e = &s_int[slot];
    /* A slot taken over by a DIFFERENT intersection must start empty -- the previous
     * occupant's MAPEM data would otherwise stay attached to the new one. */
    if (!same_intersection)
    {
        memset(e, 0, sizeof(*e));
        memset(&s_ph[slot], 0, sizeof(s_ph[slot]));
        /* The counter is the half that matters: at 0 the skip in
         * spatem_note_geometry() cannot consult the previous occupant's revision. */
        s_geom_fail_n[slot] = 0;
        s_geom_failed_rev[slot] = 0;
        /* spatem_geometry() scans by region+id, not by slot: left set, it keeps
         * serving the evicted intersection's lanes. */
        s_geom_ready[slot] = false;   /* a plain flag; readers test it first */
    }

    uint8_t n = s->n <= ITS_SPAT_MAX_SG ? s->n : ITS_SPAT_MAX_SG;

    /* Phase-end deadline: fresh whenever the message carried timing, else carry
     * the previous one forward only while that group's phase has not flipped. */
    /* Durations are sampled at message rate, so they are good to about a second. */
    /* A revision bump is a NEW signal plan: group ids may mean something else,
     * and averages from the old plan must not be shown as the new one's. */
    if (same_intersection && e->revision != s->revision)
    {
        memset(&s_ph[slot], 0, sizeof(s_ph[slot]));
    }

    /* Keyed by signal group ID, each with its own last-seen instant: an omitted
     * group keeps its history, a returning one sees the gap for ITSELF. */
    uint32_t mono = mono_now();
    if (same_intersection)
        for (uint8_t j = 0; j < n; j++)
        {
            int r = ph_row(&s_ph[slot], s->sg[j]);
            if (r < 0)
                continue;                     /* no room for another group */
            spatem_phases_t *ph = &s_ph[slot];
            bool fresh = (ph->last_mono[r] != 0);
            bool gap = !fresh || mono - ph->last_mono[r] > SPAT_GAP_SEC;
            int prev = fresh ? spat_phase_class(ph->phase[r]) : -1;
            int now  = spat_phase_class(s->phase[j]);
            bool armed = (ph->armed >> r) & 1u;

            if (fresh && prev == now)
            {
                /* Same phase still running: keep timing it only if its start is
                 * known AND nothing was missed since. */
                if (!(armed && !gap))
                {
                    ph->since[r] = mono;
                    ph->armed &= ~(1u << r);
                }
            }
            else
            {
                if (armed && !gap && prev >= 0 && mono > ph->since[r])
                {
                    uint32_t dur = mono - ph->since[r];
                    /* Observed without a gap, so however long it was, it
                     * really lasted that long -- no upper bound needed. */
                    if (ph->cnt[r][prev] < 0xFFFFFFFEu &&
                        ph->secs[r][prev] <= 0xFFFFFFFFu - dur)
                    {
                        ph->secs[r][prev] += dur;
                        ph->cnt[r][prev]++;
                    }
                    if (dur > ph->max[r][prev])
                        ph->max[r][prev] = dur;
                }
                /* The new phase starts now, but that is only KNOWN without a gap:
                 * arming after one records the next phase short by up to the gap. */
                ph->since[r] = mono;
                if (!gap)
                    ph->armed |= 1u << r;
                else
                    ph->armed &= ~(1u << r);
            }
            /* Updated here, so a group repeated within ONE message sees
             * prev == now on its second occurrence and cannot count twice. */
            ph->phase[r] = s->phase[j];
            ph->last_mono[r] = mono;
        }

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
    /* No remap, no zeroing: tallies live in rows keyed by group id, so a group
     * this message left out simply keeps its row. */
    e->last_seen = seconds;
    /* 0 doubles as "phases never decoded" here and in webserver.c; before NTP
     * sync `seconds` is uptime, so second 0 collides for one second. */
    e->phase_seen = seconds;   /* this message carried phases */
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
        /* A MAPEM is a sighting too: without this an intersection whose SPATEM
         * we cannot decode ages out and reads as dead. */
        s_int[slot].last_seen = seconds;
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

    /* Already have this exact revision: nothing to do. The common case. */
    if (s_geom_ready[slot] && s_geom[slot] &&
        s_geom[slot]->region == m->region && s_geom[slot]->id == m->id &&
        s_geom[slot]->revision == m->revision)
        return;

    /* Likewise once a revision has failed SPAT_GEOM_MAX_FAIL times in a row;
     * a one-off short frame is still retried. */
    if (s_geom_fail_n[slot] >= SPAT_GEOM_MAX_FAIL && s_geom_failed_rev[slot] == m->revision)
        return;

    if (!s_geom[slot])
    {
        s_geom[slot] = heap_caps_malloc(sizeof(*s_geom[slot]), MALLOC_CAP_SPIRAM);
        if (!s_geom[slot])
        {
            /* ONCE: PSRAM exhaustion is sticky, so an unconditional warning
             * would block the packet path on UART plus SD writes indefinitely. */
            static bool oom_told;
            if (!oom_told)
            {
                oom_told = true;
                ESP_LOGW(TAG, "no PSRAM for lane geometry (%u bytes)",
                         (unsigned)sizeof(*s_geom[slot]));
            }
            return;
        }
    }

    /* Held across the in-place re-decode so no reader sees half of each revision.
     * Bounded: runs with msg_ring_mutex held -- a slow reader costs this MAPEM, not reception. */
    if (!spatem_geometry_lock_timeout(50))
        return;
    s_geom_ready[slot] = false;
    if (its_decode_map_geometry(frame, len, s_geom[slot]))
    {
        s_geom_ready[slot] = true;
        s_geom_fail_n[slot] = 0;
    }
    else
    {
        /* A different revision restarts the count, which saturates rather than
         * wrapping. A sender bumping the revision every frame keeps retrying: intended. */
        if (s_geom_failed_rev[slot] != m->revision)
        {
            s_geom_failed_rev[slot] = m->revision;
            s_geom_fail_n[slot] = 0;
        }
        if (s_geom_fail_n[slot] < SPAT_GEOM_MAX_FAIL)
            s_geom_fail_n[slot]++;
    }
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
