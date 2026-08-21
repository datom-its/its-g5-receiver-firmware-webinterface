#include "sdkconfig.h"

#include "inventory.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_attr.h"

#if CONFIG_ENABLE_SD
#include <sys/stat.h>
#include "sdcard.h"

#define INV_DIR CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define INV_CSV INV_DIR "/senders.csv"
#define INV_TMP INV_DIR "/senders.tmp"
#define INV_SAVE_TICKS 60   /* sysmon runs every 5 s -> save every 5 min */
#endif

/* Stations live in PSRAM: 128 rows are ~10 KB, far more than the internal
 * heap should carry for a display-only table. */
static EXT_RAM_BSS_ATTR inv_station_t s_tab[INV_MAX_STATIONS];
static int s_count;
static bool s_overflow;

/* Everything without a row of its own -- vehicles, mostly. Frames only: a
 * vehicle count would be fiction, ETSI rotates their station id and MAC. */
static uint32_t s_veh_frames;

static SemaphoreHandle_t s_lock;
static int s_last_hit = -1;   /* an RSU repeats; skip the scan for its rows */
static bool s_dirty;
/* Bumped by clear(): a save whose snapshot predates it must not commit. */
#if CONFIG_ENABLE_SD
/* Both are read and written only inside the SD blocks; declaring them outside
 * makes a CONFIG_ENABLE_SD=n build fail on -Werror=unused-variable. */
static volatile uint32_t s_gen;
static volatile bool s_wipe_pending;
#endif

void inventory_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

/* Message types only infrastructure sends. SREM (9) is deliberately absent:
 * buses send it to request priority. */
static inline bool is_infra_msg(uint8_t mid)
{
    return mid == 4 || mid == 5 || mid == 6 || mid == 10 || mid == 13;
}

void inventory_note(uint32_t seconds, int rssi, const its_decoded_t *d)
{
    if (!s_lock || !d->station_id)
        return;
    /* Before the clock is set, "first seen" would be a device-relative
     * number -- worse than not recording it at all. */
    if (seconds < 1600000000u)
        return;

    bool infra = (d->station_type == 15) || is_infra_msg(d->message_id);

    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;

    if (!infra)
    {
        s_veh_frames++;
        xSemaphoreGive(s_lock);
        return;
    }

    int idx = -1;
    if (s_last_hit >= 0 && s_last_hit < s_count &&
        s_tab[s_last_hit].station_id == d->station_id)
        idx = s_last_hit;
    else
        for (int i = 0; i < s_count; i++)
            if (s_tab[i].station_id == d->station_id) { idx = i; break; }

    if (idx < 0)
    {
        if (s_count >= INV_MAX_STATIONS)
        {
            s_overflow = true;
            xSemaphoreGive(s_lock);
            return;
        }
        idx = s_count++;
        s_tab[idx] = (inv_station_t){ .station_id = d->station_id,
                                      .first_seen = seconds };
    }
    s_last_hit = idx;

    inv_station_t *s = &s_tab[idx];
    s->last_seen = seconds;
    s->frames++;
    s->station_type = d->station_type;
    /* Only ids that actually fit get a bit; masking with 15 made an id above
     * 15 light up a DIFFERENT type's bit and mislabel the sender. */
    if (d->message_id && d->message_id < 16)
        s->msg_mask |= (uint16_t)(1u << d->message_id);
    if (rssi < 0 && rssi > -128)      /* 0 = the driver had no reading */
    {
        if (!s->rssi_cnt || rssi < s->rssi_min) s->rssi_min = (int16_t)rssi;
        if (!s->rssi_cnt || rssi > s->rssi_max) s->rssi_max = (int16_t)rssi;
        s->rssi_sum += rssi;
        s->rssi_cnt++;
    }
    if (d->has_position) { s->lat_e7 = d->lat_e7; s->lon_e7 = d->lon_e7; s->has_pos = true; }
    if (d->has_src_mac)  { memcpy(s->mac, d->src_mac, 6); s->has_mac = true; }
    if (d->map.valid && d->map.name[0] && !s->name[0])
    {
        /* Operator text lands in HTML and in the CSV: drop control chars and
         * commas here, let the page escape the rest. */
        size_t o = 0;
        for (size_t i = 0; d->map.name[i] && o + 1 < sizeof(s->name); i++)
            if ((unsigned char)d->map.name[i] >= 0x20 && d->map.name[i] != ',')
                s->name[o++] = d->map.name[i];
        s->name[o] = '\0';
    }
    s_dirty = true;

    xSemaphoreGive(s_lock);
}

int inventory_snapshot(inv_station_t *out)
{
    if (!s_lock || !out)
        return 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return 0;
    int n = s_count;
    memcpy(out, s_tab, (size_t)n * sizeof(s_tab[0]));
    xSemaphoreGive(s_lock);

    for (int i = 1; i < n; i++)   /* newest activity first */
    {
        inv_station_t t = out[i];
        int j = i - 1;
        while (j >= 0 && out[j].last_seen < t.last_seen) { out[j + 1] = out[j]; j--; }
        out[j + 1] = t;
    }
    return n;
}

int inventory_lookup_mac(const uint8_t mac[6], char *out, size_t cap,
                         uint32_t *id_out)
{
    if (out && cap) out[0] = 0;
    if (id_out) *id_out = 0;
    /* Short timeout, never portMAX_DELAY: this is asked per table row on the
     * httpd task while inv_save may hold the lock for a whole rewrite. */
    if (!s_lock || !mac || xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE)
        return -1;
    int found = 0;
    for (int i = 0; i < s_count; i++)
        if (s_tab[i].has_mac && memcmp(s_tab[i].mac, mac, 6) == 0)
        {
            if (out && cap) snprintf(out, cap, "%s", s_tab[i].name);
            if (id_out) *id_out = s_tab[i].station_id;
            found = 1;
            break;
        }
    xSemaphoreGive(s_lock);
    return found;
}

uint32_t inventory_vehicle_frames(void) { return s_veh_frames; }

bool inventory_overflow(void) { return s_overflow; }

#if CONFIG_ENABLE_SD

/* Insert or fold one restored row; caller holds s_lock, so the whole batch
 * lands in one critical section. */
static void inv_upsert_locked(const inv_station_t *r)
{
    int idx = -1;
    for (int i = 0; i < s_count; i++)
        if (s_tab[i].station_id == r->station_id) { idx = i; break; }
    if (idx < 0)
    {
        if (s_count >= INV_MAX_STATIONS) { s_overflow = true; return; }
        idx = s_count++;
        s_tab[idx] = *r;
    }
    else
    {
        inv_station_t *s = &s_tab[idx];
        if (r->first_seen && r->first_seen < s->first_seen) s->first_seen = r->first_seen;
        if (r->last_seen > s->last_seen) s->last_seen = r->last_seen;
        s->frames += r->frames;
        s->msg_mask |= r->msg_mask;
        if (r->rssi_cnt)
        {
            if (!s->rssi_cnt || r->rssi_min < s->rssi_min) s->rssi_min = r->rssi_min;
            if (!s->rssi_cnt || r->rssi_max > s->rssi_max) s->rssi_max = r->rssi_max;
            s->rssi_sum += r->rssi_sum;
            s->rssi_cnt += r->rssi_cnt;
        }
        if (!s->name[0] && r->name[0]) memcpy(s->name, r->name, sizeof(s->name));
        if (!s->has_pos && r->has_pos) { s->lat_e7 = r->lat_e7; s->lon_e7 = r->lon_e7; s->has_pos = true; }
        if (!s->has_mac && r->has_mac) { memcpy(s->mac, r->mac, 6); s->has_mac = true; }
    }
}

/* Staging for inv_load, applied to s_tab exactly ONCE at the end: the upsert
 * ADDS frames and rssi_sum, so a partial apply plus a retry doubles them. */
static EXT_RAM_BSS_ATTR inv_station_t s_load_tmp[INV_MAX_STATIONS];

/* False = nothing was APPLIED to s_tab; the retry rests on that, since the
 * upsert adds. Until it returns true the caller must not save. */
static bool inv_load(void)
{
    /* A clear landing mid-load bumps s_gen; restoring rows read before it
     * would silently undo the wipe, so the batch is dropped and retried. */
    uint32_t gen_at_start = s_gen;
    bool over = false;
    int nload = 0;
    if (!sdcard_io_begin_timeout(2000))
        return false;
    FILE *f = fopen(INV_CSV, "r");
    /* A power cut between remove() and rename() leaves only the temp file --
     * it holds the complete newer content, so prefer it over nothing. */
    if (!f)
        f = fopen(INV_TMP, "r");
    if (!f)
    {
        sdcard_io_end();
        return true;      /* nothing stored yet is a valid, complete answer */
    }
    /* Name is the last field and may contain spaces, so it is read as the
     * rest of the line rather than a comma-delimited token. */
    char line[256];
    while (fgets(line, sizeof(line), f))
    {
        inv_station_t r = { 0 };
        unsigned long id = 0, first = 0, last = 0, frames = 0;
        unsigned type = 0, mask = 0, m[6] = { 0 };
        long lat = 0, lon = 0;
        long long rsum = 0;
        unsigned long rcnt = 0;
        int rmin = 0, rmax = 0, used = 0;
        int got = sscanf(line,
            "%lu,%u,%lu,%lu,%lu,%u,%ld,%ld,%2x:%2x:%2x:%2x:%2x:%2x,%n",
            &id, &type, &first, &last, &frames, &mask, &lat, &lon,
            &m[0], &m[1], &m[2], &m[3], &m[4], &m[5], &used);
        if (got < 14 || !id || used <= 0)
            continue;
        r.station_id = (uint32_t)id;
        r.first_seen = (uint32_t)first;
        r.last_seen = (uint32_t)last;
        r.frames = (uint32_t)frames;
        r.lat_e7 = (int32_t)lat;
        r.lon_e7 = (int32_t)lon;
        r.station_type = (uint8_t)type;
        r.msg_mask = (uint16_t)mask;
        r.has_pos = (r.lat_e7 || r.lon_e7);
        for (int i = 0; i < 6; i++) r.mac[i] = (uint8_t)m[i];
        r.has_mac = (m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) != 0;

        /* Signal fields came with 0.27.0; older rows go straight to the name
         * here, so they are parsed separately and simply stay zero. */
        int used2 = 0;
        if (sscanf(line + used, "%d,%d,%lld,%lu,%n",
                   &rmin, &rmax, &rsum, &rcnt, &used2) == 4 && used2 > 0)
        {
            r.rssi_min = (int16_t)rmin; r.rssi_max = (int16_t)rmax;
            r.rssi_sum = (int64_t)rsum; r.rssi_cnt = (uint32_t)rcnt;
            used += used2;
        }

        {
            char *nm = line + used;
            size_t l = strlen(nm);
            while (l && (nm[l - 1] == '\n' || nm[l - 1] == '\r')) nm[--l] = '\0';
            if (l >= sizeof(r.name)) l = sizeof(r.name) - 1;
            memcpy(r.name, nm, l);
        }
        if (nload < INV_MAX_STATIONS)
            s_load_tmp[nload++] = r;
        else
            over = true;   /* more senders on the card than the table holds */
    }
    fclose(f);

    /* ONE application, all or nothing: it ADDS (frames folded before the card
     * mounted must survive), so it may run only once per successful load. */
    bool ok = false;
    if (s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) == pdTRUE)
    {
        /* Cleared mid-read: applying now would resurrect what the user just
         * deleted. Drop the batch; the retry then reads an empty file. */
        if (gen_at_start == s_gen)
        {
            for (int i = 0; i < nload; i++)
                inv_upsert_locked(&s_load_tmp[i]);
            if (over)
                s_overflow = true;
            ok = true;
        }
        xSemaphoreGive(s_lock);
    }
    sdcard_io_end();
    return ok;   /* nothing was applied on failure, so the retry is clean */
}

/* Full rewrite, not append: rows keep changing, unlike the event and track
 * logs. Snapshot first so the file write never holds the table lock. */
/* File scope so inventory_flush_now() honours it too: inv_save() replaces the
 * whole file, so saving before inv_load() succeeded drops the stored senders. */
static bool s_loaded;

static bool inv_save(void)
{
    static EXT_RAM_BSS_ATTR inv_station_t snap[INV_MAX_STATIONS];
    /* SD lock BEFORE the snapshot: two tasks call this and snap[] is shared --
     * re-sorting it mid-write emits a row twice, folded additively next boot. */
    if (!sdcard_io_begin_timeout(2000))
        return false;
    uint32_t gen = s_gen;
    int n = inventory_snapshot(snap);
    if (n <= 0)
    {
        sdcard_io_end();
        return false;
    }

    mkdir(INV_DIR, 0777);
    FILE *f = fopen(INV_TMP, "w");
    if (!f)
    {
        sdcard_io_end();
        return false;
    }
    bool ok = true;
    for (int i = 0; i < n && ok; i++)
    {
        inv_station_t *s = &snap[i];
        if (fprintf(f, "%lu,%u,%lu,%lu,%lu,%u,%ld,%ld,"
                       "%02x:%02x:%02x:%02x:%02x:%02x,%d,%d,%lld,%lu,%s\n",
                    (unsigned long)s->station_id, s->station_type,
                    (unsigned long)s->first_seen, (unsigned long)s->last_seen,
                    (unsigned long)s->frames, s->msg_mask,
                    (long)s->lat_e7, (long)s->lon_e7,
                    s->mac[0], s->mac[1], s->mac[2], s->mac[3], s->mac[4], s->mac[5],
                    s->rssi_min, s->rssi_max, (long long)s->rssi_sum,
                    (unsigned long)s->rssi_cnt, s->name) < 0)
            ok = false;
    }
    if (fclose(f) != 0)
        ok = false;
    if (ok && gen != s_gen)
    {
        /* Cleared while we were writing -- discard, don't resurrect. */
        remove(INV_TMP);
        ok = false;
    }
    else if (ok && sdcard_read_active() != 0)
    {
        /* The swap unlinks senders.csv, which a streaming download holds
         * open. Keep the live file; s_dirty retries a save interval later. */
        ok = false;
    }
    else if (ok)
    {
        remove(INV_CSV);
        rename(INV_TMP, INV_CSV);
    }
    sdcard_io_end();
    return ok;
}

void inventory_tick(void)
{
    static int ticks;

    if (!s_lock || !sdcard_is_mounted())
        return;
    if (s_wipe_pending)
    {
        /* The clear could not reach the card at the time -- finish it now,
         * before any save can put the old rows back. */
        if (sdcard_io_begin_timeout(2000))
        {
            remove(INV_CSV);
            remove(INV_TMP);
            sdcard_io_end();
            s_wipe_pending = false;
        }
        return;
    }
    if (!s_loaded)
    {
        /* Retried until it actually succeeds -- saving before the stored rows
         * are back would replace them with whatever little is in RAM. */
        s_loaded = inv_load();
        return;
    }
    if (++ticks < INV_SAVE_TICKS || !s_dirty)
        return;
    ticks = 0;
    /* Cleared only on success: a failed write must be retried, not dropped. */
    if (inv_save())
        s_dirty = false;
}

#else
void inventory_tick(void) {}
#endif

/* Persists the table now instead of waiting for the 5-minute tick. */
void inventory_flush_now(void)
{
#if CONFIG_ENABLE_SD
    /* Same precedence as the tick: s_wipe_pending dies with the restart that
     * follows, so finish the deferred delete instead of saving around it. */
    if (s_wipe_pending)
    {
        if (sdcard_io_begin_timeout(2000))
        {
            remove(INV_CSV);
            remove(INV_TMP);
            sdcard_io_end();
            s_wipe_pending = false;
        }
        return;
    }
    if (s_loaded && s_dirty && inv_save())
        s_dirty = false;
#endif
}

void inventory_clear(void)
{
    if (!s_lock || xSemaphoreTake(s_lock, pdMS_TO_TICKS(100)) != pdTRUE)
        return;
    memset(s_tab, 0, sizeof(s_tab));
    s_count = 0;
    s_veh_frames = 0;
    s_overflow = false;
    s_last_hit = -1;
    s_dirty = false;
#if CONFIG_ENABLE_SD
    /* Bumped under the lock, like ptlog_clear: a loader that takes s_lock the
     * moment we give it then sees the new gen and drops its stale batch. */
    s_gen++;
#endif
    xSemaphoreGive(s_lock);

#if CONFIG_ENABLE_SD
    /* Also drop the stored copy: an empty table is never written back
     * (inv_save bails on zero rows), so the old file would return on reboot. */
    if (sdcard_io_begin_timeout(2000))
    {
        remove(INV_CSV);
        remove(INV_TMP);   /* inv_load() falls back to it, so a leftover undoes the wipe */
        sdcard_io_end();
    }
    else
        s_wipe_pending = true;
#endif
}
