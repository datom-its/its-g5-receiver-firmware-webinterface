#include "sdkconfig.h"

#include "inventory.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_attr.h"

#if CONFIG_ENABLE_SD
#include <errno.h>
#include <sys/stat.h>
#include "sd_csv.h"
#include "sdcard.h"
#ifdef ESP_PLATFORM
#include "esp_log.h"
#else
#define ESP_LOGW(tag, ...) ((void)(tag))   /* a host build has no esp_log.h */
#endif

static const char *TAG = "inventory";
#define INV_DIR CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define INV_CSV INV_DIR "/senders.csv"
#define INV_TMP INV_DIR "/senders.tmp"
#define INV_BAD INV_DIR "/senders.bad"
/* First line of a file whose msg_mask bits are message kinds. In a file without it, bit 3 is
 * the raw message id 3 and may mean an old EVCSN, so its rows lose bit 3 once. A POIM sets it
 * again when heard. Older firmware skips the line, because its sscanf fails. */
#define INV_MARK "#senders 2"
#define INV_SAVE_TICKS 60   /* sysmon runs every 5 s -> save every 5 min */
/* Failed reads in a row before the file goes to senders.bad: about 5 min of sysmon ticks. */
#define INV_BAD_TICKS 60
#endif

/* Stations live in PSRAM: 128 rows of 144 B are 18 KB (riscv32), far more than the internal
 * heap should carry for a display-only table. */
static EXT_RAM_BSS_ATTR inv_station_t s_tab[INV_MAX_STATIONS];
static int s_count;
static bool s_overflow;

/* Frames from senders that never get a row of their own, mostly vehicles.
 * Counting them would be fiction, because they rotate station id and MAC. */
static uint32_t s_veh_frames;

static SemaphoreHandle_t s_lock;
static int s_last_hit = -1;   /* an RSU sends again and again: check its row first */
static bool s_dirty;
/* Bumped by clear(): a save whose snapshot predates it must not commit. */
#if CONFIG_ENABLE_SD
/* Both are read and written only inside the SD blocks. Declared outside, they
 * would draw an unused-variable warning in a CONFIG_ENABLE_SD=n build. */
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

void inventory_note(uint32_t seconds, int rssi, const its_decoded_t *d, const msg_extra_t *x)
{
    if (!s_lock || !d->station_id)
        return;
    /* Before the clock is set, "first seen" would be seconds since boot.
     * Recording that is worse than recording nothing. */
    if (seconds < 1600000000u)
        return;

    /* The kind, not the raw id: an old EVCSN (id 3 at version 0) must not show as POIM. */
    uint8_t kind = its_msg_kind(d->pdu_version, d->message_id);
    bool infra = (d->station_type == 15) || is_infra_msg(kind);
    /* A forwarder's level and MAC are not the unit's: a relayed frame counts, but gives neither. */
    int hops = x ? its_gn_hops(&x->gn) : -1;
    bool direct = hops <= 0;

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
    /* Only kinds 1..15 get a bit. Masking a larger id would set the bit of a
     * different message type and mislabel the sender. */
    if (kind && kind < 16)
        s->msg_mask |= (uint16_t)(1u << kind);
    if (direct && rssi < 0 && rssi > -128)      /* 0 = no RF reading, as on Ethernet */
    {
        if (!s->rssi_cnt || rssi < s->rssi_min) s->rssi_min = (int16_t)rssi;
        if (!s->rssi_cnt || rssi > s->rssi_max) s->rssi_max = (int16_t)rssi;
        s->rssi_sum += rssi;
        s->rssi_cnt++;
    }
    if (d->has_position) { s->lat_e7 = d->lat_e7; s->lon_e7 = d->lon_e7; s->has_pos = true; }
    if (direct && d->has_src_mac) { memcpy(s->mac, d->src_mac, 6); s->has_mac = true; }
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
    if (x && x->has_dcc)
    {
        s->has_dcc = true;
        if (x->dcc_tx_power_dbm)
            s->tx_power_dbm = x->dcc_tx_power_dbm;
        uint8_t cbr = x->dcc_cbr_r0 > x->dcc_cbr_r1 ? x->dcc_cbr_r0 : x->dcc_cbr_r1;
        if (cbr > s->cbr_max)
            s->cbr_max = cbr;
    }
    if (x && x->sig.kind != ITS_SIG_NONE)
        s->sig = x->sig;
    if (x && x->sechdr.read)
        its_sechdr_unit_fold(&s->sec, &x->sechdr);
    if (x)
        its_gn_unit_fold(&s->gnu, &x->gn);
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
     * httpd task, so a busy table must not stall the page. */
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

int inventory_lookup_station(uint32_t id, char *out, size_t cap)
{
    if (out && cap) out[0] = 0;
    /* The same short wait as above: /trust asks once per row. */
    if (!s_lock || !id || xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE)
        return id ? -1 : 0;
    int found = 0;
    for (int i = 0; i < s_count; i++)
        if (s_tab[i].station_id == id)
        {
            if (out && cap) snprintf(out, cap, "%s", s_tab[i].name);
            found = 1;
            break;
        }
    xSemaphoreGive(s_lock);
    return found;
}

uint32_t inventory_vehicle_frames(void) { return s_veh_frames; }

bool inventory_overflow(void) { return s_overflow; }

#if CONFIG_ENABLE_SD

/* Fold the stored header summary into the one since boot. The newer values win, and the count
 * and the reasons add up, so this runs once per load, like the frame count. */
static void sec_fold_stored(its_sechdr_unit_t *u, const its_sechdr_unit_t *r)
{
    uint8_t take = (uint8_t)(r->has & ~u->has);
    if (take & SEC_UNIT_SIG)  u->sig_type = r->sig_type;
    if (take & SEC_UNIT_KEY)  u->key_type = r->key_type;
    if (take & SEC_UNIT_HASH) u->hash_id = r->hash_id;
    if (take & SEC_UNIT_ELEV) u->elev = r->elev;
    u->has |= take;
    u->dev_frames = r->dev_frames > UINT32_MAX - u->dev_frames ? UINT32_MAX
                                                                : u->dev_frames + r->dev_frames;
    u->dev_mask |= r->dev_mask;
}

/* Fold the stored sequence-number counts into the ones since boot. The sums saturate, and
 * this too runs once per load. */
static void gn_fold_stored(its_gn_unit_t *u, const its_gn_unit_t *r)
{
    u->got = r->got > UINT32_MAX - u->got ? UINT32_MAX : u->got + r->got;
    u->missing = r->missing > UINT32_MAX - u->missing ? UINT32_MAX : u->missing + r->missing;
    u->relayed = r->relayed > UINT32_MAX - u->relayed ? UINT32_MAX : u->relayed + r->relayed;
    u->dup = r->dup > UINT32_MAX - u->dup ? UINT32_MAX : u->dup + r->dup;
}

/* Insert or fold one restored row. The caller holds s_lock, so a whole batch
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
        /* What arrived since boot is newer than the stored copy, except for the maximum. */
        if (!s->tx_power_dbm) s->tx_power_dbm = r->tx_power_dbm;
        if (r->has_dcc) s->has_dcc = true;
        if (r->has_dcc && r->cbr_max > s->cbr_max) s->cbr_max = r->cbr_max;
        if (s->sig.kind == ITS_SIG_NONE) s->sig = r->sig;
        sec_fold_stored(&s->sec, &r->sec);
        gn_fold_stored(&s->gnu, &r->gnu);
    }
}

/* "-" or 16 lowercase hex digits, as inv_save writes an identifier. */
static bool parse_id(const char *hex, bool *has, uint8_t id[8])
{
    if (strcmp(hex, "-") == 0)
    {
        *has = false;
        return true;
    }
    if (strlen(hex) != 16)
        return false;
    for (int i = 0; i < 16; i++)
    {
        char c = hex[i];
        unsigned v = (c >= '0' && c <= '9') ? (unsigned)(c - '0')
                   : (c >= 'a' && c <= 'f') ? (unsigned)(c - 'a' + 10) : 16;
        if (v > 15)
            return false;
        id[i / 2] = (uint8_t)((i % 2) ? (id[i / 2] << 4) | v : v);
    }
    *has = true;
    return true;
}

/* One number of the header or sequence-number block: an optional '-' and 1 to 10 digits, in
 * lo..hi. By hand, because sscanf's %lu reads "-1" as 4294967295 and leaves a value past 32 bits
 * undefined. */
static const char *parse_num(const char *p, int64_t lo, int64_t hi, int64_t *v)
{
    bool neg = *p == '-';
    int64_t x = 0;
    int n = 0;
    if (neg)
        p++;
    for (; *p >= '0' && *p <= '9' && n <= 10; p++, n++)
        x = x * 10 + (*p - '0');
    if (neg)
        x = -x;
    if (n == 0 || n > 10 || x < lo || x > hi)
        return NULL;
    *v = x;
    return p;
}

/* Columns 21 to 26, the header summary, all or none, up to the line end or the next block. The
 * ranges are the ones inv_save writes, and -1 means that no header gave the value yet. Returns
 * where the block ends, NULL when it was not taken. */
static const char *parse_sec_fields(const char *p, its_sechdr_unit_t *out)
{
    static const int64_t lo[6] = { -1, -1, -1, -1, 0, 0 };
    static const int64_t hi[6] = { ITS_SEC_SIG_OTHER, ITS_SEC_KEY_OTHER, 255, 65535, UINT32_MAX,
                                   SEC_DEV_ALL };
    int64_t v[6] = { 0 };
    for (int i = 0; i < 6; i++)
    {
        p = parse_num(p, lo[i], hi[i], &v[i]);
        if (!p || (i < 5 ? *p != ',' : *p != '\0' && *p != ','))
            return NULL;
        if (i < 5)
            p++;
    }
    if (v[2] > 2 && v[2] != 255)      /* hashId: SHA-256, SHA-384, SM3, or 255 for another */
        return NULL;
    its_sechdr_unit_t u = { .dev_frames = (uint32_t)v[4], .dev_mask = (uint16_t)v[5] };
    if (v[0] >= 0) { u.sig_type = (uint8_t)v[0]; u.has |= SEC_UNIT_SIG; }
    if (v[1] >= 0) { u.key_type = (uint8_t)v[1]; u.has |= SEC_UNIT_KEY; }
    if (v[2] >= 0) { u.hash_id = (uint8_t)v[2]; u.has |= SEC_UNIT_HASH; }
    if (v[3] >= 0) { u.elev = (uint16_t)v[3]; u.has |= SEC_UNIT_ELEV; }
    *out = u;
    return p;
}

/* Columns 27 to 30, the sequence numbers (got, missing, relayed, dup), all or none and up to the
 * line end. A bad block leaves them 0 and costs no column before it. */
static void parse_gn_fields(const char *p, its_gn_unit_t *out)
{
    uint32_t v[4];
    for (int i = 0; i < 4; i++)
    {
        int64_t x;
        p = parse_num(p, 0, UINT32_MAX, &x);
        if (!p || *p != (i < 3 ? ',' : '\0'))
            return;
        v[i] = (uint32_t)x;
        if (i < 3)
            p++;
    }
    *out = (its_gn_unit_t){ .got = v[0], .missing = v[1], .relayed = v[2], .dup = v[3] };
}

/* The fields behind the name, which older files do not have. They are taken all or none. The
 * header block may follow them, and the sequence numbers may follow the header block. */
static void parse_sig_fields(const char *p, inv_station_t *r)
{
    unsigned kind, cert;
    char id[17], iss[17];
    int power, cbr, used = 0;
    if (sscanf(p, "%u,%u,%16[-0-9a-f],%16[-0-9a-f],%d,%d%n", &kind, &cert, id, iss, &power, &cbr,
               &used) != 6 || (p[used] != '\0' && p[used] != ','))
        return;
    its_sig_summary_t g = { 0 };
    if (kind > ITS_SIG_OTHER || cert > ITS_CERT_MISSING || power < -1 || power > 31 ||
        cbr < -1 || cbr > 255 || (power < 0) != (cbr < 0) ||
        !parse_id(id, &g.has_id, g.id) || !parse_id(iss, &g.has_issuer, g.issuer_id))
        return;
    g.kind = (uint8_t)kind;
    g.cert = (uint8_t)cert;
    r->sig = g;
    r->has_dcc = power >= 0;
    r->tx_power_dbm = power >= 0 ? (uint8_t)power : 0;
    r->cbr_max = cbr >= 0 ? (uint8_t)cbr : 0;
    if (p[used] == ',')
    {
        const char *q = parse_sec_fields(p + used + 1, &r->sec);
        if (q && *q == ',')
            parse_gn_fields(q + 1, &r->gnu);
    }
}

/* Staging for inv_load, applied to s_tab exactly ONCE at the end: the upsert
 * ADDS frames and rssi_sum, so a partial apply plus a retry doubles them. */
static EXT_RAM_BSS_ATTR inv_station_t s_load_tmp[INV_MAX_STATIONS];

/* A file that never reads again would stop every save for good. After INV_BAD_TICKS failures
 * in a row it goes to senders.bad (an older one is replaced), and the next save writes only the
 * rows since boot. */
static int s_read_fails;

/* One more failed read of `path`, under the SD lock: true once the file moved, else false. */
static bool inv_read_failed(const char *path)
{
    /* No file handle, no memory or the volume lock busy: the file is not at fault. */
    int e = errno;
    if (e == ENFILE || e == EMFILE || e == ENOMEM || e == ETIMEDOUT || e == EACCES)
        return false;
    if (s_read_fails < INV_BAD_TICKS)
        s_read_fails++;
    /* FS_LOCK=0: no remove or rename while a download may hold either file. */
    if (s_read_fails < INV_BAD_TICKS || sdcard_read_active() != 0)
        return false;
    remove(INV_BAD);                 /* FatFs does not rename onto an existing file */
    if (rename(path, INV_BAD) != 0)
        return false;                /* stays at the limit: the next tick tries again */
    s_read_fails = 0;
    ESP_LOGW(TAG, "%s failed to read %d times in a row, moved to %s; the list starts empty",
             path, INV_BAD_TICKS, INV_BAD);
    return true;
}

/* False = nothing was APPLIED to s_tab. The retry depends on that, because the upsert adds.
 * Until it returns true (read, nothing stored, or moved to senders.bad) the caller must not save.
 * noinline: inlined into inventory_tick, its frame would sit under inv_save as well (528
 * instead of 16 B, riscv32). */
static __attribute__((noinline)) bool inv_load(void)
{
    /* A clear landing mid-load bumps s_gen. Restoring rows read before it
     * would silently undo the wipe, so the batch is dropped and retried. */
    uint32_t gen_at_start = s_gen;
    bool over = false;
    int nload = 0;
    if (!sdcard_io_begin_timeout(2000))
        return false;
    /* Only ENOENT means nothing is stored: after a bus error (EIO) a save would put the rows since
     * boot in its place. errno is cleared: a remove() of a missing file leaves ENOENT behind. */
    const char *path = INV_CSV;
    errno = 0;
    FILE *f = fopen(path, "r");
    /* A power cut between remove() and rename() leaves only the temp file.
     * It holds the complete newer content, so prefer it over nothing. */
    if (!f && errno == ENOENT)
    {
        path = INV_TMP;
        errno = 0;
        f = fopen(path, "r");
    }
    if (!f)
    {
        /* ENOENT: nothing stored yet is a valid, complete answer */
        bool ok = errno == ENOENT || inv_read_failed(path);
        sdcard_io_end();
        return ok;
    }
    /* Name may contain spaces, so it runs to the next comma or the line end. Names never
     * hold a comma, and inv_save writes at most 308 bytes a line with its '\n' (every field
     * at the widest its C type prints). Static: only the sysmon task loads, on 4 KB of stack. */
    static EXT_RAM_BSS_ATTR char line[384];
    bool kinds = false, rest = false;
    for (;;)
    {
        /* fgets writes the last byte only when the piece fills the buffer. picolibc's fgets
         * hands back the part before a read error, so ferror is asked before the piece counts. */
        line[sizeof(line) - 1] = 1;
        if (!fgets(line, sizeof(line), f) || ferror(f))
            break;
        /* A piece that fills line[] (383 bytes or more before the LF) is skipped with the rest of
         * its line. Every row inv_save writes is shorter. */
        bool skip = rest;
        rest = line[sizeof(line) - 1] == '\0' && line[sizeof(line) - 2] != '\n';
        if (skip || rest)
            continue;
        if (line[0] == '#')
        {
            kinds = kinds || strncmp(line, INV_MARK, sizeof(INV_MARK) - 1) == 0;
            continue;
        }
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
        if (!kinds)
            r.msg_mask &= (uint16_t)~(1u << 3);
        r.has_pos = (r.lat_e7 || r.lon_e7);
        for (int i = 0; i < 6; i++) r.mac[i] = (uint8_t)m[i];
        r.has_mac = (m[0] | m[1] | m[2] | m[3] | m[4] | m[5]) != 0;

        /* Older rows put the name right after the MAC field. The four signal
         * fields are read separately, so those rows simply keep zeros. */
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
            char *more = strchr(nm, ',');
            if (more)
            {
                *more++ = '\0';
                l = strlen(nm);
                parse_sig_fields(more, &r);
            }
            if (l >= sizeof(r.name)) l = sizeof(r.name) - 1;
            memcpy(r.name, nm, l);
        }
        if (nload < INV_MAX_STATIONS)
            s_load_tmp[nload++] = r;
        else
            over = true;   /* more senders on the card than the table holds */
    }
    /* A read error ends the loop like the end of the file, and the rows after it would be lost
     * for good once inv_save runs. Nothing is applied, so the next tick reads the file again. */
    bool read_ok = !ferror(f);
    int e = errno;           /* the read error's errno, kept for inv_read_failed after fclose */
    fclose(f);
    if (!read_ok)
    {
        errno = e;
        bool moved = inv_read_failed(path);
        sdcard_io_end();
        return moved;
    }
    s_read_fails = 0;   /* read whole, so a refused lock below retries without an old count */

    /* ONE application, all or nothing: it ADDS (frames folded before the card
     * mounted must survive), so it may run only once per successful load. */
    bool ok = false;
    if (s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) == pdTRUE)
    {
        /* Cleared mid-read: applying now would resurrect what the user just
         * deleted. Drop the batch. The retry then finds the file gone. */
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

/* File scope so inventory_flush_now() honours it too: inv_save() replaces the
 * whole file, so saving before inv_load() succeeded drops the stored senders. */
static bool s_loaded;

/* Full rewrite, not append: rows keep changing, unlike the event and track
 * logs. Snapshot first so the file write never holds the table lock. */
static bool inv_save(void)
{
    static EXT_RAM_BSS_ATTR inv_station_t snap[INV_MAX_STATIONS];
    /* SD lock BEFORE the snapshot: two tasks call this and snap[] is shared.
     * Re-sorting it mid-write emits a row twice, folded again on next boot. */
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
    /* A senders.tmp without senders.csv is the only copy, so it goes back to senders.csv before
     * "w" empties it. During a download it waits, and s_dirty retries. */
    if (sdcsv_recover_tmp(INV_CSV, INV_TMP) != SDCSV_OK)
    {
        sdcard_io_end();
        return false;
    }
    FILE *f = fopen(INV_TMP, "w");
    if (!f)
    {
        sdcard_io_end();
        return false;
    }
    /* picolibc drops its 128-B buffer when a write fails, and fclose does not tell. So every row
     * is flushed and checked, and the file must be as long as the bytes written: a cut
     * senders.tmp never replaces senders.csv. */
    bool ok = fputs(INV_MARK "\n", f) >= 0;
    unsigned long written = sizeof(INV_MARK "\n") - 1;
    for (int i = 0; i < n && ok; i++)
    {
        inv_station_t *s = &snap[i];
        /* New columns only ever go at the end, so every older layout stays readable. */
        char id[17] = "-", iss[17] = "-";
        if (s->sig.has_id)
            snprintf(id, sizeof(id), "%02x%02x%02x%02x%02x%02x%02x%02x", s->sig.id[0], s->sig.id[1],
                     s->sig.id[2], s->sig.id[3], s->sig.id[4], s->sig.id[5], s->sig.id[6], s->sig.id[7]);
        if (s->sig.has_issuer)
            snprintf(iss, sizeof(iss), "%02x%02x%02x%02x%02x%02x%02x%02x",
                     s->sig.issuer_id[0], s->sig.issuer_id[1], s->sig.issuer_id[2],
                     s->sig.issuer_id[3], s->sig.issuer_id[4], s->sig.issuer_id[5],
                     s->sig.issuer_id[6], s->sig.issuer_id[7]);
        /* The header summary in the ranges parse_sec_fields accepts, -1 for a value none gave. */
        const its_sechdr_unit_t *u = &s->sec;
        int sig = !(u->has & SEC_UNIT_SIG) ? -1
                : u->sig_type < ITS_SEC_SIG_OTHER ? u->sig_type : ITS_SEC_SIG_OTHER;
        int key = !(u->has & SEC_UNIT_KEY) ? -1
                : u->key_type < ITS_SEC_KEY_OTHER ? u->key_type : ITS_SEC_KEY_OTHER;
        int hash = !(u->has & SEC_UNIT_HASH) ? -1 : u->hash_id <= 2 ? u->hash_id : 255;
        int w = fprintf(f, "%lu,%u,%lu,%lu,%lu,%u,%ld,%ld,"
                           "%02x:%02x:%02x:%02x:%02x:%02x,%d,%d,%lld,%lu,%s,%u,%u,%s,%s,%d,%d",
                    (unsigned long)s->station_id, s->station_type,
                    (unsigned long)s->first_seen, (unsigned long)s->last_seen,
                    (unsigned long)s->frames, s->msg_mask,
                    (long)s->lat_e7, (long)s->lon_e7,
                    s->mac[0], s->mac[1], s->mac[2], s->mac[3], s->mac[4], s->mac[5],
                    s->rssi_min, s->rssi_max, (long long)s->rssi_sum,
                    (unsigned long)s->rssi_cnt, s->name,
                    s->sig.kind, s->sig.cert, id, iss,
                    s->has_dcc ? (int)s->tx_power_dbm : -1,
                    s->has_dcc ? (int)s->cbr_max : -1);
        /* The header block in a call of its own: as six more arguments of the call above it
         * would sit on the 4 KB sysmon stack (inv_save 272 instead of 240 B, riscv32). */
        int w2 = w < 0 ? -1 : fprintf(f, ",%d,%d,%d,%ld,%lu,%u",
                    sig, key, hash, (u->has & SEC_UNIT_ELEV) ? (long)u->elev : -1L,
                    (unsigned long)u->dev_frames, (unsigned)(u->dev_mask & SEC_DEV_ALL));
        /* The sequence numbers go in a third call for the same reason. w2 then counts both. */
        int w3 = w2 < 0 ? -1 : fprintf(f, ",%lu,%lu,%lu,%lu\n",
                    (unsigned long)s->gnu.got, (unsigned long)s->gnu.missing,
                    (unsigned long)s->gnu.relayed, (unsigned long)s->gnu.dup);
        w2 = w3 < 0 ? -1 : w2 + w3;
        if (w2 < 0 || fflush(f) != 0 || ferror(f))
            ok = false;
        else
            written += (unsigned long)w + (unsigned long)w2;
    }
    /* Everything is flushed, so ftell only asks where the file ends. */
    long end = ok ? ftell(f) : -1;
    if (end < 0 || (unsigned long)end != written)
        ok = false;
    if (fclose(f) != 0)
        ok = false;
    if (!ok)
        remove(INV_TMP);   /* a cut copy must not wait there for inv_load's fallback */
    else if (gen != s_gen)
    {
        /* Cleared while we were writing -- discard, don't resurrect. */
        remove(INV_TMP);
        ok = false;
    }
    else if (sdcard_read_active() != 0)
    {
        /* The swap unlinks senders.csv, which a streaming download holds
         * open. Keep the live file; s_dirty retries a save interval later. */
        ok = false;
    }
    /* FatFs renames onto no existing file, so senders.csv goes first. If it stays, it still has
     * every row. */
    else if (remove(INV_CSV) != 0 && errno != ENOENT)
    {
        ESP_LOGW(TAG, "cannot remove %s, the next save tries again", INV_CSV);
        remove(INV_TMP);
        ok = false;
    }
    /* senders.csv is gone: inv_load and the next save take senders.tmp back first. */
    else if (rename(INV_TMP, INV_CSV) != 0)
    {
        ESP_LOGW(TAG, "cannot rename %s, the next save tries again", INV_TMP);
        ok = false;
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
        /* The clear could not reach the card back then. Finish it now, before
         * any save can put the old rows back. */
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
        /* Retried until it succeeds. Saving before the stored rows are back
         * would replace them with the few rows collected since boot. */
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
    /* Same precedence as the tick: this runs before a restart or power-off, so
     * finish the deferred delete instead of saving around it. */
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
