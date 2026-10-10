#include "sdkconfig.h"

#include "events_log.h"

#include <stdio.h>

/* Unix time just after each leap second since 2004. TimestampIts counts them and
 * Unix time does not, so each one passed puts TimestampIts one second further ahead. */
/* The list ends with the leap second at the end of 2016. Add any that is announced later. */
static const uint32_t EV_LEAP_UNIX[] = {
    1136073600u,   /* 2006-01-01 */
    1230768000u,   /* 2009-01-01 */
    1341100800u,   /* 2012-07-01 */
    1435708800u,   /* 2015-07-01 */
    1483228800u,   /* 2017-01-01 */
};

uint64_t events_its_to_unix_ms(uint64_t its_ms)
{
    uint64_t unix_ms = its_ms + 1072915200000ull;   /* 2004-01-01 00:00:00 UTC */
    uint64_t leaps = 0;
    for (size_t i = 0; i < sizeof(EV_LEAP_UNIX) / sizeof(EV_LEAP_UNIX[0]); i++)
        if (unix_ms - (leaps + 1) * 1000u >= (uint64_t)EV_LEAP_UNIX[i] * 1000u)
            leaps++;
    return unix_ms - leaps * 1000u;
}

uint32_t events_valid_until(const event_rec_t *e)
{
    if (e->validity_src == EVENT_VALIDITY_NONE || e->detection_ms == 0)
        return 0;
    uint64_t s = events_its_to_unix_ms(e->detection_ms) / 1000u + e->validity_s;
    return s > UINT32_MAX ? UINT32_MAX : (uint32_t)s;
}

/* validityDuration is at most 86400 s and counts from detectionTime, which never lies after
 * the last reception. The extra hour allows for a sender clock that runs ahead of ours. */
#define EV_MAX_VALID_AFTER_RX_S (86400u + 3600u)

event_state_t events_state(const event_rec_t *e, uint32_t now)
{
    if (e->termination == ITS_DENM_TERM_CANCELLATION)
        return EVENT_STATE_CANCELLED;
    if (e->termination == ITS_DENM_TERM_NEGATION)
        return EVENT_STATE_NEGATED;
    if (now < EVENTS_CLOCK_MIN)
        return EVENT_STATE_UNKNOWN;
    uint32_t until = events_valid_until(e);
    if (until)
        return now > until ? EVENT_STATE_EXPIRED : EVENT_STATE_ACTIVE;
    /* Without readable times a warning is still over for certain once that bound has passed. */
    return now > e->last_seen && now - e->last_seen > EV_MAX_VALID_AFTER_RX_S
               ? EVENT_STATE_EXPIRED : EVENT_STATE_UNKNOWN;
}

size_t events_format_row(const event_rec_t *e, char *out, size_t cap)
{
    /* New columns are APPENDED, so old readers keep finding fields 1-8 in
     * place. multi_sender goes to the card too, or a restart would lose it. */
    const uint8_t *ma = e->mac_a, *mb = e->mac_b;
    int n = snprintf(out, cap, "%lu,%u,%u,%ld,%ld,%u,%lu,%u,%lu,%d,%d,%u,"
                               "%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x,%u,%u,%u",
                     (unsigned long)e->seconds, e->station_type,
                     e->cause, (long)e->lat_e7, (long)e->lon_e7,
                     (unsigned)e->count, (unsigned long)e->last_seen,
                     (unsigned)e->subcause,
                     (unsigned long)e->sender_id,
                     e->rssi_min, e->rssi_max,
                     e->multi_sender ? 1u : 0u,
                     ma[0], ma[1], ma[2], ma[3], ma[4], ma[5],
                     mb[0], mb[1], mb[2], mb[3], mb[4], mb[5],
                     (unsigned)e->count_b, (unsigned)e->b_after_s,
                     (unsigned)e->n_macs);
    if (n < 0 || (size_t)n >= cap)
        return 0;
    size_t pos = (size_t)n;
    /* Six steps keep each argument list short enough to check by eye. */
    n = snprintf(out + pos, cap - pos, ",%lu,%u,%u,%llu,%llu,%lu,%u,%u,%ld,%ld,%u,%u,%u",
                 (unsigned long)e->action_station, (unsigned)e->action_seq,
                 (unsigned)e->termination,
                 (unsigned long long)e->detection_ms, (unsigned long long)e->reference_ms,
                 (unsigned long)e->validity_s, (unsigned)e->validity_src,
                 (unsigned)e->area_shape,
                 (long)e->area_lat_e7, (long)e->area_lon_e7,
                 (unsigned)e->area_a_m, (unsigned)e->area_b_m,
                 (unsigned)e->area_angle_deg);
    if (n < 0 || (size_t)n >= cap - pos)
        return 0;
    pos += (size_t)n;
    const event_denm_t *x = &e->denm;
    n = snprintf(out + pos, cap - pos, ",%u,%u,%u,%u,%u,%u,%u,%u,%u,%ld,%u,%u",
                 (unsigned)x->aware_dist, (unsigned)x->traffic_dir, (unsigned)x->road_type,
                 (unsigned)x->info_quality, (unsigned)x->tx_interval_ms,
                 (unsigned)x->n_traces, (unsigned)x->path_len,
                 (unsigned)x->speed_cms, (unsigned)x->heading_ddeg, (long)x->alt_cm,
                 (unsigned)x->origin_type, (unsigned)x->n_hist);
    if (n < 0 || (size_t)n >= cap - pos)
        return 0;
    pos += (size_t)n;
    n = snprintf(out + pos, cap - pos, ",%u,%u,%u,%u,%u,%u",
                 (unsigned)e->gn_mhl, (unsigned)e->gn_hops_min, (unsigned)e->gn_hops_max,
                 (unsigned)e->gn_got, (unsigned)e->gn_relayed, (unsigned)e->gn_missing);
    if (n < 0 || (size_t)n >= cap - pos)
        return 0;
    pos += (size_t)n;
    const uint8_t *mo = e->orig_mac, *mr = e->relay_mac;
    n = snprintf(out + pos, cap - pos, ",%02x%02x%02x%02x%02x%02x,%02x%02x%02x%02x%02x%02x,%d,%d",
                 mo[0], mo[1], mo[2], mo[3], mo[4], mo[5], mr[0], mr[1], mr[2], mr[3], mr[4], mr[5],
                 e->relay_rssi_min, e->relay_rssi_max);
    if (n < 0 || (size_t)n >= cap - pos)
        return 0;
    pos += (size_t)n;
    /* Column 53 alone: events_read takes it as a block of its own behind 49-52. */
    const uint8_t *mg = e->gn_src_mid;
    n = snprintf(out + pos, cap - pos, ",%02x%02x%02x%02x%02x%02x\n",
                 mg[0], mg[1], mg[2], mg[3], mg[4], mg[5]);
    if (n < 0 || (size_t)n >= cap - pos)
        return 0;
    return pos + (size_t)n;
}

#if CONFIG_ENABLE_SD

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_attr.h"

#include "config.h"
#include "sd_rcache.h"
#include "sdcard.h"

static const char TAG[] = "EVENTS";

#define EV_DIR   CONFIG_SNIFFER_MOUNT_POINT "/logs"
#define EV_CSV   EV_DIR "/events.csv"

/* Events awaiting an SD write, drained by the sysmon tick so SD I/O never
 * blocks the sniffer path. On overflow the oldest queued event is dropped. */
#define EV_EVENT_GAP_SEC 120  /* silence after which an event counts as over */
#define EV_QUEUE  32
/* In PSRAM like the message ring: 4864 bytes of records are too much internal RAM. */
static EXT_RAM_BSS_ATTR event_rec_t s_queue[EV_QUEUE];
static int s_qhead, s_qcount;
/* Monotone: a ring-index delta cannot tell "nothing moved" from exactly
 * EV_QUEUE evictions. Never reset; only compared across one write. */
static uint32_t s_evicted;
static SemaphoreHandle_t s_lock;
static uint32_t s_flushes;

void events_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

/* Events still being repeated, held back so their count can keep rising.
 * SEVERAL slots: senders interleave, so a single slot would flush on every swap. */
#define EV_OPEN 8
static EXT_RAM_BSS_ATTR event_rec_t s_open[EV_OPEN];
static bool s_open_valid[EV_OPEN];

/* Closed events kept in RAM for events_current: a warning can stay valid for a
 * day after its last repeat, long after its row went to the card. */
#define EV_RECENT (EVENTS_CURRENT_MAX - EV_OPEN)
static EXT_RAM_BSS_ATTR event_rec_t s_recent[EV_RECENT];
static bool s_recent_valid[EV_RECENT];
/* Latest moment a displaced record could still have been valid, 0 = none displaced. */
static uint32_t s_lost_until;

static inline bool ev_same_action(const event_rec_t *a, const event_rec_t *b)
{
    return a->action_station == b->action_station && a->action_seq == b->action_seq;
}

/* How long a record can matter: until it ends, or with an unknown validity until
 * events_state counts it as expired. */
static uint32_t ev_relevant_until(const event_rec_t *e)
{
    if (e->termination != ITS_DENM_TERM_NONE)
        return e->last_seen;
    uint32_t u = events_valid_until(e);
    if (u)
        return u;
    return e->last_seen > UINT32_MAX - EV_MAX_VALID_AFTER_RX_S
               ? UINT32_MAX : e->last_seen + EV_MAX_VALID_AFTER_RX_S;
}

/* Keeps a closed event, replacing an older record of the same ActionID. When
 * full, the record that stopped mattering first makes room. */
static void ev_recent_put_locked(const event_rec_t *e, uint32_t now)
{
    int slot = -1;
    for (int i = 0; i < EV_RECENT && slot < 0; i++)
        if (s_recent_valid[i] && ev_same_action(&s_recent[i], e))
            slot = i;
    if (slot < 0)
    {
        uint32_t least = UINT32_MAX;
        for (int i = 0; i < EV_RECENT; i++)
        {
            if (!s_recent_valid[i]) { slot = i; break; }
            uint32_t r = ev_relevant_until(&s_recent[i]);
            if (slot < 0 || r < least) { least = r; slot = i; }
        }
        /* A displaced record that may still be valid leaves events_current incomplete. */
        if (s_recent_valid[slot] && s_recent[slot].termination == ITS_DENM_TERM_NONE &&
            least >= now && least > s_lost_until)
            s_lost_until = least;
    }
    s_recent[slot] = *e;
    s_recent_valid[slot] = true;
}

/* A slot reopened by a late repeat starts from what RAM still knows about its
 * ActionID, so an old repeat cannot bring back a warning that has ended. */
/* The gn_* fields, the addresses and the forwarder's level are not inherited. Like the level
 * and the MACs, they describe one stretch only. */
static void ev_recent_inherit_locked(event_rec_t *e)
{
    for (int i = 0; i < EV_RECENT; i++)
    {
        if (!s_recent_valid[i] || !ev_same_action(&s_recent[i], e))
            continue;
        const event_rec_t *r = &s_recent[i];
        e->cause = r->cause;
        e->subcause = r->subcause;
        e->detection_ms = r->detection_ms;
        e->reference_ms = r->reference_ms;
        e->validity_s = r->validity_s;
        e->validity_src = r->validity_src;
        e->termination = r->termination;
        e->area_shape = r->area_shape;
        e->area_a_m = r->area_a_m;
        e->area_b_m = r->area_b_m;
        e->area_angle_deg = r->area_angle_deg;
        e->area_lat_e7 = r->area_lat_e7;
        e->area_lon_e7 = r->area_lon_e7;
        e->denm = r->denm;
        return;
    }
}

/* A field left out keeps the known value: a termination usually sends none of them. Called
 * for the newest version only, so an older one changes nothing. */
static void ev_denm_fold(event_denm_t *x, const its_decoded_t *d)
{
    if (d->denm_aware_dist != ITS_DENM_DIST_NONE) x->aware_dist = d->denm_aware_dist;
    if (d->denm_traffic_dir != ITS_DENM_DIR_NONE) x->traffic_dir = d->denm_traffic_dir;
    if (d->denm_road_type != ITS_DENM_ROAD_NONE) x->road_type = d->denm_road_type;
    if (d->denm_info_quality != ITS_DENM_QUALITY_NONE) x->info_quality = d->denm_info_quality;
    if (d->denm_tx_interval_ms) x->tx_interval_ms = d->denm_tx_interval_ms;
    /* A pair: the point count belongs to the traces it was counted in. */
    if (d->denm_n_traces)
    {
        x->n_traces = d->denm_n_traces;
        x->path_len = d->denm_path_len;
    }
    if (d->denm_has_speed) x->speed_cms = d->denm_speed_cms;
    if (d->denm_has_heading) x->heading_ddeg = d->denm_heading_ddeg;
    if (d->denm_has_alt) x->alt_cm = d->denm_alt_cm;
    if (d->denm_station_type != ITS_DENM_STATION_NONE) x->origin_type = d->denm_station_type;
    if (d->denm_n_hist) x->n_hist = d->denm_n_hist;
}

/* Folds one DENM's times, termination, cause, area and other fields into `e`. The newest
 * referenceTime wins: repeats keep theirs, while an update or a termination gets a later one. */
static void ev_state_fold(event_rec_t *e, const its_decoded_t *d)
{
    if (!d)
        return;
    /* A readable ManagementContainer always yields a validity, the sent one or 600. */
    bool read = d->denm_validity_sent || d->denm_validity_s != 0;
    bool newer = read && d->denm_reference_ms > e->reference_ms;
    bool same = read && d->denm_reference_ms == e->reference_ms;
    /* A termination counts whatever its referenceTime says: a negation comes from another
     * station, whose clock may lag. Only a later version without one revives the warning. */
    if (d->denm_termination != ITS_DENM_TERM_NONE)
        e->termination = d->denm_termination;
    else if (newer)
        e->termination = ITS_DENM_TERM_NONE;
    /* Only a newer version may change the cause. A termination often leaves out the
     * situation container, and its missing cause must not erase the known one. */
    if (newer && d->denm_cause != 0)
    {
        e->cause = d->denm_cause;
        e->subcause = d->denm_subcause;
    }
    /* Without readable times the order is unknown, and only the area can update. */
    bool current = !read || newer || same;
    if (read && current)
    {
        e->detection_ms = d->denm_detection_ms;
        e->reference_ms = d->denm_reference_ms;
        e->validity_s = d->denm_validity_s;
        e->validity_src = d->denm_validity_sent ? EVENT_VALIDITY_SENT : EVENT_VALIDITY_DEFAULT;
        ev_denm_fold(&e->denm, d);
    }
    /* A frame without an area, such as a single-hop relay, keeps the known one. */
    if (current && d->gn_area_shape != ITS_GN_AREA_NONE)
    {
        e->area_shape = d->gn_area_shape;
        e->area_a_m = d->gn_area_a_m;
        e->area_b_m = d->gn_area_b_m;
        e->area_angle_deg = d->gn_area_angle_deg;
        e->area_lat_e7 = d->gn_area_lat_e7;
        e->area_lon_e7 = d->gn_area_lon_e7;
    }
}

static void queue_locked(const event_rec_t *e)
{
    int i = (s_qhead + s_qcount) % EV_QUEUE;
    s_queue[i] = *e;
    if (s_qcount < EV_QUEUE)
        s_qcount++;
    else
    {
        s_qhead = (s_qhead + 1) % EV_QUEUE;   /* overwrite oldest */
        s_evicted++;
    }
}

/* 0 dBm is "the driver had no reading" (wired path), not a level -- it must
 * neither open nor widen the span. */
static inline void ev_span_fold(int8_t *lo, int8_t *hi, int rssi)
{
    if (rssi >= 0 || rssi <= -128)
        return;
    if (!*hi || rssi > *hi) *hi = (int8_t)rssi;
    if (!*lo || rssi < *lo) *lo = (int8_t)rssi;
}

static inline void ev_rssi_fold(event_rec_t *e, int rssi)
{
    ev_span_fold(&e->rssi_min, &e->rssi_max, rssi);
}

/* Who the stretch came from and through whom, from frames of sender_id only (the caller checks):
 * the first address with 0 hops, and the first forwarder with the level of its own frames. */
static void ev_path_fold(event_rec_t *e, const uint8_t *mac, int rssi, int hops)
{
    static const uint8_t Z[6];
    if (hops == 0)
    {
        /* An address that already passed the warning on is a forwarder, whatever it sends later. */
        if (!memcmp(e->orig_mac, Z, 6) && memcmp(e->relay_mac, mac, 6))
            memcpy(e->orig_mac, mac, 6);
        return;
    }
    if (hops < 0)   /* a header that does not say or contradicts itself proves neither */
        return;
    /* All zero stands for "none": such a forwarder could not be told from the next one. */
    if (!memcmp(mac, Z, 6))
        return;
    if (!memcmp(e->relay_mac, Z, 6))
        memcpy(e->relay_mac, mac, 6);
    else if (memcmp(e->relay_mac, mac, 6))
        return;   /* a second forwarder: its level would mix another radio path into the first's */
    ev_span_fold(&e->relay_rssi_min, &e->relay_rssi_max, rssi);
}

/* Whether a frame came from the kept forwarder. All zero is none: ev_path_fold keeps no such
 * address, so an all-zero sender must not match an empty relay_mac. */
static inline bool ev_from_relay(const event_rec_t *e, const uint8_t *mac)
{
    static const uint8_t Z[6];
    return mac && memcmp(e->relay_mac, Z, 6) && !memcmp(e->relay_mac, mac, 6);
}

/* The MID of the GN source address, which forwarders keep: the originator's even when only
 * forwarders were heard. The first frame of sender_id counts. An unreadable header gives none. */
static inline void ev_mid_fold(event_rec_t *e, const its_gn_t *gn, int hops)
{
    static const uint8_t Z[6];
    /* hops >= 0 first: its_gn_hops gives -1 for a NULL gn. */
    if (hops >= 0 && gn->has_lpv && !memcmp(e->gn_src_mid, Z, 6))
        memcpy(e->gn_src_mid, gn->addr + 2, 6);
}

/* A second radio address on one ActionID means the warning was re-broadcast;
 * the station id stays the originator's, so only this can show it. */
static void ev_mac_fold(event_rec_t *e, const uint8_t *mac, uint32_t seconds)
{
    if (!e->n_macs)
    {
        memcpy(e->mac_a, mac, 6);
        e->n_macs = 1;
        return;
    }
    if (memcmp(e->mac_a, mac, 6) == 0)
        return;
    if (!e->count_b)
    {
        memcpy(e->mac_b, mac, 6);
        uint32_t d = seconds > e->seconds ? seconds - e->seconds : 0;
        e->b_after_s = d > 0xFFFFu ? 0xFFFFu : (uint16_t)d;
        e->n_macs = 2;
    }
    if (memcmp(e->mac_b, mac, 6) == 0)
    {
        if (e->count_b < 0xFFFF) e->count_b++;
    }
    else if (e->n_macs < 255)
        e->n_macs++;
}

/* How the stretch travelled, from every frame of it. The counts follow its_gn_unit_fold,
 * saturating at 65535: DUP, OLD and NONE change nothing. */
static void ev_gn_fold(event_rec_t *e, const its_gn_t *gn, int hops)
{
    if (!gn)
        return;
    /* hops < mhl holds for every readable count, and events_read accepts no other row. */
    if (hops >= 0 && hops < gn->mhl)
    {
        uint8_t h = (uint8_t)hops;
        if (!e->gn_mhl)
        {
            e->gn_hops_min = e->gn_hops_max = h;
            e->gn_mhl = gn->mhl;
        }
        else
        {
            if (h < e->gn_hops_min) e->gn_hops_min = h;
            if (h > e->gn_hops_max) e->gn_hops_max = h;
            /* The newest limit, unless an earlier frame passed more forwarders than it allows. */
            if (gn->mhl > e->gn_hops_max) e->gn_mhl = gn->mhl;
        }
    }
    uint8_t c = gn->sn_cls;
    if (c != GN_SN_FIRST && c != GN_SN_NEW && c != GN_SN_LATE)
        return;
    if (e->gn_got < 0xFFFF) e->gn_got++;
    if (hops > 0 && e->gn_relayed < 0xFFFF) e->gn_relayed++;
    if (c == GN_SN_NEW)
        e->gn_missing = (unsigned)gn->gap > 0xFFFFu - e->gn_missing
                            ? 0xFFFFu : (uint16_t)(e->gn_missing + gn->gap);
    /* A late number fills a gap counted before. A saturated count no longer knows which. */
    else if (c == GN_SN_LATE && e->gn_missing > 0 && e->gn_missing < 0xFFFF)
        e->gn_missing--;
}

void events_note(uint32_t seconds, uint8_t station_type, uint32_t sender_id, int rssi,
                 uint8_t message_id,
                 uint8_t cause, uint8_t subcause,
                 uint32_t action_station, uint16_t action_seq,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7,
                 const uint8_t *src_mac, const its_decoded_t *d, const its_gn_t *gn)
{
    if (message_id != 1 || !s_lock)   /* 1 = DENM (warning) */
        return;
    /* Reject pre-clock timestamps: before the clock is set the row would carry
     * a 1970 date that no time window of the last hours can match. */
    if (seconds < EVENTS_CLOCK_MIN)
        return;
    /* A forwarder's level is not the sender's. Headers that do not say count as direct. */
    int hops = its_gn_hops(gn);   /* -1 for NULL */
    bool direct = hops <= 0;
    if (xSemaphoreTake(s_lock, 0) != pdTRUE)
        return;

    /* An ActionID of 0/0 would fold every warning from every sender into one
     * row. Synthesise an identity from the sender and the cause instead. */
    if (action_station == 0 && action_seq == 0)
    {
        action_station = sender_id;
        action_seq = (uint16_t)((cause << 8) | subcause);
    }

    /* Already tracking this event? Then this is another broadcast of it. Count
     * it and keep the newest position. */
    int free_slot = -1, oldest = 0;
    for (int i = 0; i < EV_OPEN; i++)
    {
        if (!s_open_valid[i])
        {
            if (free_slot < 0) free_slot = i;
            continue;
        }
        if (s_open[i].action_station == action_station &&
            s_open[i].action_seq == action_seq)
        {
            s_open[i].last_seen = seconds;
            if (s_open[i].count < 0xFFFF) s_open[i].count++;
            if (src_mac) ev_mac_fold(&s_open[i], src_mac, seconds);
            if (has_pos) { s_open[i].lat_e7 = lat_e7; s_open[i].lon_e7 = lon_e7; }
            /* Keep the level only while it belongs to the stored sender and the frame came
             * straight from it. An id of 0 means unknown: it neither matches nor proves a
             * second sender. */
            if (sender_id && (!s_open[i].sender_id || s_open[i].sender_id == sender_id))
            {
                s_open[i].sender_id = sender_id;   /* adopt the first id we learn */
                /* A forwarder stays one whatever it sends later: no frame from the kept relay_mac
                 * gives the sender's level, not even with 0 hops. */
                if (ev_from_relay(&s_open[i], src_mac))
                    direct = false;
                if (direct)
                    ev_rssi_fold(&s_open[i], rssi);
                /* The same frames name who it came from. The GN source needs no 802.11 address. */
                if (src_mac)
                    ev_path_fold(&s_open[i], src_mac, rssi, hops);
                ev_mid_fold(&s_open[i], gn, hops);
            }
            else if (sender_id)
                s_open[i].multi_sender = true;
            ev_state_fold(&s_open[i], d);
            ev_gn_fold(&s_open[i], gn, hops);
            xSemaphoreGive(s_lock);
            return;
        }
        if (s_open[i].last_seen < s_open[oldest].last_seen)
            oldest = i;
    }

    int slot = free_slot;
    if (slot < 0)
    {
        slot = oldest;                 /* all busy: the stalest one is done */
        queue_locked(&s_open[slot]);
        ev_recent_put_locked(&s_open[slot], seconds);
    }

    /* No id, no level: a synthesised ActionID groups unknown senders, and their span would be an
     * artefact. A relayed level is the forwarder's. A new slot has no forwarder yet to exclude. */
    int8_t r0 = (direct && sender_id && rssi < 0 && rssi > -128) ? (int8_t)rssi : 0;

    s_open[slot] = (event_rec_t){
        .seconds = seconds, .last_seen = seconds,
        .action_station = action_station, .action_seq = action_seq,
        .count = 1, .station_type = station_type, .cause = cause,
        .subcause = subcause,
        .lat_e7 = has_pos ? lat_e7 : 0, .lon_e7 = has_pos ? lon_e7 : 0,
        .sender_id = sender_id, .rssi_min = r0, .rssi_max = r0,
        .multi_sender = false,
        .denm = EVENT_DENM_UNSENT,
    };
    /* The literal above already zeroed mac_a. An array cannot be filled from a
     * pointer inside an initialiser, so copy it here. */
    if (src_mac) { memcpy(s_open[slot].mac_a, src_mac, 6); s_open[slot].n_macs = 1; }
    /* As for r0: a frame without an id is not known to be the sender's, so it names no one. */
    if (src_mac && sender_id)
        ev_path_fold(&s_open[slot], src_mac, rssi, hops);
    if (sender_id)
        ev_mid_fold(&s_open[slot], gn, hops);
    ev_recent_inherit_locked(&s_open[slot]);
    ev_state_fold(&s_open[slot], d);
    ev_gn_fold(&s_open[slot], gn, hops);
    s_open_valid[slot] = true;

    xSemaphoreGive(s_lock);
}

#define EV_TMP   EV_DIR "/events.tmp"

/* For prune and the tail mend. Static, because the sysmon stack has only 4096 bytes. The SD
 * lock held by events_tick serialises the two callers. */
static EXT_RAM_BSS_ATTR char s_line[EVENTS_LINE_MAX];
static EXT_RAM_BSS_ATTR char s_row[EVENTS_LINE_MAX];
/* The last append failed and said so: one warning per streak of failures. */
static bool s_warned;

/* The rows of events.csv that end at s_rc_from or later, oldest first, with their ends, and
 * events_read's place in the file. A refresh of /traffic then reads only what was added. */
#define EV_RC 256
static EXT_RAM_BSS_ATTR event_rec_t s_rc_rows[EV_RC];
static EXT_RAM_BSS_ATTR uint32_t s_rc_end[EV_RC];
static int s_rc_n;
static uint32_t s_rc_from;
/* The latest end of a row that left the full cache: up to there, older rows may still count. */
static uint32_t s_rc_gone;
static bool s_rc_any_gone;
static EXT_RAM_BSS_ATTR sdrc_t s_rc;
/* Counts prunes and failed writes, because the anchor misses a prune that keeps the bytes
 * before the place. All of it under the SD lock. */
static uint32_t s_rgen;
/* The reader's line, httpd only and under the SD lock: 448 B less on its stack for the cache. */
static EXT_RAM_BSS_ATTR char s_rd[EVENTS_LINE_MAX];

/* fgets for both readers. *whole says that the piece is one row with its '\n'. A lost sector
 * reads as NUL bytes that hide the '\n' from strlen. fgets writes b's last byte only when the
 * piece fills b. */
static bool ev_gets(char *b, size_t cap, FILE *f, bool *rest, bool *whole)
{
    b[cap - 1] = 1;
    if (!fgets(b, (int)cap, f))
        return false;
    size_t len = strlen(b);
    bool skip = *rest;
    /* A full piece without '\n' at its end is a row wider than b: the next piece is its rest. */
    *rest = b[cap - 1] == '\0' && b[cap - 2] != '\n';
    /* A NUL inside or no '\n' at the end (a cut last row) drops this piece alone. */
    *whole = !skip && !*rest && len > 0 && b[len - 1] == '\n';
    return true;
}

/* Streams to a temp file and swaps: a fixed read-all buffer silently drops the
 * NEWEST rows once the file outgrows it. */
static void prune(uint32_t keep_from_sec)
{
    FILE *f = fopen(EV_CSV, "r");
    if (!f)
        return;
    FILE *w = fopen(EV_TMP, "w");
    if (!w)
    {
        fclose(f);
        return;
    }

    /* Whole rows only. picolibc's fgets hands back the part before a read error. */
    bool ok = true, rest = false, whole;
    while (ev_gets(s_line, sizeof(s_line), f, &rest, &whole))
    {
        if (ferror(f)) { ok = false; break; }
        if (!whole)
            continue;
        unsigned long sec = strtoul(s_line, NULL, 10);
        if (sec < keep_from_sec)
            continue;
        if (fputs(s_line, w) == EOF) { ok = false; break; }
    }
    /* A read error ends fgets like EOF would, and the swap would delete every row after it. */
    if (ferror(f))
        ok = false;
    fclose(f);
    /* picolibc's fclose hides a failed flush: without this a cut events.tmp would replace
     * events.csv. */
    if (ok && (fflush(w) != 0 || ferror(w)))
        ok = false;
    if (fclose(w) != 0)
        ok = false;

    if (!ok)
        remove(EV_TMP);
    /* FatFs does not rename onto an existing file, so events.csv goes first. If it stays, it
     * still has every row. */
    else if (remove(EV_CSV) != 0)
    {
        ESP_LOGW(TAG, "cannot remove %s, the next prune tries again", EV_CSV);
        remove(EV_TMP);
    }
    /* events.csv is gone: ev_recover_tmp renames events.tmp before the next append. */
    else if (rename(EV_TMP, EV_CSV) != 0)
        ESP_LOGW(TAG, "cannot rename %s, the next write tries again", EV_TMP);
}

enum { EV_OK, EV_WAIT, EV_FAIL };

/* A power cut between prune's remove and rename leaves only events.tmp, with every row: it
 * becomes events.csv again before an append, or the next prune would overwrite it. */
static int ev_recover_tmp(void)
{
    struct stat st;
    if (stat(EV_CSV, &st) == 0)
        return EV_OK;
    /* A tmp that cannot be checked may hold every row, so only ENOENT means there is none. After
     * a stat error of events.csv the rename runs too. That is safe, because FatFs does not rename
     * onto an existing file. */
    if (stat(EV_TMP, &st) != 0)
        return errno == ENOENT ? EV_OK : EV_FAIL;
    /* FS_LOCK=0: no rename under a download, and no new events.csv beside it either. */
    if (sdcard_read_active() != 0)
        return EV_WAIT;
    return rename(EV_TMP, EV_CSV) == 0 ? EV_OK : EV_FAIL;
}

/* A row cut by power or a card error (FatFs keeps what a failed write got out) is removed: the
 * lenient reader would take its start for an old short row, and the next row would glue on. */
static int ev_mend_tail(FILE *f, const char **fail)
{
    char last = '\n';
    *fail = "read";
    long size = fseek(f, 0, SEEK_END) == 0 ? ftell(f) : -1;
    if (size < 0 || (size > 0 && (fseek(f, size - 1, SEEK_SET) != 0 || fread(&last, 1, 1, f) != 1)))
        return EV_FAIL;
    if (last != '\n')
    {
        /* FS_LOCK=0: no truncation under a download. The rows wait for it to end. */
        if (sdcard_read_active() != 0)
            return EV_WAIT;
        long back = size < EVENTS_LINE_MAX ? size : EVENTS_LINE_MAX, i;
        if (fseek(f, size - back, SEEK_SET) != 0 || fread(s_line, 1, (size_t)back, f) != (size_t)back)
            return EV_FAIL;
        for (i = back - 1; i >= 0 && s_line[i] != '\n'; i--)
            ;
        *fail = "mend";
        if (i >= 0 || back == size)
        {
            /* fflush first: picolibc seeks back over what fread buffered, and after the cut that
             * seek could make FatFs grow the file again. A file of one cut row ends up empty. */
            if (fflush(f) != 0 || ftruncate(fileno(f), (off_t)(size - back + i + 1)) != 0)
                return EV_FAIL;
        }
        /* Wider than any row: it only gets a line end, and both readers skip it whole. */
        else if (fseek(f, 0, SEEK_END) != 0 || fputs("\n", f) == EOF || fflush(f) != 0)
            return EV_FAIL;
    }
    /* 'a+' reads and writes one FILE: C wants a positioning call between the two. */
    return fseek(f, 0, SEEK_END) == 0 ? EV_OK : EV_FAIL;
}

void events_tick(void)
{
    if (!s_lock)
        return;

    /* An event that has gone quiet is finished. Hand it to the queue so it
     * appears without waiting for the next warning. */
    if (xSemaphoreTake(s_lock, 0) == pdTRUE)
    {
        uint32_t now = (uint32_t)time(NULL);
        for (int i = 0; i < EV_OPEN; i++)
            if (s_open_valid[i] && now > s_open[i].last_seen &&
                now - s_open[i].last_seen > EV_EVENT_GAP_SEC)
            {
                queue_locked(&s_open[i]);
                ev_recent_put_locked(&s_open[i], now);
                s_open_valid[i] = false;
            }
        xSemaphoreGive(s_lock);
    }

    if (s_qcount == 0 || !sdcard_is_mounted())
        return;

    /* Guards append and prune against unmount/format and a concurrent
     * events_read(). Bounded: sysmon is the watchdog task and must not block. */
    if (!sdcard_io_begin_timeout(2000))
        return;

    /* Copy WITHOUT consuming; clear the queue only once the rows are on the
     * card, or a failed fopen throws the warnings away for good. */
    /* In PSRAM: 4864 bytes are too much scarce internal RAM for a buffer that
     * only the sysmon tick touches, never the packet path. */
    static EXT_RAM_BSS_ATTR event_rec_t batch[EV_QUEUE];
    int count;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE)
    {
        sdcard_io_end();
        return;
    }
    count = s_qcount;
    /* RE-CHECK under the lock: events_tick has two callers on different tasks,
     * so the other can drain the queue while we wait on the SD guard. */
    if (count == 0)
    {
        xSemaphoreGive(s_lock);
        sdcard_io_end();
        return;
    }
    uint32_t evicted_at_copy = s_evicted;
    for (int i = 0; i < count; i++)
        batch[i] = s_queue[(s_qhead + i) % EV_QUEUE];
    xSemaphoreGive(s_lock);

    mkdir(EV_DIR, 0777);
    const char *fail = "tmp rename";
    int r = ev_recover_tmp();
    FILE *f = NULL;
    if (r == EV_OK)
    {
        fail = "open";
        f = fopen(EV_CSV, "a+");
        r = f ? ev_mend_tail(f, &fail) : EV_FAIL;
    }
    /* Rows that left the batch: on the card, or lost as wider than a line. */
    int written = 0;
    uint32_t newest = 0;
    for (int i = 0; i < count && r == EV_OK; i++)
    {
        if (!events_format_row(&batch[i], s_row, sizeof(s_row)))
        {
            /* Only a stale EVENTS_LINE_MAX gets here. If kept, the row would block the queue. */
            ESP_LOGE(TAG, "event row wider than %u B, lost", (unsigned)EVENTS_LINE_MAX);
            written++;
            continue;
        }
        /* picolibc drops its whole 128-B buffer when a write fails, with an earlier row's tail
         * in it, and fclose hides a failed flush. Flushed row by row, a failure costs only
         * this row. */
        if (fputs(s_row, f) == EOF || fflush(f) != 0)
        {
            r = EV_FAIL;
            fail = "write";
            break;
        }
        written++;
        if (batch[i].seconds > newest) newest = batch[i].seconds;
    }
    /* The commit point: FatFs may not have the rows without it, so every one stays queued. */
    if (f && fclose(f) != 0)
    {
        if (r != EV_FAIL)
            fail = "close";
        r = EV_FAIL;
        written = 0;
    }
    /* Waiting for a download is no failure and ends no streak. A failed write starts the reader
     * at 0 (as in priolog.c). */
    if (r == EV_FAIL)
        s_rgen++;
    if (r == EV_FAIL && !s_warned)
        ESP_LOGW(TAG, "%s: %s failed, %d rows stay queued", EV_CSV, fail, count - written);
    if (r != EV_WAIT)
        s_warned = r == EV_FAIL;
    /* An eviction meanwhile means we cannot say which entries were ours: drop
     * none, duplicates beat wrong deletions. No timeout -- already committed. */
    if (written > 0 && xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE)
    {
        if (s_evicted == evicted_at_copy)
        {
            int drop = written < s_qcount ? written : s_qcount;
            s_qhead = (s_qhead + drop) % EV_QUEUE;
            s_qcount -= drop;
        }
        else
            ESP_LOGW(TAG, "event queue overran during the write, %d rows may repeat", written);
        xSemaphoreGive(s_lock);
    }

    /* %32==1, not ==0: the counter restarts at every boot, so a device that
     * reboots often would never reach a first prune. `newest` is defensive. */
    /* Only after a whole append: a card that just failed is not rewritten. */
    if (r == EV_OK && newest && ++s_flushes % 32 == 1)
    {
        uint32_t days = 30;
        config_get_u32(CONFIG_INDEX_EVENT_RETAIN_DAYS, &days);
        if (days == 0 || days > 30) days = 30;
        /* Never let the cutoff wrap: an underflowed cutoff keeps nothing and
         * deletes the entire history. */
        uint32_t span = days * 86400u;
        /* Unlinking events.csv under an in-flight download truncates it --
         * FATFS is built with FS_LOCK=0 and will not refuse. */
        if (sdcard_read_active() == 0)
        {
            prune(newest > span ? newest - span : 0);
            s_rgen++;
        }
        else
            s_flushes--;
    }
    sdcard_io_end();
}

/* A planned restart or power-off writes the running warnings too, as if each had gone quiet
 * now. RAM would lose them. One that is still sent afterwards opens a second row. */
void events_flush_now(void)
{
    if (!s_lock)
        return;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(200)) == pdTRUE)
    {
        uint32_t now = (uint32_t)time(NULL);
        for (int i = 0; i < EV_OPEN; i++)
            if (s_open_valid[i])
            {
                queue_locked(&s_open[i]);
                ev_recent_put_locked(&s_open[i], now);
                s_open_valid[i] = false;
            }
        xSemaphoreGive(s_lock);
    }
    events_tick();
}

uint32_t events_evicted(void) { return s_evicted; }

/* 12 hex digits back into 6 bytes; anything shorter leaves the address zeroed. */
static void ev_hex_mac(const char *hex, uint8_t *out)
{
    if (strlen(hex) != 12)
        return;
    for (int i = 0; i < 6; i++)
    {
        char b[3] = { hex[i * 2], hex[i * 2 + 1], 0 };
        out[i] = (uint8_t)strtoul(b, NULL, 16);
    }
}

/* Columns 49 to 52, all or none, ended by the line end or by column 53. A bad block costs no
 * column before it. Older rows stop at column 48 and never get here. */
static void ev_parse_path(const char *p, event_rec_t *e)
{
    static const uint8_t Z[6];
    char om[13] = "", rm[13] = "";
    int lo = 0, hi = 0, n = 0;
    if (sscanf(p, "%12[0-9a-fA-F],%12[0-9a-fA-F],%d,%d%n", om, rm, &lo, &hi, &n) != 4 ||
        (p[n] != '\n' && p[n] != ',') || strlen(om) != 12 || strlen(rm) != 12)
        return;
    ev_hex_mac(om, e->orig_mac);
    ev_hex_mac(rm, e->relay_mac);
    /* A span only as a valid pair and with its forwarder, as columns 10 and 11. */
    if (lo < 0 && lo > -128 && hi < 0 && hi > -128 && lo <= hi && memcmp(e->relay_mac, Z, 6))
    {
        e->relay_rssi_min = (int8_t)lo;
        e->relay_rssi_max = (int8_t)hi;
    }
    /* Column 53 on its own, exactly up to the line end: a bad one costs only itself. */
    char mm[13] = "";
    int k = 0;
    if (p[n] == ',' && sscanf(p + n + 1, "%12[0-9a-fA-F]%n", mm, &k) == 1 && p[n + 1 + k] == '\n')
        ev_hex_mac(mm, e->gn_src_mid);   /* 12 digits or nothing */
}

/* Keeps the newest `cap` rows of a[] in file order and returns their count: a full array lets
 * its oldest go. With ends (the cache), s_rc_gone keeps the latest end of those that left. */
static int ev_keep(event_rec_t *a, uint32_t *ends, int cap, int n, const event_rec_t *e,
                   uint32_t end)
{
    if (n == cap)
    {
        if (ends && (!s_rc_any_gone || ends[0] > s_rc_gone))
            s_rc_gone = ends[0];
        if (ends)
            s_rc_any_gone = true;
        memmove(a, a + 1, (size_t)(cap - 1) * sizeof(*a));
        if (ends)
            memmove(ends, ends + 1, (size_t)(cap - 1) * sizeof(*ends));
        n--;
    }
    a[n] = *e;
    if (ends)
        ends[n] = end;
    return n + 1;
}

/* A row that ends before the window never matches again, so the cache starts at `from`. */
static void ev_rc_start(uint32_t from, bool resumed)
{
    int k = 0;
    for (int i = 0; resumed && i < s_rc_n; i++)
        if (s_rc_end[i] >= from)
        {
            s_rc_rows[k] = s_rc_rows[i];
            s_rc_end[k++] = s_rc_end[i];
        }
    s_rc_n = k;
    s_rc_from = from;
    if (!resumed)
        s_rc_any_gone = false;
}

/* The newest `max` of the cache, oldest first: the rows a full read keeps in out[]. */
static int ev_rc_out(event_rec_t *out, int max)
{
    int k = s_rc_n < max ? s_rc_n : max;
    memcpy(out, s_rc_rows + s_rc_n - k, (size_t)k * sizeof(*out));
    return k;
}

int events_read(uint32_t hours, event_rec_t *out, int max, bool *history_ok,
                bool *capped)
{
    if (history_ok)
        *history_ok = true;
    if (capped)
        *capped = false;
    if (max <= 0)
        return 0;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint32_t from = (tv.tv_sec > (long)hours * 3600) ? (uint32_t)(tv.tv_sec - (long)hours * 3600) : 0;

    /* Keep a rolling window of the newest `max` matching rows. */
    int count = 0;
    /* Same lock as the writer, or prune() renames EV_CSV mid-read. Bounded:
     * this is the single httpd task, so a stuck writer would freeze the UI. */
    /* A lock miss must not skip the still-open events below -- those live in
     * RAM and need no card at all. */
    bool locked = sdcard_io_begin_timeout(2000);
    /* Without a card there is nothing stored to miss -- only a real lock miss
     * on a mounted card makes the list incomplete. */
    if (!locked && history_ok && sdcard_is_mounted())
        *history_ok = false;
    /* Two passes at most: a tail the cache cannot answer reads the file again from the start. */
    for (int pass = 0; locked && pass < 2; pass++)
    {
        /* The cache answers up to EV_RC rows, and windows from s_rc_from on. A longer list
         * reads the file straight into out[]. */
        bool cached = max <= EV_RC;
        FILE *f = cached ? sdrc_open(&s_rc, EV_CSV, s_rgen, pass == 0 && from >= s_rc_from)
                         : fopen(EV_CSV, "r");
        /* A power cut in prune can leave only events.tmp, with every row. The next tick
         * renames it. */
        if (!f && errno == ENOENT)
        {
            f = fopen(EV_TMP, "r");
            cached = false;
        }
        /* Only a missing file is an empty history; any other failed open is a failed read. */
        if (!f && errno != ENOENT && history_ok)
            *history_ok = false;
        if (!f)
            break;
        bool resumed = cached && s_rc.tail, lany = false;
        if (cached)
            ev_rc_start(from, resumed);
        /* Whole lines only, as in prune: a piece split off by fgets would parse as
         * its own row and pass the tolerant got >= 3 check. */
        char *line = s_rd;
        bool rest = false, whole;
        while (ev_gets(line, sizeof(s_rd), f, &rest, &whole))
        {
            /* picolibc hands back the part before a read error: not a row. */
            if (ferror(f))
                break;
            if (cached)
                sdrc_piece(&s_rc, f, line, sizeof(s_rd));
            if (!whole)
                continue;
            /* Set the defaults for every line, so this block stays inside the
             * loop. They keep the shorter rows of older firmware readable. */
            unsigned long sec = 0, last = 0, sender = 0;
            unsigned st, cause, cnt = 1, multi = 0; long lat = 0, lon = 0;
            unsigned sub = 0; int rmin = 0, rmax = 0;
            unsigned cb = 0, aft = 0, nmac = 0;
            char ma[13] = "", mb[13] = "";
            unsigned long ast = 0, vs = 0;
            unsigned aseq = 0, term = 0, vsrc = 0, shape = 0, aa = 0, ab = 0, aang = 0;
            unsigned long long det = 0, ref = 0;
            long alat = 0, alon = 0;
            unsigned aw = 0, dir = 0, road = 0, qual = 0, tx = 0, ntr = 0, plen = 0;
            unsigned spd = 0, hdg = 0, orig = 0, nh = 0;
            long alt = 0;
            unsigned mhl = 0, hmin = 0, hmax = 0, ggot = 0, grel = 0, gmis = 0;
            int end = 0;
            int got = sscanf(line, "%lu,%u,%u,%ld,%ld,%u,%lu,%u,%lu,%d,%d,%u,"
                                   "%12[0-9a-fA-F],%12[0-9a-fA-F],%u,%u,%u,"
                                   "%lu,%u,%u,%llu,%llu,%lu,%u,%u,%ld,%ld,%u,%u,%u,"
                                   "%u,%u,%u,%u,%u,%u,%u,%u,%u,%ld,%u,%u,"
                                   "%u,%u,%u,%u,%u,%u%n",
                             &sec, &st, &cause, &lat, &lon, &cnt, &last, &sub,
                             &sender, &rmin, &rmax, &multi,
                             ma, mb, &cb, &aft, &nmac,
                             &ast, &aseq, &term, &det, &ref, &vs, &vsrc,
                             &shape, &alat, &alon, &aa, &ab, &aang,
                             &aw, &dir, &road, &qual, &tx, &ntr, &plen,
                             &spd, &hdg, &alt, &orig, &nh,
                             &mhl, &hmin, &hmax, &ggot, &grel, &gmis, &end);
            /* Only a valid PAIR is a span -- clamping one half alone would put an
             * impossible "0 dBm" end into the table. */
            if (rmin >= 0 || rmin <= -128 || rmax >= 0 || rmax <= -128 || rmin > rmax)
                rmin = rmax = 0;
            /* Window by END time: an event that started earlier but was still
             * broadcast inside it counts, exactly as the RAM branch below. */
            uint32_t ends_at = (got >= 7 && last > sec) ? (uint32_t)last : (uint32_t)sec;
            if (got >= 3 && ends_at >= from)
            {
                /* Rows written before grouping existed have no count/last
                 * columns; treat them as single-message events. */
                if (got < 6) { cnt = 1; last = sec; }
                /* Designated on purpose: positional would silently shift lat/lon
                 * onto the fields appended after them. */
                event_rec_t e = {
                    .seconds = (uint32_t)sec, .last_seen = (uint32_t)last,
                    .action_station = 0, .action_seq = 0,
                    .count = (uint16_t)cnt, .station_type = (uint8_t)st,
                    .cause = (uint8_t)cause, .subcause = (uint8_t)sub,
                    .lat_e7 = (int32_t)lat, .lon_e7 = (int32_t)lon,
                    .sender_id = (uint32_t)sender,
                    .rssi_min = (int8_t)rmin, .rssi_max = (int8_t)rmax,
                    .multi_sender = multi != 0,
                    .denm = EVENT_DENM_UNSENT,
                };
                /* Only a row that carried ALL five appended fields has them;
                 * anything shorter is an older row and keeps n_macs 0. */
                if (got >= 17)
                {
                    ev_hex_mac(ma, e.mac_a);
                    ev_hex_mac(mb, e.mac_b);
                    e.count_b = (uint16_t)(cb > 0xFFFFu ? 0xFFFFu : cb);
                    e.b_after_s = (uint16_t)(aft > 0xFFFFu ? 0xFFFFu : aft);
                    e.n_macs = (uint8_t)(nmac > 255u ? 255u : nmac);
                }
                /* Values out of range read as unknown rather than wrapped into a valid one. */
                if (got >= 30)
                {
                    e.action_station = (uint32_t)ast;
                    e.action_seq = (uint16_t)(aseq > 0xFFFFu ? 0u : aseq);
                    e.termination = (uint8_t)(term <= ITS_DENM_TERM_NEGATION ? term : 0u);
                    e.detection_ms = det;
                    e.reference_ms = ref;
                    e.validity_s = (uint32_t)vs;
                    e.validity_src = (uint8_t)(vsrc <= EVENT_VALIDITY_SENT ? vsrc : 0u);
                    if (shape <= ITS_GN_AREA_ELLIPSE && aa <= 0xFFFFu && ab <= 0xFFFFu && aang <= 0xFFFFu)
                    {
                        e.area_shape = (uint8_t)shape;
                        e.area_lat_e7 = (int32_t)alat;
                        e.area_lon_e7 = (int32_t)alon;
                        e.area_a_m = (uint16_t)aa;
                        e.area_b_m = (uint16_t)ab;
                        e.area_angle_deg = (uint16_t)aang;
                    }
                }
                /* A block of its own. An older row stops at column 30 and leaves these unsent,
                 * and a damaged one loses only these. */
                if (got >= 42)
                {
                    event_denm_t *x = &e.denm;
                    x->aware_dist = (uint8_t)(aw <= ITS_DENM_DIST_OVER ? aw : ITS_DENM_DIST_NONE);
                    x->traffic_dir = (uint8_t)(dir <= ITS_DENM_DIR_OPPOSITE ? dir : ITS_DENM_DIR_NONE);
                    x->road_type = (uint8_t)(road <= ITS_DENM_ROAD_RURAL_SEP ? road : ITS_DENM_ROAD_NONE);
                    x->info_quality = (uint8_t)(qual <= 7u ? qual : ITS_DENM_QUALITY_NONE);
                    x->tx_interval_ms = (uint16_t)(tx <= EVENT_TX_MAX_MS ? tx : 0u);
                    x->n_traces = (uint8_t)(ntr <= 7u ? ntr : 0u);
                    /* The count belongs to the traces: none, no count. */
                    x->path_len = (uint8_t)(plen <= 40u && x->n_traces ? plen : 0u);
                    x->speed_cms = (uint16_t)(spd < EVENT_SPEED_NONE ? spd : EVENT_SPEED_NONE);
                    x->heading_ddeg = (uint16_t)(hdg <= 3600u ? hdg : EVENT_HEADING_NONE);
                    x->alt_cm = alt >= -100000 && alt <= 800000 ? (int32_t)alt : EVENT_ALT_NONE;
                    x->origin_type = (uint8_t)(orig < ITS_DENM_STATION_NONE ? orig : ITS_DENM_STATION_NONE);
                    x->n_hist = (uint8_t)(nh <= 23u ? nh : 0u);
                }
                /* How the stretch travelled, a block of its own too. Only what events_note can
                 * write counts, up to the line end or the next block. Otherwise all six stay 0. */
                bool hops_ok = mhl == 0 ? hmin == 0 && hmax == 0
                                        : mhl <= 255u && hmin <= hmax && hmax <= mhl - 1;
                bool tail = line[end] == '\n' || line[end] == ',';
                if (got >= 48 && tail && hops_ok && ggot <= 0xFFFFu &&
                    grel <= ggot && gmis <= 0xFFFFu)
                {
                    e.gn_mhl = (uint8_t)mhl;
                    e.gn_hops_min = (uint8_t)hmin;
                    e.gn_hops_max = (uint8_t)hmax;
                    e.gn_got = (uint16_t)ggot;
                    e.gn_relayed = (uint16_t)grel;
                    e.gn_missing = (uint16_t)gmis;
                }
                /* Outside the test above: bad hop values do not cost the addresses behind them. */
                if (got >= 48 && line[end] == ',')
                    ev_parse_path(line + end + 1, &e);
                if (cached)
                    s_rc_n = ev_keep(s_rc_rows, s_rc_end, EV_RC, s_rc_n, &e, ends_at);
                else
                {
                    lany |= count == max;
                    count = ev_keep(out, NULL, max, count, &e, ends_at);
                }
            }
        }
        bool err = ferror(f);
        if (cached)
            sdrc_done(&s_rc, f, !err);
        fclose(f);
        /* A row that left the cache still counts while it ends in the window. The cache must
         * then hold `max` rows without it, or the file is read once more from the start. */
        bool more = cached && s_rc_any_gone && s_rc_gone >= from;
        if (resumed && more && s_rc_n < max)
            continue;
        /* A read error ends fgets like EOF would: the rows after it are missing. */
        if (err && history_ok)
            *history_ok = false;
        if (cached)
            count = ev_rc_out(out, max);
        if (capped && (cached ? s_rc_n > max || more : lany))
            *capped = true;
        break;
    }
    if (locked)
        sdcard_io_end();

    /* Still-open events live only in RAM until they go quiet, so a warning
     * being repeated right now would otherwise be missing entirely. */
    if (s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) == pdTRUE)
    {
        uint32_t now = (uint32_t)time(NULL);
        uint32_t cutoff = now > hours * 3600 ? now - hours * 3600 : 0;
        for (int i = 0; i < EV_OPEN; i++)
            if (s_open_valid[i] && s_open[i].last_seen >= cutoff)
            {
                /* A full list must not cost the running events: drop the
                 * oldest stored row instead. */
                if (count == max)
                {
                    if (max <= 1) break;
                    memmove(out, out + 1, (size_t)(max - 1) * sizeof(*out));
                    count--;
                    if (capped) *capped = true;
                }
                out[count++] = s_open[i];
            }
        xSemaphoreGive(s_lock);
    }
    /* Sort the WHOLE list, not just the appended tail: rows land in flush
     * order, i.e. by END time, so they are not ascending by start. */
    for (int i = 1; i < count; i++)
    {
        event_rec_t e = out[i];
        int j = i;
        while (j > 0 && out[j - 1].seconds < e.seconds) { out[j] = out[j - 1]; j--; }
        out[j] = e;   /* descending: newest start first */
    }
    return count;
}

int events_current(event_rec_t *out, int max, bool *capped)
{
    if (capped)
        *capped = false;
    if (!s_lock || max <= 0)
        return 0;
    if (xSemaphoreTake(s_lock, pdMS_TO_TICKS(50)) != pdTRUE)
        return -1;
    int n = 0;
    bool dropped = false;
    for (int i = 0; i < EV_OPEN; i++)
    {
        if (!s_open_valid[i]) continue;
        if (n < max) out[n++] = s_open[i];
        else dropped = true;
    }
    int open_n = n;
    for (int i = 0; i < EV_RECENT; i++)
    {
        if (!s_recent_valid[i]) continue;
        /* A reopened slot already carries this record's state. */
        bool open = false;
        for (int k = 0; k < open_n && !open; k++)
            open = ev_same_action(&out[k], &s_recent[i]);
        if (open) continue;
        if (n < max) out[n++] = s_recent[i];
        else dropped = true;
    }
    uint32_t now = (uint32_t)time(NULL);
    if (capped)
        *capped = dropped || (s_lost_until && now <= s_lost_until);
    xSemaphoreGive(s_lock);
    return n;
}

#else  /* !CONFIG_ENABLE_SD */
void events_init(void) {}
void events_note(uint32_t seconds, uint8_t station_type, uint32_t sender_id, int rssi,
                 uint8_t message_id,
                 uint8_t cause, uint8_t subcause,
                 uint32_t action_station, uint16_t action_seq,
                 bool has_pos, int32_t lat_e7, int32_t lon_e7,
                 const uint8_t *src_mac, const its_decoded_t *d, const its_gn_t *gn)
{ (void)seconds;(void)station_type;(void)sender_id;(void)rssi;(void)message_id;(void)cause;(void)subcause;
  (void)action_station;(void)action_seq;(void)has_pos;(void)lat_e7;(void)lon_e7;(void)src_mac;(void)d;
  (void)gn; }
void events_tick(void) {}
void events_flush_now(void) {}
uint32_t events_evicted(void) { return 0; }
int  events_read(uint32_t hours, event_rec_t *out, int max, bool *history_ok,
                 bool *capped)
{
    (void)hours; (void)out; (void)max;
    if (history_ok) *history_ok = true;
    if (capped) *capped = false;
    return 0;
}
int events_current(event_rec_t *out, int max, bool *capped)
{
    (void)out; (void)max;
    if (capped) *capped = false;
    return 0;
}
#endif
