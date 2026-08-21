#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "its_decode.h"

/* Inventory of stationary senders (RSUs, traffic lights) seen since boot.
 * Vehicles are only counted, never listed -- they rotate their pseudonyms. */

#define INV_MAX_STATIONS 128
#define INV_NAME_LEN     40

typedef struct {
    uint32_t station_id;
    uint32_t first_seen, last_seen;   /* unix time */
    uint32_t frames;
    int32_t  lat_e7, lon_e7;
    uint16_t msg_mask;                /* bit (1 << message_id); ids 0 and >=16
                                       * are dropped, not folded onto a wrong bit */
    int16_t  rssi_min, rssi_max;      /* dBm, 0 when nothing was measured */
    int64_t  rssi_sum;   /* 64 bit: an RSU heard for weeks overflows 32 */
    uint32_t rssi_cnt;
    uint8_t  station_type;
    uint8_t  mac[6];
    bool     has_pos, has_mac;
    char     name[INV_NAME_LEN];      /* MAPEM intersection name, "" if none */
} inv_station_t;

void inventory_init(void);

/* Periodic (sysmon): loads the table once the card is up, then writes it back
 * every few minutes so the inventory survives a restart. */
void inventory_tick(void);

/* Persists the sender table now -- call before a planned restart. */
void inventory_flush_now(void);

/* Hot path: fold one decoded frame in. Cheap, RAM only, never blocks. */
void inventory_note(uint32_t seconds, int rssi, const its_decoded_t *d);

/* Copies the table for rendering (caller supplies room for INV_MAX_STATIONS).
 * Returns the number written, newest activity first. */
int inventory_snapshot(inv_station_t *out);

/* Name of the stationary sender with this MAC, "" when the address has none or
 * is not in the table at all -- vehicles never get a row here. */
/* 1 = MAC is listed, 0 = not listed, -1 = list was busy. The name may be
 * empty for a listed sender, so only the return value means "found". */
int inventory_lookup_mac(const uint8_t mac[6], char *out, size_t cap,
                         uint32_t *id_out);

/* Frames from senders that never get a row of their own (vehicles). */
uint32_t inventory_vehicle_frames(void);

/* True once the table is full and further senders are being turned away. */
bool inventory_overflow(void);

void inventory_clear(void);
