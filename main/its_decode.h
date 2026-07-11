#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Identifies the facility-layer message type in a raw 802.11p frame (walks
 * LLC/SNAP -> GeoNetworking -> BTP-B to the message's ITS PDU header) and
 * prefixes it with the sender's station type when known, e.g. "Bus CAM",
 * "RSU SPATEM", "Signed" (secured, envelope not decoded), "?" (not GeoNet).
 * `out` is always a valid non-empty string.
 *
 * Position: prefers the GeoNetworking extended header's own Source Position
 * Vector (present for every facility message, so RSUs get a position too);
 * for CAM specifically, the message body's own (UPER-encoded)
 * referencePosition overrides it as the more precise value. `station_id` is
 * ItsPduHeader.stationId (the map-marker tracking key), not the GN source
 * address used for the station-type label. `has_speed`/`speed_cmps` come
 * from the same Source Position Vector (cm/s), skipped for RSUs (stationary).
 * Byte offsets validated against real captured traffic -- see
 * reference-its-decode in the project's memory before changing any of them. */
void its_decode_frame(const uint8_t *frame, size_t len, char *out, size_t out_size,
                      bool *has_position, int32_t *lat_e7, int32_t *lon_e7,
                      uint32_t *station_id, bool *has_speed, int32_t *speed_cmps);

#ifdef __cplusplus
}
#endif
