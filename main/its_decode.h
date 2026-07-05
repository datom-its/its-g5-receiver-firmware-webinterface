#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Best-effort identification of the facility-layer message type carried in a
 * raw 802.11p frame, by walking the LLC/SNAP -> GeoNetworking (ETSI EN 302
 * 636-4-1) -> BTP-B (ETSI EN 302 636-5-1) headers to the BTP destination port
 * and mapping well-known ports (ETSI TS 103 301) to their C-ITS message name.
 * Also reads the sender's station type (car/bus/pedestrian/roadside unit/...)
 * from the GeoNetworking source address, when available, and prefixes it
 * (e.g. "Bus CAM", "RSU GeoNet:2004").
 *
 * Frames secured per ETSI TS 103 097 / IEEE 1609.2 (the common case on real
 * V2X traffic) are unwrapped far enough to reach the same Common-Header-
 * onward structure and station type -- without ever parsing the
 * certificate/signature, which simply isn't read. If that unwrap doesn't
 * match the shape verified against real traffic, the frame falls back to
 * plain "Signed" rather than a guess.
 *
 * The message type is read from the ITS PDU header's messageId field (CAM,
 * DENM, SPATEM, MAPEM, IVIM, CPM, ...), mapped via the ETSI TS 102 894-2
 * registry. This is a label for the web UI, not a full ASN.1/UPER decode of
 * the message content (e.g. CAM's speed/heading aren't read). A messageId not
 * in the table falls back to "GeoNet:<port>".
 *
 * `out` is always left as a valid, non-empty, NUL-terminated string, e.g.
 * "Bus CAM", "RSU SPATEM", "DENM", "Signed", "?". */
void its_decode_msg_type(const uint8_t *frame, size_t len, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif
