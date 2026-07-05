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
 *
 * This is a label for the web UI, not a full ASN.1/UPER decode of the message
 * content. Only CAM and DENM ports are mapped to a name with confidence;
 * other recognised facility ports are labelled "GeoNet:<port>" rather than
 * guessed, since a wrong name would be worse than a raw port number. Frames
 * secured per ETSI TS 103 097 (common on real V2X traffic) are labelled
 * "Signed" -- the certificate/signature envelope has a variable length that
 * isn't parsed here.
 *
 * `out` is always left as a valid, non-empty, NUL-terminated string, e.g.
 * "CAM", "DENM", "Signed", "GeoNet:2004", "?". */
void its_decode_msg_type(const uint8_t *frame, size_t len, char *out, size_t out_size);

#ifdef __cplusplus
}
#endif
