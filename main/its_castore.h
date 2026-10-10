#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_security.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Authority certificates compiled into the firmware. They come from the distribution centres
 * the European trust lists name and were fetched when this table was generated, not by the
 * device. So a sender whose authority never sends its own certificate can still be checked
 * without network access. The module only hands out bytes. its_verify checks them against a
 * root as usual. */

/* One built-in authority certificate. The pointers lead into flash and stay valid forever.
 * Both identifiers are stored for the same reason as in its_trustlist: which hash forms a
 * HashedId8 is decided by whoever refers to the certificate, not by the certificate. */
typedef struct
{
    uint8_t        id8_sha256[8];
    uint8_t        id8_sha384[8];
    const uint8_t *cert;
    const char    *name;        /* The name from the certificate, never NULL. */
    uint16_t       cert_len;
    uint8_t        env;         /* Values come from its_trust_env_t. */
    uint8_t        is_aa;       /* 1 for an authorization authority, 0 for an enrolment one. */
} its_castore_entry_t;

/* Look for an authority under the identifier a child named. hash_alg follows
 * its_trust_hash_t, so 0 asks for the SHA-256 form and 1 for the SHA-384 one. Returns NULL
 * when nothing matches, which is the normal case for a PKI outside Europe. */
const its_castore_entry_t *its_castore_find(const uint8_t id8[8], uint8_t hash_alg);

/* Walk the table for the user interface. Returns false once index is past the last entry. */
bool its_castore_at(size_t index, its_castore_entry_t *out);

size_t its_castore_count(void);

/* What the set costs in flash: the certificate bytes, the names and the table itself. The
 * generator counts it, because a host build has wider pointers than the device. */
size_t its_castore_flash_bytes(void);

/* The day the certificates were fetched, as Time32 seconds like every other time here.
 * 0 means no set was compiled in. The user interface shows it, because authorities that
 * appeared after that day are missing from the firmware. */
uint32_t its_castore_fetched(void);

#ifdef __cplusplus
}
#endif
