#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_security.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The European trust lists are compiled into the firmware, so the device never fetches one.
 * The module only says whether a HashedId8 is listed; it verifies nothing. */

typedef enum
{
    ITS_TRUST_ENV_L0    = 0,  /* The test environment of the European PKI. */
    ITS_TRUST_ENV_L1    = 1,  /* The pre-production environment. */
    ITS_TRUST_ENV_L2    = 2,  /* The production environment. */
    ITS_TRUST_ENV_COUNT = 3,
} its_trust_env_t;

typedef enum
{
    ITS_TRUST_ROLE_ROOT = 0,  /* A root CA that the trust list names. */
    ITS_TRUST_ROLE_TLM  = 1,  /* The trust list manager that signs the list itself. */
} its_trust_role_t;

/* Which hash a HashedId8 came from. The values match the hash_alg field of an entry. */
typedef enum
{
    ITS_TRUST_HASH_SHA256 = 0,
    ITS_TRUST_HASH_SHA384 = 1,
} its_trust_hash_t;

/* The list named this certificate as the predecessor of another entry, so its own validity
 * can have ended while certificates issued under it are still around. */
#define ITS_TRUST_PREDECESSOR 0x01

/* One listed certificate. The pointers lead into flash and stay valid forever.
 *
 * Which hash gives a certificate its HashedId8 is decided by whoever refers to it, not by
 * the certificate: a child names sha256AndDigest or sha384AndDigest in its own issuer
 * field, and a trust list entry can be referred to either way. Both identifiers are
 * therefore stored, and hash_alg only says which one matches this certificate's own issuer
 * field, which is the form the European PKI publishes it under. */
typedef struct
{
    uint8_t        id8_sha256[8];
    uint8_t        id8_sha384[8];
    const uint8_t *cert;           /* The certificate bytes both identifiers were taken over. */
    const char    *name;           /* The name from the certificate, never NULL or empty. */
    uint16_t       cert_len;
    /* The verification key point starts here inside cert, at its own CHOICE tag, and
     * key_len counts the coordinate bytes that follow that tag. */
    uint16_t       key_off;
    uint8_t        key_len;
    uint8_t        key_type;       /* Values come from its_sec_key_t. */
    /* The point form is 0 for x-only, 2 and 3 for compressed and 4 for uncompressed, which
     * follows the CHOICE order of EccP256CurvePoint. */
    uint8_t        key_form;
    uint8_t        hash_alg;       /* Values come from its_trust_hash_t, see above. */
    uint8_t        env;            /* Values come from its_trust_env_t. */
    uint8_t        role;           /* Values come from its_trust_role_t. */
    uint8_t        flags;          /* The ITS_TRUST_* bits go here. */
    uint8_t        duration_unit;  /* Values come from its_sec_duration_t. */
    uint16_t       duration;       /* The validity lasts this many duration_unit steps. */
    uint32_t       validity_start; /* Time32 counts TAI seconds since 2004-01-01 00:00:00 UTC. */
} its_trust_entry_t;

/* What one trust list says about itself. */
typedef struct
{
    uint8_t  env;              /* Values come from its_trust_env_t. */
    uint8_t  ctl_version;
    uint8_t  ctl_sequence;
    bool     is_full;          /* A delta list is rejected while the file is read. */
    uint16_t n_roots;          /* Root CA entries, predecessors not counted. */
    uint16_t n_tlm;
    uint16_t n_dc;             /* Distribution centres, counted but not stored. */
    uint32_t next_update;      /* Both times are Time32 and use the epoch named above. */
    uint32_t generation_time;  /* The list was signed at this second. */
    uint32_t file_len;
    uint8_t  signer_id8[8];    /* The HashedId8 of the TLM certificate that signed the list. */
    uint8_t  sha256[32];       /* SHA-256 over the whole list file the table was built from. */
} its_trust_list_t;

/* Look up a certificate by a HashedId8 of unknown origin. The SHA-256 identifiers are
 * searched first and the SHA-384 ones after them, so either kind is found. Both searches
 * are binary ones over sorted flash, so a call per new certificate costs nothing worth
 * measuring. */
bool its_trustlist_find(const uint8_t id8[8], its_trust_entry_t *out);

/* Look up a certificate by a HashedId8 whose hash the caller knows, which is the way to go
 * when a child's issuer field named the algorithm. `alg` takes its_trust_hash_t values, and
 * anything else finds nothing. */
bool its_trustlist_find_alg(const uint8_t id8[8], uint8_t alg, its_trust_entry_t *out);

/* Copy the entry at `index`, which lets a page walk the whole table. The order follows the
 * SHA-256 identifier, not the environment. */
bool its_trustlist_at(size_t index, its_trust_entry_t *out);

size_t its_trustlist_count(void);

/* Describe one list, for a page that wants to name its date and its size. Returns NULL for
 * an environment outside its_trust_env_t. */
const its_trust_list_t *its_trustlist_list(uint8_t env);

/* Return "L0", "L1" or "L2", and "?" for anything else. */
const char *its_trustlist_env_name(uint8_t env);

/* How much flash the tables take. No page shows the number. The host tests weigh it against
 * the certificate bytes. */
size_t its_trustlist_flash_bytes(void);

#ifdef __cplusplus
}
#endif
