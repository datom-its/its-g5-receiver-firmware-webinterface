#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Revocation lists compiled into the firmware, one per root that publishes one. They were
 * fetched from the distribution centres when its_crl.c was generated, so the device asks
 * nothing of the network. Such a list only grows stale, never wrong: it names certificates
 * that were withdrawn up to its date, and the user interface shows that date. */

typedef enum
{
    ITS_CRL_NO_DATA    = 0,  /* No list in the firmware, so nothing can be said. */
    ITS_CRL_NOT_LISTED = 1,  /* No compiled-in list names this certificate. */
    ITS_CRL_LISTED     = 2,  /* A list names it: the authority withdrew it. */
} its_crl_state_t;

/* Ask about one certificate. Both identifiers are passed because a list may name either
 * form, and a caller that has only one form passes NULL for the other. */
its_crl_state_t its_crl_lookup(const uint8_t id8_sha256[8], const uint8_t id8_sha384[8]);

/* Withdrawn certificates in the firmware, and the lists they came from. */
size_t its_crl_count(void);
size_t its_crl_lists(void);

/* Dates of the compiled-in lists as Time32 seconds, the oldest thisUpdate and the earliest
 * nextUpdate any list asked for. Both are 0 when no list was compiled in. The second one
 * says when the set should have been renewed, which is what makes staleness visible. */
uint32_t its_crl_oldest_update(void);
/* The newest thisUpdate of any list, so both ends of the span can be shown. */
uint32_t its_crl_newest_update(void);
uint32_t its_crl_next_update(void);

/* Lists that asked to be renewed by `now`, a Time32 second, or 0 when the clock is not set.
 * The oldest thisUpdate and the earliest nextUpdate are minima, so a single abandoned list
 * drags them years into the past. This count says how much of the set that really concerns. */
size_t its_crl_overdue(uint32_t now);

/* One compiled-in list, for the user interface. root_name points into flash and is never
 * NULL: it is what the trust list calls the root, or the identifier written out. */
typedef struct
{
    uint8_t     root_id8[8];   /* The certificate that signed the list. */
    const char *root_name;
    uint32_t    this_update;
    uint32_t    next_update;
    uint16_t    entries;
    uint8_t     env;           /* Values come from its_trust_env_t. */
} its_crl_list_t;

/* Copy one list. Returns false once index is past the last one, so a walk ends by itself. */
bool its_crl_list_at(size_t index, its_crl_list_t *out);

/* Walk the withdrawn identifiers. list_index names the list the entry came from, the older
 * one where two lists name the same certificate. Returns false past the last entry. */
bool its_crl_revoked_at(size_t index, uint8_t out_id8[8], size_t *list_index);

/* Which list names this identifier, so a verdict can give the date of the right list.
 * Returns false when no list names it. Two lists can name the same certificate. Then the one
 * with the oldest thisUpdate is given, because the withdrawal is at least that old. */
bool its_crl_list_of(const uint8_t id8_sha256[8], const uint8_t id8_sha384[8], size_t *index);

#ifdef __cplusplus
}
#endif
