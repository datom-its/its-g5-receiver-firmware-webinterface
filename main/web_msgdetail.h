#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_certcache.h"
#include "its_verify.h"
#include "msg_extra.h"
#include "web_strings.h"

/* The texts in this module are HTML without quotes or backslashes, so the message feed can
 * put them into a JSON string unchanged. Every function keeps `out` terminated and never
 * leaves half an entity behind. */

/* Append the msg_extra_t parts to a detail line that already holds `used` bytes, joined by
 * " &middot; ". `src_mac` and `cc` may be NULL, and `cc` is the cache entry of the signing
 * certificate, which adds the chain verdict. The two permission answers follow it as items of
 * their own, then the message signature (web_msgsig.h) and the signature header (web_sechdr.h).
 * How the frame travelled (web_gn.h) comes last. Returns the new length, which stays below cap. */
size_t web_msgdetail_append(const msg_extra_t *x, const uint8_t *src_mac,
                            const its_certcache_entry_t *cc, lang_t lang,
                            char *out, size_t used, size_t cap);

/* The same line in two halves, for /messages: first what the message says, joined to the
 * `used` bytes before it. */
size_t web_msgdetail_append_content(const msg_extra_t *x, lang_t lang,
                                    char *out, size_t used, size_t cap);

/* Then signer, chain, the two permission answers, the message signature and the signature
 * header (web_sechdr.h) as a line of their own. How the frame travelled (web_gn.h) comes last.
 * The first item after `used` gets no separator. Returns the new length, which stays below cap. */
size_t web_msgdetail_append_sign(const msg_extra_t *x, const uint8_t *src_mac,
                                 const its_certcache_entry_t *cc, lang_t lang,
                                 char *out, size_t used, size_t cap);

/* A roadside unit's name, from the air or the card, as HTML that is also safe in a JSON string:
 * HTML characters and backslash as entities, bad UTF-8 as '?'. 39 bytes -> 234 at most. */
size_t web_msgdetail_escape(const char *in, char *out, size_t cap);

/* The signer alone, for the sender list. Returns the length, 0 when there is nothing to say. */
size_t web_msgdetail_sig(const its_sig_summary_t *sig, const uint8_t *src_mac, lang_t lang,
                         char *out, size_t cap);

/* The chain verdict of one certificate in words, with the names of the root and the issuer
 * for a message line and with the trust list and chain length for the sender list. */
size_t web_msgdetail_trust(const its_certcache_entry_t *cc, lang_t lang, char *out, size_t cap);
size_t web_msgdetail_trust_short(const its_certcache_entry_t *cc, lang_t lang,
                                 char *out, size_t cap);

/* The chain checks since power-on, as the detail line of a cell on the system page. */
size_t web_msgdetail_trust_counts(const its_verify_stats_t *v, lang_t lang,
                                  char *out, size_t cap);

/* The permission answers since power-on, as the detail lines of two cells on the system page:
 * the service answers, then the content answers. */
size_t web_msgdetail_perm_counts(const msg_perm_stats_t *p, lang_t lang,
                                 char *out, size_t cap);
size_t web_msgdetail_perm_cont_counts(const msg_perm_stats_t *p, lang_t lang,
                                      char *out, size_t cap);

/* The built-in trust lists: roots and date per environment, behind a link to that table on
 * /trust. For /system only. */
size_t web_msgdetail_trustlists(lang_t lang, char *out, size_t cap);

/* Last transmit power and highest channel load, for the sender list. A power of 0 is left out. */
size_t web_msgdetail_radio(uint8_t tx_power_dbm, uint8_t cbr_max, lang_t lang,
                           char *out, size_t cap);

/* The three word tables of a priority request, so the log on /traffic says the same as the
 * message detail. Exported instead of copied: two tables drift apart, one does not.
 * In prio_code, `kind` is 9 for a request and 10 for an answer. In prio_access, `kind` is the
 * type of access point (ITS_SREM_AP_*). */
str_id_t web_msgdetail_prio_code(uint8_t kind, uint8_t code);
str_id_t web_msgdetail_prio_role(uint8_t role);
str_id_t web_msgdetail_prio_access(uint8_t kind);

/* StationType -> road-user word (S_CAT_*), for every page that uses these words. The English
 * labels of /messages ("Car CAM") come from its_decode.c instead. Exported for the same reason
 * as the three above. */
str_id_t web_msgdetail_station_cat(uint8_t st);
