#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_msgsig.h"
#include "web_strings.h"

/* The message signature in words. The entry, the certificate line and the counters hold no
 * quote or backslash, so the feed and /system.json can take them unchanged. What does not fit
 * is left out. */

/* The item of one message after `used` bytes, behind " &middot; " when used > 0. Nothing for
 * ITS_MSGSIG_NONE. Returns the new length, which stays below cap. */
size_t web_msgsig_append(const its_msgsig_t *m, lang_t lang, char *out, size_t used, size_t cap);

/* One certificate, "12 echt, 0 falsch", with `title` behind "Nachrichten-Signaturen
 * (Stichprobe): ". Returns the length. */
size_t web_msgsig_cert(const its_msgsig_cert_t *c, bool title, lang_t lang, char *out, size_t cap);

/* The cells of one finished check on /trust. The date shows only on another day than `now`.
 * `who` is the sender in words as HTML, or "" for none. `msg` is the name of the message, or
 * NULL to show the PSID. Returns the length, 0 when the cells do not fit. */
size_t web_msgsig_cells(const its_msgsig_rec_t *r, const char *who, const char *msg,
                        uint32_t now, lang_t lang, char *out, size_t cap);

/* The counters since power-on, as the detail line of the /system cell. Returns the length. */
size_t web_msgsig_counts(const its_msgsig_stats_t *s, lang_t lang, char *out, size_t cap);
