#pragma once

/* Shared by web_msgdetail.c and its parts _sec, _cpm, _poim, _prio and _denm, which together
 * build the detail line under a message. Nothing outside these six files includes it. */

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "its_crl.h"
#include "its_utf8.h"
#include "its_trustlist.h"

#include "web_msgdetail.h"
#include "web_fmt.h"
#include "web_gn.h"
#include "web_msgsig.h"
#include "web_sechdr.h"

typedef struct
{
    char  *s;
    size_t cap;
    size_t n;
    bool   full;                 /* Set by the first piece that did not fit. */
} sb_t;

void sb_add(sb_t *b, const char *fmt, ...) __attribute__((format(printf, 2, 3)));

#define SEP " &middot; "
#define S(id) web_str((id), lang)

/* web_msgdetail.c */
size_t item_begin(sb_t *b, const char *sep);
void item_end(sb_t *b, size_t mark);
void add_escaped(sb_t *b, const char *in);
void add_us(sb_t *b, uint32_t us, lang_t lang);
void add_text_utf8_n(sb_t *b, const char *t, size_t len, bool cut, size_t max);

/* One file per kind of message, called from content_parts() in web_msgdetail.c. */
void denm_text(sb_t *b, const msg_extra_t *x, lang_t lang);
void cpm_text(sb_t *b, const msg_extra_t *x, lang_t lang);
void poim_text(sb_t *b, const its_poim_t *p, lang_t lang);
void prio_text(sb_t *b, const msg_prio_t *p, lang_t lang);

/* web_msgdetail_sec.c: the signature and permission items, after the content. */
void sign_parts(sb_t *b, const msg_extra_t *x, const uint8_t *src_mac,
                const its_certcache_entry_t *cc, lang_t lang);

/* web_msgdetail_prio.c keeps the role table with the other request texts; the permission
 * text in web_msgdetail_sec.c names the role with it too. */
str_id_t role_name(uint8_t role);
