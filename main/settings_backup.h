#pragma once

#include <stdbool.h>
#include <stddef.h>

#include "settings_apply.h"
#include "settings_json.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Settings file export and import, without any HTTP. Every imported value goes
 * through the checks the /settings form uses: set_apply(), and set_apply_address()
 * for the static address block. */

#define SETTINGS_FILE_FORMAT  "its-g5-receiver-settings"
#define SETTINGS_FILE_VERSION 1

/* Largest settings file accepted. The export stays far below it. */
#define SETTINGS_FILE_MAX 16384

typedef enum {
    SB_FILE_OK,
    SB_FILE_EMPTY,
    SB_FILE_JSON,       /* not valid JSON or not an object */
    SB_FILE_NOMEM,
    SB_FILE_TOO_MANY,
    SB_FILE_FORMAT,     /* no "format" of ours, no valid "format_version" or no "settings" object */
    SB_FILE_NEWER,      /* "format_version" above SETTINGS_FILE_VERSION */
} sb_file_err_t;

typedef enum { SB_APPLIED, SB_UNCHANGED, SB_REJECTED, SB_IGNORED } sb_outcome_t;

typedef enum {
    SB_WHY_NONE,
    SB_WHY_UNKNOWN,
    SB_WHY_PASSWORD,
    SB_WHY_DEVICE,       /* node ID or static address without the device option */
    SB_WHY_NOT_BUILT,    /* a setting this firmware build leaves out */
    SB_WHY_DHCP_UNUSED,  /* static address part while "dhcp" is true */
    SB_WHY_NEEDS_DHCP,   /* static address part without "dhcp" */
} sb_why_t;

typedef struct {
    char key[SJ_KEY_LEN];
    set_id_t id;         /* SET_COUNT for anything that is not a setting */
    sb_outcome_t outcome;
    set_err_t err;       /* SB_REJECTED */
    sb_why_t why;        /* SB_IGNORED */
} sb_item_t;

/* One item per member of the file, top level and settings together. */
#define SB_TOP_MAX 16
#define SB_SET_MAX 64

typedef struct {
    sb_file_err_t file_err;
    bool reboot;          /* a setting that needs a restart has changed */
    unsigned applied, unchanged, rejected, ignored;
    size_t n;
    sb_item_t items[SB_TOP_MAX + SB_SET_MAX];
} sb_result_t;

/* Work space for one import or export, 24320 bytes. */
typedef struct {
    sj_member_t top[SB_TOP_MAX];
    sj_member_t set[SB_SET_MAX];
} sb_work_t;

/* Checks and applies a settings file. `with_device` also takes the node ID and
 * the static address block. */
void settings_import(const char *json, size_t len, bool with_device,
                     sb_work_t *work, sb_result_t *res);

/* Writes the current settings as a settings file. exported_at is a UTC time like
 * 2026-09-30T10:57:05Z, or NULL without a set clock. Returns the length, 0 if it did not fit. */
size_t settings_export(const char *firmware, const char *exported_at,
                       sb_work_t *work, char *out, size_t cap);

/* Copies the boundary out of a multipart/form-data Content-Type value. */
bool multipart_boundary(const char *content_type, char *out, size_t cap);

/* Finds the body of the part called `name`. */
bool multipart_part(const char *body, size_t len, const char *boundary,
                    const char *name, const char **data, size_t *data_len);

#ifdef __cplusplus
}
#endif
