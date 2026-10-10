#pragma once

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Reads and writes the settings file with ArduinoJson. Only flat members are
 * exchanged: the top level and the members of its "settings" object. */

typedef enum { SJ_NULL, SJ_BOOL, SJ_INT, SJ_FLOAT, SJ_STR, SJ_ARRAY, SJ_OBJECT } sj_type_t;

#define SJ_KEY_LEN 32
#define SJ_STR_LEN 256

typedef struct {
    char key[SJ_KEY_LEN];
    sj_type_t type;
    bool key_cut;         /* the key did not fit or holds a NUL, and is shortened */
    bool str_cut;         /* the string did not fit, so str holds only its start */
    bool str_nul;         /* the string holds a NUL character */
    bool b;
    long long num;
    char str[SJ_STR_LEN];
} sj_member_t;

typedef enum {
    SJ_PARSE_OK,
    SJ_PARSE_EMPTY,
    SJ_PARSE_SYNTAX,      /* not JSON, cut off, or nested too deep */
    SJ_PARSE_NOMEM,
    SJ_PARSE_NOT_OBJECT,
    SJ_PARSE_TOO_MANY,    /* more members than the caller has room for */
} sj_parse_t;

/* Parses `len` bytes. The top-level members go to top[], the members of a
 * top-level "settings" object to set[]. set_n stays 0 without that object. */
sj_parse_t settings_json_parse(const char *json, size_t len,
                               sj_member_t *top, size_t top_cap, size_t *top_n,
                               sj_member_t *set, size_t set_cap, size_t *set_n);

/* Writes top[] with set[] as its "settings" object, indented. Returns the
 * length without the NUL, or 0 when it does not fit into cap. */
size_t settings_json_write(const sj_member_t *top, size_t top_n,
                           const sj_member_t *set, size_t set_n,
                           char *out, size_t cap);

#ifdef __cplusplus
}
#endif
