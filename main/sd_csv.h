#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Small CSV files on the card through picolibc's stdio (CONFIG_LIBC_PICOLIBC). It has 128 B of
 * buffer per FILE, and a failed write-out drops all of it. Its fclose hides a failed flush, and
 * fgets hands back the part before a read error. Each helper checks what that stdio hides. The
 * caller holds the SD lock (sdcard_io_begin) around every call. */

typedef enum { SDCSV_OK, SDCSV_WAIT, SDCSV_FAIL } sdcsv_rc_t;

/* fgets for a row reader. *whole is true when this piece is one row with its '\n': not the rest
 * of a row wider than cap, not a cut last row, and no NUL inside. *rest carries over between
 * calls and starts false. Returns false at the end. A read error may first hand back a cut
 * piece, so ask ferror after every call. */
bool sdcsv_gets(char *b, size_t cap, FILE *f, bool *rest, bool *whole);

/* A power cut or a failed rename in the swap leaves only `tmp`. It becomes `csv` again before
 * any append. Returns WAIT during a download (FS_LOCK=0), FAIL while tmp cannot be checked or
 * renamed. */
sdcsv_rc_t sdcsv_recover_tmp(const char *csv, const char *tmp);

/* On a FILE opened "a+": a last row cut by a failed write is cut off after the last '\n' within
 * `cap` bytes, or only ended when there is none. Leaves the position at the end. Returns WAIT
 * during a download. `scratch` holds the look-back. */
sdcsv_rc_t sdcsv_mend_tail(FILE *f, char *scratch, size_t cap);

/* One row written out at once: a failure costs this row and no earlier one. */
bool sdcsv_put(FILE *f, const char *row);

/* Keeps the newest `keep` whole rows of `csv` through `tmp`. Swaps only when the read reached
 * the end and every write-out landed. True when the file holds at most `keep` rows afterwards.
 * The caller checks sdcard_read_active() first (the swap unlinks the file). */
bool sdcsv_keep_newest(const char *csv, const char *tmp, uint32_t keep, char *scratch, size_t cap);

/* Removes both. True when neither is left (a missing file counts as removed). */
bool sdcsv_wipe(const char *csv, const char *tmp);

#ifdef __cplusplus
}
#endif
