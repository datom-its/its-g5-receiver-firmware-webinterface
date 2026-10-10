#include "sdkconfig.h"

#include "sd_csv.h"

/* Without a card nothing calls these, and sdcard.c has no sdcard_read_active then. */
#if CONFIG_ENABLE_SD

#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "esp_log.h"
#include "sdcard.h"

static const char TAG[] = "SDCSV";

/* A lost sector reads as NUL bytes that hide the '\n' from strlen. fgets writes b's last byte
 * only when the piece fills b, so the mark there tells a full piece from a short one. */
bool sdcsv_gets(char *b, size_t cap, FILE *f, bool *rest, bool *whole)
{
    b[cap - 1] = 1;
    if (!fgets(b, (int)cap, f))
        return false;
    size_t len = strlen(b);
    bool skip = *rest;
    /* A full piece without '\n' at its end is a row wider than b: the next piece is its rest. */
    *rest = b[cap - 1] == '\0' && b[cap - 2] != '\n';
    /* A NUL inside or no '\n' at the end (a cut last row) drops this piece alone. */
    *whole = !skip && !*rest && len > 0 && b[len - 1] == '\n';
    return true;
}

/* Before the append: a new csv would hide the tmp from the readers, and a later trim would
 * overwrite it. A tmp that cannot be checked may hold every row: only ENOENT means none. */
sdcsv_rc_t sdcsv_recover_tmp(const char *csv, const char *tmp)
{
    struct stat st;
    if (stat(csv, &st) == 0)
        return SDCSV_OK;
    /* The rename runs after any stat error of the csv, not just ENOENT. FatFs does not rename
     * onto an existing file, so a csv that is there stays. */
    if (stat(tmp, &st) != 0)
        return errno == ENOENT ? SDCSV_OK : SDCSV_FAIL;
    /* FS_LOCK=0: no rename under a download, and no new csv beside it either. */
    if (sdcard_read_active() != 0)
        return SDCSV_WAIT;
    return rename(tmp, csv) == 0 ? SDCSV_OK : SDCSV_FAIL;
}

/* FatFs keeps what a failed write got out: the next row would glue onto the cut one, and the
 * readers drop such a line whole, the good row with it. */
sdcsv_rc_t sdcsv_mend_tail(FILE *f, char *scratch, size_t cap)
{
    char last = '\n';
    long size = fseek(f, 0, SEEK_END) == 0 ? ftell(f) : -1;
    if (size < 0 || (size > 0 && (fseek(f, size - 1, SEEK_SET) != 0 || fread(&last, 1, 1, f) != 1)))
        return SDCSV_FAIL;
    if (last != '\n')
    {
        /* FS_LOCK=0: no truncation under a download; the rows wait for it. */
        if (sdcard_read_active() != 0)
            return SDCSV_WAIT;
        long back = size < (long)cap ? size : (long)cap, i;
        if (fseek(f, size - back, SEEK_SET) != 0 ||
            fread(scratch, 1, (size_t)back, f) != (size_t)back)
            return SDCSV_FAIL;
        for (i = back - 1; i >= 0 && scratch[i] != '\n'; i--)
            ;
        if (i >= 0 || back == size)
        {
            /* fflush first: picolibc seeks back over what fread buffered, and after the cut that
             * seek could make FatFs grow the file again. A file of one cut row ends up empty. */
            if (fflush(f) != 0 || ftruncate(fileno(f), (off_t)(size - back + i + 1)) != 0)
                return SDCSV_FAIL;
        }
        /* No '\n' in the last cap bytes, so the cut row is wider than any row. It only gets its
         * '\n', and the readers skip it whole. */
        else if (fseek(f, 0, SEEK_END) != 0 || fputs("\n", f) == EOF || fflush(f) != 0)
            return SDCSV_FAIL;
    }
    /* 'a+' reads and writes one FILE: C wants a positioning call between the two. */
    return fseek(f, 0, SEEK_END) == 0 ? SDCSV_OK : SDCSV_FAIL;
}

/* picolibc drops its whole 128-B buffer when a write-out fails, with the tail of an earlier row
 * in it. Its fclose hides a failed flush too. Flushed after every row, a failure concerns this
 * row alone. */
bool sdcsv_put(FILE *f, const char *row)
{
    return fputs(row, f) != EOF && fflush(f) == 0;
}

/* picolibc's fgets hands back the part before a read error, and the error ends the loop like EOF:
 * a swap then would delete every row behind the bad sector. */
bool sdcsv_keep_newest(const char *csv, const char *tmp, uint32_t keep, char *scratch, size_t cap)
{
    FILE *r = fopen(csv, "r");
    if (!r)
        return errno == ENOENT;
    uint32_t total = 0;
    bool rest = false, whole;
    while (sdcsv_gets(scratch, cap, r, &rest, &whole) && !ferror(r))
        if (whole)
            total++;
    if (ferror(r))
    {
        fclose(r);
        return false;
    }
    /* Not above `keep`: no rewrite of a file that is small enough. */
    if (total <= keep)
    {
        fclose(r);
        return true;
    }
    FILE *w = fseek(r, 0, SEEK_SET) == 0 ? fopen(tmp, "w") : NULL;
    if (!w)
    {
        fclose(r);
        return false;
    }
    uint32_t skip = total - keep, i = 0;
    bool ok = true;
    rest = false;
    while (sdcsv_gets(scratch, cap, r, &rest, &whole))
    {
        if (ferror(r))
        {
            ok = false;
            break;
        }
        if (whole && i++ >= skip && fputs(scratch, w) == EOF)
        {
            ok = false;
            break;
        }
    }
    if (ferror(r))
        ok = false;
    fclose(r);
    /* picolibc's fclose hides a failed flush: without this a cut tmp would replace the csv. */
    if (ok && (fflush(w) != 0 || ferror(w)))
        ok = false;
    if (fclose(w) != 0)
        ok = false;
    if (!ok)
    {
        remove(tmp);
        return false;
    }
    /* FatFs does not rename onto an existing file, so the csv goes first. If that remove fails,
     * the csv stays with every row. */
    if (remove(csv) != 0)
    {
        ESP_LOGW(TAG, "cannot remove %s, the next trim tries again", csv);
        remove(tmp);
        return false;
    }
    /* The csv is gone: sdcsv_recover_tmp renames the tmp before the next append. */
    if (rename(tmp, csv) != 0)
    {
        ESP_LOGW(TAG, "cannot rename %s, the next write tries again", tmp);
        return false;
    }
    return true;
}

/* A missing file counts as removed, so a second delete is no failure. errno keeps the first
 * real error for the caller's log line. */
bool sdcsv_wipe(const char *csv, const char *tmp)
{
    int e = 0;
    if (remove(csv) != 0 && errno != ENOENT)
        e = errno;
    if (remove(tmp) != 0 && errno != ENOENT && !e)
        e = errno;
    errno = e;
    return e == 0;
}

#endif /* CONFIG_ENABLE_SD */
