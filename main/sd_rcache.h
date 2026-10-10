#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* A reader's place in one CSV on the card, so a 5 s refresh of /traffic reads only what was
 * added. Four whole files per refresh came to ~100 KB/s on the bus the SD card shares with
 * Ethernet. The caller keeps the rows it parsed, and this keeps where they end. The caller
 * holds the SD lock or the reader guard around open, the reads and done, as for any file. */

/* The bytes before the resume point that must still be there: the sector FatFs rewrites on an
 * append lies inside them, and a prune or an upload that moves the rows changes them. */
#define SDRC_ANCHOR 512

typedef struct {
    uint32_t off;     /* parsed up to here, always just after a '\n' */
    uint32_t pos;     /* the read in progress: bytes consumed */
    uint32_t end;     /* the read in progress: just after its last '\n' */
    uint32_t gen;     /* the writer's count of rewrites and failed writes at open */
    uint32_t pend;    /* the read in progress: bytes in anchor past end (a row cut at the end) */
    uint16_t alen;    /* bytes in anchor */
    bool valid;       /* off, alen and anchor describe the file */
    bool tail;        /* the read in progress started at off */
    bool lost;        /* pos is unknown: a piece ran into the end of the file */
    char anchor[SDRC_ANCHOR];
} sdrc_t;

/* Opens path for reading. c->tail true: the place still holds (same gen, the bytes before off
 * unchanged) and the FILE stands at off, the caller keeps its rows. c->tail false: it stands at
 * 0 and the caller drops them. may_tail false always reads from 0. NULL with fopen's errno. */
FILE *sdrc_open(sdrc_t *c, const char *path, uint32_t gen, bool may_tail);

/* Call after each piece the reader's fgets wrapper handed back, while ferror is clear. Counts
 * the piece's bytes and keeps the last of them, so the anchor needs no second read. */
void sdrc_piece(sdrc_t *c, FILE *f, const char *b, size_t cap);

/* After the read, before fclose: keeps the place when ok (the end reached, no error, every row
 * kept), else the next open reads from 0. */
void sdrc_done(sdrc_t *c, FILE *f, bool ok);

#ifdef __cplusplus
}
#endif
