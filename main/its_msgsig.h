#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_certcache.h"
#include "its_security.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Checks the signature of received messages themselves, as a sample. IEEE 1609.2 signs
 * h(h(ToBeSignedData) || h(signer certificate)). its_verify.c runs the ECDSA. */

/* The answer for one message. NONE is the zero value, so a cleared msg_extra_t says nothing. */
typedef enum
{
    ITS_MSGSIG_NONE        = 0,  /* No signed envelope, or a frame out of the archive. */
    ITS_MSGSIG_SAMPLE      = 1,  /* Not checked: this certificate was checked a short time ago. */
    ITS_MSGSIG_BUSY        = 2,  /* Not checked: a check is running or the time share is used up. */
    ITS_MSGSIG_PENDING     = 3,  /* Handed to the verify task, the answer is not back yet. */
    ITS_MSGSIG_OK          = 4,  /* The signature matches the key of the certificate. */
    ITS_MSGSIG_BAD         = 5,  /* It does not: changed on the way, or not signed with that key. */
    ITS_MSGSIG_UNCHECKABLE = 6,  /* Something the check needs is missing, see its_msgsig_why_t. */
} its_msgsig_state_t;

typedef enum
{
    ITS_MSGSIG_WHY_NONE   = 0,
    ITS_MSGSIG_WHY_NOCERT = 1,   /* The digest names a certificate not received (yet) or let go. */
    ITS_MSGSIG_WHY_FORM   = 2,   /* A certificate or signature form this build does not read. */
    ITS_MSGSIG_WHY_HASH   = 3,   /* The message names a hash other than SHA-256. */
    ITS_MSGSIG_WHY_CRYPTO = 4,   /* The crypto library refused the key or the hash. */
    ITS_MSGSIG_WHY_CURVE  = 5,   /* With BAD: the signature uses another curve than the key. */
} its_msgsig_why_t;

/* Kept with every listed message, 12 bytes. ok and bad count the checks of its certificate when
 * the frame came, so a message that was not checked still tells how its sender fared. */
typedef struct
{
    uint8_t  state;              /* Values come from its_msgsig_state_t. */
    uint8_t  why;                /* Values come from its_msgsig_why_t. */
    uint8_t  curve;              /* its_sec_key_t of the signer key, 0xFF when unknown. */
    uint8_t  spare;
    uint16_t ok;
    uint16_t bad;
    uint32_t serial;             /* The check behind PENDING, for the sink; 0 for none. */
} its_msgsig_t;

/* One check for the verify task: a 256-bit key point (form byte 2 or 3, then x), the finished
 * hash and r followed by s. */
typedef struct
{
    uint32_t serial;
    uint8_t  slot;
    uint8_t  key_type;           /* Values come from its_sec_key_t. */
    uint8_t  key[33];
    uint8_t  digest[32];
    uint8_t  rs[64];
    uint8_t  trusted;            /* The certificate's chain was trusted when the check began. */
} its_msgsig_job_t;

/* One finished check, for /trust. */
typedef struct
{
    uint32_t serial;
    uint32_t at;                 /* Receive clock second of the frame. */
    uint32_t station;            /* ItsPduHeader.stationId, 0 when the header was not found. */
    uint32_t psid;
    uint32_t us;                 /* Time of the ECDSA run on the verify task, 0 without one. */
    uint8_t  id[8];              /* HashedId8 of the signing certificate, zero when unknown. */
    uint8_t  state;              /* Values come from its_msgsig_state_t. */
    uint8_t  why;
    uint8_t  curve;              /* its_sec_key_t */
    uint8_t  msg_kind;           /* Message type from its_msg_kind (11 = EVCSN), 0 when unknown. */
    uint8_t  stype;              /* GN station type of the source (5 car, 15 RSU), 0 when unknown. */
} its_msgsig_rec_t;

/* What the checks of one certificate gave so far. */
typedef struct
{
    uint16_t ok;
    uint16_t bad;
    uint8_t  last;               /* its_msgsig_state_t of the newest answer, NONE before one. */
    uint8_t  curve;
    uint32_t last_at;            /* Receive clock second of the frame of that answer. */
} its_msgsig_cert_t;

/* Counters per curve: NIST P-256 and brainpoolP256r1, the two curves whose keys are kept. */
#define ITS_MSGSIG_CURVES 2

typedef struct
{
    /* Per message, counted on the receive task. With `started` they add up to the signed
     * messages, except frames cut before their signer and a rare lost lock on the curve path. */
    uint32_t sample;
    uint32_t busy;
    uint32_t nocheck;            /* ITS_MSGSIG_UNCHECKABLE before any ECDSA */
    uint32_t started;            /* handed to the verify task, or turned down on the curve */
    uint32_t untrusted;          /* of those, certificates without a trusted chain */
    /* Per finished check: ok + bad + refused equals started minus the checks in flight. */
    uint32_t ok;
    uint32_t bad;
    uint32_t refused;            /* the crypto library refused, UNCHECKABLE/CRYPTO */
    /* Timed per curve: matches only, since any other answer may have stopped early. */
    uint32_t n[ITS_MSGSIG_CURVES];
    uint32_t us_max[ITS_MSGSIG_CURVES];
    uint32_t us_last[ITS_MSGSIG_CURVES];
    uint64_t us_sum[ITS_MSGSIG_CURVES];
    uint32_t hash_us_max;        /* the hashing of one sampled frame, receive task */
    uint32_t note_us_max;        /* one its_msgsig_note, scan and hashing included */
    uint32_t certs;              /* certificates whose key is kept */
} its_msgsig_stats_t;

/* Create the lock and seed the sampling jitter. Call once before the receive task starts. */
void its_msgsig_init(void);

/* Look at one received frame: `sec` is its envelope, `sig` its signer. Receive task only. `sec`
 * is read only when sig->kind says signed, since it may otherwise hold an earlier frame. */
void its_msgsig_note(const uint8_t *frame, size_t len, const its_sec_info_t *sec,
                     const its_sig_summary_t *sig, uint32_t station, uint8_t stype,
                     uint8_t msg_kind, uint32_t now_sec, its_msgsig_t *out);

/* Whether the frame its_msgsig_note saw last was sampled, so the recording keeps it. Reading
 * clears it; receive task only. */
bool its_msgsig_take_keep(void);

/* The verify task takes the next waiting check with its_msgsig_take and hands back the result
 * with its_msgsig_done: 1 match, 0 no match, -1 the library refused. `us` is the time the
 * ECDSA took. */
bool its_msgsig_take(its_msgsig_job_t *job);
void its_msgsig_done(const its_msgsig_job_t *job, int match, uint32_t us);

/* Called on the verify task after each answer, outside every lock of this module, so the message
 * list can update its copy of a PENDING message. */
typedef void (*its_msgsig_sink_t)(uint32_t serial, uint8_t state, uint8_t why);
void its_msgsig_set_sink(its_msgsig_sink_t fn);

/* The checks of one certificate. False when its key is not (or no longer) kept. Any task. */
bool its_msgsig_cert(const uint8_t id[8], its_msgsig_cert_t *out);

/* The finished checks, newest first. False past the last one. Any task. */
bool its_msgsig_recent(size_t index, its_msgsig_rec_t *out);

void its_msgsig_stats(its_msgsig_stats_t *out);

#ifndef ESP_PLATFORM
/* Host tests only: the hash (alg 0 SHA-256, 1 SHA-384; NULL fails every hash), a pinned
 * microsecond clock and a fixed jitter seed, and a reset between cases. */
extern bool (*its_msgsig_host_hash)(uint8_t alg, const uint8_t *p, size_t n, uint8_t *out);
void its_msgsig_host_set_us(int64_t us);
/* Called for every log line of a mismatch, with its receive second and the frames it names as
 * left out since the line before. */
extern void (*its_msgsig_host_warn)(uint32_t at, uint32_t quiet);
void its_msgsig_host_reset(void);
/* File a finished check as if the verify task had answered it, for the page tests. */
void its_msgsig_host_file(const its_msgsig_rec_t *r);
/* The numbers the texts on /system and /trust repeat, so a test can hold the two together. */
void its_msgsig_host_policy(unsigned *hold_hw_s, unsigned *hold_sw_s, unsigned *share_permille,
                            unsigned *recent, unsigned *warn_s);
#endif

#ifdef __cplusplus
}
#endif
