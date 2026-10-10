#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_security.h"
#include "its_verify.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The module remembers the certificates that signed received messages, so that a later
 * digest signer can be matched to one. It verifies nothing. */

/* A digest only points back to a certificate its sender announced shortly before, so the table
 * has to cover the senders in range at one time, not hours of history. The 63 captures of the
 * reference site brought 372 different certificates in total, so nothing was ever evicted. */
#ifndef ITS_CERTCACHE_SIZE
#define ITS_CERTCACHE_SIZE 512
#endif

typedef enum
{
    ITS_SIG_NONE     = 0,  /* No GeoNetworking frame, or the envelope could not be read. */
    ITS_SIG_UNSIGNED = 1,  /* A plain Common Header, or an envelope with unsecured content. */
    ITS_SIG_DIGEST   = 2,
    ITS_SIG_CERT     = 3,
    ITS_SIG_OTHER    = 4,  /* A self signer, encrypted content or an unread alternative. */
} its_sig_kind_t;

typedef enum
{
    ITS_CERT_UNKNOWN = 0,  /* The digest was not looked up. */
    ITS_CERT_KNOWN   = 1,  /* The certificate behind the digest was received before. */
    ITS_CERT_MISSING = 2,  /* The certificate behind the digest is not in the cache. */
} its_cert_state_t;

/* The signer of one frame, small enough to keep with every listed message. */
typedef struct
{
    uint8_t kind;          /* Values come from its_sig_kind_t. */
    uint8_t cert;          /* Values come from its_cert_state_t. Only a digest signer sets it. */
    bool    has_id;        /* id holds the digest or the HashedId8 of the certificate. */
    bool    has_issuer;    /* issuer_id holds the HashedId8 of the certificate's issuer. */
    uint8_t id[8];
    uint8_t issuer_id[8];
} its_sig_summary_t;

/* Permission bytes kept per service. Seven is the longest octet scheme a service defines
 * today: a signal request numbers octets 0 to 6. CAM and DENM reserve octets past that for
 * later use, and such an SSP is kept as unusable on purpose. A receiver that guesses at
 * bytes it does not hold would invent permissions. */
#define ITS_CERTCACHE_SSP_MAX 7
/* A frame showed this service and it carried no permission bytes: the service is allowed
 * without any limit on the content. */
#define ITS_CERTCACHE_SSP_OPEN   0xFE
/* No frame has shown this service yet, so nothing can be said about its content. */
#define ITS_CERTCACHE_SSP_UNSEEN 0xFF

/* One entry as measured with clang on the host and with riscv32-esp-elf-gcc for the device,
 * both 272 bytes. A _Static_assert in its_certcache.c holds the two together. */
#define ITS_CERTCACHE_ENTRY_BYTES 272

typedef struct
{
    uint8_t  id[8];              /* HashedId8 of the certificate. */
    uint8_t  issuer_id[8];       /* It is zero unless the issuer is a digest. */
    uint8_t  issuer;             /* Values come from its_sec_issuer_t. */
    uint8_t  key_type;           /* Values come from its_sec_key_t. */
    uint8_t  duration_unit;      /* Values come from its_sec_duration_t. */
    uint8_t  n_psids;
    bool     psids_cut;          /* The certificate listed more than ITS_SEC_MAX_PSIDS PSIDs. */
    /* Where the issuer certificate came from, with values from its_verify_issuer_from_t.
     * It sits here because the byte fills padding, so the entry does not grow by it. */
    uint8_t  issuer_from;
    uint16_t duration;
    uint32_t validity_start;     /* Time32 counts TAI seconds since 2004-01-01 00:00:00 UTC. */
    uint32_t app_psids[ITS_SEC_MAX_PSIDS];
    /* The permission bytes of each listed service, as far as frames have shown them. The
     * decoder reads them only for the service a frame was sent under, so an entry fills in
     * over time. A message signed by digest can then be judged by what is stored here instead
     * of staying unjudged. Values of ssp_form come from its_sec_ssp_t plus the two markers
     * above, and ssp_len is 0 whenever the bytes cannot be handed out. */
    uint8_t  ssp[ITS_SEC_MAX_PSIDS][ITS_CERTCACHE_SSP_MAX];
    uint8_t  ssp_len[ITS_SEC_MAX_PSIDS];
    uint8_t  ssp_form[ITS_SEC_MAX_PSIDS];
    uint32_t first_seen;         /* Both times use the clock the caller passes in. */
    uint32_t last_seen;
    uint32_t station_id;         /* ItsPduHeader.stationId of the last frame it signed. */
    uint32_t cert_frames;        /* Frames that carried the certificate itself. */
    uint32_t digest_frames;      /* Frames that named it by digest. */
    /* The chain check of its_verify.c, filled in once per certificate. */
    uint8_t  verify;             /* Values come from its_verify_state_t. */
    uint8_t  verify_why;         /* Values come from its_verify_why_t. */
    uint8_t  verify_env;         /* The trust list of the root, 0xFF when there is none. */
    uint8_t  verify_chain;       /* Signatures checked between this certificate and the root. */
    char     issuer_name[ITS_VERIFY_NAME_MAX];
    char     root_name[ITS_VERIFY_NAME_MAX];
} its_certcache_entry_t;

typedef struct
{
    uint32_t entries;
    uint32_t capacity;
    uint32_t hashes;             /* Certificate frames hashed in the receive task. */
    uint32_t reused;             /* Certificate frames whose bytes had just been hashed. */
    uint32_t digests_known;
    uint32_t digests_missing;
    uint32_t evicted;
    uint32_t throttled;          /* Checks the rate limit refused, asked for again later. */
    uint32_t retried;            /* Checks started over because their issuer became known. */
} its_certcache_stats_t;

void its_certcache_init(void);

#ifndef ESP_PLATFORM
/* Host tests only: while this is set the table reports itself busy, which is how the device
 * behaves when a lock times out. It covers the give-up paths of every caller. */
extern bool its_certcache_host_busy;
#endif

/* Describe the signer of an envelope that its_decode_security read from `buf`, which is `len`
 * bytes long. The certificate is held against `len` before a byte of it is hashed, so nothing
 * here rests on its_security.c keeping its offsets in range. Any task may call it, and a digest
 * signer keeps ITS_CERT_UNKNOWN because the table is not asked. */
void its_sig_summarize_len(const uint8_t *buf, size_t len, const its_sec_info_t *sec,
                           its_sig_summary_t *out);

/* Like its_sig_summarize_len, and it also records a certificate signer, looks up a digest
 * signer and asks the verify task for a chain check. The permission bytes and the authority
 * certificate of the header are held against `len` as well. Only the receive task may call it,
 * and the number of checks per second is limited. */
void its_certcache_note_len(const uint8_t *buf, size_t len, const its_sec_info_t *sec,
                            uint32_t station_id, uint32_t now_sec, its_sig_summary_t *out);

/* The same two for a caller that has no frame length at hand. The permission bytes are then
 * still held against the certificate they are in. The certificate itself can only be held
 * against the end of the envelope, and against nothing at all when the walk never reached that
 * end. New callers pass the length. */
void its_sig_summarize(const uint8_t *buf, const its_sec_info_t *sec, its_sig_summary_t *out);
void its_certcache_note(const uint8_t *buf, const its_sec_info_t *sec, uint32_t station_id,
                        uint32_t now_sec, its_sig_summary_t *out);

/* Copy the entry with this HashedId8. Any task may call it. */
bool its_certcache_lookup(const uint8_t id[8], its_certcache_entry_t *out);

/* Walk the cache for the user interface. Returns false once index is past the last used
 * entry, and also while the table is busy. The order is the table order and may change
 * between calls. */
bool its_certcache_at(size_t index, its_certcache_entry_t *out);

/* Slots in use right now, or 0 while the table is busy. Apart from that the number only
 * grows, because nothing frees a slot. */
size_t its_certcache_used(void);

/* Store the chain check of one certificate. Only the verify task calls it, and the entry is
 * found by hashing the same bytes again. */
void its_certcache_set_verify(const uint8_t *cert, size_t len, const its_verify_result_t *res);

/* Mark every certificate that was waiting for its issuer as unchecked again, so that the
 * next frame of that sender starts a new check. A newly learned issuer triggers this. It
 * may be called from any task, and a busy table only delays the sweep. */
void its_certcache_retry_unchecked(void);

/* The permission bytes this cache learned for one service of a certificate. Returns false
 * while nothing is known, which a caller must read as "unknown" and never as "allowed".
 * On true, *form says how to read them: ITS_CERTCACHE_SSP_OPEN means no limit, a bitmap with
 * *len > 0 can be read bit by bit, anything else is there but not usable. */
bool its_certcache_ssp(const its_certcache_entry_t *e, uint32_t psid, const uint8_t **ssp,
                       uint8_t *len, uint8_t *form);

void its_certcache_stats(its_certcache_stats_t *out);

#ifdef __cplusplus
}
#endif
