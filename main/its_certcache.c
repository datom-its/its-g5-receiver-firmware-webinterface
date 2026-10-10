#include "its_certcache.h"

#include <string.h>

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_attr.h"
#include "psa/crypto.h"
#else
#include <pthread.h>
#define EXT_RAM_BSS_ATTR
#endif

/* Certificate bytes up to this length are kept for the reuse check, and longer ones are hashed
 * every time. The captures of the reference site hold 148 to 213 bytes, so none is too long. */
#define MEMO_CERT_MAX 256
/* Senders repeat the same certificate over and over, so keeping the most recent ones spares
 * nearly all of the hashing: 409 hash runs for the 417 647 certificate frames measured. */
#define MEMO_SLOTS    32
/* Issuer certificates already handed over, so a repeated header costs nothing. Few slots are
 * enough: 63 captures brought one single authority, in 18 of 422 945 frames. */
#define ISSUER_SLOTS  4

/* Chain checks asked for per second, and how many may be saved up for a burst. The busiest
 * second of the reference capture brought two new certificates, so the burst carries real
 * traffic while one check per second caps what a flood of forged certificates may cost. */
#define RATE_CERT      1
#define BURST_CERT     8
#define RATE_ISSUER    1
#define BURST_ISSUER   4
/* A submitted certificate is asked for again once this many seconds brought no result. */
#define SENT_WAIT      5

/* The lookup and the eviction read only this, so one pass over the table reads 6 KiB of
 * external memory in one run (512 x 12 bytes, side by side) instead of pulling one 32-byte
 * cache line per entry, 16 KiB, out of the 136 KiB the entries take. */
typedef struct
{
    uint32_t key;                /* First four bytes of the HashedId8, 0 marks a free slot. */
    uint32_t use;                /* Use order, compared modulo 2^32 so a wrap stays harmless. */
    uint32_t sent;               /* Second the certificate went to the verify task, 0 if none. */
} idx_t;

typedef struct
{
    uint16_t len;                /* 0 marks a free slot. */
    uint8_t  id[8];
    uint8_t  bytes[MEMO_CERT_MAX];
} memo_t;

/* Hands out at most `rate` checks per second and keeps up to `burst` of them in reserve.
 * Only the receive task holds one, so no lock is needed. */
typedef struct
{
    uint32_t tokens;
    uint32_t second;
} bucket_t;

/* Keeps the entry size the header names from drifting away from the struct. */
_Static_assert(sizeof(its_certcache_entry_t) == ITS_CERTCACHE_ENTRY_BYTES,
               "ITS_CERTCACHE_ENTRY_BYTES no longer matches its_certcache_entry_t");

/* The tables live in PSRAM and s_lock guards s_idx, s_tab and the counters. The receive task
 * adds and touches entries, the verify task writes results and the web server only reads. */
static EXT_RAM_BSS_ATTR its_certcache_entry_t s_tab[ITS_CERTCACHE_SIZE];
static EXT_RAM_BSS_ATTR idx_t s_idx[ITS_CERTCACHE_SIZE];
static EXT_RAM_BSS_ATTR memo_t s_memo[MEMO_SLOTS];
static unsigned s_memo_next;
static uint32_t s_use;
static its_certcache_stats_t s_stats;
static bucket_t s_bucket_cert;
static bucket_t s_bucket_issuer;
/* The verify task sets this when the table was busy, and the receive task does the sweep.
 * Read and cleared in one step, so a wish arriving in between cannot be lost. */
static bool s_retry_want;

#ifdef ESP_PLATFORM
static SemaphoreHandle_t s_lock;

/* The receive task waits briefly and gives up. Every other caller waits longer, including
 * the verify task when it stores a result. */
static bool lock(bool writer)
{
    return s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(writer ? 10 : 100)) == pdTRUE;
}

static void unlock(void)
{
    xSemaphoreGive(s_lock);
}

void its_certcache_init(void)
{
    if (!s_lock)
        s_lock = xSemaphoreCreateMutex();
}

static bool sha256(const uint8_t *p, size_t n, uint8_t out[32])
{
    size_t olen = 0;
    return psa_hash_compute(PSA_ALG_SHA_256, p, n, out, 32, &olen) == PSA_SUCCESS && olen == 32;
}
#else
static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool s_init;
bool its_certcache_host_busy;

static bool lock(bool writer)
{
    (void)writer;
    return !its_certcache_host_busy && s_init && pthread_mutex_lock(&s_mutex) == 0;
}

static void unlock(void)
{
    pthread_mutex_unlock(&s_mutex);
}

void its_certcache_init(void)
{
    s_init = true;
}

/* Host tests supply the hash. */
bool its_certcache_host_sha256(const uint8_t *p, size_t n, uint8_t out[32]);

static bool sha256(const uint8_t *p, size_t n, uint8_t out[32])
{
    return its_certcache_host_sha256(p, n, out);
}
#endif

static bool take_token(bucket_t *b, uint32_t now, uint32_t rate, uint32_t burst)
{
    uint32_t gap = now - b->second;
    if (b->second == 0 || now < b->second || gap > burst)
    {
        b->tokens = burst;                     /* A clock that jumped starts over. */
    }
    else if (gap > 0)
    {
        b->tokens += gap * rate;               /* gap is at most `burst`, so this cannot wrap. */
        if (b->tokens > burst)
            b->tokens = burst;
    }
    b->second = now;
    if (b->tokens == 0)
        return false;
    b->tokens--;
    return true;
}

/* A submission the verify task refused started no check, so its token comes back. */
static void give_token(bucket_t *b, uint32_t burst)
{
    if (b->tokens < burst)
        b->tokens++;
}

/* How far into `buf` this module may read. The frame length is the proof. Without it, the end
 * of an envelope that was read to its end serves instead, and the reader of its_security.c
 * never places that past the buffer. 0 means neither is at hand. */
static size_t frame_end(size_t len, const its_sec_info_t *sec)
{
    if (len)
        return len;
    return (sec->flags & ITS_SEC_HAVE_SIGNATURE) ? sec->end_off : 0;
}

/* True when off..off+n lies inside 0..end. An empty span or an unknown end proves nothing. */
static bool span_ok(size_t off, size_t n, size_t end)
{
    return n && end && off <= end && n <= end - off;
}

/* True when off..off+n may be read: it is inside `end`, or there is no `end` to hold it
 * against. The second case reads without any bound, so callers should pass the frame length
 * to its_certcache_note_len or its_sig_summarize_len. */
static bool span_free(size_t off, size_t n, size_t end)
{
    return !end || span_ok(off, n, end);
}

/* The HashedId8 rule is confirmed for SHA-256 digests over P-256 certificates in canonical
 * form. Anything else would need another hash or a conversion, so it stays unknown. */
static bool id_computable(const its_sec_info_t *s)
{
    return (s->flags & ITS_SEC_HAVE_SIGNER) && s->signer == ITS_SEC_SIGNER_CERTIFICATE &&
           s->cert_count > 0 && s->cert_len > 0 &&
           !(s->flags & (ITS_SEC_CERT_NONCANON | ITS_SEC_CERT_IMPLICIT)) &&
           (s->key_type == ITS_SEC_KEY_ECDSA_NIST_P256 ||
            s->key_type == ITS_SEC_KEY_ECDSA_BRAINPOOL_P256) &&
           s->issuer == ITS_SEC_ISSUER_SHA256_DIGEST;
}

/* The HashedId8 is the last 8 bytes of the SHA-256 value. */
static bool hashed_id8(const uint8_t *cert, size_t len, uint8_t id[8])
{
    uint8_t h[32];
    if (!sha256(cert, len, h))
        return false;
    memcpy(id, h + 24, 8);
    return true;
}

/* A HashedId8 is a hash value, so its first four bytes carry enough of it for the scan.
 * The one value that marks a free slot is moved aside. */
static uint32_t id_key(const uint8_t id[8])
{
    uint32_t k = (uint32_t)id[0] << 24 | (uint32_t)id[1] << 16 | (uint32_t)id[2] << 8 | id[3];
    return k ? k : 1;
}

typedef enum
{
    HASH_NONE,
    HASH_RUN,
    HASH_REUSED,
} hash_use_t;

/* Receive task only, because the memo is not locked. */
static bool hashed_id8_reusing(const uint8_t *cert, size_t len, uint8_t id[8], hash_use_t *use)
{
    bool keep = len >= 8 && len <= MEMO_CERT_MAX;
    /* The signature at the end differs between certificates, so compare from there. */
    for (unsigned i = 0; keep && i < MEMO_SLOTS; i++)
    {
        const memo_t *m = &s_memo[i];
        if (m->len == len && memcmp(m->bytes + len - 8, cert + len - 8, 8) == 0 &&
            memcmp(m->bytes, cert, len) == 0)
        {
            memcpy(id, m->id, 8);
            *use = HASH_REUSED;
            return true;
        }
    }
    if (!hashed_id8(cert, len, id))
        return false;
    *use = HASH_RUN;
    if (keep)
    {
        memo_t *m = &s_memo[s_memo_next];
        s_memo_next = (s_memo_next + 1) % MEMO_SLOTS;
        memcpy(m->bytes, cert, len);
        memcpy(m->id, id, 8);
        m->len = (uint16_t)len;
    }
    return true;
}

static bool issuer_is_digest(uint8_t issuer)
{
    return issuer == ITS_SEC_ISSUER_SHA256_DIGEST || issuer == ITS_SEC_ISSUER_SHA384_DIGEST ||
           issuer == ITS_SEC_ISSUER_SM3_DIGEST;
}

/* `use` is NULL outside the receive task, and then nothing is reused. A nonzero `end` bounds
 * every read of `buf`, and 0 means no bound at all. */
static void summarize(const uint8_t *buf, size_t end, const its_sec_info_t *sec,
                      its_sig_summary_t *out, hash_use_t *use)
{
    memset(out, 0, sizeof *out);
    if (!buf || !sec || !sec->valid)
        return;
    if (sec->content == ITS_SEC_UNSECURED)
    {
        out->kind = ITS_SIG_UNSIGNED;
        return;
    }
    if (sec->content != ITS_SEC_SIGNED)
    {
        out->kind = ITS_SIG_OTHER;
        return;
    }
    /* A walk that stopped before the signer says nothing about it. */
    if (!(sec->flags & ITS_SEC_HAVE_SIGNER))
        return;
    switch (sec->signer)
    {
    case ITS_SEC_SIGNER_DIGEST:
        out->kind = ITS_SIG_DIGEST;
        out->has_id = true;
        memcpy(out->id, sec->digest, 8);
        break;
    case ITS_SEC_SIGNER_CERTIFICATE:
        out->kind = ITS_SIG_CERT;
        if (sec->cert_count > 0 && issuer_is_digest(sec->issuer))
        {
            out->has_issuer = true;
            memcpy(out->issuer_id, sec->issuer_id, 8);
        }
        /* With a known frame end, the certificate is hashed only when it lies inside. */
        if (id_computable(sec) && span_free(sec->cert_off, sec->cert_len, end))
            out->has_id = use ? hashed_id8_reusing(buf + sec->cert_off, sec->cert_len, out->id, use)
                              : hashed_id8(buf + sec->cert_off, sec->cert_len, out->id);
        break;
    default:
        out->kind = ITS_SIG_OTHER;
        break;
    }
}

void its_sig_summarize_len(const uint8_t *buf, size_t len, const its_sec_info_t *sec,
                           its_sig_summary_t *out)
{
    if (!buf || !sec || !out)
    {
        if (out)
            memset(out, 0, sizeof *out);
        return;
    }
    summarize(buf, frame_end(len, sec), sec, out, NULL);
}

void its_sig_summarize(const uint8_t *buf, const its_sec_info_t *sec, its_sig_summary_t *out)
{
    its_sig_summarize_len(buf, 0, sec, out);
}

/* The slot of this HashedId8, or -1. The full identifier is compared only where the key
 * matched, which for random keys is the wanted slot. */
static int find_locked(const uint8_t id[8])
{
    uint32_t key = id_key(id);
    for (size_t i = 0; i < ITS_CERTCACHE_SIZE; i++)
        if (s_idx[i].key == key && memcmp(s_tab[i].id, id, 8) == 0)
            return (int)i;
    return -1;
}

/* A free slot if there is one, else the one used longest ago. A certificate whose check is
 * still running is taken last, so that no started check is thrown away. */
static int victim_locked(uint32_t now)
{
    int idle = -1, running = -1;
    for (size_t i = 0; i < ITS_CERTCACHE_SIZE; i++)
    {
        if (!s_idx[i].key)
        {
            s_stats.entries++;
            return (int)i;
        }
        /* A submission without an answer counts as running for SENT_WAIT seconds only, so a
         * result that never came back cannot hold a slot for good. */
        bool busy = s_idx[i].sent && (uint32_t)(now - s_idx[i].sent) <= SENT_WAIT;
        int *pick = busy ? &running : &idle;
        if (*pick < 0 || (int32_t)(s_idx[i].use - s_idx[*pick].use) < 0)
            *pick = (int)i;
    }
    s_stats.evicted++;               /* One entry leaves and one arrives, so entries stays. */
    return idle >= 0 ? idle : running;
}

/* Everything that was only waiting for its issuer starts over, and a later frame of that
 * sender asks for the check again. */
static void retry_locked(void)
{
    for (size_t i = 0; i < ITS_CERTCACHE_SIZE; i++)
        if (s_idx[i].key && s_tab[i].verify == ITS_VERIFY_UNCHECKABLE &&
            s_tab[i].verify_why == ITS_VERIFY_WHY_ISSUER)
        {
            s_tab[i].verify = ITS_VERIFY_UNKNOWN;
            s_tab[i].verify_why = ITS_VERIFY_WHY_NONE;
            s_idx[i].sent = 0;
            s_stats.retried++;
        }
}

/* A frame can carry the certificate of its issuer in the header. That is the only way the
 * device learns an authority over the air, and built-in ones come from its_castore. The
 * receive task is the only caller, so nothing here is locked. */
static void note_issuer_cert(const uint8_t *buf, size_t end, const its_sec_info_t *sec,
                             uint32_t now_sec)
{
    /* The last bytes are part of the signature, so two certificates of the same length still
     * differ there. Their first bytes do not, because those hold the same issuer. */
    static uint16_t seen_len[ISSUER_SLOTS];
    static uint8_t seen_tail[ISSUER_SLOTS][8];
    static unsigned seen_next;
    /* The last eight bytes are compared, and the whole certificate goes to the verify task.
     * When `end` is known, both have to lie inside it before anything is read. */
    if (!(sec->flags & ITS_SEC_HAVE_HEADER) || sec->req_cert_len < 8 ||
        !span_free(sec->req_cert_off, sec->req_cert_len, end))
        return;
    const uint8_t *cert = buf + sec->req_cert_off;
    const uint8_t *tail = cert + sec->req_cert_len - 8;
    for (unsigned i = 0; i < ISSUER_SLOTS; i++)
        if (seen_len[i] == sec->req_cert_len && memcmp(seen_tail[i], tail, 8) == 0)
            return;
    if (!take_token(&s_bucket_issuer, now_sec, RATE_ISSUER, BURST_ISSUER))
    {
        s_stats.throttled++;
        return;
    }
    if (!its_verify_submit(cert, sec->req_cert_len, true))
    {
        give_token(&s_bucket_issuer, BURST_ISSUER);
        return;
    }
    seen_len[seen_next] = sec->req_cert_len;
    memcpy(seen_tail[seen_next], tail, 8);
    seen_next = (seen_next + 1) % ISSUER_SLOTS;
}

/* Keep the permission bytes of the service this frame was sent under. Only the matching service
 * is touched, so a certificate used for two services fills both in over time. Bytes are copied
 * only from inside the first certificate, whose appPermissions hold the SSP, and from inside
 * `end` when that is known. A span that nothing proves leaves the service as it was. A form or
 * a length this cache cannot hand on marks the service as seen without bytes, which reads as
 * unknown and never as allowed. */
static void store_ssp(its_certcache_entry_t *e, const uint8_t *buf, size_t end,
                      const its_sec_info_t *sec)
{
    bool absent = (sec->flags & ITS_SEC_SSP_ABSENT) != 0;
    if (!absent && sec->ssp_form == ITS_SEC_SSP_NONE)
        return;
    bool bitmap = !absent && sec->ssp_form == ITS_SEC_SSP_BITMAP && sec->ssp_len;
    /* The SSP sits in the appPermissions of the first certificate, and this module has hashed
     * exactly those bytes already, so the certificate bounds the copy as tightly as the frame. */
    bool span = bitmap && sec->ssp_off >= sec->cert_off &&
                span_ok(sec->ssp_off, sec->ssp_len, (size_t)sec->cert_off + sec->cert_len) &&
                span_free(sec->ssp_off, sec->ssp_len, end);
    /* The frame names bytes, but nothing proves where they are. They are neither read nor
     * written, so the service keeps what a readable frame showed before. */
    if (bitmap && !span)
        return;
    for (uint8_t k = 0; k < e->n_psids; k++)
    {
        if (e->app_psids[k] != sec->psid)
            continue;
        e->ssp_len[k] = 0;
        if (absent)
        {
            e->ssp_form[k] = ITS_CERTCACHE_SSP_OPEN;
        }
        else if (bitmap && sec->ssp_len <= ITS_CERTCACHE_SSP_MAX)
        {
            memcpy(e->ssp[k], buf + sec->ssp_off, sec->ssp_len);
            e->ssp_len[k] = sec->ssp_len;
            e->ssp_form[k] = ITS_SEC_SSP_BITMAP;
        }
        else
        {
            /* The SSP is there, but in a form this cache cannot hand on, or longer than an
             * entry holds. With ssp_len 0 both read as unknown and never as allowed. */
            e->ssp_form[k] = sec->ssp_form;
        }
        return;
    }
}

bool its_certcache_ssp(const its_certcache_entry_t *e, uint32_t psid, const uint8_t **ssp,
                       uint8_t *len, uint8_t *form)
{
    if (!e)
        return false;
    for (uint8_t k = 0; k < e->n_psids && k < ITS_SEC_MAX_PSIDS; k++)
    {
        if (e->app_psids[k] != psid || e->ssp_form[k] == ITS_CERTCACHE_SSP_UNSEEN)
            continue;
        if (ssp)
            *ssp = e->ssp[k];
        if (len)
            *len = e->ssp_len[k];
        if (form)
            *form = e->ssp_form[k];
        return true;
    }
    return false;
}

void its_certcache_note_len(const uint8_t *buf, size_t len, const its_sec_info_t *sec,
                            uint32_t station_id, uint32_t now_sec, its_sig_summary_t *out)
{
    if (!buf || !sec || !out)
    {
        if (out)
            memset(out, 0, sizeof *out);
        return;
    }
    hash_use_t use = HASH_NONE;
    size_t end = frame_end(len, sec);
    summarize(buf, end, sec, out, &use);
    note_issuer_cert(buf, end, sec, now_sec);
    if (out->kind == ITS_SIG_CERT && out->has_id)
    {
        if (!lock(true))
            return;
        if (__atomic_exchange_n(&s_retry_want, false, __ATOMIC_RELAXED))
            retry_locked();
        s_stats.hashes += use == HASH_RUN;
        s_stats.reused += use == HASH_REUSED;
        int i = find_locked(out->id);
        if (i < 0)
        {
            i = victim_locked(now_sec);
            memset(&s_tab[i], 0, sizeof s_tab[i]);
            s_idx[i].key = id_key(out->id);
            s_idx[i].sent = 0;
            its_certcache_entry_t *e = &s_tab[i];
            memcpy(e->id, out->id, 8);
            memcpy(e->issuer_id, sec->issuer_id, 8);
            e->issuer = sec->issuer;
            e->key_type = sec->key_type;
            e->duration_unit = sec->duration_unit;
            e->duration = sec->duration;
            e->validity_start = sec->validity_start;
            e->n_psids = sec->n_psids <= ITS_SEC_MAX_PSIDS ? sec->n_psids : ITS_SEC_MAX_PSIDS;
            memcpy(e->app_psids, sec->app_psids, e->n_psids * sizeof e->app_psids[0]);
            e->psids_cut = (sec->flags & ITS_SEC_PSIDS_CUT) != 0;
            /* Zero would read as its_sec_ssp_t NONE, so every slot starts as UNSEEN. */
            memset(e->ssp_form, ITS_CERTCACHE_SSP_UNSEEN, sizeof e->ssp_form);
            e->first_seen = now_sec;
            e->verify_env = 0xFF;
        }
        store_ssp(&s_tab[i], buf, end, sec);
        s_tab[i].last_seen = now_sec;
        s_tab[i].station_id = station_id;
        s_tab[i].cert_frames++;
        s_idx[i].use = ++s_use;
        /* A submission whose result never came back is asked for again, so a lost result or
         * a verify task that did not start cannot leave a certificate unchecked for good. */
        bool want = s_tab[i].verify == ITS_VERIFY_UNKNOWN &&
                    (s_idx[i].sent == 0 || now_sec - s_idx[i].sent > SENT_WAIT);
        unlock();
        if (!want)
            return;
        if (!take_token(&s_bucket_cert, now_sec, RATE_CERT, BURST_CERT))
        {
            s_stats.throttled++;
            return;
        }
        /* The check itself runs in another task, and the queue is asked outside the lock so
         * that the two never wait on each other. */
        if (!its_verify_submit(buf + sec->cert_off, sec->cert_len, false))
        {
            give_token(&s_bucket_cert, BURST_CERT);
            return;
        }
        if (lock(true))
        {
            int again = find_locked(out->id);
            if (again >= 0)
                s_idx[again].sent = now_sec ? now_sec : 1;
            unlock();
        }
    }
    else if (out->kind == ITS_SIG_DIGEST)
    {
        if (!lock(true))
            return;
        int i = find_locked(out->id);
        if (i >= 0)
        {
            out->cert = ITS_CERT_KNOWN;
            if (issuer_is_digest(s_tab[i].issuer))
            {
                out->has_issuer = true;
                memcpy(out->issuer_id, s_tab[i].issuer_id, 8);
            }
            s_tab[i].last_seen = now_sec;
            s_tab[i].station_id = station_id;
            s_tab[i].digest_frames++;
            s_idx[i].use = ++s_use;
            s_stats.digests_known++;
        }
        else
        {
            out->cert = ITS_CERT_MISSING;
            s_stats.digests_missing++;
        }
        unlock();
    }
}

void its_certcache_note(const uint8_t *buf, const its_sec_info_t *sec, uint32_t station_id,
                        uint32_t now_sec, its_sig_summary_t *out)
{
    its_certcache_note_len(buf, 0, sec, station_id, now_sec, out);
}

void its_certcache_set_verify(const uint8_t *cert, size_t len, const its_verify_result_t *res)
{
    uint8_t id[8];
    /* Hashed before the lock, because the lock must not hold a hash run. */
    if (!cert || !len || !res || !hashed_id8(cert, len, id) || !lock(false))
        return;
    int i = find_locked(id);
    if (i >= 0)
    {
        s_tab[i].verify = res->state;
        s_tab[i].verify_why = res->why;
        s_tab[i].verify_env = res->root_env;
        s_tab[i].verify_chain = res->chain;
        s_tab[i].issuer_from = res->issuer_from;
        memcpy(s_tab[i].issuer_name, res->issuer_name, sizeof s_tab[i].issuer_name);
        memcpy(s_tab[i].root_name, res->root_name, sizeof s_tab[i].root_name);
        s_idx[i].sent = 0;
    }
    unlock();
}

void its_certcache_retry_unchecked(void)
{
    if (!lock(false))
    {
        __atomic_store_n(&s_retry_want, true, __ATOMIC_RELAXED);
        return;
    }
    retry_locked();
    unlock();
}

bool its_certcache_lookup(const uint8_t id[8], its_certcache_entry_t *out)
{
    if (!id || !out || !lock(false))
        return false;
    int i = find_locked(id);
    if (i >= 0)
        *out = s_tab[i];
    unlock();
    return i >= 0;
}

/* A free slot is skipped rather than shown, so `index` counts used slots and not table
 * places. The lock is taken and given back per entry, like its_certcache_lookup does:
 * holding it for a whole page would stall the receive task for as long as the page takes.
 * A busy table therefore ends the walk early, which shows fewer rows and never wrong ones. */
bool its_certcache_at(size_t index, its_certcache_entry_t *out)
{
    if (!out || !lock(false))
        return false;
    bool found = false;
    size_t seen = 0;
    for (size_t i = 0; i < ITS_CERTCACHE_SIZE; i++)
    {
        if (!s_idx[i].key)
            continue;
        if (seen++ == index)
        {
            *out = s_tab[i];
            found = true;
            break;
        }
    }
    unlock();
    return found;
}

/* Counted from the table and not from s_stats.entries, so a page can never ask for more
 * rows than its_certcache_at hands out. A busy table answers 0 for the same reason. */
size_t its_certcache_used(void)
{
    if (!lock(false))
        return 0;
    size_t n = 0;
    for (size_t i = 0; i < ITS_CERTCACHE_SIZE; i++)
        if (s_idx[i].key)
            n++;
    unlock();
    return n;
}

void its_certcache_stats(its_certcache_stats_t *out)
{
    /* The counters are only displayed. When the lock stays busy, an unlocked copy may mix
     * two updates, which is still closer to the truth than zeros. */
    bool locked = lock(false);
    *out = s_stats;
    if (locked)
        unlock();
    out->capacity = ITS_CERTCACHE_SIZE;
}
