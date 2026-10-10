#include "its_msgsig.h"

#include <string.h>

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "psa/crypto.h"

#include "its_verify.h"
static const char *TAG = "its_msgsig";
#else
#include <pthread.h>
#define EXT_RAM_BSS_ATTR
#endif

/* As many keys as its_certcache.c keeps certificates: a digest names a certificate sent shortly
 * before. 63 captures of the test receiver brought 372 in 240 h. */
#define CERTS 512
/* A certificate waits half to one and a half times this before its next sample, so no sender
 * can time its frames around them. 0 checks every frame (host tests). */
#ifndef ITS_MSGSIG_HOLD_HW_S
#define ITS_MSGSIG_HOLD_HW_S 10
#endif
#ifndef ITS_MSGSIG_HOLD_SW_S
#define ITS_MSGSIG_HOLD_SW_S 600
#endif
/* Time share per kind in tenths of a percent: after d us the next check waits d*(1000-s)/s.
 * P-256 runs in hardware (19.4 ms on the test receiver), Brainpool in software (3.6 s). */
#define SHARE_HW 20
#define SHARE_SW 25
/* Certificates without a trusted chain get half of that at most, so self-made ones cannot take
 * the sample away from trusted senders. */
#define SHARE_UN_DIV 2
/* What an answer other than a match costs the brakes until a match measured its kind: the self
 * test for P-256, the mean of two message checks for Brainpool, both on the test receiver. */
#define FLOOR_HW_US 19420
#define FLOOR_SW_US 3620641
/* Answers kept for /trust. The brakes let about one check a second finish, so 32 cover some
 * half a minute or more. At the test receiver they cover about an hour. */
#define RECENT 32
/* A mismatch goes to the log at most once in this many seconds. The first mismatch of a
 * certificate with a trusted chain always does. */
#define WARN_EVERY_S 10

typedef struct
{
    uint8_t  id[8];
    uint8_t  hash[32];           /* SHA-256 over the certificate bytes, the signer input. */
    uint8_t  key[33];
    uint8_t  key_type;
    uint8_t  last;
    uint8_t  spare;
    uint16_t ok;
    uint16_t bad;
    uint32_t due;                /* Receive clock second before which no sample starts, 0 none. */
    uint32_t last_at;
} cert_t;

typedef struct
{
    uint8_t          busy;       /* 0 free, 1 waiting, 2 running */
    its_msgsig_job_t job;
    its_msgsig_rec_t rec;
} slot_t;

/* The table lives in PSRAM. Only the receive task writes key, hash, due and s_use, so it reads
 * them unlocked. It also reads ok and bad unlocked, because it only shows them. The other
 * tasks take s_lock for every field. */
static EXT_RAM_BSS_ATTR cert_t s_cert[CERTS];
static EXT_RAM_BSS_ATTR uint32_t s_key[CERTS];     /* first 4 bytes of the id, 0 marks free */
static EXT_RAM_BSS_ATTR uint32_t s_use[CERTS];
static uint32_t s_use_ctr;
static EXT_RAM_BSS_ATTR slot_t s_slot[2];          /* 0 hardware curve, 1 software curve */
static int64_t s_next_us[2];                       /* the brake of each kind */
static int64_t s_next_un[2];                       /* and its part for untrusted chains */
static EXT_RAM_BSS_ATTR its_msgsig_rec_t s_recent[RECENT];
static unsigned s_recent_head, s_recent_n;
static its_msgsig_stats_t s_st;
static uint32_t s_serial;
static its_msgsig_sink_t s_sink;
static uint32_t s_warn_at, s_warn_quiet;
static uint32_t s_rand = 0x9E3779B9u;
static bool s_keep;

#ifdef ESP_PLATFORM
static SemaphoreHandle_t s_lock;

void its_msgsig_init(void)
{
    if (!s_lock)
        s_lock = xSemaphoreCreateMutex();
    s_rand ^= esp_random();
    if (!s_rand)
        s_rand = 0x9E3779B9u;
}

static bool lock(uint32_t ms)
{
    return s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(ms)) == pdTRUE;
}

static void unlock(void)
{
    xSemaphoreGive(s_lock);
}

static int64_t now_us(void)
{
    return esp_timer_get_time();
}

/* alg 0 is SHA-256, 1 SHA-384. */
static bool hash(uint8_t alg, const uint8_t *p, size_t n, uint8_t *out)
{
    size_t olen = 0, want = alg ? 48 : 32;
    return psa_hash_compute(alg ? PSA_ALG_SHA_384 : PSA_ALG_SHA_256, p, n, out, want, &olen) ==
               PSA_SUCCESS &&
           olen == want;
}
#else
static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;
static int64_t s_host_us;

void its_msgsig_init(void)
{
}

bool (*its_msgsig_host_hash)(uint8_t alg, const uint8_t *p, size_t n, uint8_t *out);

static bool lock(uint32_t ms)
{
    (void)ms;
    return pthread_mutex_lock(&s_mutex) == 0;
}

static void unlock(void)
{
    pthread_mutex_unlock(&s_mutex);
}

static int64_t now_us(void)
{
    return s_host_us;
}

static bool hash(uint8_t alg, const uint8_t *p, size_t n, uint8_t *out)
{
    return its_msgsig_host_hash && its_msgsig_host_hash(alg, p, n, out);
}

void its_msgsig_host_set_us(int64_t us)
{
    s_host_us = us;
}

void its_msgsig_host_reset(void)
{
    memset(s_cert, 0, sizeof s_cert);
    memset(s_key, 0, sizeof s_key);
    memset(s_use, 0, sizeof s_use);
    memset(s_slot, 0, sizeof s_slot);
    memset(s_next_us, 0, sizeof s_next_us);
    memset(s_next_un, 0, sizeof s_next_un);
    memset(s_recent, 0, sizeof s_recent);
    memset(&s_st, 0, sizeof s_st);
    s_recent_head = s_recent_n = 0;
    s_use_ctr = s_serial = s_warn_at = s_warn_quiet = 0;
    s_rand = 0x9E3779B9u;
    s_sink = NULL;
    s_keep = false;
}

/* file_answer is defined further down, but the host hook below needs it here. */
static bool file_answer(const its_msgsig_rec_t *r);

void its_msgsig_host_file(const its_msgsig_rec_t *r)
{
    if (r && lock(100))
    {
        (void)file_answer(r);
        unlock();
    }
}

void its_msgsig_host_policy(unsigned *hold_hw_s, unsigned *hold_sw_s, unsigned *share_permille,
                            unsigned *recent, unsigned *warn_s)
{
    *hold_hw_s = ITS_MSGSIG_HOLD_HW_S;
    *hold_sw_s = ITS_MSGSIG_HOLD_SW_S;
    *share_permille = SHARE_HW + SHARE_SW;
    *recent = RECENT;
    *warn_s = WARN_EVERY_S;
}
#endif

/* xorshift32: the jitter only has to be unknown to a sender, not secret. */
static uint32_t next_rand(void)
{
    s_rand ^= s_rand << 13;
    s_rand ^= s_rand >> 17;
    s_rand ^= s_rand << 5;
    return s_rand;
}

/* 0 stays free for "no check". */
static uint32_t next_serial(void)
{
    if (!++s_serial)
        ++s_serial;
    return s_serial;
}

static uint32_t id_key(const uint8_t id[8])
{
    uint32_t k = (uint32_t)id[0] << 24 | (uint32_t)id[1] << 16 | (uint32_t)id[2] << 8 | id[3];
    return k ? k : 1;
}

static int find(const uint8_t id[8])
{
    uint32_t k = id_key(id);
    for (int i = 0; i < CERTS; i++)
        if (s_key[i] == k && memcmp(s_cert[i].id, id, 8) == 0)
            return i;
    return -1;
}

/* A free slot, else the one used longest ago. Under the lock. */
static int victim(void)
{
    int old = 0;
    for (int i = 0; i < CERTS; i++)
    {
        if (!s_key[i])
            return i;
        if ((int32_t)(s_use[i] - s_use[old]) < 0)
            old = i;
    }
    return old;
}

static void answer(its_msgsig_t *out, uint8_t state, uint8_t why)
{
    out->state = state;
    out->why = why;
}

/* Copy the compressed key point of the certificate. The certificate and the key point must both
 * lie inside the frame. Only the two curves kept here count, and only canonical explicit
 * certificates hash to the signer input. */
static bool key_of(const uint8_t *f, size_t len, const its_sec_info_t *s, uint8_t key[33])
{
    size_t c0 = s->cert_off, c1 = (size_t)s->cert_off + s->cert_len;
    if ((s->key_type != ITS_SEC_KEY_ECDSA_NIST_P256 &&
         s->key_type != ITS_SEC_KEY_ECDSA_BRAINPOOL_P256) ||
        (s->flags & (ITS_SEC_CERT_NONCANON | ITS_SEC_CERT_IMPLICIT)) || !s->cert_len ||
        c1 > len || s->key_off <= c0 || (size_t)s->key_off + 33 > c1)
        return false;
    uint8_t tag = f[s->key_off];
    if ((tag & 0xC0) != 0x80 || ((tag & 0x3F) != 2 && (tag & 0x3F) != 3))
        return false;
    key[0] = tag & 0x3F;
    memcpy(key + 1, f + s->key_off + 1, 32);
    return true;
}

/* The HashedId8 of a certificate signer: its_certcache.c's, else the low 8 bytes of SHA-384
 * when the issuer is a sha384AndDigest. False for a self-signed one. */
static bool cert_id(const uint8_t *f, const its_sec_info_t *s, const its_sig_summary_t *sig,
                    uint8_t id[8])
{
    if (sig->has_id)
    {
        memcpy(id, sig->id, 8);
        return true;
    }
    uint8_t h[48];
    if (s->issuer != ITS_SEC_ISSUER_SHA384_DIGEST || !hash(1, f + s->cert_off, s->cert_len, h))
        return false;
    memcpy(id, h + 40, 8);
    return true;
}

/* The message Signature at sig_off: the curve tag, rSig as x-only, compressed or uncompressed
 * point, then sSig. Returns the curve, or -1 for another form. r and s are copied only for
 * 256-bit curves. */
static int sig_of(const uint8_t *f, size_t len, const its_sec_info_t *s, uint8_t rs[64])
{
    size_t p = s->sig_off, end = s->end_off < len ? s->end_off : len;
    if (p + 2 > end || (f[p] & 0xC0) != 0x80 || (f[p + 1] & 0xC0) != 0x80)
        return -1;
    unsigned curve = f[p] & 0x3F, form = f[p + 1] & 0x3F;
    if (curve > ITS_SEC_SIG_ECDSA_NIST_P384 || form == 1 || form > 4)
        return -1;
    size_t w = curve >= ITS_SEC_SIG_ECDSA_BRAINPOOL_P384 ? 48 : 32;
    size_t r = p + 2, sx = r + (form == 4 ? 2 * w : w);
    if (sx + w > end)
        return -1;
    if (w == 32)
    {
        memcpy(rs, f + r, 32);
        memcpy(rs + 32, f + sx, 32);
    }
    return (int)curve;
}

/* Book a check of `us` on the brake of its kind, and one without a trusted chain also on its
 * own part. Under the lock. */
static void charge(int kind, bool trusted, uint32_t us)
{
    int64_t now = now_us(), share = kind ? SHARE_SW : SHARE_HW, un = share / SHARE_UN_DIV;
    s_next_us[kind] = now + (int64_t)us * (1000 - share) / share;
    if (!trusted)
        s_next_un[kind] = now + (int64_t)us * (1000 - un) / un;
}

/* What a full check of `kind` costs: the newest match, else the floor. Under the lock. */
static uint32_t full_us(int kind)
{
    return s_st.n[kind] ? s_st.us_last[kind] : kind ? FLOOR_SW_US : FLOOR_HW_US;
}

static void push_recent(const its_msgsig_rec_t *r)
{
    s_recent[s_recent_head] = *r;
    s_recent_head = (s_recent_head + 1) % RECENT;
    if (s_recent_n < RECENT)
        s_recent_n++;
}

/* File one answer: the certificate, the list of answers and the counters. Under the lock.
 * True for the first mismatch of a certificate in the table. */
static bool file_answer(const its_msgsig_rec_t *r)
{
    bool first_bad = false;
    int i = find(r->id);
    if (i >= 0)
    {
        cert_t *c = &s_cert[i];
        if (r->state == ITS_MSGSIG_OK && c->ok < UINT16_MAX)
            c->ok++;
        if (r->state == ITS_MSGSIG_BAD && c->bad < UINT16_MAX)
            first_bad = ++c->bad == 1;
        c->last = r->state;
        c->last_at = r->at;
    }
    push_recent(r);
    s_st.ok += r->state == ITS_MSGSIG_OK;
    s_st.bad += r->state == ITS_MSGSIG_BAD;
    s_st.refused += r->state == ITS_MSGSIG_UNCHECKABLE;
    return first_bad;
}

/* Whether a mismatch gets its log line: the first of a certificate with a trusted chain always,
 * the others one per WARN_EVERY_S, counted into *quiet. Under the lock. */
static bool warn_due(const its_msgsig_rec_t *r, bool first_trusted, uint32_t *quiet)
{
    if (!first_trusted && s_warn_at && r->at - s_warn_at < WARN_EVERY_S)
    {
        s_warn_quiet++;
        return false;
    }
    *quiet = s_warn_quiet;
    s_warn_at = r->at ? r->at : 1;
    s_warn_quiet = 0;
    return true;
}

/* Called outside the lock. The line goes to the console and the system log on the card, and
 * it holds what is needed to find the frame in the recording. */
static void warn_line(const its_msgsig_rec_t *r, bool trusted, uint32_t quiet)
{
#ifdef ESP_PLATFORM
    ESP_LOGW(TAG, "message signature does not match: received %lu, station %lu, message %u, "
                  "PSID %lu, certificate %02x%02x%02x%02x%02x%02x%02x%02x (chain %s), "
                  "%lu more since the last line",
             (unsigned long)r->at, (unsigned long)r->station, (unsigned)r->msg_kind,
             (unsigned long)r->psid, r->id[0], r->id[1], r->id[2], r->id[3], r->id[4], r->id[5],
             r->id[6], r->id[7], trusted ? "trusted" : "not trusted", (unsigned long)quiet);
#else
    (void)r;
    (void)trusted;
    (void)quiet;
#endif
}

/* Whether the chain of this certificate checked out (its_certcache.c). */
static bool chain_trusted(const uint8_t id[8])
{
    /* Static: only the receive task asks, and an entry is 272 bytes. */
    static EXT_RAM_BSS_ATTR its_certcache_entry_t e;
    return its_certcache_lookup(id, &e) && e.verify == ITS_VERIFY_CHECKED;
}

static void note(const uint8_t *frame, size_t len, const its_sec_info_t *sec,
                 const its_sig_summary_t *sig, uint32_t station, uint8_t stype,
                 uint8_t msg_kind, uint32_t now_sec, its_msgsig_t *out)
{
    memset(out, 0, sizeof *out);
    out->curve = 0xFF;
    if (!frame || !len || !sec || !sig)
        return;
    /* Only these kinds come from `sec` of this very frame; the others leave it as it was. */
    if (sig->kind == ITS_SIG_OTHER && sec->valid && sec->content == ITS_SEC_SIGNED)
    {
        answer(out, ITS_MSGSIG_UNCHECKABLE, ITS_MSGSIG_WHY_FORM);
        s_st.nocheck++;
        return;
    }
    if (sig->kind != ITS_SIG_CERT && sig->kind != ITS_SIG_DIGEST)
        return;
    if (!(sec->flags & ITS_SEC_HAVE_SIGNATURE) || (sig->kind == ITS_SIG_DIGEST && !sig->has_id))
    {
        answer(out, ITS_MSGSIG_UNCHECKABLE, ITS_MSGSIG_WHY_FORM);
        s_st.nocheck++;
        return;
    }

    /* Static like the job below: only the receive task gets here, and its stack is small. */
    static EXT_RAM_BSS_ATTR cert_t fresh;
    uint8_t id[8];
    bool have_id = sig->kind == ITS_SIG_DIGEST;
    int i = -1;
    if (have_id)
    {
        memcpy(id, sig->id, 8);
        i = find(id);
        if (i < 0)
        {
            answer(out, ITS_MSGSIG_UNCHECKABLE, ITS_MSGSIG_WHY_NOCERT);
            s_st.nocheck++;
            return;
        }
    }
    else
    {
        memset(&fresh, 0, sizeof fresh);
        if (!key_of(frame, len, sec, fresh.key))
        {
            answer(out, ITS_MSGSIG_UNCHECKABLE, ITS_MSGSIG_WHY_FORM);
            s_st.nocheck++;
            return;
        }
        have_id = cert_id(frame, sec, sig, id);
        i = have_id ? find(id) : -1;
    }
    /* A certificate signer seen for the first time: its key and hash. Without an id (a
     * self-signed one) the entry serves this frame only and stays out of the table. */
    if (i < 0)
    {
        if (!hash(0, frame + sec->cert_off, sec->cert_len, fresh.hash))
        {
            answer(out, ITS_MSGSIG_UNCHECKABLE, ITS_MSGSIG_WHY_CRYPTO);
            s_st.nocheck++;
            return;
        }
        fresh.key_type = sec->key_type;
        if (have_id)
        {
            memcpy(fresh.id, id, 8);
            if (!lock(10))
            {
                answer(out, ITS_MSGSIG_BUSY, ITS_MSGSIG_WHY_NONE);
                s_st.busy++;
                return;
            }
            i = victim();
            if (!s_key[i])
                s_st.certs++;
            s_cert[i] = fresh;
            s_key[i] = id_key(id);
            unlock();
        }
    }
    cert_t *c = i >= 0 ? &s_cert[i] : &fresh;
    if (i >= 0)
        s_use[i] = ++s_use_ctr;
    out->curve = c->key_type;
    out->ok = c->ok;
    out->bad = c->bad;
    if (sec->hash_id != 0)
    {
        answer(out, ITS_MSGSIG_UNCHECKABLE, ITS_MSGSIG_WHY_HASH);
        s_st.nocheck++;
        return;
    }
    /* A due further ahead than any wait this module sets comes from a clock that jumped back. */
    uint32_t ahead = c->due - now_sec;
    if (c->due && (int32_t)ahead > 0 && ahead <= 2 * ITS_MSGSIG_HOLD_SW_S)
    {
        answer(out, ITS_MSGSIG_SAMPLE, ITS_MSGSIG_WHY_NONE);
        s_st.sample++;
        return;
    }
    int kind = c->key_type == ITS_SEC_KEY_ECDSA_NIST_P256 ? 0 : 1;
    if (!lock(10))
    {
        answer(out, ITS_MSGSIG_BUSY, ITS_MSGSIG_WHY_NONE);
        s_st.busy++;
        return;
    }
    int64_t t = now_us();
    bool open = !s_slot[kind].busy && t >= s_next_us[kind], open_un = t >= s_next_un[kind];
    unlock();
    /* The chain is asked only while the general brake is open. While the brake of untrusted
     * chains is shut, each of their frames asks again (a read lock and a lookup, no ECDSA). */
    bool trusted = open && have_id && chain_trusted(id);
    if (!open || (!trusted && !open_un))
    {
        answer(out, ITS_MSGSIG_BUSY, ITS_MSGSIG_WHY_NONE);
        s_st.busy++;
        return;
    }

    its_msgsig_rec_t rec;
    memset(&rec, 0, sizeof rec);
    rec.at = now_sec;
    rec.station = station;
    rec.psid = sec->psid;
    rec.msg_kind = msg_kind;
    rec.stype = stype;
    rec.curve = c->key_type;
    memcpy(rec.id, c->id, 8);
    static EXT_RAM_BSS_ATTR its_msgsig_job_t job;
    memset(&job, 0, sizeof job);
    int curve = sig_of(frame, len, sec, job.rs);
    if (curve < 0 || (size_t)sec->tbs_off + sec->tbs_len > len || !sec->tbs_len)
    {
        answer(out, ITS_MSGSIG_UNCHECKABLE, ITS_MSGSIG_WHY_FORM);
        s_st.nocheck++;
        return;
    }
    /* The next sample of this certificate waits from here on, also after the answers below. */
    uint32_t hold = kind ? ITS_MSGSIG_HOLD_SW_S : ITS_MSGSIG_HOLD_HW_S;
    c->due = now_sec + (hold ? hold / 2 + next_rand() % hold : 0);
    if (!c->due)
        c->due = 1;
    if (curve != c->key_type)
    {
        /* No ECDSA could match, but it counts on the brakes like a check of its kind, so
         * such frames cannot flood the list and the log. */
        rec.state = ITS_MSGSIG_BAD;
        rec.why = ITS_MSGSIG_WHY_CURVE;
        answer(out, ITS_MSGSIG_BAD, ITS_MSGSIG_WHY_CURVE);
        uint32_t quiet = 0;
        bool warn = false;
        if (lock(10))
        {
            rec.serial = next_serial();
            s_st.started++;
            s_st.untrusted += !trusted;
            bool first = file_answer(&rec);
            uint32_t d = full_us(kind);
            charge(kind, trusted, d);
            warn = warn_due(&rec, first && trusted, &quiet);
            unlock();
        }
        if (warn)
            warn_line(&rec, trusted, quiet);
        return;
    }
    int64_t t0 = now_us();
    uint8_t both[64];
    bool hashed = hash(0, frame + sec->tbs_off, sec->tbs_len, both);
    memcpy(both + 32, c->hash, 32);
    hashed = hashed && hash(0, both, sizeof both, job.digest);
    uint32_t hus = (uint32_t)(now_us() - t0);
    if (hus > s_st.hash_us_max)
        s_st.hash_us_max = hus;
    if (!hashed)
    {
        answer(out, ITS_MSGSIG_UNCHECKABLE, ITS_MSGSIG_WHY_CRYPTO);
        s_st.nocheck++;
        return;
    }
    job.key_type = c->key_type;
    memcpy(job.key, c->key, sizeof job.key);
    job.slot = (uint8_t)kind;
    job.trusted = trusted;
    if (!lock(10))
    {
        answer(out, ITS_MSGSIG_BUSY, ITS_MSGSIG_WHY_NONE);
        s_st.busy++;
        return;
    }
    /* Only this task fills a slot, so the one found free above is still free. */
    job.serial = rec.serial = next_serial();
    s_slot[kind].job = job;
    s_slot[kind].rec = rec;
    s_slot[kind].busy = 1;
    s_st.started++;
    s_st.untrusted += !trusted;
    unlock();
    out->serial = job.serial;
    answer(out, ITS_MSGSIG_PENDING, ITS_MSGSIG_WHY_NONE);
#ifdef ESP_PLATFORM
    its_verify_wake();
#endif
}

void its_msgsig_note(const uint8_t *frame, size_t len, const its_sec_info_t *sec,
                     const its_sig_summary_t *sig, uint32_t station, uint8_t stype,
                     uint8_t msg_kind, uint32_t now_sec, its_msgsig_t *out)
{
    s_keep = false;
    if (!out)
        return;
    /* The whole cost on the receive task, table scan and hashing included. */
    int64_t t0 = now_us();
    note(frame, len, sec, sig, station, stype, msg_kind, now_sec, out);
    uint32_t us = (uint32_t)(now_us() - t0);
    if (us > s_st.note_us_max)
        s_st.note_us_max = us;
    s_keep = out->state == ITS_MSGSIG_PENDING || out->state == ITS_MSGSIG_BAD;
}

bool its_msgsig_take_keep(void)
{
    bool k = s_keep;
    s_keep = false;
    return k;
}

bool its_msgsig_take(its_msgsig_job_t *job)
{
    if (!job || !lock(100))
        return false;
    bool got = false;
    for (int k = 0; k < 2 && !got; k++)
        if (s_slot[k].busy == 1)
        {
            s_slot[k].busy = 2;
            *job = s_slot[k].job;
            got = true;
        }
    unlock();
    return got;
}

void its_msgsig_done(const its_msgsig_job_t *job, int match, uint32_t us)
{
    if (!job || job->slot > 1)
        return;
    uint8_t state = match > 0    ? ITS_MSGSIG_OK
                    : match == 0 ? ITS_MSGSIG_BAD
                                 : ITS_MSGSIG_UNCHECKABLE;
    uint8_t why = match < 0 ? ITS_MSGSIG_WHY_CRYPTO : ITS_MSGSIG_WHY_NONE;
    its_msgsig_sink_t sink = NULL;
    its_msgsig_rec_t r;
    uint32_t quiet = 0;
    bool first = false, warn = false;
    uint32_t serial = job->serial;
    /* The verify task waits for the lock: a lost answer would keep its slot taken for good. */
    while (!lock(1000))
        ;
    slot_t *sl = &s_slot[job->slot];
    if (sl->busy == 2 && sl->job.serial == serial)
    {
        r = sl->rec;
        r.state = state;
        r.why = why;
        r.us = us;
        bool first_bad = file_answer(&r);
        /* Only a match proves a full run: an r or s out of range fails within microseconds. So
         * only matches are timed, and every other answer costs the brake at least a full one. */
        uint32_t full = full_us(job->slot);
        if (match > 0)
        {
            first = s_st.n[job->slot] == 0;
            s_st.n[job->slot]++;
            s_st.us_last[job->slot] = us;
            s_st.us_sum[job->slot] += us;
            if (us > s_st.us_max[job->slot])
                s_st.us_max[job->slot] = us;
        }
        if (state == ITS_MSGSIG_BAD)
            warn = warn_due(&r, first_bad && job->trusted, &quiet);
        charge(job->slot, job->trusted, match > 0 || us > full ? us : full);
        sl->busy = 0;
        sink = s_sink;
    }
    unlock();
    if (warn)
        warn_line(&r, job->trusted, quiet);
#ifdef ESP_PLATFORM
    /* One line per curve and boot, so the log carries the measured cost. */
    if (first)
        ESP_LOGI(TAG, "first check on %s took %lu us",
                 job->key_type == ITS_SEC_KEY_ECDSA_NIST_P256 ? "P-256" : "brainpoolP256r1",
                 (unsigned long)us);
#else
    (void)first;
#endif
    if (sink)
        sink(serial, state, why);
}

void its_msgsig_set_sink(its_msgsig_sink_t fn)
{
    if (lock(1000))
    {
        s_sink = fn;
        unlock();
    }
}

bool its_msgsig_cert(const uint8_t id[8], its_msgsig_cert_t *out)
{
    if (!id || !out || !lock(100))
        return false;
    int i = find(id);
    if (i >= 0)
    {
        out->ok = s_cert[i].ok;
        out->bad = s_cert[i].bad;
        out->last = s_cert[i].last;
        out->curve = s_cert[i].key_type;
        out->last_at = s_cert[i].last_at;
    }
    unlock();
    return i >= 0;
}

bool its_msgsig_recent(size_t index, its_msgsig_rec_t *out)
{
    if (!out || !lock(100))
        return false;
    bool got = index < s_recent_n;
    if (got)
        *out = s_recent[(s_recent_head + RECENT - 1 - index) % RECENT];
    unlock();
    return got;
}

void its_msgsig_stats(its_msgsig_stats_t *out)
{
    if (!out)
        return;
    /* Only displayed: an unlocked copy beats zeros when the lock stays busy. */
    bool locked = lock(100);
    *out = s_st;
    if (locked)
        unlock();
}
