#include "its_verify.h"

#include <string.h>
#include <time.h>

#include "its_castore.h"
#include "its_certcache.h"
#include "its_crl.h"
#include "its_msgsig.h"
#include "its_trustlist.h"

#ifdef ESP_PLATFORM
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "esp_attr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "mbedtls/pk.h"
#include "psa/crypto.h"
static const char *TAG = "its_verify";
#else
#include <pthread.h>
#define EXT_RAM_BSS_ATTR
#endif

/* ------------------------------------------------------------- COER walk */

/* The cursor walks the COER bytes of one certificate. `err` latches on the first truncated
 * or malformed field, and every later read then returns 0 without touching the buffer. */
typedef struct
{
    const uint8_t *b;
    size_t len;
    size_t pos;
    bool err;
} oer_t;

static bool oer_avail(oer_t *r, size_t n)
{
    if (r->err || n > r->len - r->pos)
    {
        r->err = true;
        return false;
    }
    return true;
}

static uint64_t oer_uint(oer_t *r, unsigned n)
{
    if (!oer_avail(r, n))
        return 0;
    uint64_t v = 0;
    for (unsigned i = 0; i < n; i++)
        v = (v << 8) | r->b[r->pos + i];
    r->pos += n;
    return v;
}

static uint8_t oer_u8(oer_t *r)
{
    return (uint8_t)oer_uint(r, 1);
}

static void oer_skip(oer_t *r, size_t n)
{
    if (oer_avail(r, n))
        r->pos += n;
}

/* Read a COER length determinant. A certificate never needs more than four length bytes. */
static size_t oer_length(oer_t *r)
{
    if (!oer_avail(r, 1))
        return 0;
    uint8_t b0 = r->b[r->pos];
    if ((b0 & 0x80) == 0)
    {
        r->pos++;
        return b0;
    }
    unsigned n = b0 & 0x7F;
    if (n == 0 || n > 4 || !oer_avail(r, 1 + n))
    {
        r->err = true;
        return 0;
    }
    size_t v = 0;
    for (unsigned i = 0; i < n; i++)
        v = (v << 8) | r->b[r->pos + 1 + i];
    r->pos += 1 + n;
    return v;
}

static void oer_skip_prefixed(oer_t *r)
{
    oer_skip(r, oer_length(r));
}

/* Read an unconstrained INTEGER, which COER writes as a length and two's complement bytes.
 * A chain length stays far below four bytes, so anything longer is malformed here. */
static int32_t oer_int(oer_t *r)
{
    size_t n = oer_length(r);
    if (r->err || n == 0 || n > 4 || !oer_avail(r, n))
    {
        r->err = true;
        return 0;
    }
    uint32_t v = (r->b[r->pos] & 0x80) ? 0xFFFFFFFFu : 0;
    for (size_t i = 0; i < n; i++)
        v = (v << 8) | r->b[r->pos + i];
    r->pos += n;
    /* Spelled out because C11 leaves the conversion above INT32_MAX implementation-defined. */
    return v > (uint32_t)INT32_MAX ? -(int32_t)(~v) - 1 : (int32_t)v;
}

/* Read a SEQUENCE OF quantity. Every element takes at least one byte, so a count beyond the
 * remaining bytes means the data is malformed. */
static size_t oer_quantity(oer_t *r)
{
    size_t n = oer_length(r);
    if (r->err || n == 0 || n > 4)
    {
        r->err = true;
        return 0;
    }
    size_t q = (size_t)oer_uint(r, (unsigned)n);
    if (r->err || q > r->len - r->pos)
    {
        r->err = true;
        return 0;
    }
    return q;
}

/* Read a context class CHOICE tag with a tag number below 63 and return the index of the
 * chosen alternative. */
static unsigned oer_tag(oer_t *r)
{
    uint8_t t = oer_u8(r);
    if ((t & 0xC0) != 0x80 || (t & 0x3F) == 0x3F)
        r->err = true;
    return r->err ? 0 : (unsigned)(t & 0x3F);
}

/* Read an ENUMERATED value. The long form only encodes values unknown here, so it is
 * skipped and reported as 255. */
static uint8_t oer_enum(oer_t *r)
{
    uint8_t b = oer_u8(r);
    if (b < 0x80)
        return b;
    oer_skip(r, b & 0x7F);
    return 255;
}

/* Read a Psid, an INTEGER (0..MAX) that COER writes as a length and unsigned bytes. Four bytes
 * cover every registered value, and a longer one is malformed here rather than silently
 * truncated. */
static uint32_t oer_psid(oer_t *r)
{
    size_t n = oer_length(r);
    if (r->err || n == 0 || n > 4)
    {
        r->err = true;
        return 0;
    }
    return (uint32_t)oer_uint(r, (unsigned)n);
}

/* Read the extension presence bitmap and skip one open type per set bit. */
static void oer_extensions(oer_t *r)
{
    size_t n = oer_length(r);
    uint8_t unused = oer_u8(r);
    if (r->err || n == 0 || unused > 7 || (n == 1 && unused != 0) || !oer_avail(r, n - 1))
    {
        r->err = true;
        return;
    }
    const uint8_t *bits = r->b + r->pos;
    size_t nbytes = n - 1;
    r->pos += nbytes;
    for (size_t i = 0; i < nbytes && !r->err; i++)
    {
        uint8_t v = bits[i];
        if (i + 1 == nbytes)
            v &= (uint8_t)(0xFF << unused);
        for (unsigned k = 0; k < 8 && !r->err; k++)
            if (v & (0x80 >> k))
                oer_skip_prefixed(r);
    }
}

/* A curve point is x-only, fill, compressed-y-0, compressed-y-1 or uncompressed. `size` is
 * the byte length of one coordinate, and `off` and `bytes` describe what follows the form. */
static unsigned read_point(oer_t *r, size_t size, uint16_t *off, uint16_t *bytes)
{
    unsigned form = oer_tag(r);
    if (form > 4)
    {
        r->err = true;
        return form;
    }
    size_t n = form == 1 ? 0 : form == 4 ? 2 * size : size;
    if (off)
        *off = (uint16_t)r->pos;
    if (bytes)
        *bytes = (uint16_t)n;
    oer_skip(r, n);
    return form;
}

static bool point_compressed(unsigned form)
{
    return form == 2 || form == 3;
}

static void skip_identified_region(oer_t *r)
{
    unsigned idx = oer_tag(r);
    if (idx > 2)
    {
        oer_skip_prefixed(r);
        return;
    }
    oer_skip(r, 2);                           /* UnCountryId */
    if (idx == 1)
    {
        oer_skip(r, oer_quantity(r));         /* Each region takes one byte. */
    }
    else if (idx == 2)
    {
        size_t q = oer_quantity(r);
        for (size_t i = 0; i < q && !r->err; i++)
        {
            oer_skip(r, 1);                   /* region */
            oer_skip(r, 2 * oer_quantity(r)); /* Each subregion takes two bytes. */
        }
    }
}

static void skip_region(oer_t *r)
{
    unsigned idx = oer_tag(r);
    if (idx == 0)
        oer_skip(r, 8 + 2);                   /* CircularRegion has a center and a radius. */
    else if (idx == 1)
        oer_skip(r, 16 * oer_quantity(r));    /* Each RectangularRegion takes 16 bytes. */
    else if (idx == 2)
        oer_skip(r, 8 * oer_quantity(r));     /* Each PolygonalRegion corner takes 8 bytes. */
    else if (idx == 3)
    {
        size_t q = oer_quantity(r);
        for (size_t i = 0; i < q && !r->err; i++)
            skip_identified_region(r);
    }
    else
    {
        oer_skip_prefixed(r);
    }
}

/* Step over one SspRange: opaque is a SequenceOfOctetString, all is a NULL and takes no
 * bytes, and everything beyond is an extension and so an open type. */
static void skip_ssp_range(oer_t *r)
{
    unsigned idx = oer_tag(r);
    if (idx == 0)
    {
        size_t n = oer_quantity(r);           /* SequenceOfOctetString */
        for (size_t k = 0; k < n && !r->err; k++)
            oer_skip_prefixed(r);
    }
    else if (idx > 1)
    {
        oer_skip_prefixed(r);                 /* bitmapSspRange is an extension. */
    }
}

/* Walk a SequenceOfPsidSspRange. With `want` given the walk stops at that PSID and `found`
 * says whether it was there, which is how a group is asked whether it covers a PSID. */
static void walk_psid_ranges(oer_t *r, const uint32_t *want, bool *found)
{
    size_t q = oer_quantity(r);
    for (size_t i = 0; i < q && !r->err; i++)
    {
        uint8_t opt = oer_u8(r);              /* Bit 7 flags sspRange. */
        uint32_t psid = oer_psid(r);
        if (r->err)
            return;
        if (want && psid == *want)
        {
            *found = true;
            return;
        }
        if (opt & 0x80)
            skip_ssp_range(r);
    }
}

static void skip_psid_ranges(oer_t *r)
{
    walk_psid_ranges(r, NULL, NULL);
}

/* One PsidGroupPermissions as the chain check needs it. The PSIDs stay in the certificate
 * bytes. `psid_off` and `psid_len` say where, so nothing of variable size lands on the stack. */
typedef struct
{
    uint8_t  subject;        /* 0 explicit, 1 all, 2 an alternative this build cannot read. */
    uint8_t  ee_type;        /* Bit 7 app, bit 6 enrol. The ASN.1 default {app} is 0x80. */
    int32_t  min_chain;
    int32_t  range;          /* -1 leaves the upper end of the window open. */
    uint16_t psid_off;
    uint16_t psid_len;
} group_t;

/* Read the next PsidGroupPermissions out of `r`. The three DEFAULT fields carry the values
 * of Ieee1609Dot2.asn when their preamble bit is clear. */
static bool read_group(oer_t *r, group_t *g)
{
    uint8_t opt = oer_u8(r);                  /* Bits 7 to 5 flag the three DEFAULT fields. */
    g->subject = 1;
    g->ee_type = 0x80;
    g->min_chain = 1;
    g->range = 0;
    g->psid_off = 0;
    g->psid_len = 0;
    unsigned idx = oer_tag(r);                /* subjectPermissions */
    if (idx == 0)
    {
        size_t from = r->pos;
        g->subject = 0;
        skip_psid_ranges(r);
        g->psid_off = (uint16_t)from;
        g->psid_len = (uint16_t)(r->pos - from);
    }
    else if (idx > 1)
    {
        g->subject = 2;
        oer_skip_prefixed(r);
    }
    if (opt & 0x80)
        g->min_chain = oer_int(r);
    if (opt & 0x40)
        g->range = oer_int(r);
    if (opt & 0x20)
        g->ee_type = oer_u8(r);
    return !r->err;
}

/* The longest chain `g` still allows below its certificate, INT32_MAX for a range of -1.
 * Computed wide, because minChainLength and chainLengthRange are unconstrained integers. */
static int32_t group_top(const group_t *g)
{
    if (g->range == -1)
        return INT32_MAX;
    int64_t hi = (int64_t)g->min_chain + g->range;
    return hi > INT32_MAX ? INT32_MAX : (hi < 0 ? 0 : (int32_t)hi);
}

/* Read a SequenceOfPsidGroupPermissions. With `out` given, the group count, the smallest
 * minChainLength with its chainLengthRange and the widest window are kept, which is what
 * certIssuePermissions has to offer for a chain check. Pass NULL for certRequestPermissions,
 * whose own span is enough to walk it again later. */
static void read_group_permissions(oer_t *r, its_verify_cert_t *out)
{
    size_t q = oer_quantity(r);
    for (size_t i = 0; i < q && !r->err; i++)
    {
        group_t g;
        if (!read_group(r, &g) || !out)
            continue;
        if (!out->issue_groups || g.min_chain < out->issue_min_chain)
        {
            out->issue_min_chain = g.min_chain;
            out->issue_chain_range = g.range;
        }
        int32_t top = group_top(&g);
        if (!out->issue_groups || top > out->issue_max_chain)
            out->issue_max_chain = top;
        if (g.subject == 2)
            out->issue_unknown = true;
        if (out->issue_groups < 255)
            out->issue_groups++;
    }
}

/* PublicEncryptionKey holds supportedSymmAlg and a BasePublicEncryptionKey. Return true when
 * its point is not compressed. The canonical form requires a compressed point. */
static bool skip_public_enc_key(oer_t *r)
{
    oer_enum(r);
    unsigned idx = oer_tag(r);
    if (idx <= 1)
        return !point_compressed(read_point(r, 32, NULL, NULL));
    size_t n = oer_length(r);                 /* ecencSm2 is an extension. */
    size_t end = r->pos + n;
    if (idx > 2)
    {
        oer_skip(r, n);
        return false;                         /* An unknown key type says nothing about the form. */
    }
    bool loose = !point_compressed(read_point(r, 32, NULL, NULL));
    if (r->pos != end)
        r->err = true;
    return loose;
}

/* Read the CertificateId. `name` gets the name alternative and stays empty otherwise. */
static void read_cert_id(oer_t *r, char *name)
{
    unsigned idx = oer_tag(r);
    switch (idx)
    {
    case 0:                                   /* linkageData */
    {
        uint8_t opt = oer_u8(r);              /* Bit 7 flags group-linkage-value. */
        oer_skip(r, 2 + 9);                   /* iCert, linkage-value */
        if (opt & 0x80)
            oer_skip(r, 4 + 9);               /* jValue, value */
        break;
    }
    case 1:                                   /* name */
    {
        size_t n = oer_length(r);
        if (!oer_avail(r, n))
            return;
        size_t keep = n < ITS_VERIFY_NAME_MAX - 1 ? n : ITS_VERIFY_NAME_MAX - 1;
        for (size_t i = 0; i < keep; i++)
        {
            uint8_t c = r->b[r->pos + i];
            name[i] = c >= 0x20 && c < 0x7F ? (char)c : '?';
        }
        name[keep] = 0;
        r->pos += n;
        break;
    }
    case 3:                                   /* none */
        break;
    default:                                  /* binaryId, or an unknown extension */
        oer_skip_prefixed(r);
        break;
    }
}

/* Read the Signature and note where rSig and sSig start. */
static uint8_t read_signature(oer_t *r, its_verify_cert_t *out)
{
    unsigned idx = oer_tag(r);
    size_t end = 0;
    size_t size = 32;
    if (idx > ITS_SEC_SIG_ECDSA_BRAINPOOL_P256)
    {
        size_t n = oer_length(r);
        end = r->pos + n;
        if (idx > ITS_SEC_SIG_SM2)
        {
            oer_skip(r, n);
            return ITS_SEC_SIG_OTHER;
        }
        size = idx == ITS_SEC_SIG_SM2 ? 32 : 48;
    }
    if (idx == ITS_SEC_SIG_SM2)
    {
        oer_skip(r, 2 * size);                /* Both parts are plain OCTET STRINGs. */
    }
    else
    {
        uint16_t off = 0, bytes = 0;
        unsigned form = read_point(r, size, &off, &bytes);
        if (form == 1)
            r->err = true;                    /* The fill alternative carries no r at all. */
        else if (form != 0)
            out->canonical = false;           /* Only an x-only rSig is canonical. */
        out->sig_r_off = off;
        out->sig_s_off = (uint16_t)r->pos;
        out->sig_len = (uint16_t)size;
        oer_skip(r, size);                    /* sSig */
    }
    if (end && r->pos != end)
        r->err = true;
    return (uint8_t)idx;
}

bool its_verify_parse(const uint8_t *cert, size_t len, its_verify_cert_t *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    out->canonical = true;
    if (!cert || len < 6 || len > UINT16_MAX)
        return false;

    oer_t r = { cert, len, 0, false };
    /* CertificateBase has the signature as its only option and no extension marker, so
     * every other bit of the preamble has to be zero. */
    uint8_t opt = oer_u8(&r);
    uint8_t version = oer_u8(&r);
    uint8_t type = oer_enum(&r);
    if (version != 3 || type > 1 || (opt & 0x7F) != 0)
        return false;
    out->implicit = type == 1;

    unsigned issuer = oer_tag(&r);
    if (issuer == ITS_SEC_ISSUER_SELF)
    {
        out->self_signed = true;
        out->hash_alg = oer_enum(&r);         /* HashAlgorithm of a self-signed certificate. */
    }
    else if (issuer <= ITS_SEC_ISSUER_SM3_DIGEST)
    {
        /* Only sha256AndDigest comes without a length, the other two are extensions. */
        if (issuer != ITS_SEC_ISSUER_SHA256_DIGEST && oer_length(&r) != 8)
            return false;
        if (!oer_avail(&r, 8))
            return false;
        memcpy(out->issuer_id, cert + r.pos, 8);
        oer_skip(&r, 8);
        out->hash_alg = issuer == ITS_SEC_ISSUER_SHA256_DIGEST
                            ? 0
                            : (issuer == ITS_SEC_ISSUER_SHA384_DIGEST ? 1 : 2);
    }
    else
    {
        return false;
    }
    if (r.err)
        return false;

    size_t tbs = r.pos;
    /* Bit 7 flags extensions. Bits 6 to 0 flag the optional fields. */
    uint8_t flags = oer_u8(&r);
    read_cert_id(&r, out->name);
    oer_skip(&r, 3 + 2);                      /* cracaId, crlSeries */
    out->valid_start = (uint32_t)oer_uint(&r, 4);
    out->duration_unit = (uint8_t)oer_tag(&r);
    if (out->duration_unit > ITS_SEC_DUR_YEARS)
        r.err = true;
    out->duration = (uint16_t)oer_uint(&r, 2);
    if (flags & 0x40)
        skip_region(&r);
    if (flags & 0x20)
        oer_skip(&r, 1);                      /* assuranceLevel */
    if (flags & 0x10)
    {
        out->app_perms = true;                /* appPermissions */
        size_t from = r.pos;
        size_t q = oer_quantity(&r);
        for (size_t i = 0; i < q && !r.err; i++)
        {
            uint8_t ssp = oer_u8(&r);         /* Bit 7 flags ssp. */
            oer_psid(&r);
            if (ssp & 0x80)
            {
                oer_tag(&r);                  /* Every alternative continues with a length. */
                oer_skip_prefixed(&r);
            }
        }
        out->app_off = (uint16_t)from;
        out->app_len = (uint16_t)(r.pos - from);
    }
    if (flags & 0x08)
    {
        out->cert_issue = true;               /* certIssuePermissions */
        size_t from = r.pos;
        read_group_permissions(&r, out);
        out->issue_off = (uint16_t)from;
        out->issue_len = (uint16_t)(r.pos - from);
    }
    if (flags & 0x04)
    {
        out->cert_request = true;             /* certRequestPermissions */
        size_t from = r.pos;
        read_group_permissions(&r, NULL);
        out->request_off = (uint16_t)from;
        out->request_len = (uint16_t)(r.pos - from);
    }
    /* Bit 1 is canRequestRollover, a NULL that takes no bytes. */
    if ((flags & 0x01) && skip_public_enc_key(&r))
        out->canonical = false;
    /* ToBeSignedCertificate demands at least one of the three permission fields, so bytes
     * without any of them are no certificate and must not come out trusted. */
    if (!out->app_perms && !out->cert_issue && !out->cert_request)
        return false;

    unsigned ind = oer_tag(&r);               /* VerificationKeyIndicator */
    if (ind == 1)
    {
        out->key_type = ITS_SEC_KEY_RECONSTRUCTION;
        out->key_form = (uint8_t)read_point(&r, 32, &out->key_off, &out->key_len);
    }
    else if (ind > 1)
    {
        oer_skip_prefixed(&r);
        out->key_type = ITS_SEC_KEY_OTHER;
    }
    else
    {
        unsigned key = oer_tag(&r);
        if (key <= ITS_SEC_KEY_ECDSA_BRAINPOOL_P256)
        {
            out->key_type = (uint8_t)key;
            out->key_form = (uint8_t)read_point(&r, 32, &out->key_off, &out->key_len);
        }
        else
        {
            /* The P-384 and SM2 keys are extensions, so their point fills the open type. */
            size_t n = oer_length(&r);
            size_t end = r.pos + n;
            if (key > ITS_SEC_KEY_SM2)
            {
                oer_skip(&r, n);
                out->key_type = ITS_SEC_KEY_OTHER;
            }
            else
            {
                out->key_type = (uint8_t)key;
                out->key_form =
                    (uint8_t)read_point(&r, key == ITS_SEC_KEY_SM2 ? 32 : 48, &out->key_off,
                                        &out->key_len);
            }
            if (r.pos != end)
                r.err = true;
        }
    }
    if (!point_compressed(out->key_form))
        out->canonical = false;
    if (flags & 0x80)
        oer_extensions(&r);
    if (r.err)
        return false;

    out->tbs_off = (uint16_t)tbs;
    out->tbs_len = (uint16_t)(r.pos - tbs);
    /* An explicit certificate carries a signature and an implicit one does not, so anything
     * else is not a certificate. */
    if (((opt & 0x80) != 0) == out->implicit)
        return false;
    out->sig_type = out->implicit ? ITS_SEC_SIG_OTHER : read_signature(&r, out);
    if (r.err || r.pos != len)
        return false;
    out->ok = true;
    return true;
}

/* ------------------------------------------------------ issuing permissions */

/* Whether the explicit group `g` of `issuer` names `psid`. `all` names nothing of its own,
 * and issuer_grants() answers that alternative. */
static bool group_names(const uint8_t *issuer, const group_t *g, uint32_t psid)
{
    if (g->subject != 0 || !g->psid_len)
        return false;
    oer_t r = { issuer, (size_t)g->psid_off + g->psid_len, g->psid_off, false };
    bool found = false;
    walk_psid_ranges(&r, &psid, &found);
    return found;
}

/* Whether any explicit group of `ic` names `psid`. Ieee1609Dot2.asn gives subjectPermissions
 * `all` every PSID that no other group of the same field names, so `all` has to ask this. */
static bool any_group_names(const uint8_t *issuer, const its_verify_cert_t *ic, uint32_t psid)
{
    oer_t r = { issuer, (size_t)ic->issue_off + ic->issue_len, ic->issue_off, false };
    size_t q = oer_quantity(&r);
    for (size_t i = 0; i < q && !r.err; i++)
    {
        group_t g;
        if (!read_group(&r, &g))
            break;
        if (group_names(issuer, &g, psid))
            return true;
    }
    return false;
}

/* Whether some group of the issuer carries `psid` for an end entity of the kind `ee_bit` at
 * a chain of `len` certificates below the issuer. ONE group is enough: the real trust lists
 * name the same PSID in two groups with different windows, and a chain only has to pass
 * through one of them. `ee_bit` 0 asks about the PSID alone and `len` -1 about any length.
 * A group this build cannot read sets `unknown`, so a no can be told from a maybe. */
static bool issuer_grants(const uint8_t *issuer, const its_verify_cert_t *ic, uint32_t psid,
                          uint8_t ee_bit, int32_t len, bool *unknown)
{
    oer_t r = { issuer, (size_t)ic->issue_off + ic->issue_len, ic->issue_off, false };
    size_t q = oer_quantity(&r);
    for (size_t i = 0; i < q && !r.err; i++)
    {
        group_t g;
        if (!read_group(&r, &g))
            break;
        if (g.subject == 2)
        {
            *unknown = true;
            continue;
        }
        if (g.subject == 0 ? !group_names(issuer, &g, psid)
                           : any_group_names(issuer, ic, psid))
            continue;
        if (ee_bit && !(g.ee_type & ee_bit))
            continue;
        if (len >= 0 && (len < g.min_chain || len > group_top(&g)))
            continue;
        return true;
    }
    /* Bytes the first walk read and this one did not: a maybe, never a yes. */
    if (r.err)
        *unknown = true;
    return false;
}

/* Whether the issuer covers the unbounded set that a subjectPermissions `all` of the child
 * claims. Only an `all` of its own reaches that far, and that one leaves out every PSID the
 * issuer's other groups name, so each of those has to be granted in its own right. Asking
 * for more than Ieee1609Dot2.asn does is safe here: it can only withhold a yes. */
static bool issuer_grants_all(const uint8_t *issuer, const its_verify_cert_t *ic,
                              uint8_t ee_bit, int32_t len, bool *unknown)
{
    bool have_all = false;
    oer_t r = { issuer, (size_t)ic->issue_off + ic->issue_len, ic->issue_off, false };
    size_t q = oer_quantity(&r);
    for (size_t i = 0; i < q && !r.err; i++)
    {
        group_t g;
        if (!read_group(&r, &g))
            break;
        if (g.subject == 2)
        {
            *unknown = true;
            return false;
        }
        if (g.subject == 1)
        {
            if ((!ee_bit || (g.ee_type & ee_bit)) &&
                (len < 0 || (len >= g.min_chain && len <= group_top(&g))))
                have_all = true;
            continue;
        }
        oer_t pr = { issuer, (size_t)g.psid_off + g.psid_len, g.psid_off, false };
        size_t n = oer_quantity(&pr);
        for (size_t k = 0; k < n && !pr.err; k++)
        {
            uint8_t opt = oer_u8(&pr);        /* Bit 7 flags sspRange. */
            uint32_t psid = oer_psid(&pr);
            if (pr.err)
                break;
            if (opt & 0x80)
                skip_ssp_range(&pr);
            if (!issuer_grants(issuer, ic, psid, ee_bit, len, unknown))
                return false;
        }
        if (pr.err)
        {
            *unknown = true;
            return false;
        }
    }
    if (r.err)
    {
        *unknown = true;
        return false;
    }
    return have_all;
}

/* Every appPermissions PSID of the child has to come from a group of the issuer that names
 * app in its eeType and whose window holds a chain of one: for that application the child
 * itself is the end entity, one certificate below its issuer. */
static bool app_perms_granted(const uint8_t *child, const its_verify_cert_t *cc,
                              const uint8_t *issuer, const its_verify_cert_t *ic,
                              bool *unknown)
{
    if (!cc->app_len)
        return true;
    oer_t r = { child, (size_t)cc->app_off + cc->app_len, cc->app_off, false };
    size_t q = oer_quantity(&r);
    for (size_t i = 0; i < q && !r.err; i++)
    {
        uint8_t ssp = oer_u8(&r);             /* Bit 7 flags ssp. */
        uint32_t psid = oer_psid(&r);
        if (r.err)
            break;
        if (ssp & 0x80)
        {
            oer_tag(&r);
            oer_skip_prefixed(&r);
        }
        if (!issuer_grants(issuer, ic, psid, 0x80, 1, unknown))
            return false;
    }
    if (r.err)
    {
        /* The parse walked these bytes once already. Reading them differently now says
         * nothing about the permission, so the answer stays a maybe. */
        *unknown = true;
        return false;
    }
    return true;
}

/* Every PSID that a SequenceOfPsidGroupPermissions of the child names has to be granted by
 * the issuer as well. `ee_bit` and `len` say which end entity kind and which chain length
 * the granting group must allow. `len` -1 leaves the window out, which is what passing an
 * issuing right further down does. A child group of subjectPermissions `all` names no PSID
 * of its own, so it is measured against an `all` of the issuer instead. */
static bool child_groups_granted(const uint8_t *child, uint16_t off, uint16_t bytes,
                                 const uint8_t *issuer, const its_verify_cert_t *ic,
                                 uint8_t ee_bit, int32_t len, bool *unknown)
{
    if (!bytes)
        return true;
    oer_t r = { child, (size_t)off + bytes, off, false };
    size_t q = oer_quantity(&r);
    for (size_t i = 0; i < q && !r.err; i++)
    {
        group_t g;
        if (!read_group(&r, &g))
            break;
        if (g.subject == 2)
        {
            *unknown = true;
            return false;
        }
        if (g.subject == 1)
        {
            if (!issuer_grants_all(issuer, ic, ee_bit, len, unknown))
                return false;
            continue;
        }
        oer_t pr = { child, (size_t)g.psid_off + g.psid_len, g.psid_off, false };
        size_t n = oer_quantity(&pr);
        for (size_t k = 0; k < n && !pr.err; k++)
        {
            uint8_t opt = oer_u8(&pr);        /* Bit 7 flags sspRange. */
            uint32_t psid = oer_psid(&pr);
            if (pr.err)
                break;
            if (opt & 0x80)
                skip_ssp_range(&pr);
            if (!issuer_grants(issuer, ic, psid, ee_bit, len, unknown))
                return false;
        }
        if (pr.err)
            r.err = true;
    }
    if (r.err)
    {
        /* The parse read these bytes once already, so a different reading here says nothing
         * about the permission. That is a maybe, never a yes. */
        *unknown = true;
        return false;
    }
    return true;
}

/* The rule of Ieee1609Dot2.asn, PsidGroupPermissions and SubjectPermissions: an issuer only
 * passes on what its own certIssuePermissions hold. Fills the verdict and returns false when
 * the child claims more, and says "not checkable" instead of "invalid" when only a field
 * this build cannot read stands between the two. */
static bool perms_ok(const uint8_t *child, const its_verify_cert_t *cc,
                     const uint8_t *issuer, const its_verify_cert_t *ic,
                     its_verify_result_t *out)
{
    bool unknown = false;
    if (app_perms_granted(child, cc, issuer, ic, &unknown) &&
        child_groups_granted(child, cc->request_off, cc->request_len, issuer, ic, 0x40, 1,
                             &unknown) &&
        child_groups_granted(child, cc->issue_off, cc->issue_len, issuer, ic, 0, -1, &unknown))
        return true;
    out->state = unknown ? ITS_VERIFY_UNCHECKABLE : ITS_VERIFY_INVALID;
    out->why = unknown ? ITS_VERIFY_WHY_PERMFORM : ITS_VERIFY_WHY_NOPERM;
    return false;
}

/* Certificates the chain may still take below `c`, given the room its issuer left. 255 keeps
 * its meaning of "nothing above sets a bound". A chainLengthRange of -1 gives it, and so does
 * a window that reaches 255 or further. A certificate without certIssuePermissions ends the
 * chain and so leaves no room at all. */
static uint8_t room_join(uint8_t issuer_room, const its_verify_cert_t *c)
{
    /* An issuer_room of 0 is caught by the callers, but subtracting from it here would wrap
     * and hand out room instead of none, so the floor is spelled out. */
    uint32_t below = issuer_room == 255 ? 255u : (issuer_room ? (uint32_t)issuer_room - 1u : 0u);
    uint32_t own = 0;
    if (c->cert_issue)
        own = c->issue_max_chain >= 255 ? 255u
              : (c->issue_max_chain < 0 ? 0u : (uint32_t)c->issue_max_chain);
    return (uint8_t)(below < own ? below : own);
}

/* -------------------------------------------------------- hashes and ECDSA */

static size_t hash_size(uint8_t alg)
{
    return alg == 0 ? 32 : alg == 1 ? 48 : 0;
}

static void copy_name(char *dst, const char *src)
{
    size_t n = 0;
    while (src && src[n] && n < ITS_VERIFY_NAME_MAX - 1)
    {
        dst[n] = src[n];
        n++;
    }
    dst[n] = 0;
}

#ifdef ESP_PLATFORM
static bool hash_bytes(uint8_t alg, const uint8_t *p, size_t n, uint8_t *out)
{
    size_t want = hash_size(alg);
    size_t got = 0;
    if (!want)
        return false;
    psa_algorithm_t a = alg == 0 ? PSA_ALG_SHA_256 : PSA_ALG_SHA_384;
    return psa_hash_compute(a, p, n, out, want, &got) == PSA_SUCCESS && got == want;
}

/* Verify one ECDSA signature. `spki` is a DER SubjectPublicKeyInfo, and `sig` holds r and s
 * as plain big-endian integers of equal length, which is the form PSA expects. 1 is a match,
 * 0 a signature that does not match, -1 a key or call the library refused. */
static int ecdsa_verify3(const uint8_t *spki, size_t spki_len, uint8_t alg,
                         const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len)
{
    mbedtls_pk_context pk;
    psa_key_attributes_t attr = PSA_KEY_ATTRIBUTES_INIT;
    mbedtls_svc_key_id_t kid = MBEDTLS_SVC_KEY_ID_INIT;
    psa_algorithm_t a = PSA_ALG_ECDSA(alg == 0 ? PSA_ALG_SHA_256 : PSA_ALG_SHA_384);
    int rc = -1;

    mbedtls_pk_init(&pk);
    /* The key parser turns the compressed point of a certificate into a full curve point,
     * which psa_import_key cannot do on its own. */
    if (mbedtls_pk_parse_public_key(&pk, spki, spki_len) == 0 &&
        mbedtls_pk_get_psa_attributes(&pk, PSA_KEY_USAGE_VERIFY_HASH, &attr) == 0)
    {
        psa_set_key_usage_flags(&attr, PSA_KEY_USAGE_VERIFY_HASH);
        psa_set_key_algorithm(&attr, a);
        if (mbedtls_pk_import_into_psa(&pk, &attr, &kid) == 0)
        {
            psa_status_t st = psa_verify_hash(kid, a, hash, hash_len, sig, sig_len);
            rc = st == PSA_SUCCESS ? 1 : st == PSA_ERROR_INVALID_SIGNATURE ? 0 : -1;
            psa_destroy_key(kid);
        }
    }
    psa_reset_key_attributes(&attr);
    mbedtls_pk_free(&pk);
    return rc;
}

/* The chain check counts every failure as a signature that does not match. */
static bool ecdsa_verify_spki(const uint8_t *spki, size_t spki_len, uint8_t alg,
                              const uint8_t *hash, size_t hash_len, const uint8_t *sig,
                              size_t sig_len)
{
    return ecdsa_verify3(spki, spki_len, alg, hash, hash_len, sig, sig_len) == 1;
}
#else
/* Host tests supply the crypto. */
bool its_verify_host_hash(uint8_t alg, const uint8_t *p, size_t n, uint8_t *out);
bool its_verify_host_ecdsa(const uint8_t *spki, size_t spki_len, uint8_t alg,
                           const uint8_t *hash, size_t hash_len, const uint8_t *sig,
                           size_t sig_len);

static bool hash_bytes(uint8_t alg, const uint8_t *p, size_t n, uint8_t *out)
{
    return hash_size(alg) != 0 && its_verify_host_hash(alg, p, n, out);
}

static bool ecdsa_verify_spki(const uint8_t *spki, size_t spki_len, uint8_t alg,
                              const uint8_t *hash, size_t hash_len, const uint8_t *sig,
                              size_t sig_len)
{
    return its_verify_host_ecdsa(spki, spki_len, alg, hash, hash_len, sig, sig_len);
}

/* The host shim knows no refusal: a key OpenSSL cannot read counts as no match. */
static int ecdsa_verify3(const uint8_t *spki, size_t spki_len, uint8_t alg,
                         const uint8_t *hash, size_t hash_len, const uint8_t *sig, size_t sig_len)
{
    return ecdsa_verify_spki(spki, spki_len, alg, hash, hash_len, sig, sig_len) ? 1 : 0;
}
#endif

/* The object identifiers of the four curves and of an EC public key, each a full DER
 * OBJECT IDENTIFIER. */
static const uint8_t OID_EC_PUBKEY[] = { 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 };
static const uint8_t OID_P256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static const uint8_t OID_P384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
static const uint8_t OID_BP256[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
static const uint8_t OID_BP384[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B };

/* A key of 384 bits in uncompressed form gives the longest SubjectPublicKeyInfo. */
#define SPKI_MAX (4 + sizeof OID_EC_PUBKEY + sizeof OID_BP384 + 4 + 96)

/* Build a DER SubjectPublicKeyInfo from the key point of a certificate. The point forms of
 * IEEE 1609.2 and the leading byte of SEC 1 agree, so the form byte goes in unchanged. */
static size_t build_spki(uint8_t key_type, uint8_t form, const uint8_t *point, size_t point_len,
                         uint8_t *out)
{
    const uint8_t *oid;
    size_t oid_len, want;
    switch (key_type)
    {
    case ITS_SEC_KEY_ECDSA_NIST_P256:      oid = OID_P256;  oid_len = sizeof OID_P256;  want = 32; break;
    case ITS_SEC_KEY_ECDSA_BRAINPOOL_P256: oid = OID_BP256; oid_len = sizeof OID_BP256; want = 32; break;
    case ITS_SEC_KEY_ECDSA_BRAINPOOL_P384: oid = OID_BP384; oid_len = sizeof OID_BP384; want = 48; break;
    case ITS_SEC_KEY_ECDSA_NIST_P384:      oid = OID_P384;  oid_len = sizeof OID_P384;  want = 48; break;
    default: return 0;
    }
    if (form == 4)
        want *= 2;
    else if (form != 2 && form != 3)
        return 0;
    if (point_len != want)
        return 0;
    size_t alg = sizeof OID_EC_PUBKEY + oid_len;
    size_t bits = 2 + point_len;              /* Unused-bits byte, form byte, coordinates. */
    size_t body = 2 + alg + 2 + bits;
    if (body > 127)
        return 0;
    size_t n = 0;
    out[n++] = 0x30;
    out[n++] = (uint8_t)body;
    out[n++] = 0x30;
    out[n++] = (uint8_t)alg;
    memcpy(out + n, OID_EC_PUBKEY, sizeof OID_EC_PUBKEY);
    n += sizeof OID_EC_PUBKEY;
    memcpy(out + n, oid, oid_len);
    n += oid_len;
    out[n++] = 0x03;
    out[n++] = (uint8_t)bits;
    out[n++] = 0x00;
    out[n++] = form;
    memcpy(out + n, point, point_len);
    return n + point_len;
}

int its_verify_ecdsa(uint8_t key_type, uint8_t key_form, const uint8_t *key, size_t key_len,
                     const uint8_t *hash, size_t hash_len, const uint8_t *rs, size_t rs_len)
{
    uint8_t spki[SPKI_MAX];
    size_t n = key && hash && rs ? build_spki(key_type, key_form, key, key_len, spki) : 0;
    if (!n || (hash_len != 32 && hash_len != 48) || (rs_len != 64 && rs_len != 96))
        return -1;
    return ecdsa_verify3(spki, n, hash_len == 32 ? 0 : 1, hash, hash_len, rs, rs_len);
}

/* Time32 counts TAI seconds from 2004-01-01 00:00:00 UTC, and five leap seconds have been
 * inserted since then, so the same moment in UTC is that much earlier. */
#define TIME32_EPOCH 1072915200u
#define TIME32_LEAP  5u
/* Below this the device clock has not been set, and a validity cannot be judged. */
#define CLOCK_MIN    1600000000u
/* The seconds a year of a Duration stands for, which is the average length of a year. */
#define YEAR_SECONDS 31556952u

/* Seconds of a Duration. The two units below a second are rounded down, so a period shorter
 * than a second covers nothing. The largest values need more than 32 bits. */
static uint64_t duration_seconds(uint16_t value, uint8_t unit)
{
    switch (unit)
    {
    case ITS_SEC_DUR_MICROSECONDS: return value / 1000000u;
    case ITS_SEC_DUR_MILLISECONDS: return value / 1000u;
    case ITS_SEC_DUR_SECONDS:      return value;
    case ITS_SEC_DUR_MINUTES:      return (uint64_t)value * 60u;
    case ITS_SEC_DUR_HOURS:        return (uint64_t)value * 3600u;
    case ITS_SEC_DUR_SIXTY_HOURS:  return (uint64_t)value * 216000u;
    case ITS_SEC_DUR_YEARS:        return (uint64_t)value * YEAR_SECONDS;
    default:                       return 0;
    }
}

/* Whether `now` lies inside the validity, with the outcome in `out` when it does not.
 * A start time of 0 means the certificate carries no usable period. */
static bool in_validity(uint32_t now, uint32_t start, uint16_t duration, uint8_t unit,
                        its_verify_result_t *out)
{
    if (now < CLOCK_MIN)
    {
        out->state = ITS_VERIFY_UNCHECKABLE;
        out->why = ITS_VERIFY_WHY_CLOCK;
        return false;
    }
    uint64_t from = (uint64_t)start + TIME32_EPOCH - TIME32_LEAP;
    uint64_t to = from + duration_seconds(duration, unit);
    if (!start || now < from || now >= to)
    {
        out->state = ITS_VERIFY_INVALID;
        /* Three cases get three reasons: no period, not yet valid, expired. A shared "expired"
         * would contradict the validity column next to it. */
        out->why = !start        ? ITS_VERIFY_WHY_NOPERIOD
                   : (now < from) ? ITS_VERIFY_WHY_NOTYET
                                  : ITS_VERIFY_WHY_EXPIRED;
        return false;
    }
    return true;
}

/* A signature covers hash(hash(data) || hash(signer identifier)), and for a certificate the
 * signer identifier is the issuer certificate, or nothing at all when it signed itself. */
static bool signed_hash(uint8_t alg, const uint8_t *tbs, size_t tbs_len,
                        const uint8_t *signer_hash, uint8_t *out)
{
    size_t hs = hash_size(alg);
    uint8_t both[2 * 48];
    if (!hs || !hash_bytes(alg, tbs, tbs_len, both))
        return false;
    memcpy(both + hs, signer_hash, hs);
    return hash_bytes(alg, both, 2 * hs, out);
}

/* ---------------------------------------------------------- issuer table */

typedef struct
{
    bool     used;
    bool     cert_issue;         /* It was granted certIssuePermissions, so it may sign. */
    uint8_t  from_store;         /* Values come from its_verify_issuer_from_t. */
    uint8_t  state;              /* Values come from its_verify_state_t. */
    uint8_t  why;
    uint8_t  root_env;
    uint8_t  chain;
    uint8_t  key_type;
    uint8_t  key_form;
    uint8_t  key_len;
    uint8_t  id[2][8];           /* The HashedId8 from SHA-256 and the one from SHA-384. */
    uint8_t  hash[2][48];        /* SHA-256 and SHA-384 over the certificate bytes. */
    uint32_t valid_start;        /* Its own validity, checked again for every child. */
    uint16_t duration;
    uint8_t  duration_unit;
    uint8_t  key[96];
    /* Certificates the chain may still take below this one, 255 without a bound. */
    uint8_t  room;
    uint16_t cert_len;
    /* The bytes and the parse are kept because the PSID lists of certIssuePermissions live
     * in the bytes, and a child that arrives later has to be measured against them. */
    its_verify_cert_t parsed;
    uint8_t  cert[ITS_VERIFY_CERT_MAX];
    char     name[ITS_VERIFY_NAME_MAX];
    char     root_name[ITS_VERIFY_NAME_MAX];
} issuer_t;

/* What a chain needs from a learned issuer, copied out of the table so the lock is free
 * while ECDSA runs, which takes seconds on a Brainpool curve. */
typedef struct
{
    bool     found;
    bool     busy;               /* The lock could not be taken, so `found` says nothing. */
    bool     cert_issue;
    uint8_t  from_store;
    uint8_t  state;
    uint8_t  root_env;
    uint8_t  chain;
    uint8_t  key_type;
    uint8_t  key_form;
    uint8_t  key_len;
    uint8_t  id[2][8];
    uint8_t  hash[48];           /* Over the issuer bytes, in the hash the child named. */
    uint32_t valid_start;
    uint16_t duration;
    uint8_t  duration_unit;
    uint8_t  key[96];
    uint8_t  room;
    /* What the issuer grants this child: 0 granted, 1 refused, 2 not readable. It is decided
     * inside issuer_copy, while the lock keeps the entry from moving. */
    uint8_t  perm;
    char     name[ITS_VERIFY_NAME_MAX];
    char     root_name[ITS_VERIFY_NAME_MAX];
} issuer_snap_t;

static EXT_RAM_BSS_ATTR issuer_t s_issuers[ITS_VERIFY_ISSUERS];
static unsigned s_issuer_next;
static its_verify_stats_t s_stats;

/* The built-in authority store holds fewer than 256 certificates, and one bit per index
 * remembers that an entry was already tried, so a hopeless one costs nothing per frame. */
#define CASTORE_BITS 256
static uint8_t s_store_tried[CASTORE_BITS / 8];
/* Set while an authority from the store is being learned. It keeps the store out of its own
 * check, which would otherwise recurse through note_issuer, and it tells note_issuer where
 * the certificate came from. Only the verify task gets here. */
static bool s_in_store;
/* How many checks are running inside one another. Only the outermost one is tallied, so a
 * frame that has to learn an authority on the way still counts as one check. */
static unsigned s_depth;

#ifdef ESP_PLATFORM
static SemaphoreHandle_t s_lock;

static bool lock(uint32_t ms)
{
    return s_lock && xSemaphoreTake(s_lock, pdMS_TO_TICKS(ms)) == pdTRUE;
}

static void unlock(void)
{
    xSemaphoreGive(s_lock);
}

static uint32_t now_us(void)
{
    return (uint32_t)esp_timer_get_time();
}

static uint32_t now_unix(void)
{
    return (uint32_t)time(NULL);
}
#else
static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;

static bool lock(uint32_t ms)
{
    (void)ms;
    return pthread_mutex_lock(&s_mutex) == 0;
}

static void unlock(void)
{
    pthread_mutex_unlock(&s_mutex);
}

static uint32_t now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint32_t)(t.tv_sec * 1000000 + t.tv_nsec / 1000);
}

/* Host tests pin the time so a fixed set of certificates keeps the same verdict. */
static uint32_t s_host_now;
static bool s_host_pinned;

void its_verify_host_set_now(uint32_t unix_seconds)
{
    s_host_now = unix_seconds;
    s_host_pinned = true;
}

static uint32_t now_unix(void)
{
    return s_host_pinned ? s_host_now : (uint32_t)time(NULL);
}

void its_verify_host_reset(void)
{
    memset(s_issuers, 0, sizeof s_issuers);
    memset(&s_stats, 0, sizeof s_stats);
    memset(s_store_tried, 0, sizeof s_store_tried);
    s_issuer_next = 0;
    s_in_store = false;
    s_depth = 0;
}
#endif

static const issuer_t *issuer_find(const uint8_t id[8], uint8_t hash_alg)
{
    if (hash_alg > 1)
        return NULL;
    for (unsigned i = 0; i < ITS_VERIFY_ISSUERS; i++)
        if (s_issuers[i].used && memcmp(s_issuers[i].id[hash_alg], id, 8) == 0)
            return &s_issuers[i];
    return NULL;
}

/* Copy what a chain needs out of the learned table. `out->found` stays false when the issuer
 * is unknown or the lock is busy, and `busy` tells the two apart. With `child` given, the
 * permission question is answered here too. The PSID lists are in the bytes of the entry,
 * and only the lock keeps that entry from changing. */
static void issuer_copy(const uint8_t id[8], uint8_t hash_alg, const uint8_t *child,
                        const its_verify_cert_t *cc, issuer_snap_t *out)
{
    memset(out, 0, sizeof *out);
    if (!lock(200))
    {
        out->busy = true;
        return;
    }
    const issuer_t *e = issuer_find(id, hash_alg);
    if (e)
    {
        out->found = true;
        out->room = e->room;
        if (child && cc)
        {
            its_verify_result_t pr = { 0 };
            /* Without the bytes nothing can be compared, and that is a maybe, not a yes. */
            if (!e->cert_len)
                out->perm = 2;
            else if (!perms_ok(child, cc, e->cert, &e->parsed, &pr))
                out->perm = pr.state == ITS_VERIFY_INVALID ? 1 : 2;
        }
        out->cert_issue = e->cert_issue;
        out->from_store = e->from_store;
        out->state = e->state;
        out->root_env = e->root_env;
        out->chain = e->chain;
        out->key_type = e->key_type;
        out->key_form = e->key_form;
        out->key_len = e->key_len;
        memcpy(out->id, e->id, sizeof out->id);
        memcpy(out->hash, e->hash[hash_alg], sizeof out->hash);
        out->valid_start = e->valid_start;
        out->duration = e->duration;
        out->duration_unit = e->duration_unit;
        memcpy(out->key, e->key, sizeof out->key);
        memcpy(out->name, e->name, sizeof out->name);
        memcpy(out->root_name, e->root_name, sizeof out->root_name);
    }
    unlock();
}

static bool store_tried(size_t i)
{
    bool v = false;
    if (i < CASTORE_BITS && lock(200))
    {
        v = (s_store_tried[i >> 3] >> (i & 7)) & 1;
        unlock();
    }
    return v;
}

static void store_mark(size_t i)
{
    if (i < CASTORE_BITS && lock(200))
    {
        s_store_tried[i >> 3] |= (uint8_t)(1u << (i & 7));
        unlock();
    }
}

/* -------------------------------------------------------------- the check */

/* Check the signature of `cert` against a key and the hash of the signer identifier. The
 * result keeps the reason apart from a signature that simply did not match. */
static bool check_sig(const uint8_t *cert, const its_verify_cert_t *c, uint8_t key_type,
                      uint8_t key_form, const uint8_t *key, size_t key_len,
                      const uint8_t *signer_hash, its_verify_result_t *out)
{
    uint8_t spki[SPKI_MAX];
    uint8_t h[48];
    uint8_t sig[96];
    if (key_type != c->sig_type)
    {
        /* The signature has to use the curve of the issuer's key, so this cannot match. */
        out->state = ITS_VERIFY_INVALID;
        out->why = ITS_VERIFY_WHY_NONE;
        return false;
    }
    size_t spki_len = build_spki(key_type, key_form, key, key_len, spki);
    if (!spki_len)
    {
        out->state = ITS_VERIFY_UNCHECKABLE;
        out->why = ITS_VERIFY_WHY_CURVE;
        return false;
    }
    if (!signed_hash(c->hash_alg, cert + c->tbs_off, c->tbs_len, signer_hash, h))
    {
        out->state = ITS_VERIFY_UNCHECKABLE;
        out->why = ITS_VERIFY_WHY_CRYPTO;
        return false;
    }
    memcpy(sig, cert + c->sig_r_off, c->sig_len);
    memcpy(sig + c->sig_len, cert + c->sig_s_off, c->sig_len);
    if (!ecdsa_verify_spki(spki, spki_len, c->hash_alg, h, hash_size(c->hash_alg), sig,
                           2u * (size_t)c->sig_len))
    {
        out->state = ITS_VERIFY_INVALID;
        out->why = ITS_VERIFY_WHY_NONE;
        return false;
    }
    return true;
}

/* Hold a finished chain against the built-in revocation lists: the certificate itself first,
 * then the identifiers of the link above it. Of the lookup results only ITS_CRL_LISTED changes
 * a verdict, so a firmware without lists and a certificate no list names both stay as they
 * were. `above` holds the SHA-256 and the SHA-384 form of the issuer, which is also the root
 * when a root signed the certificate directly. */
static void apply_crl(const uint8_t *cert, size_t len, const uint8_t above[2][8],
                      its_verify_result_t *out)
{
    uint8_t h256[32], h384[48];
    if (out->state != ITS_VERIFY_CHECKED)
        return;
    /* Which hash gives the identifier is the revocation list's choice, so both are offered.
     * Two hashes over one certificate cost little next to the ECDSA that just ran. */
    if (!hash_bytes(0, cert, len, h256) || !hash_bytes(1, cert, len, h384))
    {
        /* Without the identifiers nothing can be said, and saying nothing must not pass for
         * trusted. */
        out->state = ITS_VERIFY_UNCHECKABLE;
        out->why = ITS_VERIFY_WHY_CRYPTO;
        return;
    }
    if (its_crl_lookup(h256 + 24, h384 + 40) == ITS_CRL_LISTED ||
        its_crl_lookup(above[0], above[1]) == ITS_CRL_LISTED)
    {
        out->state = ITS_VERIFY_REVOKED;
        out->why = ITS_VERIFY_WHY_NONE;
    }
}

/* Whether a certificate may sign another one. IEEE 1609.2 5.1.2.1 grants that through
 * certIssuePermissions alone, and it calls a minChainLength of zero invalid. */
static bool may_issue(bool cert_issue, int32_t min_chain)
{
    return cert_issue && min_chain >= 1;
}

/* Reject what cannot be checked before any crypto runs. The certificate's own point forms
 * do not matter here, only the ones of the issuer whose bytes get hashed. */
static bool usable(const uint8_t *cert, size_t len, its_verify_cert_t *c,
                   its_verify_result_t *out)
{
    memset(out, 0, sizeof *out);
    out->root_env = 0xFF;
    out->state = ITS_VERIFY_UNCHECKABLE;
    if (!cert || !len)
    {
        out->state = ITS_VERIFY_UNKNOWN;
        return false;
    }
    if (len > ITS_VERIFY_CERT_MAX)
        out->why = ITS_VERIFY_WHY_LONG;
    else if (!its_verify_parse(cert, len, c))
        out->why = ITS_VERIFY_WHY_PARSE;
    else if (c->implicit)
        out->why = ITS_VERIFY_WHY_IMPLICIT;
    else if (!hash_size(c->hash_alg) || c->sig_len == 0)
        out->why = ITS_VERIFY_WHY_CURVE;
    else
        return true;
    return false;
}

/* Check `cert` against the root that `id` names. A missing root is not an error here,
 * because the issuer may still be an authority further down. */
static bool against_root(const uint8_t *cert, size_t len, const its_verify_cert_t *c,
                         const uint8_t *id, its_verify_result_t *out)
{
    static const uint8_t nothing[1] = { 0 };
    its_trust_entry_t t;
    /* The issuer field says which hash made the identifier, so the search uses that one. */
    if (!its_trustlist_find_alg(id, c->hash_alg, &t))
    {
        out->state = ITS_VERIFY_UNCHECKABLE;
        out->why = c->self_signed ? ITS_VERIFY_WHY_ROOT : ITS_VERIFY_WHY_ISSUER;
        return false;
    }
    /* The trust list held the named certificate. Not SENT, as nothing came with the message,
     * and not BUILTIN, as the built-in authority store did not supply it either. */
    out->issuer_from = ITS_VERIFY_ISSUER_ROOT;
    if (c->self_signed)
    {
        /* The list makes a self-signed certificate trusted, not its own signature, so the
         * bytes have to be the listed ones and not just carry the same identifier. */
        if (t.cert_len != len || memcmp(cert, t.cert, len) != 0)
        {
            out->state = ITS_VERIFY_UNCHECKABLE;
            out->why = ITS_VERIFY_WHY_ROOT;
            return false;
        }
    }
    else if (t.role != ITS_TRUST_ROLE_ROOT)
    {
        /* A trust list manager signs the list itself and no certificates, so it cannot stand
         * at the top of a chain. */
        out->state = ITS_VERIFY_UNCHECKABLE;
        out->why = ITS_VERIFY_WHY_ROOT;
        return false;
    }

    /* A signature that matches says nothing while the certificate or the root it hangs on is
     * outside its validity, so both periods are checked before any crypto runs. */
    uint32_t now = now_unix();
    if (!in_validity(now, c->valid_start, c->duration, c->duration_unit, out) ||
        !in_validity(now, t.validity_start, t.duration, t.duration_unit, out))
        return false;

    uint8_t signer[48];
    uint8_t key_type, key_form, key_len;
    uint8_t room;
    const uint8_t *key;
    if (c->self_signed)
    {
        /* A self-signed certificate signs itself, and then the signer identifier is empty. */
        if (!hash_bytes(c->hash_alg, nothing, 0, signer))
        {
            out->state = ITS_VERIFY_UNCHECKABLE;
            out->why = ITS_VERIFY_WHY_CRYPTO;
            return false;
        }
        key_type = c->key_type;
        key_form = c->key_form;
        key_len = (uint8_t)c->key_len;
        key = cert + c->key_off;
        /* A root is the top of its own chain, so only its own groups bound what follows. */
        room = room_join(255, c);
    }
    else
    {
        its_verify_cert_t rc;
        if (!its_verify_parse(t.cert, t.cert_len, &rc))
        {
            out->state = ITS_VERIFY_UNCHECKABLE;
            out->why = ITS_VERIFY_WHY_PARSE;
            return false;
        }
        if (!rc.canonical)
        {
            /* The bytes that get hashed are the canonical ones, not the stored ones. */
            out->state = ITS_VERIFY_UNCHECKABLE;
            out->why = ITS_VERIFY_WHY_NONCANON;
            return false;
        }
        if (!may_issue(rc.cert_issue, rc.issue_min_chain))
        {
            /* A listed certificate that was never granted certIssuePermissions signs no
             * child, however well the signature matches. */
            out->state = ITS_VERIFY_INVALID;
            out->why = ITS_VERIFY_WHY_NOISSUE;
            copy_name(out->issuer_name, t.name);
            return false;
        }
        /* What the root passes on has to cover what the child claims, and the root has to
         * leave room for one certificate below it. Both are decided before any crypto. */
        uint8_t above = room_join(255, &rc);
        if (!above)
        {
            out->state = ITS_VERIFY_INVALID;
            out->why = ITS_VERIFY_WHY_DEEP;
            copy_name(out->issuer_name, t.name);
            return false;
        }
        if (!perms_ok(cert, c, t.cert, &rc, out))
        {
            copy_name(out->issuer_name, t.name);
            return false;
        }
        room = room_join(above, c);
        if (!hash_bytes(c->hash_alg, t.cert, t.cert_len, signer))
        {
            out->state = ITS_VERIFY_UNCHECKABLE;
            out->why = ITS_VERIFY_WHY_CRYPTO;
            return false;
        }
        /* The trust list points at the CHOICE tag of the key point, so the coordinates
         * start one byte later. */
        key_type = t.key_type;
        key_form = t.key_form;
        key_len = t.key_len;
        key = t.cert + t.key_off + 1;
    }
    if (!check_sig(cert, c, key_type, key_form, key, key_len, signer, out))
        return false;
    out->state = ITS_VERIFY_CHECKED;
    out->why = ITS_VERIFY_WHY_NONE;
    out->root_env = t.env;
    out->room = room;
    out->chain = c->self_signed ? 0 : 1;
    copy_name(out->root_name, t.name);
    copy_name(out->issuer_name, t.name);
    /* The entry is the issuer and the root in one, so one pair of identifiers covers both. */
    uint8_t above[2][8];
    memcpy(above[0], t.id8_sha256, 8);
    memcpy(above[1], t.id8_sha384, 8);
    apply_crl(cert, len, above, out);
    return true;
}

/* Finish a chain against a learned issuer. The snapshot already left the lock behind, so the
 * ECDSA here blocks nobody. */
static void against_issuer(const uint8_t *cert, size_t len, const its_verify_cert_t *c,
                           const issuer_snap_t *is, its_verify_result_t *out)
{
    uint32_t now = now_unix();
    /* The user interface names the issuer in every outcome, so the name and where it came
     * from go in first. */
    copy_name(out->issuer_name, is->name);
    out->issuer_from = is->from_store;
    if (is->state == ITS_VERIFY_REVOKED)
    {
        /* A withdrawn authority takes its children with it. */
        out->state = ITS_VERIFY_REVOKED;
        out->why = ITS_VERIFY_WHY_NONE;
        out->root_env = is->root_env;
        copy_name(out->root_name, is->root_name);
        return;
    }
    if (is->state != ITS_VERIFY_CHECKED)
    {
        /* The issuer is known but not trusted itself. verify_parsed calls this only with the
         * reason ITS_VERIFY_WHY_ISSUER, which becomes ITS_VERIFY_WHY_CHAIN here. */
        if (out->state == ITS_VERIFY_UNCHECKABLE && out->why == ITS_VERIFY_WHY_ISSUER)
            out->why = ITS_VERIFY_WHY_CHAIN;
        return;
    }
    if (!is->cert_issue)
    {
        /* A trusted certificate is not an authority. Without this the sender certificate of
         * any well behaved chain could sign certificates of its own. */
        out->state = ITS_VERIFY_INVALID;
        out->why = ITS_VERIFY_WHY_NOISSUE;
        return;
    }
    if (!is->room)
    {
        /* Something above the issuer allows no further certificate, so this one is one too
         * many however well its signature matches. */
        out->state = ITS_VERIFY_INVALID;
        out->why = ITS_VERIFY_WHY_DEEP;
        return;
    }
    if (is->perm)
    {
        /* issuer_copy already measured the child against certIssuePermissions. */
        out->state = is->perm == 1 ? ITS_VERIFY_INVALID : ITS_VERIFY_UNCHECKABLE;
        out->why = is->perm == 1 ? ITS_VERIFY_WHY_NOPERM : ITS_VERIFY_WHY_PERMFORM;
        return;
    }
    if (!in_validity(now, c->valid_start, c->duration, c->duration_unit, out) ||
        !in_validity(now, is->valid_start, is->duration, is->duration_unit, out))
        return;
    if (!check_sig(cert, c, is->key_type, is->key_form, is->key, is->key_len, is->hash, out))
        return;
    out->state = ITS_VERIFY_CHECKED;
    out->why = ITS_VERIFY_WHY_NONE;
    out->root_env = is->root_env;
    out->room = room_join(is->room, c);
    out->chain = (uint8_t)(is->chain + 1);
    copy_name(out->root_name, is->root_name);
    apply_crl(cert, len, is->id, out);
}

/* Find the index the built-in store keeps `e` at, which the repeat brake needs. The walk
 * only runs after a hit, so the cost falls on the rare frame that needs the store. */
static size_t castore_index(const its_castore_entry_t *e)
{
    its_castore_entry_t t;
    for (size_t i = 0; i < CASTORE_BITS && its_castore_at(i, &t); i++)
        if (memcmp(t.id8_sha256, e->id8_sha256, 8) == 0 &&
            memcmp(t.id8_sha384, e->id8_sha384, 8) == 0)
            return i;
    return CASTORE_BITS;
}

static bool note_issuer(const uint8_t *cert, size_t len);

/* Take the issuer the traffic never carried out of the built-in store and learn it the usual
 * way, which checks it against the roots. This holds no lock, because note_issuer takes one
 * itself. `snap` is the caller's buffer and is filled with whatever the table holds
 * afterwards, so no second one lands on the stack. */
static void from_castore(const uint8_t *cert, const its_verify_cert_t *c, issuer_snap_t *snap)
{
    /* The store must not be consulted while one of its own entries is being checked: an
     * entry whose issuer were another entry would recurse through this function. */
    if (s_in_store)
        return;
    const its_castore_entry_t *e = its_castore_find(c->issuer_id, c->hash_alg);
    if (!e || !e->cert || !e->cert_len)
        return;
    /* Without an index the brake cannot work, and an entry the walk does not find again is
     * not worth a hash either. */
    size_t idx = castore_index(e);
    if (idx >= CASTORE_BITS || store_tried(idx))
        return;

    uint32_t now = now_unix();
    if (now < CLOCK_MIN)
        return;                               /* Nothing is decided yet, so nothing is noted. */
    its_verify_cert_t sc;
    if (!its_verify_parse(e->cert, e->cert_len, &sc))
    {
        store_mark(idx);                      /* Bytes that are no certificate never become one. */
        return;
    }
    uint64_t from = (uint64_t)sc.valid_start + TIME32_EPOCH - TIME32_LEAP;
    uint64_t to = from + duration_seconds(sc.duration, sc.duration_unit);
    if (!sc.valid_start || now >= to)
    {
        store_mark(idx);                      /* A period that has ended never comes back. */
        return;
    }
    if (now < from)
        return;                               /* It may still start, so the bit stays clear. */

    s_in_store = true;
    bool had_lock = note_issuer(e->cert, e->cert_len);
    s_in_store = false;

    /* Only a failure that cannot change sets the bit, so a busy table or a clock that was
     * not set yet does not shut the entry out for good. A root that has not started yet sets
     * it as well: retrying would run the signature check again for every frame. */
    issuer_copy(c->issuer_id, c->hash_alg, cert, c, snap);
    if (had_lock && !snap->busy && (!snap->found || snap->state != ITS_VERIFY_CHECKED))
        store_mark(idx);
}

/* Check a certificate that was already read. */
static void verify_parsed(const uint8_t *cert, size_t len, const its_verify_cert_t *c,
                          its_verify_result_t *out)
{
    uint8_t own[48];
    /* IEEE 1609.2 5.1.2.1 calls a minChainLength of zero in certIssuePermissions invalid, so
     * the rule bites before any signature is looked at. */
    if (c->cert_issue && !may_issue(c->cert_issue, c->issue_min_chain))
    {
        out->state = ITS_VERIFY_INVALID;
        out->why = ITS_VERIFY_WHY_NOISSUE;
        return;
    }
    if (c->self_signed)
    {
        /* Only the built-in list makes a self-signed certificate trusted, so it is looked
         * up under its own HashedId8. */
        if (!hash_bytes(c->hash_alg, cert, len, own))
        {
            out->why = ITS_VERIFY_WHY_CRYPTO;
            return;
        }
        against_root(cert, len, c, own + hash_size(c->hash_alg) - 8, out);
        return;
    }
    if (against_root(cert, len, c, c->issuer_id, out))
        return;
    if (out->state != ITS_VERIFY_UNCHECKABLE || out->why != ITS_VERIFY_WHY_ISSUER)
        return;

    issuer_snap_t is;
    issuer_copy(c->issuer_id, c->hash_alg, cert, c, &is);
    if (!is.found)
        from_castore(cert, c, &is);
    if (is.found)
        against_issuer(cert, len, c, &is, out);
}

void its_verify_cert(const uint8_t *cert, size_t len, its_verify_result_t *out)
{
    its_verify_cert_t c;
    if (!out)
        return;
    uint32_t t0 = now_us();
    s_depth++;
    if (usable(cert, len, &c, out))
        verify_parsed(cert, len, &c, out);
    uint32_t dt = now_us() - t0;
    bool outer = --s_depth == 0;
    if (!lock(200))
        return;
    /* A nested check belongs to the one that started it. Learning an authority out of the
     * built-in store runs a whole check of its own in the middle of a frame, and that must not
     * count as a second check. The times stay on every level, because each of them was really
     * spent, and the outer one wins because it finishes last. */
    if (outer)
    {
        s_stats.checked += out->state == ITS_VERIFY_CHECKED;
        s_stats.unavailable += out->state == ITS_VERIFY_UNCHECKABLE;
        s_stats.invalid += out->state == ITS_VERIFY_INVALID;
        s_stats.revoked += out->state == ITS_VERIFY_REVOKED;
        s_stats.expired += out->why == ITS_VERIFY_WHY_EXPIRED;
    }
    s_stats.us_last = dt;
    if (dt > s_stats.us_max)
        s_stats.us_max = dt;
    unlock();
}

/* Learn one authority. Returns false only when the lock was busy, so nothing was kept and
 * the store may offer the entry again. */
static bool note_issuer(const uint8_t *cert, size_t len)
{
    its_verify_cert_t c;
    its_verify_result_t res;
    uint8_t h256[32], h384[48];
    if (!usable(cert, len, &c, &res))
        return true;
    /* Only a canonical certificate can serve as an issuer, because its stored bytes are
     * what a child's signature was computed over. */
    if (!c.canonical || !hash_bytes(0, cert, len, h256) || !hash_bytes(1, cert, len, h384))
        return true;
    if (!lock(200))
        return false;
    bool known = issuer_find(h256 + 24, 0) != NULL;
    unlock();
    if (known)
        return true;

    its_verify_cert(cert, len, &res);
    /* A verdict that only the clock or a period produced must not be kept, because nothing
     * would ever look at this certificate again. The next sighting judges it afresh. */
    if (res.state != ITS_VERIFY_CHECKED &&
        (res.why == ITS_VERIFY_WHY_CLOCK || res.why == ITS_VERIFY_WHY_EXPIRED ||
         res.why == ITS_VERIFY_WHY_NOTYET))
        return true;
    bool may = may_issue(c.cert_issue, c.issue_min_chain);
    if (!lock(200))
        return false;
    /* A trusted authority is worth more than anything else, so a free slot comes first and a
     * slot that cannot sign children next. Otherwise anyone could push the real authority
     * out of the table with a certificate of their own. A withdrawn authority is spared as
     * well: it carries the verdict its children get, and the built-in lists never take a
     * withdrawal back, so losing the entry would turn "withdrawn" into "issuer missing". */
    unsigned slot = ITS_VERIFY_ISSUERS;
    for (unsigned i = 0; i < ITS_VERIFY_ISSUERS && slot == ITS_VERIFY_ISSUERS; i++)
        if (!s_issuers[i].used)
            slot = i;
    for (unsigned i = 0; i < ITS_VERIFY_ISSUERS && slot == ITS_VERIFY_ISSUERS; i++)
        if (s_issuers[i].state != ITS_VERIFY_REVOKED &&
            (s_issuers[i].state != ITS_VERIFY_CHECKED || !s_issuers[i].cert_issue))
            slot = i;
    if (slot == ITS_VERIFY_ISSUERS)
    {
        if (res.state != ITS_VERIFY_CHECKED || !may)
        {
            unlock();
            return true;
        }
        slot = s_issuer_next++ % ITS_VERIFY_ISSUERS;
    }
    issuer_t *e = &s_issuers[slot];
    memset(e, 0, sizeof *e);
    memcpy(e->id[0], h256 + 24, 8);
    memcpy(e->id[1], h384 + 40, 8);
    memcpy(e->hash[0], h256, sizeof h256);
    memcpy(e->hash[1], h384, sizeof h384);
    e->valid_start = c.valid_start;
    e->duration = c.duration;
    e->duration_unit = c.duration_unit;
    e->key_type = c.key_type;
    e->key_form = c.key_form;
    e->key_len = c.key_len <= sizeof e->key ? (uint8_t)c.key_len : 0;
    memcpy(e->key, cert + c.key_off, e->key_len);
    /* The bytes stay with the entry because the PSID lists of certIssuePermissions are read
     * out of them for every child. usable() already refused anything above the buffer. */
    e->cert_len = (uint16_t)len;
    memcpy(e->cert, cert, len);
    e->parsed = c;
    e->room = res.state == ITS_VERIFY_CHECKED ? res.room : 0;
    e->state = res.state;
    e->why = res.why;
    e->root_env = res.root_env;
    e->chain = res.chain;
    e->cert_issue = may;
    /* The store sets this flag around its own call, so it says who supplied the bytes. */
    e->from_store = s_in_store ? ITS_VERIFY_ISSUER_BUILTIN : ITS_VERIFY_ISSUER_SENT;
    copy_name(e->name, c.name);
    copy_name(e->root_name, res.root_name);
    e->used = true;
    unsigned n = 0;
    for (unsigned i = 0; i < ITS_VERIFY_ISSUERS; i++)
        n += s_issuers[i].used;
    s_stats.issuers = n;
    unlock();
    if (res.state == ITS_VERIFY_CHECKED)
        its_certcache_retry_unchecked();
    return true;
}

void its_verify_note_issuer(const uint8_t *cert, size_t len)
{
    (void)note_issuer(cert, len);
}

void its_verify_stats(its_verify_stats_t *out)
{
    if (!out)
        return;
    bool locked = lock(100);
    *out = s_stats;
    if (locked)
        unlock();
}

/* ------------------------------------------------------------ verify task */

#ifdef ESP_PLATFORM

/* The receive task only copies bytes into a free slot, and the verify task does the work.
 * Four slots are enough because senders repeat the same certificate. */
#define SLOTS 4

typedef struct
{
    uint16_t len;
    bool     issuer;
    uint8_t  bytes[ITS_VERIFY_CERT_MAX];
} slot_t;

static EXT_RAM_BSS_ATTR slot_t s_slot[SLOTS];
static bool s_slot_busy[SLOTS];
static QueueHandle_t s_queue;            /* Filled slot indices, or 0xFF to only wake the task. */
static SemaphoreHandle_t s_slot_lock;

static void release_slot(unsigned i)
{
    if (xSemaphoreTake(s_slot_lock, portMAX_DELAY) == pdTRUE)
    {
        s_slot_busy[i] = false;
        xSemaphoreGive(s_slot_lock);
    }
}

/* Verify the self-signature of one built-in root, which needs no received data and no clock.
 * A device that cannot do this cannot check any chain either, and it says so. */
static void selftest(void)
{
    its_trust_entry_t t;
    its_verify_cert_t c;
    its_verify_result_t res = { 0 };
    uint8_t signer[48];
    static const uint8_t nothing[1] = { 0 };
    uint8_t state = 2;
    uint32_t t0 = now_us();

    /* A root on the NIST curve is checked in hardware and costs milliseconds, while Brainpool
     * runs in software and costs seconds, so such a root is picked first. */
    bool found = false;
    for (size_t i = 0; !found && its_trustlist_at(i, &t); i++)
        found = t.role == ITS_TRUST_ROLE_ROOT && !(t.flags & ITS_TRUST_PREDECESSOR) &&
                t.key_type == ITS_SEC_KEY_ECDSA_NIST_P256;
    for (size_t i = 0; !found && its_trustlist_at(i, &t); i++)
        found = t.role == ITS_TRUST_ROLE_ROOT && !(t.flags & ITS_TRUST_PREDECESSOR);
    if (found && its_verify_parse(t.cert, t.cert_len, &c) && c.self_signed &&
        hash_bytes(c.hash_alg, nothing, 0, signer) &&
        check_sig(t.cert, &c, c.key_type, c.key_form, t.cert + c.key_off, c.key_len,
                  signer, &res))
        state = 1;
    uint32_t dt = now_us() - t0;
    if (!lock(200))
        return;
    s_stats.selftest = state;
    s_stats.selftest_us = dt;
    unlock();
    if (state == 1)
        ESP_LOGI(TAG, "self test passed in %lu us", (unsigned long)dt);
    else
        ESP_LOGE(TAG, "self test failed, certificates stay unchecked");
}

/* Words the task never touched, turned into bytes. Zero on the host, which has no task. */
static void note_stack_left(void)
{
#ifdef ESP_PLATFORM
    uint32_t left = (uint32_t)uxTaskGetStackHighWaterMark(NULL) * sizeof(StackType_t);
    if (lock(10))
    {
        if (s_stats.stack_left == 0 || left < s_stats.stack_left)
            s_stats.stack_left = left;
        unlock();
    }
#endif
}

/* One message check of its_msgsig.c, false when none waits. */
static bool run_msgsig(void)
{
    its_msgsig_job_t j;
    if (!its_msgsig_take(&j))
        return false;
    uint32_t t0 = now_us();
    int m = its_verify_ecdsa(j.key_type, j.key[0], j.key + 1, 32, j.digest, sizeof j.digest,
                             j.rs, sizeof j.rs);
    its_msgsig_done(&j, m, now_us() - t0);
    return true;
}

static void verify_task(void *arg)
{
    (void)arg;
    selftest();
    for (;;)
    {
        uint8_t i;
        if (xQueueReceive(s_queue, &i, portMAX_DELAY) != pdTRUE)
            continue;
        if (i < SLOTS)
        {
            if (s_slot[i].issuer)
            {
                its_verify_note_issuer(s_slot[i].bytes, s_slot[i].len);
            }
            else
            {
                its_verify_result_t res;
                its_verify_cert(s_slot[i].bytes, s_slot[i].len, &res);
                its_certcache_set_verify(s_slot[i].bytes, s_slot[i].len, &res);
            }
            release_slot(i);
            /* The deepest path only shows itself once authorities are compiled in, so the room
             * left is measured here instead of being trusted from -fstack-usage. */
            note_stack_left();
        }
        /* Message checks run only while no chain check waits, so the brake of its_certcache.c
         * keeps its pace. A running message check delays a chain check by its own time at most. */
        while (uxQueueMessagesWaiting(s_queue) == 0 && run_msgsig())
            note_stack_left();
    }
}

void its_verify_start(void)
{
    if (s_queue)
        return;
    /* A key can only be imported once PSA is up. Calling this again is harmless, so it does
     * not matter whether another component got there first. */
    psa_status_t ps = psa_crypto_init();
    if (ps != PSA_SUCCESS)
    {
        ESP_LOGE(TAG, "psa_crypto_init failed (%d), certificates stay unchecked", (int)ps);
        return;
    }
    if (!s_lock)
        s_lock = xSemaphoreCreateMutex();
    if (!s_slot_lock)
        s_slot_lock = xSemaphoreCreateMutex();
    /* Three places more than slots: one wake-up per message slot of its_msgsig.c, and one left
     * behind when the task took that job before reading its wake-up. */
    s_queue = xQueueCreate(SLOTS + 3, sizeof(uint8_t));
    if (!s_lock || !s_slot_lock || !s_queue)
    {
        ESP_LOGE(TAG, "no memory for the verify queue");
        return;
    }
    /* An issuer out of its_castore nests a second note_issuer and its_verify_cert pair inside
     * the first. -fstack-usage puts that at 1104 bytes on top of 3792 on the
     * target, about 4900 in all. 6144 would be too close to guess at, hence 7168 and the
     * measured stack_left. The priority stays below the receive task, so a check never delays
     * a frame. A Brainpool curve has no hardware support, and one chain took nine seconds on
     * the device. Most of that time goes to waiting for the arithmetic unit, so the idle task
     * still runs and the watchdog stays quiet. */
    if (xTaskCreate(verify_task, "itsverify", 7168, NULL, 1, NULL) != pdPASS)
        ESP_LOGE(TAG, "verify task did not start");
}

void its_verify_wake(void)
{
    /* Any index past the slots only wakes the task. A full queue means the task is busy and
     * looks at the message checks once the chain checks are done. */
    uint8_t wake = 0xFF;
    if (s_queue)
        (void)xQueueSend(s_queue, &wake, 0);
}

bool its_verify_submit(const uint8_t *cert, size_t len, bool issuer)
{
    if (!s_queue || !cert || !len || len > ITS_VERIFY_CERT_MAX)
        return false;
    /* The receive task must not wait here, so a busy table drops the certificate. The
     * counter is only displayed, which is why it is raised without the lock. */
    if (xSemaphoreTake(s_slot_lock, 0) != pdTRUE)
    {
        s_stats.dropped++;
        return false;
    }
    int slot = -1;
    for (int i = 0; i < SLOTS && slot < 0; i++)
        if (!s_slot_busy[i])
            slot = i;
    if (slot >= 0)
        s_slot_busy[slot] = true;
    xSemaphoreGive(s_slot_lock);
    if (slot < 0)
    {
        s_stats.dropped++;
        return false;
    }
    memcpy(s_slot[slot].bytes, cert, len);
    s_slot[slot].len = (uint16_t)len;
    s_slot[slot].issuer = issuer;
    uint8_t idx = (uint8_t)slot;
    if (xQueueSend(s_queue, &idx, 0) == pdTRUE)
        return true;
    release_slot((unsigned)slot);
    s_stats.dropped++;
    return false;
}

#else

void its_verify_start(void)
{
}

void its_verify_wake(void)
{
}

/* Without FreeRTOS there is no second task, so the host test takes the same steps right
 * here and gets the whole path covered. */
bool its_verify_submit(const uint8_t *cert, size_t len, bool issuer)
{
    if (!cert || !len || len > ITS_VERIFY_CERT_MAX)
        return false;
    if (issuer)
    {
        its_verify_note_issuer(cert, len);
    }
    else
    {
        its_verify_result_t res;
        its_verify_cert(cert, len, &res);
        its_certcache_set_verify(cert, len, &res);
    }
    return true;
}

#endif
