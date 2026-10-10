#include "its_security.h"

#include <string.h>

#include "its_bits.h"

_Static_assert(sizeof(its_sec_info_t) < 200, "its_sec_info_t must stay below 200 bytes");
/* check_sig in its_verify.c compares a key_type with a sig_type, and its_sec_alg_name names both.
 * The casts are needed: -Werror=enum-compare rejects comparing two enum types. */
_Static_assert((int)ITS_SEC_SIG_ECDSA_NIST_P256 == (int)ITS_SEC_KEY_ECDSA_NIST_P256 &&
               (int)ITS_SEC_SIG_ECDSA_BRAINPOOL_P256 == (int)ITS_SEC_KEY_ECDSA_BRAINPOOL_P256 &&
               (int)ITS_SEC_SIG_ECDSA_BRAINPOOL_P384 == (int)ITS_SEC_KEY_ECDSA_BRAINPOOL_P384 &&
               (int)ITS_SEC_SIG_ECDSA_NIST_P384 == (int)ITS_SEC_KEY_ECDSA_NIST_P384 &&
               (int)ITS_SEC_SIG_SM2 == (int)ITS_SEC_KEY_SM2,
               "its_sec_sig_t and its_sec_key_t must share the values 0 to 4");

/* The cursor walks COER bytes. `err` latches on the first truncated or malformed field,
 * and every later read then returns 0 without touching the buffer. */
typedef struct
{
    const uint8_t *b;
    size_t len;
    size_t pos;
    bool err;
} oer_t;

/* A span marks the content of one open type in an extension list. */
typedef struct
{
    size_t off;
    size_t len;
} oer_span_t;

/* Return true when n more bytes can be read. This keeps `pos` from passing `len`. */
static bool oer_avail(oer_t *r, size_t n)
{
    if (r->err || n > r->len - r->pos)
    {
        r->err = true;
        return false;
    }
    return true;
}

/* Read a big-endian unsigned value of n bytes. The count must not exceed 8. */
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

/* COER sends a fixed signed INTEGER range as 4 octets two's complement. The sign is restored by
 * arithmetic, since converting a value above INT32_MAX to int32_t is implementation-defined. */
static int32_t oer_s32(oer_t *r)
{
    uint32_t u = (uint32_t)oer_uint(r, 4);
    return u < 0x80000000u ? (int32_t)u : (int32_t)((int64_t)u - 0x100000000);
}

static void oer_skip(oer_t *r, size_t n)
{
    if (oer_avail(r, n))
        r->pos += n;
}

static void oer_copy(oer_t *r, uint8_t *dst, size_t n)
{
    if (!oer_avail(r, n))
        return;
    memcpy(dst, r->b + r->pos, n);
    r->pos += n;
}

static size_t oer_length(oer_t *r)
{
    size_t value_len, field_len;
    if (r->err || !its_oer_length(r->b, r->len, r->pos, &value_len, &field_len))
    {
        r->err = true;
        return 0;
    }
    r->pos += field_len;
    return value_len;
}

/* Skip a value behind a length prefix. Open types, OCTET STRINGs of variable size and
 * INTEGERs without an upper bound use this form. */
static void oer_skip_prefixed(oer_t *r)
{
    size_t n = oer_length(r);
    oer_skip(r, n);
}

/* Read a SEQUENCE OF quantity. Every element read here takes at least one byte, so a
 * count beyond the remaining bytes means the data is malformed. */
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

/* Read a context class CHOICE tag with a tag number below 63. The result is the index
 * of the chosen alternative. */
static unsigned oer_tag(oer_t *r)
{
    uint8_t t = oer_u8(r);
    if ((t & 0xC0) != 0x80 || (t & 0x3F) == 0x3F)
        r->err = true;
    return r->err ? 0 : (unsigned)(t & 0x3F);
}

/* Read an ENUMERATED value. The long form only encodes values unknown to this module,
 * so it is skipped and reported as 255. */
static uint8_t oer_enum(oer_t *r)
{
    uint8_t b = oer_u8(r);
    if (b < 0x80)
        return b;
    oer_skip(r, b & 0x7F);
    return 255;
}

/* Psid is an INTEGER without upper bound, but IEEE 1609.12 PSIDs fit in four bytes. */
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

/* Read the extension presence bitmap and skip one open type per set bit. Addition 0 sets bit 15
 * of the result, and addition 15 and every later one set bit 0. The first nspans additions also
 * get their span. */
static uint16_t oer_extensions(oer_t *r, oer_span_t *spans, size_t nspans)
{
    size_t n = oer_length(r);
    uint8_t unused = oer_u8(r);
    if (r->err || n == 0 || unused > 7 || (n == 1 && unused != 0) || !oer_avail(r, n - 1))
    {
        r->err = true;
        return 0;
    }
    const uint8_t *bits = r->b + r->pos;
    size_t nbytes = n - 1;
    r->pos += nbytes;

    uint16_t first = 0;
    for (size_t i = 0; i < nbytes && !r->err; i++)
    {
        uint8_t v = bits[i];
        if (i + 1 == nbytes)
            v &= (uint8_t)(0xFF << unused);
        for (unsigned k = 0; k < 8 && !r->err; k++)
        {
            if (!(v & (0x80 >> k)))
                continue;
            size_t index = 8 * i + k;
            first |= (uint16_t)(0x8000u >> (index < 16 ? index : 15));
            size_t len = oer_length(r);
            if (index < nspans)
            {
                spans[index].off = r->pos;
                spans[index].len = len;
            }
            oer_skip(r, len);
        }
    }
    return r->err ? 0 : first;
}

/* The SSP that belongs to the PSID of the message, collected while walking appPermissions. */
typedef struct
{
    size_t  off;
    size_t  len;
    uint8_t form;    /* Values come from its_sec_ssp_t. */
    bool    absent;  /* The matching entry has no ssp field, so its contents are unrestricted. */
    bool    found;   /* An entry for that PSID was seen, so a later one is left alone. */
} ssp_pick_t;

/* Note where the SSP octets of the matching appPermissions entry are. `form` is the CHOICE
 * index of ServiceSpecificPermissions and off..off+len is its encoding, already inside the
 * buffer. Nothing is copied, and a length that ssp_len cannot hold ends up unknown. */
static void pick_ssp(const oer_t *r, unsigned form, size_t off, size_t len, ssp_pick_t *p)
{
    if (form == 0)                            /* opaque is a root alternative: octets are here. */
    {
        p->form = ITS_SEC_SSP_OPAQUE;
        p->off = off;
        p->len = len;
    }
    else if (form == 1)                       /* bitmapSsp is an extension, so it is an open
                                               * type holding the octet string encoding. */
    {
        oer_t in = { r->b, off + len, off, false };
        size_t n = oer_length(&in);
        if (!in.err && n == (off + len) - in.pos)
        {
            p->form = ITS_SEC_SSP_BITMAP;
            p->off = in.pos;
            p->len = n;
        }
        else
        {
            p->form = ITS_SEC_SSP_OTHER;      /* The open type does not hold one octet string. */
        }
    }
    else
    {
        p->form = ITS_SEC_SSP_OTHER;          /* An alternative this module does not know. */
    }
    if (p->len > UINT8_MAX)
    {
        p->len = 0;                           /* Longer than the services use: unknown to us. */
    }
    if (p->len == 0)
    {
        p->off = 0;                           /* Keep the pair consistent: no bytes, no offset. */
    }
}

/* A curve point is x-only, fill, compressed-y-0, compressed-y-1 or uncompressed.
 * `size` is the byte length of one coordinate. The return value is the form's index. */
static unsigned skip_point(oer_t *r, size_t size)
{
    unsigned form = oer_tag(r);
    switch (form)
    {
    case 0:
    case 2:
    case 3:
        oer_skip(r, size);
        break;
    case 1:
        break;
    case 4:
        oer_skip(r, 2 * size);
        break;
    default:
        r->err = true;
        break;
    }
    return form;
}

/* The canonical form of a certificate has every key point compressed and an x-only rSig. */
static bool point_compressed(unsigned form)
{
    return form == 2 || form == 3;
}

/* Return the point form at the start of an open type's content without reading it, or
 * 0xFF when there is no such byte. */
static unsigned peek_form(const oer_t *r, size_t n)
{
    if (r->err || n == 0 || r->pos >= r->len || (r->b[r->pos] & 0xC0) != 0x80)
        return 0xFF;
    return r->b[r->pos] & 0x3F;
}

/* The P-384 and SM2 signature alternatives are extensions and arrive as open types.
 * `noncanon` may be NULL. It is set when an ECDSA rSig is not x-only. */
static uint8_t read_signature(oer_t *r, bool *noncanon)
{
    unsigned idx = oer_tag(r);
    if (idx <= ITS_SEC_SIG_ECDSA_BRAINPOOL_P256)
    {
        unsigned form = skip_point(r, 32);    /* rSig */
        oer_skip(r, 32);                      /* sSig */
        if (noncanon)
            *noncanon = form != 0;
        return (uint8_t)idx;
    }
    size_t n = oer_length(r);
    unsigned form = peek_form(r, n);          /* rSig of a P-384 signature */
    oer_skip(r, n);
    if (noncanon && idx <= ITS_SEC_SIG_ECDSA_NIST_P384)
        *noncanon = form != 0xFF && form != 0;
    return (uint8_t)(idx <= ITS_SEC_SIG_SM2 ? idx : ITS_SEC_SIG_OTHER);
}

static void skip_identified_region(oer_t *r)
{
    unsigned idx = oer_tag(r);
    if (idx > 2)
    {
        oer_skip_prefixed(r);                 /* This alternative is an extension. */
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
    {
        oer_skip(r, 8 + 2);                   /* CircularRegion has a center and a radius. */
    }
    else if (idx == 1)
    {
        oer_skip(r, 16 * oer_quantity(r));    /* Each RectangularRegion takes 16 bytes. */
    }
    else if (idx == 2)
    {
        oer_skip(r, 8 * oer_quantity(r));     /* Each PolygonalRegion corner takes 8 bytes. */
    }
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

/* Skip the SequenceOfPsidSspRange of SubjectPermissions.explicit. */
static void skip_psid_ranges(oer_t *r)
{
    size_t q = oer_quantity(r);
    for (size_t i = 0; i < q && !r->err; i++)
    {
        uint8_t opt = oer_u8(r);              /* Bit 7 flags sspRange. */
        oer_skip_prefixed(r);                 /* psid */
        if (!(opt & 0x80))
            continue;
        unsigned idx = oer_tag(r);
        if (idx == 0)
        {
            size_t n = oer_quantity(r);       /* SequenceOfOctetString */
            for (size_t k = 0; k < n && !r->err; k++)
                oer_skip_prefixed(r);
        }
        else if (idx > 1)
        {
            oer_skip_prefixed(r);             /* bitmapSspRange is an extension. */
        }
    }
}

/* Skip the SequenceOfPsidGroupPermissions of certIssuePermissions or certRequestPermissions. */
static void skip_group_permissions(oer_t *r)
{
    size_t q = oer_quantity(r);
    for (size_t i = 0; i < q && !r->err; i++)
    {
        uint8_t opt = oer_u8(r);              /* Bits 7 to 5 flag the three DEFAULT fields. */
        unsigned idx = oer_tag(r);            /* subjectPermissions */
        if (idx == 0)
            skip_psid_ranges(r);
        else if (idx > 1)
            oer_skip_prefixed(r);
        if (opt & 0x80)
            oer_skip_prefixed(r);             /* minChainLength */
        if (opt & 0x40)
            oer_skip_prefixed(r);             /* chainLengthRange */
        if (opt & 0x20)
            oer_skip(r, 1);                   /* eeType */
    }
}

/* PublicEncryptionKey holds supportedSymmAlg and then a BasePublicEncryptionKey.
 * Return true when its point is not compressed. `annex_a` may be NULL. It is set when the key
 * is one TS 103 097 Annex A allows: aes128Ccm with eciesNistP256 or eciesBrainpoolP256r1. */
static bool skip_public_enc_key(oer_t *r, bool *annex_a)
{
    uint8_t alg = oer_enum(r);
    unsigned idx = oer_tag(r);
    if (annex_a)
        *annex_a = alg == 0 && idx <= 1;
    if (idx <= 1)
        return !point_compressed(skip_point(r, 32));
    size_t n = oer_length(r);                 /* ecencSm2 is an extension. */
    unsigned form = peek_form(r, n);
    oer_skip(r, n);
    return idx == 2 && form != 0xFF && !point_compressed(form);
}

/* HeaderInfo.encryptionKey is a CHOICE of public and symmetric. Return true when TS 103 097
 * Annex A allows its form. For symmetric that is aes128Ccm alone. */
static bool skip_header_enc_key(oer_t *r)
{
    unsigned idx = oer_tag(r);
    bool annex_a = false;
    if (idx == 0)
    {
        skip_public_enc_key(r, &annex_a);
    }
    else if (idx == 1)
    {
        annex_a = oer_tag(r) == 0;
        if (annex_a)
            oer_skip(r, 16);                  /* aes128Ccm */
        else
            oer_skip_prefixed(r);             /* sm4Ccm is an extension. */
    }
    else
    {
        r->err = true;
    }
    return annex_a;
}

/* Read the VerificationKeyIndicator. `point_off` gets the offset of the curve point, and
 * `noncanon` is set when that point is not compressed. */
static uint8_t read_verify_key(oer_t *r, size_t *point_off, bool *noncanon)
{
    *point_off = 0;
    *noncanon = false;
    unsigned idx = oer_tag(r);
    if (idx == 1)
    {
        *point_off = r->pos;
        *noncanon = !point_compressed(skip_point(r, 32));
        return ITS_SEC_KEY_RECONSTRUCTION;
    }
    if (idx > 1)
    {
        oer_skip_prefixed(r);
        return ITS_SEC_KEY_OTHER;
    }
    unsigned key = oer_tag(r);
    if (key <= ITS_SEC_KEY_ECDSA_BRAINPOOL_P256)
    {
        *point_off = r->pos;
        *noncanon = !point_compressed(skip_point(r, 32));
        return (uint8_t)key;
    }
    /* The P-384 and SM2 keys are extensions, so their point has to fill the open type. */
    size_t n = oer_length(r);
    size_t end = r->pos + n;
    if (key > ITS_SEC_KEY_SM2)
    {
        oer_skip(r, n);
        return ITS_SEC_KEY_OTHER;
    }
    *point_off = r->pos;
    *noncanon = !point_compressed(skip_point(r, key == ITS_SEC_KEY_SM2 ? 32 : 48));
    if (r->pos != end)
        r->err = true;
    return (uint8_t)key;
}

static uint8_t read_cert_id(oer_t *r)
{
    unsigned idx = oer_tag(r);
    switch (idx)
    {
    case ITS_SEC_CERT_ID_LINKAGE:
    {
        uint8_t opt = oer_u8(r);              /* Bit 7 flags group-linkage-value. */
        oer_skip(r, 2 + 9);                   /* iCert, linkage-value */
        if (opt & 0x80)
            oer_skip(r, 4 + 9);               /* jValue, value */
        break;
    }
    case ITS_SEC_CERT_ID_NAME:
    case ITS_SEC_CERT_ID_BINARY:
        oer_skip_prefixed(r);
        break;
    case ITS_SEC_CERT_ID_NONE:
        break;
    default:
        oer_skip_prefixed(r);
        return ITS_SEC_CERT_ID_OTHER;
    }
    return (uint8_t)idx;
}

/* Walk one CertificateBase. Its fields go to `out` only when `out` is given and the
 * certificate was read completely. */
static void read_cert(oer_t *r, its_sec_info_t *out)
{
    size_t start = r->pos;
    uint8_t opt = oer_u8(r);                  /* Bit 7 flags the signature. */
    uint8_t version = oer_u8(r);
    uint8_t type = oer_enum(r);
    if (version != 3)
        r->err = true;

    uint8_t issuer_id[8] = { 0 };
    unsigned issuer = oer_tag(r);
    if (issuer == ITS_SEC_ISSUER_SHA256_DIGEST)
    {
        oer_copy(r, issuer_id, 8);
    }
    else if (issuer == ITS_SEC_ISSUER_SELF)
    {
        oer_enum(r);                          /* HashAlgorithm */
    }
    else
    {
        size_t n = oer_length(r);             /* Extension alternatives are open types. */
        if (issuer > ITS_SEC_ISSUER_SM3_DIGEST)
        {
            oer_skip(r, n);
            issuer = ITS_SEC_ISSUER_OTHER;
        }
        else if (n == 8)
        {
            oer_copy(r, issuer_id, 8);
        }
        else
        {
            r->err = true;
        }
    }

    /* Bit 7 flags extensions. Bits 6 to 0 flag the optional fields. */
    uint8_t tbs = oer_u8(r);
    uint8_t id = read_cert_id(r);
    oer_skip(r, 3 + 2);                       /* cracaId, crlSeries */
    uint32_t start_time = (uint32_t)oer_uint(r, 4);
    unsigned unit = oer_tag(r);
    if (unit > ITS_SEC_DUR_YEARS)
        r->err = true;
    uint16_t duration = (uint16_t)oer_uint(r, 2);
    if (tbs & 0x40)
        skip_region(r);
    if (tbs & 0x20)
        oer_skip(r, 1);                       /* assuranceLevel */

    uint32_t psids[ITS_SEC_MAX_PSIDS] = { 0 };
    size_t npsids = 0;
    /* The PSID of the message is already read when the first certificate is walked. Every
     * entry is looked at, also past ITS_SEC_MAX_PSIDS, so a cut PSID list still finds the SSP. */
    ssp_pick_t pick = { 0, 0, ITS_SEC_SSP_NONE, false, false };
    bool want_ssp = out && (out->flags & ITS_SEC_HAVE_HEADER);
    if (tbs & 0x10)
    {
        npsids = oer_quantity(r);
        for (size_t i = 0; i < npsids && !r->err; i++)
        {
            uint8_t ssp = oer_u8(r);          /* Bit 7 flags ssp. */
            uint32_t psid = oer_psid(r);
            /* Only the first entry for that PSID counts. IEEE 1609.2 wants one entry per PSID,
             * and a second one cannot widen what the first already allows. */
            bool mine = want_ssp && !pick.found && !r->err && psid == out->psid;
            if (ssp & 0x80)
            {
                unsigned form = oer_tag(r);   /* Every alternative continues with a length. */
                size_t n = oer_length(r);
                size_t body = r->pos;
                oer_skip(r, n);
                if (mine && !r->err)
                    pick_ssp(r, form, body, n, &pick);
            }
            else if (mine)
            {
                pick.absent = true;
            }
            if (mine)
                pick.found = true;
            if (i < ITS_SEC_MAX_PSIDS)
                psids[i] = psid;
        }
    }
    if (tbs & 0x08)
        skip_group_permissions(r);            /* certIssuePermissions */
    if (tbs & 0x04)
        skip_group_permissions(r);            /* certRequestPermissions */
    /* Bit 1 is canRequestRollover, a NULL that takes no bytes. */
    bool enc_noncanon = false;
    if (tbs & 0x01)
        enc_noncanon = skip_public_enc_key(r, NULL);   /* encryptionKey */
    size_t key_off;
    bool key_noncanon;
    uint8_t key_type = read_verify_key(r, &key_off, &key_noncanon);
    if (tbs & 0x80)
        oer_extensions(r, NULL, 0);
    bool sig_noncanon = false;
    if (opt & 0x80)
        read_signature(r, &sig_noncanon);
    if (r->err || !out)
        return;

    out->cert_off = (uint16_t)start;
    out->cert_len = (uint16_t)(r->pos - start);
    out->issuer = (uint8_t)issuer;
    memcpy(out->issuer_id, issuer_id, sizeof issuer_id);
    out->cert_id = id;
    out->validity_start = start_time;
    out->duration_unit = (uint8_t)unit;
    out->duration = duration;
    out->key_type = key_type;
    out->key_off = (uint16_t)key_off;
    out->n_psids = (uint8_t)(npsids < ITS_SEC_MAX_PSIDS ? npsids : ITS_SEC_MAX_PSIDS);
    memcpy(out->app_psids, psids, out->n_psids * sizeof psids[0]);
    out->ssp_off = (uint16_t)pick.off;
    out->ssp_len = (uint8_t)pick.len;
    out->ssp_form = pick.form;
    if (pick.absent)
        out->flags |= ITS_SEC_SSP_ABSENT;
    if (npsids > ITS_SEC_MAX_PSIDS)
        out->flags |= ITS_SEC_PSIDS_CUT;
    if (type == 1)
        out->flags |= ITS_SEC_CERT_IMPLICIT;
    if (enc_noncanon || key_noncanon || sig_noncanon)
        out->flags |= ITS_SEC_CERT_NONCANON;
}

/* contributedExtensions: blocks of a contributorId and open types. In ETSI's block (id 2)
 * each open type holds an id and another open type. An unreadable list gives BAD alone,
 * with no half-read bits, and it never sets r->err.
 * noinline keeps its two cursors out of its_decode_security's frame (224 -> 176 B, riscv32). */
static __attribute__((noinline)) uint8_t read_contrib(const uint8_t *b, oer_span_t sp)
{
    oer_t in = { b, sp.off + sp.len, sp.off, false };
    uint8_t c = 0;
    size_t q = oer_quantity(&in);
    if (q == 0)
        in.err = true;                        /* SIZE(1..MAX) */
    for (size_t i = 0; i < q && !in.err; i++)
    {
        uint8_t who = oer_u8(&in);            /* contributorId */
        size_t n = oer_quantity(&in);
        if (n == 0)
            in.err = true;                    /* extns is SIZE(1..MAX) as well. */
        else if (who != 2)
            c |= ITS_SEC_C_FOREIGN;
        for (size_t k = 0; k < n && !in.err; k++)
        {
            size_t len = oer_length(&in);
            size_t off = in.pos;
            oer_skip(&in, len);
            if (in.err || who != 2)
                continue;
            oer_t ex = { b, off + len, off, false };
            uint8_t id = oer_u8(&ex);
            oer_skip_prefixed(&ex);           /* content */
            if (ex.err || ex.pos != ex.len)
                in.err = true;
            else if (id == 1)
                c |= ITS_SEC_C_CRL;
            else if (id == 2 || id == 3)
                c |= ITS_SEC_C_CTL;           /* delta or full CTL */
            else
                c |= ITS_SEC_C_ETSI;
        }
    }
    return in.err || in.pos != in.len ? ITS_SEC_C_BAD : c;
}

/* Read HeaderInfo: the psid, both times, the location and what the rare parts carry. A broken
 * requestedCertificate or list does not cost the rest. */
static void read_header(oer_t *r, its_sec_info_t *out)
{
    /* Bit 7 flags extensions. Bits 6 to 1 flag the optional fields. */
    uint8_t opt = oer_u8(r);
    uint32_t psid = oer_psid(r);
    uint16_t hdr = 0;
    uint8_t x = 0;                            /* ITS_SEC_X_* */
    uint64_t gen = 0;
    uint64_t exp = 0;
    int32_t lat = 0;
    int32_t lon = 0;
    uint16_t elev = 0;
    uint16_t n_inline = 0;
    uint8_t pdu = 0;
    uint8_t contrib = 0;
    oer_span_t ext[4] = { 0 };
    if (opt & 0x40)
    {
        gen = oer_uint(r, 8);
        hdr |= ITS_SEC_HDR_GENERATION_TIME;
    }
    if (opt & 0x20)
    {
        exp = oer_uint(r, 8);
        hdr |= ITS_SEC_HDR_EXPIRY_TIME;
    }
    if (opt & 0x10)
    {
        lat = oer_s32(r);                     /* ThreeDLocation */
        lon = oer_s32(r);
        elev = (uint16_t)oer_uint(r, 2);
        hdr |= ITS_SEC_HDR_LOCATION;
    }
    if (opt & 0x08)
    {
        oer_skip(r, 3);                       /* HashedId3 */
        hdr |= ITS_SEC_HDR_P2PCD_LEARNING;
    }
    if (opt & 0x04)
    {
        uint8_t more = oer_u8(r);             /* MissingCrlIdentifier is extensible. */
        oer_skip(r, 3 + 2);                   /* cracaId, crlSeries */
        if (more & 0x80)
            oer_extensions(r, NULL, 0);
        hdr |= ITS_SEC_HDR_MISSING_CRL;
    }
    if (opt & 0x02)
    {
        if (!skip_header_enc_key(r))
            x |= ITS_SEC_X_ENC_FORM;
        hdr |= ITS_SEC_HDR_ENCRYPTION_KEY;
    }
    /* Each addition is an open type with its own length, so a bad content only marks itself
     * and never sets r->err. A set bit also means every span lies inside the buffer. */
    if (opt & 0x80)
    {
        uint16_t bits = oer_extensions(r, ext, 4);
        if (bits & 0x8000)
        {
            oer_t in = { r->b, ext[0].off + ext[0].len, ext[0].off, false };
            size_t q = oer_quantity(&in);     /* SequenceOfHashedId3 */
            oer_skip(&in, 3 * q);
            if (!in.err && in.pos == in.len)
                n_inline = (uint16_t)(q < UINT16_MAX ? q : UINT16_MAX);
            else
                x |= ITS_SEC_X_INLINE_BAD;
            hdr |= ITS_SEC_HDR_INLINE_P2PCD;
        }
        if (bits & 0x4000)
        {
            /* The open type has to hold exactly one Certificate. Otherwise its span stays 0,
             * which its_certcache ignores (note_issuer_cert wants 8 octets or more). */
            oer_t cert = { r->b, ext[1].off + ext[1].len, ext[1].off, false };
            read_cert(&cert, NULL);
            if (cert.err || cert.pos != cert.len)
            {
                x |= ITS_SEC_X_REQCERT_BAD;
                ext[1] = (oer_span_t){ 0, 0 };
            }
            hdr |= ITS_SEC_HDR_REQUESTED_CERT;
        }
        if (bits & 0x2000)
        {
            if (ext[2].len == 1)
                pdu = r->b[ext[2].off];       /* INTEGER (0..255) */
            else
                x |= ITS_SEC_X_PDU_BAD;
            hdr |= ITS_SEC_HDR_PDU_FUNCTIONAL;
        }
        if (bits & 0x1000)
        {
            contrib = read_contrib(r->b, ext[3]);
            hdr |= ITS_SEC_HDR_CONTRIBUTED_EXT;
        }
        if (bits & 0x0FFF)
            x |= ITS_SEC_X_EXT_OTHER;
    }
    if (r->err)
        return;
    out->psid = psid;
    out->header = hdr;
    out->xflags |= x;
    out->generation_time = gen;
    out->expiry_time = exp;
    out->gen_lat = lat;
    out->gen_lon = lon;
    out->gen_elev = elev;
    out->n_inline = n_inline;
    out->pdu_type = pdu;
    out->contrib = contrib;
    out->req_cert_off = (uint16_t)ext[1].off;
    out->req_cert_len = (uint16_t)ext[1].len;
}

bool its_decode_security(const uint8_t *buf, size_t len, size_t off, its_sec_info_t *out)
{
    if (!out)
        return false;
    memset(out, 0, sizeof *out);
    if (!buf || len > UINT16_MAX || off > len)
        return false;

    oer_t r = { buf, len, off, false };
    uint8_t version = oer_u8(&r);
    unsigned content = oer_tag(&r);
    if (r.err || version != 3)
        return false;
    out->valid = true;
    out->version = version;
    out->content = (uint8_t)(content < ITS_SEC_OTHER ? content : ITS_SEC_OTHER);
    if (content != ITS_SEC_SIGNED)
        return true;

    uint8_t hash_id = oer_enum(&r);
    size_t tbs_off = r.pos;
    uint8_t xpay = 0;                         /* ITS_SEC_X_* of the payload */
    /* Bit 7 flags extensions. Bits 6 and 5 flag data and extDataHash. */
    uint8_t payload = oer_u8(&r);
    if (payload & 0x40)
    {
        /* Only unsecuredData is unwrapped, so nested signed data ends the walk here. */
        uint8_t inner_version = oer_u8(&r);
        if (oer_tag(&r) != ITS_SEC_UNSECURED || inner_version != 3)
            r.err = true;
        size_t n = oer_length(&r);
        if (r.err)
            return true;
        size_t rest = len - r.pos;
        out->payload_off = (uint16_t)r.pos;
        out->payload_len = (uint16_t)(n < rest ? n : rest);
        out->flags |= ITS_SEC_HAVE_PAYLOAD;
        oer_skip(&r, n);
    }
    if (payload & 0x20)
    {
        unsigned form = oer_tag(&r);
        if (form == 0)
            oer_skip(&r, 32);                 /* sha256HashedData */
        else
            oer_skip_prefixed(&r);
        if (!r.err)
            xpay |= form == 0 ? ITS_SEC_X_EXT_HASH : ITS_SEC_X_EXT_HASH | ITS_SEC_X_HASH_NOT256;
    }
    if (payload & 0x80)
    {
        uint16_t pb = oer_extensions(&r, NULL, 0);
        if ((pb & 0x8000) && !r.err)
            xpay |= ITS_SEC_X_OMITTED;
    }

    read_header(&r, out);
    if (r.err)
        return true;
    /* Only now, so a frame cut inside the header leaves no ITS_SEC_X_* bit behind. */
    out->xflags |= xpay;
    out->hash_id = hash_id;
    out->tbs_off = (uint16_t)tbs_off;
    out->tbs_len = (uint16_t)(r.pos - tbs_off);
    out->flags |= ITS_SEC_HAVE_HEADER;

    unsigned signer = oer_tag(&r);
    size_t certs = 0;
    if (signer == ITS_SEC_SIGNER_DIGEST)
    {
        oer_copy(&r, out->digest, 8);
    }
    else if (signer == ITS_SEC_SIGNER_CERTIFICATE)
    {
        certs = oer_quantity(&r);
        for (size_t i = 0; i < certs && !r.err; i++)
            read_cert(&r, i == 0 ? out : NULL);
    }
    else if (signer > ITS_SEC_SIGNER_SELF)
    {
        oer_skip_prefixed(&r);
        signer = ITS_SEC_SIGNER_OTHER;
    }
    if (r.err)
        return true;
    out->signer = (uint8_t)signer;
    out->cert_count = (uint8_t)(certs < 255 ? certs : 255);
    out->sig_off = (uint16_t)r.pos;
    out->flags |= ITS_SEC_HAVE_SIGNER;

    uint8_t sig_type = read_signature(&r, NULL);
    if (r.err)
        return true;
    out->sig_type = sig_type;
    out->end_off = (uint16_t)r.pos;
    out->flags |= ITS_SEC_HAVE_SIGNATURE;
    return true;
}
