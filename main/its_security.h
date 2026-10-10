#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The module reads the signer and the header of the IEEE 1609.2 envelope of ETSI TS 103 097.
 * It verifies nothing, and every offset counts from the start of the frame. */

/* IEEE 1609.2 requires support for at least eight appPermissions entries.
 * Roadside unit certificates in use list ten. */
#define ITS_SEC_MAX_PSIDS 12

/* Unless a comment says otherwise, each enum follows the CHOICE order of the ASN.1 modules
 * and matches the index tshark prints. OTHER covers the alternatives this module skips. */
typedef enum
{
    ITS_SEC_UNSECURED = 0,
    ITS_SEC_SIGNED    = 1,
    ITS_SEC_ENCRYPTED = 2,
    ITS_SEC_OTHER     = 3,
} its_sec_content_t;

typedef enum
{
    ITS_SEC_SIGNER_DIGEST      = 0,
    ITS_SEC_SIGNER_CERTIFICATE = 1,
    ITS_SEC_SIGNER_SELF        = 2,
    ITS_SEC_SIGNER_OTHER       = 3,
} its_sec_signer_t;

typedef enum
{
    ITS_SEC_ISSUER_SHA256_DIGEST = 0,
    ITS_SEC_ISSUER_SELF          = 1,
    ITS_SEC_ISSUER_SHA384_DIGEST = 2,
    ITS_SEC_ISSUER_SM3_DIGEST    = 3,
    ITS_SEC_ISSUER_OTHER         = 4,
} its_sec_issuer_t;

typedef enum
{
    ITS_SEC_CERT_ID_LINKAGE = 0,
    ITS_SEC_CERT_ID_NAME    = 1,
    ITS_SEC_CERT_ID_BINARY  = 2,
    ITS_SEC_CERT_ID_NONE    = 3,
    ITS_SEC_CERT_ID_OTHER   = 4,
} its_sec_cert_id_t;

/* Which ServiceSpecificPermissions alternative carried the SSP. This one does NOT follow the
 * CHOICE order: NONE has to be the zero value, so a cleared struct claims no permissions.
 * OTHER means the entry has an SSP whose bytes this module cannot hand out. That is as unknown
 * as no SSP at all, because reading opaque bytes as a bitmap would invent permissions. */
typedef enum
{
    ITS_SEC_SSP_NONE   = 0,
    ITS_SEC_SSP_BITMAP = 1,
    ITS_SEC_SSP_OPAQUE = 2,
    ITS_SEC_SSP_OTHER  = 3,
} its_sec_ssp_t;

typedef enum
{
    ITS_SEC_DUR_MICROSECONDS = 0,
    ITS_SEC_DUR_MILLISECONDS = 1,
    ITS_SEC_DUR_SECONDS      = 2,
    ITS_SEC_DUR_MINUTES      = 3,
    ITS_SEC_DUR_HOURS        = 4,
    ITS_SEC_DUR_SIXTY_HOURS  = 5,
    ITS_SEC_DUR_YEARS        = 6,
} its_sec_duration_t;

typedef enum
{
    ITS_SEC_SIG_ECDSA_NIST_P256      = 0,
    ITS_SEC_SIG_ECDSA_BRAINPOOL_P256 = 1,
    ITS_SEC_SIG_ECDSA_BRAINPOOL_P384 = 2,
    ITS_SEC_SIG_ECDSA_NIST_P384      = 3,
    ITS_SEC_SIG_SM2                  = 4,
    ITS_SEC_SIG_OTHER                = 5,
} its_sec_sig_t;

/* Values up to SM2 follow PublicVerificationKey. RECONSTRUCTION stands for the
 * reconstruction value of an implicit certificate, which is a 256-bit point. */
typedef enum
{
    ITS_SEC_KEY_ECDSA_NIST_P256      = 0,
    ITS_SEC_KEY_ECDSA_BRAINPOOL_P256 = 1,
    ITS_SEC_KEY_ECDSA_BRAINPOOL_P384 = 2,
    ITS_SEC_KEY_ECDSA_NIST_P384      = 3,
    ITS_SEC_KEY_SM2                  = 4,
    ITS_SEC_KEY_RECONSTRUCTION       = 5,
    ITS_SEC_KEY_OTHER                = 6,
} its_sec_key_t;

/* These bits mark the parts of the walk that completed. A truncated frame stops the
 * walk early, so a field only counts when the part that fills it is set. */
#define ITS_SEC_HAVE_PAYLOAD    0x01  /* payload_off and payload_len are set. */
/* hash_id, psid, header, xflags, both times, the location, n_inline, pdu_type, contrib,
 * tbs_off, tbs_len and the req_cert fields are set. */
#define ITS_SEC_HAVE_HEADER     0x02
/* signer, digest, cert_count, the certificate fields and sig_off are set. */
#define ITS_SEC_HAVE_SIGNER     0x04
#define ITS_SEC_HAVE_SIGNATURE  0x08  /* sig_type and end_off are set. */
#define ITS_SEC_CERT_IMPLICIT   0x10  /* The first certificate is an implicit one. */
/* The appPermissions of the first certificate hold more than ITS_SEC_MAX_PSIDS PSIDs. */
#define ITS_SEC_PSIDS_CUT       0x20
/* A key point of the first certificate is not compressed or its rSig is not x-only. Hashing
 * the raw bytes then does not give the HashedId8, which needs the canonical form. */
#define ITS_SEC_CERT_NONCANON   0x40
/* An appPermissions entry for the PSID of the message is there and carries no SSP: the service
 * is allowed and its contents are not restricted. Without this bit an ssp_form of
 * ITS_SEC_SSP_NONE would also mean that no entry for that PSID was found at all. */
#define ITS_SEC_SSP_ABSENT      0x80

/* These bits mark the optional HeaderInfo fields that were present. */
#define ITS_SEC_HDR_GENERATION_TIME  0x0001
#define ITS_SEC_HDR_EXPIRY_TIME      0x0002
#define ITS_SEC_HDR_LOCATION         0x0004
#define ITS_SEC_HDR_P2PCD_LEARNING   0x0008
#define ITS_SEC_HDR_MISSING_CRL      0x0010
#define ITS_SEC_HDR_ENCRYPTION_KEY   0x0020
#define ITS_SEC_HDR_INLINE_P2PCD     0x0040
#define ITS_SEC_HDR_REQUESTED_CERT   0x0080
#define ITS_SEC_HDR_PDU_FUNCTIONAL   0x0100
#define ITS_SEC_HDR_CONTRIBUTED_EXT  0x0200
/* What the walk noticed beyond the presence bits. its_sechdr.c judges them. */
/* The payload carries an extDataHash. ITS_SEC_HAVE_PAYLOAD says whether the data came as well. */
#define ITS_SEC_X_EXT_HASH    0x01
#define ITS_SEC_X_HASH_NOT256 0x02  /* That extDataHash is not sha256HashedData. */
#define ITS_SEC_X_OMITTED     0x04  /* The payload carries its omitted addition. */
#define ITS_SEC_X_INLINE_BAD  0x08  /* inlineP2pcdRequest does not hold one list of HashedId3. */
/* requestedCertificate is not exactly one readable certificate. Its span stays 0, and the rest
 * of the header is still read. */
#define ITS_SEC_X_REQCERT_BAD 0x10
#define ITS_SEC_X_PDU_BAD     0x20  /* pduFunctionalType is not one octet. */
/* encryptionKey uses an alternative TS 103 097 Annex A does not allow: another symmetric
 * algorithm than aes128Ccm, or a public key other than eciesNistP256 and eciesBrainpoolP256r1. */
#define ITS_SEC_X_ENC_FORM    0x40
#define ITS_SEC_X_EXT_OTHER   0x80  /* HeaderInfo has an addition after contributedExtensions. */

/* contributedExtensions as far as the walk could read it (TS 103 097 4.3.2 and 5.2). */
#define ITS_SEC_C_CRL      0x01  /* an ETSI request for a CRL (EtsiTs102941CrlRequest, id 1) */
#define ITS_SEC_C_CTL      0x02  /* an ETSI request for a delta or full CTL (id 2 or 3) */
#define ITS_SEC_C_ETSI     0x04  /* an ETSI extension with another id */
#define ITS_SEC_C_FOREIGN  0x08  /* a block whose contributorId is not ETSI's 2 */
#define ITS_SEC_C_BAD      0x10  /* the list did not read to its end */

/* The certificate fields issuer, issuer_id, cert_id, validity_start, duration, duration_unit,
 * n_psids, app_psids, ssp_off, ssp_len, ssp_form, key_type, key_off, cert_off and cert_len
 * describe the first certificate. */
typedef struct
{
    bool     valid;
    uint8_t  version;            /* The protocolVersion equals 3 whenever valid is set. */
    uint8_t  content;            /* Values come from its_sec_content_t. */
    uint8_t  flags;              /* The ITS_SEC_HAVE_* bits and the four certificate bits go here. */
    uint8_t  hash_id;            /* hashId is 0 for SHA-256, 1 for SHA-384 and 2 for SM3. */
    uint8_t  signer;             /* Values come from its_sec_signer_t. */
    uint8_t  sig_type;           /* The message signature uses its_sec_sig_t values. */
    uint8_t  cert_count;         /* The signer chain has this many certificates, capped at 255. */
    uint8_t  issuer;             /* Values come from its_sec_issuer_t. */
    uint8_t  cert_id;            /* Values come from its_sec_cert_id_t. */
    uint8_t  duration_unit;      /* Values come from its_sec_duration_t. */
    uint8_t  n_psids;            /* This many entries of app_psids are in use. */
    uint8_t  key_type;           /* Values come from its_sec_key_t. */
    uint8_t  ssp_len;            /* Bytes at ssp_off. It stays 0 when no usable SSP was found. */
    uint8_t  ssp_form;           /* Values come from its_sec_ssp_t. */
    uint8_t  xflags;             /* The ITS_SEC_X_* bits. It fills the hole in front of header. */
    uint16_t header;             /* The ITS_SEC_HDR_* bits go here. */
    uint16_t duration;           /* The validity period lasts this many duration_unit steps. */
    uint16_t payload_off;        /* The inner unsecuredData starts here. */
    uint16_t payload_len;        /* The length is cut at the buffer end. */
    uint16_t tbs_off;            /* ToBeSignedData starts here. The signature covers it. */
    uint16_t tbs_len;
    uint16_t req_cert_off;       /* The requestedCertificate of HeaderInfo starts here. */
    uint16_t req_cert_len;       /* Both req_cert fields stay 0 when it is absent. */
    /* The SSP octets of the appPermissions entry whose PSID equals psid. A permission check
     * needs that one entry only, so nothing is copied and the other SSPs stay unread. Both
     * ssp fields are 0 unless ssp_form names a form whose bytes are here. */
    uint16_t ssp_off;
    /* Hashing the certificate bytes gives its HashedId8 only when every key point is
     * compressed and the certificate signature has an x-only rSig, see ITS_SEC_CERT_NONCANON. */
    uint16_t cert_off;
    uint16_t cert_len;
    /* The key point begins here with its CHOICE tag. key_off stays 0 for ITS_SEC_KEY_OTHER. */
    uint16_t key_off;
    uint16_t sig_off;            /* The message Signature starts here with its CHOICE tag. */
    uint16_t end_off;            /* The envelope ends right before this byte. */
    uint32_t psid;
    uint32_t validity_start;     /* Time32 counts TAI seconds since 2004-01-01 00:00:00 UTC. */
    uint64_t generation_time;    /* Time64 counts TAI microseconds since the same epoch. */
    uint64_t expiry_time;
    uint8_t  digest[8];          /* A digest signer gives the HashedId8 of its certificate here. */
    uint8_t  issuer_id[8];       /* The issuer HashedId8 is zero unless the issuer is a digest. */
    uint32_t app_psids[ITS_SEC_MAX_PSIDS];  /* The first appPermissions PSIDs keep their order. */
    /* generationLocation as sent, valid with ITS_SEC_HDR_LOCATION: latitude and longitude in
     * 1/10 microdegree, the elevation in decimetres above -409.5 m. its_sechdr.c judges them. */
    int32_t  gen_lat;
    int32_t  gen_lon;
    uint16_t gen_elev;
    uint16_t n_inline;           /* HashedId3 in inlineP2pcdRequest, capped at 65535. */
    uint8_t  pdu_type;           /* pduFunctionalType, valid with its HDR bit and without X_PDU_BAD. */
    uint8_t  contrib;            /* The ITS_SEC_C_* bits. */
} its_sec_info_t;

/* The curve names of its_sec_sig_t and its_sec_key_t 0 to 4, the same in both languages.
 * Any other value gives NULL. Header-only, so the page modules need nothing linked for it. */
static inline const char *its_sec_alg_name(uint8_t alg)
{
    static const char *const names[] = { "ECDSA NIST P-256", "ECDSA Brainpool P-256",
                                         "ECDSA Brainpool P-384", "ECDSA NIST P-384", "SM2" };
    return alg < sizeof names / sizeof names[0] ? names[alg] : NULL;
}

/* Read the Ieee1609Dot2Data at off, which follows the 4-byte GeoNetworking Basic Header.
 * Return false with valid false if len exceeds 65535 or no version 3 envelope is there. */
bool its_decode_security(const uint8_t *buf, size_t len, size_t off, its_sec_info_t *out);

#ifdef __cplusplus
}
#endif
