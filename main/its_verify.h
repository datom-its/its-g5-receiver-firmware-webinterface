#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "its_security.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The module walks the chain of a received certificate with ECDSA, from the sender over its
 * issuer to a root of the built-in list, which a self-signed certificate has to equal. An
 * issuer nobody sent is taken from its_castore, and its_crl can withdraw any link. */

/* CertificateId.name is longer in theory. The names in use are well below this. */
#define ITS_VERIFY_NAME_MAX 32
/* Certificates above this length are not checked. The longest one seen is 433 bytes. It also
 * sizes the copy an issuer keeps of its own bytes, which the permission check reads. */
#define ITS_VERIFY_CERT_MAX 1024
/* Issuer certificates kept at one time. One authorization authority per root is the rule.
 * Each entry carries its own bytes, so a slot costs about 1.4 kB of the external RAM. */
#ifndef ITS_VERIFY_ISSUERS
#define ITS_VERIFY_ISSUERS 8
#endif

typedef enum
{
    ITS_VERIFY_UNKNOWN     = 0,  /* Not checked yet, or no certificate to check. */
    ITS_VERIFY_CHECKED     = 1,  /* Every signature up to a built-in root matched. */
    ITS_VERIFY_UNCHECKABLE = 2,  /* Something needed for the check is missing. */
    /* A signature in the chain did not match, or the chain breaks a rule of IEEE 1609.2. */
    ITS_VERIFY_INVALID     = 3,
    /* A built-in revocation list names the certificate or one above it in the chain. Every
     * signature may still match, so this verdict beats ITS_VERIFY_CHECKED. */
    ITS_VERIFY_REVOKED     = 4,
} its_verify_state_t;

/* Why a check did not end in ITS_VERIFY_CHECKED. Most reasons say what was missing and go
 * with ITS_VERIFY_UNCHECKABLE. The ones that name a broken rule of IEEE 1609.2 go with
 * ITS_VERIFY_INVALID and say so on their own line. */
typedef enum
{
    ITS_VERIFY_WHY_NONE      = 0,
    ITS_VERIFY_WHY_PARSE     = 1,  /* The certificate bytes could not be read. */
    ITS_VERIFY_WHY_LONG      = 2,  /* The certificate is longer than ITS_VERIFY_CERT_MAX. */
    ITS_VERIFY_WHY_IMPLICIT  = 3,  /* An implicit certificate carries no signature. */
    ITS_VERIFY_WHY_NONCANON  = 4,  /* A key or signature point is not in canonical form. */
    ITS_VERIFY_WHY_ISSUER    = 5,  /* The issuer certificate was never received. */
    ITS_VERIFY_WHY_ROOT      = 6,  /* No built-in root covers this certificate. */
    ITS_VERIFY_WHY_CURVE     = 7,  /* This curve or hash algorithm is not supported. */
    ITS_VERIFY_WHY_CRYPTO    = 8,  /* The crypto library refused the operation. */
    ITS_VERIFY_WHY_CHAIN     = 9,  /* The issuer itself is not trusted. */
    /* 10 was "queue full". A dropped submission writes no entry at all, so that reason could
     * never reach a verdict. its_verify_stats_t.dropped counts the drops instead. */
    /* The certificate, its issuer or the root has expired. ITS_VERIFY_INVALID. */
    ITS_VERIFY_WHY_EXPIRED   = 11,
    ITS_VERIFY_WHY_CLOCK     = 12, /* Without a set clock the validity cannot be judged. */
    /* A certificate served as an issuer without holding certIssuePermissions, or its
     * certIssuePermissions name a chain length below one. Both belong to
     * ITS_VERIFY_INVALID, because the chain breaks a rule and not just a signature. */
    ITS_VERIFY_WHY_NOISSUE   = 13,
    /* The issuer holds certIssuePermissions, but no group of them carries what this
     * certificate claims: a PSID no group names, an eeType that forbids this kind of end
     * entity, or a chain length outside the group's window. ITS_VERIFY_INVALID. */
    ITS_VERIFY_WHY_NOPERM    = 14,
    /* A certificate above this one allows no further certificate below it, so the chain is
     * longer than it was issued for. ITS_VERIFY_INVALID. */
    ITS_VERIFY_WHY_DEEP      = 15,
    /* An issuer names a subjectPermissions alternative this build cannot read, so whether it
     * covers the child stays unknown. IEEE 1609.2 5.2.6 asks for exactly this verdict.
     * ITS_VERIFY_UNCHECKABLE. */
    ITS_VERIFY_WHY_PERMFORM  = 16,
    /* The certificate, its issuer or the root is not valid yet. It has its own reason because
     * the validity column next to it says "not valid yet", which EXPIRED would contradict.
     * ITS_VERIFY_INVALID. */
    ITS_VERIFY_WHY_NOTYET    = 17,
    /* The certificate, its issuer or the root has no validity period (start 0).
     * ITS_VERIFY_INVALID. */
    ITS_VERIFY_WHY_NOPERIOD  = 18,
} its_verify_why_t;

/* Who supplied the issuer certificate. NONE is the zero value, so a result that never found
 * one reads as "unknown" and not as "sent". A certificate that a built-in root signed directly
 * reports ROOT. Then nothing was sent and the built-in authority store was not asked either,
 * because the issuer is on the European trust list. */
typedef enum
{
    ITS_VERIFY_ISSUER_NONE    = 0,  /* No issuer certificate was found at all. */
    ITS_VERIFY_ISSUER_SENT    = 1,  /* The traffic carried the issuer certificate. */
    ITS_VERIFY_ISSUER_BUILTIN = 2,  /* The built-in authority store held it. */
    ITS_VERIFY_ISSUER_ROOT    = 3,  /* The issuer is a root of the built-in EU trust list. */
} its_verify_issuer_from_t;

/* What one certificate check found. issuer_name and root_name come from CertificateId.name of
 * the issuer and of the root. Each is empty when that certificate has no name. */
typedef struct
{
    uint8_t state;                            /* Values come from its_verify_state_t. */
    uint8_t why;                              /* Values come from its_verify_why_t. */
    /* The trust list the root came from, with values from its_trust_env_t, or 0xFF. */
    uint8_t root_env;
    uint8_t chain;                            /* Signatures up to the root, 0 for a root itself. */
    uint8_t issuer_from;                      /* Values come from its_verify_issuer_from_t. */
    /* Certificates the chain may still take below this one, down to and including the end
     * entity. 0 means this one has to be the last, and 255 means no bound is set. It is the
     * smallest window that this certificate or any above it leaves, and it only says something
     * together with ITS_VERIFY_CHECKED. */
    uint8_t room;
    char    issuer_name[ITS_VERIFY_NAME_MAX];
    char    root_name[ITS_VERIFY_NAME_MAX];
} its_verify_result_t;

#ifndef ESP_PLATFORM
/* Host tests only: pin the wall clock, so a fixed set of certificates keeps one verdict. */
void its_verify_host_set_now(uint32_t unix_seconds);
/* Host tests only: forget every learned issuer, so one case cannot decide the next one. */
void its_verify_host_reset(void);
#endif

/* One certificate as the fields needed for a check. Offsets count from the certificate start. */
typedef struct
{
    bool     ok;                 /* The walk reached the end of the certificate. */
    bool     implicit;
    bool     canonical;          /* Every key point is compressed and rSig is x-only. */
    bool     self_signed;
    /* certIssuePermissions is present, which is what lets this certificate sign another. */
    bool     cert_issue;
    bool     app_perms;          /* appPermissions is present: an authorisation certificate. */
    /* certRequestPermissions is present: an enrolment certificate, which an issuer may only
     * produce through a group whose eeType names enrol. */
    bool     cert_request;
    /* A group of certIssuePermissions names a subjectPermissions alternative this build
     * cannot read, so what that group covers stays unknown. */
    bool     issue_unknown;
    uint8_t  issue_groups;       /* PsidGroupPermissions in certIssuePermissions, 0 without. */
    /* The smallest minChainLength of those groups and the chainLengthRange beside it. The
     * ASN.1 defaults are 1 and 0, and a chainLengthRange of -1 means no upper bound. */
    int32_t  issue_min_chain;
    int32_t  issue_chain_range;
    /* The longest chain any group still allows below this certificate, counted down to and
     * including the end entity. INT32_MAX stands for a chainLengthRange of -1. */
    int32_t  issue_max_chain;
    /* Where the three permission fields start inside the certificate, each at its own quantity
     * determinant. The lists stay in the bytes instead of in this struct, because several
     * copies of the struct go on the verify task stack. Length 0 means absent. */
    uint16_t app_off;            /* SequenceOfPsidSsp of appPermissions. */
    uint16_t app_len;
    uint16_t issue_off;          /* SequenceOfPsidGroupPermissions of certIssuePermissions. */
    uint16_t issue_len;
    uint16_t request_off;        /* SequenceOfPsidGroupPermissions of certRequestPermissions. */
    uint16_t request_len;
    uint8_t  hash_alg;           /* 0 for SHA-256, 1 for SHA-384, 2 for SM3, from the issuer. */
    uint8_t  issuer_id[8];       /* Zero when the certificate is self-signed. */
    uint8_t  key_type;           /* Values come from its_sec_key_t. */
    uint8_t  key_form;           /* Point form: 0 x-only, 2 or 3 compressed, 4 uncompressed. */
    uint8_t  sig_type;           /* Values come from its_sec_sig_t. */
    uint16_t tbs_off;            /* ToBeSignedCertificate, the data the signature covers. */
    uint16_t tbs_len;
    uint16_t key_off;            /* The key point without its form byte. */
    uint16_t key_len;            /* 32 or 48 for one coordinate, twice that if uncompressed. */
    uint16_t sig_r_off;          /* rSig without its form byte. sSig starts at sig_s_off. */
    uint16_t sig_s_off;
    uint16_t sig_len;            /* Length of rSig and of sSig, 32 or 48. */
    uint32_t valid_start;        /* Time32: TAI seconds since 2004-01-01 00:00:00 UTC. */
    uint16_t duration;           /* Validity length, counted in duration_unit. */
    uint8_t  duration_unit;      /* Values come from its_sec_duration_t. */
    char     name[ITS_VERIFY_NAME_MAX];
} its_verify_cert_t;

/* Read one CertificateBase. Returns false with ok false when the bytes are not one. */
bool its_verify_parse(const uint8_t *cert, size_t len, its_verify_cert_t *out);

/* Check one certificate and fill in the result. This runs ECDSA, which can take seconds on a
 * Brainpool curve, so only the verify task and host tests call it. */
void its_verify_cert(const uint8_t *cert, size_t len, its_verify_result_t *out);

/* Learn an issuer certificate, for example the requestedCertificate of a HeaderInfo. It is
 * checked against the built-in roots at once and kept in a small table. */
void its_verify_note_issuer(const uint8_t *cert, size_t len);

/* Start the verify task and its queue. Call it once, after its_certcache_init(). */
void its_verify_start(void);

/* One ECDSA check over a finished hash with the key point of a certificate (form byte 2, 3 or 4).
 * Returns 1 for a match, 0 for none and -1 when refused. It takes seconds on Brainpool, so only
 * the verify task and host tests call it. */
int its_verify_ecdsa(uint8_t key_type, uint8_t key_form, const uint8_t *key, size_t key_len,
                     const uint8_t *hash, size_t hash_len, const uint8_t *rs, size_t rs_len);

/* Wake the verify task for a message check of its_msgsig.c. It never blocks, and a waiting chain
 * check still goes first. Does nothing on the host. */
void its_verify_wake(void);

/* Copy `len` certificate bytes into the queue for the verify task. Any task may call it, and it
 * never blocks. It returns false when the queue is full. */
bool its_verify_submit(const uint8_t *cert, size_t len, bool issuer);

typedef struct
{
    uint32_t checked;            /* Certificates that came out trusted. */
    uint32_t unavailable;        /* Certificates that could not be checked. */
    uint32_t invalid;
    uint32_t expired;            /* Checks that failed because a validity period had ended. */
    uint32_t revoked;            /* Certificates a built-in revocation list named. */
    uint32_t dropped;            /* Submissions dropped because the queue was full or busy. */
    uint32_t issuers;            /* Issuer certificates in the table. */
    uint32_t us_last;            /* Time the last check took, in microseconds. */
    uint32_t us_max;
    /* Result of the self test: 0 not run yet, 1 passed, 2 failed. It proves on the device
     * itself that hashing and ECDSA work, without waiting for a certificate to arrive. */
    uint8_t  selftest;
    uint32_t selftest_us;        /* Time that one check took, in microseconds. */
    /* Smallest room ever left on the verify task stack, in bytes, measured after a check.
     * 0 means nothing was measured yet, which is the normal state on a host test. */
    uint32_t stack_left;
} its_verify_stats_t;

void its_verify_stats(its_verify_stats_t *out);

#ifdef __cplusplus
}
#endif
