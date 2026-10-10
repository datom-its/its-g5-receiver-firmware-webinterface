#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "its_decode.h"
#include "its_security.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The signature header of one message, judged against IEEE 1609.2 and the ETSI profile of
 * TS 103 097 V2.2.1. Every value is the sender's own claim: nothing here is verified. */

/* Where the header says the message was signed. */
typedef enum
{
    SEC_LOC_NONE    = 0,  /* no generationLocation */
    SEC_LOC_SAME    = 1,  /* exactly the sender's own position in the frame */
    SEC_LOC_OTHER   = 2,  /* somewhere else; has_ref says whether a distance can be given */
    SEC_LOC_UNKNOWN = 3,  /* latitude 900000001 or longitude 1800000001: the sender did not know */
    SEC_LOC_RANGE   = 4,  /* outside the ranges of IEEE 1609.2; SEC_DEV_RANGE is set */
} sec_loc_t;

/* Why the header does not follow the standard. its_sechdr.c names the clause of each rule. */
#define SEC_DEV_TIME    0x0001  /* no generationTime */
#define SEC_DEV_LOC     0x0002  /* a DENM without generationLocation */
#define SEC_DEV_RANGE   0x0004  /* latitude or longitude outside its type */
#define SEC_DEV_ORDER   0x0008  /* expiryTime not after generationTime */
#define SEC_DEV_FORBID  0x0010  /* a part the profile does not allow here; `forbid` names it */
#define SEC_DEV_ALG     0x0020  /* a hash other than SHA-256/384, or a signature that is no ECDSA */
#define SEC_DEV_SIGNER  0x0040  /* signer self or an unknown alternative */
#define SEC_DEV_DIGEST  0x0080  /* a DENM signed by digest */
#define SEC_DEV_CHAIN   0x0100  /* a certificate list that does not hold exactly one */
#define SEC_DEV_PSID    0x0200  /* the PSID is not the ITS-AID of the message type */
#define SEC_DEV_ALL     0x03FF

/* forbid holds the ITS_SEC_HDR_* bits of header parts, plus these two parts of the payload. */
/* extDataHash beside the data, as the only content of a CAM or DENM, or not SHA-256 */
#define SEC_FORBID_EXT_HASH  0x0400
#define SEC_FORBID_OMITTED   0x0800  /* SignedDataPayload.omitted */

typedef struct
{
    /* Unix microseconds; UINT64_MAX when the Time64 lies too far ahead to convert. */
    uint64_t gen_us;          /* generationTime, with has_gen */
    uint64_t exp_us;          /* expiryTime, with has_exp */
    uint64_t rx_us;           /* reception, with has_rx */
    int32_t  lat_e7, lon_e7;  /* generationLocation as sent, 1/10 microdegree */
    int32_t  ref_lat_e7, ref_lon_e7;  /* the sender's own position in the frame, with has_ref */
    int32_t  msg_alt_cm;      /* CAM, DENM event or MAPEM refPoint altitude, with has_msg_alt */
    uint32_t want_psid;       /* the ITS-AID of this message type, with SEC_DEV_PSID */
    uint16_t hdr;             /* ITS_SEC_HDR_* */
    uint16_t forbid;          /* ITS_SEC_HDR_* and SEC_FORBID_* of parts not allowed here */
    uint16_t dev;             /* SEC_DEV_* */
    uint16_t elev;            /* Elevation as sent: decimetres above -409.5 m */
    uint16_t n_inline;        /* HashedId3 in inlineP2pcdRequest */
    uint8_t  loc;             /* sec_loc_t */
    uint8_t  sig_type;        /* its_sec_sig_t of the message, 0xFF when the walk did not reach it */
    uint8_t  key_type;        /* its_sec_key_t of a certificate in the frame, 0xFF without one */
    uint8_t  hash_id;         /* hashId: 0 SHA-256, 1 SHA-384, 2 SM3, 255 unknown */
    uint8_t  pdu_type;        /* pduFunctionalType, with its HDR bit and without ITS_SEC_X_PDU_BAD */
    uint8_t  xflags;          /* ITS_SEC_X_* */
    uint8_t  contrib;         /* ITS_SEC_C_* */
    uint8_t  cert_count;      /* certificates the signer carried, 0 for a digest */
    /* read is false for every frame without a signed envelope whose header was read, and nothing
     * else counts then. 0 is a real time, place and algorithm, hence the has_* flags. */
    bool     read;
    bool     has_gen, has_exp, has_rx, has_ref, has_msg_alt;
    bool     has_data;        /* ITS_SEC_HAVE_PAYLOAD: the message itself came, not only its hash */
} its_sechdr_t;               /* 80 B on riscv32 (riscv32-esp-elf-gcc 15.2) */

/* What the headers of one roadside unit said, for inventory.c and senders.csv. Zero is empty. */
#define SEC_UNIT_SIG   0x01
#define SEC_UNIT_KEY   0x02
#define SEC_UNIT_HASH  0x04
#define SEC_UNIT_ELEV  0x08
typedef struct
{
    uint32_t dev_frames;      /* frames with any SEC_DEV_* bit, saturating */
    uint16_t dev_mask;        /* every SEC_DEV_* bit seen */
    uint16_t elev;            /* Elevation of the last header with a location */
    uint8_t  sig_type;        /* last message signature */
    uint8_t  key_type;        /* last certificate key a frame carried */
    uint8_t  hash_id;         /* last hashId */
    uint8_t  has;             /* SEC_UNIT_* */
} its_sechdr_unit_t;          /* 12 B */

/* Judge the header its_decode_security read into `s`, for the frame its_decode_frame read into
 * `d`. Clears `h` first. No floating point: it runs on the 4 KB receive task. */
void its_sechdr_fill(its_sechdr_t *h, const its_sec_info_t *s, const its_decoded_t *d);

/* The reception stamp of the frame. has_rx stays false for a `sec` below EVENTS_CLOCK_MIN,
 * which counts from boot, for a `usec` above 999999, and for a header that was not read. */
void its_sechdr_note_rx(its_sechdr_t *h, uint32_t sec, uint32_t usec);

/* The ITS-AID TS 102 965 V2.4.1 Annex A assigns to a message kind (its_msg_kind). Returns 0
 * for a kind with no ITS-AID or more than one, such as EVCSN and POIM. */
uint32_t its_sechdr_its_aid(uint8_t kind);

/* Fold one message into the summary of its sender. Nothing happens without h->read. */
void its_sechdr_unit_fold(its_sechdr_unit_t *u, const its_sechdr_t *h);

#ifdef __cplusplus
}
#endif
