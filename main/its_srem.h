#pragma once

/* This module decodes SREM (messageId 9) and SSEM (messageId 10) of ETSI TS 103 301, whose
 * bodies are the SignalRequestMessage and SignalStatusMessage of its DSRC module, in UPER. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ITS_SREM_MAX_REQ     4    /* The message may carry up to 32 requests. */
#define ITS_SREM_NAME_LEN    24   /* DescriptiveName has up to 63 characters. */
#define ITS_SREM_ROUTE_LEN   16
#define ITS_SSEM_MAX_STATUS  2    /* The message may carry up to 32 SignalStatus entries. */
#define ITS_SSEM_MAX_PKG     8    /* This limit counts the packages of all kept entries together. */

/* These are the VehicleID alternatives. An entityID keeps its 4 TemporaryID octets as a
 * big-endian number, and ITS_SREM_ID_NONE only occurs in an SSEM package without requester. */
#define ITS_SREM_ID_NONE     0
#define ITS_SREM_ID_ENTITY   1
#define ITS_SREM_ID_STATION  2

/* These are the IntersectionAccessPoint alternatives. NONE means the optional field was not
 * sent, and EXT means an extension alternative that was skipped, with value 0. */
#define ITS_SREM_AP_NONE        0
#define ITS_SREM_AP_LANE        1
#define ITS_SREM_AP_APPROACH    2
#define ITS_SREM_AP_CONNECTION  3
#define ITS_SREM_AP_EXT         4

/* This value stands in for an ENUMERATED extension value that the decoder does not know. */
#define ITS_SREM_ENUM_EXT  0xFF

typedef struct {
    uint8_t kind;    /* This is one of ITS_SREM_AP_*. */
    uint8_t value;   /* This holds the LaneID, ApproachID or LaneConnectionID. */
} its_srem_access_t;

/* Each entry holds one SignalRequestPackage. The presence flags are 0 or 1 and share a word
 * with the minute. */
typedef struct {
    uint16_t region;                 /* It is only valid when has_region is set. */
    uint16_t id;
    unsigned minute       : 20;      /* MinuteOfTheYear fits in 20 bits. */
    unsigned has_region   : 1;
    unsigned has_minute   : 1;
    unsigned has_second   : 1;
    unsigned has_duration : 1;
    uint16_t second;                 /* DSecond counts milliseconds. */
    uint16_t duration;
    uint8_t  request_id;
    uint8_t  request_type;           /* It is a PriorityRequestType or ITS_SREM_ENUM_EXT. */
    its_srem_access_t inbound;
    its_srem_access_t outbound;      /* The kind is ITS_SREM_AP_NONE when it was not sent. */
} its_srem_request_t;

/* Names are cut to the buffer and always terminated, and "" means not sent. Control
 * characters become '?', so a NUL inside a name cannot shorten it unnoticed. */
typedef struct {
    bool     valid;
    bool     truncated;              /* More than ITS_SREM_MAX_REQ requests were sent. */
    bool     has_seq;
    bool     has_type;               /* RequestorType was sent, so role is valid. */
    bool     has_hpms;
    uint8_t  sequence_number;        /* It is SignalRequestMessage.sequenceNumber. */
    uint8_t  requestor_kind;         /* It is ITS_SREM_ID_ENTITY or ITS_SREM_ID_STATION. */
    /* It is a BasicVehicleRole including tram (23), or ITS_SREM_ENUM_EXT. */
    uint8_t  role;
    uint8_t  hpms_type;              /* It is a VehicleType or ITS_SREM_ENUM_EXT. */
    uint8_t  n_requests;
    uint32_t station_id;             /* It is ItsPduHeader.stationId. */
    uint32_t requestor_id;
    char     name[ITS_SREM_NAME_LEN];
    char     route_name[ITS_SREM_ROUTE_LEN];
    its_srem_request_t req[ITS_SREM_MAX_REQ];
} its_srem_t;

/* Each entry holds one SignalStatus, and its kept packages follow those of the previous
 * entry in pkg[]. */
typedef struct {
    uint16_t region;                 /* It is only valid when has_region is set. */
    uint16_t id;
    uint8_t  sequence_number;
    uint8_t  n_packages;
    bool     has_region;
} its_ssem_status_t;

/* Each entry holds one SignalStatusPackage. Requester fields are valid unless requester_kind is
 * ITS_SREM_ID_NONE. The role needs has_role. It comes from the role field, or from
 * typeData.role when that field was not sent. */
typedef struct {
    uint32_t requester_id;
    unsigned minute         : 20;
    unsigned requester_kind : 2;     /* This is one of ITS_SREM_ID_*. */
    unsigned has_role       : 1;
    unsigned has_minute     : 1;
    unsigned has_second     : 1;
    unsigned has_duration   : 1;
    uint16_t second;
    uint16_t duration;
    its_srem_access_t inbound;
    its_srem_access_t outbound;      /* The kind is ITS_SREM_AP_NONE when it was not sent. */
    uint8_t  request_id;
    uint8_t  requester_seq;          /* It is SignalRequesterInfo.sequenceNumber. */
    /* It is a BasicVehicleRole including tram (23), or ITS_SREM_ENUM_EXT. */
    uint8_t  role;
    uint8_t  status;                 /* a PrioritizationResponseStatus or ITS_SREM_ENUM_EXT */
} its_ssem_package_t;

typedef struct {
    bool     valid;
    bool     truncated;              /* More entries or packages were sent than are kept. */
    uint8_t  n_status;
    uint8_t  n_packages;
    uint32_t station_id;             /* It is ItsPduHeader.stationId. */
    its_ssem_status_t  status[ITS_SSEM_MAX_STATUS];
    its_ssem_package_t pkg[ITS_SSEM_MAX_PKG];
} its_ssem_t;

/* `pdu` starts at the ItsPduHeader, and bytes behind the encoding are ignored. On false the
 * whole struct is zero, so valid is false. */
bool its_decode_srem(const uint8_t *pdu, size_t len, its_srem_t *out);
bool its_decode_ssem(const uint8_t *pdu, size_t len, its_ssem_t *out);

#ifdef __cplusplus
}
#endif
