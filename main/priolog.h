#pragma once

#include <stdbool.h>
#include <stdint.h>

#include "msg_extra.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Priority requests of buses and trams (SREM) and the answers of the traffic light (SSEM),
 * kept on the card. Own module, not part of ptlog: a passage there belongs to a vehicle and
 * is keyed by station id, line and course, while an answer here belongs to the INTERSECTION
 * and is keyed by its region and id. One SREM carries up to 32 requests and one SSEM answers
 * up to 32 requesters. Up to MSG_PRIO_ITEMS of them become one row each, while a passage is
 * always one row. */

/* One request or one answer, flattened to what a reader looks at. */
typedef struct {
    uint32_t seconds;
    uint32_t station_id;     /* the sender: the vehicle for a request, the light for an answer */
    uint32_t requester_id;   /* SSEM: who the answer is for. 0 when not sent. */
    uint16_t region;         /* IntersectionID. region is 0 when the message left it out. */
    uint16_t id;
    uint8_t  kind;           /* 9 = request (SREM), 10 = answer (SSEM) */
    uint8_t  request_id;
    uint8_t  code;           /* PriorityRequestType, or PrioritizationResponseStatus */
    uint8_t  role;           /* BasicVehicleRole of the requester, PRIO_NO_ROLE when not sent */
    uint8_t  in_kind;        /* ITS_SREM_AP_*, ITS_SREM_AP_NONE when not sent */
    uint8_t  out_kind;
    uint16_t in_val;
    uint16_t out_val;
    char     name[ITS_SREM_NAME_LEN];    /* DescriptiveName, "" when not sent */
    char     route[ITS_SREM_ROUTE_LEN];  /* RouteName, "" when not sent */
} prio_row_t;

/* 0xFF, not 0: role 0 is a valid BasicVehicleRole ("default"). */
#define PRIO_NO_ROLE 0xFF

/* Rows kept on the card. At ~70 bytes a row that is ~140 KB, the same order as the
 * passage log. In the header because a caller with a smaller array only sees fewer rows. */
#define PRIO_KEEP 2000

void priolog_init(void);

/* One decoded SREM or SSEM. Does nothing when the summary holds neither. */
void priolog_note(uint32_t seconds, uint32_t station_id, const msg_prio_t *p);

/* Appends what is waiting and trims the file. A delete that waited for the card goes first.
 * Called from the sysmon tick and from sysmon_flush_persistent. */
void priolog_tick(void);

/* Reads up to `max` newest rows, newest first. Returns how many were written. */
int priolog_read(prio_row_t *out, int max);

/* Rows the queue could not take: it was full, as with a slow or missing card, or its lock
 * stayed busy for 50 ms. */
uint32_t priolog_dropped(void);

/* Drops the queue at once, and the file too when the card is free within 2 s. Otherwise the
 * next tick or the restart flush deletes it. The readers show nothing meanwhile. */
void priolog_clear(void);

#ifdef __cplusplus
}
#endif
