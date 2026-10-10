#pragma once

#include "esp_http_server.h"

/* The /traffic section with the newest CPM, EVCSN, POIM and RTCMEM per sender (infolog.c), read
 * from RAM only, so it also works without a card. SD builds only, like /traffic itself. */
void web_infolog_emit(httpd_req_t *req);
