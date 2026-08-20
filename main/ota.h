#pragma once

#include <stdbool.h>

void register_ota_cmd(void);
void ota_init(void);

/* Marks the currently running app as valid and cancels the pending rollback.
 * Returns true on success. Safe to call even if no verification is pending. */
bool ota_confirm(void);

/* True if the running app was booted from an OTA update and has not yet been
 * confirmed (i.e. a rollback is still pending). */
bool ota_is_pending_verify(void);

/* True while the automatic 30-minute rollback timer is actually running. */
bool ota_rollback_armed(void);
