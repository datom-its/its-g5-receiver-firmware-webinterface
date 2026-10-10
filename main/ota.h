#pragma once

#include <stdbool.h>
#include <stdint.h>

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

/* Microseconds until that timer rolls back, -1 while it is not armed. */
int64_t ota_rollback_left_us(void);

/* The running slot: confirmed, waiting for confirmation, or anything else (flashed over USB,
 * blank otadata). */
typedef enum { OTA_RUN_OTHER, OTA_RUN_CONFIRMED, OTA_RUN_PENDING } ota_run_t;
ota_run_t ota_running_state(void);

/* An update in the other slot that did not come up, read once in ota_init(). `aborted` is true
 * when it was found unconfirmed at a restart, and false when the timer or 'ota -R' marked it
 * invalid. `acked` means its notice is hidden. */
typedef struct {
    bool present;
    bool aborted;
    bool acked;
    char version[32];
} ota_failed_t;

/* Copies the record and returns present. */
bool ota_failed_get(ota_failed_t *out);

/* Hides the notice for this failed image (stored in NVS). False when NVS fails. */
bool ota_failed_ack(void);

/* Forgets the hidden notice. Call once a new image is in the other slot. */
void ota_failed_forget(void);
