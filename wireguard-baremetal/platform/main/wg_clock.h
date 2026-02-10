/**
 * @file wg_clock.h
 * @brief Monotonic clock wrapper — seconds since boot.
 *
 * Wraps esp_timer_get_time() (microseconds) → seconds for the
 * WireGuard timer subsystem.  Both Ada (Timer.Clock.Now) and C
 * (wg_session_timer, wg_task) call wg_clock_now() so all timer
 * comparisons use the same second-resolution timestamps.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Return monotonic seconds since boot.
 *
 * Resolution: 1 second.  This is the time source for all WireGuard
 * timer constants (REKEY_AFTER_TIME, REJECT_AFTER_TIME, etc.).
 */
uint64_t wg_clock_now(void);

#ifdef __cplusplus
}
#endif
