/**
 * @file wg_clock.h
 * @brief Monotonic clock wrapper — seconds since boot.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Return monotonic seconds since boot.
 *
 * Resolution: 1 second.
 *
 * @deprecated Slated for removal once the timer-driven peer-deadline
 * design is fully migrated. Prefer wg_clock_now_ms(). See
 * docs/timer_driven_urgent_queue_design.md.
 */
uint64_t wg_clock_now(void);

/**
 * @brief Return monotonic milliseconds since boot.
 *
 * Resolution: 1 millisecond. Backed by esp_timer_get_time(),
 * monotonic across runtime, never wall-clock.
 *
 * This is the time unit used at the Ada/C boundary in the new
 * timer-driven design.
 */
int64_t wg_clock_now_ms(void);

#ifdef __cplusplus
}
#endif
