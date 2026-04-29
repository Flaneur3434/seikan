/**
 * @file wg_clock.h
 * @brief Monotonic clock wrapper — milliseconds since boot.
 */

#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
