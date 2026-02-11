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
 */
uint64_t wg_clock_now(void);

#ifdef __cplusplus
}
#endif
