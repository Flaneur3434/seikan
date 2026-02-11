/**
 * @file wg_clock.c
 * @brief Monotonic clock wrapper — seconds since boot.
 */

#include "wg_clock.h"
#include <esp_timer.h>

uint64_t wg_clock_now(void)
{
    // Converts esp_timer_get_time() (microseconds) to seconds.
    return (uint64_t)(esp_timer_get_time() / 1000000ULL);
}
