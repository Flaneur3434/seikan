/**
 * @file wg_clock.c
 * @brief Monotonic clock wrapper — seconds since boot.
 *
 * Converts esp_timer_get_time() (microseconds) to seconds.
 * This is the single time source for WireGuard timers on ESP-IDF.
 *
 * The Ada side imports this as "wg_clock_now" via Timer.Platform.
 */

#include "wg_clock.h"
#include <esp_timer.h>

uint64_t wg_clock_now(void)
{
    return (uint64_t)(esp_timer_get_time() / 1000000ULL);
}
