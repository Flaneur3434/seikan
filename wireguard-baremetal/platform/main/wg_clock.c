/**
 * @file wg_clock.c
 * @brief Monotonic clock wrapper — milliseconds since boot.
 */

#include "wg_clock.h"
#include <esp_timer.h>

int64_t wg_clock_now_ms(void)
{
    // Converts esp_timer_get_time() (microseconds) to milliseconds.
    // esp_timer_get_time() returns int64_t microseconds since boot.
    return esp_timer_get_time() / 1000;
}
