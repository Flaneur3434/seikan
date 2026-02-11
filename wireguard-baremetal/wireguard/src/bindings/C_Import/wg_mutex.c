/**
 * wg_mutex.c - FreeRTOS binary semaphore lock/unlock wrappers
 *
 * xSemaphoreTake and xSemaphoreGive are preprocessor macros on
 * ESP-IDF, so Ada cannot Import them directly. These wrappers
 * provide real function symbols.
 *
 * Semaphore creation/ownership lives in packet_pool.c.
 */
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "wg_mutex.h"

void wg_mutex_lock(void *handle)
{
    xSemaphoreTake((SemaphoreHandle_t)handle, portMAX_DELAY);
}

void wg_mutex_unlock(void *handle)
{
    xSemaphoreGive((SemaphoreHandle_t)handle);
}
