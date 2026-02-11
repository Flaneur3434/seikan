/**
 * @file wg_mutex.c 
 * @brief FreeRTOS binary semaphore lock/unlock wrappers
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
