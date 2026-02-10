/**
 * wg_sessions.c - Static binary semaphore for session table mutex
 *
 * Follows the same pattern as packet_pool.c:
 *   - C owns the StaticSemaphore_t backing storage in BSS (zero heap)
 *   - C creates the semaphore via xSemaphoreCreateBinaryStatic
 *   - C passes the opaque handle into Ada's session_init()
 *   - Ada stores the handle and uses it for Take/Give
 *
 * Call wg_session_init() once at startup, after packet_pool_init().
 */
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "wg_sessions.h"

/* Ada-exported function — declared here to avoid header dependency */
extern void session_init(void *sem_handle);

/* Static backing storage — lives in BSS, zero heap cost */
static StaticSemaphore_t s_session_sem_buf;

void wg_session_init(void)
{
    /* Create binary semaphore from static buffer */
    SemaphoreHandle_t sem =
        xSemaphoreCreateBinaryStatic(&s_session_sem_buf);

    /* Binary semaphores start empty; give once so first Take succeeds */
    xSemaphoreGive(sem);

    /* Pass handle into Ada — initializes session table + mutex */
    session_init(sem);
}
