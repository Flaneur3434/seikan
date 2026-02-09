/**
 * packet_pool.c - Static binary semaphores for RX/TX memory pools
 *
 * Each pool (RX, TX) gets its own statically-allocated binary semaphore.
 * The semaphore handles are passed into Ada's Memory_Pool.Initialize so
 * each generic instance has its own lock.
 *
 * Call packet_pool_init() once at startup, before any pool operations.
 */
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "packet_pool.h"

/* Static backing storage — lives in BSS, zero heap cost */
static StaticSemaphore_t s_rx_pool_sem_buf;
static StaticSemaphore_t s_tx_pool_sem_buf;

void packet_pool_init(void)
{
    /* Create binary semaphores from static buffers */
    SemaphoreHandle_t rx_sem =
        xSemaphoreCreateBinaryStatic(&s_rx_pool_sem_buf);
    SemaphoreHandle_t tx_sem =
        xSemaphoreCreateBinaryStatic(&s_tx_pool_sem_buf);

    /* Binary semaphores start empty; give once so first Take succeeds */
    xSemaphoreGive(rx_sem);
    xSemaphoreGive(tx_sem);

    /* Pass semaphore handles into Ada pool init */
    rx_pool_init(rx_sem);
    tx_pool_init(tx_sem);
}
