/**
 * wg_mutex_api.h - Platform lock/unlock API
 *
 * Thin C wrappers around OS locking primitives. On ESP-IDF these wrap
 * FreeRTOS binary semaphore macros; on POSIX they wrap pthread_mutex.
 *
 * Semaphore creation/ownership lives in packet_pool.c (static allocation).
 * This header just exposes the lock/unlock operations that Ada imports.
 */
#pragma once

#include <stdint.h>

/**
 * Acquire lock, blocking indefinitely.
 * @param handle  Opaque lock handle (SemaphoreHandle_t on FreeRTOS,
 *                pthread_mutex_t* on POSIX).
 */
void wg_mutex_lock(void *handle);

/**
 * Release lock.
 * @param handle  Same handle passed to wg_mutex_lock.
 */
void wg_mutex_unlock(void *handle);
