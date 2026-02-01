/**
 * packet_pool.h - C interface for Ada memory pool
 *
 * Provides zero-copy buffer management for network packets.
 * Buffers are pre-allocated and can be efficiently allocated/freed.
 *
 * OWNERSHIP RULES (must be followed by caller):
 *   1. Handles (pointers) must not be aliased/copied
 *   2. No double-free
 *   3. No use-after-free
 */

#ifndef PACKET_POOL_H
#define PACKET_POOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the packet pool.
 * Must be called before any other pool functions.
 */
void packet_pool_init(void);

/**
 * Allocate a buffer from the pool.
 *
 * @return Pointer to the allocated buffer, or NULL if pool exhausted.
 *         Caller receives ownership - must call packet_pool_free() when done.
 */
void* packet_pool_allocate(void);

/**
 * Free a buffer back to the pool.
 *
 * @param buf Pointer obtained from packet_pool_allocate().
 *            Safe to call with NULL (no-op).
 *            After this call, buf must not be used.
 */
void packet_pool_free(void* buf);

/**
 * Get the size of each buffer in the pool.
 *
 * @return Buffer size in bytes.
 */
size_t packet_pool_get_buffer_size(void);

/**
 * Get the total number of buffers in the pool.
 *
 * @return Number of buffers.
 */
size_t packet_pool_get_pool_size(void);

#ifdef __cplusplus
}
#endif

#endif /* PACKET_POOL_H */
