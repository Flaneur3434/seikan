/**
 * packet_pool.h - C interface for Ada memory pool
 *
 * Provides zero-copy buffer management for network packets.
 * Buffers are pre-allocated and can be efficiently allocated/freed.
 */

#ifndef PACKET_POOL_H
#define PACKET_POOL_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Buffer handle type. Use packet_pool_allocate() to obtain. */
typedef int32_t packet_buffer_handle_t;

/** Invalid handle constant */
#define PACKET_BUFFER_INVALID (-1)

/**
 * Initialize the packet pool.
 * Must be called before any other pool functions.
 */
void packet_pool_init(void);

/**
 * Allocate a buffer from the pool.
 *
 * @return Handle to the allocated buffer, or PACKET_BUFFER_INVALID if pool exhausted.
 */
packet_buffer_handle_t packet_pool_allocate(void);

/**
 * Free a buffer back to the pool.
 *
 * @param handle Handle obtained from packet_pool_allocate().
 *               Safe to call with PACKET_BUFFER_INVALID (no-op).
 */
void packet_pool_free(packet_buffer_handle_t handle);

/**
 * Get the memory address of a buffer.
 *
 * @param handle Handle obtained from packet_pool_allocate().
 * @return Pointer to the buffer memory, or NULL if handle is invalid.
 */
void* packet_pool_get_address(packet_buffer_handle_t handle);

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
