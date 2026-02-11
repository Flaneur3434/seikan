/**
 * packet_pool.h - C interface for Ada RX and TX memory pools
 *
 * Provides zero-copy buffer management for network packets.
 * Two separate pools: TX (outgoing) and RX (incoming).
 * Buffers are pre-allocated and can be efficiently allocated/freed.
 *
 * OWNERSHIP RULES (must be followed by caller):
 *   1. Handles (pointers) must not be aliased/copied
 *   2. No double-free
 *   3. No use-after-free
 */

#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Buffer record returned by pool.
 * Contains index for O(1) free + metadata + aligned data payload.
 *
 * Layout matches Ada's Utils.Memory_Pool.Buffer record exactly
 */
typedef struct {
    int32_t  index;   // Internal pool index; -1 = null
    uint16_t len;     // Valid data length
    uint16_t offset;  // Start offset in data
    uint8_t  data[];  // Flexible array - actual size = packet_pool_get_buffer_size()
} packet_buffer_t;

/* -----------------------------------------------------------------------
 * System Init - Creates semaphores and initializes both pools
 * ----------------------------------------------------------------------- */

/**
 * Initialize both RX and TX pools with statically-allocated semaphores.
 * Must be called once at startup, before any allocate/free or wg_init().
 */
void packet_pool_init(void);

/* -----------------------------------------------------------------------
 * TX Pool - Outgoing packets (handshake initiation, response, data)
 * ----------------------------------------------------------------------- */

/**
 * Initialize the TX packet pool with a pre-created semaphore.
 * Called by packet_pool_init(); not normally called directly.
 *
 * @param sem_handle  Opaque semaphore handle (SemaphoreHandle_t).
 */
void tx_pool_init(void *sem_handle);

/**
 * Allocate a buffer from the TX pool. O(1), thread-safe.
 *
 * @return Pointer to packet_buffer_t, or NULL if pool exhausted.
 *         Caller receives ownership - must call tx_pool_free() when done.
 */
packet_buffer_t* tx_pool_allocate(void);

/**
 * Free a buffer back to the TX pool. O(1), thread-safe.
 *
 * @param buf Pointer obtained from tx_pool_allocate().
 *            Safe to call with NULL (no-op).
 */
void tx_pool_free(packet_buffer_t* buf);

/* -----------------------------------------------------------------------
 * RX Pool - Incoming packets (received from network)
 * ----------------------------------------------------------------------- */

/**
 * Initialize the RX packet pool with a pre-created semaphore.
 * Called by packet_pool_init(); not normally called directly.
 *
 * @param sem_handle  Opaque semaphore handle (SemaphoreHandle_t).
 */
void rx_pool_init(void *sem_handle);

/**
 * Allocate a buffer from the RX pool. O(1), thread-safe.
 *
 * @return Pointer to packet_buffer_t, or NULL if pool exhausted.
 *         Caller receives ownership - must call rx_pool_free() when done.
 */
packet_buffer_t* rx_pool_allocate(void);

/**
 * Free a buffer back to the RX pool. O(1), thread-safe.
 *
 * @param buf Pointer obtained from rx_pool_allocate().
 *            Safe to call with NULL (no-op).
 */
void rx_pool_free(packet_buffer_t* buf);

/* -----------------------------------------------------------------------
 * Query functions
 * ----------------------------------------------------------------------- */

/**
 * Get the size of each buffer in bytes (same for both pools).
 */
size_t packet_pool_get_buffer_size(void);

/**
 * Get the number of buffers per pool (same for both pools).
 */
size_t packet_pool_get_pool_size(void);

#ifdef __cplusplus
}
#endif
