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
 *
 * DESIGN:
 *   packet_buffer_t contains both an index (for O(1) free) and the data.
 *   C code receives pointer to the whole struct, uses ->data for packet I/O.
 *   Both allocate and free are O(1) operations.
 */

#ifndef PACKET_POOL_H
#define PACKET_POOL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Buffer record returned by pool.
 * Contains index for O(1) free + metadata + aligned data payload.
 *
 * Layout matches Ada's Utils.Memory_Pool.Buffer record exactly:
 *   int32_t  index   (4 bytes) — pool index, -1 = null
 *   uint16_t len     (2 bytes) — valid data length
 *   uint16_t offset  (2 bytes) — start offset in data (headroom)
 *   uint8_t  data[]  — packet payload
 */
typedef struct {
    int32_t  index;   /* Internal pool index; -1 = null */
    uint16_t len;     /* Valid data length */
    uint16_t offset;  /* Start offset in data (headroom) */
    uint8_t  data[];  /* Flexible array - actual size = packet_pool_get_buffer_size() */
} packet_buffer_t;

/* -----------------------------------------------------------------------
 * TX Pool - Outgoing packets (handshake initiation, response, data)
 * ----------------------------------------------------------------------- */

/**
 * Initialize the TX packet pool.
 * Must be called before any other tx_pool functions.
 */
void tx_pool_init(void);

/**
 * Allocate a buffer from the TX pool. O(1) operation.
 *
 * @return Pointer to packet_buffer_t, or NULL if pool exhausted.
 *         Caller receives ownership - must call tx_pool_free() when done.
 */
packet_buffer_t* tx_pool_allocate(void);

/**
 * Free a buffer back to the TX pool. O(1) operation.
 *
 * @param buf Pointer obtained from tx_pool_allocate().
 *            Safe to call with NULL (no-op).
 */
void tx_pool_free(packet_buffer_t* buf);

/* -----------------------------------------------------------------------
 * RX Pool - Incoming packets (received from network)
 * ----------------------------------------------------------------------- */

/**
 * Initialize the RX packet pool.
 * Must be called before any other rx_pool functions.
 */
void rx_pool_init(void);

/**
 * Allocate a buffer from the RX pool. O(1) operation.
 *
 * @return Pointer to packet_buffer_t, or NULL if pool exhausted.
 *         Caller receives ownership - must call rx_pool_free() when done.
 */
packet_buffer_t* rx_pool_allocate(void);

/**
 * Free a buffer back to the RX pool. O(1) operation.
 *
 * @param buf Pointer obtained from rx_pool_allocate().
 *            Safe to call with NULL (no-op).
 */
void rx_pool_free(packet_buffer_t* buf);

/* -----------------------------------------------------------------------
 * Shared queries
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

#endif /* PACKET_POOL_H */
