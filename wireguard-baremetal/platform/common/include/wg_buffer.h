/**
 * @file wg_buffer.h
 * @brief WireGuard buffer pool interface (implemented in Ada/SPARK)
 *
 * This header provides the C interface to the SPARK-proven ring buffer.
 * Ownership semantics are formally verified in the Ada implementation.
 *
 * OWNERSHIP MODEL (formally verified by SPARK):
 *
 * Each buffer has exactly ONE owner at any time:
 *   - FREE_POOL   : Available for allocation
 *   - APPLICATION : Held by C or Ada code
 *   - RX_QUEUE    : Queued for receive processing
 *   - TX_QUEUE    : Queued for transmission
 *
 * Ownership Transitions:
 *   wg_buf_alloc()   : FREE_POOL   -> APPLICATION (caller owns)
 *   wg_buf_free()    : APPLICATION -> FREE_POOL   (caller must own)
 *   wg_rx_enqueue()  : APPLICATION -> RX_QUEUE    (caller transfers)
 *   wg_rx_dequeue()  : RX_QUEUE    -> APPLICATION (caller receives)
 *   wg_tx_enqueue()  : APPLICATION -> TX_QUEUE    (caller transfers)
 *   wg_tx_dequeue()  : TX_QUEUE    -> APPLICATION (caller receives)
 *
 * SAFETY GUARANTEES (proven by SPARK for Ada code, runtime-checked for C):
 *   - Double-free impossible: wg_buf_free() checks ownership
 *   - Use-after-free detectable: operations verify buffer ownership
 *   - No leaks: conservation invariant (all buffers accounted for)
 *
 * C BOUNDARY CHECKS:
 *   All C interface functions perform runtime ownership validation.
 *   Invalid operations are silently ignored (no crash, but may lose data).
 *   In debug builds, ownership violations should be logged.
 *
 * Thread Safety:
 *   - Current implementation is NOT thread-safe
 *   - Use external synchronization if accessing from multiple contexts
 */

#ifndef WG_BUFFER_H
#define WG_BUFFER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Buffer descriptor returned by dequeue operations
 */
typedef struct {
    void*  ptr;  /**< Pointer to buffer data, NULL if queue empty */
    size_t len;  /**< Length of valid data in buffer */
} wg_buffer_t;

/**
 * @brief Initialize the buffer pool
 *
 * Must be called once before using any other buffer functions.
 * Can be called again to reset all state.
 */
void wg_buf_init(void);

/**
 * @brief Allocate a buffer from the pool
 *
 * @param capacity Requested capacity (ignored - all buffers are max size)
 * @return Pointer to buffer, or NULL if pool exhausted
 *
 * Caller owns the returned buffer and must either:
 * - Free it with wg_buf_free()
 * - Transfer ownership via wg_rx_enqueue() or wg_tx_enqueue()
 */
void* wg_buf_alloc(size_t capacity);

/**
 * @brief Return a buffer to the pool
 *
 * @param ptr Buffer pointer (NULL is safely ignored)
 */
void wg_buf_free(void* ptr);

/**
 * @brief Get the capacity of each buffer
 *
 * @return Buffer capacity in bytes
 */
size_t wg_buf_capacity(void);

/**
 * @brief Get number of free buffers available
 *
 * @return Number of buffers available for allocation
 */
size_t wg_buf_free_count(void);

/**
 * @brief Enqueue a received packet for processing
 *
 * @param ptr Buffer containing received data (ownership transferred)
 * @param len Length of received data
 *
 * If queue is full, buffer is freed and packet is dropped.
 */
void wg_rx_enqueue(void* ptr, size_t len);

/**
 * @brief Dequeue a received packet for processing
 *
 * @return Buffer descriptor (ptr is NULL if queue empty)
 *
 * Caller owns the returned buffer and must free it after processing.
 */
wg_buffer_t wg_rx_dequeue(void);

/**
 * @brief Enqueue a packet for transmission
 *
 * @param ptr Buffer containing data to transmit (ownership transferred)
 * @param len Length of data to transmit
 *
 * If queue is full, buffer is freed and packet is dropped.
 */
void wg_tx_enqueue(void* ptr, size_t len);

/**
 * @brief Dequeue a packet for transmission
 *
 * @return Buffer descriptor (ptr is NULL if queue empty)
 *
 * Caller owns the returned buffer and must free it after sending.
 */
wg_buffer_t wg_tx_dequeue(void);

#ifdef __cplusplus
}
#endif

#endif /* WG_BUFFER_H */
