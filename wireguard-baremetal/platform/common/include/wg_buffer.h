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
 * @brief Packet buffer with metadata
 *
 * Layout matches Ada Buffer record for zero-copy interop.
 * All buffers are fixed-size (WG_PACKET_SIZE) but len/offset
 * describe the valid data region.
 *
 * Usage:
 *   RX: Driver writes at data+offset, sets len
 *   TX: Ada builds at data[0], sets len. Driver sends data[0..len-1]
 *   Headroom: Set offset > 0 if driver needs to prepend headers
 */
typedef struct {
    int32_t  index;     /**< Pool index for O(1) free (-1 = invalid) */
    uint16_t len;       /**< Valid data length in bytes */
    uint16_t offset;    /**< Start offset of data (headroom) */
    uint8_t  data[];    /**< Packet data (flexible array member) */
} wg_packet_t;

/**
 * @brief Get data pointer accounting for offset
 */
static inline uint8_t* wg_packet_data(wg_packet_t* pkt) {
    return pkt->data + pkt->offset;
}

/**
 * @brief Buffer descriptor for legacy API compatibility
 */
typedef struct {
    wg_packet_t* pkt;   /**< Packet pointer, NULL if queue empty */
    size_t       len;   /**< Length of valid data (same as pkt->len) */
} wg_buffer_t;

/**
 * @brief Initialize the buffer pool
 *
 * Must be called once before using any other buffer functions.
 * Can be called again to reset all state.
 */
void wg_buf_init(void);

/**
 * @brief Allocate a packet buffer from the pool
 *
 * @return Packet pointer with len=0, offset=0, or NULL if pool exhausted
 *
 * Caller owns the returned buffer and must either:
 * - Free it with wg_buf_free()
 * - Transfer ownership via wg_rx_enqueue() or wg_tx_enqueue()
 */
wg_packet_t* wg_buf_alloc(void);

/**
 * @brief Return a packet buffer to the pool
 *
 * @param pkt Packet pointer (NULL is safely ignored)
 *
 * Clears len/offset and returns buffer to pool.
 */
void wg_buf_free(wg_packet_t* pkt);

/**
 * @brief Get the data capacity of each buffer
 *
 * @return Buffer data capacity in bytes
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
 * @param pkt Packet with len/offset set by driver (ownership transferred)
 *
 * If queue is full, buffer is freed and packet is dropped.
 */
void wg_rx_enqueue(wg_packet_t* pkt);

/**
 * @brief Dequeue a received packet for processing
 *
 * @return Packet pointer, or NULL if queue empty
 *
 * Caller owns the returned buffer and must free it after processing.
 */
wg_packet_t* wg_rx_dequeue(void);

/**
 * @brief Enqueue a packet for transmission
 *
 * @param pkt Packet with len set (ownership transferred)
 *
 * If queue is full, buffer is freed and packet is dropped.
 */
void wg_tx_enqueue(wg_packet_t* pkt);

/**
 * @brief Dequeue a packet for transmission
 *
 * @return Packet pointer, or NULL if queue empty
 *
 * Caller owns the returned buffer and must free it after sending.
 */
wg_packet_t* wg_tx_dequeue(void);

#ifdef __cplusplus
}
#endif

#endif /* WG_BUFFER_H */
