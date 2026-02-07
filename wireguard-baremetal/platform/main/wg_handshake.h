/**
 * @file wg_handshake.h
 * @brief C interface to Ada WireGuard handshake operations.
 *
 * These functions are implemented in Ada (wg_handshake.adb) and exported
 * with C convention. They orchestrate the Noise IK handshake using the
 * shared packet pool for zero-copy buffer management.
 *
 * Typical initiator flow:
 *   1. wg_init()
 *   2. buf = wg_create_initiation(&len)   → send buf->data[0..len-1]
 *   3. receive response into pool buffer
 *   4. wg_handle_response(rx_buf)         → handshake complete
 *
 * Typical responder flow:
 *   1. wg_init()
 *   2. receive initiation into pool buffer
 *   3. buf = wg_handle_initiation(rx_buf, &len)  → send buf->data[0..len-1]
 *   4. handshake complete after send
 */

#ifndef WG_HANDSHAKE_H
#define WG_HANDSHAKE_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the handshake subsystem.
 * Loads keys from sdkconfig, computes derived keys, initializes
 * the packet pool. Must be called once before any handshake ops.
 *
 * @return true on success, false if keys are missing/invalid.
 */
bool wg_init(void);

/**
 * Create a handshake initiation message (Initiator TX).
 *
 * Allocates a pool buffer, builds the 148-byte initiation message,
 * and returns the buffer for C to transmit.
 *
 * @param[out] out_len  Message length (148 on success, 0 on failure).
 * @return  Address of wg_packet_t on success, NULL on failure.
 *          Caller must free via packet_pool_free().
 */
void *wg_create_initiation(uint16_t *out_len);

/**
 * Handle a received initiation and create a response (Responder RX+TX).
 *
 * Processes the received initiation, creates a 92-byte response in a
 * new pool buffer. The RX buffer is freed internally.
 *
 * @param[in]  rx_buf   Address of wg_packet_t containing the initiation.
 *                      Ownership is transferred to Ada (freed internally).
 * @param[out] out_len  Response length (92 on success, 0 on failure).
 * @return  Address of wg_packet_t containing the response, or NULL.
 *          Caller must free via packet_pool_free().
 */
void *wg_handle_initiation(void *rx_buf, uint16_t *out_len);

/**
 * Handle a received response to complete the handshake (Initiator RX).
 *
 * Processes the 92-byte response and completes the handshake.
 * The RX buffer is freed internally.
 *
 * @param[in] rx_buf  Address of wg_packet_t containing the response.
 *                    Ownership is transferred to Ada (freed internally).
 * @return true if handshake completed successfully.
 */
bool wg_handle_response(void *rx_buf);

#ifdef __cplusplus
}
#endif

#endif /* WG_HANDSHAKE_H */
