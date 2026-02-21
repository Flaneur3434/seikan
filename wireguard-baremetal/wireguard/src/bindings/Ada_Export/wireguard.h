/**
 * @file wireguard.h
 * @brief Minimal C interface to the Ada WireGuard implementation.
 *
 * C is a dumb I/O driver.  All protocol intelligence lives in Ada.
 * C decides WHAT to send; Ada decides HOW.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Max plaintext bytes from a single wg_receive() call.
 *  Packet_Size (1560) - Header (16) - AEAD Tag (16) = 1528.
 */
#define WG_MAX_PLAINTEXT 1528

/**
 * Size of the WireGuard transport data header (type, receiver index, counter).
 * Plaintext from wg_receive_netif() starts at rx_buf->data[WG_TRANSPORT_HEADER_SIZE].
 */
#define WG_TRANSPORT_HEADER_SIZE 16

/**
 * Action codes returned by wg_receive().
 */
typedef enum
{
    WG_ACTION_NONE                  = 0, // Nothing to do (keepalive / HS response processed)
    WG_ACTION_SEND_RESPONSE         = 1, // Call wg_create_response(), sendto(), free
    WG_ACTION_RX_DECRYPTION_SUCCESS = 2, // Decrypted data in pt_out; C decides next step
    WG_ACTION_ERROR                 = 3  // Processing failed
} wg_action_t;

/**
 * Initialize the WireGuard subsystem.
 * @return true on success, false if keys are missing/invalid.
 */
bool wg_init(void);

/**
 * Process an incoming packet — zero-copy netif RX path.
 *
 * Like wg_receive(), but for WG_ACTION_RX_DECRYPTION_SUCCESS Ada does NOT
 * copy plaintext into a C-side stack buffer.  Instead Ada decrypts in-place
 * inside the RX pool buffer and releases that buffer back to C.
 *
 * On WG_ACTION_RX_DECRYPTION_SUCCESS:
 *   - *pt_len  = plaintext byte count (> 0)
 *   - Plaintext is at rx_buf->data[WG_TRANSPORT_HEADER_SIZE .. +pt_len-1]
 *   - C owns the buffer and MUST eventually call rx_pool_free(rx_buf)
 *     (typically via a pbuf_custom callback wired to wg_netif_inject_plaintext).
 *
 * On any other return value:
 *   - Ada has already freed rx_buf.  C must NOT touch it.
 *   - *pt_len = 0.
 *
 * @param[in]  rx_buf   RX pool buffer.  Ownership always transferred to Ada,
 *                      and returned to C only on RX_DECRYPTION_SUCCESS.
 * @param[out] pt_len   Plaintext length.
 * @return Action code.
 */
wg_action_t wg_receive_netif(void *rx_buf, uint16_t *pt_len);

/**
 * Build a handshake initiation (148 bytes).
 * Caller must sendto() then tx_pool_free().
 */
void *wg_create_initiation(uint16_t *out_len);

/**
 * Build a handshake response.
 * Call ONLY after wg_receive() returned WG_ACTION_SEND_RESPONSE.
 * Derives transport keys and activates the new session.
 * Caller must sendto() then tx_pool_free().
 */
void *wg_create_response(uint16_t *out_len);

/**
 * Encrypt payload and return a ready-to-send TX buffer.
 * Pass payload=NULL, payload_len=0 for keepalive (32 bytes on wire).
 * Caller must sendto() then tx_pool_free().
 */
void *wg_send(unsigned int peer, const uint8_t *payload,
              uint16_t payload_len, uint16_t *out_len);

#ifdef __cplusplus
}
#endif
