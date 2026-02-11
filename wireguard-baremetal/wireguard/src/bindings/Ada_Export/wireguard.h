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
 *  Packet_Size (256) - Header (16) - AEAD Tag (16) = 224. 
 */
#define WG_MAX_PLAINTEXT 224

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
 * Process an incoming packet (RX only - never allocates TX buffers).
 *
 * Ada takes ownership of rx_buf (freed internally — do NOT free in C).
 *
 * @param[in]  rx_buf   RX pool buffer.  Ownership transferred to Ada.
 * @param[out] pt_out   Buffer for decrypted plaintext (>= WG_MAX_PLAINTEXT).
 *                      Written only when action == SEND_TRANSPORT.
 * @param[out] pt_len   Plaintext length.  0 unless action == SEND_TRANSPORT.
 * @return Action code telling C what to do next.
 */
wg_action_t wg_receive(void *rx_buf, uint8_t *pt_out, uint16_t *pt_len);

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
