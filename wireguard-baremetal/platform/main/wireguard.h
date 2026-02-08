/**
 * @file wireguard.h
 * @brief Minimal C interface to the Ada WireGuard implementation.
 *
 * C is a dumb I/O driver. All protocol intelligence lives in Ada.
 *
 * Typical loop:
 *   wg_init();
 *   while (1) {
 *       pkt = rx_pool_allocate();
 *       len = recvfrom(sock, pkt->data, ...);
 *       pkt->len = len;
 *       action = wg_receive(pkt, &tx_pkt, &tx_len);
 *       if (action == WG_ACTION_SEND_RESPONSE ||
 *           action == WG_ACTION_SEND_TRANSPORT) {
 *           sendto(sock, tx_pkt->data, tx_len, ...);
 *           tx_pool_free(tx_pkt);
 *       }
 *   }
 */

#ifndef WIREGUARD_H
#define WIREGUARD_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Action codes returned by wg_receive().
 * Tells C what to do with the (optional) TX buffer.
 */
typedef enum {
    WG_ACTION_NONE           = 0,  /**< Processed internally, nothing to send */
    WG_ACTION_SEND_RESPONSE  = 1,  /**< Handshake reply ready — sendto() then free */
    WG_ACTION_SEND_TRANSPORT = 2,  /**< Encrypted data ready  — sendto() then free */
    WG_ACTION_ERROR          = 3   /**< Processing failed, nothing to send */
} wg_action_t;

/**
 * Initialize the WireGuard subsystem.
 *
 * Loads keys, initializes packet pools, resets protocol state.
 * Must be called once before wg_receive / wg_create_initiation.
 *
 * @return true on success, false if keys are missing/invalid.
 */
bool wg_init(void);

/**
 * Process an incoming packet.
 *
 * Ada takes ownership of rx_buf (freed internally — do NOT free in C).
 * Ada inspects the message type, dispatches to handshake or transport,
 * and optionally returns a TX buffer for C to send.
 *
 * @param[in]  rx_buf   RX pool buffer received from the network.
 *                      Ownership transferred to Ada.
 * @param[out] tx_buf   On SEND actions: pool buffer to sendto(), then free.
 *                      On NONE/ERROR: NULL.
 * @param[out] tx_len   Number of valid bytes in tx_buf.
 * @return Action code telling C what to do.
 */
wg_action_t wg_receive(void *rx_buf, void **tx_buf, uint16_t *tx_len);

/**
 * Trigger an ESP32-initiated handshake.
 *
 * Allocates a TX pool buffer and builds a 148-byte initiation message.
 * Caller must sendto() and then free via tx_pool_free().
 *
 * @param[out] out_len  Message length (148 on success, 0 on failure).
 * @return Pool buffer on success, NULL on failure.
 */
void *wg_create_initiation(uint16_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* WIREGUARD_H */
