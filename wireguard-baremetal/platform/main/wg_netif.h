#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "packet_pool.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Initialise wg0 netif and bind the outer UDP PCB. */
bool wg_netif_init(void);

/** Start the wg0 tunnel (currently a no-op, reserved for future use). */
bool wg_netif_start(void);

/**
 * Transmit an encrypted WireGuard packet via the outer UDP PCB.
 *
 * Uses PBUF_REF/pbuf_custom — zero-copy.  On success, ownership of
 * tx_buf is transferred to the pbuf_custom callback; caller MUST NOT
 * free tx_buf.  On failure caller retains ownership.
 */
bool wg_netif_send_outer(packet_buffer_t *tx_buf,
                         uint16_t tx_len,
                         const struct sockaddr_in *peer);

/**
 * Inject a decrypted plaintext IP packet into the lwIP stack via wg0.
 *
 * Uses PBUF_REF/pbuf_custom — zero-copy.  On success, ownership of
 * rx_buf is transferred to the pbuf_custom callback (-> rx_pool_free);
 * caller MUST NOT free rx_buf.  On failure caller retains ownership.
 *
 * @param rx_buf    RX pool buffer returned by wg_receive_netif().
 * @param pt_offset Offset of plaintext inside rx_buf->data
 *                  (WG_TRANSPORT_HEADER_SIZE = 16).
 * @param pt_len    Plaintext byte count.
 */
bool wg_netif_inject_plaintext(packet_buffer_t *rx_buf,
                               uint16_t pt_offset,
                               uint16_t pt_len);

#ifdef __cplusplus
}
#endif
