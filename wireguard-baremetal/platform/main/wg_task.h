/**
 * @file wg_task.h
 * @brief WireGuard protocol task — crypto + protocol logic thread.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include "packet_pool.h"
#include "wireguard.h"

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------
 * Queue message types
 * -------------------------------------------------------------------- */

/* IO thread -> WG task: incoming packet to process */
typedef struct {
    packet_buffer_t *rx_buf;  // RX pool buffer (ownership transferred)
    struct sockaddr_in peer;  // Sender address for reply routing
} wg_rx_msg_t;

/* lwIP wg0 output -> WG task: inner plaintext packet to encrypt */
typedef struct {
    packet_buffer_t *buf;     // TX pool buffer; plaintext at buf->data[16..16+pt_len-1]
    uint16_t         pt_len;  // Plaintext byte count (NOT including the 16-byte headroom)
    uint16_t         peer_idx; // 1-based peer index from AllowedIPs lookup (0 = unknown)
} wg_inner_msg_t;

/* --------------------------------------------------------------------
 * Queue handles (created by wg_task, used by udp_server)
 * -------------------------------------------------------------------- */

/* Queue: IO -> WG (rx packets + initiation triggers) */
extern QueueHandle_t g_wg_rx_queue;

/* Queue: lwIP wg0 output -> WG (inner plaintext to encrypt) */
extern QueueHandle_t g_wg_inner_queue;

/* --------------------------------------------------------------------
 * API
 * -------------------------------------------------------------------- */

/**
 * Initialize WireGuard subsystem resources.
 *
 * Creates RX/TX queues (static), initializes packet pools and the
 * Ada/SPARK session + crypto subsystem.  Does NOT spawn any tasks.
 *
 * Must be called before wg_task_start() and before any other WG API.
 *
 * @return true on success, false if wg_init() failed.
 */
bool wg_task_init(void);

/**
 * Spawn the WireGuard protocol task.
 *
 * Must be called after wg_task_init() and after all other resources
 * (timer queue, etc.) are initialized.
 *
 * @return true on success, false if xTaskCreate failed.
 */
bool wg_task_start(void);

/**
 * Get the last known endpoint for a peer.
 *
 * Endpoint is learned only from cryptographically verified packets.
 *
 * @param peer Peer index (1..WG_MAX_PEERS)
 * @param out  Destination sockaddr_in (output)
 * @return true when endpoint exists, false otherwise.
 */
bool wg_task_get_peer_endpoint(unsigned int peer, struct sockaddr_in *out);

#ifdef __cplusplus
}
#endif
