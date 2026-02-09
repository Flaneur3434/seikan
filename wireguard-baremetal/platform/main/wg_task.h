/**
 * @file wg_task.h
 * @brief WireGuard protocol task — crypto + protocol logic thread.
 *
 * Architecture (2-thread pipeline):
 *
 *   IO Thread (udp_server)          WG Task (this)
 *   ─────────────────────           ──────────────
 *   recvfrom() into pool buf  ──►  wg_receive() dispatch
 *                             ◄──  TX buf + action
 *   sendto() + free TX buf         (crypto, handshake, replay)
 *
 * The IO thread owns the memory pools (allocate/free).
 * This task only borrows buffers passed through FreeRTOS queues.
 */

#ifndef WG_TASK_H
#define WG_TASK_H

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

/** IO thread -> WG task: incoming packet to process */
typedef struct {
    packet_buffer_t *rx_buf;  /**< RX pool buffer (ownership transferred) */
    struct sockaddr_in peer;  /**< Sender address for reply routing */
} wg_rx_msg_t;

/** WG task -> IO thread: outgoing packet to send */
typedef struct {
    packet_buffer_t *tx_buf;  /**< TX pool buffer (ownership transferred) */
    uint16_t         tx_len;  /**< Valid bytes in tx_buf->data */
    struct sockaddr_in peer;  /**< Destination address */
} wg_tx_msg_t;

/** IO thread -> WG task: request to create an initiation */
typedef struct {
    struct sockaddr_in peer;  /**< Target peer address */
} wg_initiate_msg_t;

/* --------------------------------------------------------------------
 * Queue handles (created by wg_task, used by udp_server)
 * -------------------------------------------------------------------- */

/** Queue: IO -> WG (rx packets + initiation triggers) */
extern QueueHandle_t g_wg_rx_queue;

/** Queue: WG -> IO (tx packets to send) */
extern QueueHandle_t g_wg_tx_queue;

/* --------------------------------------------------------------------
 * API
 * -------------------------------------------------------------------- */

/**
 * Start the WireGuard protocol task.
 *
 * Creates the RX/TX queues, calls wg_init(), then spawns a FreeRTOS
 * task that dequeues packets, runs Ada crypto/protocol, and enqueues
 * TX results.
 *
 * Must be called before udp_server_task.
 *
 * @return true on success, false if wg_init() or task creation failed.
 */
bool wg_task_start(void);

#ifdef __cplusplus
}
#endif

#endif /* WG_TASK_H */
