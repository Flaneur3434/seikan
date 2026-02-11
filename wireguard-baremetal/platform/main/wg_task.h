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

/* WG task -> IO thread: outgoing packet to send */
typedef struct {
    packet_buffer_t *tx_buf;  // TX pool buffer (ownership transferred)
    uint16_t         tx_len;  // Valid bytes in tx_buf->data
    struct sockaddr_in peer;  // Destination address
} wg_tx_msg_t;

/* --------------------------------------------------------------------
 * Queue handles (created by wg_task, used by udp_server)
 * -------------------------------------------------------------------- */

/* Queue: IO -> WG (rx packets + initiation triggers) */
extern QueueHandle_t g_wg_rx_queue;

/* Queue: WG -> IO (tx packets to send) */
extern QueueHandle_t g_wg_tx_queue;

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

#ifdef __cplusplus
}
#endif
