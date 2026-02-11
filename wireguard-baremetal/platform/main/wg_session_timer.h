/**
 * @file wg_session_timer.h
 * @brief Session timer task — evaluates WireGuard peer timers.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------
 * Queue message types
 * -------------------------------------------------------------------- */

/* Per-peer timer action flags (matches Ada's C_Timer_Action layout exactly) */
typedef struct {
    uint8_t send_keepalive;   // Send empty transport as keepalive
    uint8_t initiate_rekey;   // Start new handshake (rekey)
    uint8_t session_expired;  // Wipe all keypair slots
    uint8_t rekey_timed_out;  // Rekey attempt exceeded timeout
} wg_timer_action_t;

/* Timer -> WG task: action needed for a specific peer */
typedef struct {
    unsigned int        peer;    // 1-based peer index
    wg_timer_action_t   action;  // Which timer events fired
} wg_timer_msg_t;

/* --------------------------------------------------------------------
 * Queue handle (created by timer task, drained by WG task)
 * -------------------------------------------------------------------- */

/* Queue handle (created by timer task, drained by WG task) */
extern QueueHandle_t g_wg_timer_queue;

/* --------------------------------------------------------------------
 * API
 * -------------------------------------------------------------------- */

/**
 * Initialize the session timer queue.
 *
 * Creates the static timer action queue.  Does NOT spawn the task.
 * Must be called before wg_task_start().
 *
 * @return true (static queue always succeeds).
 */
bool wg_session_timer_init(void);

/**
 * Spawn the session timer task.
 *
 * Must be called after wg_session_timer_init() and after all other
 * resources are initialized.
 *
 * @return true on success, false if xTaskCreate failed.
 */
bool wg_session_timer_start(void);

#ifdef __cplusplus
}
#endif
