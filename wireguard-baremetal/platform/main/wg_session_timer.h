/**
 * @file wg_session_timer.h
 * @brief Session timer task — evaluates WireGuard peer timers.
 *
 * Architecture (3-thread pipeline):
 *
 *   Timer Task (this, pri 7)   WG Task (pri 6)          IO Thread (pri 5)
 *   ────────────────────────   ────────────────          ─────────────────
 *   Tick_All every 1 s   ──►  drain action queue  ──►   sendto() / free
 *   (Ada evaluates timers)     dispatch: expire,
 *                              rekey, keepalive
 *
 * The timer task calls Ada's session_tick_all() under the session mutex,
 * then enqueues any non-empty actions to g_wg_timer_queue for the WG
 * task to drain non-blocking at the top of its loop.
 *
 * Design: "Ada is the brain, C is the hands"
 *   Ada owns all timer evaluation logic (SPARK-proved).
 *   C owns the FreeRTOS task, queue, and action dispatch.
 */

#ifndef WG_SESSION_TIMER_H
#define WG_SESSION_TIMER_H

#include <stdbool.h>
#include <stdint.h>

#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------
 * Timer action — matches Ada's C_Timer_Action layout exactly
 * -------------------------------------------------------------------- */

/** Per-peer timer action flags (from Ada Session.Timers.Tick) */
typedef struct {
    uint8_t send_keepalive;   /**< Send empty transport as keepalive */
    uint8_t initiate_rekey;   /**< Start new handshake (rekey) */
    uint8_t session_expired;  /**< Wipe all keypair slots */
    uint8_t rekey_timed_out;  /**< Rekey attempt exceeded timeout */
} wg_timer_action_t;

/** Timer -> WG task: action for a specific peer */
typedef struct {
    unsigned int        peer;    /**< 1-based peer index (Ada Peer_Index) */
    wg_timer_action_t   action;  /**< Which timer events fired */
} wg_timer_msg_t;

/* --------------------------------------------------------------------
 * Queue handle (created by timer task, drained by WG task)
 * -------------------------------------------------------------------- */

/** Queue: Timer -> WG (timer actions to dispatch) */
extern QueueHandle_t g_wg_timer_queue;

/* --------------------------------------------------------------------
 * API
 * -------------------------------------------------------------------- */

/**
 * Initialize the session timer queue.
 *
 * Creates the static timer action queue.  Does NOT spawn the task.
 * Must be called after wg_session_init() and before wg_task_start().
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

#endif /* WG_SESSION_TIMER_H */
