/**
 * @file wg_timer_manager.h
 * @brief Per-peer one-shot deadline timer manager.
 *
 * This module owns one esp_timer handle per WireGuard peer. Each peer
 * has at most one armed deadline at a time: the next moment at which
 * Ada might have timer-driven work to do for that peer.
 *
 * On expiry, the timer callback:
 *   1. Validates the captured generation against the currently armed
 *      generation (stale callbacks are dropped).
 *   2. Sets the peer's bit in the pending due-peer mask.
 *   3. Notifies the wg_urgent task.
 *
 * The callback never calls Ada session APIs, never allocates buffers,
 * and never performs crypto. All semantic decisions happen in
 * wg_urgent under the Ada session mutex.
 *
 * See docs/timer_driven_urgent_queue_design.md for the full design.
 *
 * Concurrency model (single-core ESP32-C3):
 *   esp_timer task priority > wg_urgent priority > wg_transport priority.
 *   The timer callback runs to completion atomically with respect to
 *   wg_urgent, so the pending mask is a plain uint32_t.
 *
 * If this module is ever ported to a multi-core target, the pending
 * mask must use atomics or a spinlock.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

#include "wg_sessions.h"  /* WG_MAX_PEERS */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize timer manager state.
 *
 * Allocates one esp_timer handle per peer slot. No timers are armed.
 * Must be called once at startup before any arm/disarm operation.
 *
 * @return true on success, false if any esp_timer_create failed.
 */
bool wg_timer_manager_init(void);

/**
 * @brief Register the task to notify when a peer becomes due.
 *
 * The timer callback uses xTaskNotifyGive() to wake this task when a
 * non-stale expiry occurs. Must be called once during startup, after
 * the wg_urgent task has been created.
 *
 * Passing NULL disables notifications (callbacks still update the
 * pending mask but no task is woken).
 *
 * @param task Task to notify, or NULL to disable.
 */
void wg_timer_manager_set_notify_task(TaskHandle_t task);

/**
 * @brief Arm peer N's one-shot deadline at an absolute monotonic time.
 *
 * If a timer is already armed for peer N, it is first disarmed (which
 * increments the generation, neutralizing any in-flight callback).
 *
 * Deadlines in the past are clamped to fire ASAP.
 *
 * @param peer       1-based peer index (1..WG_MAX_PEERS).
 * @param deadline_ms Absolute deadline in monotonic ms since boot.
 * @return true on success, false on invalid peer index or
 *         esp_timer_start_once failure.
 */
bool wg_timer_manager_arm(unsigned int peer, int64_t deadline_ms);

/**
 * @brief Disarm peer N's timer.
 *
 * Stops the timer (best effort) and increments the peer's generation
 * counter, so any already-dispatched callback for the previous arm
 * becomes a no-op when it eventually runs.
 *
 * @param peer 1-based peer index (1..WG_MAX_PEERS).
 */
void wg_timer_manager_disarm(unsigned int peer);

/**
 * @brief Snapshot and clear the pending due-peer mask.
 *
 * Bit (peer - 1) is set if peer's timer expired and the callback
 * marked it due since the last snapshot.
 *
 * Single-core assumption: the read-then-clear sequence is atomic with
 * respect to the timer callback because the callback runs at higher
 * priority on the same CPU. See file header for porting notes.
 *
 * @return Bitmask: bit i corresponds to peer (i + 1).
 */
uint32_t wg_timer_manager_take_due_mask(void);

/**
 * @brief Read (without clearing) the currently armed deadline for a
 *        peer, if any. Useful for tracing only.
 *
 * @param peer        1-based peer index.
 * @param deadline_ms Out parameter; only written if function returns true.
 * @return true if peer N currently has an armed timer.
 */
bool wg_timer_manager_get_armed_deadline(unsigned int peer,
                                         int64_t *deadline_ms);

#ifdef __cplusplus
}
#endif
