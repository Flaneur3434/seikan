/**
 * @file wg_urgent_task.h
 * @brief WireGuard urgent control task — handles timer-driven peer events.
 *
 * The urgent task is the consumer of the wg_timer_manager's pending
 * due-peer mask. It runs at a priority higher than the periodic
 * transport task (wg_proto) so timer-driven session work (handshake
 * retransmits, rekey, keepalive) cannot be starved by packet I/O.
 *
 * Loop structure (Chunk 4 scaffolding):
 *   for (;;) {
 *       ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
 *       uint32_t due = wg_timer_manager_take_due_mask();
 *       for each set bit i in due:
 *           log "peer (i+1) due"
 *   }
 *
 * Subsequent phases will replace the log line with the call into
 * Ada's session-tick API under the session mutex.
 *
 * See docs/timer_driven_urgent_queue_design.md.
 */

#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Spawn the wg_urgent task and register it with the timer manager.
 *
 * Must be called after wg_timer_manager_init().
 *
 * @return true on success, false if xTaskCreate failed.
 */
bool wg_urgent_task_start(void);

#ifdef __cplusplus
}
#endif
