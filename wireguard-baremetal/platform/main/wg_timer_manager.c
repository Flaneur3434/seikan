/**
 * @file wg_timer_manager.c
 * @brief Per-peer one-shot deadline timer manager.
 *
 * See wg_timer_manager.h for the contract and design rationale.
 * See docs/timer_driven_urgent_queue_design.md for the full design.
 */

#include "wg_timer_manager.h"
#include "wg_clock.h"

#include <stdint.h>
#include <string.h>

#include <esp_log.h>
#include <esp_timer.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "wg_timer";

/* Compile-time guard: the pending mask uses one bit per peer in a
 * uint32_t, so we cannot represent more than 32 peers. */
_Static_assert(WG_MAX_PEERS <= 32,
               "wg_timer_manager pending mask is uint32_t");

/* -----------------------------------------------------------------------
 * Per-peer state
 *
 * Indexed 1..WG_MAX_PEERS; slot 0 is unused so the rest of the
 * codebase's 1-based peer indexing maps directly.
 * --------------------------------------------------------------------- */

typedef struct {
    esp_timer_handle_t handle;        /* esp_timer handle (created at init) */
    uint32_t           generation;    /* incremented on every arm/disarm */
    int64_t            deadline_ms;   /* tracing only; meaningful iff armed */
    bool               armed;
} wg_timer_peer_t;

static wg_timer_peer_t s_peers[WG_MAX_PEERS + 1];

/* Pending due-peer mask. Bit i corresponds to peer (i + 1).
 * Written by the timer callback (set) and by wg_urgent
 * (snapshot-and-clear via wg_timer_manager_take_due_mask). On
 * single-core ESP32-C3 with esp_timer task priority > wg_urgent
 * priority, no atomics or critical section is required. */
static volatile uint32_t s_pending_due_mask;

/* Task to notify on non-stale expiry, or NULL to disable. */
static TaskHandle_t s_notify_task;

/* -----------------------------------------------------------------------
 * Callback context
 *
 * esp_timer callback args are void*. We pass a pointer to a per-peer
 * "callback context" struct that captures BOTH the peer index and the
 * generation that armed this expiry. The context lives inline in the
 * peer state, but we update it before each arm and the callback only
 * reads it.
 *
 * Because esp_timer runs at higher priority than wg_urgent on this
 * single-core target, the writer (wg_urgent during arm) and the
 * callback do not race: arm runs to completion before any subsequent
 * callback can fire.
 * --------------------------------------------------------------------- */

typedef struct {
    unsigned int peer;
    uint32_t     generation;
} wg_timer_cb_ctx_t;

/* One context per peer, written by arm, read by the callback. */
static wg_timer_cb_ctx_t s_cb_ctx[WG_MAX_PEERS + 1];

/* -----------------------------------------------------------------------
 * Timer callback
 *
 * Runs in the esp_timer task at a higher priority than wg_urgent on
 * the single-core ESP32-C3. Therefore:
 *
 *   - The generation read here cannot be torn relative to wg_urgent's
 *     arm/disarm updates: arm completes (or has not yet started)
 *     before this callback can preempt.
 *   - The OR into s_pending_due_mask cannot race with wg_urgent's
 *     snapshot-and-clear.
 *
 * The callback intentionally does no Ada work and no logging in the
 * hot path: it only marks a bit and pokes a task. Semantic decisions
 * happen in wg_urgent under the session mutex.
 *
 * Stale callbacks (arm-then-disarm-or-rearm before this callback ran)
 * are detected by comparing the captured generation against the live
 * generation and dropped silently.
 * --------------------------------------------------------------------- */

static void wg_timer_cb(void *arg)
{
    const wg_timer_cb_ctx_t *ctx = (const wg_timer_cb_ctx_t *)arg;
    if (ctx == NULL) {
        return;
    }

    const unsigned int peer = ctx->peer;
    if (peer == 0 || peer > WG_MAX_PEERS) {
        return;
    }

    /* Stale-expiry filter: drop callbacks for arms that have since
     * been superseded by a re-arm or cancelled by a disarm. */
    if (ctx->generation != s_peers[peer].generation) {
        return;
    }

    /* Mark this peer due. Bit (peer - 1). */
    s_pending_due_mask |= (uint32_t)(1u << (peer - 1));

    /* Note that we are no longer armed; the next arm() call will skip
     * the redundant esp_timer_stop. This is purely an optimization. */
    s_peers[peer].armed = false;

    /* Wake wg_urgent if it has been registered. esp_timer dispatch
     * method is ESP_TIMER_TASK, so we are in task context (not ISR)
     * and use the plain task-context notify primitive. */
    TaskHandle_t notify = s_notify_task;
    if (notify != NULL) {
        xTaskNotifyGive(notify);
    }
}

/* -----------------------------------------------------------------------
 * Public API
 * --------------------------------------------------------------------- */

bool wg_timer_manager_init(void)
{
    memset(s_peers,  0, sizeof(s_peers));
    memset(s_cb_ctx, 0, sizeof(s_cb_ctx));
    s_pending_due_mask = 0;
    s_notify_task      = NULL;

    for (unsigned int peer = 1; peer <= WG_MAX_PEERS; peer++) {
        s_cb_ctx[peer].peer       = peer;
        s_cb_ctx[peer].generation = 0;

        const esp_timer_create_args_t args = {
            .callback        = &wg_timer_cb,
            .arg             = &s_cb_ctx[peer],
            .dispatch_method = ESP_TIMER_TASK,
            .name            = "wg_peer_timer",
            .skip_unhandled_events = false,
        };

        esp_err_t err = esp_timer_create(&args, &s_peers[peer].handle);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "esp_timer_create failed for peer %u: %d",
                     peer, (int)err);
            return false;
        }
    }

    ESP_LOGI(TAG, "timer manager initialized (%d peers)", WG_MAX_PEERS);
    return true;
}

void wg_timer_manager_set_notify_task(TaskHandle_t task)
{
    s_notify_task = task;
}

bool wg_timer_manager_arm(unsigned int peer, int64_t deadline_ms)
{
    if (peer == 0 || peer > WG_MAX_PEERS) {
        return false;
    }

    /* Disarm any existing timer first; this also bumps the generation. */
    if (s_peers[peer].armed) {
        (void)esp_timer_stop(s_peers[peer].handle);
        s_peers[peer].armed = false;
    }

    /* Bump generation for the new arm and update the callback context.
     * The callback uses the captured context to detect stale expiries. */
    s_peers[peer].generation += 1;
    s_cb_ctx[peer].generation = s_peers[peer].generation;

    /* Compute delta to fire-time, clamping to a small minimum so we do
     * not pass zero or a negative delta to esp_timer_start_once. */
    int64_t now_ms = wg_clock_now_ms();
    int64_t delta_ms = deadline_ms - now_ms;
    if (delta_ms < 1) {
        delta_ms = 1;
    }

    uint64_t delta_us = (uint64_t)delta_ms * 1000ULL;
    esp_err_t err = esp_timer_start_once(s_peers[peer].handle, delta_us);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_timer_start_once failed for peer %u: %d",
                 peer, (int)err);
        return false;
    }

    s_peers[peer].deadline_ms = deadline_ms;
    s_peers[peer].armed       = true;
    return true;
}

void wg_timer_manager_disarm(unsigned int peer)
{
    if (peer == 0 || peer > WG_MAX_PEERS) {
        return;
    }

    if (s_peers[peer].armed) {
        (void)esp_timer_stop(s_peers[peer].handle);
        s_peers[peer].armed = false;
    }

    /* Bump generation unconditionally so any in-flight callback is
     * neutralized even if we were not strictly "armed" at the moment of
     * the call (defensive). */
    s_peers[peer].generation += 1;
    s_cb_ctx[peer].generation = s_peers[peer].generation;
}

uint32_t wg_timer_manager_take_due_mask(void)
{
    /* Single-core read-then-clear; see file header for porting notes. */
    uint32_t snapshot = s_pending_due_mask;
    s_pending_due_mask = 0;
    return snapshot;
}

bool wg_timer_manager_get_armed_deadline(unsigned int peer,
                                         int64_t *deadline_ms)
{
    if (peer == 0 || peer > WG_MAX_PEERS) {
        return false;
    }
    if (!s_peers[peer].armed) {
        return false;
    }
    if (deadline_ms != NULL) {
        *deadline_ms = s_peers[peer].deadline_ms;
    }
    return true;
}
