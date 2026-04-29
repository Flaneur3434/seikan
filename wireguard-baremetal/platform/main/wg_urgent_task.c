/**
 * @file wg_urgent_task.c
 * @brief WireGuard urgent control task — see wg_urgent_task.h.
 */

#include "wg_urgent_task.h"
#include "wg_clock.h"
#include "wg_sessions.h"        /* WG_MAX_PEERS, session_on_peer_timer_due */
#include "wg_timer_manager.h"

#include <stdint.h>

#include <esp_log.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "wg_urgent";

#define WG_URGENT_TASK_STACK     4096
#define WG_URGENT_TASK_PRIORITY  7   /* one above wg_proto (6) */

/* Shadow-mode polling interval. Each due peer is re-armed for
 * (now + WG_URGENT_RECHECK_MS) after a tick. While the legacy
 * 100 ms polling loop remains live this matches its order of
 * magnitude and keeps timer-driven evaluation cheap. */
#define WG_URGENT_RECHECK_MS     1000

static TaskHandle_t s_urgent_task;

/* -----------------------------------------------------------------------
 * Action name table — for shadow-mode logging only.
 * --------------------------------------------------------------------- */

static const char *action_name(uint8_t action)
{
    switch (action) {
    case WG_TIMER_NO_ACTION:       return "no_action";
    case WG_TIMER_SEND_KEEPALIVE:  return "keepalive";
    case WG_TIMER_INITIATE_REKEY:  return "rekey";
    case WG_TIMER_REKEY_TIMED_OUT: return "rekey_timed_out";
    case WG_TIMER_SESSION_EXPIRED: return "expired";
    default:                       return "unknown";
    }
}

/* -----------------------------------------------------------------------
 * Per-peer due handler — SHADOW MODE
 *
 * Calls Ada's single-peer evaluation under the session mutex (acquired
 * internally by Ada) and logs what action it would take. It does NOT
 * call wg_dispatch_timer: the legacy polling path in wg_task remains
 * the only side-effecting consumer of Timer_Action this chunk.
 *
 * After evaluation the peer's timer is re-armed so the urgent path
 * keeps producing observations at WG_URGENT_RECHECK_MS cadence.
 * --------------------------------------------------------------------- */

static void handle_peer_due_shadow(unsigned int peer)
{
    uint64_t now_s = wg_clock_now();
    uint8_t  action = session_on_peer_timer_due(peer, now_s);

    if (action != WG_TIMER_NO_ACTION) {
        ESP_LOGI(TAG, "[shadow] peer %u would dispatch %s",
                 peer, action_name(action));
    } else {
        ESP_LOGD(TAG, "[shadow] peer %u no action", peer);
    }

    int64_t next_deadline_ms = wg_clock_now_ms() + WG_URGENT_RECHECK_MS;
    (void)wg_timer_manager_arm(peer, next_deadline_ms);
}

/* -----------------------------------------------------------------------
 * Task body
 * --------------------------------------------------------------------- */

static void wg_urgent_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "wg_urgent task running (prio=%d, shadow mode)",
             WG_URGENT_TASK_PRIORITY);

    for (;;) {
        /* portMAX_DELAY: wait forever for the next notification.
         * The timer manager's callback wakes us via xTaskNotifyGive
         * when at least one peer's deadline has expired. */
        (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        uint32_t due = wg_timer_manager_take_due_mask();
        while (due != 0) {
            /* __builtin_ctz returns the bit index of the lowest set
             * bit; peer index is bit+1 (1-based). */
            unsigned int bit  = (unsigned int)__builtin_ctz(due);
            unsigned int peer = bit + 1u;
            due &= ~(1u << bit);

            handle_peer_due_shadow(peer);
        }
    }
}

bool wg_urgent_task_start(void)
{
    if (s_urgent_task != NULL) {
        ESP_LOGW(TAG, "wg_urgent task already started");
        return true;
    }

    BaseType_t ret = xTaskCreate(
        wg_urgent_task,
        "wg_urgent",
        WG_URGENT_TASK_STACK,
        NULL,
        WG_URGENT_TASK_PRIORITY,
        &s_urgent_task
    );

    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create wg_urgent task");
        s_urgent_task = NULL;
        return false;
    }

    /* Register so timer callbacks notify us on non-stale expiries. */
    wg_timer_manager_set_notify_task(s_urgent_task);

    /* Bootstrap: arm every peer's first deadline. From here on, each
     * tick re-arms itself in handle_peer_due_shadow. */
    int64_t first_deadline_ms = wg_clock_now_ms() + WG_URGENT_RECHECK_MS;
    for (unsigned int peer = 1; peer <= WG_MAX_PEERS; peer++) {
        (void)wg_timer_manager_arm(peer, first_deadline_ms);
    }

    return true;
}
