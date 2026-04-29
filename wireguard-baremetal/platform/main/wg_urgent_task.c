/**
 * @file wg_urgent_task.c
 * @brief WireGuard urgent control task — see wg_urgent_task.h.
 */

#include "wg_urgent_task.h"
#include "wg_timer_manager.h"
#include "wg_sessions.h"   /* WG_MAX_PEERS */

#include <stdint.h>

#include <esp_log.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "wg_urgent";

#define WG_URGENT_TASK_STACK     4096
#define WG_URGENT_TASK_PRIORITY  7   /* one above wg_proto (6) */

static TaskHandle_t s_urgent_task;

/* -----------------------------------------------------------------------
 * Task body
 *
 * Blocks indefinitely on a direct-to-task notification. When woken,
 * snapshots and clears the pending due-peer mask and dispatches per
 * peer.
 *
 * For Chunk 4 the per-peer dispatch is just a log line; the next
 * phase replaces it with a call into Ada under the session mutex.
 * --------------------------------------------------------------------- */

static void wg_urgent_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "wg_urgent task running (prio=%d)",
             WG_URGENT_TASK_PRIORITY);

    for (;;) {
        /* portMAX_DELAY: wait forever for the next notification. The
         * timer callback wakes us via xTaskNotifyGive when at least
         * one peer becomes due. */
        (void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

        uint32_t due = wg_timer_manager_take_due_mask();
        while (due != 0) {
            /* __builtin_ctz returns the bit index of the lowest set
             * bit; peer index is bit+1 (1-based). */
            unsigned int bit  = (unsigned int)__builtin_ctz(due);
            unsigned int peer = bit + 1u;
            due &= ~(1u << bit);

            ESP_LOGD(TAG, "peer %u due (mask handling stub)", peer);
            /* TODO(next chunk): take session mutex and call Ada
             * session tick for this peer. */
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

    return true;
}
