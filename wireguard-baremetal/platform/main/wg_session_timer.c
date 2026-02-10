/**
 * @file wg_session_timer.c
 * @brief Session timer task — evaluates WireGuard peer timers.
 *
 * This task runs at priority 7 (highest in the WG pipeline) and:
 *   1. Sleeps for 1 second (vTaskDelay)
 *   2. Calls Ada's session_tick_all() which evaluates all peer timers
 *      under a single session-mutex hold
 *   3. Enqueues any non-empty actions to g_wg_timer_queue
 *   4. The WG task (pri 6) drains this queue non-blocking and dispatches
 *
 * No crypto or I/O happens here — just timer evaluation + queue push.
 */

#include "wg_session_timer.h"
#include "wg_sessions.h"
#include "wg_clock.h"

#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>

static const char *TAG = "wg_timer";

/* Max_Peers — must match Ada Session.Max_Peers */
#define WG_MAX_PEERS 2

/* Queue depth: one action per peer, with some headroom */
#define TIMER_QUEUE_DEPTH 4

/* Ada-exported: evaluate all peer timers under session mutex */
extern void session_tick_all(uint64_t now, wg_timer_action_t actions[]);

/* Static backing storage — lives in BSS, zero heap cost */
static StaticQueue_t s_timer_queue_buf;
static uint8_t s_timer_queue_storage[TIMER_QUEUE_DEPTH * sizeof(wg_timer_msg_t)];

/* Queue handle (extern'd in wg_session_timer.h) */
QueueHandle_t g_wg_timer_queue = NULL;

/* -----------------------------------------------------------------------
 * Timer task main loop
 * ----------------------------------------------------------------------- */

static void session_timer_task(void *pvParameters)
{
    (void)pvParameters;
    wg_timer_action_t actions[WG_MAX_PEERS];

    ESP_LOGI(TAG, "Session timer task running (1 s tick)");

    while (1)
    {
        vTaskDelay(pdMS_TO_TICKS(1000));

        uint64_t now = wg_clock_now();

        /* Ada evaluates all peer timers under session mutex */
        session_tick_all(now, actions);

        /* Enqueue any non-empty actions for the WG task to dispatch */
        for (unsigned int i = 0; i < WG_MAX_PEERS; i++)
        {
            const wg_timer_action_t *a = &actions[i];
            if (a->send_keepalive  || a->initiate_rekey ||
                a->session_expired || a->rekey_timed_out)
            {
                wg_timer_msg_t msg = {
                    .peer   = i + 1,  /* Ada Peer_Index is 1-based */
                    .action = *a,
                };
                /* Non-blocking: if queue is full, drop (timer will
                 * re-evaluate next tick anyway). */
                if (xQueueSend(g_wg_timer_queue, &msg, 0) != pdTRUE)
                {
                    ESP_LOGW(TAG, "Timer queue full, dropping peer %u", i + 1);
                }
            }
        }
    }
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

bool wg_session_timer_init(void)
{
    g_wg_timer_queue = xQueueCreateStatic(
        TIMER_QUEUE_DEPTH,
        sizeof(wg_timer_msg_t),
        s_timer_queue_storage,
        &s_timer_queue_buf);

    ESP_LOGI(TAG, "Session timer queue initialized");
    return true;
}

bool wg_session_timer_start(void)
{
    wg_session_init();
    
    BaseType_t ret = xTaskCreate(
        session_timer_task,
        "wg_timer",
        4096,
        NULL,
        7,    /* Priority 7 — highest in the WG pipeline */
        NULL
    );

    if (ret != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create session timer task");
        return false;
    }

    ESP_LOGI(TAG, "Session timer task started (pri 7)");
    return true;
}
