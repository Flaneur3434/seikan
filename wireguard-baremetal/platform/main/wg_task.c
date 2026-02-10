/**
 * @file wg_task.c
 * @brief WireGuard protocol task — crypto + protocol logic thread.
 *
 * This task owns all Ada/SPARK protocol state. It:
 *   1. Initializes WireGuard (wg_init)
 *   2. Dequeues RX packets from the IO thread
 *   3. Calls wg_receive() (Ada dispatches handshake/transport)
 *   4. Enqueues TX results back to the IO thread for sendto()
 *
 * No socket I/O happens here — that's the IO thread's job.
 */

#include "wg_task.h"
#include "wg_session_timer.h"
#include "wg_sessions.h"

#include <string.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include <esp_timer.h>


static const char *TAG = "wg_task";

/* Queue depth: how many packets can be in-flight between threads */
#define RX_QUEUE_DEPTH 4
#define TX_QUEUE_DEPTH 4

/* Static backing storage — lives in BSS, zero heap cost */
static StaticQueue_t s_rx_queue_buf;
static uint8_t s_rx_queue_storage[RX_QUEUE_DEPTH * sizeof(wg_rx_msg_t)];
static StaticQueue_t s_tx_queue_buf;
static uint8_t s_tx_queue_storage[TX_QUEUE_DEPTH * sizeof(wg_tx_msg_t)];

/* Queue handles (extern'd in wg_task.h) */
QueueHandle_t g_wg_rx_queue = NULL;
QueueHandle_t g_wg_tx_queue = NULL;

/* -----------------------------------------------------------------------
 * Protocol task main loop
 * ----------------------------------------------------------------------- */

static void wg_task(void *pvParameters)
{
    (void)pvParameters;
    wg_rx_msg_t rx_msg;

    ESP_LOGI(TAG, "WireGuard protocol task running");

    while (1)
    {
        /* ── Drain timer action queue (non-blocking) ── */
        wg_timer_msg_t tmr_msg;
        while (xQueueReceive(g_wg_timer_queue, &tmr_msg, 0) == pdTRUE)
        {
            const wg_timer_action_t *a = &tmr_msg.action;
            unsigned int peer = tmr_msg.peer;

            if (a->session_expired || a->rekey_timed_out)
            {
                ESP_LOGW(TAG, "Peer %u: %s — expiring session",
                         peer,
                         a->session_expired ? "session expired"
                                            : "rekey timed out");
                session_expire(peer);
            }

            if (a->initiate_rekey)
            {
                ESP_LOGI(TAG, "Peer %u: initiating rekey", peer);
                uint64_t now = esp_timer_get_time();

                uint16_t init_len = 0;
                packet_buffer_t *init_pkt =
                    (packet_buffer_t *)wg_create_initiation(&init_len);

                if (init_pkt != NULL && init_len > 0)
                {
                    wg_tx_msg_t tx_msg = {
                        .tx_buf = init_pkt,
                        .tx_len = init_len,
                        .peer   = {0},  /* filled by IO from known endpoint */
                    };
                    if (xQueueSend(g_wg_tx_queue, &tx_msg, 0) == pdTRUE)
                    {
                        /* Sent — mark rekey in progress so the timer
                         * doesn't fire initiate_rekey again while we
                         * wait for the handshake response. */
                        session_set_rekey_flag(peer, now);
                        ESP_LOGI(TAG, "<< Rekey Initiation (%u bytes)",
                                 init_len);
                    }
                    else
                    {
                        /* TX queue full — free the buffer, retry next tick */
                        tx_pool_free(init_pkt);
                        ESP_LOGW(TAG, "TX queue full, rekey retry next tick");
                    }
                }
                else
                {
                    ESP_LOGE(TAG, "Rekey initiation failed, retry next tick");
                }
            }

            if (a->send_keepalive)
            {
                ESP_LOGD(TAG, "Peer %u: keepalive (TODO)", peer);
                /* TODO: send empty transport packet as keepalive */
            }
        }

        /* ── Block until the IO thread sends us a packet ── */
        /* Use 100 ms timeout so timer actions get drained even when
         * no packets arrive (idle peer keepalive, rekey, expiry). */
        if (xQueueReceive(g_wg_rx_queue, &rx_msg,
                          pdMS_TO_TICKS(100)) != pdTRUE)
            continue;

        packet_buffer_t *rx_buf = rx_msg.rx_buf;
        uint8_t msg_type = rx_buf->data[0];

        /* ── Test-only: trigger ESP32-initiated handshake ── */
        if (msg_type == 0xFF)
        {
            ESP_LOGI(TAG, ">> Trigger: ESP32-initiated handshake");
            /* Free the trigger packet — it carried no payload.
             * Send free request back to IO thread via a TX msg
             * with NULL tx_buf so it frees the RX buffer. */
            rx_pool_free(rx_buf);

            uint16_t init_len = 0;
            packet_buffer_t *init_pkt =
                (packet_buffer_t *)wg_create_initiation(&init_len);

            if (init_pkt == NULL || init_len == 0)
            {
                ESP_LOGE(TAG, "wg_create_initiation failed");
                continue;
            }

            ESP_LOGI(TAG, "<< Handshake Initiation (%u bytes)", init_len);

            wg_tx_msg_t tx_msg = {
                .tx_buf = init_pkt,
                .tx_len = init_len,
                .peer   = rx_msg.peer,
            };
            xQueueSend(g_wg_tx_queue, &tx_msg, portMAX_DELAY);
            continue;
        }

        /* ── Normal path: hand to Ada ── */
        void *tx_pkt = NULL;
        uint16_t tx_len = 0;
        wg_action_t action = wg_receive(rx_buf, &tx_pkt, &tx_len);
        /* rx_buf is now owned by Ada (freed internally) */

        switch (action)
        {
        case WG_ACTION_SEND_RESPONSE:
            ESP_LOGI(TAG, "<< Handshake Response (%u bytes)", tx_len);
            /* fall through */
        case WG_ACTION_SEND_TRANSPORT:
        {
            if (action == WG_ACTION_SEND_TRANSPORT) {
                ESP_LOGI(TAG, "<< Transport Data (%u bytes)", tx_len);
            }

            wg_tx_msg_t tx_msg = {
                .tx_buf = (packet_buffer_t *)tx_pkt,
                .tx_len = tx_len,
                .peer   = rx_msg.peer,
            };
            xQueueSend(g_wg_tx_queue, &tx_msg, portMAX_DELAY);
            break;
        }

        case WG_ACTION_NONE:
            ESP_LOGD(TAG, "   Processed (no reply needed)");
            break;

        case WG_ACTION_ERROR:
        default:
            ESP_LOGW(TAG, "   wg_receive error (type 0x%02x)", msg_type);
            break;
        }
    }
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

bool wg_task_init(void)
{
    /* Create inter-thread queues (static allocation, zero heap) */
    g_wg_rx_queue = xQueueCreateStatic(
        RX_QUEUE_DEPTH, sizeof(wg_rx_msg_t),
        s_rx_queue_storage, &s_rx_queue_buf);
    g_wg_tx_queue = xQueueCreateStatic(
        TX_QUEUE_DEPTH, sizeof(wg_tx_msg_t),
        s_tx_queue_storage, &s_tx_queue_buf);

    /* Initialize pools with static semaphores, then Ada subsystem */
    packet_pool_init();

    if (!wg_init())
    {
        ESP_LOGE(TAG, "wg_init() failed — check keys in sdkconfig");
        return false;
    }

    ESP_LOGI(TAG, "WireGuard initialized: %zu buffers of %zu bytes per pool",
             packet_pool_get_pool_size(), packet_pool_get_buffer_size());

    return true;
}

bool wg_task_start(void)
{
    BaseType_t ret = xTaskCreate(
        wg_task,
        "wg_proto",
        8192,
        NULL,
        6,    /* Priority 6 (IO thread is 5) */
        NULL
    );

    if (ret != pdPASS)
    {
        ESP_LOGE(TAG, "Failed to create WG protocol task");
        return false;
    }

    ESP_LOGI(TAG, "WG protocol task started");
    return true;
}
