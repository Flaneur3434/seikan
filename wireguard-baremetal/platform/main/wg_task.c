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
#include "wg_commands.h"
#include "wg_session_timer.h"
#include "wg_sessions.h"
#include "wg_clock.h"

#include <string.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>


static const char *TAG = "wg_task";

/* Queue depth: how many packets can be in-flight between threads */
#define RX_QUEUE_DEPTH 4
#define TX_QUEUE_DEPTH 4

/* Static backing storage */
static StaticQueue_t s_rx_queue_buf;
static uint8_t s_rx_queue_storage[RX_QUEUE_DEPTH * sizeof(wg_rx_msg_t)];
static StaticQueue_t s_tx_queue_buf;
static uint8_t s_tx_queue_storage[TX_QUEUE_DEPTH * sizeof(wg_tx_msg_t)];

/* Queue handles (extern'd in wg_task.h) */
QueueHandle_t g_wg_rx_queue = NULL;
QueueHandle_t g_wg_tx_queue = NULL;

/* -----------------------------------------------------------------------
 * Peer endpoint table — remember the last known address for each peer
 * so timer-initiated sends (rekey, keepalive) have a destination.
 *
 * Updated on every RX packet.  Single-peer today (index 0 = peer 1).
 * ----------------------------------------------------------------------- */
#define WG_MAX_PEERS 2
static struct sockaddr_in s_peer_endpoints[WG_MAX_PEERS];

static void update_peer_endpoint(unsigned int peer,
                                 const struct sockaddr_in *addr)
{
    if (peer >= 1 && peer <= WG_MAX_PEERS) {
        s_peer_endpoints[peer - 1] = *addr;
    }
}

static struct sockaddr_in get_peer_endpoint(unsigned int peer)
{
    if (peer >= 1 && peer <= WG_MAX_PEERS) {
        return s_peer_endpoints[peer - 1];
    }
    struct sockaddr_in empty = {0};
    return empty;
}

static void wg_session_action(wg_timer_action_t action, unsigned int peer)
{
    switch (action)
    {
    case WG_TIMER_SESSION_EXPIRED:
    case WG_TIMER_REKEY_TIMED_OUT:
        ESP_LOGW(TAG, "Peer %u: %s — expiring session",
                 peer,
                 action == WG_TIMER_SESSION_EXPIRED ? "session expired"
                                                    : "rekey timed out");
        session_expire(peer);
        break;

    case WG_TIMER_INITIATE_REKEY:
    {
        ESP_LOGI(TAG, "Peer %u: initiating rekey", peer);

        uint16_t init_len = 0;
        packet_buffer_t *init_pkt =
            (packet_buffer_t *)wg_create_initiation(&init_len);

        if (init_pkt != NULL && init_len > 0)
        {
            wg_tx_msg_t tx_msg = {
                .tx_buf = init_pkt,
                .tx_len = init_len,
                .peer = get_peer_endpoint(peer),
            };
            
            if (xQueueSend(g_wg_tx_queue, &tx_msg, 0) == pdTRUE)
            {
                session_set_rekey_flag(peer, wg_clock_now());
                ESP_LOGI(TAG, "<< Rekey Initiation (%u bytes)",
                         init_len);
            }
            else
            {
                tx_pool_free(init_pkt);
                ESP_LOGW(TAG, "TX queue full, rekey retry next tick");
            }
        }
        else
        {
            ESP_LOGE(TAG, "Rekey initiation failed, retry next tick");
        }
        break;
    }

    case WG_TIMER_SEND_KEEPALIVE:
    {
        uint16_t ka_len = 0;
        packet_buffer_t *ka_pkt =
            (packet_buffer_t *)wg_send(peer, NULL, 0, &ka_len);

        if (ka_pkt != NULL && ka_len > 0)
        {
            wg_tx_msg_t tx_msg = {
                .tx_buf = ka_pkt,
                .tx_len = ka_len,
                .peer = get_peer_endpoint(peer),
            };

            if (xQueueSend(g_wg_tx_queue, &tx_msg, 0) == pdTRUE)
            {
                ESP_LOGI(TAG, "Peer %u: keepalive sent (%u bytes)",
                         peer, ka_len);
            }
            else
            {
                // TX queue full — free the buffer, drop keepalive message
                // (re-try next keepalive epoch)
                tx_pool_free(ka_pkt);
                ESP_LOGW(TAG, "TX queue full, keepalive dropped");
            }
        }
        else
        {
            ESP_LOGW(TAG, "Peer %u: keepalive failed (no session?)", peer);
        }
        break;
    }

    case WG_TIMER_NO_ACTION:
    default:
        break;
    }
}

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
        // Drain timer action queue (non-blocking)
        wg_timer_msg_t tmr_msg;
        while (xQueueReceive(g_wg_timer_queue, &tmr_msg, 0) == pdTRUE)
        {
            wg_session_action(tmr_msg.action, tmr_msg.peer);
        }

        // Block until the IO thread sends us a packet
        // Use 100 ms timeout so timer actions get drained even when
        // no packets arrive (idle peer keepalive, rekey, expiry).
        if (xQueueReceive(g_wg_rx_queue, &rx_msg, pdMS_TO_TICKS(100)) != pdTRUE)
        {
            continue;
        }

        packet_buffer_t *rx_buf = rx_msg.rx_buf;
        uint8_t msg_type = rx_buf->data[0];

        /* Endpoint update is deferred until AFTER crypto verification.
         * Per WireGuard §6.5: only update a peer's endpoint from the
         * outer UDP source address of a cryptographically authenticated
         * packet. This prevents an attacker from redirecting traffic
         * by sending spoofed packets from a different address. */

        // Test commands from Python suite (bit 7 set)
        if (wg_is_command(msg_type))
        {
            wg_command_dispatch(msg_type, &rx_msg);
            continue;
        }

        // Nominal path: hand to Ada
        uint8_t pt_buf[WG_MAX_PLAINTEXT];
        uint16_t pt_len = 0;
        wg_action_t action = wg_receive(rx_buf, pt_buf, &pt_len);
        // rx_buf is now owned by Ada (freed internally)

        switch (action)
        {
        case WG_ACTION_SEND_RESPONSE:
        {
            // Initiation processed — build and send the response
            uint16_t resp_len = 0;
            packet_buffer_t *resp_pkt =
                (packet_buffer_t *)wg_create_response(&resp_len);

            if (resp_pkt == NULL || resp_len == 0)
            {
                ESP_LOGE(TAG, "wg_create_response failed");
                break;
            }

            ESP_LOGI(TAG, "<< Handshake Response (%u bytes)", resp_len);

            // §6.5: crypto succeeded — safe to learn endpoint
            update_peer_endpoint(1, &rx_msg.peer);

            wg_tx_msg_t tx_msg = {
                .tx_buf = resp_pkt,
                .tx_len = resp_len,
                .peer   = rx_msg.peer,
            };

            // Network I/O handed by different thread, enqueue response (blocking)
            xQueueSend(g_wg_tx_queue, &tx_msg, portMAX_DELAY);
            break;
        }

        case WG_ACTION_RX_DECRYPTION_SUCCESS:
        {
            // Transport data decrypted successfully
            update_peer_endpoint(1, &rx_msg.peer);

            ESP_LOGI(TAG, "Decrypted Transport Data (%u plaintext)", pt_len);

            // Echo mode: re-encrypt and send back (test-only)
            if (wg_echo_enabled())
            {
                uint16_t tx_len = 0;
                packet_buffer_t *tx_pkt =
                    (packet_buffer_t *)wg_send(1, pt_buf, pt_len, &tx_len);

                if (tx_pkt == NULL || tx_len == 0)
                {
                    ESP_LOGW(TAG, "wg_send (echo) failed");
                    break;
                }

                ESP_LOGI(TAG, "<< Echo Transport (%u bytes)", tx_len);

                wg_tx_msg_t tx_msg = {
                    .tx_buf = tx_pkt,
                    .tx_len = tx_len,
                    .peer   = rx_msg.peer,
                };
                xQueueSend(g_wg_tx_queue, &tx_msg, portMAX_DELAY);
            }

            // TODO: do something with plaintext in the future
            break;
        }

        case WG_ACTION_NONE:
            // Handshake response processed or keepalive received.
            // Crypto verified — safe to update endpoint.
            update_peer_endpoint(1, &rx_msg.peer);
            ESP_LOGI(TAG, "<< Processed (no reply needed)");
            break;

        case WG_ACTION_ERROR:
        default:
            ESP_LOGW(TAG, "<< wg_receive error (type 0x%02x)", msg_type);
            break;
        }
    }
}

/* -----------------------------------------------------------------------
 * Public API
 * ----------------------------------------------------------------------- */

bool wg_task_init(void)
{
    // Create inter-thread queues
    g_wg_rx_queue = xQueueCreateStatic(
        RX_QUEUE_DEPTH, sizeof(wg_rx_msg_t),
        s_rx_queue_storage, &s_rx_queue_buf);
    g_wg_tx_queue = xQueueCreateStatic(
        TX_QUEUE_DEPTH, sizeof(wg_tx_msg_t),
        s_tx_queue_storage, &s_tx_queue_buf);

    // Initialize pools with static semaphores and Ada subsystem structures
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
