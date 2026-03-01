/**
 * @file wg_task.c
 * @brief WireGuard protocol task — crypto + protocol logic thread.
 *
 * This task owns all Ada/SPARK protocol state. It:
 *   1. Initializes WireGuard (wg_init)
 *   2. Dequeues outer RX packets from wg_netif (UDP callback)
 *   3. Dequeues inner plaintext packets from wg0 output callback
 *   4. Calls Ada APIs for decrypt / encrypt / handshake and sends via wg_netif
 */

#include "wg_task.h"
#include "wg_commands.h"
#include "wg_sessions.h"
#include "wg_clock.h"
#include "wg_netif.h"

#include <string.h>
#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>


static const char *TAG = "wg_task";

/* Queue depth: how many packets can be in-flight between threads */
#define RX_QUEUE_DEPTH    4
#define INNER_QUEUE_DEPTH 4

/* Static backing storage */
static StaticQueue_t s_rx_queue_buf;
static uint8_t s_rx_queue_storage[RX_QUEUE_DEPTH * sizeof(wg_rx_msg_t)];
static StaticQueue_t s_inner_queue_buf;
static uint8_t s_inner_queue_storage[INNER_QUEUE_DEPTH * sizeof(wg_inner_msg_t)];

/* Queue handles (extern'd in wg_task.h) */
QueueHandle_t g_wg_rx_queue = NULL;
QueueHandle_t g_wg_inner_queue = NULL;

/* -----------------------------------------------------------------------
 * Peer endpoint table — remember the last known address for each peer
 * so timer-initiated sends (rekey, keepalive) have a destination.
 *
 * Updated on every RX packet.  Single-peer today (index 0 = peer 1).
 * ----------------------------------------------------------------------- */
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

bool wg_task_get_peer_endpoint(unsigned int peer, struct sockaddr_in *out)
{
    if (out == NULL) {
        return false;
    }

    if (peer < 1 || peer > WG_MAX_PEERS) {
        return false;
    }

    struct sockaddr_in ep = get_peer_endpoint(peer);
    if (ep.sin_family != AF_INET || ep.sin_port == 0) {
        return false;
    }

    *out = ep;
    return true;
}

/* send_outer_packet — transmit then free.
 *
 * wg_netif_send_outer() uses PBUF_REF: on success the pbuf_custom callback
 * (tx_custom_free) calls tx_pool_free() once lwIP is done with the buffer.
 * We must NOT double-free on success.  On failure the buffer was never
 * handed to lwIP, so we free it here to avoid a leak.
 */
static bool send_outer_packet(packet_buffer_t *pkt,
                              uint16_t len,
                              const struct sockaddr_in *peer)
{
    if (pkt == NULL || len == 0 || peer == NULL) {
        return false;
    }

    if (!wg_netif_send_outer(pkt, len, peer)) {
        /* Ownership NOT transferred on failure — free here */
        tx_pool_free(pkt);
        return false;
    }

    /* Ownership transferred — pbuf_custom callback will call tx_pool_free */
    return true;
}

/* -----------------------------------------------------------------------
 * Protocol task main loop
 * ----------------------------------------------------------------------- */

/* Rate limit auto-initiation: at most once every 5 seconds */
#define AUTO_INIT_INTERVAL_S 5
static uint64_t s_last_auto_init = 0;

static void wg_task(void *pvParameters)
{
    (void)pvParameters;
    wg_rx_msg_t rx_msg;
    wg_inner_msg_t inner_msg;

    ESP_LOGI(TAG, "WireGuard protocol task running");

    while (1)
    {
        // Evaluate all peer timers inline, dispatch in Ada
        {
            uint64_t now = wg_clock_now();
            uint8_t actions[WG_MAX_PEERS];
            session_tick_all(now, actions);
            for (unsigned int i = 0; i < WG_MAX_PEERS; i++)
            {
                if (actions[i] != WG_TIMER_NO_ACTION)
                {
                    unsigned int peer = i + 1;  /* Ada Peer_Index is 1-based */
                    void *tx_buf = NULL;
                    uint16_t tx_len = 0;

                    wg_dispatch_timer(peer, actions[i], &tx_buf, &tx_len);

                    if (tx_buf != NULL && tx_len > 0)
                    {
                        struct sockaddr_in endpoint = get_peer_endpoint(peer);
                        if (!send_outer_packet((packet_buffer_t *)tx_buf,
                                               tx_len, &endpoint))
                        {
                            ESP_LOGW(TAG, "Peer %u: timer-initiated send failed",
                                     peer);
                        }
                    }
                }
            }
        }

        // Drain inner plaintext queue from wg0 output callback.
        // Each entry holds a TX pool buffer with plaintext at offset 16;
        // wg_send() writes the WG header into [0..15] and encrypts in-place,
        // then returns that same buffer as the encrypted packet.
        //
        // Auto-initiation: if data is pending but no session exists,
        // trigger a handshake instead of draining (packets stay queued
        // until session is established).  Rate-limited to once per 5 s.
        if (uxQueueMessagesWaiting(g_wg_inner_queue) > 0)
        {
            if (wg_session_is_active(1))
            {
                // Session active — drain and encrypt normally
                while (xQueueReceive(g_wg_inner_queue, &inner_msg, 0)
                       == pdTRUE)
                {
                    uint16_t tx_len = 0;
                    packet_buffer_t *tx_pkt =
                        (packet_buffer_t *)wg_send(
                            1,
                            inner_msg.buf->data + WG_TRANSPORT_HEADER_SIZE,
                            inner_msg.pt_len,
                            &tx_len);

                    tx_pool_free(inner_msg.buf);

                    if (tx_pkt == NULL || tx_len == 0)
                    {
                        ESP_LOGW(TAG, "wg_send failed for inner packet");
                        continue;
                    }

                    struct sockaddr_in endpoint = get_peer_endpoint(1);
                    if (!send_outer_packet(tx_pkt, tx_len, &endpoint)) {
                        ESP_LOGW(TAG,
                                 "Failed to send encrypted inner packet");
                    }
                }
            }
            else
            {
                // No session — auto-initiate handshake (rate-limited)
                uint64_t now = wg_clock_now();
                if (now - s_last_auto_init >= AUTO_INIT_INTERVAL_S)
                {
                    struct sockaddr_in endpoint = get_peer_endpoint(1);
                    if (endpoint.sin_port != 0)
                    {
                        uint16_t init_len = 0;
                        packet_buffer_t *init_pkt =
                            (packet_buffer_t *)wg_create_initiation(
                                &init_len);

                        if (init_pkt != NULL && init_len > 0)
                        {
                            ESP_LOGI(TAG,
                                     "Auto-initiating handshake "
                                     "(inner data pending)");
                            send_outer_packet(init_pkt, init_len,
                                              &endpoint);
                        }
                    }
                    s_last_auto_init = now;
                }
                // Don't drain — packets stay queued until session up
            }
        }

        // Block until outer RX packet arrives
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

        // Nominal path: hand to Ada via zero-copy netif path.
        // wg_receive_netif() decrypts transport data in-place in the RX pool
        // buffer; on WG_ACTION_RX_DECRYPTION_SUCCESS, C re-owns rx_buf.
        uint16_t pt_len = 0;
        wg_action_t action = wg_receive_netif(rx_buf, &pt_len);
        // rx_buf ownership: returned to C only on RX_DECRYPTION_SUCCESS;
        // Ada has freed it for all other return values.

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

            if (!send_outer_packet(resp_pkt, resp_len, &rx_msg.peer)) {
                ESP_LOGW(TAG, "Failed to send handshake response");
                tx_pool_free(resp_pkt);
            }
            break;
        }

        case WG_ACTION_RX_DECRYPTION_SUCCESS:
        {
            // Transport data decrypted in-place.  Plaintext is at
            // rx_buf->data[WG_TRANSPORT_HEADER_SIZE .. +pt_len-1].
            // C owns rx_buf and must free it (directly or via pbuf_custom).
            update_peer_endpoint(1, &rx_msg.peer);

            ESP_LOGI(TAG, "Decrypted Transport Data (%u plaintext)", pt_len);

            // Echo mode: re-encrypt and send back (test-only)
            if (wg_echo_enabled())
            {
                // For echo we copy the plaintext into wg_send, then free rx_buf.
                uint16_t tx_len = 0;
                packet_buffer_t *tx_pkt =
                    (packet_buffer_t *)wg_send(
                        1,
                        rx_buf->data + WG_TRANSPORT_HEADER_SIZE,
                        pt_len,
                        &tx_len);

                // Done with RX buffer
                rx_pool_free(rx_buf);

                if (tx_pkt == NULL || tx_len == 0)
                {
                    ESP_LOGW(TAG, "wg_send (echo) failed");
                    break;
                }

                ESP_LOGI(TAG, "<< Echo Transport (%u bytes)", tx_len);

                if (!send_outer_packet(tx_pkt, tx_len, &rx_msg.peer)) {
                    ESP_LOGW(TAG, "Failed to send echo transport packet");
                    // Already freed by send_outer_packet on failure
                }
            }
            else
            {
                // Zero-copy netif inject.  On success, rx_buf ownership
                // transfers to pbuf_custom callback -> rx_pool_free.
                // On failure, we retain rx_buf and must free it.
                if (!wg_netif_inject_plaintext(rx_buf,
                                               WG_TRANSPORT_HEADER_SIZE,
                                               pt_len))
                {
                    ESP_LOGW(TAG, "Failed to inject plaintext into wg0 netif");
                    rx_pool_free(rx_buf);
                }
            }
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
    g_wg_inner_queue = xQueueCreateStatic(
        INNER_QUEUE_DEPTH, sizeof(wg_inner_msg_t),
        s_inner_queue_storage, &s_inner_queue_buf);

    // Initialize pools with static semaphores and Ada subsystem structures
    packet_pool_init();

    // Create session mutex and initialize session tables (must precede wg_init)
    wg_session_init();

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
