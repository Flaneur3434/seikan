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
#include "wg_peer_table.h"
#include "wg_clock.h"
#include "wg_netif.h"
#include "wg_timer_manager.h"
#include "wg_urgent_task.h"

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

/* Per-peer inner queues: one queue per peer (1-indexed, slot 0 unused) */
static StaticQueue_t s_inner_queue_bufs[WG_MAX_PEERS];
static uint8_t s_inner_queue_storage[WG_MAX_PEERS]
    [INNER_QUEUE_DEPTH * sizeof(wg_inner_msg_t)];

/* Queue handles (extern'd in wg_task.h) */
QueueHandle_t g_wg_rx_queue = NULL;
QueueHandle_t g_wg_inner_queues[WG_MAX_PEERS + 1] = {0};

/* -----------------------------------------------------------------------
 * Peer endpoint table — Ada-owned (Peer_Table package).
 *
 * Thin C wrappers keep the same local call-sites, but all state
 * lives in Ada.  See wg_peer_table.h for the Ada FFI.
 * ----------------------------------------------------------------------- */

static void update_peer_endpoint(unsigned int peer,
                                 const struct sockaddr_in *addr)
{
    wg_peer_update_endpoint(peer, addr->sin_addr.s_addr, addr->sin_port);
}

static struct sockaddr_in get_peer_endpoint(unsigned int peer)
{
    struct sockaddr_in ep = {0};
    uint32_t addr;
    uint16_t port;
    if (wg_peer_get_endpoint(peer, &addr, &port)) {
        ep.sin_family = AF_INET;
        ep.sin_addr.s_addr = addr;
        ep.sin_port = port;
    }
    return ep;
}

bool wg_task_get_peer_endpoint(unsigned int peer, struct sockaddr_in *out)
{
    if (out == NULL) {
        return false;
    }

    struct sockaddr_in ep = get_peer_endpoint(peer);
    if (ep.sin_family != AF_INET || ep.sin_port == 0) {
        return false;
    }

    *out = ep;
    return true;
}

/* -----------------------------------------------------------------------
 * Re-arm peer timer after an Ada state-mutating call.
 *
 * Each Ada entry point that touches per-peer session state
 * (wg_send, wg_auto_handshake, wg_create_response, wg_receive_netif)
 * can shift a peer's next deadline — e.g. a fresh Last_Sent extends
 * keepalive, a completed handshake sets Created_At.  Without this
 * helper, the timer manager keeps firing at the deadline armed by
 * wg_urgent's previous wake (at most 1 s old), so the *acted* state
 * change lags by up to 1 s.
 *
 * Calls session_next_deadline (lock + Next_Deadline read, no Tick),
 * then arms the peer's esp_timer.  Caps at WG_REARM_FALLBACK_MS to
 * keep the wg_urgent-driven safety recheck cadence even when Ada
 * returns Never (counter-driven triggers, etc.).
 *
 * Concurrency: wg_timer_manager_arm is now serialized internally
 * against wg_urgent's concurrent arms via taskENTER_CRITICAL.
 * --------------------------------------------------------------------- */

#define WG_REARM_FALLBACK_MS  1000

static void rearm_peer_timer(unsigned int peer)
{
    if (peer == 0 || peer > WG_MAX_PEERS) {
        return;
    }

    uint64_t now_s          = wg_clock_now();
    uint64_t next_deadline_s = 0;
    session_next_deadline(peer, now_s, &next_deadline_s);

    int64_t now_ms = wg_clock_now_ms();
    int64_t next_deadline_ms;
    if (next_deadline_s != 0) {
        next_deadline_ms = (int64_t)next_deadline_s * 1000;
        int64_t fallback_ms = now_ms + WG_REARM_FALLBACK_MS;
        if (next_deadline_ms > fallback_ms) {
            next_deadline_ms = fallback_ms;
        }
        if (next_deadline_ms < now_ms + 1) {
            next_deadline_ms = now_ms + 1;
        }
    } else {
        next_deadline_ms = now_ms + WG_REARM_FALLBACK_MS;
    }
    (void)wg_timer_manager_arm(peer, next_deadline_ms);
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

static void wg_task(void *pvParameters)
{
    (void)pvParameters;
    wg_rx_msg_t rx_msg;
    wg_inner_msg_t inner_msg;

    ESP_LOGI(TAG, "WireGuard protocol task running");

    while (1)
    {
        /* Timer-driven actions (keepalive, rekey, expiry, zeroing) are
         * now handled by the wg_urgent task via wg_timer_manager. The
         * legacy session_tick_all() polling block was removed in
         * Phase 3 of docs/timer_driven_urgent_queue_design.md. */

        // Per-peer inner TX queues: for each peer, if data is pending,
        // either drain+encrypt (session active) or auto-handshake.
        // Each peer has its own queue, eliminating head-of-line blocking
        // where one inactive peer would stall another peer's traffic.
        for (unsigned int peer = 1; peer <= WG_MAX_PEERS; peer++)
        {
            if (uxQueueMessagesWaiting(g_wg_inner_queues[peer]) == 0)
            {
                continue;
            }

            if (wg_session_is_active(peer))
            {
                // Session active — drain and encrypt
                while (xQueueReceive(g_wg_inner_queues[peer], &inner_msg, 0)
                       == pdTRUE)
                {
                    uint16_t tx_len = 0;
                    packet_buffer_t *tx_pkt =
                        (packet_buffer_t *)wg_send(
                            peer,
                            inner_msg.buf->data + WG_TRANSPORT_HEADER_SIZE,
                            inner_msg.pt_len,
                            &tx_len);

                    tx_pool_free(inner_msg.buf);
                    rearm_peer_timer(peer);

                    if (tx_pkt == NULL || tx_len == 0)
                    {
                        ESP_LOGW(TAG, "wg_send failed for peer %u", peer);
                        continue;
                    }

                    struct sockaddr_in endpoint = get_peer_endpoint(peer);
                    if (!send_outer_packet(tx_pkt, tx_len, &endpoint)) {
                        ESP_LOGW(TAG,
                                 "Failed to send encrypted packet for peer %u",
                                 peer);
                    }
                }
            }
            else
            {
                // No session — ask Ada to auto-initiate for this peer
                void *init_pkt = NULL;
                uint16_t init_len = 0;
                wg_auto_handshake(peer, &init_pkt, &init_len);
                rearm_peer_timer(peer);
                if (init_pkt != NULL && init_len > 0)
                {
                    struct sockaddr_in endpoint = get_peer_endpoint(peer);
                    ESP_LOGI(TAG,
                             "Auto-initiating handshake for peer %u "
                             "(inner data pending)", peer);
                    send_outer_packet((packet_buffer_t *)init_pkt,
                                      init_len, &endpoint);
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
        // Ada also returns the 1-based peer index via peer_out.
        uint16_t pt_len = 0;
        unsigned int rx_peer = 0;
        wg_action_t action = wg_receive_netif(rx_buf, &pt_len, &rx_peer);
        // rx_buf ownership: returned to C only on RX_DECRYPTION_SUCCESS;
        // Ada has freed it for all other return values.

        // §6.5: update endpoint from authenticated packets only.
        // Any non-error return means crypto verification passed.
        if (action != WG_ACTION_ERROR && rx_peer != 0) {
            update_peer_endpoint(rx_peer, &rx_msg.peer);
            // Any authenticated RX may have shifted this peer's
            // next deadline (Last_Received, handshake completion,
            // etc.); arm before any further Ada calls below so the
            // re-arm reflects post-receive state.
            rearm_peer_timer(rx_peer);
        }

        switch (action)
        {
        case WG_ACTION_SEND_RESPONSE:
        {
            // Initiation processed — build and send the response
            uint16_t resp_len = 0;
            packet_buffer_t *resp_pkt =
                (packet_buffer_t *)wg_create_response(&resp_len);
            rearm_peer_timer(rx_peer);

            if (resp_pkt == NULL || resp_len == 0)
            {
                ESP_LOGE(TAG, "wg_create_response failed");
                break;
            }

            ESP_LOGI(TAG, "<< Handshake Response (%u bytes) for peer %u",
                     resp_len, rx_peer);

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
            ESP_LOGD(TAG, "Decrypted Transport Data (%u plaintext) from peer %u",
                     pt_len, rx_peer);

            // Echo mode: re-encrypt and send back (test-only)
            if (wg_echo_enabled())
            {
                // For echo we copy the plaintext into wg_send, then free rx_buf.
                uint16_t tx_len = 0;
                packet_buffer_t *tx_pkt =
                    (packet_buffer_t *)wg_send(
                        rx_peer,
                        rx_buf->data + WG_TRANSPORT_HEADER_SIZE,
                        pt_len,
                        &tx_len);

                // Done with RX buffer
                rx_pool_free(rx_buf);
                rearm_peer_timer(rx_peer);

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
            ESP_LOGI(TAG, "<< Processed (no reply needed) for peer %u",
                     rx_peer);
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

    // Per-peer inner queues (1-indexed; slot 0 stays NULL)
    for (unsigned int i = 0; i < WG_MAX_PEERS; i++) {
        g_wg_inner_queues[i + 1] = xQueueCreateStatic(
            INNER_QUEUE_DEPTH, sizeof(wg_inner_msg_t),
            s_inner_queue_storage[i], &s_inner_queue_bufs[i]);
    }

    // Initialize pools with static semaphores and Ada subsystem structures
    packet_pool_init();

    // Create session mutex and initialize session tables (must precede wg_init)
    wg_session_init();

    if (!wg_init())
    {
        ESP_LOGE(TAG, "wg_init() failed — check keys in sdkconfig");
        return false;
    }

    /* Create per-peer esp_timer handles. The wg_urgent task is not
     * yet running, so callbacks (if any are armed before then) will
     * just update the pending mask. */
    if (!wg_timer_manager_init())
    {
        ESP_LOGE(TAG, "wg_timer_manager_init() failed");
        return false;
    }

    ESP_LOGI(TAG, "WireGuard initialized: %zu buffers of %zu bytes per pool",
             packet_pool_get_pool_size(), packet_pool_get_buffer_size());

    return true;
}

bool wg_task_start(void)
{
    /* Spawn the urgent task first so that by the time the transport
     * task starts arming peer timers, expiries can already be
     * delivered. wg_urgent_task_start() also registers the new task
     * with the timer manager. */
    if (!wg_urgent_task_start())
    {
        return false;
    }

    BaseType_t ret = xTaskCreate(
        wg_task,
        "wg_proto",
        12288,
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
