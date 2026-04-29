/**
 * @file wg_urgent_task.c
 * @brief WireGuard urgent control task — see wg_urgent_task.h.
 */

#include "wg_urgent_task.h"
#include "wg_clock.h"
#include "wg_netif.h"
#include "wg_sessions.h"        /* WG_MAX_PEERS, session_on_peer_timer_due */
#include "wg_task.h"            /* wg_task_get_peer_endpoint */
#include "wg_timer_manager.h"
#include "wireguard.h"          /* wg_dispatch_timer */
#include "packet_pool.h"        /* packet_buffer_t, tx_pool_free */

#include <stdint.h>

#include <esp_log.h>

#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

static const char *TAG = "wg_urgent";

#define WG_URGENT_TASK_STACK     4096
#define WG_URGENT_TASK_PRIORITY  7   /* one above wg_proto (6) */

static TaskHandle_t s_urgent_task;

/* -----------------------------------------------------------------------
 * send_outer_packet — transmit then free.
 *
 * Mirrors the helper in wg_task.c: wg_netif_send_outer uses PBUF_REF
 * and calls tx_pool_free via the pbuf_custom callback on success. On
 * failure the buffer was never handed to lwIP, so we free it here.
 * --------------------------------------------------------------------- */

static bool send_outer_packet(packet_buffer_t *pkt,
                              uint16_t len,
                              const struct sockaddr_in *peer)
{
    if (pkt == NULL || len == 0 || peer == NULL) {
        return false;
    }

    if (!wg_netif_send_outer(pkt, len, peer)) {
        tx_pool_free(pkt);
        return false;
    }

    return true;
}

/* -----------------------------------------------------------------------
 * Per-peer due handler
 *
 * Evaluates the peer's current timer action via Ada (single-peer
 * locked tick) and dispatches via wg_dispatch_timer. Any resulting
 * outer packet is sent on the peer's last-known endpoint. The peer's
 * timer is then re-armed for the next recheck deadline so we keep
 * producing wakeups until Ada returns next-deadline intents.
 *
 * Mutex discipline: session_on_peer_timer_due and wg_dispatch_timer
 * each take/release the Ada session mutex internally. The send and
 * the timer rearm happen outside any Ada lock.
 * --------------------------------------------------------------------- */

static void handle_peer_due(unsigned int peer)
{
    uint64_t now_s = wg_clock_now();
    uint8_t  action = WG_TIMER_NO_ACTION;
    uint64_t next_deadline_s = 0;

    session_on_peer_timer_due(peer, now_s, &action, &next_deadline_s);

    if (action != WG_TIMER_NO_ACTION) {
        void *tx_buf = NULL;
        uint16_t tx_len = 0;

        wg_dispatch_timer(peer, action, &tx_buf, &tx_len);

        switch (action) {
        case WG_TIMER_SEND_KEEPALIVE:
            ESP_LOGI(TAG, "Peer %u: keepalive sent", peer);
            break;
        case WG_TIMER_INITIATE_REKEY:
            ESP_LOGI(TAG, "Peer %u: initiating rekey", peer);
            break;
        case WG_TIMER_REKEY_TIMED_OUT:
            ESP_LOGW(TAG, "Peer %u: rekey timed out", peer);
            break;
        case WG_TIMER_SESSION_EXPIRED:
            ESP_LOGW(TAG, "Peer %u: session expired", peer);
            break;
        default:
            break;
        }

        if (tx_buf != NULL && tx_len > 0) {
            struct sockaddr_in endpoint;
            if (wg_task_get_peer_endpoint(peer, &endpoint)) {
                if (!send_outer_packet((packet_buffer_t *)tx_buf,
                                       tx_len, &endpoint)) {
                    ESP_LOGW(TAG, "Peer %u: timer-initiated send failed",
                             peer);
                }
            } else {
                ESP_LOGW(TAG, "Peer %u: no endpoint for timer-initiated send",
                         peer);
                tx_pool_free((packet_buffer_t *)tx_buf);
            }
        }
    }

    /* Rearm at the precise deadline Ada gave us.  Next_Deadline now
     * folds counter-driven triggers into Now, so we no longer need a
     * periodic recheck cap.  If Ada returned Never, leave the peer
     * disarmed — the next state change in wg_proto (wg_send,
     * wg_auto_handshake, wg_receive_netif, wg_create_response) will
     * call rearm_peer_timer and bring the timer back online. */
    if (next_deadline_s == 0) {
        return;
    }
    int64_t now_ms          = wg_clock_now_ms();
    int64_t next_deadline_ms = (int64_t)next_deadline_s * 1000;
    if (next_deadline_ms < now_ms + 1) {
        next_deadline_ms = now_ms + 1;
    }
    (void)wg_timer_manager_arm(peer, next_deadline_ms);
}

/* -----------------------------------------------------------------------
 * Task body
 * --------------------------------------------------------------------- */

static void wg_urgent_task(void *arg)
{
    (void)arg;
    ESP_LOGI(TAG, "wg_urgent task running (prio=%d)",
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

            handle_peer_due(peer);
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

    /* No bootstrap arm: peers come online when wg_proto first calls
     * rearm_peer_timer (after wg_auto_handshake on queued inner data,
     * or after wg_receive_netif on incoming UDP).  An Inactive peer
     * with no traffic has no time-based deadline and does not need a
     * timer. */

    return true;
}
