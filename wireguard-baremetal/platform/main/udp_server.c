#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

/* BSD sockets */
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <esp_log.h>

/* FreeRTOS */
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

/* Ada zero-copy memory pools (RX + TX) */
#include "packet_pool.h"
/* Ada WireGuard handshake API */
#include "wg_handshake.h"

#define PORT 51820

static const char *TAG = "wg_srv";

/* WireGuard message types (first byte on the wire) */
#define WG_MSG_INITIATION 1
#define WG_MSG_RESPONSE 2
#define WG_MSG_COOKIE 3
#define WG_MSG_TRANSPORT 4

/* Test-only: triggers ESP32-initiated handshake back to the sender */
#define WG_MSG_TRIGGER_INITIATION 0xFF

/*
 * WireGuard ESP32-C6 — Responder UDP Server
 *
 * Architecture:
 *   Ada/SPARK core owns protocol logic and state
 *   C layer provides hardware I/O and driver integration
 *
 * This file orchestrates:
 *   1. wg_init() — load keys, initialize pools
 *   2. Main event loop: receive -> dispatch on message type -> respond
 *   3. Zero-copy: RX pool for incoming, TX pool for outgoing
 *
 * Ownership rules:
 *   - wg_handle_initiation() takes ownership of the RX buffer (frees it)
 *     and returns a TX buffer that the caller must free via tx_pool_free().
 *   - wg_handle_response() takes ownership of the RX buffer (frees it).
 *   - Unknown messages: caller frees the RX buffer via rx_pool_free().
 */

void udp_server_task(void *pvParameters)
{
    (void)pvParameters;

    char addr_str[128];

    /* Initialize WireGuard handshake subsystem (keys + both pools) */
    if (!wg_init())
    {
        ESP_LOGE(TAG, "wg_init() failed - check keys in sdkconfig");
        return;
    }
    ESP_LOGI(TAG, "WireGuard initialized: %zu buffers of %zu bytes per pool",
             packet_pool_get_pool_size(), packet_pool_get_buffer_size());

    struct sockaddr_in dest_addr = {};
    dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "Unable to create socket: errno %d", errno);
        return;
    }
    ESP_LOGI(TAG, "Socket created");

    /* 10-second receive timeout */
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);

    int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0)
    {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
    }
    ESP_LOGI(TAG, "Socket bound, port %d", PORT);

    struct sockaddr_storage source_addr;
    socklen_t socklen;

    while (1)
    {
        ESP_LOGI(TAG, "Waiting for data");

        /* Allocate RX buffer from pool (O(1)) */
        packet_buffer_t *pkt = rx_pool_allocate();
        if (pkt == NULL)
        {
            ESP_LOGE(TAG, "RX pool exhausted!");
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        size_t buf_size = packet_pool_get_buffer_size();
        socklen = sizeof(source_addr);

        int len = recvfrom(sock, pkt->data, buf_size, 0,
                           (struct sockaddr *)&source_addr, &socklen);

        if (len < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                /* Timeout - no data, loop again */
                rx_pool_free(pkt);
                continue;
            }
            ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
            rx_pool_free(pkt);
            break;
        }

        if (len == 0)
        {
            rx_pool_free(pkt);
            continue;
        }

        /* Get sender address for logging */
        if (source_addr.ss_family == PF_INET)
        {
            inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr,
                        addr_str, sizeof(addr_str) - 1);
        }
        else
        {
            ESP_LOGE(TAG, "IPv6 not supported");
            rx_pool_free(pkt);
            break;
        }

        ESP_LOGI(TAG, "Received %d bytes from %s:", len, addr_str);
        ESP_LOG_BUFFER_HEXDUMP(TAG, pkt->data, len, ESP_LOG_INFO);

        /* Store length in buffer (Ada reads this via Acquire_RX_From_C) */
        pkt->len = (uint16_t)len;

        /* Dispatch on WireGuard message type (first byte) */
        uint8_t msg_type = pkt->data[0];

        switch (msg_type)
        {

        case WG_MSG_INITIATION:
        {
            ESP_LOGI(TAG, ">> Handshake Initiation (%d bytes)", len);

            uint16_t resp_len = 0;
            /*
             * Ada takes ownership of pkt (frees RX internally).
             * Returns a TX pool buffer containing the response.
             */
            packet_buffer_t *tx_pkt =
                (packet_buffer_t *)wg_handle_initiation(pkt, &resp_len);

            if (tx_pkt == NULL)
            {
                ESP_LOGE(TAG, "wg_handle_initiation failed");
                /* pkt already freed by Ada - do NOT rx_pool_free(pkt) */
                break;
            }
            else if (resp_len == 0)
            {
                ESP_LOGE(TAG, "wg_handle_initiation failed, cause resp_len == 0");
                /* pkt already freed by Ada - do NOT rx_pool_free(pkt) */
                break;
            }

            ESP_LOGI(TAG, "<< Handshake Response (%u bytes)", resp_len);
            ESP_LOG_BUFFER_HEXDUMP(TAG, tx_pkt->data, resp_len, ESP_LOG_INFO);

            int sent = sendto(sock, tx_pkt->data, resp_len, 0,
                              (struct sockaddr *)&source_addr,
                              sizeof(struct sockaddr_in));
            if (sent < 0)
            {
                ESP_LOGE(TAG, "sendto failed: errno %d", errno);
            }
            else
            {
                ESP_LOGI(TAG, "Handshake Response sent (%d bytes)", sent);
            }

            /* Return TX buffer to pool */
            tx_pool_free(tx_pkt);
            break;
        }

        case WG_MSG_RESPONSE:
        {
            ESP_LOGI(TAG, ">> Handshake Response (%d bytes)", len);

            /* Ada takes ownership of pkt (frees RX internally) */
            bool ok = wg_handle_response(pkt);

            if (ok)
            {
                ESP_LOGI(TAG, "Handshake complete!");
            }
            else
            {
                ESP_LOGE(TAG, "wg_handle_response failed");
            }
            /* pkt already freed by Ada - do NOT rx_pool_free(pkt) */
            break;
        }

        case WG_MSG_TRIGGER_INITIATION:
        {
            ESP_LOGI(TAG, ">> Trigger: ESP32-initiated handshake");
            /* Free the trigger packet — it carried no payload */
            rx_pool_free(pkt);

            uint16_t init_len = 0;
            packet_buffer_t *init_pkt =
                (packet_buffer_t *)wg_create_initiation(&init_len);

            if (init_pkt == NULL || init_len == 0)
            {
                ESP_LOGE(TAG, "wg_create_initiation failed");
                break;
            }

            ESP_LOGI(TAG, "<< Handshake Initiation (%u bytes)", init_len);
            ESP_LOG_BUFFER_HEXDUMP(TAG, init_pkt->data, init_len, ESP_LOG_INFO);

            int sent = sendto(sock, init_pkt->data, init_len, 0,
                              (struct sockaddr *)&source_addr,
                              sizeof(struct sockaddr_in));
            if (sent < 0)
            {
                ESP_LOGE(TAG, "sendto failed: errno %d", errno);
            }
            else
            {
                ESP_LOGI(TAG, "Handshake Initiation sent (%d bytes)", sent);
            }

            tx_pool_free(init_pkt);
            break;
        }

        default:
            ESP_LOGW(TAG, "Unknown message type: 0x%02x (%d bytes)",
                     msg_type, len);
            rx_pool_free(pkt);
            break;
        }
    }

    if (sock != -1)
    {
        ESP_LOGE(TAG, "Shutting down socket and restarting ...");
        shutdown(sock, 0);
        close(sock);
    }
}
