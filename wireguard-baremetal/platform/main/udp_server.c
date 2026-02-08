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
/* Ada WireGuard protocol — single entry point */
#include "wireguard.h"

#define PORT 51820

static const char *TAG = "wg_srv";

/* Test-only: triggers ESP32-initiated handshake back to the sender */
#define WG_MSG_TRIGGER_INITIATION 0xFF

/*
 * WireGuard ESP32-C6 — UDP I/O Driver
 *
 * Architecture:
 *   Ada/SPARK core owns ALL protocol logic and state.
 *   C is a dumb I/O driver: receive bytes → wg_receive() → sendto().
 *
 * This file orchestrates:
 *   1. wg_init() — load keys, initialize pools
 *   2. Main event loop: recvfrom → wg_receive → sendto if needed
 *
 * Buffer ownership:
 *   - After recvfrom: C owns the RX pool buffer
 *   - After wg_receive: Ada owns it (freed internally)
 *   - If wg_receive returns SEND_*: C gets a TX buffer, must free after send
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

        /* Check for test-only trigger before handing to Ada */
        uint8_t msg_type = pkt->data[0];

        if (msg_type == WG_MSG_TRIGGER_INITIATION)
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
                continue;
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
            continue;
        }

        /*
         * Hand the packet to Ada. Ada takes ownership of pkt (freed
         * internally). On SEND actions, Ada returns a TX pool buffer
         * for us to transmit.
         */
        void *tx_pkt = NULL;
        uint16_t tx_len = 0;
        wg_action_t action = wg_receive(pkt, &tx_pkt, &tx_len);
        /* pkt is now owned by Ada — do NOT rx_pool_free(pkt) */

        switch (action)
        {
        case WG_ACTION_SEND_RESPONSE:
            ESP_LOGI(TAG, "<< Handshake Response (%u bytes)", tx_len);
            ESP_LOG_BUFFER_HEXDUMP(TAG, ((packet_buffer_t *)tx_pkt)->data,
                                   tx_len, ESP_LOG_INFO);
            /* fall through */
        case WG_ACTION_SEND_TRANSPORT:
        {
            if (action == WG_ACTION_SEND_TRANSPORT)
                ESP_LOGI(TAG, "<< Transport Data (%u bytes)", tx_len);

            int sent = sendto(sock,
                              ((packet_buffer_t *)tx_pkt)->data,
                              tx_len, 0,
                              (struct sockaddr *)&source_addr,
                              sizeof(struct sockaddr_in));
            if (sent < 0)
            {
                ESP_LOGE(TAG, "sendto failed: errno %d", errno);
            }
            tx_pool_free((packet_buffer_t *)tx_pkt);
            break;
        }

        case WG_ACTION_NONE:
            ESP_LOGI(TAG, "   Processed (no reply needed)");
            break;

        case WG_ACTION_ERROR:
        default:
            ESP_LOGW(TAG, "   wg_receive error (type 0x%02x, %d bytes)",
                     msg_type, len);
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
