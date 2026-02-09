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
#include <freertos/queue.h>

/* Ada zero-copy memory pools (RX + TX) */
#include "packet_pool.h"
/* WG protocol task queues */
#include "wg_task.h"

#define PORT 51820

static const char *TAG = "wg_io";

/*
 * WireGuard ESP32-C6 — UDP I/O Thread
 *
 * Pure I/O: no protocol logic, no crypto.
 *
 *   RX: recvfrom -> allocate RX buffer -> enqueue to WG task
 *   TX: dequeue from WG task -> sendto -> free TX buffer
 *
 * Buffer ownership:
 *   - RX: IO allocates, transfers ownership to WG task via queue
 *   - TX: WG task produces, IO receives ownership via queue, frees after send
 */

/**
 * Drain the TX queue: send all pending outbound packets.
 * Non-blocking — returns when the queue is empty.
 */
static void send_pending_tx(int sock)
{
    wg_tx_msg_t tx_msg;

    while (xQueueReceive(g_wg_tx_queue, &tx_msg, 0) == pdTRUE)
    {
        ESP_LOGI(TAG, "<< Sending %u bytes", tx_msg.tx_len);
        // ESP_LOG_BUFFER_HEXDUMP(TAG, tx_msg.tx_buf->data,
        //                        tx_msg.tx_len, ESP_LOG_DEBUG);

        int sent = sendto(sock,
                          tx_msg.tx_buf->data,
                          tx_msg.tx_len, 0,
                          (struct sockaddr *)&tx_msg.peer,
                          sizeof(struct sockaddr_in));
        if (sent < 0)
        {
            ESP_LOGE(TAG, "sendto failed: errno %d", errno);
        }

        tx_pool_free(tx_msg.tx_buf);
    }
}

void udp_server_task(void *pvParameters)
{
    (void)pvParameters;

    char addr_str[128];

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

    /* Short receive timeout so we can service the TX queue regularly */
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 50000; /* 50 ms */
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
        /* ── TX: send any queued outbound packets ── */
        send_pending_tx(sock);

        /* ── RX: try to receive an inbound packet ── */
        packet_buffer_t *pkt = rx_pool_allocate();
        if (pkt == NULL)
        {
            ESP_LOGE(TAG, "RX pool exhausted!");
            vTaskDelay(pdMS_TO_TICKS(10));
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
                /* Timeout — no data, free buffer and loop (services TX) */
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

        /* Log sender */
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

        ESP_LOGI(TAG, "Received %d bytes from %s", len, addr_str);

        /* Fill in length, then hand off to the WG protocol task */
        pkt->len = (uint16_t)len;

        wg_rx_msg_t rx_msg = {
            .rx_buf = pkt,
            .peer   = *(struct sockaddr_in *)&source_addr,
        };

        if (xQueueSend(g_wg_rx_queue, &rx_msg, 0) != pdTRUE)
        {
            ESP_LOGW(TAG, "RX queue full — dropping packet");
            rx_pool_free(pkt);
        }
    }

    if (sock != -1)
    {
        ESP_LOGE(TAG, "Shutting down socket and restarting ...");
        shutdown(sock, 0);
        close(sock);
    }
}
