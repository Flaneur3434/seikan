#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>

// BSD socket functions and  data structures
#include <sys/socket.h>
// Address family and protocal information
#include <netinet/in.h>
// Functions for manipulating numeric IP addresses
#include <arpa/inet.h>

#include <esp_log.h>

// FreeRTOS
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// Ada memory pool for zero-copy packet buffers
#include "packet_pool.h"

#define PORT 51820

static const char *TAG = "udp srv";

/*
 * WireGuard ESP32-C6 Application Entry Point
 *
 * Architecture:
 *   Ada/SPARK core owns protocol logic and state
 *   C layer provides hardware I/O and driver integration
 *
 * This file orchestrates:
 *   1. Hardware initialization
 *   2. Main event loop calling Ada core
 *   3. Packet RX/TX with network driver
 */

/*
 * External Ada ABI - defined in bindings/
 */
extern void wg_receive_bytes(const uint8_t *buf, size_t len);
extern size_t wg_prepare_tx(uint8_t *out, size_t max_len);

void udp_server_task(void *pvParameters)
{
    (void)pvParameters;

    char addr_str[128];

    // Initialize Ada packet pool
    packet_pool_init();
    ESP_LOGI(TAG, "Packet pool initialized: %zu buffers of %zu bytes",
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

    // Increase RX buffer size with SO_RCVBUF in the future if needed
    // UDP drops happen when the socket receive queue fills.
    // More buffer = more burst absorption

    // Increase TX buffer size with SO_SNDBUF in the future if needed
    // Useful if enqueuing a burst of outgoing packets (handshake
    // bursts, keepalives across many peers, etc.).

    // SO_TIMESTAMP / SO_TIMESTAMPNS can provide per-packet timestamps

    // Use connect()

    // Tweak LwIP settings form menuconfig in future too if needed

    // Set timeout
    struct timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);

    // Binds a local address + port
    int err = bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
    if (err < 0)
    {
        ESP_LOGE(TAG, "Socket unable to bind: errno %d", errno);
    }
    ESP_LOGI(TAG, "Socket bound, port %d", PORT);

    // TODO: Use connect() to set default remote peer
    // Filter incoming packets, restrict to default peer
    // Slightly cheaper send/receive path
    // Better error reporting
    // Need to reconnect if endpoint changes

    struct sockaddr_storage source_addr; // Large enough for both IPv4 or IPv6
    socklen_t socklen = sizeof(source_addr);

    while (1)
    {
        ESP_LOGI(TAG, "Waiting for data");

        // Allocate buffer from Ada pool (O(1) operation)
        packet_buffer_t *pkt = packet_pool_allocate();
        if (pkt == NULL)
        {
            ESP_LOGE(TAG, "Packet pool exhausted!");
            vTaskDelay(pdMS_TO_TICKS(100));  // Back off and retry
            continue;
        }

        size_t buf_size = packet_pool_get_buffer_size();

        // Haven't setup connect() yet, so can receive packets from any IP
        int len = recvfrom(sock, pkt->data, buf_size, 0, (struct sockaddr *)&source_addr, &socklen);
        // Error occurred on receiving
        if (len < 0)
        {
            ESP_LOGE(TAG, "recvfrom failed: errno %d", errno);
            packet_pool_free(pkt);  // Return buffer to pool
            break;
        }
        // Data received
        else
        {
            // Get the sender's ip address as string
            if (source_addr.ss_family == PF_INET)
            {
                inet_ntoa_r(((struct sockaddr_in *)&source_addr)->sin_addr, addr_str, sizeof(addr_str) - 1);
            }
            else
            {
                ESP_LOGE(TAG, "Haven't setup IPv6, exiting program ...");
                packet_pool_free(pkt);
                break;
            }

            ESP_LOGI(TAG, "Received %d bytes from %s:", len, addr_str);
            ESP_LOG_BUFFER_HEXDUMP(TAG, pkt->data, len, ESP_LOG_INFO);

            // Echo back packet using zero-copy buffer
            int err = sendto(sock, pkt->data, len, 0, (struct sockaddr *)&source_addr, sizeof(source_addr));
            if (err < 0)
            {
                ESP_LOGE(TAG, "Error occurred during sending: errno %d", errno);
                packet_pool_free(pkt);
                break;
            }

            // Return buffer to pool (O(1) operation)
            packet_pool_free(pkt);
        }
    }

    if (sock != -1)
    {
        ESP_LOGE(TAG, "Shutting down socket and restarting ...");
        shutdown(sock, 0);
        close(sock);
    }
}
