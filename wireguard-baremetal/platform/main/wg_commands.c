/**
 * @file wg_commands.c
 * @brief Test-suite command dispatcher.
 *
 * Adding a new command:
 *   1. #define WG_CMD_FOO 0xNN in wg_commands.h
 *   2. Write a static cmd_foo() handler below.
 *   3. Add the case to wg_command_dispatch().
 */

#include "wg_commands.h"
#include "wireguard.h"
#include "wg_sessions.h" /* WG_MAX_PEERS */
#include "packet_pool.h"
#include "wg_netif.h"
#include "wg_peer_table.h"

#include <string.h>
#include <unistd.h>     /* close() */

#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <lwip/def.h>    /* ntohl */
#include <lwip/sockets.h> /* socket, sendto */

static const char *TAG = "wg_cmd";

/* -------------------------------------------------------------------
 * Echo mode flag (default off)
 * ------------------------------------------------------------------- */

static bool s_echo_enabled = false;

bool wg_echo_enabled(void)
{
    return s_echo_enabled;
}

/* -------------------------------------------------------------------
 * Command handlers
 * ------------------------------------------------------------------- */

/**
 * 0xFF — Initiate an ESP32-side handshake.
 *
 * Wire format:  [0xFF] [peer_id:1 (optional, default 1)]
 *
 * The trigger packet carried no WireGuard payload; it just tells us
 * to build an initiation and send it to the peer that sent the trigger.
 */
static void cmd_initiate_handshake(const wg_rx_msg_t *rx_msg, uint16_t len)
{
    /* Optional peer index byte — default to peer 1 for backward compat */
    unsigned int peer = 1;
    if (len >= 2) {
        peer = rx_msg->rx_buf->data[1];
        if (peer == 0 || peer > WG_MAX_PEERS) {
            ESP_LOGW(TAG, "CMD_INITIATE: invalid peer %u", peer);
            return;
        }
    }

    ESP_LOGI(TAG, ">> CMD: Initiate handshake (peer %u)", peer);

    uint16_t init_len = 0;
    packet_buffer_t *init_pkt =
        (packet_buffer_t *)wg_create_initiation(peer, &init_len);

    if (init_pkt == NULL || init_len == 0)
    {
        ESP_LOGE(TAG, "wg_create_initiation failed");
        return;
    }

    ESP_LOGI(TAG, "<< Handshake Initiation (%u bytes)", init_len);

    if (!wg_netif_send_outer(init_pkt, init_len, &rx_msg->peer))
    {
        /* Ownership NOT transferred on failure — free here */
        tx_pool_free(init_pkt);
        ESP_LOGE(TAG, "Failed to send initiation");
        return;
    }

    /* Ownership transferred to pbuf_custom callback — do NOT free here */
}

/**
 * 0xFE — Set echo mode.
 *
 * Payload byte 1: 0x01 = enable, 0x00 = disable.
 * When enabled, wg_task echoes decrypted transport data back to the
 * sender.  When disabled (default), received data is consumed silently.
 */
static void cmd_set_echo_mode(const wg_rx_msg_t *rx_msg, uint16_t len)
{
    bool enable = (len >= 2) && (rx_msg->rx_buf->data[1] != 0);
    s_echo_enabled = enable;
    ESP_LOGI(TAG, ">> CMD: Echo mode %s", enable ? "ON" : "OFF");
}

/**
 * 0xFD — Inject application data through the wg0 netif via BSD socket.
 *
 * Wire format:  [0xFD] [dest_ip:4 NBO] [dest_port:2 NBO] [payload...]
 *
 * The handler opens a UDP socket and sendto(dest_ip:dest_port, payload),
 * which lwIP routes through the wg0 netif.  This exercises the real
 * application data path:  sendto → lwIP → wg_netif_output → inner queue.
 *
 * Before sending, the handler records the command sender's outer UDP
 * address as the peer endpoint so auto-handshake knows where to send
 * the initiation.
 */
static void cmd_inject_inner(const wg_rx_msg_t *rx_msg, uint16_t len)
{
    /* Minimum: cmd(1) + dest_ip(4) + dest_port(2) = 7 */
    if (len < 7) {
        ESP_LOGW(TAG, "CMD_INJECT_INNER: too short (%u)", len);
        return;
    }

    const uint8_t *data = rx_msg->rx_buf->data;
    uint32_t dest_ip_nbo;
    uint16_t dest_port_nbo;
    memcpy(&dest_ip_nbo,   data + 1, 4);
    memcpy(&dest_port_nbo, data + 5, 2);

    const uint8_t *payload = data + 7;
    uint16_t payload_len = len - 7;

    ESP_LOGI(TAG, ">> CMD: Inject inner (%u bytes)", payload_len);

    /* AllowedIPs lookup on the tunnel destination IP */
    unsigned int peer = wg_peer_lookup_by_ip(ntohl(dest_ip_nbo));
    if (peer == 0) {
        ESP_LOGW(TAG, "CMD_INJECT_INNER: no peer for dest IP");
        return;
    }

    /* Record the sender's outer UDP address as the peer endpoint */
    wg_peer_update_endpoint(peer,
                            rx_msg->peer.sin_addr.s_addr,
                            rx_msg->peer.sin_port);

    /* Send through BSD socket → lwIP → wg_netif_output → inner queue */
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) {
        ESP_LOGW(TAG, "CMD_INJECT_INNER: socket() failed");
        return;
    }

    struct sockaddr_in dest = {
        .sin_family      = AF_INET,
        .sin_port        = dest_port_nbo,
        .sin_addr.s_addr = dest_ip_nbo,
    };

    ssize_t sent = sendto(sock, payload, payload_len, 0,
                          (struct sockaddr *)&dest, sizeof(dest));
    close(sock);

    if (sent < 0) {
        ESP_LOGW(TAG, "CMD_INJECT_INNER: sendto() failed: %d", errno);
        return;
    }

    ESP_LOGI(TAG, "<< Injected %u bytes via wg0 (peer %u)",
             payload_len, peer);
}

/* -------------------------------------------------------------------
 * Dispatcher
 * ------------------------------------------------------------------- */

void wg_command_dispatch(uint8_t cmd, const wg_rx_msg_t *rx_msg)
{
    // Save length before freeing — some commands inspect payload
    uint16_t len = rx_msg->rx_buf->len;

    switch (cmd)
    {
    case WG_CMD_INITIATE_HANDSHAKE:
        cmd_initiate_handshake(rx_msg, len);
        rx_pool_free(rx_msg->rx_buf);
        break;

    case WG_CMD_SET_ECHO_MODE:
        cmd_set_echo_mode(rx_msg, len);
        rx_pool_free(rx_msg->rx_buf);
        break;

    case WG_CMD_INJECT_INNER:
        cmd_inject_inner(rx_msg, len);
        rx_pool_free(rx_msg->rx_buf);
        break;

    default:
        rx_pool_free(rx_msg->rx_buf);
        ESP_LOGW(TAG, "Unknown command 0x%02x — ignored", cmd);
        break;
    }
}
