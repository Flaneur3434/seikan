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
#include "packet_pool.h"
#include "wg_netif.h"
#include "wg_peer_table.h"

#include <string.h>

#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>
#include <lwip/def.h>   /* ntohl */

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
 * The trigger packet carried no WireGuard payload; it just tells us
 * to build an initiation and send it to the peer that sent the trigger.
 */
static void cmd_initiate_handshake(const wg_rx_msg_t *rx_msg)
{
    ESP_LOGI(TAG, ">> CMD: Initiate handshake");

    uint16_t init_len = 0;
    packet_buffer_t *init_pkt =
        (packet_buffer_t *)wg_create_initiation(1, &init_len);

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
 * 0xFD — Inject a synthetic IP packet into the inner (wg0) queue.
 *
 * Payload bytes [1..N] are treated as an IP packet that an application
 * would send through the tunnel.  The handler allocates a TX pool buffer,
 * copies the payload at offset WG_TRANSPORT_HEADER_SIZE (16 bytes headroom),
 * performs an AllowedIPs lookup for the peer, and enqueues to
 * g_wg_inner_queue — the same path as wg_netif_output().
 *
 * This lets the Python test suite trigger the auto-handshake flow:
 *   inject inner → no session → auto_handshake fires → initiation sent.
 */
static void cmd_inject_inner(const wg_rx_msg_t *rx_msg, uint16_t len)
{
    ESP_LOGI(TAG, ">> CMD: Inject inner (%u payload bytes)", len - 1);

    if (len < 2) {
        ESP_LOGW(TAG, "CMD_INJECT_INNER: no payload");
        return;
    }

    uint16_t pt_len = len - 1;  /* strip command byte */

    size_t cap = packet_pool_get_buffer_size();
    if ((size_t)pt_len + WG_TRANSPORT_HEADER_SIZE > cap) {
        ESP_LOGW(TAG, "CMD_INJECT_INNER: payload too large: %u", pt_len);
        return;
    }

    packet_buffer_t *buf = tx_pool_allocate();
    if (buf == NULL) {
        ESP_LOGW(TAG, "CMD_INJECT_INNER: TX pool exhausted");
        return;
    }

    /* Copy payload at offset 16 — headroom for WG transport header */
    memcpy(buf->data + WG_TRANSPORT_HEADER_SIZE,
           rx_msg->rx_buf->data + 1, pt_len);
    buf->len = (uint16_t)(WG_TRANSPORT_HEADER_SIZE + pt_len);

    /* AllowedIPs lookup: IPv4 dest at offset 16 in the IP header */
    uint32_t dest_ip_nbo;
    memcpy(&dest_ip_nbo,
           buf->data + WG_TRANSPORT_HEADER_SIZE + 16,
           sizeof(dest_ip_nbo));
    unsigned int peer = wg_peer_lookup_by_ip(ntohl(dest_ip_nbo));
    if (peer == 0) {
        ESP_LOGW(TAG, "CMD_INJECT_INNER: no peer for dest IP");
        tx_pool_free(buf);
        return;
    }

    /* Record the sender's UDP address as this peer's endpoint so the
     * auto-handshake knows where to send the initiation.  Without this,
     * the endpoint is still zeroed and the initiation goes nowhere. */
    wg_peer_update_endpoint(peer,
                            rx_msg->peer.sin_addr.s_addr,
                            rx_msg->peer.sin_port);

    wg_inner_msg_t msg = {
        .buf      = buf,
        .pt_len   = pt_len,
        .peer_idx = (uint16_t)peer,
    };

    if (xQueueSend(g_wg_inner_queue, &msg, 0) != pdTRUE) {
        ESP_LOGW(TAG, "CMD_INJECT_INNER: inner queue full");
        tx_pool_free(buf);
        return;
    }

    ESP_LOGI(TAG, "<< Injected %u bytes to inner queue (peer %u)",
             pt_len, peer);
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
        rx_pool_free(rx_msg->rx_buf);
        cmd_initiate_handshake(rx_msg);
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
