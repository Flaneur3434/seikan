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

#include <esp_log.h>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

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

    default:
        rx_pool_free(rx_msg->rx_buf);
        ESP_LOGW(TAG, "Unknown command 0x%02x — ignored", cmd);
        break;
    }
}
