#include <stddef.h>
#include <stdint.h>

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

/*
 * TODO: Hardware abstraction layer stubs
 *   - wifi_rx_packet()      - fetch received packet from queue
 *   - wifi_tx_packet()      - send packet via DMA
 *   - timer_init()          - start timers for keepalive/timeout
 *   - memory_init()         - allocate buffers
 */

int app_main(void)
{
    /*
     * TODO: Implement ESP-IDF application entry point
     *
     * 1. Initialize hardware (WiFi, DMA, timers)
     * 2. Call Ada initialization (if needed)
     * 3. Enter main loop:
     *    - Poll for RX packets, call wg_receive_bytes()
     *    - Check TX queue, call wg_prepare_tx()
     *    - Handle interrupts / timers
     */

    return 0;
}
