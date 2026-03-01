/**
 * @file wg_commands.h
 * @brief Test-suite command dispatcher.
 *
 * The Python integration tests inject commands as RX packets with a
 * synthetic message type in byte 0.  The WG task checks for these
 * before handing real WireGuard packets to Ada.
 *
 * Each command ID occupies the 0x80-0xFF range (bit 7 set) so they
 * never collide with WireGuard message types (1-4).
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "wg_task.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------
 * Command IDs  (byte 0 of the injected RX packet)
 * ------------------------------------------------------------------- */

#define WG_CMD_INITIATE_HANDSHAKE  0xFF
#define WG_CMD_SET_ECHO_MODE       0xFE
#define WG_CMD_INJECT_INNER        0xFD

/* -------------------------------------------------------------------
 * API
 * ------------------------------------------------------------------- */

/**
 * Is this message type a test command rather than a real WG packet?
 */
static inline bool wg_is_command(uint8_t msg_type)
{
    return (msg_type & 0x80) != 0;
}

/**
 * Is transport echo mode enabled?
 * When true, wg_task echoes decrypted transport data back to sender.
 * Default: false (off).  Toggled by WG_CMD_SET_ECHO_MODE.
 */
bool wg_echo_enabled(void);

/**
 * Dispatch a test command.
 *
 * The caller has already dequeued the wg_rx_msg_t.  This function
 * frees the RX buffer and handles the command (may enqueue TX).
 *
 * @param cmd     Command byte (msg_type with bit 7 set).
 * @param rx_msg  The full RX message (buffer + peer address).
 */
void wg_command_dispatch(uint8_t cmd, const wg_rx_msg_t *rx_msg);

#ifdef __cplusplus
}
#endif
