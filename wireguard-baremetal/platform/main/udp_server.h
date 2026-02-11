/**
 * @file udp_server.h
 * @brief UDP I/O thread — pure socket I/O, no protocol logic.
 */

#pragma once

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Spawn the UDP I/O task.
 *
 * Binds to port 51820, runs the recvfrom/sendto loop at priority 5
 * (lowest in the WG pipeline).
 *
 * Must be called after wg_task_init() and wg_task_start().
 *
 * @return true on success, false if xTaskCreate failed.
 */
bool udp_server_task_start(void);

#ifdef __cplusplus
}
#endif
