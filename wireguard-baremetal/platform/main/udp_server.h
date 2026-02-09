/**
 * @file udp_server.h
 * @brief UDP I/O thread -- pure socket I/O, no protocol logic.
 *
 * Receives packets via recvfrom(), enqueues to the WG protocol task,
 * dequeues TX results and sends via sendto().
 *
 * Requires wg_task_start() to have been called first.
 */

#ifndef UDP_SERVER_H
#define UDP_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * FreeRTOS task function for the UDP I/O thread.
 *
 * Binds to port 51820, runs the recvfrom/sendto loop.
 * Pass to xTaskCreate() after wg_task_start() succeeds.
 */
void udp_server_task(void *pvParameters);

#ifdef __cplusplus
}
#endif

#endif /* UDP_SERVER_H */
