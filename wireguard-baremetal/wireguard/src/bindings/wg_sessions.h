/**
 * wg_sessions.h - Session table initialization
 *
 * C owns the static binary semaphore for the session table mutex.
 * Call wg_session_init() once at startup (after packet_pool_init,
 * before wg_init) to create the semaphore and initialize the Ada
 * session table.
 *
 * The semaphore handle is passed into Ada's session_init(), which
 * stores it for all subsequent Lock/Unlock operations.
 */
#pragma once

/**
 * Create the session table semaphore and initialize all session state.
 * Must be called once at startup, before any WireGuard protocol operations.
 */
void wg_session_init(void);
