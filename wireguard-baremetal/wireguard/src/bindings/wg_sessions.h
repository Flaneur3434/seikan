/**
 * wg_sessions.h - Session table management (C interface to Ada)
 *
 * Initialization:
 *   wg_session_init()  — C owns the static binary semaphore, creates it,
 *                         passes handle into Ada's Session.Init.
 *
 * Timer tick (called by timer task, pri 7):
 *   session_tick_all()  — Ada evaluates all peer timers under mutex.
 *
 * Action dispatch (called by WG task, pri 6):
 *   session_expire()           — Wipe all keypair slots.
 *   session_set_rekey_flag()   — Mark rekey in progress.
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* --------------------------------------------------------------------
 * Initialization
 * -------------------------------------------------------------------- */

/**
 * Create the session table semaphore and initialize all session state.
 * Must be called once at startup, before any WireGuard protocol operations.
 */
void wg_session_init(void);

/* --------------------------------------------------------------------
 * Timer action dispatch — Ada-exported functions
 *
 * These are implemented in Ada (WG_Sessions package) and linked
 * by the External_Name pragma.  Declared here so C callers get
 * proper prototypes.
 * -------------------------------------------------------------------- */

/**
 * Wipe all three keypair slots for a peer.
 * Thread-safe: acquires session mutex internally.
 * @param peer  1-based peer index (Ada Session.Peer_Index).
 */
void session_expire(unsigned int peer);

/**
 * Mark rekey in progress before sending initiation.
 * @param peer  1-based peer index.
 * @param now   Monotonic clock value (microseconds).
 */
void session_set_rekey_flag(unsigned int peer, uint64_t now);

#ifdef __cplusplus
}
#endif
