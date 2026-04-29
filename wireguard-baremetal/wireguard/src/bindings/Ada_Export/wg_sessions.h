/**
 * wg_sessions.h - Session table management (C interface to Ada)
 *
 * Initialization:
 *   wg_session_init()      — C owns the static binary semaphore, creates it,
 *                             passes handle into Ada's Session.Init.
 *
 * Timer tick (called by WG task inline):
 *   session_tick_all()     — Ada evaluates all peer timers under mutex.
 *
 * Session query:
 *   wg_session_is_active() — Check if a peer has a valid current keypair.
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
 * Timer tick — Ada-exported (called by WG task inline)
 * -------------------------------------------------------------------- */

/**
 * Max peers — must match Ada Session.Max_Peers.
 */
#define WG_MAX_PEERS 2

/**
 * Per-peer timer action — flat enum matching Ada Timer_Action.
 * 0=none, 1=keepalive, 2=rekey, 3=rekey_timeout, 4=expired.
 */
typedef enum {
    WG_TIMER_NO_ACTION       = 0,
    WG_TIMER_SEND_KEEPALIVE  = 1,
    WG_TIMER_INITIATE_REKEY  = 2,
    WG_TIMER_REKEY_TIMED_OUT = 3,
    WG_TIMER_SESSION_EXPIRED = 4,
} wg_timer_action_t;

/**
 * Evaluate all peer timers under a single session-mutex hold.
 * Fills actions[0..WG_MAX_PEERS-1].  C index 0 = Ada Peer 1.
 *
 * @param now      Monotonic clock value (microseconds).
 * @param actions  Output array of per-peer timer actions.
 */
void session_tick_all(uint64_t now, uint8_t actions[]);

/**
 * Single-peer timer evaluation, taken when the timer-driven urgent
 * path marks one peer as due. Equivalent to extracting the relevant
 * slot from session_tick_all() but without the per-peer scan.
 *
 * Acquires the session mutex internally and snapshots the peer's
 * current action AND its next time-based deadline atomically.
 *
 * @param peer                 1-based peer index (Ada Session.Peer_Index).
 * @param now                  Monotonic clock value (seconds).
 * @param out_action           Output: per-peer timer action
 *                             (wg_timer_action_t enum).
 * @param out_next_deadline_s  Output: earliest absolute Now (seconds)
 *                             at which the caller should re-evaluate
 *                             this peer.  0 means "no time-based
 *                             deadline meaningful right now"
 *                             (Timer.Clock.Never); the caller should
 *                             fall back to its periodic recheck.
 *                             Counter-driven triggers (Send_Counter
 *                             limits) are NOT modelled by this value.
 *
 * If peer is out of range or either output pointer is NULL, no
 * action is performed.  If only peer is out of range, both outputs
 * are set to 0.
 */
void session_on_peer_timer_due(unsigned int peer,
                               uint64_t now,
                               uint8_t  *out_action,
                               uint64_t *out_next_deadline_s);

/**
 * Single-peer next-deadline query.  Used by the wg_proto task to
 * re-arm a peer's esp_timer right after each Ada state-mutating
 * call (wg_send, wg_auto_handshake, wg_create_response,
 * wg_receive_netif), so the deadline tracks the freshest peer
 * state without waiting for the next wg_urgent recheck.
 *
 * Acquires the session mutex internally.
 *
 * @param peer                 1-based peer index.
 * @param now                  Monotonic clock value (seconds).
 * @param out_next_deadline_s  Output: earliest absolute Now
 *                             (seconds) at which the peer should be
 *                             re-evaluated, or 0 for "no time-based
 *                             deadline meaningful" (Never).
 *
 * If peer is out of range, *out_next_deadline_s is set to 0.  If
 * out_next_deadline_s is NULL the call is a no-op.
 */
void session_next_deadline(unsigned int peer,
                           uint64_t now,
                           uint64_t *out_next_deadline_s);

/* --------------------------------------------------------------------
 * Session query
 * -------------------------------------------------------------------- */

/**
 * Check whether a peer has a valid current session keypair.
 * Thread-safe: acquires session mutex internally.
 *
 * @param peer  1-based peer index (Ada Session.Peer_Index).
 * @return      Non-zero if session is active, 0 otherwise.
 */
uint8_t wg_session_is_active(unsigned int peer);

#ifdef __cplusplus
}
#endif
