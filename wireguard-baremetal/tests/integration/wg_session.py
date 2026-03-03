"""WireGuard session timer state machine — Python reference model.

A pure-Python reimplementation of the Ada/SPARK session timer logic from
``session.ads``, ``session.adb``, and ``session-timers.adb``.  This
module serves as an independent test oracle for pytest, mirroring the
three-slot (Current / Previous / Next) keypair model and the timer
tick evaluation exactly.

Protocol timing constants come from the WireGuard whitepaper §6.1–6.4.

This is NOT production code.  It exists solely so that pytest can verify
the timer state machine independently of the embedded target.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field


# ── Protocol constants (from session.ads) ────────────────────────────

MAX_PEERS: int = 2

#  Message counter limits (whitepaper §5.4.6)
REKEY_AFTER_MESSAGES: int = 2 ** 60
REJECT_AFTER_MESSAGES: int = 2 ** 64 - 2 ** 13 - 1

#  Timing constants in seconds (whitepaper §6.1–6.4)
REKEY_AFTER_TIME: int = 120
REJECT_AFTER_TIME: int = 180
REKEY_ATTEMPT_TIME: int = 90
REKEY_TIMEOUT: int = 5
KEEPALIVE_TIMEOUT: int = 10

#  §6.3: erase all keys after 3×Reject_After_Time (540 s)
KEY_ZEROING_AFTER_TIME: int = 3 * REJECT_AFTER_TIME

#  §6.5: unresponsive peer detection threshold (15 s)
NEW_HANDSHAKE_TIME: int = KEEPALIVE_TIMEOUT + REKEY_TIMEOUT

#  Sentinel timestamp: "never happened"
NEVER: int = 0


# ── Timer action (from session-timers.ads) ───────────────────────────

@dataclass
class TimerAction:
    """Result of evaluating one peer's timers for a single tick."""

    send_keepalive: bool = False
    initiate_rekey: bool = False
    session_expired: bool = False
    rekey_timed_out: bool = False
    zero_all_keys: bool = False

    def is_empty(self) -> bool:
        return not (
            self.send_keepalive
            or self.initiate_rekey
            or self.session_expired
            or self.rekey_timed_out
            or self.zero_all_keys
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TimerAction):
            return NotImplemented
        return (
            self.send_keepalive == other.send_keepalive
            and self.initiate_rekey == other.initiate_rekey
            and self.session_expired == other.session_expired
            and self.rekey_timed_out == other.rekey_timed_out
            and self.zero_all_keys == other.zero_all_keys
        )


NO_ACTION = TimerAction()


# ── Keypair (from session.ads private section) ───────────────────────

@dataclass
class Keypair:
    """One direction's transport keys + counters."""

    send_key: bytes = field(default_factory=lambda: bytes(32))
    receive_key: bytes = field(default_factory=lambda: bytes(32))
    sender_index: int = 0
    receiver_index: int = 0
    send_counter: int = 0
    created_at: int = NEVER
    kp_id: int = 0
    valid: bool = False


def null_keypair() -> Keypair:
    """Return a keypair equivalent to Ada's Null_Keypair."""
    return Keypair()


# ── Peer state (from session.ads private section) ────────────────────

@dataclass
class PeerState:
    """Complete per-peer session state with three keypair slots."""

    current: Keypair = field(default_factory=null_keypair)
    previous: Keypair = field(default_factory=null_keypair)
    next_kp: Keypair = field(default_factory=null_keypair)

    last_sent: int = NEVER
    last_data_sent: int = NEVER
    last_received: int = NEVER
    last_handshake: int = NEVER

    rekey_attempted: bool = False
    rekey_attempt_start: int = NEVER
    rekey_last_sent: int = NEVER

    active: bool = False

    # True when we initiated the current session's handshake.
    # Per WireGuard §5.4: only the initiator may do time-based rekeying.
    is_initiator: bool = False

    # Persistent keepalive interval in seconds (0 = disabled).
    # Per WireGuard §6.5: if configured, the peer unconditionally sends
    # an empty transport packet every N seconds to keep NAT mappings open.
    persistent_keepalive_s: int = 0

    # Jitter added to rekey retry interval (0..2 seconds).
    # Per §6.1: prevents lock-step retransmissions between peers.
    # Generated from random byte in set_rekey_flag on each retry.
    rekey_jitter_s: int = 0


def null_peer() -> PeerState:
    """Return a peer equivalent to Ada's Null_Peer."""
    return PeerState()


# ── Timer tick (from session-timers.adb) ─────────────────────────────

def _elapsed(start: int, now: int) -> int:
    """Elapsed time since *start*, returning 0 only for backward jumps.

    Mirrors the Ada ``Elapsed`` function in session-timers.adb.
    NEVER = 0, so ``_elapsed(NEVER, now)`` returns ``now`` — i.e.
    "infinitely long ago", which is the correct semantic.
    """
    if now < start:
        return 0
    return now - start


def tick(peer: PeerState, now: int) -> TimerAction:
    """Evaluate one peer's timer state for a single tick.

    Returns a ``TimerAction`` with the flags the C layer should enqueue.
    Mirrors ``Session.Timers.Tick`` exactly, including the SPARK-proved
    postcondition:

        Session_Expired ⟹ ¬Initiate_Rekey ∧ ¬Send_Keepalive ∧ ¬Rekey_Timed_Out

    Precondition: ``now > NEVER``.
    """
    assert now > NEVER, "now must be > NEVER (0)"

    # 0. Key zeroing at 3×Reject (540 s) — §6.3 last sentence
    #    Even for inactive/expired peers: if last_handshake is set,
    #    erase all remaining cryptographic material after 540 s.
    if (not peer.active
            and peer.last_handshake != NEVER
            and _elapsed(peer.last_handshake, now) >= KEY_ZEROING_AFTER_TIME):
        return TimerAction(zero_all_keys=True)

    if not peer.active or not peer.current.valid:
        return TimerAction()

    a = TimerAction()
    age = _elapsed(peer.current.created_at, now)

    # 1. Session expiry — Reject_After_Time exceeded
    if age >= REJECT_AFTER_TIME:
        a.session_expired = True
        return a

    # 2. Message counter limits
    if peer.current.send_counter >= REJECT_AFTER_MESSAGES:
        a.session_expired = True
        return a

    # 3. Counter-based rekey: ANY peer (§6.2 paragraph 1)
    #    "WireGuard will try to create a new session … after it has
    #    sent Rekey-After-Messages transport data messages."
    #    No initiator restriction — matches wireguard-go
    #    keepKeyFreshSending(): nonce > RekeyAfterMessages.
    if not peer.rekey_attempted:
        if peer.current.send_counter >= REKEY_AFTER_MESSAGES:
            a.initiate_rekey = True

    # 4. Time-based rekey: ONLY initiator (§6.2 paragraph 2)
    #    Prevents the "thundering herd" problem.
    if not peer.rekey_attempted and peer.is_initiator:
        # After SENDING: session age >= Rekey_After_Time (120 s)
        # Matches wireguard-go keepKeyFreshSending():
        #   keypair.isInitiator && age > RekeyAfterTime
        if age >= REKEY_AFTER_TIME:
            a.initiate_rekey = True

        # After RECEIVING: session age >= Reject - Keepalive - Rekey (165 s)
        # One-shot by construction: first Initiate_Rekey transitions to
        # Rekeying, so the Established branch never fires again.
        # Matches wireguard-go keepKeyFreshReceiving().
        if age >= REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT:
            a.initiate_rekey = True

    # 4b. Unresponsive peer detection — §6.5 last paragraph
    #     Matches wireguard-go expiredNewHandshake (15 s).
    #     If we sent DATA (not just keepalive) and got no reply
    #     in NEW_HANDSHAKE_TIME (15 s), initiate a rekey.
    if not peer.rekey_attempted:
        if (peer.last_data_sent != NEVER
                and peer.last_data_sent > peer.last_received
                and _elapsed(peer.last_data_sent, now) >= NEW_HANDSHAKE_TIME):
            a.initiate_rekey = True

    # 5. Rekey retry / attempt timeout (§6.4)
    #    Check timeout FIRST (90 s window exhausted), then retry (5 s interval).
    #    This prevents retrying after the attempt window is exhausted.
    if peer.rekey_attempted:
        attempt_elapsed = _elapsed(peer.rekey_attempt_start, now)
        if attempt_elapsed >= REKEY_ATTEMPT_TIME:
            a.rekey_timed_out = True
        else:
            since_last_init = _elapsed(peer.rekey_last_sent, now)
            if since_last_init >= REKEY_TIMEOUT + peer.rekey_jitter_s:
                a.initiate_rekey = True

    # 6. Reactive keepalive (§6.5)
    #    _elapsed(NEVER, now) = now (large), so "never sent" correctly
    #    satisfies since_sent >= KEEPALIVE_TIMEOUT.
    if peer.last_received != NEVER:
        since_recv = _elapsed(peer.last_received, now)
        since_sent = _elapsed(peer.last_sent, now)
        if since_recv < KEEPALIVE_TIMEOUT and since_sent >= KEEPALIVE_TIMEOUT:
            a.send_keepalive = True

    # 7. Persistent keepalive (§6.5)
    #    Unconditional periodic empty packet to keep NAT mappings alive.
    #    Fires when we haven't sent anything for persistent_keepalive_s.
    if peer.persistent_keepalive_s > 0:
        since_sent = _elapsed(peer.last_sent, now)
        if since_sent >= peer.persistent_keepalive_s:
            a.send_keepalive = True

    return a


def tick_all(peers: list[PeerState], now: int) -> list[TimerAction]:
    """Evaluate all peers' timers.  Mirrors ``Session.Timers.Tick_All``."""
    return [tick(p, now) for p in peers]


# ── Session lifecycle operations (from session.adb) ──────────────────

def activate_next(peer: PeerState) -> PeerState:
    """Rotate: Previous ← Current, Current ← Next, Next ← null.

    Mirrors ``Session.Activate_Next``.  Clears rekey state since we now
    have a fresh session.  Returns a new PeerState (immutable style).
    """
    p = deepcopy(peer)

    if not p.next_kp.valid:
        return p

    # Rotate
    p.previous = p.current
    p.current = p.next_kp
    p.next_kp = null_keypair()

    # Update handshake timestamp
    p.last_handshake = p.current.created_at

    # Reset data-path timestamps — the handshake itself counts as
    # a send/receive event, preventing the unresponsive-peer check
    # from immediately triggering another rekey.
    p.last_sent = p.current.created_at
    p.last_data_sent = NEVER
    p.last_received = p.current.created_at

    # Clear rekey state
    p.rekey_attempted = False
    p.rekey_attempt_start = NEVER
    p.rekey_last_sent = NEVER

    return p


def expire_session(peer: PeerState) -> PeerState:
    """Invalidate all three keypair slots and clear rekey state.

    Mirrors ``Session.Expire_Session`` (with the Refined_Post proving
    all three slots become ``not Valid``).  Preserves persistent
    keepalive configuration since it outlives individual sessions.
    """
    p = deepcopy(peer)

    saved_pka = p.persistent_keepalive_s
    saved_lh = p.last_handshake

    # Mirror Ada: Peers(Peer) := (others => <>); — reset ALL fields
    # to defaults (Active=False, Mode=Inactive, etc.), then restore
    # configuration that outlives sessions.
    new_p = PeerState()
    new_p.persistent_keepalive_s = saved_pka
    # Preserve Last_Handshake so the 540 s key-zeroing check fires
    new_p.last_handshake = saved_lh

    return new_p


def set_rekey_flag(
    peer: PeerState, now: int, *, jitter: int = 0,
) -> PeerState:
    """Mark that a rekey attempt is in-flight.

    Mirrors ``Session.Set_Rekey_Flag``.
    Only sets ``rekey_attempt_start`` on the first call (preserves
    the 90 s window on retries).  Always updates ``rekey_last_sent``
    and ``rekey_jitter_s``.

    *jitter* defaults to 0 for deterministic tests.  Ada generates
    ``random_byte mod 3`` (0..2 s) via ``Crypto.Random.Fill_Random``.
    """
    p = deepcopy(peer)
    if not p.rekey_attempted:
        p.rekey_attempted = True
        p.rekey_attempt_start = now
    p.rekey_last_sent = now
    p.rekey_jitter_s = jitter
    return p


def mark_sent(peer: PeerState, now: int) -> PeerState:
    """Record that we sent a packet.

    Mirrors ``Session.Mark_Sent``.  Also resets the attempt window
    when rekeying (§6.4 authenticated-packet-traversal extension).
    """
    p = deepcopy(peer)
    p.last_sent = now
    if p.rekey_attempted and now != NEVER:
        p.rekey_attempt_start = now
    return p


def mark_data_sent(peer: PeerState, now: int) -> PeerState:
    """Record that we sent a DATA packet (not keepalive).

    Mirrors ``Session.Mark_Data_Sent``.
    Used by unresponsive peer detection (§6.5).
    """
    p = deepcopy(peer)
    p.last_data_sent = now
    return p


def mark_received(peer: PeerState, now: int) -> PeerState:
    """Record that we received an authenticated packet.

    Mirrors ``Session.Mark_Received``.  Also resets the attempt window
    when rekeying (§6.4 authenticated-packet-traversal extension).
    """
    p = deepcopy(peer)
    p.last_received = now
    if p.rekey_attempted and now != NEVER:
        p.rekey_attempt_start = now
    return p


def zero_all_keys(peer: PeerState) -> PeerState:
    """Erase all cryptographic material and handshake timestamp.

    Mirrors the ``Zero_All_Keys`` action handler in ``Dispatch_Timer``:
    calls ``expire_session`` then clears ``last_handshake`` so the
    540 s zeroing never fires again.
    """
    p = expire_session(peer)
    p.last_handshake = NEVER
    return p


# ── Helpers for test setup ───────────────────────────────────────────

_next_kp_id: int = 1


def make_active_peer(
    created_at: int,
    *,
    send_counter: int = 0,
    last_sent: int = NEVER,
    last_data_sent: int = NEVER,
    last_received: int = NEVER,
    rekey_attempted: bool = False,
    rekey_attempt_start: int = NEVER,
    rekey_last_sent: int = NEVER,
    is_initiator: bool = True,
    persistent_keepalive_s: int = 0,
    rekey_jitter_s: int = 0,
) -> PeerState:
    """Create an active peer with a valid Current keypair for testing."""
    global _next_kp_id

    kp = Keypair(
        send_key=bytes(range(32)),
        receive_key=bytes(range(32, 64)),
        sender_index=1,
        receiver_index=2,
        send_counter=send_counter,
        created_at=created_at,
        kp_id=_next_kp_id,
        valid=True,
    )
    _next_kp_id += 1

    return PeerState(
        current=kp,
        previous=null_keypair(),
        next_kp=null_keypair(),
        last_sent=last_sent,
        last_data_sent=last_data_sent,
        last_received=last_received,
        last_handshake=created_at,
        rekey_attempted=rekey_attempted,
        rekey_attempt_start=rekey_attempt_start,
        rekey_last_sent=rekey_last_sent,
        active=True,
        is_initiator=is_initiator,
        persistent_keepalive_s=persistent_keepalive_s,
        rekey_jitter_s=rekey_jitter_s,
    )


def make_keypair(created_at: int, *, valid: bool = True) -> Keypair:
    """Create a keypair for testing slot rotation."""
    global _next_kp_id
    kp = Keypair(
        send_key=bytes(range(32)),
        receive_key=bytes(range(32, 64)),
        sender_index=_next_kp_id,
        receiver_index=_next_kp_id + 100,
        send_counter=0,
        created_at=created_at,
        kp_id=_next_kp_id,
        valid=valid,
    )
    _next_kp_id += 1
    return kp


# ── Handshake state kind (from handshake.ads) ────────────────────────

class HandshakeStateKind:
    """Mirrors Ada ``Handshake.Handshake_State_Kind``."""

    STATE_EMPTY = 0            # No handshake in progress
    STATE_INITIATOR_SENT = 1   # Initiation sent, waiting for response
    STATE_RESPONDER_SENT = 2   # Response sent, waiting for first data
    STATE_ESTABLISHED = 3      # Handshake complete, session keys derived


# ── Auto-handshake model (from wireguard.adb Auto_Handshake) ─────────

@dataclass
class AutoHandshakeState:
    """State for the auto-handshake rate limiter.

    Mirrors the package-level state in ``wireguard.adb``:
        Last_Auto_Init : Timer.Clock.Timestamp := Timer.Clock.Never
        HS_State.Kind  : Handshake_State_Kind  := State_Empty

    The auto-handshake logic is:
      1. If HS_State.Kind /= State_Empty → handshake in flight, skip
      2. If Now - Last_Auto_Init < REKEY_TIMEOUT → rate-limited, skip
      3. Otherwise → initiate handshake, update Last_Auto_Init := Now
    """

    hs_kind: int = HandshakeStateKind.STATE_EMPTY
    last_auto_init: int = NEVER


def auto_handshake(
    state: AutoHandshakeState,
    session_active: bool,
    now: int,
) -> tuple[AutoHandshakeState, bool]:
    """Evaluate whether to auto-initiate a handshake.

    Mirrors ``Wireguard.Auto_Handshake`` in ``wireguard.adb``.

    Called when inner data is queued but no session exists.  Returns
    ``(new_state, should_initiate)`` where ``should_initiate`` is True
    if the caller should build and send a handshake initiation.

    The ``session_active`` parameter mirrors the C-side
    ``wg_session_is_active()`` gate — the auto-handshake path is only
    reached when this is False. Included here, however, to model the
    complete decision chain.

    Precondition: ``now > NEVER``.

    Rate-limiting:
      - At most one initiation per REKEY_TIMEOUT (5 s)
      - Skipped if a handshake is already in flight (HS_Kind != Empty)
    """
    assert now > NEVER, "now must be > NEVER (0)"

    # Gate: only auto-initiate when session is not active
    if session_active:
        return state, False

    # Handshake already in flight — don't re-initiate
    if state.hs_kind != HandshakeStateKind.STATE_EMPTY:
        return state, False

    # Rate limit: at most once every REKEY_TIMEOUT seconds
    if state.last_auto_init != NEVER:
        if now - state.last_auto_init < REKEY_TIMEOUT:
            return state, False

    # Initiate!
    new_state = AutoHandshakeState(
        hs_kind=HandshakeStateKind.STATE_INITIATOR_SENT,
        last_auto_init=now,
    )
    return new_state, True
