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

    def is_empty(self) -> bool:
        return not (
            self.send_keepalive
            or self.initiate_rekey
            or self.session_expired
            or self.rekey_timed_out
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, TimerAction):
            return NotImplemented
        return (
            self.send_keepalive == other.send_keepalive
            and self.initiate_rekey == other.initiate_rekey
            and self.session_expired == other.session_expired
            and self.rekey_timed_out == other.rekey_timed_out
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
    last_received: int = NEVER
    last_handshake: int = NEVER

    rekey_attempted: bool = False
    rekey_attempt_start: int = NEVER
    rekey_last_sent: int = NEVER

    active: bool = False


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

    if peer.current.send_counter >= REKEY_AFTER_MESSAGES:
        if not peer.rekey_attempted:
            a.initiate_rekey = True

    # 3. Time-based rekey
    if age >= REKEY_AFTER_TIME and not peer.rekey_attempted:
        a.initiate_rekey = True

    # 4. Rekey retry / attempt timeout (§6.4)
    #    Retry every Rekey_Timeout (5 s).  Give up after Rekey_Attempt_Time (90 s).
    if peer.rekey_attempted:
        attempt_elapsed = _elapsed(peer.rekey_attempt_start, now)
        since_last_init = _elapsed(peer.rekey_last_sent, now)
        if attempt_elapsed >= REKEY_ATTEMPT_TIME:
            a.rekey_timed_out = True
        elif since_last_init >= REKEY_TIMEOUT:
            a.initiate_rekey = True

    # 5. Keepalive
    #    _elapsed(NEVER, now) = now (large), so "never sent" correctly
    #    satisfies since_sent >= KEEPALIVE_TIMEOUT.
    if peer.last_received != NEVER:
        since_recv = _elapsed(peer.last_received, now)
        since_sent = _elapsed(peer.last_sent, now)
        if since_recv < KEEPALIVE_TIMEOUT and since_sent >= KEEPALIVE_TIMEOUT:
            a.send_keepalive = True

    # 6. Unresponsive peer (§6.2)
    #    No transport data for Keepalive_Timeout + Rekey_Timeout (15 s).
    #    Initiate handshake.  Retries handled by condition 4 above.
    if peer.last_received != NEVER and not peer.rekey_attempted:
        since_recv = _elapsed(peer.last_received, now)
        if since_recv >= KEEPALIVE_TIMEOUT + REKEY_TIMEOUT:
            a.initiate_rekey = True

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

    # Clear rekey state
    p.rekey_attempted = False
    p.rekey_attempt_start = NEVER
    p.rekey_last_sent = NEVER

    return p


def expire_session(peer: PeerState) -> PeerState:
    """Invalidate all three keypair slots and clear rekey state.

    Mirrors ``Session.Expire_Session`` (with the Refined_Post proving
    all three slots become ``not Valid``).
    """
    p = deepcopy(peer)

    p.current = null_keypair()
    p.previous = null_keypair()
    p.next_kp = null_keypair()

    # Clear rekey state to prevent stuck Rekey_Attempted = True
    p.rekey_attempted = False
    p.rekey_attempt_start = NEVER
    p.rekey_last_sent = NEVER

    return p


def set_rekey_flag(peer: PeerState, now: int) -> PeerState:
    """Mark that a rekey attempt is in-flight.

    Mirrors ``Session.Set_Rekey_Flag``.
    Only sets ``rekey_attempt_start`` on the first call (preserves
    the 90 s window on retries).  Always updates ``rekey_last_sent``.
    """
    p = deepcopy(peer)
    if not p.rekey_attempted:
        p.rekey_attempted = True
        p.rekey_attempt_start = now
    p.rekey_last_sent = now
    return p


# ── Helpers for test setup ───────────────────────────────────────────

_next_kp_id: int = 1


def make_active_peer(
    created_at: int,
    *,
    send_counter: int = 0,
    last_sent: int = NEVER,
    last_received: int = NEVER,
    rekey_attempted: bool = False,
    rekey_attempt_start: int = NEVER,
    rekey_last_sent: int = NEVER,
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
        last_received=last_received,
        last_handshake=created_at,
        rekey_attempted=rekey_attempted,
        rekey_attempt_start=rekey_attempt_start,
        rekey_last_sent=rekey_last_sent,
        active=True,
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
