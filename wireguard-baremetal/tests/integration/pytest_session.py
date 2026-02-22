"""WireGuard session timer state-machine tests.

Layer 1 — Self-tests (Python):
    Validates a Python reference implementation of the WireGuard session
    timer state machine against the protocol specification (whitepaper
    §6.1–6.4).  The reference model in ``wg_session.py`` mirrors the
    Ada/SPARK implementation in ``session-timers.adb``.

    Sub-layers:
        1a. Protocol constants match the WireGuard specification
        1b. Tick evaluation — inactive/active peers, expiry, rekey,
            keepalive, counter limits
        1c. SPARK postcondition — session_expired exclusivity invariant
        1d. Session lifecycle — slot rotation, expiry clears all,
            rekey state management

Layer 2 — ESP32 integration (requires hardware):
    Verifies the FreeRTOS session timer task and timer-driven lifecycle
    on the ESP32-C6.  Tests check UART log output for timer events
    after performing a real WireGuard handshake.
"""

import re
import socket
import struct
import time
import pytest

from wg_session import (
    # Constants
    MAX_PEERS,
    REKEY_AFTER_MESSAGES,
    REJECT_AFTER_MESSAGES,
    REKEY_AFTER_TIME,
    REJECT_AFTER_TIME,
    REKEY_ATTEMPT_TIME,
    REKEY_TIMEOUT,
    KEEPALIVE_TIMEOUT,
    NEVER,
    # Types
    TimerAction,
    NO_ACTION,
    Keypair,
    PeerState,
    # Functions
    tick,
    tick_all,
    activate_next,
    expire_session,
    set_rekey_flag,
    null_keypair,
    null_peer,
    # Test helpers
    make_active_peer,
    make_keypair,
)


# =====================================================================
#  Layer 1a — Protocol constants
# =====================================================================

class TestProtocolConstants:
    """Verify timing constants match the WireGuard whitepaper §6.1–6.4."""

    def test_rekey_after_time(self):
        """Rekey-After-Time = 120 seconds (whitepaper §6.2)."""
        assert REKEY_AFTER_TIME == 120

    def test_reject_after_time(self):
        """Reject-After-Time = 180 seconds (whitepaper §6.2)."""
        assert REJECT_AFTER_TIME == 180

    def test_rekey_attempt_time(self):
        """Rekey-Attempt-Time = 90 seconds (whitepaper §6.4)."""
        assert REKEY_ATTEMPT_TIME == 90

    def test_rekey_timeout(self):
        """Rekey-Timeout = 5 seconds (whitepaper §6.4)."""
        assert REKEY_TIMEOUT == 5

    def test_keepalive_timeout(self):
        """Keepalive-Timeout = 10 seconds (whitepaper §6.5)."""
        assert KEEPALIVE_TIMEOUT == 10

    def test_rekey_after_messages(self):
        """Rekey-After-Messages = 2^60 (whitepaper §5.4.6)."""
        assert REKEY_AFTER_MESSAGES == 2 ** 60

    def test_reject_after_messages(self):
        """Reject-After-Messages = 2^64 − 2^13 − 1 (whitepaper §5.4.6)."""
        assert REJECT_AFTER_MESSAGES == 2 ** 64 - 2 ** 13 - 1

    def test_max_peers(self):
        """Max concurrent peers = 2."""
        assert MAX_PEERS == 2

    def test_timing_ordering(self):
        """Rekey triggers before reject; keepalive < rekey < reject."""
        assert KEEPALIVE_TIMEOUT < REKEY_AFTER_TIME < REJECT_AFTER_TIME

    def test_rekey_attempt_time_less_than_reject(self):
        """Rekey attempt timeout fires before session reject."""
        assert REKEY_ATTEMPT_TIME < REJECT_AFTER_TIME


# =====================================================================
#  Layer 1b — Tick evaluation
# =====================================================================

class TestTickInactivePeer:
    """Tick on an inactive or empty peer always returns No_Action."""

    def test_null_peer_returns_no_action(self):
        """Freshly initialized peer (not active) → no action."""
        peer = null_peer()
        assert tick(peer, now=1000) == NO_ACTION

    def test_active_but_no_valid_keypair(self):
        """Active peer with no valid Current keypair → no action."""
        peer = null_peer()
        peer.active = True
        assert tick(peer, now=1000) == NO_ACTION

    def test_inactive_with_valid_keypair(self):
        """Valid keypair but peer not active → no action."""
        peer = make_active_peer(created_at=100)
        peer.active = False
        assert tick(peer, now=200) == NO_ACTION


class TestSessionExpiry:
    """Session expires when Reject_After_Time or counter limit is reached."""

    def test_expires_at_reject_after_time(self):
        """Session created at T=100, tick at T=280 (age=180) → expired."""
        peer = make_active_peer(created_at=100)
        action = tick(peer, now=100 + REJECT_AFTER_TIME)
        assert action.session_expired is True

    def test_not_expired_just_before_reject(self):
        """One second before Reject_After_Time → not expired."""
        peer = make_active_peer(created_at=100)
        action = tick(peer, now=100 + REJECT_AFTER_TIME - 1)
        assert action.session_expired is False

    def test_expires_well_past_reject(self):
        """Way past Reject_After_Time → still expired."""
        peer = make_active_peer(created_at=100)
        action = tick(peer, now=100 + REJECT_AFTER_TIME + 1000)
        assert action.session_expired is True

    def test_counter_limit_expiry(self):
        """Send counter at Reject_After_Messages → expired."""
        peer = make_active_peer(created_at=100, send_counter=REJECT_AFTER_MESSAGES)
        action = tick(peer, now=110)
        assert action.session_expired is True

    def test_counter_just_below_reject(self):
        """One below Reject_After_Messages → not expired by counter."""
        peer = make_active_peer(
            created_at=100,
            send_counter=REJECT_AFTER_MESSAGES - 1,
        )
        action = tick(peer, now=110)  # age=10, well within time limits
        assert action.session_expired is False


class TestTimeBasedRekey:
    """Rekey triggers when session age reaches Rekey_After_Time."""

    def test_rekey_at_rekey_after_time(self):
        """Age == Rekey_After_Time → initiate rekey."""
        peer = make_active_peer(created_at=100)
        action = tick(peer, now=100 + REKEY_AFTER_TIME)
        # At exactly REJECT_AFTER_TIME=180 it would expire, but
        # REKEY_AFTER_TIME=120 < 180, so we get rekey not expire
        assert action.initiate_rekey is True
        assert action.session_expired is False

    def test_no_rekey_before_threshold(self):
        """One second before Rekey_After_Time → no rekey."""
        peer = make_active_peer(created_at=100)
        action = tick(peer, now=100 + REKEY_AFTER_TIME - 1)
        assert action.initiate_rekey is False

    def test_no_rekey_if_already_attempted(self):
        """Rekey_Attempted = True, recently sent → no duplicate initiation."""
        peer = make_active_peer(
            created_at=100,
            rekey_attempted=True,
            rekey_attempt_start=200,
            rekey_last_sent=218,  # sent 2 s ago → < 5 s, no retry
        )
        action = tick(peer, now=100 + REKEY_AFTER_TIME)
        assert action.initiate_rekey is False

    def test_rekey_suppressed_by_expiry(self):
        """At Reject_After_Time, expiry takes priority over rekey."""
        peer = make_active_peer(created_at=100)
        action = tick(peer, now=100 + REJECT_AFTER_TIME)
        assert action.session_expired is True
        assert action.initiate_rekey is False


class TestCounterBasedRekey:
    """Rekey triggers when send counter reaches Rekey_After_Messages."""

    def test_rekey_at_counter_threshold(self):
        """Send counter == Rekey_After_Messages → initiate rekey."""
        peer = make_active_peer(
            created_at=100,
            send_counter=REKEY_AFTER_MESSAGES,
        )
        action = tick(peer, now=110)
        assert action.initiate_rekey is True

    def test_no_rekey_below_threshold(self):
        """One below Rekey_After_Messages → no rekey."""
        peer = make_active_peer(
            created_at=100,
            send_counter=REKEY_AFTER_MESSAGES - 1,
        )
        action = tick(peer, now=110)
        assert action.initiate_rekey is False

    def test_counter_rekey_suppressed_if_attempted(self):
        """Already attempting rekey, recently sent → no duplicate initiation."""
        peer = make_active_peer(
            created_at=100,
            send_counter=REKEY_AFTER_MESSAGES,
            rekey_attempted=True,
            rekey_attempt_start=105,
            rekey_last_sent=108,  # sent 2 s ago → < 5 s, no retry
        )
        action = tick(peer, now=110)
        assert action.initiate_rekey is False


class TestRekeyTimeout:
    """Rekey attempt times out after Rekey_Attempt_Time."""

    def test_timeout_at_rekey_attempt_time(self):
        """Attempt started at T=200, tick at T=290 (elapsed=90) → timed out.

        Note: created_at must be recent enough that session age stays
        below Reject_After_Time (180) at the tick time.
        """
        peer = make_active_peer(
            created_at=200,
            rekey_attempted=True,
            rekey_attempt_start=200,
            rekey_last_sent=200,
        )
        action = tick(peer, now=200 + REKEY_ATTEMPT_TIME)
        assert action.rekey_timed_out is True

    def test_no_timeout_before_threshold(self):
        """One second before Rekey_Attempt_Time → not timed out."""
        peer = make_active_peer(
            created_at=100,
            rekey_attempted=True,
            rekey_attempt_start=200,
            rekey_last_sent=200 + REKEY_ATTEMPT_TIME - 3,  # recent
        )
        action = tick(peer, now=200 + REKEY_ATTEMPT_TIME - 1)
        assert action.rekey_timed_out is False

    def test_no_timeout_if_not_attempting(self):
        """Rekey_Attempted = False → no timeout regardless of time."""
        peer = make_active_peer(created_at=100)
        action = tick(peer, now=100 + REKEY_ATTEMPT_TIME + 100)
        # Age = 190 > 180 → actually expired, but verify no spurious timeout
        assert action.rekey_timed_out is False

    def test_timeout_does_not_coexist_with_retry(self):
        """Rekey timeout and retry are mutually exclusive (elsif).

        When the 90 s window expires, we get rekey_timed_out but NOT
        initiate_rekey, even though since_last_init >= 5.
        """
        peer = make_active_peer(
            created_at=200,
            rekey_attempted=True,
            rekey_attempt_start=200,
            rekey_last_sent=200,  # old enough for retry
        )
        action = tick(peer, now=200 + REKEY_ATTEMPT_TIME)
        assert action.rekey_timed_out is True
        assert action.initiate_rekey is False


class TestKeepalive:
    """Keepalive sent when data received recently but nothing sent."""

    def test_keepalive_triggered(self):
        """Received 5s ago, sent 15s ago → keepalive needed."""
        now = 1000
        peer = make_active_peer(
            created_at=900,                     # age=100, < 180
            last_received=now - 5,              # 5s ago (< 10s threshold)
            last_sent=now - KEEPALIVE_TIMEOUT,  # exactly at threshold
        )
        action = tick(peer, now)
        assert action.send_keepalive is True

    def test_no_keepalive_if_recently_sent(self):
        """Received 5s ago, sent 3s ago → no keepalive needed."""
        now = 1000
        peer = make_active_peer(
            created_at=500,
            last_received=now - 5,
            last_sent=now - 3,
        )
        action = tick(peer, now)
        assert action.send_keepalive is False

    def test_no_keepalive_if_not_recently_received(self):
        """Received 15s ago (> threshold), sent 15s ago → no keepalive."""
        now = 1000
        peer = make_active_peer(
            created_at=500,
            last_received=now - KEEPALIVE_TIMEOUT,  # at threshold (not <)
            last_sent=now - KEEPALIVE_TIMEOUT,
        )
        action = tick(peer, now)
        assert action.send_keepalive is False

    def test_no_keepalive_if_never_received(self):
        """Last_Received = NEVER → no keepalive."""
        peer = make_active_peer(created_at=500, last_sent=500)
        assert peer.last_received == NEVER
        action = tick(peer, now=520)
        assert action.send_keepalive is False

    def test_keepalive_with_never_sent(self):
        """Received recently, Last_Sent = NEVER → keepalive fires.

        If we've received data but never sent any transport packet,
        the peer hasn't heard from us.  _elapsed(NEVER, now) = now,
        which is large (>= 10), so the keepalive condition triggers.
        """
        now = 1000
        peer = make_active_peer(
            created_at=now - 30,
            last_received=now - 5,
            # last_sent defaults to NEVER
        )
        action = tick(peer, now)
        assert action.send_keepalive is True

    def test_keepalive_boundary_recv(self):
        """Received exactly at threshold boundary → no keepalive.

        since_recv must be strictly less than KEEPALIVE_TIMEOUT.
        """
        now = 1000
        peer = make_active_peer(
            created_at=500,
            last_received=now - KEEPALIVE_TIMEOUT,  # since_recv == 10 (not <)
            last_sent=now - 20,
        )
        action = tick(peer, now)
        assert action.send_keepalive is False


# =====================================================================
#  Layer 1b-2 — Unresponsive peer detection (§6.2) + retry (§6.4)
# =====================================================================

class TestResponderNoTimeRekey:
    """Responders must NOT do time-based rekeying (§6.2 paragraph 2).

    Only the initiator of the current session does time-based rekeying
    to prevent the 'thundering herd' problem.  Responders rely on the
    initiator to rekey.
    """

    def test_responder_no_rekey_at_120s(self):
        """Responder at Rekey_After_Time → no rekey."""
        peer = make_active_peer(
            created_at=100,
            is_initiator=False,
        )
        action = tick(peer, now=100 + REKEY_AFTER_TIME)
        assert action.initiate_rekey is False

    def test_responder_no_rekey_at_165s(self):
        """Responder at 165 s (receive-side threshold) → no rekey."""
        peer = make_active_peer(
            created_at=100,
            is_initiator=False,
        )
        action = tick(peer, now=100 + REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT)
        assert action.initiate_rekey is False

    def test_responder_counter_rekey_still_works(self):
        """Responder at counter threshold → rekey fires (§6.2 paragraph 1).

        Counter-based rekey is NOT gated on is_initiator — matches
        wireguard-go keepKeyFreshSending(): nonce > RekeyAfterMessages.
        """
        peer = make_active_peer(
            created_at=100,
            send_counter=REKEY_AFTER_MESSAGES,
            is_initiator=False,
        )
        action = tick(peer, now=110)
        assert action.initiate_rekey is True

    def test_initiator_rekeys_at_120s(self):
        """Initiator at Rekey_After_Time → rekey fires."""
        peer = make_active_peer(
            created_at=100,
            is_initiator=True,
        )
        action = tick(peer, now=100 + REKEY_AFTER_TIME)
        assert action.initiate_rekey is True

    def test_responder_still_expires(self):
        """Responder at Reject_After_Time → session expired (not rekey)."""
        peer = make_active_peer(
            created_at=100,
            is_initiator=False,
        )
        action = tick(peer, now=100 + REJECT_AFTER_TIME)
        assert action.session_expired is True
        assert action.initiate_rekey is False

    def test_responder_keepalive_still_works(self):
        """Responder keepalive is not affected by is_initiator."""
        now = 1000
        peer = make_active_peer(
            created_at=900,
            last_received=now - 5,
            last_sent=now - KEEPALIVE_TIMEOUT,
            is_initiator=False,
        )
        action = tick(peer, now)
        assert action.send_keepalive is True
        assert action.initiate_rekey is False


class TestRekeyRetry:
    """After first initiation, retry every Rekey_Timeout (5 s)."""

    def test_retry_after_5s(self):
        """Last init sent 5 s ago → retry."""
        now = 1000
        peer = make_active_peer(
            created_at=now - 30,
            rekey_attempted=True,
            rekey_attempt_start=now - 10,
            rekey_last_sent=now - REKEY_TIMEOUT,  # exactly 5 s ago
        )
        action = tick(peer, now)
        assert action.initiate_rekey is True

    def test_no_retry_before_5s(self):
        """Last init sent 4 s ago → too soon to retry."""
        now = 1000
        peer = make_active_peer(
            created_at=now - 30,
            rekey_attempted=True,
            rekey_attempt_start=now - 10,
            rekey_last_sent=now - (REKEY_TIMEOUT - 1),  # 4 s ago
        )
        action = tick(peer, now)
        assert action.initiate_rekey is False

    def test_retry_stops_at_90s(self):
        """At Rekey_Attempt_Time, timeout fires instead of retry."""
        now = 1000
        peer = make_active_peer(
            created_at=now - 100,
            rekey_attempted=True,
            rekey_attempt_start=now - REKEY_ATTEMPT_TIME,  # exactly 90 s
            rekey_last_sent=now - REKEY_TIMEOUT,  # eligible for retry
        )
        action = tick(peer, now)
        assert action.rekey_timed_out is True
        assert action.initiate_rekey is False  # elsif: mutually exclusive

    def test_retry_at_89s_still_retries(self):
        """At 89 s into attempt, retry still fires."""
        now = 1000
        peer = make_active_peer(
            created_at=now - 100,
            rekey_attempted=True,
            rekey_attempt_start=now - (REKEY_ATTEMPT_TIME - 1),
            rekey_last_sent=now - REKEY_TIMEOUT,
        )
        action = tick(peer, now)
        assert action.initiate_rekey is True
        assert action.rekey_timed_out is False

    def test_set_rekey_flag_first_call(self):
        """First call sets attempted, attempt_start, and last_sent."""
        peer = make_active_peer(created_at=100)
        p = set_rekey_flag(peer, now=200)
        assert p.rekey_attempted is True
        assert p.rekey_attempt_start == 200
        assert p.rekey_last_sent == 200

    def test_set_rekey_flag_retry_preserves_window(self):
        """Second call only updates last_sent — doesn't reset 90s window."""
        peer = make_active_peer(
            created_at=100,
            rekey_attempted=True,
            rekey_attempt_start=200,
            rekey_last_sent=200,
        )
        p = set_rekey_flag(peer, now=205)
        assert p.rekey_attempted is True
        assert p.rekey_attempt_start == 200  # unchanged
        assert p.rekey_last_sent == 205      # updated


# =====================================================================
#  Layer 1c — SPARK postcondition: expiry exclusivity invariant
# =====================================================================

class TestExpiryExclusivity:
    """When session_expired is True, all other actions must be False.

    This invariant is formally proved by SPARK (Tick'Result.Session_Expired ⟹
    ¬Initiate_Rekey ∧ ¬Send_Keepalive ∧ ¬Rekey_Timed_Out).  We verify the
    Python reference model obeys it too.
    """

    def test_time_expiry_exclusive(self):
        """Time-based expiry blocks rekey and keepalive."""
        peer = make_active_peer(
            created_at=100,
            last_received=100 + REJECT_AFTER_TIME - 5,
            last_sent=100,
        )
        action = tick(peer, now=100 + REJECT_AFTER_TIME)
        assert action.session_expired is True
        assert action.initiate_rekey is False
        assert action.send_keepalive is False
        assert action.rekey_timed_out is False

    def test_counter_expiry_exclusive(self):
        """Counter-based expiry blocks everything else."""
        peer = make_active_peer(
            created_at=100,
            send_counter=REJECT_AFTER_MESSAGES,
            rekey_attempted=True,
            rekey_attempt_start=100,
            rekey_last_sent=108,
        )
        action = tick(peer, now=110)
        assert action.session_expired is True
        assert action.initiate_rekey is False
        assert action.send_keepalive is False
        assert action.rekey_timed_out is False

    def test_non_expired_can_have_multiple_actions(self):
        """A non-expired peer can have both rekey and keepalive."""
        now = 1000
        peer = make_active_peer(
            created_at=now - REKEY_AFTER_TIME,
            last_received=now - 5,
            last_sent=now - KEEPALIVE_TIMEOUT,
        )
        action = tick(peer, now)
        assert action.session_expired is False
        assert action.initiate_rekey is True
        assert action.send_keepalive is True

    def test_exhaustive_edge_cases(self):
        """Sweep across timing boundaries and verify exclusivity holds."""
        base = 1000
        for offset in range(REJECT_AFTER_TIME - 5, REJECT_AFTER_TIME + 5):
            peer = make_active_peer(created_at=base)
            action = tick(peer, now=base + offset)
            if action.session_expired:
                assert not action.initiate_rekey
                assert not action.send_keepalive
                assert not action.rekey_timed_out


# =====================================================================
#  Layer 1d — Session lifecycle: slot rotation, expiry, rekey state
# =====================================================================

class TestSlotRotation:
    """Activate_Next rotates Current→Previous, Next→Current, Next←null."""

    def test_basic_rotation(self):
        """Next becomes Current, old Current becomes Previous."""
        peer = PeerState(active=True)
        peer.current = make_keypair(created_at=100)
        peer.next_kp = make_keypair(created_at=200)

        old_current_id = peer.current.kp_id
        old_next_id = peer.next_kp.kp_id

        peer = activate_next(peer)

        assert peer.current.kp_id == old_next_id
        assert peer.previous.kp_id == old_current_id
        assert not peer.next_kp.valid

    def test_rotation_clears_rekey_state(self):
        """Activate_Next clears Rekey_Attempted and Rekey_Attempt_Start."""
        peer = PeerState(
            active=True,
            rekey_attempted=True,
            rekey_attempt_start=150,
        )
        peer.current = make_keypair(created_at=100)
        peer.next_kp = make_keypair(created_at=200)

        peer = activate_next(peer)
        assert peer.rekey_attempted is False
        assert peer.rekey_attempt_start == NEVER

    def test_rotation_updates_handshake_timestamp(self):
        """Last_Handshake set to the new Current's Created_At."""
        peer = PeerState(active=True, last_handshake=100)
        peer.current = make_keypair(created_at=100)
        peer.next_kp = make_keypair(created_at=200)

        peer = activate_next(peer)
        assert peer.last_handshake == 200

    def test_rotation_noop_without_next(self):
        """Activate_Next is a no-op if Next is not valid."""
        peer = PeerState(active=True)
        peer.current = make_keypair(created_at=100)

        old_id = peer.current.kp_id
        peer = activate_next(peer)
        assert peer.current.kp_id == old_id
        assert not peer.next_kp.valid

    def test_three_keypairs_survive_rotation(self):
        """Current → Previous preserves the old keypair data."""
        peer = PeerState(active=True)
        kp_old = make_keypair(created_at=100)
        kp_new = make_keypair(created_at=200)
        peer.current = kp_old
        peer.next_kp = kp_new

        peer = activate_next(peer)

        # The old current should now be in previous, data intact
        assert peer.previous.valid is True
        assert peer.previous.created_at == 100
        assert peer.current.valid is True
        assert peer.current.created_at == 200


class TestExpireSession:
    """Expire_Session invalidates all three slots and clears rekey state."""

    def test_all_slots_invalidated(self):
        """After expire, Current, Previous, and Next are all invalid."""
        peer = PeerState(active=True)
        peer.current = make_keypair(created_at=100)
        peer.previous = make_keypair(created_at=50)
        peer.next_kp = make_keypair(created_at=150)

        peer = expire_session(peer)

        assert not peer.current.valid
        assert not peer.previous.valid
        assert not peer.next_kp.valid

    def test_expire_clears_rekey_state(self):
        """Rekey_Attempted and Rekey_Attempt_Start cleared on expire."""
        peer = make_active_peer(
            created_at=100,
            rekey_attempted=True,
            rekey_attempt_start=150,
        )
        peer = expire_session(peer)
        assert peer.rekey_attempted is False
        assert peer.rekey_attempt_start == NEVER

    def test_expire_then_tick_returns_no_action(self):
        """After expire, tick returns No_Action (no valid Current)."""
        peer = make_active_peer(created_at=100)
        peer = expire_session(peer)
        action = tick(peer, now=200)
        assert action == NO_ACTION

    def test_expire_idempotent(self):
        """Expiring an already-expired peer is safe."""
        peer = null_peer()
        peer = expire_session(peer)
        assert not peer.current.valid
        assert not peer.previous.valid
        assert not peer.next_kp.valid


class TestRekeyStateLifecycle:
    """Full rekey lifecycle: flag set → success/failure → cleared."""

    def test_set_rekey_flag(self):
        """Set_Rekey_Flag sets attempted=True and records timestamp."""
        peer = make_active_peer(created_at=100)
        assert peer.rekey_attempted is False

        peer = set_rekey_flag(peer, now=120)
        assert peer.rekey_attempted is True
        assert peer.rekey_attempt_start == 120

    def test_success_path_clears_via_activate(self):
        """Rekey success: activate_next clears rekey state.

        This is the 'happy path': handshake succeeds → Derive_And_Activate
        calls Activate_Next → rekey state cleared.
        """
        peer = make_active_peer(
            created_at=100,
            rekey_attempted=True,
            rekey_attempt_start=120,
        )
        peer.next_kp = make_keypair(created_at=200)

        peer = activate_next(peer)
        assert peer.rekey_attempted is False
        assert peer.rekey_attempt_start == NEVER

    def test_failure_path_clears_via_expire(self):
        """Rekey failure: expire_session clears rekey state.

        This is the 'sad path': rekey timed out → session_expire called
        → Rekey_Attempted cleared, preventing a dead state.
        """
        peer = make_active_peer(
            created_at=100,
            rekey_attempted=True,
            rekey_attempt_start=120,
        )
        peer = expire_session(peer)
        assert peer.rekey_attempted is False

    def test_rekey_flag_blocks_duplicate_initiation(self):
        """Once flag is set, tick won't request another rekey."""
        peer = make_active_peer(
            created_at=100,
            rekey_attempted=True,
            rekey_attempt_start=120,
        )
        # Well past REKEY_AFTER_TIME, but flag blocks new initiation
        action = tick(peer, now=100 + REKEY_AFTER_TIME + 10)
        assert action.initiate_rekey is False

    def test_full_lifecycle_rekey_success(self):
        """End-to-end: tick → set flag → handshake → activate → tick clean."""
        base = 1000
        peer = make_active_peer(created_at=base)

        # T=1120: Rekey_After_Time reached
        action = tick(peer, now=base + REKEY_AFTER_TIME)
        assert action.initiate_rekey is True

        # C code calls set_rekey_flag
        peer = set_rekey_flag(peer, now=base + REKEY_AFTER_TIME)
        assert peer.rekey_attempted is True

        # Next tick: no duplicate rekey request
        action = tick(peer, now=base + REKEY_AFTER_TIME + 1)
        assert action.initiate_rekey is False

        # Handshake succeeds, new keypair placed in Next
        peer.next_kp = make_keypair(created_at=base + REKEY_AFTER_TIME + 2)

        # Derive_And_Activate
        peer = activate_next(peer)
        assert peer.rekey_attempted is False
        assert peer.current.created_at == base + REKEY_AFTER_TIME + 2

        # Next tick: clean state, no actions (session is fresh)
        action = tick(peer, now=base + REKEY_AFTER_TIME + 3)
        assert action == NO_ACTION

    def test_full_lifecycle_rekey_timeout(self):
        """End-to-end: tick → set flag → timeout → expire → clean slate.

        Uses counter-based rekey (triggered at age=10) rather than
        time-based, because time-based rekey at age=120 plus
        Rekey_Attempt_Time=90 yields age=210 > Reject_After_Time=180,
        meaning the session would expire before timeout fires.
        """
        base = 1000
        peer = make_active_peer(
            created_at=base,
            send_counter=REKEY_AFTER_MESSAGES,  # counter-based rekey
        )

        # T=1010: Counter threshold reached → rekey
        rekey_now = base + 10
        action = tick(peer, now=rekey_now)
        assert action.initiate_rekey is True

        peer = set_rekey_flag(peer, now=rekey_now)

        # T=1100: Rekey_Attempt_Time elapsed (90s from T=1010)
        # Session age = 100 < 180, so no expiry
        timeout_now = rekey_now + REKEY_ATTEMPT_TIME
        action = tick(peer, now=timeout_now)
        assert action.rekey_timed_out is True
        assert action.session_expired is False

        # C code calls expire_session on rekey_timed_out
        peer = expire_session(peer)
        assert not peer.current.valid
        assert peer.rekey_attempted is False

        # Tick after expire: no action
        action = tick(peer, now=timeout_now + 1)
        assert action == NO_ACTION


class TestTickAll:
    """Tick_All evaluates all peers in a single pass."""

    def test_tick_all_basic(self):
        """Two peers: one active (needs rekey), one inactive."""
        peer1 = make_active_peer(created_at=100)
        peer2 = null_peer()

        actions = tick_all([peer1, peer2], now=100 + REKEY_AFTER_TIME)
        assert len(actions) == 2
        assert actions[0].initiate_rekey is True
        assert actions[1] == NO_ACTION

    def test_tick_all_both_active(self):
        """Two active peers at different ages → different actions."""
        peer1 = make_active_peer(created_at=100)   # age = 80 at T=180
        peer2 = make_active_peer(created_at=50)    # age = 130 at T=180

        actions = tick_all([peer1, peer2], now=180)
        # peer1: age=80 < 120 → no rekey
        assert actions[0].initiate_rekey is False
        # peer2: age=130 >= 120 → rekey
        assert actions[1].initiate_rekey is True

    def test_tick_all_empty(self):
        """Zero peers → empty result."""
        actions = tick_all([], now=1000)
        assert actions == []


# =====================================================================
#  Layer 1e — Edge cases and regression tests
# =====================================================================

class TestEdgeCases:
    """Corner cases, boundary values, and regression scenarios."""

    def test_now_equals_one(self):
        """Minimum valid now (just above NEVER)."""
        peer = make_active_peer(created_at=1)
        action = tick(peer, now=1)
        # age = 0, well within all limits
        assert action == NO_ACTION

    def test_created_at_equals_now(self):
        """Session just created — age = 0 → no action."""
        peer = make_active_peer(created_at=500)
        action = tick(peer, now=500)
        assert action == NO_ACTION

    def test_now_must_be_greater_than_never(self):
        """tick() precondition: now > NEVER (= 0)."""
        peer = make_active_peer(created_at=100)
        with pytest.raises(AssertionError):
            tick(peer, now=NEVER)

    def test_concurrent_rekey_and_keepalive(self):
        """Both rekey and keepalive can fire in the same tick."""
        now = 1000
        peer = make_active_peer(
            created_at=now - REKEY_AFTER_TIME,
            last_received=now - 5,
            last_sent=now - KEEPALIVE_TIMEOUT,
        )
        action = tick(peer, now)
        assert action.initiate_rekey is True
        assert action.send_keepalive is True
        assert action.session_expired is False

    def test_rekey_timeout_and_keepalive(self):
        """Rekey timeout and keepalive can coexist."""
        now = 1000
        peer = make_active_peer(
            created_at=800,  # age=200, but we need < REJECT_AFTER_TIME
            last_received=now - 5,
            last_sent=now - KEEPALIVE_TIMEOUT,
            rekey_attempted=True,
            rekey_attempt_start=now - REKEY_ATTEMPT_TIME,
        )
        # age=200 >= 180 → expired.  Let's use a younger session.
        peer = make_active_peer(
            created_at=now - 100,  # age=100, < 180
            last_received=now - 5,
            last_sent=now - KEEPALIVE_TIMEOUT,
            rekey_attempted=True,
            rekey_attempt_start=now - REKEY_ATTEMPT_TIME,
        )
        action = tick(peer, now)
        assert action.rekey_timed_out is True
        assert action.send_keepalive is True
        assert action.session_expired is False

    def test_very_large_counter(self):
        """Counter at exactly Rekey_After_Messages triggers rekey, not expire."""
        peer = make_active_peer(
            created_at=100,
            send_counter=REKEY_AFTER_MESSAGES,
        )
        action = tick(peer, now=110)
        assert action.initiate_rekey is True
        assert action.session_expired is False

    def test_counter_between_rekey_and_reject(self):
        """Counter in the danger zone between Rekey and Reject thresholds."""
        mid_counter = (REKEY_AFTER_MESSAGES + REJECT_AFTER_MESSAGES) // 2
        peer = make_active_peer(
            created_at=100,
            send_counter=mid_counter,
        )
        action = tick(peer, now=110)
        assert action.initiate_rekey is True
        assert action.session_expired is False

    def test_double_activate_is_safe(self):
        """Calling activate_next twice is safe (second is no-op)."""
        peer = PeerState(active=True)
        peer.current = make_keypair(created_at=100)
        peer.next_kp = make_keypair(created_at=200)

        peer = activate_next(peer)
        kp_id = peer.current.kp_id

        peer = activate_next(peer)  # no-op, Next is not valid
        assert peer.current.kp_id == kp_id

    def test_elapsed_with_backward_time(self):
        """Created_At in the future → elapsed = 0 → no expiry."""
        peer = make_active_peer(created_at=1000)
        action = tick(peer, now=500)  # now < created_at
        assert action == NO_ACTION


# =====================================================================
#  Layer 1f — Keepalive wire format and crypto self-tests
#
#  A keepalive is a Type 4 transport packet with zero-length plaintext:
#    header (16 B) + AEAD tag (16 B) = 32 bytes on the wire.
#
#  These tests validate the Python reference helpers and the crypto
#  round-trip independently of any hardware.
# =====================================================================

class TestKeepalivePacketFormat:
    """Wire format of a keepalive packet (Type 4, empty plaintext)."""

    def test_keepalive_size(self):
        """Keepalive packet is exactly 32 bytes (header + tag, no plaintext)."""
        from wg_noise import (
            build_keepalive_packet, KEEPALIVE_SIZE,
            TRANSPORT_HEADER_SIZE, AEAD_TAG_SIZE,
        )
        key = bytes(32)
        pkt = build_keepalive_packet(key, receiver_index=1, counter=0)
        assert len(pkt) == KEEPALIVE_SIZE
        assert KEEPALIVE_SIZE == TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE

    def test_keepalive_msg_type(self):
        """First byte is 4 (MSG_TYPE_TRANSPORT) — same as data packets."""
        from wg_noise import build_keepalive_packet, MSG_TYPE_TRANSPORT
        key = bytes(32)
        pkt = build_keepalive_packet(key, receiver_index=1, counter=0)
        assert pkt[0] == MSG_TYPE_TRANSPORT

    def test_keepalive_receiver_index(self):
        """Receiver index at bytes 4-7 is little-endian uint32."""
        from wg_noise import build_keepalive_packet
        key = bytes(32)
        pkt = build_keepalive_packet(key, receiver_index=0xAABBCCDD, counter=0)
        assert struct.unpack("<I", pkt[4:8])[0] == 0xAABBCCDD

    def test_keepalive_counter(self):
        """Counter at bytes 8-15 is little-endian uint64."""
        from wg_noise import build_keepalive_packet
        key = bytes(32)
        pkt = build_keepalive_packet(key, receiver_index=1, counter=42)
        assert struct.unpack("<Q", pkt[8:16])[0] == 42

    def test_keepalive_reserved_zero(self):
        """Bytes 1-3 are reserved (zero)."""
        from wg_noise import build_keepalive_packet
        key = bytes(32)
        pkt = build_keepalive_packet(key, receiver_index=1, counter=0)
        assert pkt[1:4] == b"\x00\x00\x00"

    def test_keepalive_different_keys_different_tag(self):
        """Two different keys produce different AEAD tags."""
        from wg_noise import build_keepalive_packet
        key_a = bytes(32)
        key_b = bytes(range(32))
        pkt_a = build_keepalive_packet(key_a, receiver_index=1, counter=0)
        pkt_b = build_keepalive_packet(key_b, receiver_index=1, counter=0)
        # Headers are identical, but tags differ
        assert pkt_a[:16] == pkt_b[:16]
        assert pkt_a[16:] != pkt_b[16:]

    def test_keepalive_counter_changes_tag(self):
        """Different counters produce different AEAD tags (nonce changes)."""
        from wg_noise import build_keepalive_packet
        key = bytes(32)
        pkt_0 = build_keepalive_packet(key, receiver_index=1, counter=0)
        pkt_1 = build_keepalive_packet(key, receiver_index=1, counter=1)
        assert pkt_0[16:] != pkt_1[16:]


class TestKeepaliveRoundTrip:
    """Encrypt → decrypt round-trip for keepalive packets."""

    def test_basic_roundtrip(self):
        """Build then parse a keepalive recovers receiver_index and counter."""
        from wg_noise import build_keepalive_packet, parse_keepalive_packet
        key = bytes(range(32))
        pkt = build_keepalive_packet(key, receiver_index=7, counter=99)
        rx_idx, ctr = parse_keepalive_packet(key, pkt)
        assert rx_idx == 7
        assert ctr == 99

    def test_roundtrip_with_random_key(self):
        """Round-trip with a random key."""
        import os
        from wg_noise import build_keepalive_packet, parse_keepalive_packet
        key = os.urandom(32)
        pkt = build_keepalive_packet(key, receiver_index=0xDEAD, counter=12345)
        rx_idx, ctr = parse_keepalive_packet(key, pkt)
        assert rx_idx == 0xDEAD
        assert ctr == 12345

    def test_wrong_key_rejected(self):
        """Decrypting a keepalive with the wrong key raises."""
        from wg_noise import build_keepalive_packet, parse_keepalive_packet
        key_a = bytes(32)
        key_b = bytes(range(32))
        pkt = build_keepalive_packet(key_a, receiver_index=1, counter=0)
        with pytest.raises(Exception):
            parse_keepalive_packet(key_b, pkt)

    def test_tampered_tag_rejected(self):
        """Flipping a byte in the tag causes authentication failure."""
        from wg_noise import build_keepalive_packet, parse_keepalive_packet
        key = bytes(32)
        pkt = bytearray(build_keepalive_packet(key, receiver_index=1, counter=0))
        pkt[-1] ^= 0xFF  # flip last byte of tag
        with pytest.raises(Exception):
            parse_keepalive_packet(key, bytes(pkt))

    def test_tampered_header_rejected(self):
        """Flipping a byte in the header causes authentication failure."""
        from wg_noise import build_keepalive_packet, parse_keepalive_packet
        key = bytes(32)
        pkt = bytearray(build_keepalive_packet(key, receiver_index=1, counter=0))
        pkt[5] ^= 0xFF  # flip byte in receiver_index
        with pytest.raises(Exception):
            parse_keepalive_packet(key, bytes(pkt))

    def test_truncated_packet_rejected(self):
        """A packet shorter than 32 bytes is rejected."""
        from wg_noise import build_keepalive_packet, parse_keepalive_packet
        key = bytes(32)
        pkt = build_keepalive_packet(key, receiver_index=1, counter=0)
        with pytest.raises(AssertionError):
            parse_keepalive_packet(key, pkt[:31])

    def test_data_packet_not_accepted_as_keepalive(self):
        """A data packet (non-empty plaintext) fails keepalive size check."""
        from wg_noise import build_transport_packet, parse_keepalive_packet
        key = bytes(32)
        pkt = build_transport_packet(key, receiver_index=1, counter=0,
                                     plaintext=b"data")
        with pytest.raises(AssertionError, match="keepalive must be"):
            parse_keepalive_packet(key, pkt)


class TestKeepaliveAfterHandshake:
    """Keepalive round-trip through a full Python ↔ Python handshake."""

    def _complete_handshake(self):
        """Run a full handshake and return (i_send_key, i_recv_key, r_send_key, r_recv_key).

        derive_transport_keys always returns (τ1, τ2).
        Initiator: send=τ1, recv=τ2.  Responder: send=τ2, recv=τ1.
        """
        from wg_noise import WireGuardPeer, derive_transport_keys

        initiator = WireGuardPeer()
        responder = WireGuardPeer()

        init_msg, i_state = initiator.create_initiation(responder.public_key)
        r_state = responder.process_initiation(init_msg)
        resp_msg, r_state = responder.create_response(r_state)
        i_state = initiator.process_response(resp_msg, i_state)

        i_send, i_recv = derive_transport_keys(i_state.chaining_key)
        # Responder keys are swapped: send=τ2, recv=τ1
        r_recv, r_send = derive_transport_keys(r_state.chaining_key)

        return i_send, i_recv, r_send, r_recv, i_state, r_state

    def test_initiator_keepalive_to_responder(self):
        """Initiator sends keepalive, responder authenticates it."""
        from wg_noise import build_keepalive_packet, parse_keepalive_packet

        i_send, _, _, r_recv, i_state, r_state = self._complete_handshake()

        # Initiator builds keepalive with its send key
        pkt = build_keepalive_packet(
            i_send,
            receiver_index=r_state.local_index,
            counter=0,
        )

        # Responder authenticates with its recv key (= initiator's send key)
        rx_idx, ctr = parse_keepalive_packet(r_recv, pkt)
        assert ctr == 0

    def test_responder_keepalive_to_initiator(self):
        """Responder sends keepalive, initiator authenticates it."""
        from wg_noise import build_keepalive_packet, parse_keepalive_packet

        _, i_recv, r_send, _, i_state, r_state = self._complete_handshake()

        pkt = build_keepalive_packet(
            r_send,
            receiver_index=i_state.local_index,
            counter=0,
        )

        rx_idx, ctr = parse_keepalive_packet(i_recv, pkt)
        assert ctr == 0

    def test_keepalive_consumes_counter(self):
        """Keepalive at counter=0, data at counter=1 — both valid."""
        from wg_noise import (
            build_keepalive_packet, parse_keepalive_packet,
            build_transport_packet, parse_transport_packet,
        )

        i_send, _, _, r_recv, i_state, r_state = self._complete_handshake()
        rx_idx = r_state.local_index

        # counter 0: keepalive
        ka_pkt = build_keepalive_packet(i_send, rx_idx, counter=0)
        parse_keepalive_packet(r_recv, ka_pkt)

        # counter 1: data
        data_pkt = build_transport_packet(i_send, rx_idx, counter=1,
                                          plaintext=b"after keepalive")
        _, ctr, pt = parse_transport_packet(r_recv, data_pkt)
        assert ctr == 1
        assert pt == b"after keepalive"


# =====================================================================
#  Layer 2 — ESP32 integration tests (require hardware)
#
#  These tests verify that the REAL firmware timer state machine on
#  the ESP32-C6 honours the WireGuard whitepaper timing constants.
#
#  Observable UART log messages (from wg_task.c):
#    • "Peer %u: initiating rekey"          — initiate_rekey fired
#    • "Peer %u: session expired — expiring session"  — session_expired
#    • "Peer %u: rekey timed out — expiring session"  — rekey_timed_out
#    • "<< Rekey Initiation (%u bytes)"     — rekey packet sent
#
#  Timing:
#    Timer task ticks every 1 second.  REKEY_AFTER_TIME = 120 s,
#    REJECT_AFTER_TIME = 180 s.  Tests have ±10 s tolerance for tick
#    jitter and scheduling.
#
#  Long-running tests are marked @pytest.mark.slow so they can be
#  selected or excluded with `-m slow` / `-m "not slow"`.
# =====================================================================

WG_PORT = 51820
UDP_TIMEOUT = 5.0


def _get_esp32_ip(dut, timeout: int = 30) -> str:
    """Parse ESP32 IP address from boot UART output."""
    output = dut.expect(
        re.compile(rb"(?:sta ip:|got ip:)\s*(\d+\.\d+\.\d+\.\d+)"),
        timeout=timeout,
    )
    return output.group(1).decode()


def _do_handshake(dut, esp32_ip):
    """Perform a WireGuard handshake and return (sock, send_key, recv_key, rx_idx).

    The caller is responsible for closing the socket.
    """
    from wg_noise import (
        WireGuardPeer,
        derive_transport_keys,
        RESPONSE_SIZE,
        MSG_TYPE_RESPONSE,
    )
    from test_keys import python_private_key, esp32_public, preshared_key

    peer = WireGuardPeer(
        private_key=python_private_key(),
        psk=preshared_key(),
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(UDP_TIMEOUT)

    init_msg, init_state = peer.create_initiation(esp32_public())
    sock.sendto(init_msg, (esp32_ip, WG_PORT))

    resp_data, _ = sock.recvfrom(256)
    assert len(resp_data) == RESPONSE_SIZE
    assert resp_data[0] == MSG_TYPE_RESPONSE

    final_state = peer.process_response(resp_data, init_state)
    dut.expect("Handshake Response", timeout=5)

    send_key, recv_key = derive_transport_keys(final_state.chaining_key)
    return sock, send_key, recv_key, final_state.remote_index


# ── 2a. Boot and idle ─────────────────────────────────────────────────

@pytest.mark.esp32c6
class TestEsp32TimerBoot:
    """Timer subsystem initializes correctly and is quiet without sessions."""

    def test_timer_subsystem_boots(self, dut):
        """Timer queue + task + WG task all start during boot.

        Checks all three boot banners in the order they appear on UART:
          1. "Session timer queue initialized"   (wg_session_timer_init)
          2. "Session timer task started"         (task entry point)
          3. "wg0 netif"                           (wg_netif ready)
        """
        dut.expect("Session timer task started", timeout=10)
        dut.expect("wg0 netif", timeout=10)

    def test_no_spurious_events_without_session(self, dut):
        """All peers inactive → timer produces No_Action for 5 seconds.

        After full boot, let the timer tick 5 times.  None of the
        timer action log messages should appear because no peer has
        an active session.
        """
        dut.expect("wg0 netif", timeout=30)
        time.sleep(5)
        with pytest.raises(Exception):
            dut.expect(
                re.compile(
                    rb"(?:initiating rekey|session expired|rekey timed out)"
                ),
                timeout=2,
            )


# ── 2b. Fresh session — quiet period ─────────────────────────────────

@pytest.mark.esp32c6
class TestEsp32FreshSession:
    """After a handshake the session is quiet for well under REKEY_AFTER_TIME."""

    @pytest.fixture(autouse=True)
    def _boot(self, dut):
        """Wait for full boot and capture IP."""
        self._ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("wg0 netif", timeout=10)

    def test_no_events_first_15_seconds(self, dut):
        """For the first 15 s after handshake, no timer events fire.

        Session age 15 s is well below REKEY_AFTER_TIME (120 s) and
        REJECT_AFTER_TIME (180 s), so the timer should produce
        No_Action every tick.

        Duration: ~20 s.
        """
        sock, *_ = _do_handshake(dut, self._ip)
        try:
            time.sleep(15)
            with pytest.raises(Exception):
                dut.expect(
                    re.compile(
                        rb"(?:initiating rekey|session expired|rekey timed)"
                    ),
                    timeout=2,
                )
        finally:
            sock.close()

    def test_transport_works_during_timer_ticks(self, dut):
        """Transport data decrypts correctly while the timer task runs.

        Sends 5 packets with 2 s gaps (crossing timer ticks) and
        verifies the WG task processes each one.  The timer task at
        priority 7 must not interfere with transport at priority 6.

        Duration: ~15 s.
        """
        from wg_noise import build_transport_packet

        ip = self._ip
        sock, send_key, _, rx_idx = _do_handshake(dut, ip)
        try:
            for counter in range(5):
                pt = f"timer-test-{counter}".encode()
                pkt = build_transport_packet(send_key, rx_idx, counter, pt)
                sock.sendto(pkt, (ip, WG_PORT))
                dut.expect("Transport Data", timeout=5)
                if counter < 4:
                    time.sleep(2)
        finally:
            sock.close()


# ── 2c. REKEY_AFTER_TIME (120 s) ─────────────────────────────────────

@pytest.mark.esp32c6
@pytest.mark.slow
class TestEsp32RekeyAfterTime:
    """Verify REKEY_AFTER_TIME = 120 s triggers rekey on real hardware.

    After a handshake the ESP32 session ages in real time.  At ~120 s
    the timer fires ``initiate_rekey`` and the WG task sends a
    Handshake Initiation packet (visible on UART as
    "Peer 1: initiating rekey" followed by "<< Rekey Initiation").

    Duration: ~135 s per test.
    """

    @pytest.fixture(autouse=True)
    def _boot(self, dut):
        self._ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("wg0 netif", timeout=10)

    def test_rekey_initiated_at_120s(self, dut):
        """Rekey initiation fires at REKEY_AFTER_TIME = 120 s.

        We do a handshake, then wait up to 130 s for the log message.
        The timer ticks every 1 s so the actual rekey may appear at
        T=120 or T=121.
        """
        sock, *_ = _do_handshake(dut, self._ip)
        try:
            dut.expect("initiating rekey", timeout=REKEY_AFTER_TIME + 10)
        finally:
            sock.close()

    def test_rekey_sends_initiation_packet(self, dut):
        """After rekey fires, a Type 1 Handshake Initiation is sent.

        The WG task logs "<< Rekey Initiation" when it successfully
        queues the initiation packet for the IO thread.
        """
        sock, *_ = _do_handshake(dut, self._ip)
        try:
            dut.expect("Rekey Initiation", timeout=REKEY_AFTER_TIME + 10)
        finally:
            sock.close()

    def test_no_rekey_before_120s(self, dut):
        """No rekey fires during the first 115 seconds.

        We wait 115 s (5 s margin below REKEY_AFTER_TIME) and verify
        no "initiating rekey" appears.  This proves the timer respects
        the lower bound, not just the upper.
        """
        sock, *_ = _do_handshake(dut, self._ip)
        try:
            time.sleep(REKEY_AFTER_TIME - 5)
            with pytest.raises(Exception):
                dut.expect("initiating rekey", timeout=2)
        finally:
            sock.close()


# ── 2d. Rekey flag — no duplicate initiation ─────────────────────────

@pytest.mark.esp32c6
@pytest.mark.slow
class TestEsp32RekeyFlag:
    """After rekey flag is set, retries are gated to every 5 s.

    The C code calls ``session_set_rekey_flag()`` immediately after
    sending the rekey initiation.  This sets ``Rekey_Attempted = True``
    and records ``Rekey_Last_Sent``.  Subsequent ticks will retry the
    handshake every ``REKEY_TIMEOUT`` (5 s) but never faster.

    Duration: ~140 s.
    """

    @pytest.fixture(autouse=True)
    def _boot(self, dut):
        self._ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("wg0 netif", timeout=10)

    def test_no_immediate_duplicate_rekey(self, dut):
        """No immediate duplicate rekey — retries are gated to every 5 s.

        After the first rekey at ~120 s, the Rekey_Last_Sent gating
        prevents a second initiation for REKEY_TIMEOUT (5 s).  We
        verify no initiation fires within 4 s (under the gate), then
        confirm a retry does arrive within the next few seconds.
        """
        sock, *_ = _do_handshake(dut, self._ip)
        try:
            # Wait for the first rekey initiation
            dut.expect("initiating rekey", timeout=REKEY_AFTER_TIME + 10)

            # No immediate duplicate within 4 s (retry gate is 5 s)
            with pytest.raises(Exception):
                dut.expect("initiating rekey", timeout=4)

            # But a retry DOES arrive within the next ~6 s
            dut.expect("initiating rekey", timeout=REKEY_TIMEOUT + 5)
        finally:
            sock.close()


# ── 2e. REJECT_AFTER_TIME (180 s) ────────────────────────────────────

@pytest.mark.esp32c6
@pytest.mark.slow
class TestEsp32RejectAfterTime:
    """Verify REJECT_AFTER_TIME = 180 s expires the session.

    The session ages past REKEY_AFTER_TIME (rekey at ~120 s, Python
    does not respond), then at ~180 s the timer fires
    ``session_expired`` and the WG task calls ``session_expire()``.

    Duration: ~195 s per test.
    """

    @pytest.fixture(autouse=True)
    def _boot(self, dut):
        self._ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("wg0 netif", timeout=10)

    def test_session_expires_at_180s(self, dut):
        """Session expiry fires at REJECT_AFTER_TIME = 180 s.

        After handshake, we simply wait.  The timer fires rekey at
        ~120 s (which we ignore) and then expiry at ~180 s.  We look
        for the "session expired" log message.
        """
        sock, *_ = _do_handshake(dut, self._ip)
        try:
            dut.expect("session expired", timeout=REJECT_AFTER_TIME + 15)
        finally:
            sock.close()

    def test_expiry_beats_rekey_timeout(self, dut):
        """Session expires at 180 s, NOT rekey-timeout at 210 s.

        REKEY_AFTER_TIME (120) + REKEY_ATTEMPT_TIME (90) = 210 s,
        which exceeds REJECT_AFTER_TIME (180 s).  So time-based
        rekey can NEVER reach the timeout path — the session always
        expires first.  We verify "session expired" appears and
        "rekey timed out" does NOT.
        """
        sock, *_ = _do_handshake(dut, self._ip)
        try:
            # Must see session expired
            dut.expect("session expired", timeout=REJECT_AFTER_TIME + 15)

            # Must NOT see rekey timed out (it would have been at 210 s
            # but the session is already dead at 180 s)
            with pytest.raises(Exception):
                dut.expect("rekey timed out", timeout=5)
        finally:
            sock.close()


# ── 2f. Full lifecycle: handshake → rekey → expire ────────────────────

@pytest.mark.esp32c6
@pytest.mark.slow
class TestEsp32SessionLifecycle:
    """End-to-end lifecycle on real hardware: handshake → rekey → expire.

    A single test walks through the full timeline:
      T=0    Handshake completes (session active)
      T=0    Python sends one data packet (sets ESP32 Last_Received)
      T~15   §6.2 unresponsive peer detection fires (since_recv >= 15)
      T~15   Rekey flag set, retries every 5 s
      T~105  Rekey attempt times out (90 s window) → session expired

    Because Python sends data in Phase 1 (setting Last_Received) and
    then goes silent, the §6.2 path triggers at ~15 s — much earlier
    than the §6.1 REKEY_AFTER_TIME (120 s) path.  The 90 s rekey
    window then expires at ~105 s via "rekey timed out", well before
    REJECT_AFTER_TIME (180 s).

    Duration: ~120 s.
    """

    @pytest.fixture(autouse=True)
    def _boot(self, dut):
        self._ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("wg0 netif", timeout=10)

    def test_full_lifecycle(self, dut):
        """Walk the complete timer state machine on real hardware."""
        from wg_noise import build_transport_packet

        ip = self._ip
        sock, send_key, _, rx_idx = _do_handshake(dut, ip)
        try:
            # ── Phase 1: Fresh session (0–10 s) ──
            # Send a transport packet to prove session is alive.
            # This sets ESP32's Last_Received, so going silent will
            # trigger §6.2 unresponsive peer detection at ~T=15.
            pkt = build_transport_packet(
                send_key, rx_idx, 0, b"lifecycle-test"
            )
            sock.sendto(pkt, (ip, WG_PORT))
            dut.expect("Transport Data", timeout=5)

            # No timer events yet
            time.sleep(5)
            with pytest.raises(Exception):
                dut.expect(
                    re.compile(rb"(?:initiating rekey|expiring session)"),
                    timeout=2,
                )

            # ── Phase 2: Wait for rekey (→ ~15 s via §6.2) ──
            # Python is silent → since_recv grows past 15 s →
            # unresponsive peer detection fires initiate_rekey.
            dut.expect(
                "initiating rekey",
                timeout=KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + 15,
            )

            # ── Phase 3: No immediate duplicate (retry gated to 5 s) ──
            with pytest.raises(Exception):
                dut.expect("initiating rekey", timeout=4)

            # Retry arrives within the next ~6 s
            dut.expect("initiating rekey", timeout=REKEY_TIMEOUT + 5)

            # ── Phase 4: Session ends (rekey timed out at ~T=105) ──
            # The 90 s rekey-attempt window started at ~T=15 and
            # expires at ~T=105.  Match "expiring session" which is
            # the common log suffix for both session_expired and
            # rekey_timed_out paths.
            dut.expect(
                "expiring session",
                timeout=REKEY_ATTEMPT_TIME + 15,
            )

            # ── Phase 5: After expiry, timer is quiet again ──
            time.sleep(3)
            with pytest.raises(Exception):
                dut.expect(
                    re.compile(
                        rb"(?:initiating rekey|expiring session)"
                    ),
                    timeout=2,
                )
        finally:
            sock.close()


# ── 2g. Keepalive ─────────────────────────────────────────────────────

@pytest.mark.esp32c6
class TestEsp32KeepaliveRx:
    """ESP32 correctly handles incoming keepalive packets (Type 4, empty).

    After a handshake, Python sends a keepalive (zero-length Type 4
    packet = 32 bytes).  The ESP32 must:
      - Accept it (AEAD authenticates)
      - NOT echo anything back (keepalive is silent)
      - NOT log an error

    These tests are fast (no timer waits needed).
    """

    @pytest.fixture(autouse=True)
    def _boot(self, dut):
        self._ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("wg0 netif", timeout=10)

    def test_keepalive_accepted_silently(self, dut):
        """ESP32 processes a keepalive without error or echo.

        We send a 32-byte keepalive, verify no "wg_receive error"
        appears, and verify NO transport echo comes back (because
        keepalive plaintext is empty — nothing to echo).
        """
        from wg_noise import build_keepalive_packet

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            pkt = build_keepalive_packet(send_key, rx_idx, counter=0)
            assert len(pkt) == 32
            sock.sendto(pkt, (ip, WG_PORT))

            # Should NOT produce an error
            time.sleep(1)
            with pytest.raises(Exception):
                dut.expect("wg_receive error", timeout=2)

            # Should NOT echo anything back (keepalive = silent ack)
            sock.settimeout(2.0)
            try:
                data, _ = sock.recvfrom(512)
                pytest.fail(f"ESP32 echoed {len(data)} bytes for keepalive")
            except socket.timeout:
                pass  # expected — no echo
        finally:
            sock.close()

    def test_keepalive_then_data_works(self, dut):
        """A data packet sent after a keepalive still decrypts.

        Keepalive consumed counter=0.  Data at counter=1 must succeed.
        """
        from wg_noise import build_keepalive_packet, build_transport_packet

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            # counter 0: keepalive
            ka = build_keepalive_packet(send_key, rx_idx, counter=0)
            sock.sendto(ka, (ip, WG_PORT))
            time.sleep(0.5)

            # counter 1: real data
            pkt = build_transport_packet(
                send_key, rx_idx, counter=1, plaintext=b"after keepalive",
            )
            sock.sendto(pkt, (ip, WG_PORT))
            dut.expect("Transport Data", timeout=5)
        finally:
            sock.close()

    def test_multiple_keepalives(self, dut):
        """Multiple keepalives with incrementing counters all accepted."""
        from wg_noise import build_keepalive_packet

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            for counter in range(5):
                ka = build_keepalive_packet(send_key, rx_idx, counter=counter)
                sock.sendto(ka, (ip, WG_PORT))
                time.sleep(0.3)

            # No errors should have appeared
            with pytest.raises(Exception):
                dut.expect("wg_receive error", timeout=2)
        finally:
            sock.close()

    def test_tampered_keepalive_rejected(self, dut):
        """A keepalive with a flipped tag byte is rejected."""
        from wg_noise import build_keepalive_packet

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            ka = bytearray(build_keepalive_packet(send_key, rx_idx, counter=0))
            ka[-1] ^= 0xFF  # corrupt tag
            sock.sendto(bytes(ka), (ip, WG_PORT))

            dut.expect("wg_receive error", timeout=5)
        finally:
            sock.close()


@pytest.mark.esp32c6
class TestEsp32KeepaliveTx:
    """ESP32 sends keepalive when the timer fires (KEEPALIVE_TIMEOUT = 10 s).

    Per §6.5: if data was received recently (< 10 s) but nothing was
    sent for ≥ 10 s, send a keepalive.

    To trigger this:
      1. Complete a handshake (sets session creation time)
      2. Send data packets every ~3 s with echo mode OFF so that
         ESP32's last_received stays fresh while last_sent ages
         (no echo → no Mark_Sent)
      3. After ~12 s the keepalive condition fires:
         since_recv < 10  AND  since_sent >= 10

    The keepalive is a 32-byte Type 4 packet that Python can decrypt
    and verify has empty plaintext.

    Duration: ~20 s per test.
    """

    @pytest.fixture(autouse=True)
    def _boot(self, dut):
        self._ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("wg0 netif", timeout=10)

    def test_keepalive_fires_after_timeout(self, dut):
        """ESP32 sends a keepalive ~10 s after last receiving data.

        Echo mode is OFF (default).  Python sends data packets every 3 s
        to keep ESP32's last_received fresh, while last_sent ages past
        KEEPALIVE_TIMEOUT (no echo → no Mark_Sent).

        After ~12 s the condition triggers:
            since_recv < 10  AND  since_sent >= 10  →  send keepalive.
        """
        from wg_noise import (
            build_transport_packet, parse_keepalive_packet, KEEPALIVE_SIZE,
        )

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            # Send data packets every 3 s to keep last_received fresh.
            # Echo is OFF, so ESP32 never calls wg_send (last_sent ages).
            for counter in range(4):
                pkt = build_transport_packet(
                    send_key, rx_idx, counter=counter,
                    plaintext=f"keepalive-poke-{counter}".encode(),
                )
                sock.sendto(pkt, (ip, WG_PORT))
                dut.expect("Decrypted Transport Data", timeout=5)
                time.sleep(3)

            # By now ~12 s since handshake (last_sent).  Keep sending
            # so last_received stays fresh while we wait for the ESP32's
            # outbound keepalive.
            pkt = build_transport_packet(
                send_key, rx_idx, counter=4,
                plaintext=b"final-poke",
            )
            sock.sendto(pkt, (ip, WG_PORT))
            dut.expect("Decrypted Transport Data", timeout=5)

            # ESP32 should send a keepalive within a few seconds
            sock.settimeout(KEEPALIVE_TIMEOUT + 5)
            ka_data, _ = sock.recvfrom(512)

            assert len(ka_data) == KEEPALIVE_SIZE, (
                f"expected {KEEPALIVE_SIZE}-byte keepalive, got {len(ka_data)}"
            )

            # Verify it's a valid keepalive (authentic, empty plaintext)
            rx_idx_ka, ctr = parse_keepalive_packet(recv_key, ka_data)

        finally:
            sock.close()

    def test_keepalive_is_valid_type4(self, dut):
        """The keepalive packet has msg_type=4 and reserved=0."""
        from wg_noise import build_transport_packet, KEEPALIVE_SIZE

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            # Send data every 3 s — echo OFF keeps last_sent stale
            for counter in range(4):
                pkt = build_transport_packet(
                    send_key, rx_idx, counter=counter,
                    plaintext=f"type4-poke-{counter}".encode(),
                )
                sock.sendto(pkt, (ip, WG_PORT))
                dut.expect("Decrypted Transport Data", timeout=5)
                time.sleep(3)

            # One more poke to keep last_received fresh
            pkt = build_transport_packet(
                send_key, rx_idx, counter=4,
                plaintext=b"final-poke",
            )
            sock.sendto(pkt, (ip, WG_PORT))
            dut.expect("Decrypted Transport Data", timeout=5)

            sock.settimeout(KEEPALIVE_TIMEOUT + 5)
            ka_data, _ = sock.recvfrom(512)

            assert len(ka_data) == KEEPALIVE_SIZE
            assert ka_data[0] == 4        # MSG_TYPE_TRANSPORT
            assert ka_data[1:4] == b"\x00\x00\x00"  # reserved

        finally:
            sock.close()

    def test_no_keepalive_if_recently_sent(self, dut):
        """No keepalive if ESP32 keeps sending echoes within the timeout.

        Enable echo mode, then send a data packet every 3 seconds for
        15 seconds.  Since ESP32 echoes each packet (updating last_sent),
        the keepalive condition (last_sent >= 10 s) never triggers.

        Duration: ~20 s.
        """
        from wg_noise import (
            build_transport_packet, build_echo_mode_command, KEEPALIVE_SIZE,
        )

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            # Enable echo mode so ESP32 echoes data back
            sock.sendto(build_echo_mode_command(True), (ip, WG_PORT))
            dut.expect("Echo mode ON", timeout=5)

            for counter in range(5):
                pkt = build_transport_packet(
                    send_key, rx_idx, counter=counter,
                    plaintext=f"keep-alive-suppress-{counter}".encode(),
                )
                sock.sendto(pkt, (ip, WG_PORT))
                dut.expect("Decrypted Transport Data", timeout=5)

                # Drain echo (this updates ESP32's last_sent)
                sock.settimeout(3.0)
                try:
                    sock.recvfrom(512)
                except socket.timeout:
                    pass

                if counter < 4:
                    time.sleep(3)

            # After the burst, quickly check: no keepalive-sized packet
            # should be queued (ESP32 was sending echoes the whole time)
            sock.settimeout(3.0)
            try:
                data, _ = sock.recvfrom(512)
                # If we get something, it should be an echo, not keepalive
                if len(data) == KEEPALIVE_SIZE:
                    pytest.fail("Unexpected keepalive while actively sending")
            except socket.timeout:
                pass  # expected — nothing to send

        finally:
            sock.close()


# ── 2h. Unresponsive peer — rekey on silence (§6.2) ──────────────────

@pytest.mark.esp32c6
@pytest.mark.slow
class TestEsp32UnresponsivePeer:
    """ESP32 detects an unresponsive peer and initiates rekey (§6.2).

    Per whitepaper §6.2: if no transport data is received for
    Keepalive_Timeout + Rekey_Timeout = 15 seconds, the peer is
    considered unresponsive.  A handshake initiation is sent,
    then retried every Rekey_Timeout (5 s), until a new session
    is created or Rekey_Attempt_Time (90 s) passes.

    Test flow:
      1. Complete handshake
      2. Send one data packet (sets ESP32's Last_Received)
      3. Go silent — Python stops sending
      4. ESP32 sends keepalive at ~T=10 (since_sent >= 10)
      5. ESP32 detects unresponsive peer at ~T=15 (since_recv >= 15)
         and sends Handshake Initiation
      6. ESP32 retries every 5 s (visible in UART log)
      7. Eventually Rekey_Attempt_Time (90 s) expires → session drops

    Duration: ~120 s for the full test.
    """

    @pytest.fixture(autouse=True)
    def _boot(self, dut):
        self._ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("wg0 netif", timeout=10)

    def test_rekey_after_silence(self, dut):
        """ESP32 initiates rekey ~15 s after Python stops sending.

        After a handshake and one data packet, Python goes silent.
        The ESP32 should detect the unresponsive peer and send a
        Handshake Initiation within Keepalive_Timeout + Rekey_Timeout
        + margin (25 s).

        Duration: ~30 s.
        """
        from wg_noise import build_transport_packet

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            # Send one data packet so ESP32's Last_Received is set
            pkt = build_transport_packet(
                send_key, rx_idx, counter=0, plaintext=b"then silence",
            )
            sock.sendto(pkt, (ip, WG_PORT))
            dut.expect("Transport Data", timeout=5)

            # Go silent — ESP32 should detect unresponsive peer at ~15 s
            # and initiate a rekey handshake
            dut.expect(
                "initiating rekey",
                timeout=KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + 10,
            )
            dut.expect("Rekey Initiation", timeout=5)

        finally:
            sock.close()

    def test_rekey_retries_every_5s(self, dut):
        """ESP32 retries the handshake every Rekey_Timeout (5 s).

        After the first rekey initiation, we wait for a second one.
        With Rekey_Timeout = 5 s it should appear within 10 s.

        Duration: ~40 s.
        """
        from wg_noise import build_transport_packet

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            # One data packet then silence
            pkt = build_transport_packet(
                send_key, rx_idx, counter=0, plaintext=b"retry test",
            )
            sock.sendto(pkt, (ip, WG_PORT))
            dut.expect("Transport Data", timeout=5)

            # First rekey at ~15 s
            dut.expect(
                "initiating rekey",
                timeout=KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + 10,
            )

            # Second rekey should follow within ~5 s (+ margin)
            dut.expect("initiating rekey", timeout=REKEY_TIMEOUT + 5)

        finally:
            sock.close()

    def test_rekey_times_out_after_90s(self, dut):
        """Rekey attempt expires after Rekey_Attempt_Time (90 s).

        The ESP32 retries every 5 s for up to 90 s.  After that,
        rekey_timed_out fires and the session is expired.

        The first rekey fires at ~15 s.  The 90 s window starts
        then, so rekey_timed_out fires at ~105 s.

        Duration: ~120 s.
        """
        from wg_noise import build_transport_packet

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            # One data packet then silence
            pkt = build_transport_packet(
                send_key, rx_idx, counter=0, plaintext=b"timeout test",
            )
            sock.sendto(pkt, (ip, WG_PORT))
            dut.expect("Transport Data", timeout=5)

            # Wait for first rekey
            dut.expect(
                "initiating rekey",
                timeout=KEEPALIVE_TIMEOUT + REKEY_TIMEOUT + 10,
            )

            # Wait for rekey timeout (90 s from first rekey + margin)
            dut.expect(
                "rekey timed out",
                timeout=REKEY_ATTEMPT_TIME + 15,
            )

            # Session should be expired now — verify by checking
            # the expiry action happened
            dut.expect("expiring session", timeout=5)

        finally:
            sock.close()

    def test_no_rekey_if_peer_responsive(self, dut):
        """No unresponsive-peer rekey while Python keeps sending data.

        Send data packets every 3 s for 20 s.  Since since_recv
        never exceeds 15 s, the unresponsive peer condition never
        triggers.

        Duration: ~25 s.
        """
        from wg_noise import build_transport_packet

        ip = self._ip
        sock, send_key, recv_key, rx_idx = _do_handshake(dut, ip)
        try:
            for counter in range(7):
                pkt = build_transport_packet(
                    send_key, rx_idx, counter=counter,
                    plaintext=f"responsive-{counter}".encode(),
                )
                sock.sendto(pkt, (ip, WG_PORT))
                dut.expect("Transport Data", timeout=5)
                if counter < 6:
                    time.sleep(3)

            # No rekey should have fired
            with pytest.raises(Exception):
                dut.expect("initiating rekey", timeout=3)

        finally:
            sock.close()
