"""Auto-handshake end-to-end tests.

Layer 1 — Self-tests (Python):
    Validates the auto-handshake rate limiter and decision logic using the
    Python reference model in ``wg_session.py``.  The model mirrors the Ada
    ``Wireguard.Auto_Handshake`` procedure in ``wireguard.adb``.

    Sub-layers:
        1a. Auto-handshake rate limiting — first call initiates, subsequent
            calls within REKEY_TIMEOUT (5 s) are suppressed, calls after
            the timeout succeed.
        1b. In-flight handshake detection — if a handshake is already in
            progress (HS_Kind != State_Empty), auto-handshake is suppressed.
        1c. Session-active gate — auto-handshake is only triggered when the
            session is inactive.
        1d. Full lifecycle — models the complete auto-initiation flow:
            no session → data pending → auto-handshake → initiation →
            response → session established → data flows.

Layer 2 — ESP32 integration (requires hardware):
    End-to-end auto-handshake tests against the ESP32.  Uses
    WG_CMD_INJECT_INNER to push inner traffic, triggering the auto-handshake
    flow.  Python acts as the remote WireGuard peer.
"""

import re
import socket
import struct
import time
import pytest

from wg_noise import (
    WireGuardPeer,
    derive_transport_keys,
    build_transport_packet,
    parse_transport_packet,
    build_inject_inner_command,
    build_echo_mode_command,
    INITIATION_SIZE,
    RESPONSE_SIZE,
    MSG_TYPE_INITIATION,
    MSG_TYPE_RESPONSE,
    TRANSPORT_HEADER_SIZE,
)

from wg_session import (
    # Constants
    REKEY_TIMEOUT,
    NEVER,
    # Auto-handshake model
    HandshakeStateKind,
    AutoHandshakeState,
    auto_handshake,
    # Session model
    PeerState,
    null_peer,
    make_active_peer,
    activate_next,
    expire_session,
    make_keypair,
)

from test_keys import (
    python_private_key,
    esp32_public,
    preshared_key,
)


# =====================================================================
#  Layer 1a — Auto-handshake rate limiting
# =====================================================================

class TestAutoHandshakeRateLimit:
    """Rate limiting: at most one initiation per REKEY_TIMEOUT (5 s)."""

    def test_first_call_initiates(self):
        """First auto-handshake call with no prior history should initiate."""
        state = AutoHandshakeState()
        new_state, should_init = auto_handshake(state, session_active=False, now=10)
        assert should_init is True
        assert new_state.last_auto_init == 10

    def test_immediate_second_call_suppressed(self):
        """Second call at the same timestamp is rate-limited."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_EMPTY,
            last_auto_init=10,
        )
        new_state, should_init = auto_handshake(state, session_active=False, now=10)
        assert should_init is False

    def test_call_within_timeout_suppressed(self):
        """Calls within REKEY_TIMEOUT (5 s) of last initiation are suppressed."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_EMPTY,
            last_auto_init=10,
        )
        for t in range(11, 10 + REKEY_TIMEOUT):
            _, should_init = auto_handshake(state, session_active=False, now=t)
            assert should_init is False, f"should be suppressed at t={t}"

    def test_call_at_timeout_boundary_initiates(self):
        """Call exactly at REKEY_TIMEOUT seconds after last init should succeed."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_EMPTY,
            last_auto_init=10,
        )
        new_state, should_init = auto_handshake(
            state, session_active=False, now=10 + REKEY_TIMEOUT
        )
        assert should_init is True
        assert new_state.last_auto_init == 10 + REKEY_TIMEOUT

    def test_call_after_timeout_initiates(self):
        """Calls well past the rate limit window should succeed."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_EMPTY,
            last_auto_init=10,
        )
        new_state, should_init = auto_handshake(
            state, session_active=False, now=100
        )
        assert should_init is True
        assert new_state.last_auto_init == 100

    def test_never_timestamp_always_allows(self):
        """If last_auto_init is NEVER (0), first call always succeeds."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_EMPTY,
            last_auto_init=NEVER,
        )
        new_state, should_init = auto_handshake(state, session_active=False, now=1)
        assert should_init is True

    def test_rate_limit_uses_rekey_timeout_constant(self):
        """Rate limit interval matches REKEY_TIMEOUT = 5 seconds."""
        assert REKEY_TIMEOUT == 5
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_EMPTY,
            last_auto_init=100,
        )
        # At t=104 (4s elapsed): suppressed
        _, init_4 = auto_handshake(state, session_active=False, now=104)
        assert init_4 is False
        # At t=105 (5s elapsed): allowed
        _, init_5 = auto_handshake(state, session_active=False, now=105)
        assert init_5 is True

    def test_successive_initiations_respect_timeout(self):
        """After a successful initiation, the next is blocked for REKEY_TIMEOUT."""
        state = AutoHandshakeState()

        # First initiation at t=10
        state, init1 = auto_handshake(state, session_active=False, now=10)
        assert init1 is True

        # Simulate handshake completing: reset hs_kind to empty
        state.hs_kind = HandshakeStateKind.STATE_EMPTY

        # Too soon at t=12
        _, init2 = auto_handshake(state, session_active=False, now=12)
        assert init2 is False

        # OK at t=15
        state, init3 = auto_handshake(state, session_active=False, now=15)
        assert init3 is True


# =====================================================================
#  Layer 1b — In-flight handshake detection
# =====================================================================

class TestAutoHandshakeInFlight:
    """Handshake in-flight detection: skip if HS_Kind != State_Empty."""

    def test_state_empty_allows(self):
        """State_Empty (no handshake in progress) allows auto-initiation."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_EMPTY,
        )
        _, should_init = auto_handshake(state, session_active=False, now=10)
        assert should_init is True

    def test_initiator_sent_blocks(self):
        """State_Initiator_Sent (initiation in flight) blocks auto-initiation."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_INITIATOR_SENT,
            last_auto_init=1,  # Old enough to pass rate limit
        )
        _, should_init = auto_handshake(state, session_active=False, now=100)
        assert should_init is False

    def test_responder_sent_blocks(self):
        """State_Responder_Sent blocks auto-initiation."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_RESPONDER_SENT,
        )
        _, should_init = auto_handshake(state, session_active=False, now=100)
        assert should_init is False

    def test_established_blocks(self):
        """State_Established blocks auto-initiation.

        This state is transient (cleared after session derivation),
        but while it exists, auto-init should not fire.
        """
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_ESTABLISHED,
        )
        _, should_init = auto_handshake(state, session_active=False, now=100)
        assert should_init is False

    def test_in_flight_blocks_even_past_rate_limit(self):
        """In-flight handshake blocks even if rate limit has expired."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_INITIATOR_SENT,
            last_auto_init=1,
        )
        # Way past the rate limit, but handshake in flight
        _, should_init = auto_handshake(state, session_active=False, now=1000)
        assert should_init is False

    def test_reset_to_empty_after_timeout_allows_reinit(self):
        """After handshake fails and state resets to Empty, auto-init fires again."""
        # Initial state: handshake in flight, rate-limited
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_INITIATOR_SENT,
            last_auto_init=10,
        )
        # Handshake in flight — blocked
        _, init1 = auto_handshake(state, session_active=False, now=20)
        assert init1 is False

        # Handshake times out, state resets to empty
        state.hs_kind = HandshakeStateKind.STATE_EMPTY

        # Now allowed (past rate limit too)
        state, init2 = auto_handshake(state, session_active=False, now=20)
        assert init2 is True


# =====================================================================
#  Layer 1c — Session-active gate
# =====================================================================

class TestAutoHandshakeSessionGate:
    """Session-active gate: auto-handshake only when session is inactive."""

    def test_active_session_blocks(self):
        """Auto-handshake is suppressed when session is active."""
        state = AutoHandshakeState()
        _, should_init = auto_handshake(state, session_active=True, now=10)
        assert should_init is False

    def test_inactive_session_allows(self):
        """Auto-handshake fires when session is inactive."""
        state = AutoHandshakeState()
        _, should_init = auto_handshake(state, session_active=False, now=10)
        assert should_init is True

    def test_session_drops_then_reinit(self):
        """After session expires, auto-handshake fires on next data."""
        state = AutoHandshakeState()

        # Session active — no auto-init
        _, init1 = auto_handshake(state, session_active=True, now=10)
        assert init1 is False

        # Session expires — auto-init fires
        state, init2 = auto_handshake(state, session_active=False, now=200)
        assert init2 is True

    def test_active_session_does_not_update_timestamp(self):
        """When session is active, last_auto_init should not change."""
        state = AutoHandshakeState(last_auto_init=5)
        new_state, should_init = auto_handshake(state, session_active=True, now=10)
        assert should_init is False
        assert new_state.last_auto_init == 5  # Unchanged


# =====================================================================
#  Layer 1d — Full lifecycle integration
# =====================================================================

class TestAutoHandshakeLifecycle:
    """Full auto-handshake lifecycle: no session → handshake → session → data."""

    def test_full_auto_init_flow(self):
        """Complete flow: auto-init → handshake → session → transport data.

        Models the full sequence from wg_task.c:
          1. Inner data queued, no session → auto_handshake fires
          2. Initiation created and sent
          3. Response received, session established
          4. Data can now be encrypted and sent
        """
        # Step 0: Initial state — no session, no handshake
        ah_state = AutoHandshakeState()
        session = null_peer()
        assert not session.active

        # Step 1: Data arrives — auto-handshake triggers
        ah_state, should_init = auto_handshake(
            ah_state, session_active=False, now=10
        )
        assert should_init is True
        assert ah_state.hs_kind == HandshakeStateKind.STATE_INITIATOR_SENT

        # Step 2: Build and send initiation (using wg_noise oracle)
        initiator = WireGuardPeer()
        responder = WireGuardPeer()
        init_msg, i_state = initiator.create_initiation(responder.public_key)
        assert len(init_msg) == INITIATION_SIZE

        # Step 3: Responder processes initiation, sends response
        r_state = responder.process_initiation(init_msg)
        resp_msg, r_state = responder.create_response(r_state)
        assert len(resp_msg) == RESPONSE_SIZE

        # Step 4: Initiator processes response — session established
        i_state = initiator.process_response(resp_msg, i_state)
        i_send, i_recv = derive_transport_keys(i_state.chaining_key)

        # Model session activation
        ah_state.hs_kind = HandshakeStateKind.STATE_EMPTY  # Reset after derivation
        session = make_active_peer(created_at=10, is_initiator=True)

        # Step 5: Data flows — transport encryption works
        data_pkt = build_transport_packet(
            i_send,
            receiver_index=r_state.local_index,
            counter=0,
            plaintext=b"hello after auto-init",
        )
        r_recv, _ = derive_transport_keys(r_state.chaining_key)
        _, _, pt = parse_transport_packet(r_recv, data_pkt)
        assert pt == b"hello after auto-init"

        # Step 6: With active session, auto-handshake is suppressed
        _, should_init = auto_handshake(
            ah_state, session_active=True, now=11
        )
        assert should_init is False

    def test_auto_init_retry_after_timeout(self):
        """If handshake times out, auto-init retries after rate limit.

        Models the sequence:
          1. Auto-init fires
          2. Handshake in flight (blocked)
          3. Handshake times out → state resets
          4. Rate limit elapses → auto-init fires again
        """
        ah_state = AutoHandshakeState()

        # t=10: First auto-init
        ah_state, init1 = auto_handshake(
            ah_state, session_active=False, now=10
        )
        assert init1 is True
        assert ah_state.hs_kind == HandshakeStateKind.STATE_INITIATOR_SENT

        # t=12: Handshake in flight — blocked
        _, init2 = auto_handshake(ah_state, session_active=False, now=12)
        assert init2 is False

        # t=15: Handshake times out (no response received)
        # State machine resets to empty
        ah_state.hs_kind = HandshakeStateKind.STATE_EMPTY

        # t=15: Rate limit just expired (5s since t=10) — retry succeeds
        ah_state, init3 = auto_handshake(
            ah_state, session_active=False, now=15
        )
        assert init3 is True
        assert ah_state.last_auto_init == 15

    def test_auto_init_suppressed_during_active_session_then_fires_after_expiry(self):
        """Auto-init stays quiet during active session, fires after expiry.

        Models:
          1. Session established (auto-init suppressed)
          2. Session expires at t=190 (REJECT_AFTER_TIME=180 from t=10)
          3. New data arrives → auto-init fires
        """
        ah_state = AutoHandshakeState()

        # Active session — auto-init blocked
        _, init1 = auto_handshake(ah_state, session_active=True, now=50)
        assert init1 is False

        # Session expires externally
        # Now inactive — auto-init fires
        ah_state, init2 = auto_handshake(
            ah_state, session_active=False, now=200
        )
        assert init2 is True

    def test_repeated_rate_limited_retries(self):
        """Multiple retry cycles respect the rate limit each time.

        Simulates 3 failed handshake attempts, each followed by a
        rate-limited retry.
        """
        ah_state = AutoHandshakeState()
        init_times = []

        for attempt in range(3):
            t_init = 10 + attempt * (REKEY_TIMEOUT + 1)  # 10, 16, 22

            # Auto-init fires
            ah_state, should_init = auto_handshake(
                ah_state, session_active=False, now=t_init
            )
            assert should_init is True, f"attempt {attempt} should initiate"
            init_times.append(t_init)

            # Handshake in flight — blocked at t+1
            _, blocked = auto_handshake(
                ah_state, session_active=False, now=t_init + 1
            )
            assert blocked is False

            # Handshake fails — reset to empty
            ah_state.hs_kind = HandshakeStateKind.STATE_EMPTY

        # Verify attempts were properly spaced
        assert init_times == [10, 16, 22]
        for i in range(1, len(init_times)):
            assert init_times[i] - init_times[i - 1] >= REKEY_TIMEOUT

    def test_bidirectional_after_auto_init(self):
        """After auto-initiated handshake, both directions work.

        Full crypto round-trip: auto-init → handshake → bidirectional
        transport data exchange.
        """
        # Auto-init decision
        ah_state = AutoHandshakeState()
        ah_state, should_init = auto_handshake(
            ah_state, session_active=False, now=10
        )
        assert should_init is True

        # Full handshake
        initiator = WireGuardPeer()
        responder = WireGuardPeer()

        init_msg, i_state = initiator.create_initiation(responder.public_key)
        r_state = responder.process_initiation(init_msg)
        resp_msg, r_state = responder.create_response(r_state)
        i_state = initiator.process_response(resp_msg, i_state)

        i_send, i_recv = derive_transport_keys(i_state.chaining_key)
        r_recv, r_send = derive_transport_keys(r_state.chaining_key)

        # Initiator → Responder
        pkt_ir = build_transport_packet(
            i_send, r_state.local_index, counter=0, plaintext=b"ping"
        )
        _, _, pt_ir = parse_transport_packet(r_recv, pkt_ir)
        assert pt_ir == b"ping"

        # Responder → Initiator
        pkt_ri = build_transport_packet(
            r_send, i_state.local_index, counter=0, plaintext=b"pong"
        )
        _, _, pt_ri = parse_transport_packet(i_recv, pkt_ri)
        assert pt_ri == b"pong"

    def test_session_timer_integration(self):
        """Auto-handshake state integrates correctly with session timers.

        Verifies that the auto-handshake model and session timer model
        work together: session expires via timer → auto-init fires →
        new session established.
        """
        from wg_session import tick, REJECT_AFTER_TIME

        # Start with active session created at t=10
        peer = make_active_peer(created_at=10, is_initiator=True)
        ah_state = AutoHandshakeState()

        # t=50: session active, auto-init blocked
        _, init_early = auto_handshake(ah_state, session_active=True, now=50)
        assert init_early is False

        # t=191: session timer says expired (180s after creation at t=10 → t=190)
        action = tick(peer, now=10 + REJECT_AFTER_TIME)
        assert action.session_expired is True

        # Apply expiry
        peer = expire_session(peer)
        assert not peer.current.valid
        # Note: expire_session nullifies keypairs but doesn't clear the
        # `active` flag in the Python model.  In Ada, Is_Active checks
        # the Mode enum (Inactive after expiry).  The session is effectively
        # dead because all keypairs are invalid — tick() returns No_Action.

        # t=195: auto-init fires for the expired session
        ah_state, init_after = auto_handshake(
            ah_state, session_active=False, now=195
        )
        assert init_after is True
        assert ah_state.hs_kind == HandshakeStateKind.STATE_INITIATOR_SENT


# =====================================================================
#  Layer 1e — Edge cases and preconditions
# =====================================================================

class TestAutoHandshakeEdgeCases:
    """Edge cases and boundary conditions."""

    def test_now_must_be_greater_than_never(self):
        """Precondition: now > NEVER (0) — matches Ada assertion."""
        state = AutoHandshakeState()
        with pytest.raises(AssertionError, match="now must be > NEVER"):
            auto_handshake(state, session_active=False, now=0)

    def test_now_equals_one_works(self):
        """Minimum valid timestamp (now=1) should work."""
        state = AutoHandshakeState()
        _, should_init = auto_handshake(state, session_active=False, now=1)
        assert should_init is True

    def test_large_timestamps(self):
        """Auto-handshake works with large 64-bit timestamps."""
        state = AutoHandshakeState(
            hs_kind=HandshakeStateKind.STATE_EMPTY,
            last_auto_init=2**62,
        )
        _, init1 = auto_handshake(
            state, session_active=False, now=2**62 + REKEY_TIMEOUT - 1
        )
        assert init1 is False

        _, init2 = auto_handshake(
            state, session_active=False, now=2**62 + REKEY_TIMEOUT
        )
        assert init2 is True

    def test_state_immutability(self):
        """auto_handshake returns a new state, does not mutate the input."""
        state = AutoHandshakeState()
        original_init = state.last_auto_init
        original_kind = state.hs_kind

        new_state, _ = auto_handshake(state, session_active=False, now=10)

        # Original unchanged
        assert state.last_auto_init == original_init
        assert state.hs_kind == original_kind
        # New state updated
        assert new_state.last_auto_init == 10

    def test_handshake_state_kind_values(self):
        """HandshakeStateKind enum values match Ada Handshake_State_Kind."""
        assert HandshakeStateKind.STATE_EMPTY == 0
        assert HandshakeStateKind.STATE_INITIATOR_SENT == 1
        assert HandshakeStateKind.STATE_RESPONDER_SENT == 2
        assert HandshakeStateKind.STATE_ESTABLISHED == 3

    def test_default_state(self):
        """Default AutoHandshakeState matches Ada package initialization."""
        state = AutoHandshakeState()
        assert state.hs_kind == HandshakeStateKind.STATE_EMPTY
        assert state.last_auto_init == NEVER

    def test_all_hs_kinds_block_except_empty(self):
        """Verify all non-Empty HS_Kind values block auto-initiation."""
        for kind in [
            HandshakeStateKind.STATE_INITIATOR_SENT,
            HandshakeStateKind.STATE_RESPONDER_SENT,
            HandshakeStateKind.STATE_ESTABLISHED,
        ]:
            state = AutoHandshakeState(hs_kind=kind, last_auto_init=NEVER)
            _, should_init = auto_handshake(
                state, session_active=False, now=100
            )
            assert should_init is False, (
                f"HS_Kind={kind} should block auto-initiation"
            )


# =====================================================================
#  Layer 2 — ESP32 integration tests (require hardware)
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


def _build_ipv4_udp(src_ip: str, dst_ip: str, payload: bytes,
                     src_port: int = 12345, dst_port: int = 53) -> bytes:
    """Build a minimal IPv4/UDP packet for inject-inner testing.

    Constructs a valid-enough IPv4 header + UDP header + payload.
    The IP header checksum is computed; the UDP checksum is set to 0
    (valid per RFC 768 for IPv4).

    Args:
        src_ip:   Source IPv4 address (tunnel source, e.g. "10.0.0.2")
        dst_ip:   Destination IPv4 address (tunnel dest, e.g. "10.0.0.1")
        payload:  UDP payload bytes
        src_port: UDP source port (default 12345)
        dst_port: UDP destination port (default 53)

    Returns:
        Raw IPv4 packet bytes
    """
    udp_len = 8 + len(payload)
    udp_hdr = struct.pack("!HHHH", src_port, dst_port, udp_len, 0)

    # IPv4 header (20 bytes, no options)
    ip_total_len = 20 + udp_len
    ip_hdr = bytearray(20)
    ip_hdr[0] = 0x45       # Version=4, IHL=5
    ip_hdr[1] = 0x00       # DSCP/ECN
    struct.pack_into("!H", ip_hdr, 2, ip_total_len)
    struct.pack_into("!H", ip_hdr, 4, 0x1234)  # Identification
    struct.pack_into("!H", ip_hdr, 6, 0x4000)  # Don't-fragment
    ip_hdr[8] = 64         # TTL
    ip_hdr[9] = 17         # Protocol = UDP
    # Checksum at [10:12] — compute after filling addresses
    ip_hdr[12:16] = socket.inet_aton(src_ip)
    ip_hdr[16:20] = socket.inet_aton(dst_ip)

    # IP header checksum
    words = [int.from_bytes(ip_hdr[i:i+2], "big") for i in range(0, 20, 2)]
    s = sum(words)
    while s > 0xFFFF:
        s = (s & 0xFFFF) + (s >> 16)
    struct.pack_into("!H", ip_hdr, 10, (~s) & 0xFFFF)

    return bytes(ip_hdr) + udp_hdr + payload


@pytest.mark.esp32c6
class TestEsp32AutoHandshake:
    """E2E auto-handshake tests: inject inner traffic → handshake → data.

    These tests exercise the full cryptokey routing stack on the ESP32:
      1. Python injects a synthetic IP packet via WG_CMD_INJECT_INNER
      2. ESP32 enqueues it, finds no session → auto-handshake fires
      3. ESP32 sends Handshake Initiation to Python (the source of the inject)
      4. Python completes the handshake
      5. ESP32 drains the inner queue, encrypts, and sends the data

    Requires:
    - ESP32-C6 connected via USB
    - Firmware built with matching test keys (see test_keys.py)
    - Peer 1 configured with AllowedIPs 0.0.0.0/0
    """

    @pytest.fixture
    def wg_peer(self):
        """Python-side WireGuard peer with fixed test keys."""
        return WireGuardPeer(
            private_key=python_private_key(),
            psk=preshared_key(),
        )

    @pytest.fixture
    def esp32_addr(self, dut):
        """Wait for ESP32 to boot and return (ip, port) tuple."""
        ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("WireGuard initialized", timeout=30)
        dut.expect("wg0 netif", timeout=10)
        return (ip, WG_PORT)

    def test_inject_triggers_initiation(self, dut, wg_peer, esp32_addr):
        """Injected inner traffic with no session triggers auto-handshake.

        Flow:
          1. Python sends CMD_INJECT_INNER with dest IP + UDP payload
          2. ESP32 sendto() via wg0 → lwIP → wg_netif_output → inner queue
          3. No session → auto_handshake fires → initiation sent
          4. Python verifies it's a valid Type 1 message
        """
        cmd = build_inject_inner_command("10.0.0.1", 9999, b"trigger")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            sock.sendto(cmd, esp32_addr)

            # ESP32 should log the inject and the auto-handshake
            dut.expect("CMD: Inject inner", timeout=5)

            # Receive the auto-initiated Handshake Initiation
            init_data, _ = sock.recvfrom(256)

            assert len(init_data) == INITIATION_SIZE
            assert init_data[0] == MSG_TYPE_INITIATION

            dut.expect("Auto-initiating handshake", timeout=5)
        finally:
            sock.close()

    def test_inject_rate_limited(self, dut, wg_peer, esp32_addr):
        """Two injects within 5s produce only one initiation.

        After the first inject triggers an initiation, a second inject
        within REKEY_TIMEOUT (5s) should be enqueued but NOT produce
        another initiation (rate-limited by Ada).
        """
        cmd = build_inject_inner_command("10.0.0.1", 9999, b"first")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            # First inject → initiation
            sock.sendto(cmd, esp32_addr)
            init_data, _ = sock.recvfrom(256)
            assert init_data[0] == MSG_TYPE_INITIATION

            # Second inject immediately — should NOT produce another initiation
            cmd2 = build_inject_inner_command("10.0.0.1", 9999, b"second")
            sock.sendto(cmd2, esp32_addr)

            # Wait briefly — no second initiation should arrive
            sock.settimeout(2.0)
            with pytest.raises(socket.timeout):
                sock.recvfrom(256)
        finally:
            sock.close()

    def test_full_lifecycle(self, dut, wg_peer, esp32_addr):
        """Complete E2E: inject → auto-handshake → session → data flows.

        Full cryptokey routing lifecycle:
          1. Python injects UDP payload via BSD socket path on ESP32
          2. No session → auto-handshake fires → initiation sent
          3. Python processes initiation, sends response
          4. ESP32 completes handshake, activates session
          5. ESP32 drains inner queue → encrypts queued packet → sends it
          6. Python decrypts the transport packet, verifies UDP payload
        """
        inner_payload = b"hello through the tunnel"
        cmd = build_inject_inner_command("10.0.0.1", 9999, inner_payload)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            # Step 1: Inject inner traffic
            sock.sendto(cmd, esp32_addr)

            # Step 2: Receive auto-initiated handshake
            init_data, _ = sock.recvfrom(256)
            assert len(init_data) == INITIATION_SIZE
            assert init_data[0] == MSG_TYPE_INITIATION

            # Step 3: Python acts as responder
            resp_state = wg_peer.process_initiation(init_data)
            resp_msg, resp_state = wg_peer.create_response(resp_state)
            assert len(resp_msg) == RESPONSE_SIZE

            sock.sendto(resp_msg, esp32_addr)

            # Step 4: ESP32 completes handshake
            dut.expect("Processed", timeout=5)

            # Step 5: ESP32 drains inner queue and sends encrypted data
            # The queued UDP payload is inside an lwIP-built IP packet
            enc_data, _ = sock.recvfrom(2048)

            assert enc_data[0] == 0x04  # MSG_TYPE_TRANSPORT

            # Step 6: Decrypt and verify the UDP payload is embedded
            # ESP32 was the initiator → its send key is τ1
            # Python as responder → recv key is τ1
            r_recv, r_send = derive_transport_keys(resp_state.chaining_key)
            _, _, plaintext = parse_transport_packet(r_recv, enc_data)

            # The decrypted payload is an lwIP-built IP/UDP packet
            # containing our application payload
            assert inner_payload in plaintext
        finally:
            sock.close()

    def test_bidirectional_after_auto_init(self, dut, wg_peer, esp32_addr):
        """After auto-initiated handshake, bidirectional data works.

        Verifies that after auto-handshake completes:
          1. ESP32 → Python: queued inner data arrives encrypted
          2. Python → ESP32: new transport data is accepted and decrypted
        """
        outbound_payload = b"outbound"
        cmd = build_inject_inner_command("10.0.0.1", 9999, outbound_payload)

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            # Inject → auto-handshake → complete handshake
            sock.sendto(cmd, esp32_addr)
            init_data, _ = sock.recvfrom(256)
            assert init_data[0] == MSG_TYPE_INITIATION

            resp_state = wg_peer.process_initiation(init_data)
            resp_msg, resp_state = wg_peer.create_response(resp_state)
            sock.sendto(resp_msg, esp32_addr)
            dut.expect("Processed", timeout=5)

            r_recv, r_send = derive_transport_keys(resp_state.chaining_key)

            # Direction 1: ESP32 → Python (drained inner queue)
            enc_data, _ = sock.recvfrom(2048)
            assert enc_data[0] == 0x04
            _, _, pt_out = parse_transport_packet(r_recv, enc_data)
            assert outbound_payload in pt_out

            # Enable echo mode for direction 2
            sock.sendto(build_echo_mode_command(True), esp32_addr)
            dut.expect("Echo mode ON", timeout=5)

            # Direction 2: Python → ESP32 (echo mode)
            inbound = b"inbound echo test"
            pkt = build_transport_packet(
                r_send,
                receiver_index=resp_state.remote_index,
                counter=0,
                plaintext=inbound,
            )
            sock.sendto(pkt, esp32_addr)

            # ESP32 decrypts, echoes back encrypted
            echo_data, _ = sock.recvfrom(2048)
            assert echo_data[0] == 0x04
            _, _, pt_echo = parse_transport_packet(r_recv, echo_data)
            assert pt_echo == inbound
        finally:
            sock.close()

    def test_second_inject_queued_and_drained(self, dut, wg_peer, esp32_addr):
        """Multiple injected packets are queued and all drained after handshake.

        Verifies the inner queue staging:
          1. Inject 2 packets → both enqueued
          2. Auto-handshake fires once (rate-limited)
          3. After handshake completes, both packets are encrypted and sent
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            # Inject both packets
            sock.sendto(
                build_inject_inner_command("10.0.0.1", 9999, b"first"),
                esp32_addr)
            time.sleep(0.05)  # small gap to ensure ordering
            sock.sendto(
                build_inject_inner_command("10.0.0.1", 9999, b"second"),
                esp32_addr)

            # Receive single initiation
            init_data, _ = sock.recvfrom(256)
            assert init_data[0] == MSG_TYPE_INITIATION

            # Complete handshake
            resp_state = wg_peer.process_initiation(init_data)
            resp_msg, resp_state = wg_peer.create_response(resp_state)
            sock.sendto(resp_msg, esp32_addr)
            dut.expect("Processed", timeout=5)

            r_recv, _ = derive_transport_keys(resp_state.chaining_key)

            # Both queued packets should arrive as encrypted transport data
            payloads = []
            for _ in range(2):
                enc_data, _ = sock.recvfrom(2048)
                assert enc_data[0] == 0x04
                _, _, pt = parse_transport_packet(r_recv, enc_data)
                payloads.append(pt)

            # Check both UDP payloads are present in the decrypted packets
            combined = b"".join(payloads)
            assert b"first" in combined
            assert b"second" in combined
        finally:
            sock.close()
