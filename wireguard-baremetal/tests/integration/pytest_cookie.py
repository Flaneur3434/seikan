"""WireGuard cookie mechanism tests (§5.4.7).

Layer 1 — Self-tests (Python ↔ Python):
    Validates XChaCha20-Poly1305, cookie reply construction/parsing,
    MAC2 computation, and replay protection via TAI64N ordering.

Layer 2 — Cross-validation vectors:
    Tests HChaCha20 against RFC 7539 / draft-irtf-cfrg-xchacha test vectors.

Layer 3 — ESP32 integration (requires hardware):
    Tests the full cookie flow on real hardware:
    - Python sends initiation → ESP32 responds
    - Python sends cookie reply → ESP32 stores cookie
    - ESP32 re-initiates with MAC2 set from the stored cookie
"""

import os
import re
import socket
import struct
import time
import pytest

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from wg_noise import (
    WireGuardPeer,
    HandshakeState,
    blake2s,
    compute_mac,
    mac1_key,
    cookie_key,
    tai64n_now,
    hchacha20,
    xchacha20poly1305_encrypt,
    xchacha20poly1305_decrypt,
    build_cookie_reply,
    parse_cookie_reply,
    create_initiation_with_mac2,
    derive_transport_keys,
    LABEL_MAC1,
    LABEL_COOKIE,
    MSG_TYPE_INITIATION,
    MSG_TYPE_RESPONSE,
    MSG_TYPE_COOKIE,
    INITIATION_SIZE,
    RESPONSE_SIZE,
    COOKIE_REPLY_SIZE,
)

from test_keys import (
    python_private_key,
    python_public,
    esp32_public,
    preshared_key,
)


# =====================================================================
#  Layer 1 — HChaCha20 & XChaCha20-Poly1305
# =====================================================================

class TestHChaCha20:
    """HChaCha20 key derivation function tests."""

    def test_rfc_vector(self):
        """HChaCha20 test vector from draft-irtf-cfrg-xchacha §2.2.1."""
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        )
        nonce = bytes.fromhex(
            "000000090000004a0000000031415927"
        )
        expected = bytes.fromhex(
            "82413b4227b27bfed30e42508a877d73"
            "a0f9e4d58a74a853c12ec41326d3ecdc"
        )
        assert hchacha20(key, nonce) == expected

    def test_zero_key_zero_nonce(self):
        """HChaCha20 with all-zero inputs is deterministic and non-zero."""
        result = hchacha20(bytes(32), bytes(16))
        assert len(result) == 32
        assert result != bytes(32), "HChaCha20 of zeros should not be zeros"

    def test_different_nonces_produce_different_subkeys(self):
        """Different nonces with same key → different subkeys."""
        key = os.urandom(32)
        n1 = os.urandom(16)
        n2 = os.urandom(16)
        assert hchacha20(key, n1) != hchacha20(key, n2)


class TestXChaCha20Poly1305:
    """XChaCha20-Poly1305 AEAD tests."""

    def test_roundtrip(self):
        """Encrypt then decrypt recovers plaintext."""
        key = os.urandom(32)
        nonce = os.urandom(24)
        plaintext = b"hello cookie"
        ad = os.urandom(16)

        ct = xchacha20poly1305_encrypt(key, nonce, plaintext, ad)
        assert len(ct) == len(plaintext) + 16  # +tag
        pt = xchacha20poly1305_decrypt(key, nonce, ct, ad)
        assert pt == plaintext

    def test_tampered_ciphertext_rejected(self):
        """Flipping a ciphertext byte causes authentication failure."""
        key = os.urandom(32)
        nonce = os.urandom(24)
        ct = xchacha20poly1305_encrypt(key, nonce, b"secret", b"ad")

        bad_ct = bytearray(ct)
        bad_ct[0] ^= 0xFF
        with pytest.raises(Exception):
            xchacha20poly1305_decrypt(key, nonce, bytes(bad_ct), b"ad")

    def test_wrong_ad_rejected(self):
        """Wrong additional data causes authentication failure."""
        key = os.urandom(32)
        nonce = os.urandom(24)
        ct = xchacha20poly1305_encrypt(key, nonce, b"secret", b"good_ad")

        with pytest.raises(Exception):
            xchacha20poly1305_decrypt(key, nonce, ct, b"bad_ad_")

    def test_wrong_key_rejected(self):
        """Wrong key causes authentication failure."""
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        nonce = os.urandom(24)
        ct = xchacha20poly1305_encrypt(key1, nonce, b"secret", b"ad")

        with pytest.raises(Exception):
            xchacha20poly1305_decrypt(key2, nonce, ct, b"ad")

    def test_cookie_sized_payload(self):
        """Roundtrip with exactly 16-byte plaintext (cookie size)."""
        key = os.urandom(32)
        nonce = os.urandom(24)
        cookie = os.urandom(16)
        mac1 = os.urandom(16)

        ct = xchacha20poly1305_encrypt(key, nonce, cookie, mac1)
        assert len(ct) == 32  # 16 plaintext + 16 tag
        pt = xchacha20poly1305_decrypt(key, nonce, ct, mac1)
        assert pt == cookie


# =====================================================================
#  Layer 2 — Cookie mechanism (§5.4.7)
# =====================================================================

class TestCookieKey:
    """Cookie key derivation tests."""

    def test_cookie_key_deterministic(self):
        """Same public key always produces same cookie key."""
        pub = os.urandom(32)
        assert cookie_key(pub) == cookie_key(pub)

    def test_cookie_key_differs_from_mac1_key(self):
        """Cookie key and MAC1 key are different for the same public key."""
        pub = os.urandom(32)
        assert cookie_key(pub) != mac1_key(pub)

    def test_cookie_key_label(self):
        """Cookie key = HASH("cookie--" || Spub)."""
        pub = os.urandom(32)
        expected = blake2s(LABEL_COOKIE + pub)
        assert cookie_key(pub) == expected


class TestCookieReply:
    """Cookie reply (Type 3) message construction and parsing."""

    def test_roundtrip(self):
        """Build and parse a cookie reply recovers the cookie."""
        peer = WireGuardPeer()
        cookie = os.urandom(16)
        mac1 = os.urandom(16)
        sender_index = 0x12345678

        msg = build_cookie_reply(sender_index, cookie, mac1, peer.public_key)
        assert len(msg) == COOKIE_REPLY_SIZE
        assert msg[0] == MSG_TYPE_COOKIE

        recv_idx, recovered = parse_cookie_reply(msg, mac1, peer.public_key)
        assert recv_idx == sender_index
        assert recovered == cookie

    def test_wrong_mac1_rejected(self):
        """Cookie reply with wrong MAC1 (AD) fails authentication."""
        peer = WireGuardPeer()
        cookie = os.urandom(16)
        real_mac1 = os.urandom(16)
        wrong_mac1 = os.urandom(16)

        msg = build_cookie_reply(0x42, cookie, real_mac1, peer.public_key)

        with pytest.raises(Exception):
            parse_cookie_reply(msg, wrong_mac1, peer.public_key)

    def test_wrong_peer_key_rejected(self):
        """Cookie reply decrypted with wrong peer key fails."""
        peer1 = WireGuardPeer()
        peer2 = WireGuardPeer()
        cookie = os.urandom(16)
        mac1 = os.urandom(16)

        msg = build_cookie_reply(0x42, cookie, mac1, peer1.public_key)

        with pytest.raises(Exception):
            parse_cookie_reply(msg, mac1, peer2.public_key)

    def test_tampered_encrypted_cookie_rejected(self):
        """Tampering with encrypted cookie field fails authentication."""
        peer = WireGuardPeer()
        cookie = os.urandom(16)
        mac1 = os.urandom(16)

        msg = bytearray(build_cookie_reply(0x42, cookie, mac1, peer.public_key))
        msg[40] ^= 0xFF  # flip byte in encrypted cookie
        msg = bytes(msg)

        with pytest.raises(Exception):
            parse_cookie_reply(msg, mac1, peer.public_key)

    def test_receiver_index_preserved(self):
        """Receiver index is correctly encoded and recovered."""
        peer = WireGuardPeer()
        for idx in [0, 1, 0xFFFFFFFF, 0xDEADBEEF]:
            msg = build_cookie_reply(idx, os.urandom(16), os.urandom(16),
                                     peer.public_key)
            # Read receiver directly from wire
            wire_idx = struct.unpack("<I", msg[4:8])[0]
            assert wire_idx == idx


class TestMAC2:
    """MAC2 computation with cookies."""

    def test_mac2_nonzero_with_cookie(self):
        """Initiation with a non-zero cookie has non-zero MAC2."""
        peer = WireGuardPeer()
        responder = WireGuardPeer()
        cookie = os.urandom(16)

        msg, _state, _mac1 = create_initiation_with_mac2(
            peer, responder.public_key, cookie
        )
        mac2 = msg[132:148]
        assert mac2 != bytes(16), "MAC2 should be non-zero when cookie is set"

    def test_mac2_zero_without_cookie(self):
        """Initiation without a cookie has zero MAC2."""
        peer = WireGuardPeer()
        responder = WireGuardPeer()

        msg, _state, _mac1 = create_initiation_with_mac2(
            peer, responder.public_key, bytes(16)
        )
        mac2 = msg[132:148]
        assert mac2 == bytes(16), "MAC2 should be zeros when no cookie"

    def test_mac2_verifiable(self):
        """MAC2 can be verified by the responder using the cookie."""
        peer = WireGuardPeer()
        responder = WireGuardPeer()
        cookie = os.urandom(16)

        msg, _state, _mac1 = create_initiation_with_mac2(
            peer, responder.public_key, cookie
        )

        # Responder verifies: MAC2 == Mac(cookie, msg[0..132))
        expected_mac2 = compute_mac(cookie, msg[:132])
        assert msg[132:148] == expected_mac2

    def test_mac1_still_valid_with_mac2(self):
        """MAC1 verification still passes when MAC2 is set."""
        peer = WireGuardPeer()
        responder = WireGuardPeer()
        cookie = os.urandom(16)

        msg, _state, _mac1 = create_initiation_with_mac2(
            peer, responder.public_key, cookie
        )

        # MAC1 is computed over msg[0..116)
        resp_mac1_key = mac1_key(responder.public_key)
        expected_mac1 = compute_mac(resp_mac1_key, msg[:116])
        assert msg[116:132] == expected_mac1


class TestCookieHandshakeFlow:
    """End-to-end cookie flow: initiation → cookie reply → retransmission."""

    def test_full_cookie_flow(self):
        """Simulate: initiator sends, gets cookie reply, resends with MAC2.

        1. Initiator sends Handshake Initiation (MAC2 = zeros)
        2. Responder sends Cookie Reply with a cookie
        3. Initiator decrypts cookie, creates new initiation with MAC2
        4. Responder verifies MAC1 and MAC2
        """
        initiator = WireGuardPeer()
        responder = WireGuardPeer()

        # Step 1: Initiator sends handshake (no cookie)
        init_msg1, init_state1 = initiator.create_initiation(responder.public_key)
        mac1_of_init1 = init_msg1[116:132]
        sender_idx = struct.unpack("<I", init_msg1[4:8])[0]

        # Verify MAC2 is zeros
        assert init_msg1[132:148] == bytes(16)

        # Step 2: Responder generates a cookie and sends cookie reply
        # In real WireGuard, cookie = Mac(Rm, sender_ip_port) where Rm
        # is a rotating secret.  For testing, use a random 16-byte cookie.
        real_cookie = os.urandom(16)
        cookie_reply = build_cookie_reply(
            sender_idx, real_cookie, mac1_of_init1, responder.public_key
        )
        assert len(cookie_reply) == COOKIE_REPLY_SIZE

        # Step 3: Initiator processes cookie reply
        recv_idx, recovered_cookie = parse_cookie_reply(
            cookie_reply, mac1_of_init1, responder.public_key
        )
        assert recv_idx == sender_idx
        assert recovered_cookie == real_cookie

        # Step 4: Initiator creates a new initiation with the cookie
        init_msg2, init_state2, mac1_of_init2 = create_initiation_with_mac2(
            initiator, responder.public_key, recovered_cookie
        )

        # Verify MAC2 is non-zero
        assert init_msg2[132:148] != bytes(16)

        # Step 5: Responder verifies MAC1 and MAC2
        resp_mac1_key = mac1_key(responder.public_key)
        assert compute_mac(resp_mac1_key, init_msg2[:116]) == init_msg2[116:132], \
            "MAC1 verification failed"
        assert compute_mac(real_cookie, init_msg2[:132]) == init_msg2[132:148], \
            "MAC2 verification failed"

        # Step 6: Responder can process the initiation normally
        resp_state = responder.process_initiation(init_msg2)
        assert resp_state.remote_static == initiator.public_key

    def test_cookie_reply_to_response(self):
        """Cookie replies can also target handshake responses.

        Per §5.4.7, cookie replies can be sent in response to any message
        with a MAC1 field (Type 1 or Type 2).
        """
        initiator = WireGuardPeer()
        responder = WireGuardPeer()

        # Do a normal first half of handshake
        init_msg, init_state = initiator.create_initiation(responder.public_key)
        resp_state = responder.process_initiation(init_msg)
        resp_msg, resp_state = responder.create_response(resp_state)

        # Extract MAC1 from the response message
        mac1_of_resp = resp_msg[60:76]
        resp_sender = struct.unpack("<I", resp_msg[4:8])[0]

        # Initiator's side could send a cookie reply to the response
        # (In practice this is the initiator acting as DoS gatekeeper)
        cookie = os.urandom(16)
        cookie_reply = build_cookie_reply(
            resp_sender, cookie, mac1_of_resp, initiator.public_key
        )

        # Parse it back
        recv_idx, recovered = parse_cookie_reply(
            cookie_reply, mac1_of_resp, initiator.public_key
        )
        assert recv_idx == resp_sender
        assert recovered == cookie


class TestReplayProtection:
    """TAI64N timestamp replay protection tests (§5.1)."""

    def test_tai64n_monotonic(self):
        """Successive TAI64N timestamps are strictly increasing."""
        t1 = tai64n_now()
        time.sleep(0.01)  # ensure clock advances
        t2 = tai64n_now()
        assert t2 > t1, "TAI64N must be monotonically increasing"

    def test_tai64n_is_12_bytes(self):
        """TAI64N timestamp is exactly 12 bytes."""
        assert len(tai64n_now()) == 12

    def test_tai64n_big_endian_ordering(self):
        """TAI64N uses big-endian encoding, so byte comparison = time comparison."""
        t1 = tai64n_now()
        time.sleep(0.01)
        t2 = tai64n_now()
        # Big-endian means lexicographic byte order = numeric order
        assert t2 > t1

    def test_replay_detection_logic(self):
        """Demonstrate replay detection: repeated timestamp is rejected.

        This tests the Python oracle logic. The Ada implementation uses
        the same principle: per-peer greatest-seen timestamp, reject if
        new timestamp <= stored.
        """
        last_seen = bytes(12)  # "never seen" sentinel

        t1 = tai64n_now()
        assert t1 > last_seen, "First timestamp should pass"
        last_seen = t1

        time.sleep(0.01)
        t2 = tai64n_now()
        assert t2 > last_seen, "New timestamp should pass"
        last_seen = t2

        # Replaying t1 should fail
        assert not (t1 > last_seen), "Replayed timestamp must be rejected"

        # Same timestamp should also fail
        assert not (last_seen > last_seen), "Same timestamp must be rejected"


# =====================================================================
#  Layer 3 — ESP32 integration (requires hardware)
# =====================================================================

WG_PORT = 51820
UDP_TIMEOUT = 5.0


def _get_esp32_ip(dut, timeout: int = 30) -> str:
    """Wait for ESP32 to print its IP address on UART and return it."""
    output = dut.expect(
        re.compile(rb"(?:sta ip:|got ip:)\s*(\d+\.\d+\.\d+\.\d+)"),
        timeout=timeout,
    )
    return output.group(1).decode()


@pytest.mark.esp32c6
class TestEsp32Cookie:
    """Integration tests: cookie mechanism on ESP32 hardware (§5.4.7).

    These tests require:
    - ESP32-C6 connected via USB
    - Firmware built with matching test keys (see test_keys.py)
    - pytest-embedded-idf installed

    Test flow overview:
    1. Python initiates handshake → ESP32 responds (establishes session)
    2. Python sends a cookie reply (Type 3) to the ESP32
    3. Python triggers the ESP32 to re-initiate (0xFF command)
    4. Python verifies the new initiation has a valid non-zero MAC2
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

    def test_cookie_reply_accepted(self, dut, wg_peer, esp32_addr):
        """ESP32 accepts a well-formed cookie reply (no UART error).

        Flow:
        1. Trigger ESP32 to initiate a handshake (0xFF command)
        2. Receive the ESP32's Handshake Initiation
        3. Build and send a Cookie Reply (Type 3) back to the ESP32
        4. Verify ESP32 logs "Processed" (not "wg_receive error")
        """
        esp32_ip, esp32_port = esp32_addr

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            # Step 1: Trigger ESP32 to send an initiation
            sock.sendto(bytes([0xFF]), (esp32_ip, esp32_port))

            # Step 2: Receive the ESP32's Handshake Initiation
            init_data, _ = sock.recvfrom(256)
            assert len(init_data) == INITIATION_SIZE
            assert init_data[0] == MSG_TYPE_INITIATION
            dut.expect("Handshake Initiation", timeout=5)

            # Extract the ESP32's sender_index and MAC1 from its initiation
            esp32_sender_idx = struct.unpack("<I", init_data[4:8])[0]
            esp32_mac1 = init_data[116:132]

            # Step 3: Build a cookie reply using Python's public key
            # (ESP32 will decrypt with cookie_key(python_public))
            cookie = os.urandom(16)
            cookie_reply = build_cookie_reply(
                esp32_sender_idx, cookie, esp32_mac1, python_public()
            )
            assert len(cookie_reply) == COOKIE_REPLY_SIZE

            sock.sendto(cookie_reply, (esp32_ip, esp32_port))

            # Step 4: ESP32 should log "Processed" (Action_None)
            dut.expect("Processed", timeout=5)
        finally:
            sock.close()

    def test_cookie_reply_then_reinitiate_has_mac2(self, dut, wg_peer,
                                                    esp32_addr):
        """ESP32 uses stored cookie to set MAC2 on its next initiation.

        Full cookie flow on hardware:
        1. Trigger ESP32 → receive initiation (MAC2 should be zero)
        2. Send cookie reply back to ESP32
        3. Trigger ESP32 again → receive new initiation
        4. Verify the new initiation has non-zero MAC2
        5. Verify MAC2 = Mac(cookie, msg[0..132))
        """
        esp32_ip, esp32_port = esp32_addr

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            # ── Round 1: get initiation, verify MAC2 is zero ──

            sock.sendto(bytes([0xFF]), (esp32_ip, esp32_port))
            init1, _ = sock.recvfrom(256)
            assert len(init1) == INITIATION_SIZE
            assert init1[0] == MSG_TYPE_INITIATION
            dut.expect("Handshake Initiation", timeout=5)

            # First initiation should have zero MAC2 (no cookie stored)
            mac2_first = init1[132:148]
            assert mac2_first == bytes(16), \
                "First initiation should have zero MAC2"

            esp32_sender_idx = struct.unpack("<I", init1[4:8])[0]
            esp32_mac1 = init1[116:132]

            # ── Send cookie reply ──

            cookie = os.urandom(16)
            cookie_reply = build_cookie_reply(
                esp32_sender_idx, cookie, esp32_mac1, python_public()
            )
            sock.sendto(cookie_reply, (esp32_ip, esp32_port))
            dut.expect("Processed", timeout=5)

            # ── Round 2: trigger re-initiation, verify MAC2 ──

            # Small delay to let ESP32 process the cookie before
            # we trigger a new handshake
            time.sleep(0.1)

            sock.sendto(bytes([0xFF]), (esp32_ip, esp32_port))
            init2, _ = sock.recvfrom(256)
            assert len(init2) == INITIATION_SIZE
            assert init2[0] == MSG_TYPE_INITIATION
            dut.expect("Handshake Initiation", timeout=5)

            # ── Verify MAC2 is non-zero and correct ──

            mac2_second = init2[132:148]
            assert mac2_second != bytes(16), \
                "Second initiation should have non-zero MAC2 (cookie was set)"

            # Verify MAC2 = Mac(cookie, msg[0..132))
            expected_mac2 = compute_mac(cookie, init2[:132])
            assert mac2_second == expected_mac2, \
                "MAC2 mismatch: ESP32 did not use the cookie correctly"

            # ── Verify MAC1 is still valid ──

            resp_mac1_key = mac1_key(python_public())
            expected_mac1 = compute_mac(resp_mac1_key, init2[:116])
            assert init2[116:132] == expected_mac1, \
                "MAC1 verification failed on cookie-bearing initiation"

            # ── Complete the handshake to confirm it's functional ──

            resp_state = wg_peer.process_initiation(init2)
            resp_msg, resp_state = wg_peer.create_response(resp_state)
            assert len(resp_msg) == RESPONSE_SIZE

            sock.sendto(resp_msg, (esp32_ip, esp32_port))
            dut.expect("Processed", timeout=5)

            # Derive transport keys — handshake is valid
            send_key, recv_key = derive_transport_keys(resp_state.chaining_key)
            assert len(send_key) == 32
            assert len(recv_key) == 32
            assert send_key != recv_key
        finally:
            sock.close()

    def test_cookie_is_one_shot(self, dut, wg_peer, esp32_addr):
        """Cookie is cleared after use — third initiation has zero MAC2.

        1. Trigger → initiation (MAC2 = 0)
        2. Send cookie reply
        3. Trigger → initiation (MAC2 != 0, cookie consumed)
        4. Trigger → initiation (MAC2 = 0, cookie was cleared)
        """
        esp32_ip, esp32_port = esp32_addr

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            # Round 1: no cookie
            sock.sendto(bytes([0xFF]), (esp32_ip, esp32_port))
            init1, _ = sock.recvfrom(256)
            assert init1[132:148] == bytes(16)
            dut.expect("Handshake Initiation", timeout=5)

            # Send cookie reply
            idx1 = struct.unpack("<I", init1[4:8])[0]
            mac1_1 = init1[116:132]
            cookie = os.urandom(16)
            cookie_reply = build_cookie_reply(
                idx1, cookie, mac1_1, python_public()
            )
            sock.sendto(cookie_reply, (esp32_ip, esp32_port))
            dut.expect("Processed", timeout=5)
            time.sleep(0.1)

            # Round 2: cookie consumed → MAC2 set
            sock.sendto(bytes([0xFF]), (esp32_ip, esp32_port))
            init2, _ = sock.recvfrom(256)
            assert init2[132:148] != bytes(16), "Expected non-zero MAC2"
            dut.expect("Handshake Initiation", timeout=5)

            # Round 3: cookie was cleared → MAC2 back to zero
            time.sleep(0.1)
            sock.sendto(bytes([0xFF]), (esp32_ip, esp32_port))
            init3, _ = sock.recvfrom(256)
            assert init3[132:148] == bytes(16), \
                "Third initiation should have zero MAC2 (cookie is one-shot)"
            dut.expect("Handshake Initiation", timeout=5)
        finally:
            sock.close()

    def test_tampered_cookie_reply_rejected(self, dut, wg_peer, esp32_addr):
        """ESP32 rejects a cookie reply with tampered encrypted cookie.

        A tampered cookie reply fails AEAD decryption, so the ESP32
        should not store any cookie.  The next initiation should still
        have zero MAC2.
        """
        esp32_ip, esp32_port = esp32_addr

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            # Trigger initiation to get sender_index and MAC1
            sock.sendto(bytes([0xFF]), (esp32_ip, esp32_port))
            init1, _ = sock.recvfrom(256)
            assert len(init1) == INITIATION_SIZE
            dut.expect("Handshake Initiation", timeout=5)

            idx = struct.unpack("<I", init1[4:8])[0]
            mac1 = init1[116:132]

            # Build a valid cookie reply, then tamper with it
            cookie = os.urandom(16)
            cookie_reply = bytearray(build_cookie_reply(
                idx, cookie, mac1, python_public()
            ))
            cookie_reply[40] ^= 0xFF  # flip byte in encrypted cookie
            sock.sendto(bytes(cookie_reply), (esp32_ip, esp32_port))

            # ESP32 should log an error — tampered AEAD fails decryption
            dut.expect("wg_receive error", timeout=5)
            time.sleep(0.1)

            # Next initiation should have zero MAC2 (no cookie stored)
            sock.sendto(bytes([0xFF]), (esp32_ip, esp32_port))
            init2, _ = sock.recvfrom(256)
            assert init2[132:148] == bytes(16), \
                "Tampered cookie should not be stored — MAC2 must be zero"
            dut.expect("Handshake Initiation", timeout=5)
        finally:
            sock.close()
