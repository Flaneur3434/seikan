"""Minimal WireGuard Noise IKpsk2 handshake — Python test oracle.

Implements the WireGuard handshake protocol (Sections 5.4.2–5.4.4 of the
whitepaper) using only ``cryptography`` + ``hashlib``.

This is NOT production code.  It exists solely as an independent reference
implementation so that pytest can verify the Ada/SPARK handshake running on
the ESP32.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

# ── Protocol constants ────────────────────────────────────────────────

# ── Test-command IDs (must match platform/main/wg_commands.h) ─────────
WG_CMD_INITIATE_HANDSHAKE = 0xFF
WG_CMD_SET_ECHO_MODE      = 0xFE

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"

MSG_TYPE_INITIATION = 1
MSG_TYPE_RESPONSE = 2
MSG_TYPE_COOKIE = 3

INITIATION_SIZE = 148
RESPONSE_SIZE = 92


# ── Crypto primitives ────────────────────────────────────────────────

def blake2s(data: bytes, *, key: bytes = b"", digest_size: int = 32) -> bytes:
    """BLAKE2s hash (optionally keyed)."""
    return hashlib.blake2s(data, key=key, digest_size=digest_size).digest()


def hmac_blake2s(key: bytes, data: bytes) -> bytes:
    """HMAC-BLAKE2s as defined in the WireGuard spec (RFC 2104 construction)."""
    BLOCK = 64
    if len(key) > BLOCK:
        key = blake2s(key)
    key = key.ljust(BLOCK, b"\x00")
    ipad = bytes(k ^ 0x36 for k in key)
    opad = bytes(k ^ 0x5C for k in key)
    return blake2s(opad + blake2s(ipad + data))


def kdf1(key: bytes, input_data: bytes) -> bytes:
    """KDF1 — one derived key (new chaining key)."""
    t0 = hmac_blake2s(key, input_data)
    return hmac_blake2s(t0, b"\x01")


def kdf2(key: bytes, input_data: bytes) -> tuple[bytes, bytes]:
    """KDF2 — two derived keys (new chaining key, encryption key)."""
    t0 = hmac_blake2s(key, input_data)
    t1 = hmac_blake2s(t0, b"\x01")
    t2 = hmac_blake2s(t0, t1 + b"\x02")
    return t1, t2


def kdf3(key: bytes, input_data: bytes) -> tuple[bytes, bytes, bytes]:
    """KDF3 — three derived keys (chaining key, tau, encryption key)."""
    t0 = hmac_blake2s(key, input_data)
    t1 = hmac_blake2s(t0, b"\x01")
    t2 = hmac_blake2s(t0, t1 + b"\x02")
    t3 = hmac_blake2s(t0, t2 + b"\x03")
    return t1, t2, t3


def aead_encrypt(key: bytes, counter: int, plaintext: bytes, ad: bytes) -> bytes:
    """ChaCha20-Poly1305 AEAD encrypt (WireGuard nonce format)."""
    # Whitepaper: 4 zero bytes ‖ 8-byte LE counter
    nonce = b"\x00\x00\x00\x00" + struct.pack("<Q", counter)
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, ad)


def aead_decrypt(key: bytes, counter: int, ciphertext: bytes, ad: bytes) -> bytes:
    """ChaCha20-Poly1305 AEAD decrypt (WireGuard nonce format)."""
    nonce = b"\x00\x00\x00\x00" + struct.pack("<Q", counter)
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, ad)


def x25519(private: X25519PrivateKey, public_bytes: bytes) -> bytes:
    """Curve25519 Diffie-Hellman."""
    return private.exchange(X25519PublicKey.from_public_bytes(public_bytes))


def tai64n_now() -> bytes:
    """Current TAI64N timestamp (12 bytes)."""
    now = time.time()
    secs = int(now)
    nsecs = int((now - secs) * 1e9)
    return struct.pack(">QI", (1 << 62) + secs, nsecs)


def mac1_key(static_public: bytes) -> bytes:
    """Derive MAC1 key: HASH(LABEL_MAC1 ‖ Spub)."""
    return blake2s(LABEL_MAC1 + static_public)


def compute_mac(key: bytes, data: bytes) -> bytes:
    """Mac(key, input) = Keyed-BLAKE2s-128.

    Per the whitepaper this is BLAKE2s with native key parameter and
    128-bit (16-byte) output — NOT truncation of a 256-bit hash.
    """
    return blake2s(data, key=key, digest_size=16)


# ── Handshake state ──────────────────────────────────────────────────

@dataclass
class HandshakeState:
    """Mutable state carried across handshake steps."""
    chaining_key: bytes = b""
    hash: bytes = b""
    ephemeral_private: X25519PrivateKey | None = None
    ephemeral_public: bytes = b""
    remote_ephemeral: bytes = b""
    remote_static: bytes = b""
    local_index: int = 0
    remote_index: int = 0


def derive_transport_keys(chaining_key: bytes) -> tuple[bytes, bytes]:
    """Derive transport keys after completed handshake.

    Returns (initiator_send, initiator_recv).
    The responder uses them swapped: send = initiator_recv, recv = initiator_send.
    """
    return kdf2(chaining_key, b"")


# ── Transport data (Type 4) ─────────────────────────────────────────

MSG_TYPE_TRANSPORT = 4
TRANSPORT_HEADER_SIZE = 16
AEAD_TAG_SIZE = 16


def build_transport_packet(
    key: bytes,
    receiver_index: int,
    counter: int,
    plaintext: bytes,
) -> bytes:
    """Build a WireGuard Type 4 transport data packet.

    Wire format:
        [0]      msg_type  = 4
        [1..3]   reserved  = 0
        [4..7]   receiver  = LE32
        [8..15]  counter   = LE64
        [16..]   AEAD(plaintext) + tag (16 bytes)

    The header (bytes 0..15) is used as AAD for the AEAD.
    """
    header = struct.pack("<BxxxIQ", MSG_TYPE_TRANSPORT, receiver_index, counter)
    assert len(header) == TRANSPORT_HEADER_SIZE
    # WireGuard spec §5.4.6: transport AEAD uses empty AAD (ε)
    ciphertext_tag = aead_encrypt(key, counter, plaintext, b"")
    return header + ciphertext_tag


def parse_transport_packet(
    key: bytes,
    packet: bytes,
) -> tuple[int, int, bytes]:
    """Parse and decrypt a WireGuard Type 4 transport data packet.

    Returns (receiver_index, counter, plaintext).
    Raises on authentication failure.

    For data packets the plaintext length is > 0.  Use
    :func:`parse_keepalive_packet` for zero-length payloads.
    """
    assert len(packet) > TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE
    assert packet[0] == MSG_TYPE_TRANSPORT

    header = packet[:TRANSPORT_HEADER_SIZE]
    _, receiver_index, counter = struct.unpack("<BxxxIQ", header)
    ciphertext_tag = packet[TRANSPORT_HEADER_SIZE:]
    # WireGuard spec §5.4.6: transport AEAD uses empty AAD (ε)
    plaintext = aead_decrypt(key, counter, ciphertext_tag, b"")
    return receiver_index, counter, plaintext


# Keepalive = Type 4 with zero-length plaintext.
# On the wire: 16-byte header + 16-byte AEAD tag = 32 bytes.
KEEPALIVE_SIZE = TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE


def build_keepalive_packet(
    key: bytes,
    receiver_index: int,
    counter: int,
) -> bytes:
    """Build a WireGuard keepalive packet (Type 4, empty plaintext)."""
    return build_transport_packet(key, receiver_index, counter, plaintext=b"")


def parse_keepalive_packet(
    key: bytes,
    packet: bytes,
) -> tuple[int, int]:
    """Parse and authenticate a WireGuard keepalive packet.

    Returns (receiver_index, counter).
    Raises on authentication failure.  Asserts the decrypted plaintext
    is empty (zero-length).
    """
    assert len(packet) == KEEPALIVE_SIZE, (
        f"keepalive must be {KEEPALIVE_SIZE} bytes, got {len(packet)}"
    )
    assert packet[0] == MSG_TYPE_TRANSPORT

    header = packet[:TRANSPORT_HEADER_SIZE]
    _, receiver_index, counter = struct.unpack("<BxxxIQ", header)
    ciphertext_tag = packet[TRANSPORT_HEADER_SIZE:]
    # WireGuard spec §5.4.6: transport AEAD uses empty AAD (ε)
    plaintext = aead_decrypt(key, counter, ciphertext_tag, b"")
    assert plaintext == b"", f"keepalive plaintext must be empty, got {len(plaintext)} bytes"
    return receiver_index, counter


# ── Test-suite command packets ───────────────────────────────────────

def build_echo_mode_command(enable: bool) -> bytes:
    """Build a 2-byte echo-mode command packet for the ESP32.

    Byte 0: WG_CMD_SET_ECHO_MODE (0xFE)
    Byte 1: 0x01 (enable) or 0x00 (disable)
    """
    return bytes([WG_CMD_SET_ECHO_MODE, 0x01 if enable else 0x00])


# ── WireGuard peer ───────────────────────────────────────────────────

class WireGuardPeer:
    """Minimal WireGuard peer capable of creating/processing handshakes."""

    def __init__(
        self,
        private_key: X25519PrivateKey | None = None,
        psk: bytes | None = None,
    ):
        self.private_key = private_key or X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key().public_bytes_raw()
        self.psk = psk or bytes(32)  # No PSK → 32 zero bytes
        self.mac1_key = mac1_key(self.public_key)

    # ── Section 5.4.2: Handshake Initiation ──────────────────────────

    def create_initiation(
        self, responder_public: bytes
    ) -> tuple[bytes, HandshakeState]:
        """Build a 148-byte Handshake Initiation message."""
        C = blake2s(CONSTRUCTION)
        H = blake2s(C + IDENTIFIER)
        H = blake2s(H + responder_public)

        # Ephemeral key pair
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes_raw()

        # C = KDF1(C, e_pub)
        C = kdf1(C, eph_pub)
        # H = HASH(H ‖ e_pub)
        H = blake2s(H + eph_pub)

        # (C, K) = KDF2(C, DH(e, S_pub_r))
        C, K = kdf2(C, x25519(eph, responder_public))
        # encrypted_static = AEAD(K, 0, S_pub_i, H)
        enc_static = aead_encrypt(K, 0, self.public_key, H)
        # H = HASH(H ‖ encrypted_static)
        H = blake2s(H + enc_static)

        # (C, K) = KDF2(C, DH(S_priv_i, S_pub_r))
        C, K = kdf2(C, x25519(self.private_key, responder_public))
        # encrypted_timestamp = AEAD(K, 0, TAI64N, H)
        enc_ts = aead_encrypt(K, 0, tai64n_now(), H)
        # H = HASH(H ‖ encrypted_timestamp)
        H = blake2s(H + enc_ts)

        sender = struct.unpack("<I", os.urandom(4))[0]

        # msg_type(1) + reserved(3) + sender(4) + ephemeral(32)
        # + encrypted_static(48) + encrypted_timestamp(28)
        msg = struct.pack("<B3xI", MSG_TYPE_INITIATION, sender)
        msg += eph_pub + enc_static + enc_ts

        # MAC1 over msg[0..116)
        resp_mac1_key = mac1_key(responder_public)
        msg += compute_mac(resp_mac1_key, msg)
        # MAC2 = zeros (no cookie)
        msg += bytes(16)

        assert len(msg) == INITIATION_SIZE

        state = HandshakeState(
            chaining_key=C,
            hash=H,
            ephemeral_private=eph,
            ephemeral_public=eph_pub,
            local_index=sender,
            remote_static=responder_public,
        )
        return msg, state

    # ── Section 5.4.2: Process Initiation (responder side) ───────────

    def process_initiation(self, msg: bytes) -> HandshakeState:
        """Parse and cryptographically verify a Handshake Initiation."""
        assert len(msg) == INITIATION_SIZE, f"bad size {len(msg)}"
        assert msg[0] == MSG_TYPE_INITIATION, f"bad type {msg[0]}"

        # Verify MAC1 (cheap DoS filter)
        assert compute_mac(self.mac1_key, msg[:116]) == msg[116:132], "MAC1 fail"

        sender = struct.unpack("<I", msg[4:8])[0]
        eph_pub = msg[8:40]
        enc_static = msg[40:88]
        enc_ts = msg[88:116]

        C = blake2s(CONSTRUCTION)
        H = blake2s(C + IDENTIFIER)
        H = blake2s(H + self.public_key)

        C = kdf1(C, eph_pub)
        H = blake2s(H + eph_pub)

        # DH: es = DH(S_priv_r, e_pub_i)
        C, K = kdf2(C, x25519(self.private_key, eph_pub))
        initiator_static = aead_decrypt(K, 0, enc_static, H)
        H = blake2s(H + enc_static)

        # DH: ss = DH(S_priv_r, S_pub_i)
        C, K = kdf2(C, x25519(self.private_key, initiator_static))
        timestamp = aead_decrypt(K, 0, enc_ts, H)
        H = blake2s(H + enc_ts)

        return HandshakeState(
            chaining_key=C,
            hash=H,
            remote_ephemeral=eph_pub,
            remote_static=initiator_static,
            remote_index=sender,
        )

    # ── Section 5.4.3: Handshake Response ────────────────────────────

    def create_response(self, state: HandshakeState) -> tuple[bytes, HandshakeState]:
        """Build a 92-byte Handshake Response message."""
        C, H = state.chaining_key, state.hash

        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes_raw()
        sender = struct.unpack("<I", os.urandom(4))[0]

        # C = KDF1(C, e_pub_r)
        C = kdf1(C, eph_pub)
        # H = HASH(H ‖ e_pub_r)
        H = blake2s(H + eph_pub)

        # DH: ee, se
        C = kdf1(C, x25519(eph, state.remote_ephemeral))  # ee
        C = kdf1(C, x25519(eph, state.remote_static))     # se

        # PSK mixing: (C, τ, K) = KDF3(C, Q)
        C, tau, K = kdf3(C, self.psk)
        # H = HASH(H ‖ τ)
        H = blake2s(H + tau)

        # encrypted_nothing = AEAD(K, 0, ε, H)
        enc_nothing = aead_encrypt(K, 0, b"", H)
        # H = HASH(H ‖ encrypted_nothing)
        H = blake2s(H + enc_nothing)

        # msg_type(1) + reserved(3) + sender(4) + receiver(4) + ephemeral(32)
        # + encrypted_nothing(16)
        msg = struct.pack("<B3xII", MSG_TYPE_RESPONSE, sender, state.remote_index)
        msg += eph_pub + enc_nothing

        # MAC1 keyed to initiator's static public
        msg += compute_mac(mac1_key(state.remote_static), msg)
        # MAC2 = zeros
        msg += bytes(16)

        assert len(msg) == RESPONSE_SIZE

        new_state = HandshakeState(
            chaining_key=C,
            hash=H,
            ephemeral_private=eph,
            ephemeral_public=eph_pub,
            local_index=sender,
            remote_index=state.remote_index,
            remote_ephemeral=state.remote_ephemeral,
            remote_static=state.remote_static,
        )
        return msg, new_state

    # ── Section 5.4.4: Process Response (initiator side) ─────────────

    def process_response(
        self, msg: bytes, state: HandshakeState
    ) -> HandshakeState:
        """Parse and cryptographically verify a Handshake Response."""
        assert len(msg) == RESPONSE_SIZE, f"bad size {len(msg)}"
        assert msg[0] == MSG_TYPE_RESPONSE, f"bad type {msg[0]}"

        sender = struct.unpack("<I", msg[4:8])[0]
        receiver = struct.unpack("<I", msg[8:12])[0]
        eph_pub = msg[12:44]
        enc_nothing = msg[44:60]

        assert receiver == state.local_index, (
            f"receiver mismatch: {receiver} != {state.local_index}"
        )
        # Verify MAC1
        assert compute_mac(self.mac1_key, msg[:60]) == msg[60:76], "MAC1 fail"

        C, H = state.chaining_key, state.hash

        C = kdf1(C, eph_pub)
        H = blake2s(H + eph_pub)

        # DH: ee, se
        C = kdf1(C, x25519(state.ephemeral_private, eph_pub))  # ee
        C = kdf1(C, x25519(self.private_key, eph_pub))         # se

        # PSK mixing
        C, tau, K = kdf3(C, self.psk)
        H = blake2s(H + tau)

        # Decrypt empty
        plaintext = aead_decrypt(K, 0, enc_nothing, H)
        assert plaintext == b"", f"expected empty, got {len(plaintext)} bytes"
        H = blake2s(H + enc_nothing)

        return HandshakeState(
            chaining_key=C,
            hash=H,
            local_index=state.local_index,
            remote_index=sender,
        )
