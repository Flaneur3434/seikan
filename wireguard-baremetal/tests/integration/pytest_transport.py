"""WireGuard transport data (Type 4) tests.

Layer 1 — Self-tests (Python ↔ Python):
    Validates transport packet build/parse, encrypt/decrypt round-trip,
    key directionality, counter increment, and error conditions using
    the reference implementation in wg_noise.py.

Layer 2 — ESP32 integration (requires hardware):
    After a full handshake, exchanges encrypted Type 4 packets between
    Python and the ESP32 over UDP.
"""

import re
import socket
import struct
import threading
import time
import pytest

from wg_noise import (
    WireGuardPeer,
    derive_transport_keys,
    build_transport_packet,
    parse_transport_packet,
    build_echo_mode_command,
    aead_encrypt,
    aead_decrypt,
    MSG_TYPE_TRANSPORT,
    TRANSPORT_HEADER_SIZE,
    AEAD_TAG_SIZE,
    RESPONSE_SIZE,
    MSG_TYPE_RESPONSE,
)

from test_keys import (
    python_private_key,
    esp32_public,
    preshared_key,
)


# =====================================================================
#  Layer 1 — Python ↔ Python self-tests
# =====================================================================


def _complete_handshake():
    """Run a full handshake and return (initiator, responder, i_state, r_state)."""
    initiator = WireGuardPeer()
    responder = WireGuardPeer()

    init_msg, i_state = initiator.create_initiation(responder.public_key)
    r_state = responder.process_initiation(init_msg)
    resp_msg, r_state = responder.create_response(r_state)
    i_state = initiator.process_response(resp_msg, i_state)

    return initiator, responder, i_state, r_state


class TestTransportPacketFormat:
    """Wire format: header structure, sizes, field encoding."""

    def test_header_size(self):
        """Transport header is exactly 16 bytes."""
        key = bytes(32)
        pkt = build_transport_packet(key, receiver_index=42, counter=0,
                                     plaintext=b"hello")
        assert len(pkt) == TRANSPORT_HEADER_SIZE + len(b"hello") + AEAD_TAG_SIZE

    def test_msg_type_byte(self):
        """First byte is always 4 (MSG_TYPE_TRANSPORT)."""
        key = bytes(32)
        pkt = build_transport_packet(key, 0, 0, b"x")
        assert pkt[0] == MSG_TYPE_TRANSPORT

    def test_reserved_bytes_zero(self):
        """Bytes 1-3 are reserved (zero)."""
        key = bytes(32)
        pkt = build_transport_packet(key, 0xDEADBEEF, 0, b"x")
        assert pkt[1:4] == b"\x00\x00\x00"

    def test_receiver_index_le32(self):
        """Receiver index at bytes 4-7 is little-endian uint32."""
        key = bytes(32)
        pkt = build_transport_packet(key, receiver_index=0x12345678,
                                     counter=0, plaintext=b"x")
        assert struct.unpack("<I", pkt[4:8])[0] == 0x12345678

    def test_counter_le64(self):
        """Counter at bytes 8-15 is little-endian uint64."""
        key = bytes(32)
        pkt = build_transport_packet(key, receiver_index=0,
                                     counter=0xFEDCBA9876543210,
                                     plaintext=b"x")
        assert struct.unpack("<Q", pkt[8:16])[0] == 0xFEDCBA9876543210

    def test_minimum_packet_size(self):
        """Smallest valid packet: header + 1 byte plaintext + tag."""
        key = bytes(32)
        pkt = build_transport_packet(key, 0, 0, b"X")
        assert len(pkt) == TRANSPORT_HEADER_SIZE + 1 + AEAD_TAG_SIZE

    def test_payload_size_scales(self):
        """Packet length = header + plaintext + tag."""
        key = bytes(32)
        for pt_len in [1, 64, 256, 1024]:
            pt = bytes(pt_len)
            pkt = build_transport_packet(key, 0, 0, pt)
            assert len(pkt) == TRANSPORT_HEADER_SIZE + pt_len + AEAD_TAG_SIZE


class TestTransportRoundTrip:
    """Encrypt → decrypt round-trip with matching keys."""

    def test_basic_roundtrip(self):
        """Encrypt then decrypt recovers the original plaintext."""
        key = bytes(range(32))
        plaintext = b"Hello, WireGuard!"

        pkt = build_transport_packet(key, receiver_index=7, counter=0,
                                     plaintext=plaintext)
        rx_idx, rx_ctr, rx_pt = parse_transport_packet(key, pkt)

        assert rx_idx == 7
        assert rx_ctr == 0
        assert rx_pt == plaintext

    def test_roundtrip_large_payload(self):
        """Round-trip with a 1400-byte payload (typical MTU)."""
        key = bytes(range(32))
        plaintext = bytes(range(256)) * 5 + bytes(range(120))  # 1400 bytes
        assert len(plaintext) == 1400

        pkt = build_transport_packet(key, 99, 42, plaintext)
        _, _, rx_pt = parse_transport_packet(key, pkt)
        assert rx_pt == plaintext

    def test_sequential_counters(self):
        """Multiple packets with incrementing counters all decrypt."""
        key = bytes(range(32))
        for counter in range(10):
            pt = f"packet {counter}".encode()
            pkt = build_transport_packet(key, 1, counter, pt)
            _, rx_ctr, rx_pt = parse_transport_packet(key, pkt)
            assert rx_ctr == counter
            assert rx_pt == pt

    def test_counter_in_nonce(self):
        """Same plaintext with different counters produces different ciphertext."""
        key = bytes(range(32))
        pt = b"deterministic"
        pkt0 = build_transport_packet(key, 0, 0, pt)
        pkt1 = build_transport_packet(key, 0, 1, pt)
        # Ciphertext region differs (headers also differ at counter field)
        assert pkt0 != pkt1
        # But both decrypt to the same plaintext
        assert parse_transport_packet(key, pkt0)[2] == pt
        assert parse_transport_packet(key, pkt1)[2] == pt


class TestTransportKeyDirectionality:
    """Initiator and responder use swapped send/receive keys."""

    def test_initiator_to_responder(self):
        """Initiator encrypts with τ1, responder decrypts with τ1."""
        _, _, i_state, r_state = _complete_handshake()

        i_send, i_recv = derive_transport_keys(i_state.chaining_key)
        # Responder swaps: its recv = initiator's send, its send = initiator's recv
        r_recv, r_send = derive_transport_keys(r_state.chaining_key)

        # τ1 = initiator's send = responder's recv
        assert i_send == r_recv
        # τ2 = initiator's recv = responder's send
        assert i_recv == r_send

        # Initiator encrypts
        plaintext = b"from initiator"
        pkt = build_transport_packet(i_send, receiver_index=r_state.local_index,
                                     counter=0, plaintext=plaintext)

        # Responder decrypts with its recv key (= τ1)
        _, _, rx_pt = parse_transport_packet(r_recv, pkt)
        assert rx_pt == plaintext

    def test_responder_to_initiator(self):
        """Responder encrypts with τ2, initiator decrypts with τ2."""
        _, _, i_state, r_state = _complete_handshake()

        i_send, i_recv = derive_transport_keys(i_state.chaining_key)
        r_recv, r_send = derive_transport_keys(r_state.chaining_key)

        # Responder encrypts with τ2
        plaintext = b"from responder"
        pkt = build_transport_packet(r_send, receiver_index=i_state.local_index,
                                     counter=0, plaintext=plaintext)

        # Initiator decrypts with its recv key (= τ2)
        _, _, rx_pt = parse_transport_packet(i_recv, pkt)
        assert rx_pt == plaintext

    def test_wrong_key_fails(self):
        """Decrypting with the wrong key raises an authentication error."""
        _, _, i_state, _ = _complete_handshake()
        i_send, i_recv = derive_transport_keys(i_state.chaining_key)

        pkt = build_transport_packet(i_send, 0, 0, b"secret")

        # Trying to decrypt with the recv key instead of send key → wrong key
        with pytest.raises(Exception):
            parse_transport_packet(i_recv, pkt)


class TestTransportErrorCases:
    """Authentication failures and malformed packets."""

    def test_tampered_ciphertext_fails(self):
        """Flipping a byte in the ciphertext causes authentication failure."""
        key = bytes(range(32))
        pkt = build_transport_packet(key, 0, 0, b"tamper me")
        bad = bytearray(pkt)
        bad[TRANSPORT_HEADER_SIZE + 2] ^= 0xFF  # flip ciphertext byte
        with pytest.raises(Exception):
            parse_transport_packet(key, bytes(bad))

    def test_tampered_header_fails(self):
        """Modifying the header (AAD) causes authentication failure."""
        key = bytes(range(32))
        pkt = build_transport_packet(key, 0, 0, b"aad check")
        bad = bytearray(pkt)
        bad[5] ^= 0x01  # flip a receiver index byte
        with pytest.raises(Exception):
            parse_transport_packet(key, bytes(bad))

    def test_tampered_tag_fails(self):
        """Modifying the Poly1305 tag causes authentication failure."""
        key = bytes(range(32))
        pkt = build_transport_packet(key, 0, 0, b"tag check")
        bad = bytearray(pkt)
        bad[-1] ^= 0xFF  # flip last tag byte
        with pytest.raises(Exception):
            parse_transport_packet(key, bytes(bad))

    def test_truncated_packet_rejected(self):
        """Packet shorter than header + tag is rejected."""
        key = bytes(range(32))
        pkt = build_transport_packet(key, 0, 0, b"x")
        truncated = pkt[:TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE]  # strip payload
        with pytest.raises(Exception):
            parse_transport_packet(key, truncated)

    def test_wrong_msg_type_rejected(self):
        """Packet with msg_type != 4 is rejected."""
        key = bytes(range(32))
        pkt = build_transport_packet(key, 0, 0, b"wrong type")
        bad = bytearray(pkt)
        bad[0] = 1  # change to initiation type
        with pytest.raises(AssertionError):
            parse_transport_packet(key, bytes(bad))


class TestTransportAfterHandshake:
    """Full handshake → transport data exchange (Python ↔ Python)."""

    def test_bidirectional_exchange(self):
        """Both sides exchange multiple encrypted messages after handshake."""
        _, _, i_state, r_state = _complete_handshake()

        i_send, i_recv = derive_transport_keys(i_state.chaining_key)
        r_recv, r_send = derive_transport_keys(r_state.chaining_key)

        # Initiator → Responder: 5 messages
        for ctr in range(5):
            pt = f"i→r msg {ctr}".encode()
            pkt = build_transport_packet(i_send, r_state.local_index, ctr, pt)
            _, rx_ctr, rx_pt = parse_transport_packet(r_recv, pkt)
            assert rx_ctr == ctr
            assert rx_pt == pt

        # Responder → Initiator: 5 messages
        for ctr in range(5):
            pt = f"r→i msg {ctr}".encode()
            pkt = build_transport_packet(r_send, i_state.local_index, ctr, pt)
            _, rx_ctr, rx_pt = parse_transport_packet(i_recv, pkt)
            assert rx_ctr == ctr
            assert rx_pt == pt

    def test_receiver_index_matches(self):
        """Receiver index in the packet matches the peer's sender index."""
        _, _, i_state, r_state = _complete_handshake()
        i_send, _ = derive_transport_keys(i_state.chaining_key)

        pkt = build_transport_packet(i_send, r_state.local_index, 0, b"idx")
        rx_idx, _, _ = parse_transport_packet(i_send, pkt)
        # Receiver index in the packet should be the responder's local index
        assert rx_idx == r_state.local_index


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


@pytest.mark.esp32c6
class TestEsp32Transport:
    """Integration tests: Python sends transport packets to ESP32 over UDP.

    Each test performs a fresh handshake (ESP32 resets between tests),
    then exercises the transport data path.  Python is always the
    initiator, ESP32 is the responder.

    Key directionality:
        i_send = τ1 = ESP32's Receive_Key   (Python encrypts, ESP32 decrypts)
        i_recv = τ2 = ESP32's Send_Key       (ESP32 encrypts, Python decrypts)
    """

    @pytest.fixture
    def wg_peer(self):
        """Python-side WireGuard peer loaded with test keys."""
        return WireGuardPeer(
            private_key=python_private_key(),
            psk=preshared_key(),
        )

    @pytest.fixture
    def esp32_addr(self, dut):
        """Wait for ESP32 boot and return (ip, port)."""
        ip = _get_esp32_ip(dut, timeout=30)
        dut.expect("WireGuard initialized", timeout=30)
        dut.expect("Socket bound", timeout=10)
        return (ip, WG_PORT)

    @pytest.fixture
    def transport_session(self, dut, wg_peer, esp32_addr):
        """Complete handshake, enable echo mode, yield (sock, send_key, recv_key, receiver_index).

        The socket is automatically closed after the test.
        Echo mode is enabled so the ESP32 echoes decrypted data back.
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(UDP_TIMEOUT)
        try:
            # — Handshake —
            init_msg, init_state = wg_peer.create_initiation(esp32_public())
            sock.sendto(init_msg, esp32_addr)

            resp_data, _ = sock.recvfrom(256)
            assert len(resp_data) == RESPONSE_SIZE
            assert resp_data[0] == MSG_TYPE_RESPONSE

            final_state = wg_peer.process_response(resp_data, init_state)
            dut.expect("Handshake Response", timeout=5)

            # — Derive transport keys (initiator side) —
            send_key, recv_key = derive_transport_keys(final_state.chaining_key)

            # — Enable echo mode so ESP32 echoes transport data —
            sock.sendto(build_echo_mode_command(True), esp32_addr)
            dut.expect("Echo mode ON", timeout=5)

            yield sock, send_key, recv_key, final_state.remote_index
        finally:
            sock.close()

    # ── Positive tests ───────────────────────────────────────────

    def test_send_single_packet(self, dut, transport_session, esp32_addr):
        """Python sends one encrypted Type 4 packet, ESP32 decrypts it."""
        sock, send_key, _recv_key, rx_idx = transport_session

        pkt = build_transport_packet(
            send_key, rx_idx, counter=0, plaintext=b"Hello from Python!",
        )
        sock.sendto(pkt, esp32_addr)

        dut.expect("Transport Data", timeout=5)

    def test_send_multiple_packets(self, dut, transport_session, esp32_addr):
        """Five packets with incrementing counters all decrypt."""
        sock, send_key, _recv_key, rx_idx = transport_session

        for counter in range(5):
            pt = f"packet #{counter}".encode()
            pkt = build_transport_packet(send_key, rx_idx, counter, pt)
            sock.sendto(pkt, esp32_addr)
            dut.expect("Transport Data", timeout=5)

    def test_max_payload(self, dut, transport_session, esp32_addr):
        """Max-size payload that fits a 256-byte pool buffer (224 B)."""
        sock, send_key, _recv_key, rx_idx = transport_session

        # Pool buffer = 256.  Header(16) + plaintext + tag(16) <= 256
        # ⇒ max plaintext = 224 bytes
        plaintext = bytes(range(224))
        assert len(plaintext) == 224

        pkt = build_transport_packet(send_key, rx_idx, counter=0,
                                     plaintext=plaintext)
        assert len(pkt) == 256  # exactly fills the buffer
        sock.sendto(pkt, esp32_addr)

        dut.expect("Transport Data", timeout=5)

    # ── Negative tests ───────────────────────────────────────────

    def test_tampered_ciphertext_rejected(self, dut, transport_session,
                                          esp32_addr):
        """Flipping a ciphertext byte causes ESP32 to reject the packet."""
        sock, send_key, _recv_key, rx_idx = transport_session

        pkt = build_transport_packet(send_key, rx_idx, 0, b"tamper test")
        bad = bytearray(pkt)
        bad[TRANSPORT_HEADER_SIZE + 2] ^= 0xFF
        sock.sendto(bytes(bad), esp32_addr)

        dut.expect("wg_receive error", timeout=5)

    def test_wrong_key_rejected(self, dut, transport_session, esp32_addr):
        """Packet encrypted with a wrong key is rejected by the ESP32."""
        sock, _send_key, _recv_key, rx_idx = transport_session

        wrong_key = bytes(32)  # all zeros — not the negotiated key
        pkt = build_transport_packet(wrong_key, rx_idx, 0, b"wrong key")
        sock.sendto(pkt, esp32_addr)

        dut.expect("wg_receive error", timeout=5)

    # ── Echo round-trip tests ────────────────────────────────────

    def test_echo_roundtrip(self, dut, transport_session, esp32_addr):
        """Send encrypted packet, ESP32 decrypts and re-encrypts back.

        Python decrypts the echo response and verifies the plaintext
        matches what was sent.
        """
        sock, send_key, recv_key, rx_idx = transport_session

        plaintext = b"echo me!"
        pkt = build_transport_packet(send_key, rx_idx, counter=0,
                                     plaintext=plaintext)
        sock.sendto(pkt, esp32_addr)

        # ESP32 echoes back an encrypted Type 4 packet
        echo_data, _ = sock.recvfrom(512)
        dut.expect("Transport Data", timeout=5)

        assert len(echo_data) > TRANSPORT_HEADER_SIZE + AEAD_TAG_SIZE
        assert echo_data[0] == MSG_TYPE_TRANSPORT

        # Decrypt with our recv key (= ESP32's send key = τ2)
        _rx_idx, _rx_ctr, rx_pt = parse_transport_packet(recv_key, echo_data)
        assert rx_pt == plaintext

    def test_echo_multiple(self, dut, transport_session, esp32_addr):
        """Multiple echo round-trips with different payloads."""
        sock, send_key, recv_key, rx_idx = transport_session

        for counter in range(5):
            plaintext = f"ping {counter}".encode()
            pkt = build_transport_packet(send_key, rx_idx, counter, plaintext)
            sock.sendto(pkt, esp32_addr)

            echo_data, _ = sock.recvfrom(512)
            _, _, rx_pt = parse_transport_packet(recv_key, echo_data)
            assert rx_pt == plaintext

    # ── Benchmark ────────────────────────────────────────────────

    @pytest.mark.parametrize("payload_size", [64, 128, 224])
    def test_echo_throughput(self, dut, transport_session, esp32_addr,
                             payload_size):
        """Measure pipelined transport echo throughput.

        A dedicated TX thread blasts packets for DURATION seconds.
        The main thread collects echoes.  Each packet's plaintext
        starts with an 8-byte send timestamp so we can measure
        per-packet latency without synchronizing the two threads.

        Reports TX/RX rates, latency (avg/p50/p99), loss, and
        bidirectional throughput.
        """
        sock, send_key, recv_key, rx_idx = transport_session

        DURATION = 10.0       # seconds the TX thread runs
        DRAIN_TIMEOUT = 3.0   # extra seconds to collect trailing echoes
        STAMP_SIZE = 8        # bytes for send timestamp (float64)
        PAD_SIZE = payload_size - STAMP_SIZE
        assert PAD_SIZE >= 0, "payload_size must be >= 8 for timestamp"

        padding = bytes(range(256)) * (PAD_SIZE // 256 + 1)
        padding = padding[:PAD_SIZE]

        # Warm-up: one synchronous round-trip to prime ARP / caches
        warmup_pt = struct.pack("<d", time.monotonic()) + padding
        warmup_pkt = build_transport_packet(send_key, rx_idx, counter=0,
                                            plaintext=warmup_pt)
        sock.sendto(warmup_pkt, esp32_addr)
        sock.settimeout(UDP_TIMEOUT)
        try:
            sock.recvfrom(512)
        except socket.timeout:
            pass  # non-fatal

        # ── Shared state between TX / RX threads ──
        tx_result = {"sent": 0}       # written by TX thread only
        stop_event = threading.Event()

        def tx_thread_fn():
            """Send packets at a steady rate for DURATION seconds."""
            counter = 1  # 0 was warmup
            sent = 0
            deadline = time.monotonic() + DURATION
            TX_INTERVAL = 0.001  # 10 ms between packets (~100 pkt/s)

            while time.monotonic() < deadline:
                stamp = struct.pack("<d", time.monotonic())
                pt = stamp + padding
                pkt = build_transport_packet(
                    send_key, rx_idx, counter, pt,
                )
                try:
                    sock.sendto(pkt, esp32_addr)
                    sent += 1
                    counter += 1
                except OSError:
                    pass  # send buffer full — skip

                time.sleep(TX_INTERVAL)

            tx_result["sent"] = sent
            stop_event.set()

        # ── Start TX thread, RX runs on main thread ──
        latencies = []
        recv_count = 0

        sock.settimeout(0.1)  # short timeout so RX loop stays responsive
        tx = threading.Thread(target=tx_thread_fn, daemon=True)

        blast_start = time.monotonic()
        tx.start()

        # Collect echoes while TX is running and during drain
        while True:
            try:
                echo_data, _ = sock.recvfrom(512)
            except socket.timeout:
                if stop_event.is_set():
                    break
                continue
            except OSError:
                if stop_event.is_set():
                    break
                continue

            rx_time = time.monotonic()
            try:
                _, _, rx_pt = parse_transport_packet(recv_key, echo_data)
                send_time = struct.unpack("<d", rx_pt[:STAMP_SIZE])[0]
                latencies.append(rx_time - send_time)
                recv_count += 1
            except Exception:
                pass  # drop malformed echoes

        tx.join(timeout=2.0)

        # ── Drain phase: collect remaining in-flight echoes ──
        sock.settimeout(DRAIN_TIMEOUT)
        while True:
            try:
                echo_data, _ = sock.recvfrom(512)
            except socket.timeout:
                break
            rx_time = time.monotonic()
            try:
                _, _, rx_pt = parse_transport_packet(recv_key, echo_data)
                send_time = struct.unpack("<d", rx_pt[:STAMP_SIZE])[0]
                latencies.append(rx_time - send_time)
                recv_count += 1
            except Exception:
                pass

        blast_end = time.monotonic()

        # ── Results ──
        sent_count = tx_result["sent"]
        elapsed = blast_end - blast_start
        loss_pct = ((sent_count - recv_count) / sent_count * 100
                    if sent_count > 0 else 0.0)

        sorted_lat = sorted(latencies) if latencies else []
        avg_lat_ms = (sum(sorted_lat) / len(sorted_lat) * 1000
                      if sorted_lat else float("inf"))
        p50 = sorted_lat[len(sorted_lat) // 2] * 1000 if sorted_lat else 0
        p99_idx = min(int(len(sorted_lat) * 0.99), len(sorted_lat) - 1)
        p99 = sorted_lat[p99_idx] * 1000 if sorted_lat else 0

        send_pps = sent_count / elapsed if elapsed > 0 else 0
        recv_pps = recv_count / elapsed if elapsed > 0 else 0
        throughput_kbps = (
            (recv_count * payload_size * 2 * 8) / elapsed / 1000
            if elapsed > 0 else 0
        )

        print(f"\n{'='*64}")
        print(f"  Pipelined Echo Benchmark  ({payload_size}B payload)")
        print(f"  Duration: {elapsed:.1f}s")
        print(f"  Sent: {sent_count}  |  Received: {recv_count}  "
              f"|  Loss: {loss_pct:.1f}%")
        print(f"  TX rate: {send_pps:.1f} pkt/s  |  "
              f"RX rate: {recv_pps:.1f} pkt/s")
        print(f"  Latency — avg: {avg_lat_ms:.1f}ms  "
              f"p50: {p50:.1f}ms  p99: {p99:.1f}ms")
        print(f"  Bidirectional throughput: {throughput_kbps:.1f} kbit/s")
        print(f"{'='*64}")
