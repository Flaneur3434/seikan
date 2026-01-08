# Bindings: Ada/C Boundary Layer

This crate defines the **minimal C ABI** for calling the Ada/SPARK WireGuard core from C code.

## Design Philosophy

> **Ada defines what is allowed. C only moves bytes.**

The bindings layer enforces strict separation of concerns:

| Responsibility | Owner |
|---|---|
| Protocol semantics | Ada (wireguard crate) |
| Crypto orchestration | Ada (crypto crate) |
| Packet validation | Ada (wireguard + crypto) |
| State machine | Ada (wireguard) |
| **Raw byte transport** | **C** |
| **Hardware I/O** | **C** |
| **Buffer management** | **C** (Ada borrows temporarily) |

## The C ABI

Only **two functions** are exported to C:

### `void wg_receive_bytes(const uint8_t *buf, size_t len)`

**Purpose:** Feed incoming network packet bytes to Ada.

**What Ada does:**
1. Parse packet header (type detection)
2. Look up peer by public key
3. Check replay window
4. Decrypt and authenticate
5. Update protocol state
6. Queue decrypted data for application

**What C guarantees:**
- Pointer is valid for `len` bytes
- Bytes are from network (untrusted)
- Call is non-reentrant (no concurrent calls)

**What C cannot do:**
- Interpret any WireGuard fields
- Decide packet type
- Mutate protocol state

### `size_t wg_prepare_tx(uint8_t *out, size_t max_len)`

**Purpose:** Get outgoing packet bytes for transmission.

**What Ada does:**
1. Check if data/keepalive/retry pending
2. Construct packet (header, payload, encryption)
3. Encrypt and authenticate
4. Write encrypted bytes to `out_buf`
5. Return number of bytes written (0 if nothing to send)

**What C guarantees:**
- Output buffer is valid for `max_len` bytes
- Can be called periodically to check for pending TX

**What C does next:**
- Send returned bytes via WiFi TX DMA
- No parsing or inspection of payload

---

## Architecture: Memory Ownership

```
Ada:                           C:
┌──────────────────────────┐   ┌──────────────────┐
│ Wireguard core state     │   │ RX/TX buffers    │
│ (private, verified)      │   │ (DMA, hardware)  │
│                          │   │                  │
│ Peer[]                   │   │ packet_in[MAX]   │
│ Session[]                │◄──┤ packet_out[MAX]  │
│ Replay window[]          │   │                  │
│                          │   │                  │
│ Bounded buffers:         │   │ WiFi driver      │
│ encrypted_queue[1500]    │   │ ISR handlers     │
│ plaintext_queue[1500]    │   │ DMA engine       │
└──────────────────────────┘   └──────────────────┘
```

**Memory rules:**
- Ada allocates statically (Alire config determines sizes)
- C provides buffers and passes pointers
- Ada **borrows** C buffers during RX/TX calls (no persistent pointers)
- Ada **copies** into its own bounded buffers if persistent storage needed

This avoids:
- Lifetime bugs (dangling pointers)
- Aliasing violations (SPARK soundness)
- Unbounded allocation (predictable memory)

---

## Non-Reentrancy Guarantee

The Ada core is **single-threaded and non-reentrant**:

- C may call `wg_receive_bytes()` from main loop OR ISR
- C may call `wg_prepare_tx()` from main loop OR timer
- Ada may NOT be called concurrently
- Any concurrency is handled *outside* the verified core

**How to ensure this on FreeRTOS / ESP-IDF:**

```c
// Example: WiFi RX ISR
void wifi_rx_isr(void *arg) {
    packet_t *pkt = wifi_rx_queue_get();
    // Defer to main task (don't call wg_receive_bytes in ISR)
    xQueueSendFromISR(ada_input_queue, &pkt, NULL);
}

// Main task
void main_loop() {
    while (1) {
        // Single-threaded Ada calls
        if (ada_input_queue_get(&pkt)) {
            wg_receive_bytes(pkt->buf, pkt->len);  // Safe
        }
        if (timer_check()) {
            wg_prepare_tx(out_buf, MAX_LEN);       // Safe
        }
    }
}
```

---

## Extensibility

The ABI is intentionally minimal to start. Future additions could include:

- `int wg_configure_peer(peer_key, allowlist)` - Add peer and allowed IPs
- `int wg_get_status(status_t *out)` - Query connection state
- `int wg_force_renegotiate()` - Trigger new handshake

All additions follow the same rule: **C provides data, Ada decides.**

---

## Testing

Unit tests for the bindings layer:

```bash
cd tests/ada
alr build
./bin/run_tests
```

Integration tests call both Ada and C via the ABI:
- Mock C layer feeds test packets to Ada
- Verify Ada state transitions and output
- No protocol logic leaks into test C code

---

## Files

- `wireguard_c_abi.ads` - Public C interface (specification)
- `wireguard_c_abi.adb` - Implementation (calls crypto/wireguard core)
- `alire.toml` - Dependencies on crypto, wireguard, net

---

## References

- WireGuard Protocol: https://www.wireguard.com/protocol/
- Noise Protocol: https://noiseprotocol.org/
- SPARK User's Guide: https://docs.adacore.com/spark2014-docs/html/ug/
