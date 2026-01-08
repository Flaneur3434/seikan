# Platform: Hardware Abstraction Layer

This directory contains platform-specific implementations for bare-metal WireGuard.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│          Ada/SPARK WireGuard Core (TCB)              │
│     (crypto/, wireguard/, net/, bindings/)          │
└────────────────┬────────────────────────────────────┘
                 │
                 │ C ABI: wg_receive_bytes(), wg_prepare_tx()
                 │
┌────────────────┴────────────────────────────────────┐
│        Platform Layer (ESP-IDF, C)                   │
│                                                     │
│  ┌─────────────────────────────────────────────┐   │
│  │  main/           - App entry point (main.c) │   │
│  │  common/         - HAL abstractions         │   │
│  │  cortex_m/       - ARM Cortex-M specific    │   │
│  └─────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────┘
        │
        │ HAL: timers, RNG, memory, endian
        │
┌───────┴───────────────────────────────────┐
│     Hardware (ESP32-C6, WiFi, DMA)        │
└───────────────────────────────────────────┘
```

## Directory Layout

```
platform/
├── main/                  # ESP-IDF application component
│   ├── main.c             # app_main() - orchestrates Ada + C
│   └── CMakeLists.txt     # ESP-IDF component config
│
├── common/                # Shared HAL
│   ├── common.c
│   ├── common.h
│   │   - platform_time() - milliseconds since boot
│   │   - platform_rng()  - random bytes
│   │   - platform_memcpy_safe() - checked copy
│   │   - platform_endian_*() - endian conversions
│   └── CMakeLists.txt
│
└── cortex_m/              # ARM Cortex-M specific
    ├── cortex_m.c
    ├── cortex_m.h
    │   - systick initialization
    │   - exception handling stubs
    │   - cache control (if applicable)
    └── CMakeLists.txt
```

## Design Rules

### 1. C is Untrusted I/O Only

C code:
- ✓ Manages hardware registers
- ✓ Handles interrupts
- ✓ Owns DMA buffers
- ✓ Performs timing / RNG / memory operations

C code **cannot**:
- ✗ Interpret WireGuard protocol
- ✗ Parse packet headers
- ✗ Make security decisions
- ✗ Mutate Ada state

### 2. Ada Borrowing Model

```c
// C provides buffer
uint8_t rx_pkt[1500];
size_t rx_len;

// Ada borrows it temporarily
wg_receive_bytes(rx_pkt, rx_len);
// ^^ Ada does NOT keep a pointer to rx_pkt
// It copies into its own internal buffers if needed

// After the call, C can reuse rx_pkt
```

**Why?** Avoids lifetime bugs and SPARK soundness issues.

### 3. Single-Threaded Ada

- All `wg_*` calls must be from same execution context
- Can be main task OR ISR task, but not concurrent
- Serialization is C's responsibility

### 4. No Exceptions Cross Boundary

If Ada detects an error:
- Returns 0 from `wg_prepare_tx()`
- Silently drops invalid packet in `wg_receive_bytes()`
- C observes only outward behavior (no output, no state change)

---

## main.c: Application Entry

The main application orchestrates Ada + C:

```c
int app_main(void) {
    // 1. Initialize hardware
    platform_init();
    wifi_init();
    
    // 2. Initialize Ada core (if needed - TODO)
    // wg_initialize(...);
    
    // 3. Main loop
    while (1) {
        // Poll for RX packets
        if (wifi_rx_available()) {
            packet_t *pkt = wifi_rx_dequeue();
            wg_receive_bytes(pkt->buf, pkt->len);
            wifi_free_packet(pkt);
        }
        
        // Check for TX pending
        size_t tx_len = wg_prepare_tx(tx_buf, sizeof(tx_buf));
        if (tx_len > 0) {
            wifi_tx_send(tx_buf, tx_len);
        }
        
        // Handle timers (keepalive, handshake retry, etc)
        if (timer_tick()) {
            // TODO: Call into Ada for timer events?
        }
    }
    
    return 0;
}
```

---

## common/: Hardware Abstraction

Provides minimal HAL for Ada to use:

### `uint32_t platform_time_ms(void)`
- Returns milliseconds since boot
- Used by Ada for timeout tracking, keepalive

### `void platform_random_bytes(uint8_t *buf, size_t len)`
- Fill buffer with cryptographically secure random
- Used for nonce generation

### Endian Functions
- `uint32_t platform_hton32(uint32_t)` - host to network byte order
- `uint16_t platform_hton16(uint16_t)`
- Portable across architectures

### Memory Ops
- `platform_memcpy_checked()` - bounds-checked copy
- `platform_memmove_checked()` - overlap-aware copy

---

## cortex_m/: Architecture-Specific

Cortex-M initialization and utilities:

- **SysTick setup** - configures timer interrupt for `platform_time_ms()`
- **Exception stubs** - HardFault, MemManage, etc.
- **Cache control** - if M7/M55 with D-cache
- **RNG init** - configure TRNG or PRNG seed

---

## Integration with ESP-IDF

The root `CMakeLists.txt` orchestrates:

1. Build Ada crates with Alire
2. Collect Ada `.a` libraries
3. Pass to ESP-IDF linker
4. Link into final firmware

```cmake
# Root CMakeLists.txt
add_custom_target(build_ada_crates ...)
idf_project_init(...)
target_link_libraries(${main_lib} PUBLIC Bindings Wireguard Crypto Net)
```

---

## Building

```bash
# Full build (Ada + C)
cd /path/to/wireguard-baremetal
idf.py build

# Just C platform code
cd platform && cmake -B build && cmake --build build

# Just Ada (for testing)
cd bindings && alr build
```

---

## Testing Platform Code

Since C is "untrusted I/O," we mock it heavily in tests:

```bash
cd tests/ada
./bin/run_tests  # Runs Ada unit tests with mock C drivers
```

Platform-specific tests can use ESP-IDF's Unity framework (future).

---

## References

- ESP-IDF: https://docs.espressif.com/projects/esp-idf/
- Cortex-M CMSIS: https://github.com/ARM-software/CMSIS_5
- WireGuard on Embedded: https://www.wireguard.com/#conceptual-overview
