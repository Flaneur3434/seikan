# platform/main: Application Entry Point

This is the ESP-IDF component that contains the WireGuard application entry point.

## Responsibility

This component is **responsible for**:
- ✓ Initializing ESP32 hardware (WiFi, DMA, timers)
- ✓ Calling Ada core via C ABI functions
- ✓ Managing packet RX/TX queues
- ✓ Handling interrupt deferral to main task

This component is **not responsible for**:
- ✗ Protocol logic (Ada)
- ✗ Cryptography (Ada)
- ✗ State machine decisions (Ada)
- ✗ Packet parsing (Ada)

## Files

### `main.c`

Contains `app_main()`, the ESP-IDF application entry point.

**Current state:** Skeleton with TODO markers.

**When implemented, should:**
1. Call `platform_init()` to set up HAL
2. Initialize WiFi driver
3. Enter main loop:
   - Poll for RX packets → call `wg_receive_bytes(buf, len)`
   - Check for TX pending → call `wg_prepare_tx(out_buf, max_len)` and send
   - Handle timers (keepalive, retry, timeout)
4. Never interpret WireGuard protocol

### `CMakeLists.txt`

ESP-IDF component configuration.

**When complete, should:**
- Register this as an ESP-IDF component
- Link Ada libraries (libWireguard.a, libCrypto.a, etc.)
- Include platform/common/ and platform/cortex_m/ headers

---

## Data Flow

```
WiFi RX Interrupt
    │
    ├─→ ISR queues packet to Ada input queue
    │
Main Task Loop
    │
    ├─→ wg_receive_bytes(pkt)
    │      │
    │      ├─→ Ada validates
    │      ├─→ Ada updates state
    │      └─→ Ada queues plaintext
    │
    └─→ wg_prepare_tx(out_buf)
           │
           ├─→ Ada checks pending data
           ├─→ Ada constructs packet
           └─→ Ada encrypts & returns len
    │
    └─→ WiFi TX sends out_buf

```

**Key property:** Ada is called only from main task (serialized).

---

## Concurrency Model

To maintain single-threaded Ada semantics:

```c
// WiFi driver (ISR context)
void wifi_rx_isr(void *arg) {
    packet_t *pkt = get_rx_packet();
    
    // Do NOT call wg_receive_bytes here!
    // Instead, queue for main task
    xQueueSendFromISR(ada_input_queue, &pkt, NULL);
}

// Main task (cooperative multitasking)
void main_task(void *arg) {
    while (1) {
        packet_t pkt;
        if (xQueueReceive(ada_input_queue, &pkt, 0)) {
            // Safe to call Ada from here
            wg_receive_bytes(pkt.buf, pkt.len);
        }
        
        size_t len = wg_prepare_tx(out_buf, sizeof(out_buf));
        if (len > 0) {
            wifi_tx_send(out_buf, len);
        }
        
        vTaskDelay(10 / portTICK_PERIOD_MS);
    }
}
```

---

## Environment

| Tool | Version |
|------|---------|
| ESP-IDF | v5.x+ |
| Target | ESP32-C6 (adaptable to other Cortex-M) |
| Main clock | 160 MHz |
| RAM | ≥ 128 KB |

---

## Integration

This component is built as part of the root CMakeLists.txt:

```bash
cd /path/to/wireguard-baremetal
idf.py build  # Builds platform/main as ESP-IDF component
```

The root build system:
1. Invokes Alire to build Ada libraries
2. Passes Ada library paths to ESP-IDF linker
3. Compiles this component (main.c) and links Ada

---

## Testing

To test this entry point and C integration:

```bash
# Build and run on ESP32 simulator (QEMU)
idf.py build
qemu-system-xtensa ...

# Or on real hardware
idf.py flash monitor
```

---

## Future Work

When implemented, main.c should:
- [ ] WiFi initialization (SSID, password, AP scan)
- [ ] Task creation for main loop
- [ ] Packet RX queue from ISR
- [ ] TX transmission loop
- [ ] Timer handling (keepalive, retry)
- [ ] Graceful shutdown / error recovery

See TODO markers in main.c for details.
