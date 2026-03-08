# Platform — ESP32-C6 Main Application

This is the C / ESP-IDF platform layer. There is no real application logic here. The firmware exists primarily as a test harness for exercising the Ada/SPARK WireGuard protocol core on hardware. It brings up WiFi, initialises the tunnel, and exposes test commands over UDP.

## Files

| File | Purpose |
|------|---------|
| `main.c` | Entry point: WiFi init -> key loading -> Ada protocol init -> task start |
| `wg_task.c/h` | FreeRTOS task: RX queue consumer, dispatches packets to Ada and handles actions |
| `wg_commands.c/h` | Test command dispatcher |
| `wg_netif.c/h` | lwIP custom netif (`wg0`): zero-copy RX inject, TX output via inner queue |
| `wg_keys.c/h` | Loads static keys and peer config from NVS/Kconfig into Ada at startup |
| `wg_clock.c/h` | Monotonic clock shim: provides `esp_timer_get_time()` to Ada via C ABI |
| `wifi_station.c/h` | WiFi STA driver: connect, wait for IP, event handling |
| `Kconfig` | Menuconfig entries for WiFi credentials, WireGuard keys, peer config |
| `CMakeLists.txt` | ESP-IDF component registration, links Ada static libraries |
| `idf_component.yml` | ESP-IDF component manager manifest (managed dependencies) |
