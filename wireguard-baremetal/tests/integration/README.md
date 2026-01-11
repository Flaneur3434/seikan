# VeriGuard Integration Tests

Integration tests using pytest-embedded-idf for hardware-in-the-loop testing.

## Prerequisites

Install ESP-IDF with pytest support:

```bash
cd $IDF_PATH
bash install.sh --enable-ci --enable-pytest
. ./export.sh
```

## Running Tests

### Build first
```bash
cd /path/to/wireguard-baremetal
idf.py set-target esp32c6 build
```

### Run all tests
```bash
pytest --target esp32c6
```

### Run specific test
```bash
pytest --target esp32c6 -k test_udp_echo
```

### Specify serial port
```bash
pytest --target esp32c6 --port /dev/ttyUSB0
```

### Skip auto-flash (use already flashed firmware)
```bash
pytest --target esp32c6 --skip-autoflash y
```

## Test Descriptions

| Test | Description |
|------|-------------|
| `test_wifi_station_connects` | Verifies WiFi station connects to configured AP |
| `test_udp_server_starts` | Verifies UDP server binds to port 51820 |
| `test_full_startup_sequence` | End-to-end startup validation |
| `test_udp_echo_server` | Sends UDP packets every 2s for 10s, verifies echo |

## Configuration

WiFi credentials are read from `sdkconfig`:
- `CONFIG_ESP_WIFI_SSID`
- `CONFIG_ESP_WIFI_PASSWORD`

## Expected Log Output

```
I (xxx) wifi sta: wifi_init_sta finished.
I (xxx) wifi sta: got ip: x.x.x.x
I (xxx) wifi sta: connected to ap SSID:... password:...
I (xxx) main: ESP_WIFI_MODE_STA
I (xxx) udp srv: Socket created
I (xxx) udp srv: Socket bound, port 51820
I (xxx) udp srv: Waiting for data
```

## File Structure

According to ESP-IDF conventions, the pytest script is at project root:

```
wireguard-baremetal/
├── pytest_veriguard.py     # Main pytest test file
├── main/
│   └── ...
├── CMakeLists.txt
└── tests/
    └── integration/
        └── README.md       # This file
```
