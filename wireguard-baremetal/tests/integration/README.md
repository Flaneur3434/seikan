# VeriGuard Integration Tests

## What is Integration Testing?

**Integration tests** verify that multiple components work together correctly in a real environment. Unlike unit tests (which test isolated functions), integration tests:

- Run on **actual hardware** (ESP32-C6)
- Test **real behavior** (WiFi connects, UDP packets flow)
- Verify **end-to-end functionality** (boot → connect → serve)
- Catch issues that only appear in the real system

For embedded systems, this is called **hardware-in-the-loop (HIL)** testing.

## How pytest-embedded-idf Works

[pytest-embedded](https://github.com/espressif/pytest-embedded) is Espressif's pytest plugin for testing ESP-IDF projects on real hardware.

### The Testing Flow

```
┌─────────────────────────────────────────────────────────────────┐
│  pytest --target esp32c6                                        │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  1. pytest discovers tests in testpaths (pytest.ini)            │
│  2. For each test, pytest-embedded:                             │
│     a. Builds/flashes firmware to ESP32 via serial              │
│     b. Opens serial monitor to capture logs                     │
│     c. Injects `dut` (Device Under Test) fixture                │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  3. Test function runs:                                         │
│     - dut.expect('pattern') waits for log output                │
│     - Test can send UDP packets, check responses                │
│     - Assertions verify expected behavior                       │
└───────────────────────────────┬─────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│  4. Test passes/fails based on assertions and timeouts          │
└─────────────────────────────────────────────────────────────────┘
```

### The `dut` Fixture

The `dut` (Device Under Test) is the core pytest fixture provided by pytest-embedded-idf:

```python
def test_example(dut: IdfDut) -> None:
    # Wait for a log message (regex supported)
    dut.expect('wifi sta: got ip:', timeout=30)
    
    # Capture matched text
    match = dut.expect(r'got ip:(\d+\.\d+\.\d+\.\d+)')
    ip_address = match.group(1)
    
    # Access device info
    print(f"Target: {dut.target}")  # esp32c6
    print(f"Port: {dut.serial.port}")  # /dev/ttyUSB0
```

## File Structure Explained

```
wireguard-baremetal/
├── pytest.ini                    # pytest configuration
├── tests/
│   └── integration/
│       ├── conftest.py           # pytest fixtures (setup/teardown)
│       ├── pytest_veriguard.py   # test functions
│       └── README.md             # this file
└── build/
    └── VeriGuard.elf             # firmware (flashed by pytest)
```

### pytest.ini - Configuration

Tells pytest how to discover and run tests:

```ini
[pytest]
# Where to find tests
testpaths = tests/integration

# Test file pattern (must match pytest_*.py for ESP-IDF)
python_files = pytest_*.py

# Enable ESP-IDF services (flashing, serial, IdfDut)
addopts = --embedded-services esp,idf -s

# Custom markers for filtering
markers =
    esp32c6: Tests for ESP32-C6 target
```

**Key options:**
- `--embedded-services esp,idf` - Enables `IdfDut` fixture with flashing support
- `-s` - Show stdout (print statements) during tests
- `--target esp32c6` - Specify chip (required at runtime)

### conftest.py - Fixtures

Defines reusable setup/teardown code that runs for each test:

```python
import pytest
from pytest_embedded_idf.dut import IdfDut

@pytest.fixture(autouse=True)
def reset_device_before_test(dut: IdfDut) -> None:
    """Reset the ESP32 before each test for clean state."""
    dut.serial.hard_reset()
```

**How fixtures work:**
- `@pytest.fixture` - Declares a fixture function
- `autouse=True` - Runs automatically for every test (no explicit call needed)
- Fixture runs **before** each test function
- Can also have teardown code (using `yield`)

### pytest_veriguard.py - Test Functions

Contains the actual test logic:

```python
import pytest
from pytest_embedded_idf.dut import IdfDut

@pytest.mark.esp32c6    # Marker for filtering
@pytest.mark.generic    # Can run on any test setup
def test_wifi_connects(dut: IdfDut) -> None:
    """Test that WiFi connects successfully."""
    
    # Wait for log messages (blocks until seen or timeout)
    dut.expect('wifi sta: wifi_init_sta finished', timeout=30)
    dut.expect(r'wifi sta: got ip:', timeout=60)
    
    # If we reach here without timeout, test passes
```

**Key patterns:**
- `dut.expect(pattern, timeout)` - Wait for serial output matching pattern
- `dut.expect_exact(string)` - Wait for exact string (no regex)
- Regex groups capture values: `match.group(1)`
- Test fails if `expect()` times out or assertion fails

## Running Tests

### Prerequisites

```bash
# Install pytest-embedded in ESP-IDF environment
cd $IDF_PATH
bash install.sh --enable-pytest
source export.sh
```

### Commands

```bash
# Build firmware first
idf.py build

# Run all tests
pytest --target esp32c6

# Run specific test
pytest --target esp32c6 -k test_udp_echo

# Verbose output
pytest --target esp32c6 -v

# Specify serial port
pytest --target esp32c6 --port /dev/ttyUSB0

# Skip flashing (use already-flashed firmware)
pytest --target esp32c6 --skip-autoflash y
```

## Common Patterns

### Waiting for Boot Sequence

```python
def test_boot(dut: IdfDut):
    dut.expect('wifi sta: wifi_init_sta finished', timeout=30)
    dut.expect(r'got ip:(\d+\.\d+\.\d+\.\d+)', timeout=60)
```

### Capturing Values

```python
def test_get_ip(dut: IdfDut):
    match = dut.expect(r'got ip:(\d+\.\d+\.\d+\.\d+)')
    ip = match.group(1).decode()  # Returns bytes, decode to str
    print(f"Device IP: {ip}")
```

### Interacting with Device

```python
import socket

def test_udp_echo(dut: IdfDut):
    # Wait for server ready
    match = dut.expect(r'got ip:(\d+\.\d+\.\d+\.\d+)')
    ip = match.group(1).decode()
    dut.expect('udp srv: Waiting for data')
    
    # Send UDP packet from test host
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(b'hello', (ip, 51820))
    
    # Verify device received it
    dut.expect('Received 5 bytes')
```

## Debugging Tips

1. **Test hangs**: Check `timeout` values, device may not be printing expected log
2. **Pattern not found**: Use `-s` flag to see actual device output
3. **Port busy**: Close other serial monitors (idf.py monitor, screen, etc.)
4. **Flashing fails**: Check USB connection, try `--port /dev/ttyUSB0` explicitly

## References

- [pytest-embedded documentation](https://docs.espressif.com/projects/pytest-embedded/en/latest/)
- [ESP-IDF pytest guide](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/contribute/esp-idf-tests-with-pytest.html)
- [pytest fixtures](https://docs.pytest.org/en/stable/how-to/fixtures.html)
