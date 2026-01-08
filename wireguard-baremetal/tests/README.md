# VeriGuard Test Suite

This directory contains all tests for the VeriGuard project.

## Directory Structure

```
tests/
├── README.md
│
├── ada/                        # Ada/SPARK tests
│   ├── alire.toml              # Alire manifest (dependencies)
│   ├── tests.gpr               # GPR project file
│   ├── src/                    # Source code
│   │   ├── tests.ads           # Test framework (assertions, reporting)
│   │   ├── tests.adb
│   │   ├── test_runner.adb     # Main entry point
│   │   ├── unit/               # Unit tests
│   │   │   ├── tests-unit.ads
│   │   │   ├── tests-unit-crypto.ads
│   │   │   ├── tests-unit-crypto.adb
│   │   │   ├── tests-unit-wireguard.ads
│   │   │   └── tests-unit-wireguard.adb
│   │   └── property/           # Property-based tests - TODO
│   ├── bin/                    # Executables (generated)
│   ├── obj/                    # Object files (generated)
│   └── config/                 # Alire config (generated)
│
├── c/                          # C tests
│   ├── CMakeLists.txt          # CMake build - TODO
│   ├── unity/                  # Unity test framework (to be added)
│   ├── src/                    # Source code - TODO
│   │   └── unit/               # Unit tests
│   ├── build/                  # Build artifacts (generated)
│   └── bin/                    # Executables (generated)
│
└── integration/                # pytest-embedded integration tests - TODO
    ├── conftest.py
    ├── pytest.ini
    └── test_*.py
```

## Running Tests

### Ada Tests

```bash
cd tests/ada
alr build
./bin/run_tests
```

### C Tests (Future)

```bash
cd tests/c
cmake -B build -S .
cmake --build build
./build/run_c_tests
```

### Integration Tests (Future)

```bash
# Install pytest-embedded
pip install pytest-embedded-idf~=2.0 pytest-embedded-qemu~=2.0

# Run on QEMU (no hardware needed)
pytest --embedded-services idf,qemu --target esp32s3 integration/

# Run on real hardware
pytest --embedded-services idf --target esp32s3 --port /dev/ttyUSB0 integration/
```

---

## Test Types Explained

### Unit Tests vs Property Tests vs Integration Tests

| Aspect | Unit Tests | Property Tests | Integration Tests |
|--------|-----------|----------------|-------------------|
| **Scope** | Single function/procedure | Invariants across many inputs | Full system behavior |
| **Input** | Hand-crafted specific cases | Randomly generated | Real/simulated hardware |
| **Speed** | Very fast (ms) | Fast (seconds) | Slow (seconds-minutes) |
| **Location** | `ada/src/unit/`, `c/src/unit/` | `ada/src/property/` | `integration/` |

### Unit Tests

**Purpose:** Test individual functions or procedures in isolation with known inputs and expected outputs.

**Characteristics:**
- Test specific edge cases and known scenarios
- Fast execution (milliseconds per test)
- Easy to debug when failures occur
- Cover the "happy path" and known error conditions

**Example (Ada):**
```ada
procedure Test_ChaCha20_Known_Vector is
   Key       : constant Key_256 := (16#00#, 16#01#, ...);  -- Known test vector
   Nonce     : constant Nonce_96 := (...);
   Plaintext : constant Bytes := (...);
   Expected  : constant Bytes := (...);  -- Known correct output
   Result    : Bytes (Plaintext'Range);
begin
   Crypto.ChaCha20_Encrypt (Key, Nonce, Plaintext, Result);
   Assert (Result = Expected, "ChaCha20 output mismatch");
end Test_ChaCha20_Known_Vector;
```

**Example (C):**
```c
void test_buffer_init(void) {
    uint8_t buf[64];
    buffer_init(buf, sizeof(buf));
    TEST_ASSERT_EQUAL(0, buf[0]);
    TEST_ASSERT_EQUAL(0, buf[63]);
}
```

### Property Tests

**Purpose:** Verify that invariants and properties hold across a wide range of randomly generated inputs.

**Characteristics:**
- Test properties that should ALWAYS be true
- Generate hundreds/thousands of random inputs
- Find edge cases you didn't think of
- Complement unit tests, don't replace them

**Common Properties to Test:**
- **Round-trip:** `decrypt(encrypt(x)) = x`
- **Idempotence:** `f(f(x)) = f(x)`
- **Commutativity:** `f(a, b) = f(b, a)`
- **Invariants:** "output length always equals input length + 16"

**Example (Ada):**
```ada
procedure Test_Encrypt_Decrypt_Roundtrip is
   Key       : Key_256;
   Nonce     : Nonce_96;
   Plaintext : Bytes (1 .. 100);
   Cipher    : Bytes (1 .. 100);
   Decrypted : Bytes (1 .. 100);
begin
   --  Generate random inputs
   Random_Bytes (Key);
   Random_Bytes (Nonce);
   Random_Bytes (Plaintext);

   --  Property: decrypt(encrypt(x)) = x
   Crypto.Encrypt (Key, Nonce, Plaintext, Cipher);
   Crypto.Decrypt (Key, Nonce, Cipher, Decrypted);

   Assert (Decrypted = Plaintext, "Round-trip property violated");
end Test_Encrypt_Decrypt_Roundtrip;
```

**Example (conceptual, run many times with different random inputs):**
```ada
for I in 1 .. 1000 loop
   Test_Encrypt_Decrypt_Roundtrip;  -- Each run uses new random data
end loop;
```

### Integration Tests (pytest-embedded)

**Purpose:** Test the complete firmware running on real hardware or emulator (QEMU/Wokwi).

**Characteristics:**
- Test the actual compiled binary
- Verify boot sequence, initialization, hardware interaction
- Test timing-sensitive behavior
- Catch issues that only appear on real hardware

**What Integration Tests Verify:**
- Firmware boots correctly
- Serial output matches expected patterns
- Handshake completes within timeout
- System recovers from errors gracefully
- Memory usage stays within bounds

---

## pytest-embedded Deep Dive

### What is pytest-embedded?

pytest-embedded is Espressif's official testing framework for ESP-IDF projects. It allows you to:

1. **Flash firmware** to real hardware automatically
2. **Run on QEMU** without physical devices
3. **Run on Wokwi** cloud simulator
4. **Capture serial output** and verify with expect patterns
5. **Integrate with CI/CD** pipelines

### Installation

```bash
pip install pytest-embedded-idf~=2.0    # ESP-IDF support
pip install pytest-embedded-qemu~=2.0   # QEMU support (optional)
pip install pytest-embedded-wokwi~=2.0  # Wokwi support (optional)
```

### Configuration

**`integration/pytest.ini`:**
```ini
[pytest]
addopts = --embedded-services idf
```

**`integration/conftest.py`:**
```python
import pytest

# Configure default target
def pytest_configure(config):
    config.addinivalue_line("markers", "esp32s3: mark test for ESP32-S3")
```

### Writing Integration Tests

**Basic test - verify boot message:**
```python
# integration/test_boot.py
from pytest_embedded_idf import IdfDut

def test_wireguard_boots(dut: IdfDut):
    """Verify firmware boots and initializes WireGuard."""
    dut.expect("VeriGuard: Starting", timeout=5)
    dut.expect("WireGuard: Initialized", timeout=10)
    dut.expect("Ready for connections", timeout=5)
```

**Test with timeout verification:**
```python
def test_handshake_timeout(dut: IdfDut):
    """Verify handshake times out correctly when peer unreachable."""
    dut.expect("WireGuard: Initiating handshake")
    dut.expect("WireGuard: Handshake timeout", timeout=30)
    dut.expect("WireGuard: Retry scheduled")
```

**Test error handling:**
```python
def test_invalid_packet_rejected(dut: IdfDut):
    """Verify malformed packets are rejected gracefully."""
    dut.expect("Ready for connections")
    # Send malformed packet (via separate mechanism)
    dut.expect("WireGuard: Invalid packet rejected")
    dut.expect("WireGuard: Still operational")  # Didn't crash
```

**Parameterized tests for multiple targets:**
```python
import pytest

@pytest.mark.parametrize("target", ["esp32", "esp32s3", "esp32c3"])
def test_boots_on_target(dut: IdfDut, target):
    """Verify firmware boots on multiple chip variants."""
    dut.expect("VeriGuard: Starting")
```

### Running Integration Tests

```bash
# QEMU - no hardware needed (fastest for CI)
pytest --embedded-services idf,qemu --target esp32s3 integration/

# Real hardware
pytest --embedded-services idf --target esp32s3 --port /dev/ttyUSB0 integration/

# Wokwi cloud simulator
pytest --embedded-services idf,wokwi --target esp32s3 integration/

# Verbose output
pytest -v -s --embedded-services idf,qemu integration/

# Run specific test
pytest --embedded-services idf,qemu integration/test_boot.py::test_wireguard_boots
```

### CI/CD Integration

**GitHub Actions example:**
```yaml
jobs:
  integration-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: espressif/esp-idf-ci-action@v1
        with:
          esp_idf_version: v5.2
      - name: Install pytest-embedded
        run: pip install pytest-embedded-idf~=2.0 pytest-embedded-qemu~=2.0
      - name: Build firmware
        run: idf.py build
      - name: Run integration tests
        run: pytest --embedded-services idf,qemu --target esp32s3 tests/integration/
```

---

## Test Dependencies

### Ada
- `crypto` (local crate)
- `wireguard` (local crate)
- `net` (local crate)

### C
- Unity framework (`c/unity/`)
- Platform headers from `platform/common/` and `platform/cortex_m/`

### Integration (Python)
- `pytest-embedded-idf~=2.0`
- `pytest-embedded-qemu~=2.0` (optional)
- `pytest-embedded-wokwi~=2.0` (optional)

---

## Adding New Tests

### Ada Unit Test

1. Create spec in `ada/src/unit/tests-unit-<module>.ads`:
   ```ada
   with <Module>;  -- Import the package under test

   package Tests.Unit.<Module> is
      procedure Test_Something;
   end Tests.Unit.<Module>;
   ```

2. Create body in `ada/src/unit/tests-unit-<module>.adb`:
   ```ada
   with Tests; use Tests;

   package body Tests.Unit.<Module> is
      procedure Test_Something is
      begin
         Assert (True, "Description");
      end Test_Something;
   end Tests.Unit.<Module>;
   ```

3. Register in `ada/src/test_runner.adb`:
   ```ada
   with Tests.Unit.<Module>;
   ...
   Run_Test ("Test name", Tests.Unit.<Module>.Test_Something'Access);
   ```

### C Unit Test

1. Add Unity (if not already):
   ```bash
   git submodule add https://github.com/ThrowTheSwitch/Unity.git tests/c/unity
   ```

2. Create test file in `c/unit/test_<component>.c`:
   ```c
   #include "unity.h"
   #include "<component>.h"

   void setUp(void) { }
   void tearDown(void) { }

   void test_something(void) {
       TEST_ASSERT_TRUE(1);
   }

   int main(void) {
       UNITY_BEGIN();
       RUN_TEST(test_something);
       return UNITY_END();
   }
   ```

3. Add to `CMakeLists.txt`

### Integration Test

1. Create test file in `integration/test_<feature>.py`:
   ```python
   from pytest_embedded_idf import IdfDut

   def test_feature(dut: IdfDut):
       dut.expect("Expected output")
   ```

---

## Design Principles

1. **No code duplication** - Tests import and test actual source code
2. **Separation by language** - Ada in `src/`, C in `c/`, Python in `integration/`
3. **Layered testing** - Unit → Property → Integration
4. **Host-first** - Unit tests run on host machine, no hardware needed
5. **CI-friendly** - All tests can run in CI (QEMU for integration)
