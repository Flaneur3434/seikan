# Crypto Library

The `crypto` library provides cryptographic primitives for VeriGuard using Ada/SPARK with pluggable backend support (libsodium, mbedtls, etc.).

## Architecture

```
crypto/src/
├── crypto.ads                      # Parent package: types, constants, Status
├── interfaces/                     # Public SPARK-verified specs (.ads)
│   ├── crypto-random.ads           # RNG interface
│   └── crypto-x25519.ads           # X25519 ECDH interface
├── implementation/                 # Bodies (.adb) - use Crypto.Platform
│   ├── crypto-random.adb
│   └── crypto-x25519.adb
└── platform/                       # Backend-specific bindings
    └── libsodium/                  # Provides Crypto.Platform for libsodium
        └── crypto-platform.ads
    # Future backends:
    # └── mbedtls/
    #     ├── crypto-platform.ads
    #     └── crypto-platform.adb (if needed)
```

## Design Principles

- **SPARK specs, C FFI bodies**: Public interfaces have `SPARK_Mode => On`; bodies use `SPARK_Mode => Off`
- **Platform abstraction**: Implementations use `Crypto.Platform`, not specific backend names
- **Pluggable backends**: GPR `CRYPTO_BACKEND` variable selects which `platform/<backend>/` provides `Crypto.Platform`
- **Private bindings**: `Crypto.Platform` is a `private package` - FFI details hidden from users
- **Error handling via Status**: No exceptions; all operations return `out Status` parameter

## Available Primitives

| Module | Functions | Status |
|--------|-----------|--------|
| `Crypto.Random` | `Fill_Random` | ✅ Implemented |
| `Crypto.X25519` | `Generate_Key_Pair`, `Scalar_Mult_Base`, `Scalar_Mult` | ✅ Implemented |
| ChaCha20-Poly1305 | AEAD encrypt/decrypt | 🔲 Planned |
| BLAKE2b | Keyed hash | 🔲 Planned |

## Building

### Build Variables

| Variable | Values | Default | Description |
|----------|--------|---------|-------------|
| `PLATFORM` | `host`, `esp_idf` | `esp_idf` | Target platform |
| `CRYPTO_BACKEND` | `libsodium`, `mbedtls` | `libsodium` | Crypto library backend |

### Host (for testing)

```bash
cd crypto
alr build -- -XPLATFORM=host  -XCRYPTO_BACKEND=libsodium
```

Requires libsodium installed:
```bash
# Built from third_party/libsodium and installed to /usr/local
cd third_party/libsodium
./autogen.sh && ./configure && make -j$(nproc) && sudo make install
```

### ESP32 (for embedded)

```bash
alr build -- -XPLATFORM=esp_idf  -XCRYPTO_BACKEND=libsodium
```

Uses libsodium from ESP-IDF component registry (added via `idf.py add-dependency`).

## SPARK Analysis

```bash
# Check mode (SPARK legality)
~/.alire/bin/gnatprove -P crypto.gpr -XPLATFORM=host --mode=check

# Flow analysis (data dependencies)
~/.alire/bin/gnatprove -P crypto.gpr -XPLATFORM=host --mode=flow
```

Bodies with `SPARK_Mode => Off` are excluded from analysis. The SPARK specs define contracts that are validated for consistency.

## Unit Tests

Tests are managed by GNATtest in `tests/ada/crypto/`:

```bash
# Build and run tests
cd tests/ada/crypto/harness
gprbuild -P test_driver.gpr -XPLATFORM=host -XCRYPTO_BACKEND=libsodium
LD_LIBRARY_PATH=/usr/local/lib ./test_runner
```

Expected output:
```
crypto-random.ads:4:4: info: corresponding test PASSED
crypto-x25519.ads:10:4: info: corresponding test PASSED
crypto-x25519.ads:17:4: info: corresponding test PASSED
crypto-x25519.ads:25:4: info: corresponding test PASSED
crypto.ads:10:4: info: corresponding test PASSED
5 tests run: 5 passed; 0 failed; 0 crashed.
```

## Regenerating Test Harnesses

When you add new subprograms to the interfaces:

```bash
cd crypto
gnattest -P crypto.gpr -XPLATFORM=host \
  --harness-dir="$(pwd)/../tests/ada/crypto/harness" \
  --tests-dir="$(pwd)/../tests/ada/crypto/tests"
```

GNATtest will preserve your existing test implementations and add stubs for new subprograms.

## API Reference

### Status Type

```ada
type Status is (Success, Error_Failed, Error_Invalid_Argument);
function Is_Success (S : Status) return Boolean is (S = Success);
```

### X25519 Key Exchange

```ada
--  Generate random keypair
procedure Generate_Key_Pair (Key : out Key_Pair; Result : out Status);

--  Derive public key from secret key
procedure Scalar_Mult_Base
  (Public_Key : out X25519_Public_Key;
   Secret_Key : X25519_Secret_Key;
   Result     : out Status);

--  Diffie-Hellman: compute shared secret
procedure Scalar_Mult
  (Shared_Secret : out X25519_Shared_Secret;
   My_Secret     : X25519_Secret_Key;
   Their_Public  : X25519_Public_Key;
   Result        : out Status);
```
