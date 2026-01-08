# VeriGuard: Formally Verified WireGuard for Bare-Metal Systems

A **formally verified WireGuard client** for bare-metal and no-OS embedded systems. This project provides a **minimal, memory-safe, and cryptographically correct** implementation of the WireGuard protocol for resource-constrained microcontrollers—without POSIX, dynamic memory allocation, or a full operating system.

## Project Goals

- **Small Trusted Computing Base (TCB)**: Minimal verified core with clear boundaries
- **Memory Safety**: No heap allocation in the verified core; deterministic memory usage
- **Cryptographic Correctness**: Verified crypto interfaces with replaceable backends
- **Protocol Correctness**: Machine-checked guarantees for key agreement, replay protection, and state transitions
- **Portability**: Clean separation between protocol logic and platform-specific code

## Directory Structure

```
wireguard-baremetal/
├── crypto/                 # Ada/SPARK - Cryptographic primitives
│   └── src/
│       ├── interfaces/     # Abstract crypto API (SPARK-verified boundary)
│       └── implementations/# ChaCha20-Poly1305, BLAKE2s, X25519
│
├── wireguard/              # Ada/SPARK - Protocol core (TCB)
│   └── src/
│       ├── core/           # Types, peer, device, state, timers, replay
│       ├── handshake/      # Noise IK handshake (init, response, cookie)
│       └── transport/      # Packet encrypt/decrypt, sequencing
│
├── net/                    # Ada/SPARK - Network abstraction
│   └── src/
│       ├── interfaces/     # Abstract driver & buffer interfaces
│       └── implementations/# UDP, loopback implementations
│
├── platform/               # C (ESP-IDF) - Hardware abstraction
│   ├── common/             # Endian, time, memory abstractions
│   └── cortex_m/           # Cortex-M specific: systick, RNG
│
├── verification/           # Formal models
│   └── models/             # TLA+ specifications (handshake, replay, KDF)
│
├── proof/                  # SPARK proof artifacts
│   ├── ghost/              # Ghost state for proof
│   └── contracts/          # Contract specifications
│
├── tests/                  # Ada - Test suites
│   └── src/
│       ├── unit/           # Unit tests
│       └── property/       # Property-based tests
│
├── examples/               # Example applications
│   ├── echo_client/
│   └── minimal_tunnel/
│
├── tools/                  # Development tools
│   ├── keygen/             # Key generation utility
│   └── packet_fuzzer/      # Fuzzing tools
│
├── config/                 # Build & device configuration
└── third_party/            # External dependencies
```

## Technologies

| Technology | Purpose |
|------------|---------|
| **Ada/SPARK** | Primary implementation language; memory safety, strong typing, contract-based verification |
| **Alire** | Ada package manager for dependency management |
| **ESP-IDF** | Platform layer for embedded targets (Cortex-M, ESP32) |
| **TLA+** | Formal specification of protocol state machines |
| **GNATprove** | SPARK proof tool for absence of runtime errors |

## Trusted Computing Base

The TCB is kept minimal and explicit:

```
TCB ≈
  crypto/src/interfaces/
  wireguard/src/core/
  wireguard/src/handshake/
  wireguard/src/transport/
```

Everything outside the TCB is replaceable or mockable.

## Building

### Prerequisites

- [Alire](https://alire.ada.dev/) 2.x
- [GNAT](https://www.adacore.com/download) with SPARK tools
- [ESP-IDF](https://docs.espressif.com/projects/esp-idf/) v5.x+ (for embedded targets)
- [TLA+ Toolbox](https://lamport.azurewebsites.net/tla/toolbox.html) (for model checking)

### Build Commands

```bash
# Build crypto library
cd crypto && alr build

# Build wireguard core
cd wireguard && alr build

# Run SPARK proofs
cd wireguard && alr exec -- gnatprove -P wireguard.gpr

# Build for embedded target (ESP-IDF)
cd platform && idf.py build
```

## Verification

### SPARK Proof

The core protocol logic is written in SPARK and verified for:
- Absence of runtime errors (no overflow, no range violations)
- Contract satisfaction (preconditions, postconditions, invariants)
- Information flow correctness

### TLA+ Models

Formal specifications in `verification/models/`:
- `handshake.tla` - Noise IK handshake protocol
- `replay_protection.tla` - Sliding window replay protection
- `key_derivation.tla` - Key derivation chain

## License

MIT OR Apache-2.0 WITH LLVM-exception

## References

- [WireGuard Protocol](https://www.wireguard.com/protocol/)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [SPARK User's Guide](https://docs.adacore.com/spark2014-docs/html/ug/)
