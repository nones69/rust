# IntentKernel Build Instructions

This repository now contains two buildable implementations:

1.  **Rust Reference Implementation** (`rust/`) — the primary, actively maintained
    implementation of the IntentKernel architecture. It compiles on Windows,
    Linux, and macOS and provides the full daemon stack, SDK, and demos.
2.  **C Reference Core** (`src/reference/`) — a minimal C version of the
    capability table logic suitable for embedded kernels. Requires a host C
    compiler on Linux/macOS.

---

## Rust Implementation

### Prerequisites

- [Rust](https://rustup.rs/) 1.80 or newer
- `cargo` (installed automatically with Rust)

### Build Everything

```bash
cd rust
cargo build --release
```

Binaries are written to `rust/target/release/`.

### Run Tests

```bash
cd rust
cargo test
```

### Run the In-Process Simulator

```bash
cd rust
cargo run -p ikrl-sim
```

This exercises the full capability flow: intent → policy → token issuance →
kernel handle → single-use enforcement.

### Run the Ransomware Immunity Demo

```bash
cd rust
cargo run -p ransomware-demo
```

The demo shows:
- A ransomware-like process is blocked from writing files with no capability.
- A legitimate user action issues a single-use write token.
- The token is burned after one use and cannot be replayed.
- Result: **0 bytes encrypted** by unauthorized code.

### Run the Daemon Stack

The easiest way to start the stack is with `ikrl-init`:

```bash
./target/release/ikrl-init --bin-dir ./target/release
```

Then, in another terminal, exercise the full flow:

```bash
./target/release/ikrl-cli full-flow --resource file --action read --actor myapp
```

For manual or development setups, start the four core daemons directly:

```bash
# Terminal 1 — Capability Engine
./target/release/capd --listen tcp://127.0.0.1:9101

# Terminal 2 — Intent Broker
./target/release/intentd --listen tcp://127.0.0.1:9100 --capd-addr tcp://127.0.0.1:9101

# Terminal 3 — Lease Watchdog
./target/release/leasebroker --listen tcp://127.0.0.1:9102

# Terminal 4 — Runtime Wrapper (simulation mode on non-Linux)
./target/release/eventscope --listen tcp://127.0.0.1:9103 --capd-addr tcp://127.0.0.1:9101
```

### Benchmark Harness

A benchmark harness (`ikrl-bench`) measures token issuance, verification,
registration, and core capability-table throughput:

```bash
# Against a running stack started with ikrl-init
cargo run -p ikrl-bench --release -- --iterations 1000 --concurrency 50

# Self-contained: spawn capd and intentd internally
cargo run -p ikrl-bench --release -- --spawn-daemons --iterations 100
```

Output reports mean, p50, p95, p99, min, and max latency in nanoseconds for
`capd IssueToken`, `intentd SubmitIntent`, `capd VerifyToken`, and core table
operations.

### IP-Discrambler (Python tooling)

The `tools/ip-discrambler/` directory contains a Python package for IP
enrichment and threat intelligence. Install and run:

```bash
cd tools/ip-discrambler
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
cp .env.example .env
ipdis lookup 8.8.8.8
ipdis subnet 192.168.1.0/24 --expand
```

IP-Discrambler results can feed into IntentKernel policy decisions (e.g.,
deny network capabilities to high-threat IPs).

### SDK

The nine primitive APIs are provided by the `ikrl-sdk` crate. See
`rust/crates/ikrl-sdk/src/lib.rs` for usage.

### Cross-platform notes

- Daemons accept `tcp://` everywhere and `unix://` on Linux/macOS through
  `ikrl-transport`.
- `pipe://` is parsed on Windows but currently fails fast with an explicit
  "not yet implemented" error; use `tcp://127.0.0.1:PORT` on Windows today.
- `eventscope` is implemented as a TCP-based runtime wrapper on all hosts.
- Linux additionally contains an (experimental) `ptrace` interception module
  behind `#[cfg(target_os = "linux")]` in `ikrl-linux`.
- The daemon stack (capd → intentd → leasebroker → eventscope) is therefore
  runnable on Windows, Linux, and macOS in simulation/wrapper mode.
- **Windows cleanup:** `ikrl-init` now creates a Windows Job Object with
  `KILL_ON_JOB_CLOSE` when possible. When it works, terminating `ikrl-init.exe`
  automatically terminates `capd`, `intentd`, `leasebroker`, and `eventscope`.
  If job-object creation fails (e.g., ikrl-init was already inside another job
  object), clean up manually with:
  ```cmd
  taskkill //F //IM capd.exe //IM intentd.exe //IM leasebroker.exe //IM eventscope.exe
  ```
- Newer daemons (`ikrl-ai`, `ikrl-fs`, `ikrl-federation`) provide AI, file-
  system, and cross-device capability mediation. They are documented in
  `rust/README.md`.

---

## C Reference Core


### Build the Test Harness

On Linux or macOS with `gcc` and `make`:

```bash
make test_harness
./test_harness
```

This builds `capability_core_modified.c`, the new `secure_random.c`
portable entropy helper, and the test harness.

### What's Different from the Original

- The original `test_harness.c` implemented `getrandom()` with `rand()`.
  That has been replaced by `secure_random.c`, which uses:
  - Linux: `getrandom(2)`
  - Windows: `BCryptGenRandom`
  - Other POSIX: `/dev/urandom`
- `capability_core.h` no longer declares `getrandom()` as an external
  dependency. The C core now calls `secure_random()`.

### Kernel Build

The bare-metal x86_64 kernel skeleton still requires a cross compiler
(`x86_64-elf-gcc`) and `nasm`, which are not included in the reference
environment. To build it:

```bash
make kernel
```

To run it in QEMU:

```bash
make run
```

---

## Project Structure

```
src/reference/capability_core.c          # Original C reference core
src/reference/capability_core_modified.c # Host-testable C core
src/reference/capability_core.h          # Capability definitions
src/reference/secure_random.h            # Secure RNG interface
src/reference/secure_random.c            # Host secure RNG implementation
src/test_harness.c                       # C capability system demo
rust/crates/intentkernel-core/           # Core Rust crate (tokens, table)
rust/crates/intentkernel-crypto/         # PQC crypto primitives
rust/crates/capd/                        # Capability engine daemon
rust/crates/intentd/                     # Intent broker daemon
rust/crates/leasebroker/                 # Lease watchdog daemon
rust/crates/eventscope/                  # Runtime wrapper / syscall shim
rust/crates/ikrl-sdk/                    # Nine-primitive SDK
rust/crates/ikrl-sim/                    # In-process simulator
rust/crates/ransomware-demo/             # Ransomware immunity demo
rust/crates/ikrl-transport/              # Cross-platform IPC
rust/crates/ikrl-cli/                    # Command-line interface
rust/crates/ikrl-init/                   # Init / orchestrator
rust/crates/ikrl-linux/                  # Linux ptrace supervisor
rust/crates/ikrl-windows/                # Windows service registration stub
rust/crates/ikrl-ai/                     # AI capability gateway
rust/crates/ikrl-fs/                     # Filesystem capability mediator
rust/crates/ikrl-bench/                    # Benchmark harness
rust/crates/ikrl-federation/             # Cross-device federation
tools/ip-discrambler/                    # Python IP enrichment tooling
```

## Notes

- The Rust implementation uses algorithm-compatible **mocks** for ML-DSA-87
  and ML-KEM-1024 so that token issuance/validation/registration can be
  exercised without requiring the `liboqs` native dependency. A production
  build must link against a certified NIST FIPS 204/203 library.
- The C core is intentionally minimal and omits threading, CBOR, and
  networking to stay within the auditable TCB budget.
