# IntentKernel Rust Reference Implementation

This directory contains the cross-platform, production-oriented reference
implementation of the IntentKernel architecture.

## Components

### Core crates

| Crate | Role |
|---|---|
| `intentkernel-crypto` | Post-quantum primitives: SHA3, AES-256-GCM, ML-DSA-87, ML-KEM-1024 |
| `intentkernel-core` | Capability table, token lifecycle, policy, kernel handles |
| `ikrl-transport` | Cross-platform IPC (Unix domain sockets / TCP / Windows named-pipe stub) |

### Daemons

| Binary | Crate | Role |
|---|---|---|
| `capd` | `capd` | Capability engine — mints and verifies PQC-signed tokens |
| `intentd` | `intentd` | Intent broker — correlates user intent with policy |
| `leasebroker` | `leasebroker` | Renewable process lease watchdog |
| `eventscope` | `eventscope` | Runtime wrapper / syscall interception interface |
| `ikrl-ai` | `ikrl-ai` | Capability-gated AI inference and tool-use gateway |
| `ikrl-fs` | `ikrl-fs` | Filesystem capability mediator |
| `ikrl-federation` | `ikrl-federation` | Cross-device capability discovery and exchange |

### Platform shims

| Binary | Crate | Role |
|---|---|---|
| `ikrl-linux` | `ikrl-linux` | Linux `ptrace` syscall supervisor |
| `ikrl-windows` | `ikrl-windows` | Windows service wrapper |

### Tools

| Binary | Crate | Role |
|---|---|---|
| `ikrl-init` | `ikrl-init` | Init / orchestrator — starts all core daemons |
| `ikrl-cli` | `ikrl-cli` | Command-line administration and integration testing |
| `ikrl-sim` | `ikrl-sim` | In-process simulator |
| `ransomware-demo` | `ransomware-demo` | Structural ransomware immunity demo |
| `ikrl-bench` | `ikrl-bench` | Benchmark harness for token and table throughput |

## Quick start

```bash
cd rust

# Build everything
cargo build --release

# Run tests
cargo test

# Start the user-space OS (adjust bin-dir as needed)
./target/release/ikrl-init --bin-dir ./target/release

# In another terminal, exercise the full flow
./target/release/ikrl-cli full-flow --resource file --action read --actor myapp

# Run the simulator
./target/release/ikrl-sim

# Run the ransomware demo
./target/release/ransomware-demo
```

## Cross-platform IPC

`ikrl-transport` abstracts the underlying socket type:

- `tcp://127.0.0.1:9100` works on every platform.
- `unix:///run/intentd.sock` works on Linux and macOS.
- `pipe://IntentKernel` is the Windows named-pipe form (stub; use `tcp://` for now).

All transports carry length-prefixed JSON so every daemon speaks the same
protocol regardless of socket type.

## AI OS integration

`ikrl-ai` treats every LLM inference and tool invocation as a capability-
gated operation. Applications must present an event-scoped token to call a
model or use a tool. This makes AI agents structurally unable to exfiltrate
data or call unapproved tools without explicit user intent.

## Security notes

- The Rust implementation uses algorithm-compatible **mocks** for ML-DSA-87
  and ML-KEM-1024 so the system can be developed and tested without the
  `liboqs` native dependency. To use a real PQC backend, build with the
  `oqs` feature:
  ```bash
  cargo build --release -p intentkernel-crypto --features oqs
  ```
  Production builds must link against certified NIST FIPS 204/203 libraries.
- `ikrl-linux` provides a `ptrace`-based proof-of-concept supervisor. A
  production Linux deployment should use `seccomp` user-notification
  (Linux 5.0+) for lower overhead; a scaffold module is included.
- On Windows, `ikrl-init` creates a Job Object with `KILL_ON_JOB_CLOSE`
  when possible so that terminating `ikrl-init.exe` also terminates child
  daemons.
