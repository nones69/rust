# IntentOS Rust reference runtime

`rust/` contains the main Rust workspace for this repository. The most direct implementation path here is the **`intentos` reference runtime**, organized around three major components: **utilities**, **shell**, and **kernel**.

It is best described as a **single-process reference implementation** of the IntentKernel model, not as a production-ready operating system.

## Three major components

| # | Component | Crate | Current responsibility |
|---|-----------|-------|------------------------|
| **1** | Utilities | `intentos-utilities` | In-memory VFS, AI stub gateway, support utilities |
| **2** | Shell | `intentos-shell` | Interactive REPL, session state, command dispatch |
| **3** | Kernel | `intentos-kernel` | Policy engine, token broker, capability table, leases |
| - | Entry point | `intentos` | Boots all three components in-process |

The code for this path is in:

- [`crates/intentos/`](crates/intentos/)
- [`crates/intentos-utilities/`](crates/intentos-utilities/)
- [`crates/intentos-shell/`](crates/intentos-shell/)
- [`crates/intentos-kernel/`](crates/intentos-kernel/)

## Quick start

```bash
cd rust
cargo run -p intentos --release
```

Example session:

```text
intentos> status
intentos> flow file read
intentos> cat /readme.txt
intentos> ls /
intentos> flow ai infer
intentos> ai infer hello from IntentOS
intentos> exit
```

One-shot command:

```bash
cargo run -p intentos --release -- -c "flow file read"
```

## Current behavior

The current runtime demonstrates:

- policy evaluation from shell-generated intents
- token minting and verification in the kernel
- handle registration and gated operations
- an in-memory virtual filesystem
- a stubbed AI utility gated by kernel approval
- lease creation and reporting

What remains unproven in this reference runtime:

- the VFS is **in-memory**, not a host filesystem mediator
- the AI path is a **stub**, not a full external model runtime
- the implementation is **in-process**, not a hardened isolation boundary
- the runtime does **not** establish system-wide immunity to malware, ransomware, spyware, or botnet behavior
- the runtime does **not** establish production post-quantum cryptography or a production host-interception boundary

## Architecture

```text
+------------------------------+
| intentos                     |
| single binary                |
+---------------+--------------+
                |
    +-----------+-----------+
    |                       |
    v                       v
+-----------+         +-----------+
| shell     |         | utilities |
| tier 2    |<------->| tier 1    |
+-----+-----+         +-----+-----+
      |                     |
      +----------+----------+
                 |
                 v
           +-----------+
           | kernel    |
           | tier 3    |
           +-----------+
```

In code:

- `crates/intentos/src/main.rs` boots the runtime
- `crates/intentos-shell/src/` implements the REPL and builtins
- `crates/intentos-kernel/src/` implements policy, token, table, lease, and type logic
- `crates/intentos-utilities/src/` implements VFS, AI, federation, and helper utilities

## Cryptography note

The `intentos-kernel` crate currently uses the development signing path in [`crates/intentos-kernel/src/crypto.rs`](crates/intentos-kernel/src/crypto.rs). That code uses `ed25519-dalek` with SHA-3-based padding to exercise token issuance and verification.

This should be read as **reference implementation crypto**, not as a finished post-quantum deployment.

## Dependency boundary

The test at [`crates/intentos/tests/ground_up.rs`](crates/intentos/tests/ground_up.rs) enforces that the `intentos-*` crates do not directly depend on the legacy IKRL daemon path.

Run it with:

```bash
cargo test -p intentos --test ground_up
```

## Legacy IKRL compatibility stack

This workspace also still contains the older multi-process IKRL path, including crates such as:

- `capd`
- `intentd`
- `leasebroker`
- `eventscope`
- `ikrl-cli`
- `ikrl-init`
- `ikrl-shell`
- `ikrl-fs`
- `ikrl-ai`
- `ikrl-federation`

That code remains useful for compatibility experiments and host-integration ideas, but it is **not** the same thing as the current three-component `intentos` runtime.

## Workspace structure

```text
rust/
├── Cargo.toml
├── README.md
└── crates/
    ├── intentos/
    ├── intentos-kernel/
    ├── intentos-shell/
    ├── intentos-utilities/
    ├── intentkernel-core/
    ├── intentkernel-crypto/
    ├── intentkernel-os/
    ├── capd/
    ├── intentd/
    ├── leasebroker/
    ├── eventscope/
    ├── ikrl-sdk/
    ├── ikrl-sim/
    ├── ikrl-cli/
    ├── ikrl-init/
    ├── ikrl-shell/
    ├── ikrl-fs/
    ├── ikrl-ai/
    ├── ikrl-federation/
    ├── ikrl-linux/
    ├── ikrl-windows/
    ├── ikrl-bench/
    ├── ikrl-bridge/
    └── ransomware-demo/
```

## Suggested reading

- Top-level repo overview: [`../README.md`](../README.md)
- Build instructions: [`../BUILD.md`](../BUILD.md)
- Architecture overview: [`../docs/architecture_overview.md`](../docs/architecture_overview.md)
