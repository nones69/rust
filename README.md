# IntentKernel

**IntentKernel is a research repository for an event-scoped capability architecture.**

It contains design documents, a Rust reference implementation, a legacy IKRL compatibility stack, and a small C reference core. The most direct implementation path in the repo today is the in-process Rust runtime built around **three major components**: **utilities**, **shell**, and **kernel**.

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Reference_Implementation-green.svg)](#)
[![Version](https://img.shields.io/badge/Version-1.1.0-orange.svg)](#)

---

## Current implementation status

The repo does **not** currently ship a production-ready operating system or a proven security boundary. What it does provide is a set of reference implementations and experiments that exercise the IntentKernel model.

### Primary Rust reference runtime

Under [`rust/`](rust/), the main active path is the **`intentos`** binary and its three in-process crates:

| # | Component | Crate / Binary | Current role |
|---|-----------|----------------|--------------|
| **1** | Utilities | `intentos-utilities` | In-memory VFS, AI stub gateway, support utilities |
| **2** | Shell | `intentos-shell` | Interactive REPL and command dispatch |
| **3** | Kernel | `intentos-kernel` | Policy evaluation, token minting, capability table, lease tracking |
| - | Entry point | `intentos` | Boots the three components in one process |

Build and run:

```bash
cd rust
cargo run -p intentos --release
```

See [`rust/README.md`](rust/README.md) for details.

### Other code in this repository

The repository also includes:

- A **legacy IKRL daemon stack** in Rust (`capd`, `intentd`, `leasebroker`, `eventscope`, `ikrl-*` crates)
- A **C reference capability core** under [`src/reference/`](src/reference/)
- A **bare-metal kernel skeleton** under [`src/kernel/`](src/kernel/) and [`src/arch/`](src/arch/)
- Architecture and protocol documents in [`docs/`](docs/)

Those parts are useful context, but they should not be confused with the current three-component `intentos` runtime.

---

## What the current Rust runtime demonstrates

The current `intentos-*` crates provide a reference flow for:

- evaluating an intent in [`rust/crates/intentos-kernel/src/policy.rs`](rust/crates/intentos-kernel/src/policy.rs)
- minting and verifying signed capability tokens in [`rust/crates/intentos-kernel/src/token.rs`](rust/crates/intentos-kernel/src/token.rs)
- registering handles and enforcing simple gated syscalls in [`rust/crates/intentos-kernel/src/lib.rs`](rust/crates/intentos-kernel/src/lib.rs)
- exposing gated utilities such as a virtual filesystem in [`rust/crates/intentos-utilities/src/vfs.rs`](rust/crates/intentos-utilities/src/vfs.rs)
- exposing a stubbed AI utility in [`rust/crates/intentos-utilities/src/ai.rs`](rust/crates/intentos-utilities/src/ai.rs)
- driving the flow from an interactive shell in [`rust/crates/intentos-shell/src/`](rust/crates/intentos-shell/src/)

The included ground-up test at [`rust/crates/intentos/tests/ground_up.rs`](rust/crates/intentos/tests/ground_up.rs) also checks that the `intentos-*` path does not depend on the legacy IKRL daemon crates.

---

## What remains unproven

The repository does **not yet** establish:

- system-wide immunity to malware, ransomware, spyware, or botnet behavior
- a formally verified kernel or formally verified policy semantics
- a production-grade syscall or host-kernel interception boundary for the `intentos-*` runtime
- production post-quantum cryptography in the active reference runtime
- replacement-level compatibility with Windows, Linux, macOS, Android, or iOS

IntentKernel should therefore be read as a **research architecture and reference implementation**, not as a completed secure operating system.

---

## Three-component architecture

The active Rust reference runtime is organized around these three layers:

```text
user command / event
        |
        v
+--------------------+
| shell              |
| intentos-shell     |
| - parse commands   |
| - session state    |
+---------+----------+
          |
          v
+--------------------+
| kernel             |
| intentos-kernel    |
| - policy           |
| - tokens           |
| - capability table |
| - leases           |
+---------+----------+
          |
          v
+--------------------+
| utilities          |
| intentos-utilities |
| - vfs              |
| - ai gateway stub  |
| - helper tools     |
+--------------------+
```

This is an **in-process model**. It is separate from the older daemon-oriented IKRL path that remains in the workspace.

---

## Claims table: reference implementation status

The table below describes what the repository currently supports or illustrates, without claiming guaranteed protection.

| Topic | Status in this repo | Notes |
|------|----------------------|-------|
| Event-scoped capability model | **Implemented as a reference flow** | `intentos-kernel` evaluates intents, mints tokens, registers handles, and gates operations |
| Interactive shell workflow | **Implemented** | `intentos-shell` provides `status`, `flow`, `ls`, `cat`, `write`, `ai infer`, and lease commands |
| File access mediation demo | **Implemented in-memory** | `intentos-utilities` gates reads/writes to an in-memory VFS, not the host filesystem |
| AI capability gating | **Implemented as a stub** | `AiGateway` returns a local stub response after kernel authorization |
| Lease tracking | **Implemented** | Lease grant, renew, tick, and list logic exists in `intentos-kernel` |
| Legacy multi-process stack | **Present** | `capd`, `intentd`, `leasebroker`, `eventscope`, and related crates remain in the workspace |
| Bare-metal OS | **Partial / experimental** | C and low-level kernel sources exist, but this is not the main runnable path |
| Ransomware immunity | **Not proven** | The repo includes demos and architectural goals, not a universal guarantee |
| Spyware immunity | **Not proven** | No formal or system-wide proof is provided |
| Quantum resistance | **Not yet in `intentos-*` runtime** | Current `intentos-kernel` code uses Ed25519-based development signing, not production PQC |

---

## Cryptography note

The current `intentos-*` runtime uses the code in [`rust/crates/intentos-kernel/src/crypto.rs`](rust/crates/intentos-kernel/src/crypto.rs), which is a **development-oriented signing path** built around `ed25519-dalek` and SHA-3. It is useful for exercising token flow, but it should not be described as a finished post-quantum deployment.

Separate crypto experiments also exist in the legacy Rust workspace, including [`rust/crates/intentkernel-crypto/`](rust/crates/intentkernel-crypto/).

---

## Repository structure

This is the top-level layout as it exists today:

```text
.
├── README.md
├── BUILD.md
├── LICENSE
├── AUTHORS.md
├── docs/                 # Architecture and protocol documents
├── governance/           # Project principles
├── install/              # Install-related assets
├── mcps/                 # MCP tool definitions and related assets
├── platform/             # Platform-specific material
├── roadmap/              # Implementation planning
├── rust/                 # Rust workspace: intentos + IKRL crates
├── scripts/              # Helper scripts
├── src/                  # C reference core and low-level kernel sources
├── thesis/               # Thesis-related material
└── tools/                # Additional tooling
```

Key subtrees:

```text
rust/
├── Cargo.toml
├── README.md
└── crates/
    ├── intentos/
    ├── intentos-kernel/
    ├── intentos-shell/
    ├── intentos-utilities/
    ├── capd/
    ├── intentd/
    ├── leasebroker/
    ├── eventscope/
    ├── ikrl-*/
    └── ransomware-demo/

src/
├── reference/
│   ├── capability_core.c
│   ├── capability_core_modified.c
│   ├── capability_core.h
│   ├── secure_random.c
│   └── secure_random.h
├── test_harness.c
├── arch/
└── kernel/
```

---

## Documents and references

- Architecture overview: [`docs/architecture_overview.md`](docs/architecture_overview.md)
- IntentKernel thesis: [`docs/intentkernel_thesis.md`](docs/intentkernel_thesis.md)
- UCCS specification: [`docs/uccs_spec.md`](docs/uccs_spec.md)
- IKRL specification: [`docs/ikrl_spec.md`](docs/ikrl_spec.md)
- Intent Broker Protocol: [`docs/ibp_spec.md`](docs/ibp_spec.md)
- Token RFC: [`docs/token_rfc.md`](docs/token_rfc.md)
- Thesis proposal: [`docs/thesis_proposal.md`](docs/thesis_proposal.md)
- Build instructions: [`BUILD.md`](BUILD.md)

---

## License

This repository is released under the [Apache License 2.0](LICENSE).
