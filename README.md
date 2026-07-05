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

In addition to the active `intentos-*` reference runtime, the repository also includes several experimental and historical components:

- **Legacy IKRL daemon stack in Rust**  
  Including `capd`, `intentd`, `leasebroker`, `eventscope`, and related `ikrl-*` crates. These represent an older multi-process compatibility path and remain useful design and implementation context.

- **C reference capability core** under [`src/reference/`](src/reference/)  
  A small reference implementation of capability-oriented core logic used for low-level experimentation and comparison.

- **Bare-metal kernel skeleton** under [`src/kernel/`](src/kernel/) and [`src/arch/`](src/arch/)  
  Early low-level OS and architecture work. This is experimental and is not the main runnable path in the repository today.

- **Architecture and protocol documents** under [`docs/`](docs/)  
  Specifications, design notes, and thesis-related materials describing the broader IntentKernel model and roadmap.

These components matter to the overall project, but they should not be confused with the current active Rust reference runtime centered on `intentos`, `intentos-kernel`, `intentos-shell`, and `intentos-utilities`.

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

## What this repository does **not** currently prove

To keep the documentation honest:

- it does **not** prove malware, ransomware, spyware, or botnet **immunity**
- it does **not** provide a formally verified kernel
- it does **not** yet implement a production syscall-interception boundary for the `intentos` path
- it does **not** currently use production post-quantum cryptography in the `intentos-*` runtime
- it does **not** replace Windows, Linux, macOS, Android, or iOS today

This repo is best read as a **reference implementation plus architecture proposal**, not as a finished secure OS.

---

## Three-component architecture

The active Rust reference runtime is currently organized as three in-process layers:

```text
user command / event
        |
        v
+--------------------+
| shell              |
| intentos-shell     |
| - parse commands   |
| - session state    |
| - dispatch flow    |
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

### Layer roles

- **`intentos-shell`**  
  Accepts interactive commands, maintains shell and session state, and drives requests into the runtime.

- **`intentos-kernel`**  
  Evaluates policy, mints and verifies capability tokens, tracks leases, and mediates access decisions.

- **`intentos-utilities`**  
  Provides gated services used by the runtime, currently including an in-memory VFS and a stubbed AI utility.

The `intentos` binary boots these three components together in a single process.

This is an **in-process reference model**. It is separate from the older daemon-oriented IKRL path that also remains in the workspace.

---

## Claims table: reference implementation status

The table below summarizes what the repository currently implements, demonstrates, or includes, without claiming system-wide security guarantees.

| Topic | Status in this repo | Notes |
|------|----------------------|-------|
| Event-scoped capability flow | **Implemented as a reference flow** | `intentos-kernel` evaluates intents, mints tokens, registers handles, and mediates runtime operations |
| Interactive shell workflow | **Implemented** | `intentos-shell` provides commands such as `status`, `flow`, `ls`, `cat`, `write`, `ai infer`, and `lease` |
| File access mediation demo | **Implemented in-memory** | `intentos-utilities` gates reads and writes to an in-memory VFS, not the host filesystem |
| AI capability gating | **Implemented as a stub** | The AI utility returns a local stub response after kernel authorization |
| Lease tracking | **Implemented** | Grant, renew, tick, expire, and list logic exists in `intentos-kernel` |
| Legacy multi-process IKRL stack | **Present** | `capd`, `intentd`, `leasebroker`, `eventscope`, and related crates remain in the workspace |
| Bare-metal OS path | **Partial / experimental** | Low-level C and kernel sources exist, but this is not the primary runnable implementation |
| Ransomware immunity | **Not proven** | The repository contains architecture work, demos, and prototype flows, not a universal guarantee |
| Spyware immunity | **Not proven** | No formal or system-wide proof is currently provided |
| Botnet immunity | **Not proven** | No host-wide or network-wide proof is currently provided |
| Quantum resistance in active runtime | **Not yet implemented as production PQC** | The active `intentos-*` runtime uses development-oriented signing paths rather than a finished production post-quantum deployment |

---

## Cryptography note

The current `intentos-*` runtime uses the code in [`rust/crates/intentos-kernel/src/crypto.rs`](rust/crates/intentos-kernel/src/crypto.rs), which is a development-oriented signing path built around `ed25519-dalek` and SHA-3-derived padding, including the current versioned token signature flow.

This is suitable for exercising token issuance, verification, and capability flow in the reference runtime, but it should **not** be described as a finished production post-quantum deployment.

Separate cryptography experiments also exist elsewhere in the Rust workspace, including [`rust/crates/intentkernel-crypto/`](rust/crates/intentkernel-crypto/), but those are not the active cryptographic path used by the main `intentos-*` runtime.

---

## Repository structure

The repository currently contains research, prototype, compatibility, and low-level implementation work. At a high level:

```text
.
├── README.md
├── BUILD.md
├── LICENSE
├── AUTHORS.md
├── docs/                 # Architecture, specifications, and thesis-related documents
├── governance/           # Project principles and architectural rules
├── install/              # Installation-related assets
├── mcps/                 # MCP-related tools and assets
├── platform/             # Platform-specific material
├── roadmap/              # Implementation planning and roadmap documents
├── rust/                 # Rust workspace: active runtime + legacy IKRL crates
├── scripts/              # Helper scripts
├── src/                  # C reference core and low-level kernel sources
├── thesis/               # Thesis and proposal material
└── tools/                # Additional tooling
```

### Key subtrees

```text
rust/
├── Cargo.toml
├── README.md
└── crates/
    ├── intentos/              # Entry point for the in-process reference runtime
    ├── intentos-kernel/       # Policy, tokens, capability tables, leases
    ├── intentos-shell/        # Interactive shell and command flow
    ├── intentos-utilities/    # In-memory VFS, AI stub, support utilities
    ├── capd/                  # Legacy IKRL daemon component
    ├── intentd/               # Legacy intent broker daemon
    ├── leasebroker/           # Legacy lease broker component
    ├── eventscope/            # Legacy event-scoping support
    ├── ikrl-*/                # Legacy IKRL compatibility crates
    └── ransomware-demo/       # Experimental/demo artifact

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

The main design and specification documents currently include:

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
