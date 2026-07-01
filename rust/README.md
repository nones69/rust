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

## Current implementation status

The table below summarizes what the repository currently implements or includes.

| Topic | Status | Notes |
|---|---|---|
| Event-scoped capability flow | Implemented in active Rust runtime | `intentos-kernel` evaluates intent, mints and verifies tokens, registers handles, and mediates runtime operations |
| Interactive shell workflow | Implemented | `intentos-shell` provides commands such as `status`, `flow`, `ls`, `cat`, `write`, `ai infer`, and `lease` |
| File access mediation demo | Implemented in-memory | `intentos-utilities` gates reads and writes to an in-memory VFS, not the host filesystem |
| AI utility gating | Implemented as a stub | The AI utility returns a local stub response after kernel authorization |
| Lease lifecycle management | Implemented | Grant, renew, tick, expire, and list logic exists in `intentos-kernel` |
| Legacy IKRL daemon stack | Present / legacy | `capd`, `intentd`, `leasebroker`, `eventscope`, and related crates remain in the workspace |
| Bare-metal / native OS path | Experimental | C reference code and low-level kernel sources exist, but this is not the primary runnable path today |
| Host-kernel syscall interception for `intentos-*` | Not yet implemented | The active Rust runtime is an in-process reference model, not yet a production host-enforcement boundary |
| Production host filesystem mediation | Not yet implemented | Current file mediation is against the in-memory VFS only |
| Production AI provider integration | Not yet implemented | Current AI path is a stubbed utility, not a production external-model integration |

## Security and assurance status

The table below summarizes security properties and assurance levels that are **design goals or research targets**, rather than established guarantees of the current repository.

| Topic | Status | Notes |
|---|---|---|
| System-wide ransomware resistance | Not yet demonstrated | The repository includes architecture work, demos, and prototype flows, but not a system-wide proof or production validation |
| System-wide spyware resistance | Not yet demonstrated | No formal or host-wide proof is currently provided |
| System-wide botnet resistance | Not yet demonstrated | No complete network or OS-wide proof is currently provided |
| Formal verification | Not yet implemented | The repository does not currently provide a formally verified kernel or formally verified runtime model |
| Production post-quantum cryptography in active runtime | Not yet implemented | The active `intentos-*` runtime currently uses development-oriented Ed25519-based signing rather than production PQC |
| Legacy OS replacement | Not yet achieved | The repository does not currently replace Windows, Linux, macOS, Android, or iOS |

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
