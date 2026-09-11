# IntentKernel

**Capability-oriented execution architecture** — event-scoped authority, no ambient authority.

IntentKernel is a research architecture and reference implementation by Daniel Kirk Owings.
Maturity today is **specification + prototype** (not a production Stage 5 OS, and not a
system-wide security proof).

---

## What this repository is

| Layer | Location | Role |
|-------|----------|------|
| Specs & thesis | [`docs/`](docs/) | Architecture, IKRL/IBP/UCCS, token RFC |
| Active Rust prototype | [`rust/`](rust/) | In-process `intentos-*` reference runtime |
| Legacy IKRL daemon stack | `rust/crates/{capd,intentd,...}` | Multi-process compatibility experiments |
| C reference core | [`src/reference/`](src/reference/) | Minimal capability-table harness |
| Build / run docs | [`BUILD.md`](BUILD.md), [`rust/README.md`](rust/README.md) | How to build and exercise the prototype |

The primary runnable path is the **`intentos`** single-process reference runtime under `rust/`.

---

## Quick start (Rust prototype)

```bash
cd rust
cargo build --release
cargo test --workspace
cargo run -p intentos --release -- -c "status"
cargo run -p ransomware-demo --release
cargo run -p ikrl-sim --release
```

Interactive shell:

```bash
cargo run -p intentos --release
```

See [`BUILD.md`](BUILD.md) for the daemon stack, benchmarks, and C harness notes.

---

## What the current Rust runtime demonstrates

The active `intentos-*` path is a **self-contained reference implementation**. It shows:

- submitting intents and evaluating policy in-process
- minting and verifying **development-signed** capability tokens
- registering handles and mediating runtime operations through kernel-managed checks
- gated in-memory VFS and stub AI utilities (not host-filesystem / production-model mediation)
- lease grant / renew / expire lifecycle helpers

This demonstrates the core reference flow for event-scoped capability handling **at the
runtime level**. It should **not** yet be interpreted as a production syscall-interception
boundary or a complete operating-system enforcement layer.

---

## What remains unproven

The repository does **not yet** establish:

- system-wide immunity to malware, ransomware, spyware, or botnet behavior
- a formally verified kernel or formally verified policy semantics
- a production-grade syscall or host-kernel interception boundary for `intentos-*`
- production post-quantum cryptography in the active reference runtime
  (`intentos-kernel` currently uses development-oriented Ed25519 signing, with a
  simulation path for PQC-shaped tokens)
- replacement-level compatibility with Windows, Linux, macOS, Android, or iOS

Treat security language in older thesis drafts as **design goals**, not shipping guarantees.

---

## Install / ISO / platform trees

Directories such as [`install/`](install/), [`iso-build/`](iso-build/), and
[`platform/`](platform/) contain **experimental** packaging and live-ISO work.
Each directory includes an `EXPERIMENTAL.md` (or README banner) describing status.
They are **not** the primary verification path for the Rust prototype.

Quarantined incomplete root bare-metal stubs live under
[`experimental/baremetal-root-stubs/`](experimental/baremetal-root-stubs/).
The intentional ISO/bare-metal pipeline is [`iso-build/`](iso-build/).

Prefer `rust/` + `BUILD.md` unless you are deliberately working on those trees.

### C reference harness

```bash
make test_harness
./test_harness
```

---

## License

Apache 2.0 — see [`LICENSE`](LICENSE).

Attribution: see [`AUTHORS.md`](AUTHORS.md).
