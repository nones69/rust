# IntentKernel

**Capability-oriented execution architecture** — event-scoped authority, no ambient authority.

IntentKernel is a research architecture and reference implementation by **Daniel Kirk Owings** (2025).
Maturity today is **specification + prototype**: a serious design thesis with a working Rust
reference runtime — **not** a production Stage‑5 OS, and **not** a system-wide security proof.

For the north-star pitch (design goals, clearly labeled), see
[`docs/vision.md`](docs/vision.md). Older thesis drafts under `docs/` may still contain
overclaims; treat those as historical drafts superseded by this README and the vision doc.

---

## What this repository is

| Layer | Location | Role |
|-------|----------|------|
| Specs & thesis drafts | [`docs/`](docs/) | Architecture notes (IKRL / IBP / UCCS), vision, token RFC |
| Active Rust prototype | [`rust/`](rust/) | In-process `intentos-*` reference runtime + related crates |
| Legacy IKRL daemon stack | `rust/crates/{capd,intentd,...}` | Multi-process compatibility experiments |
| C reference core | [`src/reference/`](src/reference/) | Minimal capability-table harness |
| Build / run docs | [`BUILD.md`](BUILD.md), [`rust/README.md`](rust/README.md) | How to build and exercise the prototype |
| Stage 1/2 overlay foundations | [`docs/overlay/`](docs/overlay/) | VBS / LSM scaffolds — not host-wide enforcement |

The primary runnable path is the **`intentos`** single-process reference runtime under `rust/`.

---

## Quick start (Rust prototype)

```bash
cd rust
cargo build --release
cargo test -p intentos-kernel -p intentos --lib
cargo run -p intentos --release -- -c "status"
cargo run -p ransomware-demo --release   # in-process demo only
cargo run -p ikrl-sim --release
```

Interactive shell:

```bash
cargo run -p intentos --release
```

See [`BUILD.md`](BUILD.md) for the daemon stack, benchmarks, and C harness notes.
Repository keep/quarantine map: [`docs/REPO_LAYOUT.md`](docs/REPO_LAYOUT.md).
One-shot verify: `bash scripts/verify-prototype.sh`.
CI workflows exercise `cargo fmt` / `clippy -D warnings` / tests on the pinned nightly
toolchain (`rust-toolchain.toml`).

---

## What the current Rust runtime demonstrates

The active `intentos-*` path is a **self-contained reference implementation**. It shows:

- submitting intents and evaluating policy in-process (including default-deny for unknown intents)
- minting and verifying **development-signed** capability tokens (Ed25519; optional PQC-shaped simulation)
- registering handles and mediating runtime operations through kernel-managed checks
- gated **in-memory** VFS and stub AI utilities (not host-filesystem / production-model mediation)
- lease grant / renew / expire lifecycle helpers
- prototype modules for scheduling, modular policy evaluation (IKPE), mTLS IPC transport helpers,
  and a federation mesh **foundation** (handshake / policy-hash / task-delegation stubs)

This demonstrates the core reference flow for event-scoped capability handling **at the
runtime level**. It should **not** yet be interpreted as a production syscall-interception
boundary or a complete operating-system enforcement layer.

Remote / IPC prototypes (`ikrl-transport`, `ikrl-remote`, `intentkernel-server`) exercise
length-prefixed JSON RPC and optional mTLS with **lab-grade DevPki** fixtures. See
[`docs/dev-mtls-pki.md`](docs/dev-mtls-pki.md) — not a production PKI claim.

---

## Design goals vs current maturity

| Topic | Design goal (vision) | Current maturity |
|-------|----------------------|------------------|
| Zero default authority | Processes start with no ambient rights | Modeled in-process via tokens + policy; host OS still ambient |
| Event-scoped grants | Authority bound to a concrete intent | Prototype mint / verify / table mediation |
| Hard TTL / burn | Capabilities expire and exhaust | Token TTL / uses + lease helpers |
| Four-layer stack (IK / UCCS / IKRL / IBPS) | Incremental deployment path | Specs in `docs/`; IKRL daemons legacy; IBPS/UCCS not shipping products |
| Stage 1–4 host overlays | Governed apps on existing OSes | Prototype + experimental packaging trees |
| Stage 5 native substrate | Minimal TCB; kernel under same laws | **Goal only** — not present |
| Post-quantum crypto | PQC-first network / tokens | Design stance; runtime uses Ed25519 + PQC **simulation** path |
| Formal verification | Auditable small TCB | **Not claimed** — no verified kernel in this repo |

Full narrative: [`docs/vision.md`](docs/vision.md).

---

## What remains unproven

The repository does **not** establish:

- system-wide immunity to malware, ransomware, spyware, botnet, or IMSI-catcher class threats
- that “perfect ACE ⇒ no malicious action is possible” as a present theorem of this codebase
- a formally verified kernel, formally verified policy semantics, or seL4-style proof artifacts
- a production-grade syscall / host-kernel interception boundary for `intentos-*`
- production post-quantum cryptography in the active reference runtime
- replacement-level compatibility with Windows, Linux, macOS, Android, or iOS
- that Stages 1–4 exclude the host OS from the effective TCB (they **include** the host)

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

See also [`src/README.md`](src/README.md) (reference harness vs experimental bare-metal stubs).

### C reference harness

```bash
make test_harness
./test_harness
```

---

## License

Apache 2.0 — see [`LICENSE`](LICENSE).

Attribution: see [`AUTHORS.md`](AUTHORS.md). Citation: Daniel Kirk Owings, 2025.
