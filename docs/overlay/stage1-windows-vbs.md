# Stage 1 — Windows VBS / Micro-VM overlay

## Goal

Run IntentKernel **broker + capability checks** in a Windows-trusted execution
context (VBS / VSM-aligned), with optional Micro-VM isolation for high-risk
tasks. Host apps receive **event-scoped** tokens; file/network/exec mediation
happens at an overlay boundary — not ambient process rights.

## Implemented in this repo

| Piece | Status |
|-------|--------|
| Design + threat/TCB notes | This doc |
| Rust crate `ik-overlay-stage1` | Interfaces, config structs, mock broker harness (compiles on Linux CI) |
| Real VBS enclave / HVCI driver | **Not present** — requires Windows build + signing |
| Full Micro-VM launcher (e.g. WHP/Firecracker-class) | **Planned** — trait stubs only |

## Planned architecture

1. **Broker service** (user mode, ideally VBS-isolated): verifies user intent, mints tokens.
2. **Enforcement agent**: Filter Manager / ETW / future minifilter — presents token to broker.
3. **Micro-VM path** (optional): spawn short-lived VM for untrusted workloads; pass only scoped caps.

## Honest limits

- Linux CI only type-checks the Windows-facing APIs (cfg stubs).
- No claim of ransomware immunity or “kernel under same laws” here.
- Effective TCB **includes Windows** (Stage 1 includes the host OS).

## Build

```bash
cd rust
cargo test -p ik-overlay-stage1
```
