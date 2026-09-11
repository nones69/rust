# Stage 2 — Linux LSM / eBPF overlay

## Goal

Token-gated interception of **file open**, **network connect**, and **exec**
using LSM hooks and/or eBPF programs. Userspace IntentOS / broker mints
capabilities; the overlay denies operations without a matching live token.

## Implemented in this repo

| Piece | Status |
|-------|--------|
| Design doc | This file |
| `ik-overlay-stage2` userspace `OverlayGate` | Token check against `intentos-kernel` (runs on Linux CI) |
| Hook kind enum + simulated allow/deny tests | Yes |
| C LSM stub headers under `overlay/linux/lsm_stub/` | Scaffold for future out-of-tree module |
| Loadable LSM / production eBPF programs | **Not present** |
| Existing `ikrl-linux` ptrace supervisor | Related prototype; Stage 2 aims at LSM/eBPF for lower overhead |

## Planned hook set

| Hook | Action mediated |
|------|-----------------|
| `file_open` / `file_permission` | Path read/write |
| `socket_connect` | Outbound connect |
| `bprm_check_security` | Execve |

Token presentation options (design): SCM_RIGHTS ancillary / `BPF` map keyed by
`pid+jti` / seccomp-notify handshake with IntentOS.

## Honest limits

- CI tests the **userspace gate logic**, not a loaded kernel module.
- ptrace in `ikrl-linux` is a development supervisor, not Stage-2 complete.
- Host Linux kernel remains in the TCB for Stages 1–4.

## Build

```bash
cd rust
cargo test -p ik-overlay-stage2
```
