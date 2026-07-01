# Bare-metal kernel — current boot status

This file tracks what the bare-metal C kernel under `src/` actually boots on, updated
when the status changes. "Boots" means the kernel reaches a known-good entry point and
prints a boot banner or equivalent observable signal.

| Architecture | Toolchain | Status | Notes |
|---|---|---|---|
| x86_64 (QEMU) | GCC / MinGW | **Boots to console** | Protected-mode init, GDT/IDT, PIC, basic console I/O |
| x86_64 (bare hardware) | GCC | **Untested** | Not validated on real hardware |
| AArch64 | — | **Not started** | No AArch64 port exists |
| RISC-V | — | **Not started** | No RISC-V port exists |

## What "partial / experimental" means

- The kernel initialises the CPU into protected mode, sets up a GDT, IDT, and PIC, and
  provides basic console I/O (`src/kernel/console/`).
- There is no scheduler, no user-space, no filesystem, and no network stack.
- It is **not** the main runnable path for the IntentKernel system; the `intentos-*`
  Rust crates are the primary runtime.
- This code is retained as a low-level reference for capability-enforcement concepts that
  may eventually be implemented as an eBPF/LSM backend on a real OS.

## How to boot in QEMU

```
pwsh scripts/run-qemu.ps1
```

or from Linux/macOS:

```
make qemu
```

## Maintenance rule

Update this file whenever a change causes the boot status on any row to change.
Link the relevant commit in the Notes column so the history is checkable.
