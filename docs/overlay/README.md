# Host overlay foundations (Stages 1–2)

**Status:** design + compile-tested scaffolds. **Not** a shipping host enforcement
product. Claims remain aligned with [`../vision.md`](../vision.md) and the root README.

| Stage | Host | Enforcement idea | In-repo today |
|-------|------|------------------|---------------|
| **1** | Windows | VBS / Micro-VM oriented broker + capability gate | `ik-overlay-stage1` interfaces + design doc |
| **2** | Linux | LSM / eBPF hooks for file / net / exec | `ik-overlay-stage2` userspace gate + LSM stub headers |

Primary IntentOS path remains `rust/` in-process (`intentos`, `ikrl-sdk`). Overlays
are how Stages 1–2 attach **event-scoped capabilities** to real host syscalls later.

```text
App ──► IKRL / IntentOS broker (mint token)
     ──► Overlay interceptor (VBS | LSM/eBPF)
           └── allow only if token scope matches + TTL/uses OK
```

See:

- [`stage1-windows-vbs.md`](stage1-windows-vbs.md)
- [`stage2-linux-lsm.md`](stage2-linux-lsm.md)
