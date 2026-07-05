# IntentKernel Implementation Plan

> **Note:** This plan has been superseded by the
> [Verification and Hardening Roadmap](verification_hardening_roadmap.md),
> which replaces overconfident claim language with precise, evidence-gated
> milestones. The phases below are retained for historical reference but the
> hardening roadmap is the authoritative planning document going forward.

---

## Phase 1: Enforcement Proof of Concept (Months 1-3)

### Objective
Demonstrate that event-scoped capability tokens structurally prevent
unauthorized file writes under controlled conditions on a standard Linux
system, within a precisely stated set of assumptions.

### Stated assumptions (required for any security claim)
- The host kernel is uncompromised and boots from a verified image.
- The user is not deceived into explicitly approving a malicious intent.
- No hardware side-channels (Spectre/Meltdown-class) are being exploited.
- The enforcement boundary is not bypassed via FD-passing, TOCTOU races, or
  `/proc/self/fd` tricks (hardening of these is tracked in Phase 2).

### Deliverables
- **intentd** reference implementation for Linux (userspace, no SGX required
  for Phase 1)
- **eventscope** interception shim for eBPF/LSM `file_open` and
  `bprm_check_security` hooks
- **capd** token issuer using ML-DSA-87 (via liboqs FIPS 204) — replaces the
  current Ed25519 dev path
- Controlled lab demonstration: a ransomware-like test binary running inside
  IKRL fails to write files it was not granted a capability token for, with
  a clear record of every denied syscall in the audit log

### Technical Milestones
| Week | Milestone |
|------|-----------|
| 1 | CBOR encoding/decoding library (TinyCBOR integration) |
| 2 | Production PQC integration: liboqs ML-DSA-87 signing/verification replaces Ed25519 dev path; key lifecycle (generate, rotate, revoke) defined |
| 3 | capd prototype — issues tokens using RFC-INTENT-001 format |
| 4 | eventscope shim — intercepts `file_open`/`bprm_check_security` via eBPF/LSM, presents tokens to kernel |
| 5 | Controlled enforcement demo under stated assumptions; audit log shows denials |
| 6 | Documentation, test suite, adversarial bypass review |

### Exit criterion
A security engineer who did not write the code reviews the enforcement path
and confirms there are no known bypass classes within the stated assumption
set.

## Phase 2: Production Syscall Boundary (Months 4-9)

### Objective
Harden the Linux enforcement backend against adversarial bypass attempts and
establish it as a production-quality interception boundary.

### Deliverables
- **Linux:** Full LSM + eBPF hook coverage: `file_open`, `bprm_check_security`,
  `socket_connect`, shadow-FD lifecycle across `read`/`write`/`dup`/`mmap`
- Adversarial fuzzing of the interception boundary (TOCTOU, symlink races,
  FD passing over Unix sockets, `/proc/self/fd` tricks, `execveat` variants)
- Independent security audit of the enforcement path by a party who did not
  write it
- **Windows:** VBS-based broker service with Hyper-V micro-VM isolation
  (separate track, same audit requirement)
- **Android:** Privileged system service via Device Owner enrollment
- IKRL management console for enterprise fleet administration

### Exit criterion
Fuzzing campaign finds no unpatched bypass; independent audit report is
published; sustained soak testing on real workloads for ≥ 30 days with no
silent enforcement failures.

## Phase 3: SDK and Ecosystem (Months 10-18)

### Objective
Enable third-party development of native IntentKernel applications and
establish the scoped formal verification program.

### Deliverables
- Full SDK release (Rust, C, Python bindings)
- Developer documentation and tutorials
- App manifest specification
- IKRL simulator for testing capability flows
- Mobile SDK for Android integration
- Native kernel alpha release
- Scoped formal verification: machine-checked proof of capability confinement
  for the token issuance + revocation + capability table core (see
  [verification_hardening_roadmap.md](verification_hardening_roadmap.md))

## Phase 4: Native Hardware (Year 2+)

### Objective
Transition from compatibility layer to bare-metal execution, once the
ecosystem and formal verification programs have matured sufficiently.

### Deliverables
- IntentKernel microkernel for ARM and RISC-V
- SoC reference design with hardware capability enforcement
- Embedded firmware SDK (ESP32, STM32, Raspberry Pi)
- Vehicle/industrial controller firmware
- Cloud hypervisor replacement

### Hardware Partnership Targets
- RISC-V vendors (SiFive, StarFive) for capability-aware silicon
- CHERI-enabled processors for hardware-enforced memory safety
- TPM/HSM vendors for hardware-backed broker key storage

### Exit criterion for "replaces mainstream OS" claim
This milestone is only announced when all of the following are true:
bare-metal boot on ≥ 2 distinct hardware platforms, a compatibility layer
covering the software needed for a defined set of representative workloads,
and sustained field usage by real end-users as their primary OS for ≥ 6
months with documented issue resolution process.

## Success Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| Unauthorized file writes blocked (in-scope, stated assumptions) | 100% (structural) | Scoped to assumption set in Phase 1 |
| Token validation latency | <1ms | Measured on reference hardware |
| Background lease overhead | <2% CPU | Measured under representative workload |
| TCB size | <25,000 LOC | Applies to the formally verified core |
| Cold boot time (native) | <2 seconds | Native kernel target, Phase 4 |
| PQC migration complete | ✓ | ML-DSA-87 via liboqs in production token path |
| Formal proof coverage | ✓ | Token issuance + revocation + capability table |
