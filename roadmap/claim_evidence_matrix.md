# IntentKernel Claim–Evidence Matrix

This matrix maps every public security claim to a precise property statement,
the assumptions under which it holds, the current state, and the evidence gate
that must be satisfied before the corresponding README disclaimer is removed.

No disclaimer is removed by editing wording. It is removed by completing the
evidence gate listed here and following the process in
[verification_hardening_roadmap.md](verification_hardening_roadmap.md#program-6--disclaimer-governance).

---

## How to read this table

| Column | Meaning |
|--------|---------|
| **Claim** | The plain-language assertion being evaluated |
| **Precise property** | The narrow, assumption-qualified version that is actually provable or disprovable |
| **Assumptions** | Conditions that must hold for the property to be meaningful |
| **Current state** | What the codebase provides today |
| **Evidence gate** | What must exist before the README disclaimer can be removed |
| **Program** | Which roadmap program closes this gate |

---

## Claims table

### Claim 1 — Unauthorized file writes are structurally prevented

| | |
|---|---|
| **Claim** | The capability architecture prevents unauthorized file writes |
| **Precise property** | Under the stated assumptions, a process cannot write to a file unless it holds a currently-valid, non-expired capability token issued by the broker and explicitly scoped to `(file, write)` for that target |
| **Assumptions** | (a) Host kernel is uncompromised and boots from a verified image. (b) The enforcement backend has no unpatched bypass in the syscall hook surface. (c) The user was not deceived into approving a malicious intent. (d) No hardware side-channels are being exploited against the enforcement path. |
| **Current state** | In-process reference implementation only. The syscall gating in `intentos-kernel` is in-process and does not intercept host OS syscalls. No claim of host enforcement is valid today. |
| **Evidence gate** | (1) Production Linux eBPF/LSM enforcement backend passes adversarial bypass test suite for all hook classes listed in Program 3. (2) Independent security audit with no unresolved critical/high findings. (3) 30-day soak test with no silent enforcement failures. |
| **Program** | Program 3 |
| **Current README disclaimer** | "does not yet implement a production syscall-interception boundary" |

---

### Claim 2 — Token signing uses post-quantum cryptography

| | |
|---|---|
| **Claim** | Capability tokens are signed with post-quantum cryptography |
| **Precise property** | Token signatures use ML-DSA-87 (FIPS 204 / Dilithium) or an equivalent NIST-standardized post-quantum signature scheme, with a production key lifecycle (generate, rotate, revoke, hardware-backed storage) |
| **Assumptions** | The underlying PQC primitive is correctly implemented and has not been broken by new cryptanalysis. |
| **Current state** | `crypto.rs` uses Ed25519 (`TOKEN_SIG_V1_ED25519`) as the default. `TOKEN_SIG_V2_PQC_HYBRID` is a development convenience — Ed25519 with SHA-3 padding — not a real post-quantum scheme. Neither version uses ML-DSA. |
| **Evidence gate** | (1) A `TOKEN_SIG_V3_ML_DSA` variant backed by a FIPS 204 implementation replaces V1 and V2 as the active default. (2) Key lifecycle (generate, rotate, revoke, TPM-backed storage) is implemented and tested. (3) An independent cryptographer reviews the integration and all findings are resolved. |
| **Program** | Program 2 |
| **Current README disclaimer** | "does not currently use production post-quantum cryptography in the `intentos-*` runtime" |

---

### Claim 3 — The capability kernel is formally verified

| | |
|---|---|
| **Claim** | The kernel is formally verified |
| **Precise property** | The token issuance, revocation, and capability table core satisfies a stated confinement property: no process can access a resource without a currently-valid, non-expired capability token that was issued by this broker and scoped to that exact resource and action. This property is machine-checked by a proof assistant. |
| **Assumptions** | (a) The proof covers the specified subset of the codebase only (token core), not the full kernel, shell, or enforcement backend. (b) The hardware executes instructions correctly. (c) The boot chain is not compromised. |
| **Current state** | No formal specification or machine-checked proof exists. The repository contains a Rust reference implementation with unit and integration tests, which provide functional confidence but not formal verification. |
| **Evidence gate** | (1) A formal specification of the token core (mint, revoke, capability table) is published in the repository. (2) A machine-checked proof that the implementation refines the spec is committed. (3) The proof and spec are reviewed by an external proof engineer. |
| **Program** | Program 4 |
| **Current README disclaimer** | "does not provide a formally verified kernel" |

---

### Claim 4 — The system provides malware / ransomware / spyware immunity

| | |
|---|---|
| **Claim** | The system is immune to malware, ransomware, spyware, and botnets |
| **Precise property** | **This claim cannot be honestly closed as stated.** "Immune to malware" is not a formally stateable predicate. Malware includes phishing, social engineering, supply-chain compromise, and hardware side channels — none of which any kernel-level proof or enforcement boundary can cover. |
| **Assumptions** | N/A — no assumption set converts "immune to malware" into a provable predicate. |
| **Current state** | The architecture structurally reduces the attack surface for a specific class of attacks (unauthorized resource access without a valid token, under the assumption set in Claim 1). That is a meaningful and defensible property. Universal malware immunity is not. |
| **Evidence gate** | **This disclaimer is never removed.** Instead: when Program 3 and Program 4 are complete, the disclaimer is replaced with the precise proven property from Claim 1 and Claim 3, plus explicit statement of what remains out of scope (user deception, supply chain, hardware side channels). |
| **Program** | Programs 1, 3, 4 (partial — for the scoped property only) |
| **Current README disclaimer** | "does not prove malware, ransomware, spyware, or botnet immunity" |

---

### Claim 5 — The system replaces mainstream operating systems

| | |
|---|---|
| **Claim** | IntentKernel replaces Windows, Linux, macOS, Android, or iOS |
| **Precise property** | A user can run IntentKernel natively as their primary OS on standard hardware and perform a defined set of representative workloads without requiring a legacy OS |
| **Assumptions** | Hardware drivers, application compatibility layer, and native application ecosystem must exist at sufficient coverage for the defined workload set. |
| **Current state** | In-process reference runtime only. No bare-metal boot path, no hardware driver layer, no application compatibility layer, no native app ecosystem. |
| **Evidence gate** | All four criteria in Program 5 are met: (1) bare-metal boot on ≥ 2 hardware platforms; (2) compatibility layer covering documented workload set; (3) native app coverage for workload categories; (4) ≥ 6 months sustained field usage as primary OS with responsive support. |
| **Program** | Program 5 |
| **Current README disclaimer** | "does not replace Windows, Linux, macOS, Android, or iOS today" |

---

## Summary of current disclaimer status

| Disclaimer | Can it ever be fully removed? | Program | Status |
|---|---|---|---|
| No production syscall-interception boundary | Yes | Program 3 | Not started |
| No production post-quantum cryptography | Yes | Program 2 | Not started |
| No formally verified kernel | Partially (scoped proof of token core) | Program 4 | Not started |
| No malware/ransomware/spyware/botnet immunity | No — replace with scoped property | Programs 1, 3, 4 | In progress (claim hygiene) |
| Does not replace mainstream OSes | Yes, eventually | Program 5 | Deferred |
