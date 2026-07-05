# IntentKernel Verification and Hardening Roadmap

This document is the authoritative engineering plan for moving IntentKernel's
public security claims from aspirational to verified. Every disclaimer in the
README stays in place until the corresponding evidence gate listed here is
satisfied. No disclaimer is removed by editing wording — only by completing
the work.

The six programs below are ordered by tractability: the fastest to close
honestly comes first.

---

## Program 1 — Baseline Claim Hygiene

**Status:** In progress (this document is the first output)

**Goal:** Every public claim maps to a precisely stated, assumption-qualified
property that a reasonable security engineer would recognize as provable or
disprovable, not a marketing assertion.

### Required actions

- Replace absolute language ("immune", "eliminated", "guaranteed") in all
  public-facing documents with the narrowest accurate formulation, plus an
  explicit list of the assumptions under which the property holds.
- Create and maintain the [claim–evidence matrix](claim_evidence_matrix.md)
  so the gap between current state and each evidence gate is visible at a
  glance.
- Do not remove any existing disclaimer until the corresponding evidence gate
  in that matrix is satisfied (see Program 6).

### What this does and does not accomplish

This program makes the documentation accurate, not stronger. It does not add
any new security properties. Its value is that it removes false claims that
could mislead users into over-trusting the system, and it establishes the
governed boundary within which the engineering programs below operate.

### Exit criterion

Every claim in README.md, docs/architecture_overview.md, and any product
sheet maps to a row in the claim–evidence matrix with a stated property,
explicit assumptions, and a concrete evidence gate.

---

## Program 2 — Production Post-Quantum Cryptography

**Status:** Not started (current runtime uses Ed25519 dev path)

**Goal:** The active `intentos-*` token signing and key-exchange path uses
NIST-standardized post-quantum primitives with production key lifecycle
management, reviewed by an independent cryptographer.

### Current state

`intentos-kernel/src/crypto.rs` provides two version bytes:

- `TOKEN_SIG_V1_ED25519` (default): Ed25519 with SHA-3 padding into ML-DSA-
  sized slots. This is a development convenience, not post-quantum.
- `TOKEN_SIG_V2_PQC_HYBRID`: Ed25519 + public-key-bound SHA-3 padding. This
  is also a development convenience. The name is misleading — it is not a
  hybrid post-quantum scheme. It does not include any ML-DSA or ML-KEM
  operation.

The `SigningBackend` trait defined in `crypto.rs` provides the migration
interface: a real ML-DSA implementation can be plugged in without touching
token or kernel logic.

### Migration path

1. Integrate ML-DSA-87 (Dilithium, FIPS 204) for token signatures.
   - Preferred implementation: `pqcrypto-dilithium` crate (NIST reference
     implementation bindings) or liboqs via `oqs` crate.
   - The `SigningBackend` trait must be satisfied by the new implementation
     before the Ed25519 path is retired.
2. Key lifecycle: define and implement generate → rotate → revoke for broker
   keys, with TPM-backed storage as the production target.
3. Key exchange: identify every code path where keys are transmitted or
   agreed; replace with ML-KEM (Kyber, FIPS 203) or a hybrid.
4. Independent cryptographic review of the integrated implementation before
   production use.

### Exit criterion

- `TOKEN_SIG_V1_ED25519` and `TOKEN_SIG_V2_PQC_HYBRID` are deprecated in
  the active runtime and replaced by a `TOKEN_SIG_V3_ML_DSA` variant
  backed by a FIPS 204 implementation.
- A cryptographer who did not write the integration code has reviewed it and
  found no issues, or all found issues are resolved and documented.
- Key lifecycle (generate, rotate, revoke, TPM storage) is implemented and
  tested, not just algorithm-swapped.
- The "does not currently use production post-quantum cryptography" disclaimer
  is removed only when all of the above are true.

---

## Program 3 — Production Syscall-Interception Boundary (Linux)

**Status:** Not started (current runtime is in-process with no OS-level
enforcement)

**Goal:** A real enforcement backend on Linux that gates file and network
syscalls via eBPF/LSM, survives adversarial bypass attempts, and has been
through an independent security audit.

### Scope

Linux first, for the following reasons: the eBPF/LSM hook surface is the
most mature and well-documented of any major OS for this class of work;
the bypass literature (TOCTOU, FD-passing, `/proc/self/fd`, `execveat`) is
well-catalogued; and a Linux implementation provides the most credible
foundation for later Android and embedded work.

### Required hook surface

Minimum viable enforcement requires correct handling of all of the following:

| Hook | Purpose |
|------|---------|
| `security_file_open` / LSM `file_open` | Gate file open by capability token |
| `bprm_check_security` | Gate process execution |
| `security_socket_connect` | Gate outbound network connections |
| `security_inode_rename` | Prevent token-bypass via rename-over-target |
| FD lifecycle across `dup`/`dup2`/`dup3` | Shadow-FD must follow the FD |
| FD passing over Unix domain sockets | Receiving process inherits no capability |
| `/proc/self/fd` access | Does not bypass enforcement |
| `mmap` with `PROT_WRITE` on a file FD | Covered by open token, not a separate path |

### Exit criterion

- All hooks above are implemented and covered by a test for each bypass class.
- A fuzzing campaign (e.g., `syzkaller` against the enforcement path) runs
  for ≥ 72 hours with no unpatched bypass found.
- An independent security audit is completed and all critical/high findings
  are resolved.
- Sustained soak testing on a representative workload for ≥ 30 days with no
  silent enforcement failure.
- The "does not yet implement a production syscall-interception boundary"
  disclaimer is removed only when all of the above are true.

---

## Program 4 — Scoped Formal Verification

**Status:** Not started

**Goal:** A machine-checked proof that the token issuance, revocation, and
capability table core satisfies a stated confinement property, under a
precisely stated set of assumptions, reviewed by a proof engineer external
to the project.

### What can and cannot be proven

Formal verification proves that an *implementation* satisfies a *precisely
stated specification*, under *stated assumptions*. It does not prove
"immunity to malware" — which is not a formally stateable predicate — because
it cannot cover user deception, supply-chain compromise, hardware side
channels, or anything outside the model boundary.

The honest provable property target is something like:

> Given a correctly-booted trust anchor and an implementation that refines
> this specification, no process can access a resource without a currently
> valid, non-expired capability token that was issued by this broker and
> explicitly scoped to that resource and action.

That is a meaningful, checkable statement. It is what seL4 proved for its
access-control model. It is achievable for the IntentKernel token core.

### Scope (smallest high-value target)

Start with only:
- Token issuance (`TokenBroker::mint`): given a policy-allowed intent,
  produces a token with the correct scope, TTL, and issuer binding.
- Token revocation (`RevocationList`): once a JTI is revoked, no syscall
  using a handle bound to that JTI is allowed.
- Capability table (`CapabilityTable`): a handle grants access to exactly the
  resource and action in its bound token, no more.

Do not attempt to formally verify the full kernel, the shell, or the
enforcement backend in the first pass.

### Recommended toolchain

Rust code → [Verus](https://github.com/verus-lang/verus) or
[Creusot](https://github.com/creusot-rs/creusot) for Rust-native proofs, or
extract a formal model in Isabelle/HOL (the seL4 precedent) if a dedicated
proof engineer with Isabelle experience is available.

### Exit criterion

- A formal specification of the three-component core (mint, revoke, table)
  is written and published in the repository.
- A machine-checked proof that the implementation refines the spec is
  produced and committed.
- The proof and spec are reviewed by a proof engineer external to the project.
- The "does not provide a formally verified kernel" disclaimer is narrowed to
  reflect what is and is not covered by the proof (the full kernel is a
  multi-year program; the token core proof is the first milestone).

---

## Program 5 — Long-Horizon Platform Claim

**Status:** Deferred (no shortcut exists)

**Goal:** Define objective, public criteria that must all be satisfied before
the "does not replace Windows, Linux, macOS, Android, or iOS today" disclaimer
is removed.

### Required criteria (all must be met)

1. Bare-metal boot on ≥ 2 distinct, publicly available hardware platforms,
   with reproducible build instructions.
2. A compatibility layer covering the software required for a defined set of
   representative workloads (document the workload list before claiming
   coverage).
3. A native application ecosystem with ≥ N first-party applications covering
   the categories in the workload list (N to be defined when workloads are
   defined).
4. Sustained field usage by real end-users as their primary OS for ≥ 6 months
   with a documented, responsive issue resolution process.

### Notes

Nothing shortens this program. The criteria above are conservative relative
to what would be required for broad market adoption; they are the minimum
that would justify removing the disclaimer without misleading users.

---

## Program 6 — Disclaimer Governance

**Status:** Active (this document instantiates the process)

**Goal:** A clear, public, auditable process for removing disclaimers, so
that changes to the README's "what this does not prove" section require
evidence, not editorial decision.

### Process

1. Each disclaimer in the README maps to a row in
   [claim_evidence_matrix.md](claim_evidence_matrix.md).
2. A disclaimer may only be removed (or narrowed) via a pull request that
   includes, in its description, a reference to the completed evidence gate
   for that row — a link to an audit report, a proof artifact, a published
   test result, or an equivalent external artifact.
3. For formal-verification and security-audit claims, the PR must include a
   review or acknowledgment from the external reviewer cited in the evidence
   gate.
4. The PR is not merged by the author of the evidence; it requires a second
   approval from a maintainer who was not the primary engineer for that
   program.

### Non-negotiable rule

A disclaimer is never removed by rewording it to be less alarming. It is
removed by completing the work the disclaimer described as missing. If the
work cannot be completed, the disclaimer stays, and the README says what is
actually true.
