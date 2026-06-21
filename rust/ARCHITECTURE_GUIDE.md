# Rust Crates Analysis: Quick Reference

## 📊 Executive Summary

**Workspace:** `rust/` (Windows 11, PowerShell)  
**Total Crates:** 28 (18 binaries, 15 libraries)  
**Max Dependency Depth:** 4 layers  
**Architecture:** Dual-mode (monolithic OS + distributed daemons)

---

## 🏗️ Two-System Architecture

### IntentOS: Monolithic Single Binary

**File:** `rust/crates/intentos/src/main.rs`  
**Boot Order:** Utilities (T1) → Shell (T2) → Kernel (T3)  
**Binary:** `intentos`

```
intentos (single binary)
├─ [T1-Utilities] VFS, AI gateway, platform HAL, identity/LDAP
├─ [T2-Shell] Interactive REPL, command parser, session state
└─ [T3-Kernel] Policy, tokens, capabilities, leases, intent recognition
```

**Core Crates:**
- `intentos-kernel` — Tier-3, policy + token enforcement
- `intentos-utilities` — Tier-1, VFS + AI + platform tools
- `intentos-shell` — Tier-2, interactive REPL
- `intentos-bench` — Benchmarking harness

### IKRL: Distributed Daemon System

**Boot:** `ikrl-init` spawns platform-specific services  
**Federation:** mDNS-based peer discovery (`ikrl-federation`)  
**Daemons:** intentd, capd, leasebroker, eventscope

```
ikrl-init (supervisor)
├─ [Windows] ikrl-windows (WinAPI + service integration)
├─ [Linux] ikrl-linux (libc + nix + seccomp-notify)
├─ System Daemons
│  ├─ intentd (intent dispatch)
│  ├─ capd (capability minting)
│  ├─ leasebroker (lease lifecycle)
│  └─ eventscope (event auditing)
├─ User Interfaces
│  ├─ ikrl-cli (command-line)
│  ├─ ikrl-shell (interactive REPL)
│  └─ ikrl-bridge (protocol translator)
└─ Services
   ├─ ikrl-ai (LLM gateway, Ollama-first)
   ├─ ikrl-fs (file system verification)
   ├─ ikrl-sdk (public SDK)
   └─ ikrl-federation (mDNS discovery)
```

---

## 🔐 Foundation Layer (No Internal Deps)

| Crate | Purpose | Key Tech |
|-------|---------|----------|
| **intentkernel-crypto** | Classical + post-quantum cryptography | Ed25519, AES-GCM, SHA3, ML-KEM-1024, ML-DSA-87 |
| **intentos-audit** | Immutable hash-chained event log | SHA3 + CBOR serialization |
| **intentos-hal** | Hardware abstraction layer | x86_64/ARM64, Windows/Linux |

---

## 🔧 Core Types & Protocol Layer

| Crate | Purpose | Used By |
|-------|---------|---------|
| **intentkernel-core** | Protocol messages, session types, state | All IKRL + IntentOS crates |
| **intentkernel-os** | OS architecture descriptor | ikrl-init, ikrl-shell |
| **ikrl-transport** | Async IPC/RPC (Tokio-based) | All IKRL daemons/services |

---

## 🖥️ IntentOS Crates (Single Binary)

### Kernel Tier (T3)

**`intentos-kernel`** — Policy engine, token broker, capability tables
- Owns policy evaluation
- Mints capability tokens
- Manages leases (time-limited grants)
- Pluggable intent recognizer (trait-based)
- Hash-chained audit trail

Dependencies: `intentos-audit`, `ed25519-dalek`, `sha3`

### Utilities Tier (T1)

**`intentos-utilities`** — VFS, AI gateway, platform integration
- Virtual file system
- AI service gateway (recognizer plugins)
- Platform backend selection (Windows/Linux)
- Identity services (LDAP integration)
- Sector-specific tools (banking, enterprise, healthcare, IoT, public safety)

Dependencies: `intentos-kernel`, `intentos-hal`, `intentos-audit`, `ldap3`, `reqwest`

### Shell Tier (T2)

**`intentos-shell`** — Interactive user session
- Command parser
- Builtin commands
- Session state management
- Interactive REPL

Dependencies: `intentos-kernel`, `intentos-utilities`, `intentos-bench`

### Benchmarking

**`intentos-bench`** — Performance metrics
- Boot latency
- Intent recognition latency
- Syscall latency

Dependencies: All tier crates + `intentos-hal`

---

## ⚙️ IKRL Daemon System Crates

### Boot & Platform Adapters

| Crate | Purpose | Platform |
|-------|---------|----------|
| **ikrl-init** | Supervisor, daemon spawner | Windows (primary), Linux |
| **ikrl-windows** | WinAPI integration, service lifecycle | Windows only |
| **ikrl-linux** | libc/nix integration, seccomp-notify | Linux only |

### System Daemons

| Crate | Purpose | Exposed Service |
|-------|---------|-----------------|
| **intentd** | Intent recognition & dispatch | Intent recognition protocol |
| **capd** | Capability minting & enforcement | Capability issuance |
| **leasebroker** | Token lifecycle, revocation | Lease management |
| **eventscope** | Syscall tracing, event auditing | Event audit stream |

### User Interfaces & Services

| Crate | Purpose | Type |
|-------|---------|------|
| **ikrl-cli** | Command-line control of IKRL | Binary (CLI) |
| **ikrl-shell** | Interactive REPL for IKRL | Binary (REPL) |
| **ikrl-bridge** | Protocol translation/interop | Binary/Lib |
| **ikrl-ai** | AI/LLM service integration | Binary/Lib |
| **ikrl-fs** | File system verification | Binary/Lib |
| **ikrl-sdk** | Public SDK (C/Rust FFI) | Library (cdylib + rlib) |

### Testing & Simulation

| Crate | Purpose |
|-------|---------|
| **ikrl-bench** | IKRL protocol benchmarks |
| **ikrl-sim** | Protocol simulation environment |
| **ikrl-federation** | mDNS-based peer discovery & gossip |

---

## 🛠️ Supporting & Demo Crates

| Crate | Purpose | Status |
|-------|---------|--------|
| **leasebroker** | Daemon: lease/token management | Active service |
| **ransomware-demo** | Security demonstration | Demo/test |

---

## 🔗 Critical Dependency Paths

### Path 1: IntentOS Monolith

```
intentos (main)
  → intentos-utilities (T1)
    → intentos-kernel (T3)
      → intentos-audit
      → ed25519-dalek
    → intentos-hal
    → reqwest, ldap3
  → intentos-shell (T2)
    → intentos-kernel
    → intentos-utilities
    → intentos-bench
      → intentos-hal
```

**Critical Junction:** `intentos-kernel` — all policy & crypto flows through here

### Path 2: IKRL Daemon Bootstrap

```
ikrl-init
  → intentkernel-core
    → intentkernel-crypto
      → ed25519-dalek, sha3
      
intentd / capd / leasebroker / eventscope
  → intentkernel-core
  → [crypto]
  → ikrl-transport
    → tokio (async runtime)
```

**Critical Junction:** `intentkernel-core` — all message passing flows through here

---

## 📚 Dependency Statistics

```
Layer 0 (Foundation):        3 crates   (0 internal deps)
Layer 1 (Core Protocol):     3 crates   (1 internal dep each)
Layer 2 (Systems):          19 crates   (2-4 internal deps)
Layer 3 (Demo):              3 crates   (2-4 internal deps)
────────────────────────────────────
Total:                      28 crates
```

### By Type

- **Binaries:** 18 crates (intentos, intentd, capd, ikrl-*, ransomware-demo, etc.)
- **Libraries:** 15 crates (intentkernel-*, intentos-*, bench, audit, hal, etc.)
- **Hybrid (bin + lib):** 5 crates (ikrl-federation, ikrl-ai, ikrl-fs, ikrl-bridge, ikrl-shell)

### By Platform

- **Cross-platform:** 25 crates
- **Windows-specific:** 2 crates (ikrl-windows, windows feature flags in ikrl-init)
- **Linux-specific:** 2 crates (ikrl-linux, seccomp-notify planned)

---

## 🔐 Security Architecture

### Cryptographic Tiers

| Component | Algorithm | Use Case | PQC Ready |
|-----------|-----------|----------|-----------|
| **Signing** | Ed25519 | Message authentication | ✓ (switchable to ML-DSA-87) |
| **Encryption** | AES-GCM | Data confidentiality | ✓ (switchable to ML-KEM-1024) |
| **Hashing** | SHA3 | Audit trail integrity | ✓ (PQC-safe) |

### Policy & Capability Model

- **Capabilities:** Fine-grained, time-limited (leases)
- **Tokens:** Minted by kernel, signed with Ed25519
- **Audit:** Hash-chained, tamper-evident
- **Intent Recognition:** Pluggable (ML-ready)

---

## 🎯 Integration Points

### Sector Integrations (via intentos-utilities)

```
intentos-utilities/sectors/
├─ banking/        → SWIFT, compliance
├─ enterprise/     → LDAP, Active Directory, Kerberos
├─ healthcare/     → HIPAA, HL7, DICOM
├─ iot/            → MQTT, device mgmt
└─ public_safety/  → law enforcement ops
```

### External Service Integrations

- **LDAP/Active Directory:** `ldap3` crate
- **LLM/AI:** `ikrl-ai` → Ollama, OpenAI
- **HTTP/REST:** `reqwest` (in utilities)
- **mDNS Discovery:** `mdns-sd` (in ikrl-federation)

---

## 📖 Documentation

- **`CRATE_MAP.md`** — Full crate inventory with detailed descriptions
- **`DEPENDENCY_GRAPH.md`** — Mermaid diagrams showing all dependencies
- **`README.md`** (root) — High-level project overview

---

## 🚀 Build & Test

### Workspace Layout

```
rust/
├─ crates/
│  ├─ intentos/              ← Main binary
│  ├─ intentos-kernel/       ← Core T3
│  ├─ intentos-utilities/    ← Core T1
│  ├─ intentos-shell/        ← Core T2
│  ├─ intentkernel-core/     ← Protocol
│  ├─ intentkernel-crypto/   ← Crypto
│  ├─ ikrl-init/             ← Boot
│  ├─ ikrl-windows/          ← Windows adapter
│  ├─ ikrl-linux/            ← Linux adapter
│  ├─ [13 more...]           ← Daemons, services, tools
│  └─ ransomware-demo/       ← Demo
├─ Cargo.toml                ← Workspace manifest
├─ CRATE_MAP.md              ← This documentation
└─ DEPENDENCY_GRAPH.md       ← Mermaid diagrams
```

### Build Command

```bash
cargo build --workspace                    # Build all crates
cargo build --bin intentos                 # Build main binary
cargo test --workspace                     # Test all crates
cargo build --target aarch64-unknown-linux-gnu  # ARM64 Linux
```

---

## 💡 Key Design Principles

1. **Layered Architecture:** Foundation → Core → Systems → App
2. **Zero Code Duplication:** Shared crypto, audit, HAL
3. **Pluggability:** Trait-based extensibility (recognizers, adapters)
4. **Post-Quantum Ready:** Crypto agnostic via intentkernel-crypto
5. **Audit Trail Guarantees:** Hash-chained immutable logs
6. **Cross-Platform:** Windows/Linux, x86_64/ARM64 support
7. **Dual Architectures:** Monolithic + distributed modes
8. **Configuration over Code:** Boot-time setup, no recompilation

---

## 📝 Notes for Developers

### When Adding a New Crate

1. Place in `rust/crates/{name}/`
2. Create `Cargo.toml` with workspace inheritance
3. Use `{ workspace = true }` for dependency versions
4. Use `{ path = "..." }` for internal dependencies
5. Update this map and dependency graph
6. Add tests in `tests/` directory
7. Document sector/tier mapping if applicable

### Dependency Rules

- ✅ Allowed: Layer N → Layer N-1
- ❌ Forbidden: Layer N → Layer N+1 (circular deps)
- ✅ Allowed: Multiple crates at same layer → same parent
- ✅ Allowed: Crate → multiple parents at layer below

---

## 📊 Metrics Summary

| Metric | Value |
|--------|-------|
| Total Crates | 28 |
| Total Lines of Rust Code | ~50k+ (estimated) |
| Dependency Depth | 4 layers |
| Max Deps per Crate | 8-10 |
| Workspace Dependencies | ~25 external crates |
| Platform Targets | 4 (Windows x64, Linux x64, Linux ARM64, WASM future) |
| Test Cases | 10+ integration tests |

---

**Last Updated:** Generated from Cargo.toml manifest analysis  
**Format:** Markdown + Mermaid diagrams  
**Audience:** Developers, architects, documentation consumers
