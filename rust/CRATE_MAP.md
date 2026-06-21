# Rust Crates Architecture Map

**Project:** IntentOS + IntentKernel Runtime Library (IKRL)  
**Generated:** Automatic analysis of all Cargo.toml manifests  
**Total Crates:** 28

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Crate Hierarchy Layers](#crate-hierarchy-layers)
3. [IntentOS System (Tier-Based)](#intentos-system-tier-based)
4. [IntentKernel Runtime Library (IKRL)](#intentkernel-runtime-library-ikrl)
5. [Supporting Services & Tools](#supporting-services--tools)
6. [Cross-Cutting Concerns](#cross-cutting-concerns)
7. [Dependency Graph](#dependency-graph)
8. [Crate Matrix](#crate-matrix)

---

## Architecture Overview

The project consists of two major systems operating at different abstraction levels:

```
┌─────────────────────────────────────────────────────────────────┐
│                      IntentOS (Single Binary)                   │
│  Single unified OS image with 3-tier architecture (kernel-up)   │
├─────────────────────────────────────────────────────────────────┤
│                 IKRL (Runtime Library System)                   │
│  Distributed protocol-driven daemon architecture               │
│  Multiple processes, cross-platform (Windows/Linux), multiarch  │
├─────────────────────────────────────────────────────────────────┤
│              Shared Foundation & Cryptography Layer             │
│  Core types, crypto primitives, audit infrastructure           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Crate Hierarchy Layers

### Layer 0: Cryptographic & Foundational (No Internal Dependencies)

These crates provide primitive capabilities upon which everything else builds.

| Crate | Purpose | Key Dependencies |
|-------|---------|------------------|
| **intentkernel-crypto** | Post-quantum & classical crypto (SHA-3, AES-GCM, Ed25519, ML-KEM, ML-DSA) | ed25519-dalek, aes-gcm, sha3, oqs (PQC) |
| **intentos-audit** | Immutable hash-chained audit log with serialization | serde, serde_json, sha3, chrono, uuid |
| **intentos-hal** | Hardware abstraction layer (x86_64/ARM64, Windows/Linux) | serde |

### Layer 1: Core Types & Protocols

Foundational data structures and protocol definitions used across all systems.

| Crate | Purpose | Dependencies |
|-------|---------|--------------|
| **intentkernel-core** | Core types, message protocol, session state | intentkernel-crypto, serde, chrono, uuid |
| **intentkernel-os** | OS layout descriptor (kernel, shell, utilities tiers) | serde |
| **ikrl-transport** | IPC/RPC transport layer (async over multiple backends) | tokio, serde, thiserror |

### Layer 2: Kernel & Shell (IntentOS Tier 2 & 3)

Policy enforcement, token management, capability systems, interactive shell.

| Crate | Purpose | Dependencies |
|-------|---------|--------------|
| **intentos-kernel** | Tier-3 kernel: policy, tokens, capabilities, syscall enforcement | intentos-audit, ed25519-dalek, sha3, serde, uuid |
| **intentos-shell** | Tier-2 interactive shell: REPL, command parsing, session state | intentos-kernel, intentos-utilities, intentos-bench |
| **intentos-utilities** | Tier-1 utilities: VFS, AI gateway, platform tools, sector integration | intentos-audit, intentos-hal, intentos-kernel, serde_json, ldap3, reqwest |
| **intentos-bench** | Benchmark harness: boot, intent, syscall latency metrics | intentos-audit, intentos-hal, intentos-kernel, intentos-utilities |

### Layer 2: Application (IntentOS Main)

| Crate | Purpose | Dependencies |
|-------|---------|--------------|
| **intentos** | Single-binary OS: boots utilities(1) → shell(2) → kernel(3) | intentos-kernel, intentos-utilities, intentos-shell, clap |

### Layer 2: IKRL Daemon System (Distributed)

Network services, platform-specific adapters, protocol daemons.

| Crate | Purpose | Dependencies |
|-------|---------|--------------|
| **ikrl-init** | Boot supervisor: daemon spawn, job object management (Windows-primary) | intentkernel-os, tokio, tracing, windows (platform-specific) |
| **ikrl-federation** | mDNS-based peer discovery and federation protocol | intentkernel-core, intentkernel-crypto, ikrl-transport, mdns-sd |
| **ikrl-windows** | Windows service integration: WinAPI adapters, service lifecycle | intentkernel-core, ikrl-transport, windows-service |
| **ikrl-linux** | Linux platform adapter: seccomp-notify, libc integration | intentkernel-core, ikrl-transport, nix, libc |
| **ikrl-cli** | Command-line interface for IKRL protocol | intentkernel-core, ikrl-transport, clap, hex |
| **ikrl-shell** | Interactive shell for IKRL (separate from IntentOS shell) | intentkernel-core, intentkernel-os, ikrl-transport, tokio |
| **ikrl-ai** | AI service integration (LLM gateway, Ollama client) | intentkernel-core, ikrl-transport, reqwest, async-trait |
| **ikrl-fs** | File system service (Merkle verification, VFS backend) | intentkernel-core, ikrl-transport, walkdir |
| **ikrl-sdk** | Public SDK library (C/Rust FFI, lib + cdylib) | intentkernel-core, intentkernel-crypto, ikrl-transport |
| **ikrl-bridge** | Protocol bridge (message translation, interop) | intentkernel-core, ikrl-transport |
| **ikrl-bench** | IKRL-level performance benchmarks | intentkernel-core, intentkernel-crypto, ikrl-transport |
| **ikrl-sim** | Simulation environment for protocol testing | intentkernel-core, intentkernel-crypto |

### Layer 3: System Services (Daemon Processes)

Core system functionality exposed via IKRL protocol.

| Crate | Purpose | Dependencies |
|-------|---------|--------------|
| **intentd** | Intent daemon: intent dispatch, policy evaluation daemon | intentkernel-core, intentkernel-crypto, ikrl-transport |
| **leasebroker** | Lease management daemon: token lifecycle, revocation | intentkernel-core, ikrl-transport |
| **capd** | Capability daemon: capability minting, enforcement | intentkernel-core, intentkernel-crypto, ikrl-transport |
| **eventscope** | Event auditing daemon: syscall tracing, access logging | intentkernel-core, ikrl-transport, libc, nix |

### Layer 4: Utilities & Tools

Supporting tools and demonstrations.

| Crate | Purpose | Dependencies |
|-------|---------|--------------|
| **ransomware-demo** | Security demonstration crate | intentkernel-core, intentkernel-crypto |

---

## IntentOS System (Tier-Based)

### Single Binary Architecture

IntentOS is a **monolithic single-binary OS** with three functional tiers that boot in reverse dependency order:

```
Application (main.rs)
    ↓
[TIER_UTILITIES-1] intentos-utilities
    ├─ VFS (virtual file system)
    ├─ AI gateway
    ├─ Platform backend (HAL)
    ├─ Identity/LDAP integration
    └─ Sector-specific tools
    ↓
[TIER_SHELL-2] intentos-shell
    ├─ Interactive REPL
    ├─ Command parser
    ├─ Session state
    └─ Builtin commands
    ↓
[TIER_KERNEL-3] intentos-kernel (Tier-3)
    ├─ Policy engine
    ├─ Token broker & minting
    ├─ Capability table management
    ├─ Syscall enforcement
    ├─ Lease manager
    └─ Intent recognizer (pluggable)
```

### Dependency Order

1. **intentos-kernel**: Kernel-up (no dependencies on shell/utilities)
   - Provides: Policy, tokens, capabilities, leases
   - Owns: Cryptography via ed25519-dalek

2. **intentos-utilities**: Midlayer
   - Depends on: kernel, audit, hal
   - Provides: VFS, AI gateway, platform abstraction, identity services

3. **intentos-shell**: User-facing layer
   - Depends on: kernel, utilities, bench
   - Provides: Interactive REPL, command execution

4. **intentos** (main binary): Application layer
   - Boots the system in order: utilities → shell → kernel
   - Dev-time: includes audit, hal for testing

---

## IntentKernel Runtime Library (IKRL)

### Distributed Daemon Architecture

IKRL is a **protocol-driven daemon system** for distributed intent recognition and enforcement.

```
┌─────────────────────────────────────────────────────────────┐
│                      IKRL Federation                         │
│  (ikrl-federation: mDNS discovery + gossip protocol)        │
├─────────────────────────────────────────────────────────────┤
│  Platform Adapters   │  System Daemons    │  User Interfaces │
├─────────────────────┼────────────────────┼──────────────────┤
│ ikrl-windows        │ intentd             │ ikrl-cli         │
│ ikrl-linux          │ leasebroker         │ ikrl-shell       │
│ ikrl-init           │ capd                │ ikrl-bridge      │
│                     │ eventscope          │                  │
├─────────────────────┴────────────────────┴──────────────────┤
│          IPC Layer (ikrl-transport + Tokio async)           │
├─────────────────────────────────────────────────────────────┤
│     Core Protocol Layer (intentkernel-core + crypto)        │
└─────────────────────────────────────────────────────────────┘
```

### Bootstrap & Initialization

- **ikrl-init**: Supervisor daemon
  - Spawns platform-specific services on Windows/Linux
  - Manages job objects (Windows) / process groups (Linux)
  - Configures logging and tracing

### Service Daemons

- **intentd**: Intent recognition & dispatch
- **leasebroker**: Token lifecycle management
- **capd**: Capability minting & enforcement
- **eventscope**: Syscall tracing & event auditing

### Platform Adapters

- **ikrl-windows**: WinAPI integration, service lifecycle
- **ikrl-linux**: libc + nix integration, seccomp-notify support

### User Interfaces

- **ikrl-cli**: Command-line control
- **ikrl-shell**: Interactive REPL
- **ikrl-bridge**: Protocol interop

### Supporting Services

- **ikrl-ai**: LLM/Ollama integration
- **ikrl-fs**: File system verification
- **ikrl-federation**: Peer discovery via mDNS

---

## Cross-Cutting Concerns

### Cryptography

**intentkernel-crypto** is the single source of truth:
- Classical: SHA-3, AES-GCM, Ed25519
- Post-Quantum: ML-KEM-1024, ML-DSA-87 (via oqs library)
- Used by: intentos-kernel, intentkernel-core, many IKRL daemons

### Audit & Logging

**intentos-audit** provides immutable hash-chained event logging:
- Used by: intentos-kernel, intentos-utilities, intentos-bench, intentos-shell
- Public tracing via: intentd, leasebroker, capd, eventscope

### Platform Abstraction

**intentos-hal** provides hardware abstraction:
- Architectures: x86_64, ARM64
- Operating systems: Windows, Linux
- Used by: intentos-utilities, intentos-bench

### Transport & Serialization

**ikrl-transport** provides:
- Tokio-based async IPC
- Multiple backend support (socket, named pipe, etc.)
- Cross-platform serialization (serde/serde_json, CBOR)

---

## Dependency Graph

### IntentOS Dependency Tree (Full)

```
intentos (main binary)
├─ intentos-kernel
│  ├─ intentos-audit
│  ├─ ed25519-dalek (external)
│  └─ sha3 (external)
├─ intentos-utilities
│  ├─ intentos-audit
│  ├─ intentos-hal
│  ├─ intentos-kernel
│  ├─ serde_json (external)
│  ├─ reqwest (external)
│  └─ ldap3 (external)
├─ intentos-shell
│  ├─ intentos-kernel
│  ├─ intentos-utilities
│  └─ intentos-bench
└─ intentos-shell dependencies
   └─ intentos-bench
      ├─ intentos-audit
      ├─ intentos-hal
      ├─ intentos-kernel
      └─ intentos-utilities
```

### IKRL Dependency Tree (Selected Paths)

```
ikrl-federation
├─ intentkernel-core
│  └─ intentkernel-crypto
├─ intentkernel-crypto
├─ ikrl-transport
└─ mdns-sd (external)

ikrl-windows
├─ intentkernel-core
├─ ikrl-transport
└─ windows/windows-service (external, platform-specific)

ikrl-cli
├─ intentkernel-core
├─ ikrl-transport
└─ clap (external)

intentd
├─ intentkernel-core
├─ intentkernel-crypto
└─ ikrl-transport
```

---

## Crate Matrix

### Complete Crate Inventory

| # | Crate | Type | Entry | Status | Dependencies | Purpose |
|---|-------|------|-------|--------|--------------|---------|
| 1 | intentkernel-crypto | lib | lib.rs | ✓ | ed25519-dalek, aes-gcm, sha3 | Cryptographic primitives (classical + PQC) |
| 2 | intentos-audit | lib | lib.rs | ✓ | serde, sha3, chrono | Immutable hash-chained audit log |
| 3 | intentos-hal | lib | lib.rs | ✓ | serde | Hardware abstraction (CPU/OS) |
| 4 | intentkernel-core | lib | lib.rs | ✓ | intentkernel-crypto, serde | Core protocol types, session state |
| 5 | intentkernel-os | lib | lib.rs | ✓ | serde | OS architecture descriptor |
| 6 | ikrl-transport | lib | lib.rs | ✓ | tokio, serde | IPC/RPC transport abstraction |
| 7 | intentos-kernel | lib | lib.rs | ✓ | intentos-audit, ed25519-dalek | Tier-3: policy, tokens, capabilities |
| 8 | intentos-utilities | lib | lib.rs | ✓ | intentos-kernel, intentos-hal, ldap3, reqwest | Tier-1: VFS, AI, platform tools |
| 9 | intentos-shell | lib | lib.rs | ✓ | intentos-kernel, intentos-utilities | Tier-2: interactive shell |
| 10 | intentos-bench | lib | lib.rs | ✓ | all tier-* crates | Benchmark harness |
| 11 | intentos | bin | main.rs | ✓ | intentos-kernel/shell/utilities | Single-binary OS |
| 12 | ikrl-init | bin | main.rs | ✓ | intentkernel-os, windows (platform) | Boot supervisor |
| 13 | ikrl-federation | bin/lib | main.rs | ✓ | intentkernel-core, mdns-sd | Peer discovery & federation |
| 14 | ikrl-windows | bin/lib | main.rs | ✓ | intentkernel-core, windows-service | Windows service adapter |
| 15 | ikrl-linux | bin/lib | main.rs | ✓ | intentkernel-core, nix, libc | Linux platform adapter |
| 16 | ikrl-cli | bin/lib | main.rs | ✓ | intentkernel-core, clap | CLI client for IKRL |
| 17 | ikrl-shell | bin | main.rs | ✓ | intentkernel-core, ikrl-transport | IKRL interactive shell |
| 18 | ikrl-ai | bin/lib | main.rs | ✓ | intentkernel-core, reqwest | AI/LLM service integration |
| 19 | ikrl-fs | bin/lib | main.rs | ✓ | intentkernel-core, walkdir | File system verification |
| 20 | ikrl-sdk | lib | lib.rs | ✓ | intentkernel-core, intentkernel-crypto | Public SDK (FFI + Rust) |
| 21 | ikrl-bridge | bin/lib | main.rs | ✓ | intentkernel-core, ikrl-transport | Protocol bridge/translator |
| 22 | ikrl-bench | bin | main.rs | ✓ | intentkernel-crypto, ikrl-transport | IKRL benchmarks |
| 23 | ikrl-sim | bin | main.rs | ✓ | intentkernel-core, intentkernel-crypto | Protocol simulation |
| 24 | intentd | bin | main.rs | ✓ | intentkernel-core, intentkernel-crypto | Intent daemon |
| 25 | leasebroker | bin | main.rs | ✓ | intentkernel-core, ikrl-transport | Lease management daemon |
| 26 | capd | bin | main.rs | ✓ | intentkernel-core, intentkernel-crypto | Capability daemon |
| 27 | eventscope | bin | main.rs | ✓ | intentkernel-core, ikrl-transport, libc/nix | Event auditing daemon |
| 28 | ransomware-demo | bin | main.rs | ✓ | intentkernel-core, intentkernel-crypto | Security demo |

---

## Key Architectural Insights

### 1. **Clean Dependency Flow**

```
Foundation (No deps) ← Core Types ← Systems ← Application
    ↓                      ↓            ↓
 crypto, audit, hal ← intentkernel-* ← intentos-* → Single Binary
                       ikrl-transport ← IKRL Daemons → Distributed
```

### 2. **Separation of Concerns**

- **IntentOS**: Kernel-up monolithic architecture (single process, intra-process communication)
- **IKRL**: Daemon-oriented distributed architecture (multi-process, IPC/RPC, peer federation)
- **Shared**: Cryptography, types, audit — zero duplication

### 3. **Platform Abstraction**

- **intentos-hal**: Abstracts hardware (x86_64 vs ARM64, Windows vs Linux)
- **ikrl-windows** / **ikrl-linux**: Platform-specific service adapters
- **ikrl-init**: Platform-agnostic supervisor (uses conditional deps for platform features)

### 4. **Security Posture**

- **Cryptography**: Post-quantum ready (ML-KEM-1024, ML-DSA-87 via oqs)
- **Audit**: Hash-chained immutable logs (tamper-evident)
- **Capabilities**: Fine-grained policy-driven access control
- **Leases**: Time-limited capability grants with revocation

### 5. **Pluggability**

- **Intent Recognition**: Trait-based (`IntentRecognizer`) with stub default
- **Recognizers**: Ollama, Pilot, custom via intentos-utilities
- **AI Gateway**: LLM integration via ikrl-ai (Ollama-first)
- **Audit**: Optional pluggable via KernelConfig

---

## Design Patterns

### Trait-Based Extensibility

```rust
pub trait IntentRecognizer: Send + Sync {
    fn recognize(&self, input: &str) -> Result<RecognizedIntent>;
    fn name(&self) -> String;
}
```

Used for: Intent recognition, sector-specific adapters (banking, healthcare, IoT, enterprise)

### Error Handling Consistency

All crates use:
- `thiserror` for domain-specific errors
- `anyhow` for context propagation
- Custom error types (e.g., `KernelError`, `CryptoError`)

### Configuration at Boot

```rust
pub struct KernelConfig {
    pub audit: Option<Arc<AuditLog>>,
    pub recognizer: Option<Arc<dyn IntentRecognizer>>,
}
```

Allows runtime configuration without recompilation.

### Workspace Dependencies

All crates use workspace inheritance:
```toml
version.workspace = true
edition.workspace = true
authors.workspace = true
license.workspace = true
```

Ensures consistency across 28 crates.

---

## Version Strategy

- **Workspace Version**: Managed centrally in `rust/Cargo.toml`
- **All Internal Dependencies**: Use `{ path = "..." }` or `{ workspace = true }`
- **External Dependencies**: Pinned in workspace (e.g., tokio, serde)

---

## Testing Strategy

- **Unit Tests**: Each crate has `#[cfg(test)]` modules
- **Integration Tests**: 
  - `intentos/tests/`: ground_up, sector pilots (banking, enterprise, healthcare, IoT, public_safety)
  - `ikrl-cli/tests/`: full_flow
  - `ikrl-init/tests/`: boot_flow

---

## Future Extensions

### Phase 2 (Planned)

- Multi-kernel federation
- Hardware-accelerated PQC (GPU integration)
- Real-time syscall enforcement
- Remote attestation via capabilities

### Sector Integrations

Currently planned in intentos-utilities:
- **Banking**: SWIFT integration, compliance
- **Enterprise**: LDAP, Active Directory, Kerberos
- **Healthcare**: HIPAA, HL7, DICOM
- **IoT**: MQTT, device management
- **Public Safety**: Law enforcement ops, evidence chain

---

## Conclusion

This architecture provides:
- ✅ **Monolithic efficiency** (IntentOS) + **Distributed scalability** (IKRL)
- ✅ **Post-quantum ready** cryptography
- ✅ **Audit trail guarantees** (hash-chained logs)
- ✅ **Platform abstraction** (Windows/Linux, x86_64/ARM64)
- ✅ **Fine-grained security** (policy, capabilities, leases)
- ✅ **Pluggable intent recognition** (ML-ready)
- ✅ **Zero code duplication** (shared foundation)

**Total crates:** 28 | **Dependency depth:** 4 layers | **Platform targets:** 4 (Windows x64, Linux x64/ARM64)
