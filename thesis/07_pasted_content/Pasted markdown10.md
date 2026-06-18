# INTENTKERNEL CAPABILITY TOKEN SPECIFICATION V1.0
## RFC-IK-CT-001 | Standardized Wire Format for Event-Scoped Authority

**Status:** Proposed Standard
**Author:** IntentKernel Architecture Group
**Date:** July 2025
**Classification:** Public Engineering Specification

---

## 1. ABSTRACT

This document defines the canonical wire format for IntentKernel Capability Tokens. These tokens carry event-scoped authority from the Intent Broker to execution contexts (processes, containers, firmware modules, vehicles). 

This specification eliminates fragmentation by mandating a single binary encoding scheme compatible across all deployment stages (IKRL Windows Service → Native UCCS Microkernel). It ensures that every capability request—whether on a smartwatch sensor or a datacenter hypervisor—is authenticated, time-bound, and scope-limited using a unified cryptographic model.

**Core Design Goals:**
1.  **Canonicality:** One byte-layout definition across all platforms.
2.  **Post-Quantum Readiness:** NIST-standardized ML-DSA (Dilithium) signatures.
3.  **Compactness:** Minimal overhead for embedded constraints while supporting PQC payloads.
4.  **Verifiability:** Self-contained validation without external lookup tables.

---

## 2. CONFORMANCE LEVELS

Implementations must adhere to one of three conformance levels based on hardware capability:

| Level | Target | Signature Algo | Token Size | Description |
| :--- | :--- | :--- | :--- | :--- |
| **LEVEL-A (Full)** | Servers, Desktops, Mobile | ML-DSA-65 (Dilithium) | ~3.5 KB | Full PQC security. Required for Network/Cloud. |
| **LEVEL-B (Hybrid)** | Enterprise Workstations | ML-DSA-65 + Ed25519 | ~3.6 KB | Hybrid classical/PQC for transition period. |
| **LEVEL-C (Light)** | Embedded/IoT (Stage 4) | Ed25519 (Temporary) | ~2.1 KB | Temporary downgrade for HW-constrained devices. Migration path to A required. |

*For this canonical specification, LEVEL-A is the default reference. Implementations may opt-out of Level-A only if documented under IKRL Legacy Mode exceptions.*

---

## 3. DATA MODEL STRUCTURE

The token is composed of four logical sections: **Header**, **Payload**, **Security Bindings**, and **Proof**.

### 3.1 Header (Fixed 16 Bytes)
| Offset | Field | Size | Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| 0x00 | `Magic` | 2 bytes | `UINT16` | Fixed value `0xCA FE` (IntentKernel Cap) |
| 0x02 | `Version` | 1 byte | `UINT8` | `0x01` |
| 0x03 | `TokenType` | 1 byte | `ENUM` | See Section 3.5 |
| 0x04 | `IssuerID` | 8 bytes | `UINT64` | Hash(Identity Key) of Broker Node |
| 0x0C | `TokenID` | 8 bytes | `UUID` | Short UUID (Least Significant Bits of v7) |

### 3.2 Payload (Variable Length)
| Field | Type | Description |
| :--- | :--- | :--- |
| `SubjectID` | `SHA3-256` | Hash of Application Identity Certificate |
| `ResourceSpec` | `TLV` | Target resource (File Path, IP, Sensor ID) |
| `ActionCode` | `UINT32` | Operation permitted (READ, WRITE, EXEC, SEND) |
| `ContextHash` | `SHA3-256` | Binding to UI State or Session Context |
| `ActorBinding` | `HASH` | User Identity Hash (Biometric/Password) |

### 3.3 Lifecycle Control (Fixed 24 Bytes)
| Offset | Field | Size | Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| 0x00 | `IssuedAt` | 8 bytes | `UINT64` | Nanoseconds UTC Epoch |
| 0x08 | `ExpiresAt` | 8 bytes | `UINT64` | Nanoseconds UTC Epoch |
| 0x10 | `MaxUses` | 4 bytes | `UINT32` | Maximum consumption count |
| 0x14 | `CurrentUses`| 4 bytes | `UINT32` | Current consumption count (Mutable) |
| 0x18 | `DelegateHops`| 2 bytes | `UINT16` | Remaining delegation depth allowed |

### 3.4 Proof Section (Variable Length)
| Field | Type | Description |
| :--- | :--- | :--- |
| `SigAlgoID` | `UINT16` | NIST Algorithm Identifier |
| `Signature` | `BYTES` | Raw PQC Signature Bytes |

---

## 4. WIRE ENCODING (CBOR PROTOCOL)

To ensure efficient serialization and parsing, tokens are encoded using **IETF Concise Binary Object Representation (CBOR)** [RFC 8949]. 

### 4.1 Map Structure
```cbor
{
  0: h'magic_version',       # Header (Bytes)
  1: {                       # Payload (Map)
    0: h'...,                # SubjectID (Bytes - SHA3)
    1: [h'resource_data'],   # ResourceSpec (Array of TLVs)
    2: u32_action_code,      # ActionCode (Int)
    3: h'...'                # ContextHash (Bytes - SHA3)
  },
  2: [iss_ns, exp_ns, max_u, cur_u, hops], # Lifecycle (Array)
  3: h'proof_bytes'          # Signature Block (Bytes)
}
```

### 4.2 Binary Layout Diagram
```
[ HEADER (16B) ][ PAYLOAD (Var) ][ LIFECYCLE (24B) ][ PROOF (Var) ]
└─────┬────────┘ └──────┬──────┘ └───────┬────────┘ └──────┬──────┘
      │                 │                 │                 │
  Magic/Ver         App ID/Tgt           Time/Count      Sig/Algo
  UUID Trunc        Context/Actor        DelegateHops    (Dilithium)
```

---

## 5. CRYPTOGRAPHIC SCHEMES

All signatures must use key pairs generated by the Trust Broker within secure boundaries.

### 5.1 Primary Algorithm: ML-DSA-65 (Dilithium)
*   **Standard:** NIST FIPS 204
*   **Public Key Size:** 1952 Bytes
*   **Secret Key Size:** 4000 Bytes
*   **Signature Size:** 3309 Bytes
*   **Usage:** Used for signing the hash of the Header+Payload+Lifecycle.

### 5.2 Hash Function: SHA3-512
*   Used for generating `IssuerID`, `ContextHash`, `ActorBinding`.
*   Prevents length-extension attacks associated with SHA2 family.

### 5.3 Randomness Source: SP800-90A DRBG
*   All `TokenID` generation must use cryptographically secure random number generators (CSRNG) seeded by Hardware RNG.

---

## 6. VALIDATION LOGIC

Every consumer of a token (`eventscope`, `HostOS Interceptor`, `LeaseBroker`) MUST execute the following checks before allowing access. **Failure at any step results in immediate rejection.**

```text
FUNCTION ValidateToken(Token):
    1. CHECK_MAGIC: Token.Header.Magic == 0xCAFE
    
    2. CHECK_TIME: 
       NOW() >= Token.Lifecycle.IssuedAt AND 
       NOW() < Token.Lifecycle.ExpiresAt
       
    3. CHECK_USAGE: 
       Token.Lifecycle.CurrentUses < Token.Lifecycle.MaxUses
       
    4. CHECK_REPLAY:
       IF Token.TokenID IN RevocationCache: REJECT
        
    5. CHECK_SCOPE:
       Requested_Resource == Token.Payload.ResourceSpec AND
       Requested_Action == Token.Payload.ActionCode
       
    6. VERIFY_SIG:
       VerifyDilithium(Token.Signature, SignerKey, Token.ContentHash)
       
    7. RETURN ALLOW
```

---

## 7. EXAMPLE TRACE (Hex Dump)

Below is a truncated representation of a valid `FILE_OPEN_READ` token issued for a 10-second window.

```hex
# HEADER
CA FE 01 00     // Magic + Ver + Type (FILE)
00 01 02 03     // IssuerID (Truncated)
A1 B2 C3 D4 E5 F6 07 08 // TokenID (LSB)

# PAYLOAD (CBOR Encoded)
A3              // Map(3) keys follow
01              // Key 1: SubjectID
58 20 ...       // Value: 32-byte SHA3 Hash
02              // Key 2: ResourceSpec
67 65 78 61 6D 70 6C 65 2F 64 61 74 61 2E 74 78 74 // "example/data.txt"
03              // Key 3: ActionCode
18 01           // Int(1) = READ_ONLY

# LIFECYCLE (8 bytes each for time, 4 for counts)
00 00 01 8B C9 ... // IssuedAt (Ns)
00 00 01 8B C9 ... + 10s // ExpiresAt
00 00 00 01         // MaxUses: 1
00 00 00 00         // CurrentUses: 0
00 00               // DelegateHops: 0

# PROOF
00 05             // AlgoID: ML-DSA-65
58 E0 ...         // Signature (3309 bytes truncated here)
```

---

## 8. SECURITY CONSIDERATIONS

### 8.1 Token Size Overhead
With ML-DSA-65 signatures, Level-A tokens approach 4KB. This is significant for constrained networks (IoT).
*   **Mitigation:** In Level-C environments (IoT), use Level-C signatures (Ed25519) but store the Level-A root certificate in the device TPM for periodic audit. Do not compromise the broker signature chain.

### 8.2 Clock Synchronization
Validity relies on `IssuedAt` and `ExpiresAt`.
*   **Requirement:** Brokers and Consumers must synchronize time via NTP/PTP with drift tolerance < 50ms.
*   **Fallback:** If clock drift exceeds threshold, reject token unless signed with absolute hardware timestamp (e.g., Secure Real-Time Clock).

### 8.3 Delegation Chains
Tokens allow limited delegation (`DelegateHops`).
*   **Risk:** Privilege Escalation via Chaining.
*   **Limit:** Max 3 hops enforced by `intentd`. Any attempt to decrement below zero is logged as a violation.

### 8.4 Side-Channel Resistance
Token validation code must execute in constant time where possible to prevent timing attacks revealing signature validity or internal state.

---

## 9. IMPLEMENTATION COMPLIANCE CHECKLIST

To claim "IntentKernel Compliant", your runtime must pass these tests:

- [ ] **Token Parsing:** Can deserialize CBOR binary stream without buffer overflow.
- [ ] **Crypto Verification:** Correctly verifies Dilithium signatures using NIST test vectors.
- [ ] **TTL Enforcement:** Immediately revokes permissions upon expiry (verified via fuzz testing).
- [ ] **Replay Prevention:** Rejects reused TokenIDs within the `RevocationWindow`.
- [ ] **Scope Locking:** Cannot modify `ResourceSpec` after signing.

---

## 10. MIGRATION FROM LEGACY PERMISSIONS

Legacy systems (Windows ACLs, Linux DAC) often expect persistent strings (e.g., "User=admin").
*   **Mapping:** Legacy permissions are translated into a `RESOURCE_SPEC` that looks like: `acl_string("domain/user")`.
*   **Constraint:** Even with legacy translation, the token **must expire** and require intent renewal. Persistent legacy mappings are deprecated after Stage 2 deployment.

---

## 11. REVISION HISTORY

| Version | Date | Change |
| :--- | :--- | :--- |
| 0.1 | 2025-06-01 | Initial Draft (JSON/Struct Mix) |
| 0.5 | 2025-06-15 | Moved to CBOR Binary |
| 1.0 | 2025-07-15 | Finalized PQC & Lifecycle Fields |

---

**END OF SPECIFICATION**