This is the correct strategic pivot. By defining the repository structure, the public identity, and the licensing upfront, you convert abstract research into an engineering deliverable. This creates a defensible boundary around your work while inviting adoption under safe terms.

Steps 1–8 are validated. Proceed immediately to Step 9.

Below is the **Official Architecture Overview Document**. This is the text you will save as `docs/architecture_overview.md`. It serves as the anchor document for the GitHub repository and the primary reference for the Zenodo archive.

---

# docs/architecture_overview.md

```markdown
# IntentKernel Architecture v1.0
## A Capability-Secure Execution Model for Event-Scoped Computing

**Status:** Public Architecture Proposal  
**Version:** 1.0.0  
**Date:** July 2025  
**License:** Apache 2.0  

---

## 1. Authorship and Attribution

**Architecture Lead:** [Your Name]  
**Co-Architect:** ChatGPT (OpenAI Language Model Collaboration)  
**Contact:** [Your Contact Info / Project URL]  

> This architecture is released under the **Apache License 2.0**. Implementation must preserve core security guarantees (event-scoping, zero ambient authority, verified intent). See `governance/principles.md` for compliance requirements.

---

## 2. Executive Summary

IntentKernel is a capability-secure execution architecture designed to eliminate ambient authority across desktops, mobile devices, servers, IoT systems, vehicles, industrial controllers, and cloud infrastructure. 

Traditional computing models rely on persistent permissions granted at install time or login. This creates structural vulnerabilities where compromised applications retain unlimited access indefinitely. IntentKernel replaces this with **Event-Scoped Authority**: power is granted only at the moment of verified user intent and expires automatically when the task completes.

This specification defines a universal stack consisting of four layers: **IntentKernel**, **UCCS**, **IKRL**, and **IBPS**. Together, they provide a migration path from legacy operating systems toward a structurally secure future.

---

## 3. Problem Statement

Modern computing security faces three critical blockers:

1.  **Persistent Privilege:** Applications granted once retain permanent access to sensitive resources (files, network, sensors), enabling ransomware, spyware, and data exfiltration.
2.  **Identity-Based Trust:** Access control relies on *who* you are (user ID), not *what* you intend to do. This allows lateral movement within compromised sessions.
3.  **Migration Friction:** Existing ecosystems cannot be replaced overnight. New secure architectures require OS replacement, which stalls adoption for decades.

**IntentKernel resolves these by treating all authority as temporary.** No process runs with ambient power. Every action requires a cryptographic proof of intent, issued by a trusted broker, and bound to a strict time-to-live (TTL).

---

## 4. Architecture Stack

The system is divided into four interoperable components:

| Component | Scope | Function |
| :--- | :--- | :--- |
| **IntentKernel** | Execution Model | Defines the rules of event-scoped execution and capability lifecycle. |
| **UCCS** | Universal Substrate | The formal specification for capability tokens, scheduling, and resource mapping across all device classes. |
| **IKRL** | Relief Layer | The compatibility shim (Windows/Linux/Android) that enforces IntentKernel principles on legacy OS kernels. |
| **IBPS** | Protocol Spec | The wire format and state machine for token issuance, validation, and revocation. |

### 4.1 Interaction Diagram

```text
┌─────────────────────────────────────────────────────────┐
│                   USER INTERACTION                       │
│            (Click, Voice, Sensor Trigger, etc.)          │
└───────────────────────┬─────────────────────────────────┘
                        │ Verified Intent
                        ▼
┌─────────────────────────────────────────────────────────┐
│                  INTENT BROKER                           │
│         (intentd / capd / leasebroker / eventscope)      │
│  • Classifies Action                                   │
│  • Issues PQC-Signed Capability Token                  │
│  • Enforces Expiry                                     │
└───────────────────────┬─────────────────────────────────┘
                        │ Validated Capability Token
                        ▼
┌─────────────────────────────────────────────────────────┐
│                 EXECUTION CONTEXT                        │
│        (Process / Container / Firmware Task)             │
│  • Cannot access resources without Token               │
│  • Token auto-expires after TTL / Single Use           │
└───────────────────────┬─────────────────────────────────┘
                        │ Syscall / API Call
                        ▼
┌─────────────────────────────────────────────────────────┐
│                HOST OPERATING SYSTEM                     │
│          (Windows / Linux / Android / Embedded)          │
│  • Treated as Untrusted Resource Provider              │
│  • Interceptor validates Token before granting Handle  │
└─────────────────────────────────────────────────────────┘
```

---

## 5. Core Concepts

### 5.1 Zero Ambient Authority
By default, no process has access to any resource. Access is strictly opt-in via capability tokens. There is no "root" or "admin" concept that persists across reboots or sessions.

### 5.2 Event-Scoped Execution
Authority is tied to a specific event. If a user clicks "Send Email," the app receives a token to send one email to one address. After sending, the token burns. The app cannot silently send a second email without a new user trigger.

### 5.3 Intent Verification
The Intent Broker verifies that the digital request matches physical human input. 
*   **Desktop:** Protected UI overlays prevent phishing hooks.
*   **Mobile:** System-level touch interception prevents overlay attacks.
*   **Embedded:** Hardware interrupts bypass software stacks.

### 5.4 Cross-Device Federation
Capabilities can be securely delegated between trusted devices (e.g., Phone → Smart TV) using cryptographically chained tokens, enabling seamless workflows without shared credentials.

---

## 6. Deployment Model

Adoption occurs through an evolutionary 5-stage path:

1.  **Stage 1 (IKRL):** Windows Service + Micro-VM Wrapper. Protects existing apps without recompilation.
2.  **Stage 2 (IKRL):** Linux LSM Module + Namespace Broker. Native integration for containers and servers.
3.  **Stage 3 (IKRL):** Mobile System Service. Enforced via platform entitlements.
4.  **Stage 4 (IKRL):** Embedded Firmware Supervisor. Runs alongside bare-metal RTOS.
5.  **Stage 5 (Native):** Hardware Enforcement. Capability registers enforced in silicon (CHERI/UCCS).

**Strategic Shift:** We are not distributing a new Operating System. We are distributing a **Runtime Environment** compatible with existing OSes. This eliminates the friction of OS replacement.

---

## 7. Security Guarantees

| Threat Category | Mitigation Mechanism |
| :--- | :--- |
| **Ransomware** | No file write capability unless explicitly triggered by user. |
| **Spyware** | Input/Sensor capabilities expire instantly after capture. |
| **Backdoors** | Background services require heartbeat renewal; otherwise killed. |
| **Data Exfiltration** | Network capabilities scoped per destination; revoked post-transfer. |
| **Privilege Escalation** | No process can grant itself permissions. Only Broker can issue. |
| **Quantum Attack** | All tokens signed with NIST-standardized ML-DSA (Dilithium). |

---

## 8. Governance and Principles

To maintain architectural integrity, all implementations claiming "IntentKernel Compatible" must adhere to the following:

1.  **Structural Immunity:** Malware mitigation must be achieved via enforcement (capabilities), not detection (signatures).
2.  **Transparency:** Users must always know what capabilities are active (visual indicators).
3.  **Portability:** The protocol (IBPS) must work identically across Stage 1–5 environments.
4.  **Non-Proprietary:** Core specs must remain open. Custom extensions allowed if backward compatible.

---

## 9. Roadmap

- **v1.0 (Current):** Protocol Specification (IBPS) & Architecture Definition.
- **v1.1:** Reference Implementation (Python/Rust Prototype).
- **v1.2:** Legacy Shim Driver (Windows/LSM).
- **v1.3:** SDK Release for Developers.
- **v2.0:** Hardware Specification Draft (Native Support).

---

## 10. References & Specifications

Detailed specifications are maintained in adjacent documents:

- `[IBPS Spec](./ibps_spec.md)` — Intent Broker Protocol & Token Format
- `[UCCS Spec](./uccs_spec.md)` — Universal Capability Computing Substrate
- `[IKRL Spec](./ikrl_spec.md)` — IntentKernel Relief Layer Architecture
- `[Token RFC](./token_rfc.md)` — Canonical Wire Format v1.0

---

## 11. Citation

If you use this architecture in academic or commercial work, please cite as follows:

> [Your Name], "IntentKernel Architecture v1.0: A Capability-Secure Execution Model for Event-Scoped Computing," July 2025. Available at [Repo URL].

---

*End of Document*
```

---

# Immediate Next Actions (Execution Checklist)

You now have the core content. To complete the launch, perform these actions in order:

### 1. Create the Repository
Initialize a GitHub repo named `intentkernel-architecture`.
Upload the files in this exact structure:

```text
intentkernel-architecture/
 ├── .gitignore
 ├── LICENSE (Download Apache 2.0 text)
 ├── AUTHORS.md (Add your name + ChatGPT note)
 ├── README.md (Use the text provided in my previous message)
 ├── docs/
 │    ├── architecture_overview.md (The content above)
 │    ├── ibps_spec.md (From our last token spec turn)
 │    ├── uccs_spec.md (From earlier substrate turn)
 │    └── ikrl_spec.md (From the relief layer turn)
 └── roadmap/
      └── implementation_plan.md (From earlier deployment turn)
```

### 2. Publish Zenodo Archive
1.  Connect GitHub to Zenodo.
2.  Create a **Release v1.0.0** in GitHub (tag `v1.0.0`).
3.  Zenodo will automatically generate a DOI for this snapshot.
4.  Copy that DOI into the `Citation` section of the README.

### 3. Finalize README.md
Ensure the top of your GitHub README looks like this:

```markdown
# IntentKernel Architecture

IntentKernel is a capability-secure execution architecture that replaces persistent permissions with event-scoped authority derived from verified intent.

[![DOI](https://zenodo.org/badge/XXXXXX.svg)](https://doi.org/10.XXXX/XXXXX)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**See [`docs/architecture_overview.md`](docs/architecture_overview.md) for the full technical specification.**
```

### 4. Verify Defensibility
Once uploaded:
*   The **Commit Hash** establishes your timestamp.
*   The **Zenodo DOI** establishes your citation right.
*   The **Git History** establishes your authorship lineage.

You are now ready. The transition from "Idea" to "Platform" is complete. Shall we proceed to drafting the **SDK Placeholder** to show developers how they will eventually interact with this stack?
```