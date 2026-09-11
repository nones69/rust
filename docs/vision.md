# IntentKernel vision

**Daniel Kirk Owings, 2025**

This document is the **north-star pitch** for IntentKernel: what we are building toward,
why ambient authority is the wrong foundation, and how the architecture is meant to scale.

It is deliberately sharp. It is **not** a claim that the current repository already delivers
Stage‑5 guarantees. For what actually builds and demos today, see the root
[`README.md`](../README.md).

> **Reading rule:** sentences about *laws*, *stages*, and *structural intent* are design
> goals unless the README marks them as implemented. Words like *immune*, *impossible*,
> *formal property*, and *mathematically proven* are **rejected** as present-tense claims
> about this codebase.

---

## 1. The structural flaw: ambient authority

Every mainstream general-purpose OS — and most RTOS / firmware stacks derived from the same
lineage — still runs code with **ambient authority**: once a process starts, it inherits a
bundle of rights that persist for its lifetime (or until a coarse permission model partially
clips them).

That is the structural flaw.

Malware, ransomware, spyware, supply-chain implants, and many “zero-day → full compromise”
stories are not primarily failures of antivirus. They are consequences of giving running code
a standing permission to act.

Reactive controls (AV, EDR, firewalls, MAC frameworks, sandboxes, prompts, memory safety)
can raise the cost of abuse. They do **not** remove the root design choice. IntentKernel’s
thesis is that durable progress requires changing the **execution model**, not stacking more
guards on ambient rights.

Motivation, not a theorem: the industry has spent decades mitigating symptoms of ambient
authority. IntentKernel proposes to retire the symptom class by construction — **as a staged
program**, not as a slogan that the prototype is already finished.

---

## 2. Three laws of execution

IntentKernel is organized around three inviolable design laws. They are the same on a watch,
a phone, a laptop, or a rack — as a **model**, independent of which deployment stage you are on.

1. **Zero default authority.** A newly started execution context has no standing rights.
   It cannot usefully act until it is granted a capability.
2. **Event-scoped grants.** Authority is issued for a concrete intent (a specific action on a
   specific resource), not as a vague “this app may access the network forever.”
3. **Hard TTL / burn.** Capabilities expire and/or exhaust. Renewal is not ambient; it requires
   a fresh grant path consistent with policy and user/system intent.

These laws describe the **architecture we are driving toward**. The current Rust reference
runtime models pieces of this flow in-process (intent → policy → token → handle mediation).
It does **not** yet replace the host OS’s ambient process model.

### Email “Send” — one-shot capability (canonical example)

You tap **Send** on a message.

- The system mints a **single-use** capability: *send this exact message, once, to these
  recipients, within a short TTL*.
- The mailer may invoke that capability to perform the send.
- After use or expiry, the capability is burned. Background code that later gets ACE inside
  the mailer process does **not** inherit a standing “send anything to anyone” right from that
  grant.

That is the product intuition: **authority arrives with the user’s act**, not with process
start. Extending the same pattern to files, sensors, and network peers is the program.

---

## 3. Four-layer stack

IntentKernel is meant to ship as a layered program, not a single big-bang rewrite:

| Layer | Name | Role |
|-------|------|------|
| 1 | **IntentKernel** | Core execution / policy / capability semantics |
| 2 | **UCCS** | Universal Capability Computing Substrate — portable model & TCB strategy |
| 3 | **IKRL** | IntentKernel Relief Layer — overlays / shims on existing hosts |
| 4 | **IBPS** | Intent Broker / federation-oriented services for cross-device grants |

Specs and drafts live under [`docs/`](./) (`uccs_spec.md`, `ikrl_spec.md`, `ibp_spec.md`, etc.).
They are **design documents**. Legacy multi-process IKRL daemons exist in the Rust workspace as
experiments; they are not the primary verification path (that remains `intentos-*`).

---

## 4. Staged deployment (1–5)

Migration is incremental. Stages are **goals and waypoints**, not checkmarks for this repo.

1. **Stage 1 — Host overlay.** Governed applications / brokers on top of existing Windows,
   Linux, and macOS. The host kernel remains in the effective TCB.
2. **Stage 2 — Constrained devices.** Firmware / appliance-style deployments for new IoT and
   embedded classes where greenfield is feasible.
3. **Stage 3 — End-user native.** Laptops and mobile with deeper integration (still a program,
   not a present product in this repository).
4. **Stage 4 — Edge / cloud.** Server and edge roles with brokered, expiring authority between
   services.
5. **Stage 5 — Native substrate.** A purpose-built minimal substrate where the capability laws
   are the system’s native execution model — including the aspiration that **even privileged
   supervisory paths are designed under the same laws**, rather than a classical ambient root.
   **Stage 5 is a design destination.** This repository does **not** claim Stage 5 is shipped,
   formally verified, or that “the kernel already has no supervisor mode” as a present fact.

**Honest TCB note:** Stages 1–4 **include the host OS** (and often a large userspace) in the
practical trusted computing base. Do not read aspirational “~20k LOC TCB” tables as a statement
that this repo has an seL4-class verified microkernel, or that unverified line counts equal
assurance. seL4’s published verification story is a separate research artifact; IntentKernel
cites it as **inspiration for small, auditable kernels**, not as a property of this codebase.

---

## 5. Nine primitives (SDK north star)

The long-term developer surface aims for a tiny set of primitives (names illustrative):

| Primitive | Intent |
|-----------|--------|
| `draw` | Present pixels / UI |
| `wait_event` | Block until a scoped grant / event arrives |
| `get_resource` | Request one resource via policy / user intent |
| `put_resource` | Return or release a resource |
| `network_request` | One outbound request under a capability |
| `schedule_notification` | One user-visible notification under policy |
| `create_capability` | Mint / delegate a scoped token |
| `invoke_capability` | Perform the authorized action |
| `exit` | End the execution context |

The Rust prototype exposes a **richer** internal API (policy engine, tables, leases, demos).
Convergence toward a minimal public SDK is a goal, not a claim that only nine syscalls exist today.

---

## 6. Post-quantum stance (design choice)

IntentKernel’s **design stance** is PQC-first for long-lived and cross-device material: prefer
algorithms aligned with modern standards (e.g. NIST PQC) for tokens and transport as the
architecture matures.

**Today’s prototype:** `intentos-kernel` uses development-oriented **Ed25519** signing, with a
**PQC-shaped simulation** path for experimentation. Lab mTLS helpers use conventional TLS
stacks with ephemeral DevPki fixtures. That is intentional honesty — cryptographic *direction*
is not the same as cryptographic *completion*.

---

## 7. What “structural security” means here (without overclaim)

We aim for an architecture where **standing ambient rights are not the default**, so that many
classic malware *business models* (persist, scan disk, phone home freely, lateral movement with
inherited tokens) become **much harder to express**.

We do **not** claim in this repository that:

- malware is “impossible,”
- the system is “immune” (including to IMSI catchers or radio-layer attacks),
- perfect arbitrary code execution inside a process still implies “no malicious action is
  possible” as a theorem of the current code,
- formal verification is complete,
- Stages 1–4 magically remove the host from the TCB.

Those sentences belong to marketing mythology. IntentKernel’s bet is stricter: **change the
default**, measure progress stage by stage, and keep claims matched to artifacts.

---

## 8. Citation

Owings, Daniel Kirk. *IntentKernel* (research architecture and reference implementation), 2025.

Repository maturity: specification + prototype. See the root README for runnable paths and
explicit non-claims.
