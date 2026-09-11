//! # ikrl-sdk — nine IntentKernel primitives
//!
//! **Primary path (default):** in-process [`IntentOsRuntime`] over
//! [`intentos_kernel::Kernel`] — mint / verify / register / dispatch with
//! default-deny policy. This is the working IntentOS prototype path.
//!
//! **Legacy path (`remote` feature):** JSON-RPC to `intentd` / `eventscope`
//! daemons ([`remote::IkrlRuntime`]).
//!
//! | # | Primitive | Behavior (IntentOS path) |
//! |---|-----------|---------------------------|
//! | 1 | [`draw`](IntentOsRuntime::draw) | Mint `display/draw`, invoke once |
//! | 2 | [`wait_event`](IntentOsRuntime::wait_event) | Wait for a queued grant or timeout |
//! | 3 | [`get_resource`](IntentOsRuntime::get_resource) | Policy + mint for resource/action |
//! | 4 | [`put_resource`](IntentOsRuntime::put_resource) | Revoke token JTI (release) |
//! | 5 | [`network_request`](IntentOsRuntime::network_request) | Mint `network/connect`, one Send |
//! | 6 | [`schedule_notification`](IntentOsRuntime::schedule_notification) | Mint `display/notification`, Notify |
//! | 7 | [`create_capability`](IntentOsRuntime::create_capability) | Explicit mint / delegate |
//! | 8 | [`invoke_capability`](IntentOsRuntime::invoke_capability) | Register + mediated syscall |
//! | 9 | [`exit`](IntentOsRuntime::exit) | Mark session ended (no silent ambient work) |
//!
//! Prototype-honest: this does **not** claim host-wide enforcement. Overlay
//! Stages 1–2 are separate crates/docs.

#![cfg_attr(not(feature = "intentos"), allow(dead_code))]

use thiserror::Error;

#[cfg(feature = "intentos")]
mod intentos;
#[cfg(feature = "intentos")]
pub use intentos::IntentOsRuntime;

#[cfg(feature = "remote")]
pub mod remote;
#[cfg(feature = "remote")]
pub use remote::IkrlRuntime;

/// SDK error surface shared by backends.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SdkError {
    #[error("intent denied: {0}")]
    IntentDenied(String),
    #[error("capability missing: {0}")]
    CapabilityMissing(String),
    #[error("syscall denied: {0}")]
    SyscallDenied(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("session already exited")]
    Exited,
    #[error("timeout waiting for event")]
    Timeout,
    #[error("invalid argument: {0}")]
    Invalid(String),
}

/// Result of a mediated invoke (prototype payload).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvokeResult {
    pub remaining_uses: u32,
    pub detail: String,
}
