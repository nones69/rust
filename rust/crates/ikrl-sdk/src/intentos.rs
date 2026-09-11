//! IntentOS in-process backend for the nine primitives.

use crate::{InvokeResult, SdkError};
use intentos_kernel::{
    wall_ms, Handle, Intent, Kernel, SyscallOp, SyscallRequest, SyscallResult, Token, TrustAnchor,
};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// In-process IntentOS SDK session.
///
/// Holds a shared [`Kernel`] and an event queue used by [`wait_event`](Self::wait_event).
pub struct IntentOsRuntime {
    kernel: Arc<Kernel>,
    actor: String,
    /// Grants pushed for wait_event (UI / broker simulation).
    events: Mutex<VecDeque<Token>>,
    exited: Mutex<bool>,
}

impl IntentOsRuntime {
    /// Boot a fresh in-process kernel for this actor.
    pub fn boot(actor: impl Into<String>) -> Result<Self, SdkError> {
        let kernel = Kernel::boot().map_err(|e| SdkError::Invalid(e.to_string()))?;
        Ok(Self {
            kernel: Arc::new(kernel),
            actor: actor.into(),
            events: Mutex::new(VecDeque::new()),
            exited: Mutex::new(false),
        })
    }

    /// Wrap an existing kernel (tests / IntentOS shell sharing).
    pub fn from_kernel(kernel: Arc<Kernel>, actor: impl Into<String>) -> Self {
        Self {
            kernel,
            actor: actor.into(),
            events: Mutex::new(VecDeque::new()),
            exited: Mutex::new(false),
        }
    }

    pub fn kernel(&self) -> &Kernel {
        &self.kernel
    }

    pub fn actor(&self) -> &str {
        &self.actor
    }

    fn ensure_alive(&self) -> Result<(), SdkError> {
        if *self.exited.lock().unwrap() {
            Err(SdkError::Exited)
        } else {
            Ok(())
        }
    }

    fn make_intent(&self, resource: &str, action: &str, anchor: TrustAnchor) -> Intent {
        Intent {
            actor: self.actor.clone(),
            resource: resource.to_string(),
            action: action.to_string(),
            anchor,
            timestamp_ms: wall_ms(),
            metadata: Default::default(),
        }
    }

    /// Mint with user confirmation when policy outcome is Confirm (e.g. network).
    fn mint(&self, intent: Intent) -> Result<Token, SdkError> {
        self.ensure_alive()?;
        let decision = self.kernel.submit_intent(intent.clone());
        if !decision.allowed {
            return Err(SdkError::IntentDenied(decision.reason));
        }
        // High-risk intents need confirmation under Medium profile — treat
        // UiEvent-backed SDK calls as user-confirmed intent.
        self.kernel
            .mint_token_confirmed(intent, true)
            .map_err(|e| SdkError::IntentDenied(e.to_string()))
    }

    fn register(&self, token: &Token) -> Result<Handle, SdkError> {
        self.kernel
            .register_token(token.clone())
            .map_err(|e| SdkError::CapabilityMissing(e.to_string()))
    }

    fn syscall(
        &self,
        handle: Handle,
        op: SyscallOp,
        target: &str,
        payload: Vec<u8>,
    ) -> Result<InvokeResult, SdkError> {
        match self.kernel.syscall(
            handle,
            SyscallRequest {
                op,
                target: target.to_string(),
                payload,
            },
        ) {
            SyscallResult::Allowed {
                remaining_uses,
                kind,
            } => Ok(InvokeResult {
                remaining_uses,
                detail: format!("allowed {kind:?}"),
            }),
            SyscallResult::Denied(reason) => Err(SdkError::SyscallDenied(reason)),
        }
    }

    // ── 1. draw ───────────────────────────────────────────────────────────

    /// Present pixels under a one-shot `display/draw` capability.
    pub fn draw(&self, framebuffer: &[u8]) -> Result<InvokeResult, SdkError> {
        let token = self.mint(self.make_intent("display", "draw", TrustAnchor::UiEvent))?;
        let handle = self.register(&token)?;
        self.syscall(handle, SyscallOp::Draw, "framebuffer", framebuffer.to_vec())
    }

    // ── 2. wait_event ─────────────────────────────────────────────────────

    /// Push a grant into the wait queue (broker / UI simulation).
    pub fn push_event(&self, token: Token) {
        self.events.lock().unwrap().push_back(token);
    }

    /// Block until a queued grant arrives or `timeout` elapses.
    pub fn wait_event(&self, timeout: Duration) -> Result<Option<Token>, SdkError> {
        self.ensure_alive()?;
        let start = Instant::now();
        loop {
            if let Some(tok) = self.events.lock().unwrap().pop_front() {
                return Ok(Some(tok));
            }
            if start.elapsed() >= timeout {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    // ── 3. get_resource ───────────────────────────────────────────────────

    /// Request one resource via policy + mint (does not register).
    pub fn get_resource(&self, resource: &str, action: &str) -> Result<Token, SdkError> {
        self.mint(self.make_intent(resource, action, TrustAnchor::UiEvent))
    }

    // ── 4. put_resource ───────────────────────────────────────────────────

    /// Release a capability by revoking its JTI.
    pub fn put_resource(&self, token: &Token) -> Result<(), SdkError> {
        self.ensure_alive()?;
        let _ = self.kernel.revoke_jti(&token.jti, &self.actor);
        Ok(())
    }

    // ── 5. network_request ────────────────────────────────────────────────

    /// One outbound request under `network/connect` (maps to NetSend kind).
    pub fn network_request(&self, destination: &str, payload: &[u8]) -> Result<Vec<u8>, SdkError> {
        if destination.trim().is_empty() {
            return Err(SdkError::Invalid("empty destination".into()));
        }
        let token = self.mint(self.make_intent("network", "connect", TrustAnchor::UiEvent))?;
        let handle = self.register(&token)?;
        let _ = self.syscall(handle, SyscallOp::Send, destination, payload.to_vec())?;
        // Prototype: no real host socket — echo a mediated response.
        Ok(format!("mediated-response from {destination}").into_bytes())
    }

    // ── 6. schedule_notification ──────────────────────────────────────────

    /// Schedule one user-visible notification under policy.
    pub fn schedule_notification(&self, title: &str, body: &str) -> Result<InvokeResult, SdkError> {
        let token = self.mint(self.make_intent("display", "notification", TrustAnchor::UiEvent))?;
        let handle = self.register(&token)?;
        let payload = format!("{title}\n{body}").into_bytes();
        self.syscall(handle, SyscallOp::Notify, "notification", payload)
    }

    // ── 7. create_capability ──────────────────────────────────────────────

    /// Mint / delegate a scoped token (explicit create path).
    pub fn create_capability(
        &self,
        resource: &str,
        action: &str,
        anchor: TrustAnchor,
    ) -> Result<Token, SdkError> {
        self.mint(self.make_intent(resource, action, anchor))
    }

    // ── 8. invoke_capability ──────────────────────────────────────────────

    /// Register `token` and perform a mediated syscall.
    pub fn invoke_capability(
        &self,
        token: &Token,
        syscall: &str,
        target: &str,
        payload: &[u8],
    ) -> Result<InvokeResult, SdkError> {
        self.ensure_alive()?;
        let handle = self.register(token)?;
        let op = SyscallOp::parse(syscall);
        self.syscall(handle, op, target, payload.to_vec())
    }

    // ── 9. exit ───────────────────────────────────────────────────────────

    /// End the SDK session. Does not call `process::exit` (test-friendly).
    ///
    /// Use [`exit_process`](Self::exit_process) when a real process stop is required.
    pub fn exit(&self, _code: i32) -> Result<(), SdkError> {
        let mut g = self.exited.lock().unwrap();
        *g = true;
        Ok(())
    }

    /// Terminate the process after marking the session exited.
    pub fn exit_process(&self, code: i32) -> ! {
        let _ = self.exit(code);
        std::process::exit(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn nine_primitives_happy_path() {
        let sdk = Arc::new(IntentOsRuntime::boot("sdk-demo").unwrap());

        // 1 draw
        let d = sdk.draw(b"pixels").unwrap();
        assert_eq!(d.remaining_uses, 0);

        // 3 get_resource + 8 invoke
        let tok = sdk.get_resource("file", "read").unwrap();
        let inv = sdk
            .invoke_capability(&tok, "read", "notes.txt", &[])
            .unwrap();
        assert_eq!(inv.remaining_uses, 0);

        // burn / replay: same token cannot be registered twice
        let tok2 = sdk.get_resource("file", "write").unwrap();
        let _ = sdk
            .invoke_capability(&tok2, "write", "notes.txt", b"x")
            .unwrap();
        let again = sdk.invoke_capability(&tok2, "write", "notes.txt", b"y");
        assert!(again.is_err());

        // 5 network
        let resp = sdk.network_request("example.test", b"ping").unwrap();
        assert!(String::from_utf8_lossy(&resp).contains("example.test"));

        // 6 notification
        sdk.schedule_notification("hi", "body").unwrap();

        // 7 create_capability
        let cap = sdk
            .create_capability("file", "read", TrustAnchor::UiEvent)
            .unwrap();
        assert_eq!(cap.scope.resource, "file");

        // 4 put_resource
        let release = sdk.get_resource("file", "read").unwrap();
        sdk.put_resource(&release).unwrap();
        assert!(sdk.kernel().revocation_count() >= 1);

        // 2 wait_event (queued grant + concurrent push)
        let grant = sdk
            .create_capability("file", "read", TrustAnchor::UiEvent)
            .unwrap();
        sdk.push_event(grant);
        assert!(sdk.wait_event(Duration::from_millis(50)).unwrap().is_some());

        let pusher = Arc::clone(&sdk);
        let handle = thread::spawn(move || {
            thread::sleep(Duration::from_millis(20));
            let g = pusher
                .create_capability("file", "read", TrustAnchor::UiEvent)
                .unwrap();
            pusher.push_event(g);
        });
        assert!(sdk.wait_event(Duration::from_secs(1)).unwrap().is_some());
        handle.join().unwrap();

        // 9 exit
        sdk.exit(0).unwrap();
        assert_eq!(sdk.draw(b"nope"), Err(SdkError::Exited));
    }

    #[test]
    fn default_deny_unknown_resource() {
        let sdk = IntentOsRuntime::boot("sdk-demo").unwrap();
        let err = sdk.get_resource("totally-unknown", "explode").unwrap_err();
        assert!(matches!(err, SdkError::IntentDenied(_)));
    }

    #[test]
    fn wait_event_timeout() {
        let sdk = IntentOsRuntime::boot("sdk-demo").unwrap();
        let none = sdk.wait_event(Duration::from_millis(30)).unwrap();
        assert!(none.is_none());
    }

    #[test]
    fn low_anchor_denied() {
        let sdk = IntentOsRuntime::boot("sdk-demo").unwrap();
        let err = sdk
            .create_capability("file", "read", TrustAnchor::None)
            .unwrap_err();
        assert!(matches!(err, SdkError::IntentDenied(_)));
    }
}
