//! Kernel IPC dispatch integration — exercises `Kernel::dispatch` end-to-end.

use intentos_kernel::{
    IkCallEnvelope, IkSyscall, Intent, Kernel, OpenMode, TrustAnchor, wall_ms,
};
use uuid::Uuid;

fn read_intent(actor: &str) -> Intent {
    Intent {
        actor: actor.into(),
        resource: "file".into(),
        action: "read".into(),
        anchor: TrustAnchor::UiEvent,
        timestamp_ms: wall_ms(),
        metadata: Default::default(),
    }
}

fn open_envelope(token_jti: &str, path: &str) -> IkCallEnvelope {
    IkCallEnvelope {
        token_id: Uuid::parse_str(token_jti).unwrap(),
        call: IkSyscall::IkOpen {
            path: path.to_string(),
            mode: OpenMode::Read,
        },
        call_id: Uuid::new_v4(),
        timestamp_ms: wall_ms() as u128,
    }
}

/// Dispatching with an unknown token_id must be rejected before any VFS access.
#[test]
fn dispatch_rejects_unknown_token() {
    let kernel = Kernel::boot().expect("boot");
    let env = IkCallEnvelope {
        token_id: Uuid::new_v4(),
        call: IkSyscall::IkOpen {
            path: "secret.txt".into(),
            mode: OpenMode::Read,
        },
        call_id: Uuid::new_v4(),
        timestamp_ms: wall_ms() as u128,
    };
    let result = kernel.dispatch(env);
    assert!(result.is_err(), "unknown token must be rejected");
    let err = result.unwrap_err();
    assert!(
        err.contains("token verification failed"),
        "unexpected error: {err}"
    );
}

/// A token that was minted and registered must be accepted by dispatch.
/// (The VFS open itself may fail if /tmp/intentos_root does not exist, but
/// token verification must succeed — the test distinguishes the two outcomes.)
#[test]
fn dispatch_accepts_registered_token() {
    let kernel = Kernel::boot().expect("boot");
    let intent = read_intent("alice");
    let token = kernel.mint_token(intent.clone()).expect("mint");
    let jti = token.jti.clone();
    kernel.register_token(token).expect("register");

    let env = open_envelope(&jti, "notes.txt");
    let result = kernel.dispatch(env);

    // Token verification must pass. The only acceptable errors are VFS-level
    // (e.g. root directory not present in this test environment).
    match &result {
        Ok(_) => {}
        Err(e) => {
            assert!(
                !e.contains("token verification failed"),
                "token verification should have passed but got: {e}"
            );
        }
    }
}

/// IkClose on a valid token must return a close result (or a VFS-level error,
/// never a token-verification failure).
#[test]
fn dispatch_close_on_valid_token() {
    let kernel = Kernel::boot().expect("boot");
    let intent = read_intent("bob");
    let token = kernel.mint_token(intent).expect("mint");
    let jti = token.jti.clone();
    kernel.register_token(token).expect("register");

    let env = IkCallEnvelope {
        token_id: Uuid::parse_str(&jti).unwrap(),
        call: IkSyscall::IkClose { handle: Uuid::new_v4() },
        call_id: Uuid::new_v4(),
        timestamp_ms: wall_ms() as u128,
    };
    let result = kernel.dispatch(env);
    match &result {
        Ok(_) => {}
        Err(e) => {
            assert!(
                !e.contains("token verification failed"),
                "token verification should have passed but got: {e}"
            );
        }
    }
}
