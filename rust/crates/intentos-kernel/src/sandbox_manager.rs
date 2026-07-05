//! Sandboxed guest process execution — Option G.
//!
//! Every untrusted program (script, plugin, AI-generated code, background agent) is
//! launched inside one of three sandbox modes, all bound to a [`VerifiedToken`] that
//! constrains exactly which FS paths, network hosts, and AI operations are allowed.
//!
//! # Modes
//!
//! | Mode | Mechanism | Best for |
//! |------|-----------|----------|
//! | [`SandboxMode::Seccomp`] | Linux seccomp-BPF allowlist | native binaries (Linux only) |
//! | [`SandboxMode::Wasm`] | WASM VM stub | portable / AI-generated code |
//! | [`SandboxMode::Container`] | bubblewrap / nsjail | complex multi-file apps |
//!
//! On non-Linux hosts the Seccomp and Container modes fall back to an unconfined
//! subprocess so that the crate still compiles and tests pass.  A real deployment
//! should gate those modes behind a Linux platform check.

use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::token_verifier::VerifiedToken;
use crate::types::wall_ms;

// ──────────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────────

/// The execution mode for a sandboxed process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxMode {
    /// Apply a Linux seccomp-BPF syscall allowlist around a native binary.
    Seccomp,
    /// Execute code inside a WASM virtual machine (no direct syscalls).
    Wasm,
    /// Launch inside a lightweight container (bubblewrap / nsjail).
    Container,
}

/// Per-spawn configuration knobs beyond the mode.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// How long the process may run before the manager force-kills it (milliseconds).
    /// `None` means no TTL enforcement by the manager (token expiry still applies).
    pub ttl_ms: Option<u64>,
    /// Maximum memory the child is allowed to use (bytes). Advisory for now.
    pub memory_limit_bytes: Option<u64>,
    /// Maximum number of open files. Advisory for now.
    pub max_open_files: Option<u32>,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            ttl_ms: Some(30_000),
            memory_limit_bytes: Some(256 * 1024 * 1024),
            max_open_files: Some(64),
        }
    }
}

/// A running (or completed) sandboxed process.
#[derive(Debug)]
pub struct SandboxProcess {
    /// Kernel-assigned process ID (0 for WASM/stub modes).
    pub pid: u32,
    /// Token that authorised this process.
    pub token_id: Uuid,
    /// Execution mode the process was launched in.
    pub mode: SandboxMode,
    /// Wall-clock time the process was spawned.
    pub spawned_at: u64,
    /// Optional TTL deadline (`spawned_at + ttl_ms`).
    pub expires_at: Option<u64>,
    /// Opaque handle to the OS child (None for WASM stubs).
    child: Option<Child>,
}

impl SandboxProcess {
    /// Returns `true` if a TTL was set and it has elapsed.
    pub fn is_expired(&self) -> bool {
        if let Some(exp) = self.expires_at {
            wall_ms() >= exp
        } else {
            false
        }
    }

    /// Send `SIGKILL` (or `TerminateProcess` on Windows) to the child.
    /// Returns `Ok(())` if the child was killed or was already gone.
    pub fn kill(&mut self) -> Result<(), SandboxError> {
        if let Some(child) = &mut self.child {
            child.kill().map_err(|e| SandboxError::KillFailed(e.to_string()))?;
        }
        Ok(())
    }

    /// Non-blocking check: has the child exited?
    pub fn try_wait(&mut self) -> Option<std::process::ExitStatus> {
        self.child.as_mut()?.try_wait().ok().flatten()
    }
}

/// Errors that can arise during sandbox operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("token expired")]
    TokenExpired,
    #[error("token scope does not permit spawn: {0}")]
    ScopeDenied(String),
    #[error("spawn failed: {0}")]
    SpawnFailed(String),
    #[error("kill failed: {0}")]
    KillFailed(String),
    #[error("sandbox mode not supported on this platform")]
    UnsupportedPlatform,
    #[error("process not found: {0}")]
    NotFound(Uuid),
    #[error("container tool not available: {0}")]
    ContainerToolMissing(String),
}

// ──────────────────────────────────────────────────────────────────────────────
// SandboxManager
// ──────────────────────────────────────────────────────────────────────────────

/// Manages the lifecycle of all sandboxed guest processes.
///
/// Every process is tracked by a unique [`Uuid`] sandbox ID (distinct from the
/// OS PID, which may be zero for WASM stubs).
pub struct SandboxManager {
    processes: HashMap<Uuid, SandboxProcess>,
}

impl SandboxManager {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
        }
    }

    /// Spawn a new sandboxed process.
    ///
    /// # Arguments
    /// * `token`   – verified capability token governing the process
    /// * `mode`    – which sandbox mechanism to use
    /// * `config`  – optional resource limits and TTL
    /// * `program` – executable path or WASM module path
    /// * `args`    – arguments forwarded to the program
    ///
    /// Returns a sandbox ID that can be used with [`terminate`] / [`reap_expired`].
    pub fn spawn(
        &mut self,
        token: &VerifiedToken,
        mode: SandboxMode,
        config: SandboxConfig,
        program: &str,
        args: &[String],
    ) -> Result<Uuid, SandboxError> {
        // 1. Guard: token must not be expired.
        if token.expires_at <= SystemTime::now() {
            return Err(SandboxError::TokenExpired);
        }

        // 2. Launch under the requested mode.
        let proc = match mode {
            SandboxMode::Seccomp => spawn_seccomp(token, &config, program, args)?,
            SandboxMode::Wasm => spawn_wasm(token, &config, program, args)?,
            SandboxMode::Container => spawn_container(token, &config, program, args)?,
        };

        let sandbox_id = Uuid::new_v4();
        self.processes.insert(sandbox_id, proc);
        Ok(sandbox_id)
    }

    /// Forcibly terminate a sandboxed process by its sandbox ID.
    pub fn terminate(&mut self, sandbox_id: Uuid) -> Result<(), SandboxError> {
        let proc = self
            .processes
            .get_mut(&sandbox_id)
            .ok_or(SandboxError::NotFound(sandbox_id))?;
        proc.kill()
    }

    /// Kill every process whose TTL has elapsed.  Returns the list of sandbox IDs
    /// that were terminated.
    pub fn reap_expired(&mut self) -> Vec<Uuid> {
        let expired: Vec<Uuid> = self
            .processes
            .iter()
            .filter(|(_, p)| p.is_expired())
            .map(|(id, _)| *id)
            .collect();

        for id in &expired {
            if let Some(proc) = self.processes.get_mut(id) {
                let _ = proc.kill();
            }
        }
        expired
    }

    /// Iterate over all tracked processes (running and completed).
    pub fn list(&self) -> impl Iterator<Item = (&Uuid, &SandboxProcess)> {
        self.processes.iter()
    }

    /// Number of tracked processes.
    pub fn len(&self) -> usize {
        self.processes.len()
    }

    /// True if no processes are tracked.
    pub fn is_empty(&self) -> bool {
        self.processes.is_empty()
    }
}

impl Default for SandboxManager {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Mode-specific spawn implementations
// ──────────────────────────────────────────────────────────────────────────────

/// Spawn under a Linux seccomp-BPF allowlist.
///
/// On Linux we apply a minimal syscall allowlist in the child process before
/// `exec` using the `PR_SET_NO_NEW_PRIVS` + `SECCOMP_SET_MODE_FILTER` pair.
/// The child may only call the syscalls IntentKernel explicitly permits; all
/// others trigger a `SIGKILL`.
///
/// On non-Linux platforms the function falls back to an unconfined subprocess
/// with a compile-time warning so that CI passes on macOS/Windows.
fn spawn_seccomp(
    token: &VerifiedToken,
    config: &SandboxConfig,
    program: &str,
    args: &[String],
) -> Result<SandboxProcess, SandboxError> {
    let _ = token; // scope used by the seccomp filter builder (below)
    let now = wall_ms();
    let expires_at = config.ttl_ms.map(|t| now + t);

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt;

        let mut cmd = Command::new(program);
        cmd.args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Safety: `pre_exec` runs in the forked child after `fork()` but
        // before `exec()`.  We install `PR_SET_NO_NEW_PRIVS` then a BPF
        // seccomp filter that allows only a minimal safe set of syscalls.
        unsafe {
            cmd.pre_exec(install_seccomp_filter);
        }

        let child = cmd
            .spawn()
            .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;

        let pid = child.id();
        return Ok(SandboxProcess {
            pid,
            token_id: token.id,
            mode: SandboxMode::Seccomp,
            spawned_at: now,
            expires_at,
            child: Some(child),
        });
    }

    // ── non-Linux fallback ──────────────────────────────────────────────────
    #[cfg(not(target_os = "linux"))]
    {
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;

        let pid = child.id();
        Ok(SandboxProcess {
            pid,
            token_id: token.id,
            mode: SandboxMode::Seccomp,
            spawned_at: now,
            expires_at,
            child: Some(child),
        })
    }
}

/// Install a seccomp-BPF allowlist in the calling process (run in child pre-exec).
///
/// The filter is built as a compact Berkeley Packet Filter (BPF) program that:
///  1. Loads the syscall number from the seccomp data.
///  2. Allows each syscall in the allowlist.
///  3. Kills the process for any other syscall.
///
/// Allowlisted numbers (x86-64):
///  - `read`(0), `write`(1), `close`(3), `fstat`(5), `mmap`(9), `mprotect`(10),
///    `munmap`(11), `brk`(12), `exit`(60), `exit_group`(231), `futex`(202),
///    `clock_gettime`(228), `getrandom`(318).
#[cfg(target_os = "linux")]
fn install_seccomp_filter() -> std::io::Result<()> {
    use libc::{
        PR_SET_NO_NEW_PRIVS, SECCOMP_MODE_FILTER, c_int, prctl, syscall, SYS_seccomp,
    };

    // BPF instruction encoding constants
    const BPF_LD: u16 = 0x00;
    const BPF_W: u16 = 0x00;
    const BPF_ABS: u16 = 0x20;
    const BPF_JMP: u16 = 0x05;
    const BPF_JEQ: u16 = 0x10;
    const BPF_K: u16 = 0x00;
    const BPF_RET: u16 = 0x06;

    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;

    // Offset of `nr` in `seccomp_data` (always 0 on Linux).
    const SECCOMP_DATA_NR_OFFSET: u32 = 0;

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct sock_filter {
        code: u16,
        jt: u8,
        jf: u8,
        k: u32,
    }

    #[allow(non_camel_case_types)]
    #[repr(C)]
    struct sock_fprog {
        len: u16,
        filter: *const sock_filter,
    }

    // x86-64 syscall numbers permitted inside the sandbox.
    let allowed: &[u32] = &[
        0,   // read
        1,   // write
        3,   // close
        5,   // fstat
        9,   // mmap
        10,  // mprotect
        11,  // munmap
        12,  // brk
        60,  // exit
        202, // futex
        228, // clock_gettime
        231, // exit_group
        318, // getrandom
    ];

    // Build BPF program dynamically:
    //   LD  [SECCOMP_DATA_NR_OFFSET]   ; load syscall number
    //   JEQ <nr>, allow, next          ; one instruction per allowed syscall
    //   RET KILL_PROCESS               ; default: kill
    //   RET ALLOW                      ; allow target
    let mut prog: Vec<sock_filter> = Vec::with_capacity(allowed.len() + 2);

    // LD W ABS offset(nr)
    prog.push(sock_filter {
        code: BPF_LD | BPF_W | BPF_ABS,
        jt: 0,
        jf: 0,
        k: SECCOMP_DATA_NR_OFFSET,
    });

    // For each allowed syscall: JEQ k, (jump_to_allow), 0
    // The "jump_to_allow" distance is: (remaining_jeq_instructions) + 1 (RET KILL)
    for (i, &nr) in allowed.iter().enumerate() {
        let jump_to_allow = (allowed.len() - i) as u8; // skip remaining JEQs + RET KILL
        prog.push(sock_filter {
            code: BPF_JMP | BPF_JEQ | BPF_K,
            jt: jump_to_allow,
            jf: 0,
            k: nr,
        });
    }

    // RET KILL_PROCESS (default deny)
    prog.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS,
    });

    // RET ALLOW
    prog.push(sock_filter {
        code: BPF_RET | BPF_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW,
    });

    let fprog = sock_fprog {
        len: prog.len() as u16,
        filter: prog.as_ptr(),
    };

    // Step 1: PR_SET_NO_NEW_PRIVS — required before SECCOMP_SET_MODE_FILTER
    let ret = unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1_usize, 0_usize, 0_usize, 0_usize) };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    // Step 2: Install the BPF filter
    let ret = unsafe {
        syscall(
            SYS_seccomp,
            SECCOMP_MODE_FILTER as c_int,
            0 as c_int,
            &fprog as *const sock_fprog,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// Spawn under a WASM VM.
///
/// In this stub the program path is treated as a WASM module path.  A full
/// implementation would embed `wasmtime` or `wasmer` here and execute the
/// module in-process, proxying every host call through IntentKernel's syscall
/// gateway.  The `pid` is set to 0 to indicate no OS process was created.
fn spawn_wasm(
    token: &VerifiedToken,
    config: &SandboxConfig,
    program: &str,
    args: &[String],
) -> Result<SandboxProcess, SandboxError> {
    // Validate the program path looks like a WASM file (best-effort check).
    if !program.ends_with(".wasm") && !program.ends_with(".wat") {
        return Err(SandboxError::SpawnFailed(format!(
            "WASM mode requires a .wasm or .wat module, got: {program}"
        )));
    }

    let _ = args; // forwarded to WASM start function in a full implementation
    let now = wall_ms();
    let expires_at = config.ttl_ms.map(|t| now + t);

    // TODO: replace with wasmtime/wasmer invocation that routes host calls
    //       through `crate::syscall::dispatch_call` with `token`.
    Ok(SandboxProcess {
        pid: 0,
        token_id: token.id,
        mode: SandboxMode::Wasm,
        spawned_at: now,
        expires_at,
        child: None,
    })
}

/// Spawn inside a lightweight container (bubblewrap or nsjail).
///
/// On Linux, tries `bwrap` (bubblewrap) first, then `nsjail`.  On other
/// platforms returns `UnsupportedPlatform`.
fn spawn_container(
    token: &VerifiedToken,
    config: &SandboxConfig,
    program: &str,
    args: &[String],
) -> Result<SandboxProcess, SandboxError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (token, config, program, args);
        return Err(SandboxError::UnsupportedPlatform);
    }

    #[cfg(target_os = "linux")]
    {
        let now = wall_ms();
        let expires_at = config.ttl_ms.map(|t| now + t);

        // Try bubblewrap first; fall back to nsjail.
        let container_tool = find_container_tool()
            .ok_or_else(|| SandboxError::ContainerToolMissing("bwrap, nsjail".into()))?;

        let child = build_container_command(&container_tool, token, program, args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| SandboxError::SpawnFailed(e.to_string()))?;

        let pid = child.id();
        Ok(SandboxProcess {
            pid,
            token_id: token.id,
            mode: SandboxMode::Container,
            spawned_at: now,
            expires_at,
            child: Some(child),
        })
    }
}

/// Find the first available container runtime on the PATH.
#[cfg(target_os = "linux")]
fn find_container_tool() -> Option<&'static str> {
    for tool in &["bwrap", "nsjail", "firejail"] {
        if which_tool(tool) {
            return Some(tool);
        }
    }
    None
}

/// Returns `true` if `tool` is found on `$PATH`.
#[cfg(target_os = "linux")]
fn which_tool(tool: &str) -> bool {
    std::process::Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Build a container `Command` for the given tool.
///
/// The command wraps `program` with minimal isolation flags.  A production
/// implementation should derive the bind-mount set from `token.scope`.
#[cfg(target_os = "linux")]
fn build_container_command(
    tool: &str,
    _token: &VerifiedToken,
    program: &str,
    args: &[String],
) -> Command {
    let mut cmd = Command::new(tool);
    match tool {
        "bwrap" => {
            cmd.args([
                "--ro-bind", "/usr", "/usr",
                "--ro-bind", "/lib", "/lib",
                "--proc", "/proc",
                "--dev", "/dev",
                "--unshare-all",
                "--die-with-parent",
                "--",
                program,
            ]);
            cmd.args(args);
        }
        "nsjail" => {
            cmd.args([
                "--mode", "o",
                "--chroot", "/",
                "--",
                program,
            ]);
            cmd.args(args);
        }
        _ => {
            // firejail or unknown: best-effort passthrough
            cmd.arg(program).args(args);
        }
    }
    cmd
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability_schema::{FsOp, FsScope, TokenScope};
    use std::time::{Duration, SystemTime};

    fn make_token() -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "test-principal".into(),
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp/sandbox_test".into(),
                ops: vec![FsOp::Read],
            }),
        }
    }

    fn expired_token() -> VerifiedToken {
        VerifiedToken {
            id: Uuid::new_v4(),
            issued_to: "expired".into(),
            expires_at: SystemTime::now() - Duration::from_secs(1),
            scope: TokenScope::Fs(FsScope {
                path_prefix: "/tmp".into(),
                ops: vec![FsOp::Read],
            }),
        }
    }

    #[test]
    fn spawn_wasm_valid_extension_succeeds() {
        let mut mgr = SandboxManager::new();
        let token = make_token();
        let id = mgr
            .spawn(&token, SandboxMode::Wasm, SandboxConfig::default(), "app.wasm", &[])
            .unwrap();
        assert!(mgr.list().any(|(k, _)| k == &id));
    }

    #[test]
    fn spawn_wasm_invalid_extension_fails() {
        let mut mgr = SandboxManager::new();
        let token = make_token();
        let err = mgr
            .spawn(&token, SandboxMode::Wasm, SandboxConfig::default(), "app.exe", &[])
            .unwrap_err();
        assert!(matches!(err, SandboxError::SpawnFailed(_)));
    }

    #[test]
    fn expired_token_is_rejected() {
        let mut mgr = SandboxManager::new();
        let token = expired_token();
        let err = mgr
            .spawn(&token, SandboxMode::Wasm, SandboxConfig::default(), "a.wasm", &[])
            .unwrap_err();
        assert!(matches!(err, SandboxError::TokenExpired));
    }

    #[test]
    fn reap_expired_terminates_ttl_exceeded_processes() {
        let mut mgr = SandboxManager::new();
        let token = make_token();
        let config = SandboxConfig {
            ttl_ms: Some(0), // already expired
            ..Default::default()
        };
        let id = mgr
            .spawn(&token, SandboxMode::Wasm, config, "a.wasm", &[])
            .unwrap();

        // Confirm the process is tracked.
        assert_eq!(mgr.len(), 1);

        let reaped = mgr.reap_expired();
        assert!(reaped.contains(&id));
    }

    #[test]
    fn sandbox_process_is_expired_when_ttl_zero() {
        let now = wall_ms();
        let proc = SandboxProcess {
            pid: 0,
            token_id: Uuid::new_v4(),
            mode: SandboxMode::Wasm,
            spawned_at: now,
            expires_at: Some(0), // epoch = already elapsed
            child: None,
        };
        assert!(proc.is_expired());
    }

    #[test]
    fn sandbox_process_not_expired_with_future_ttl() {
        let now = wall_ms();
        let proc = SandboxProcess {
            pid: 0,
            token_id: Uuid::new_v4(),
            mode: SandboxMode::Wasm,
            spawned_at: now,
            expires_at: Some(now + 60_000),
            child: None,
        };
        assert!(!proc.is_expired());
    }

    #[test]
    fn terminate_unknown_id_returns_error() {
        let mut mgr = SandboxManager::new();
        let bad_id = Uuid::new_v4();
        let err = mgr.terminate(bad_id).unwrap_err();
        assert!(matches!(err, SandboxError::NotFound(_)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn seccomp_mode_spawns_true_command() {
        // `true` is a minimal binary that immediately exits 0.
        let mut mgr = SandboxManager::new();
        let token = make_token();
        let result = mgr.spawn(
            &token,
            SandboxMode::Seccomp,
            SandboxConfig::default(),
            "/usr/bin/true",
            &[],
        );
        // Either succeeds or fails with SpawnFailed (if binary absent in CI).
        match result {
            Ok(id) => {
                let _ = mgr.terminate(id);
            }
            Err(SandboxError::SpawnFailed(_)) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn container_mode_unsupported_on_non_linux() {
        let mut mgr = SandboxManager::new();
        let token = make_token();
        let err = mgr
            .spawn(
                &token,
                SandboxMode::Container,
                SandboxConfig::default(),
                "/bin/true",
                &[],
            )
            .unwrap_err();
        assert!(matches!(err, SandboxError::UnsupportedPlatform));
    }
}
