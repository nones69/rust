use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn workspace_manifest() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate dir parent")
        .parent()
        .expect("workspace dir")
        .join("Cargo.toml")
}

fn current_bin(bin_name: &str) -> PathBuf {
    // Cargo sets CARGO_BIN_EXE_{name} (dashes→underscores) for same-package binaries.
    let env_key = format!("CARGO_BIN_EXE_{}", bin_name.replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        return PathBuf::from(path);
    }

    // Fall back to the workspace target directory — cargo builds all binaries before
    // running integration tests, so the binary should already be present.
    let mut path = workspace_manifest()
        .parent()
        .expect("workspace root")
        .join("target")
        .join("debug")
        .join(bin_name);
    if cfg!(windows) {
        path.set_extension("exe");
    }
    if path.exists() {
        return path;
    }

    // Last resort: invoke cargo build (may block if the parent cargo holds the lock).
    let status = Command::new("cargo")
        .arg("build")
        .arg("--quiet")
        .arg("-p")
        .arg(bin_name)
        .arg("--manifest-path")
        .arg(workspace_manifest())
        .status()
        .unwrap_or_else(|e| panic!("build {bin_name}: {e}"));
    assert!(status.success(), "cargo build -p {bin_name} failed");

    assert!(path.exists(), "missing built binary at {}", path.display());
    path
}

fn sibling_bin(bin_dir: &Path, bin_name: &str) -> PathBuf {
    let mut path = bin_dir.join(bin_name);
    if cfg!(windows) {
        path.set_extension("exe");
    }
    assert!(
        path.exists(),
        "expected sibling binary `{}` at {}",
        bin_name,
        path.display()
    );
    path
}

fn reserve_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("read local addr")
        .port()
}

fn wait_for_tcp(addr: &str) {
    let addr: SocketAddr = addr.parse().expect("parse socket addr");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "timed out waiting for {addr}");
        thread::sleep(Duration::from_millis(100));
    }
}

struct ChildGuard {
    child: Option<std::process::Child>,
}

impl ChildGuard {
    fn spawn(mut command: Command) -> Self {
        let child = command.spawn().expect("spawn daemon");
        Self { child: Some(child) }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn ikrl_cli_full_flow_hits_real_daemons() {
    let cli_bin = current_bin("ikrl-cli");
    let capd_bin = current_bin("capd");
    let intentd_bin = current_bin("intentd");
    let eventscope_bin = current_bin("eventscope");

    let capd_port = reserve_port();
    let intentd_port = reserve_port();
    let eventscope_port = reserve_port();

    let capd_addr = format!("tcp://127.0.0.1:{capd_port}");
    let intentd_addr = format!("tcp://127.0.0.1:{intentd_port}");
    let eventscope_addr = format!("tcp://127.0.0.1:{eventscope_port}");

    let _capd = ChildGuard::spawn({
        let mut cmd = Command::new(capd_bin);
        cmd.arg("--listen")
            .arg(&capd_addr)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    });
    wait_for_tcp(&format!("127.0.0.1:{capd_port}"));

    let _eventscope = ChildGuard::spawn({
        let mut cmd = Command::new(eventscope_bin);
        cmd.arg("--listen")
            .arg(&eventscope_addr)
            .arg("--capd-addr")
            .arg(&capd_addr)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    });
    wait_for_tcp(&format!("127.0.0.1:{eventscope_port}"));

    let _intentd = ChildGuard::spawn({
        let mut cmd = Command::new(intentd_bin);
        cmd.arg("--listen")
            .arg(&intentd_addr)
            .arg("--capd-addr")
            .arg(&capd_addr)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    });
    wait_for_tcp(&format!("127.0.0.1:{intentd_port}"));

    let output = Command::new(cli_bin)
        .arg("--intentd")
        .arg(&intentd_addr)
        .arg("--capd")
        .arg(&capd_addr)
        .arg("--eventscope")
        .arg(&eventscope_addr)
        .arg("full-flow")
        .arg("--resource")
        .arg("file")
        .arg("--action")
        .arg("read")
        .arg("--actor")
        .arg("integration-test")
        .output()
        .expect("run ikrl-cli full-flow");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(output.status.success(), "ikrl-cli failed\nstdout:\n{stdout}\nstderr:\n{stderr}");
    assert!(stdout.contains("TOKEN_CBOR_HEX="), "stdout:\n{stdout}");
    assert!(stderr.contains("capd verify:"), "stderr:\n{stderr}");
    assert!(stderr.contains("eventscope register:"), "stderr:\n{stderr}");
    assert!(stderr.contains("\"status\": \"Ok\""), "stderr:\n{stderr}");
}
