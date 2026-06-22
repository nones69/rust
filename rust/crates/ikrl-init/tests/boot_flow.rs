use std::io::Write;
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
    if !path.exists() {
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

#[test]
fn ikrl_init_boots_kernel_and_shell_can_observe_it() {
    let init_bin = current_bin("ikrl-init");
    let bin_dir = init_bin.parent().expect("ikrl-init parent dir").to_path_buf();
    sibling_bin(&bin_dir, "capd");
    sibling_bin(&bin_dir, "intentd");
    sibling_bin(&bin_dir, "leasebroker");
    sibling_bin(&bin_dir, "eventscope");
    let shell_bin = sibling_bin(&bin_dir, "ikrl-shell");

    let capd_port = reserve_port();
    let intentd_port = reserve_port();
    let leasebroker_port = reserve_port();
    let eventscope_port = reserve_port();

    let capd_addr = format!("tcp://127.0.0.1:{capd_port}");
    let intentd_addr = format!("tcp://127.0.0.1:{intentd_port}");
    let leasebroker_addr = format!("tcp://127.0.0.1:{leasebroker_port}");
    let eventscope_addr = format!("tcp://127.0.0.1:{eventscope_port}");

    let mut init = Command::new(&init_bin)
        .arg("--bin-dir")
        .arg(&bin_dir)
        .arg("--capd-addr")
        .arg(&capd_addr)
        .arg("--intentd-addr")
        .arg(&intentd_addr)
        .arg("--leasebroker-addr")
        .arg(&leasebroker_addr)
        .arg("--eventscope-addr")
        .arg(&eventscope_addr)
        .env("RUST_LOG", "info")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ikrl-init");

    wait_for_tcp(&format!("127.0.0.1:{capd_port}"));
    wait_for_tcp(&format!("127.0.0.1:{intentd_port}"));
    wait_for_tcp(&format!("127.0.0.1:{leasebroker_port}"));
    wait_for_tcp(&format!("127.0.0.1:{eventscope_port}"));

    let mut shell = Command::new(shell_bin)
        .arg("--intentd")
        .arg(&intentd_addr)
        .arg("--capd")
        .arg(&capd_addr)
        .arg("--leasebroker")
        .arg(&leasebroker_addr)
        .arg("--eventscope")
        .arg(&eventscope_addr)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ikrl-shell");

    {
        let stdin = shell.stdin.as_mut().expect("ikrl-shell stdin");
        stdin
            .write_all(b"status\nlogout\n")
            .expect("write shell commands");
        stdin.flush().expect("flush shell commands");
    }

    let shell_output = shell.wait_with_output().expect("wait for ikrl-shell");
    let shell_stdout = String::from_utf8_lossy(&shell_output.stdout);
    let shell_stderr = String::from_utf8_lossy(&shell_output.stderr);

    assert!(shell_output.status.success(), "ikrl-shell failed: {shell_stderr}");
    assert!(shell_stdout.contains("intentd") && shell_stdout.contains(&intentd_addr));
    assert!(shell_stdout.contains("capd") && shell_stdout.contains(&capd_addr));
    assert!(
        shell_stdout.contains("leasebroker") && shell_stdout.contains(&leasebroker_addr)
    );
    assert!(
        shell_stdout.contains("eventscope") && shell_stdout.contains(&eventscope_addr)
    );
    assert!(shell_stdout.contains("ikrl-shell     active"));
    assert!(shell_stdout.contains("ikrl-ai") && shell_stdout.contains("down"));
    assert!(shell_stdout.contains("ikrl-fs") && shell_stdout.contains("down"));

    let _ = init.kill();
    let init_output = init.wait_with_output().expect("wait for ikrl-init");
    let init_stdout = String::from_utf8_lossy(&init_output.stdout);
    let init_stderr = String::from_utf8_lossy(&init_output.stderr);

    assert!(
        init_stdout.contains("Shell:") && init_stdout.contains("ikrl-shell"),
        "missing shell launch hint in stdout: {init_stdout}"
    );
    assert!(
        init_stderr.contains("IntentOS boot complete") || init_stdout.contains("daemons running"),
        "missing boot completion signal\nstdout:\n{init_stdout}\nstderr:\n{init_stderr}"
    );
}
