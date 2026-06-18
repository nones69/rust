"""
IntentOS — Cross-platform background daemon.

Starts the Flask control surface and keeps it alive.  Designed to run as:
  - A systemd service on Linux
  - A Windows service (via NSSM or the Windows installer wrapper)
  - A launchd agent on macOS (future)
  - A background process on Android (via Chaquopy / native layer)

Usage:
    python intentos_daemon.py [--port 5000] [--host 0.0.0.0]
"""

import argparse
import os
import sys
import signal
import logging
import threading
import time
import json
from pathlib import Path

# ------------------------------------------------------------------
# Paths
# ------------------------------------------------------------------

BASE_DIR   = Path(__file__).resolve().parent.parent   # repo root / platform/
LOG_DIR    = Path(os.environ.get("INTENTOS_LOG_DIR", Path.home() / ".intentos" / "logs"))
PID_FILE   = Path(os.environ.get("INTENTOS_PID",    Path.home() / ".intentos" / "daemon.pid"))
STATUS_FILE= Path(os.environ.get("INTENTOS_STATUS", Path.home() / ".intentos" / "status.json"))

LOG_DIR.mkdir(parents=True, exist_ok=True)
PID_FILE.parent.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------------------------
# Logging
# ------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "daemon.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("intentos.daemon")

# ------------------------------------------------------------------
# Platform detection
# ------------------------------------------------------------------

def detect_platform() -> str:
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith("darwin"):
        return "macos"
    return "unknown"

PLATFORM = detect_platform()

# ------------------------------------------------------------------
# Status file
# ------------------------------------------------------------------

def write_status(status: str, port: int, extra: dict | None = None) -> None:
    data = {
        "status":   status,
        "platform": PLATFORM,
        "port":     port,
        "pid":      os.getpid(),
        "uptime":   time.time(),
        **(extra or {}),
    }
    try:
        STATUS_FILE.write_text(json.dumps(data, indent=2))
    except OSError:
        pass


def read_status() -> dict:
    try:
        return json.loads(STATUS_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return {}

# ------------------------------------------------------------------
# PID management
# ------------------------------------------------------------------

def write_pid() -> None:
    PID_FILE.write_text(str(os.getpid()))

def remove_pid() -> None:
    try:
        PID_FILE.unlink()
    except OSError:
        pass

def is_running() -> bool:
    try:
        pid = int(PID_FILE.read_text().strip())
        if PLATFORM == "windows":
            import ctypes
            handle = ctypes.windll.kernel32.OpenProcess(0x400, False, pid)
            if handle:
                ctypes.windll.kernel32.CloseHandle(handle)
                return True
            return False
        else:
            os.kill(pid, 0)  # signal 0 = existence check
            return True
    except (OSError, ValueError, FileNotFoundError):
        return False

# ------------------------------------------------------------------
# Security monitor (lightweight, cross-platform)
# ------------------------------------------------------------------

class SecurityMonitor(threading.Thread):
    """
    Background thread that periodically checks for common security issues
    and records them in the IntentOS logger.
    """

    def __init__(self, interval: int = 60):
        super().__init__(daemon=True, name="SecurityMonitor")
        self.interval = interval
        self._stop_event = threading.Event()

    def run(self) -> None:
        log.info("Security monitor started (interval=%ds)", self.interval)
        while not self._stop_event.wait(self.interval):
            self._run_checks()

    def _run_checks(self) -> None:
        findings = []

        # Check 1: World-writable sensitive paths (Linux/macOS)
        if PLATFORM in ("linux", "macos"):
            sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
            for p in sensitive:
                try:
                    mode = os.stat(p).st_mode
                    if mode & 0o002:
                        findings.append({"severity": "HIGH",
                                          "check":    "world_writable",
                                          "path":     p})
                except OSError:
                    pass

        # Check 2: Open listening ports (basic)
        open_ports = _get_listening_ports()
        unexpected = [p for p in open_ports if p not in (22, 80, 443, 5000, 8080, 3000)]
        if unexpected:
            findings.append({"severity": "INFO",
                              "check":    "open_ports",
                              "ports":    unexpected[:10]})

        if findings:
            log.warning("Security scan findings: %s", findings)
            _record_security_event(findings)
        else:
            log.debug("Security scan: all clear")

    def stop(self) -> None:
        self._stop_event.set()


def _get_listening_ports() -> list[int]:
    """Return a list of TCP ports the local host is listening on."""
    ports = []
    try:
        if PLATFORM == "linux":
            with open("/proc/net/tcp") as fh:
                for line in fh.readlines()[1:]:
                    parts = line.split()
                    if len(parts) < 4:
                        continue
                    if parts[3] == "0A":  # LISTEN state
                        port_hex = parts[1].split(":")[1]
                        ports.append(int(port_hex, 16))
        elif PLATFORM == "windows":
            import subprocess
            out = subprocess.check_output(
                ["netstat", "-an"], text=True, stderr=subprocess.DEVNULL
            )
            for line in out.splitlines():
                if "LISTENING" in line:
                    parts = line.split()
                    if parts:
                        addr = parts[1]
                        port_str = addr.rsplit(":", 1)[-1]
                        try:
                            ports.append(int(port_str))
                        except ValueError:
                            pass
    except Exception:
        pass
    return ports


def _record_security_event(findings: list) -> None:
    """Write security events to the IntentOS audit log."""
    try:
        sys.path.insert(0, str(BASE_DIR))
        from core import logger
        for f in findings:
            logger.audit("security_monitor", f"Security finding: {f['check']}",
                         {"finding": f})
    except Exception as exc:
        log.debug("Could not write to IntentOS logger: %s", exc)

# ------------------------------------------------------------------
# Flask server runner
# ------------------------------------------------------------------

def run_flask(host: str, port: int) -> None:
    """Import and run the IntentOS Flask application."""
    platform_dir = BASE_DIR
    sys.path.insert(0, str(platform_dir))

    try:
        from app import app
        log.info("Starting IntentOS Control Surface on http://%s:%d", host, port)
        app.run(host=host, port=port, debug=False, use_reloader=False)
    except ImportError as exc:
        log.error("Could not import IntentOS app: %s", exc)
        log.error("Make sure dependencies are installed: pip install -r requirements.txt")
        sys.exit(1)

# ------------------------------------------------------------------
# Watchdog — restarts Flask if it crashes
# ------------------------------------------------------------------

class FlaskWatchdog(threading.Thread):
    def __init__(self, host: str, port: int):
        super().__init__(daemon=True, name="FlaskWatchdog")
        self.host = host
        self.port = port
        self._stop = threading.Event()

    def run(self) -> None:
        while not self._stop.is_set():
            t = threading.Thread(target=run_flask, args=(self.host, self.port),
                                 daemon=True, name="FlaskServer")
            t.start()
            t.join()
            if not self._stop.is_set():
                log.warning("Flask server exited unexpectedly — restarting in 5s")
                time.sleep(5)

    def stop(self) -> None:
        self._stop.set()

# ------------------------------------------------------------------
# Signal handling
# ------------------------------------------------------------------

_shutdown_event = threading.Event()

def _handle_signal(signum, _frame) -> None:
    log.info("Received signal %d — shutting down", signum)
    _shutdown_event.set()

# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="IntentOS background daemon")
    parser.add_argument("--host",    default="127.0.0.1",  help="Bind host")
    parser.add_argument("--port",    type=int, default=5000, help="HTTP port")
    parser.add_argument("--monitor-interval", type=int, default=60,
                        help="Security monitor interval in seconds")
    parser.add_argument("--no-monitor", action="store_true",
                        help="Disable security monitor")
    args = parser.parse_args()

    # Prevent duplicate instances
    if is_running():
        log.error("IntentOS daemon is already running (PID %s)", PID_FILE.read_text().strip())
        sys.exit(1)

    write_pid()
    write_status("starting", args.port)

    log.info("IntentOS daemon starting on %s (platform=%s, pid=%d)",
             PLATFORM, PLATFORM, os.getpid())

    # Register signal handlers
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _handle_signal)
        except (OSError, ValueError):
            pass  # Windows doesn't have all signals

    # Start security monitor
    monitor = None
    if not args.no_monitor:
        monitor = SecurityMonitor(interval=args.monitor_interval)
        monitor.start()

    # Start Flask watchdog
    watchdog = FlaskWatchdog(args.host, args.port)
    watchdog.start()

    write_status("running", args.port)
    log.info("IntentOS daemon running.  Control Surface → http://%s:%d",
             args.host, args.port)

    # Block until shutdown signal
    _shutdown_event.wait()

    log.info("Shutting down IntentOS daemon…")
    watchdog.stop()
    if monitor:
        monitor.stop()
    write_status("stopped", args.port)
    remove_pid()
    log.info("IntentOS daemon stopped.")


if __name__ == "__main__":
    main()
