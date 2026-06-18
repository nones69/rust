"""
IntentOS Control Surface — Structured logging subsystem.

Log modes:
  judicial  — full trace with integrity hash per entry
  standard  — normal operation logs
  minimal   — errors and warnings only
  none      — developer sandbox (still buffers for session)
"""

import threading
import time
import hashlib
import json
from collections import deque
from . import config as cfg

_lock = threading.RLock()
_log_buffer: deque = deque(maxlen=2000)
_entry_counter = 0

LEVELS = {"DEBUG": 0, "INFO": 1, "WARN": 2, "ERROR": 3, "AUDIT": 4}


def _should_record(level: str) -> bool:
    mode = cfg.get_section("logging").get("mode", "standard")
    if mode == "judicial":
        return True
    if mode == "standard":
        return LEVELS.get(level, 1) >= LEVELS["INFO"]
    if mode == "minimal":
        return LEVELS.get(level, 1) >= LEVELS["WARN"]
    if mode == "none":
        return False
    return True


def _integrity_hash(entry: dict) -> str:
    """Judicial mode: each entry gets a SHA-256 hash of its content."""
    payload = json.dumps(
        {k: v for k, v in entry.items() if k != "hash"}, sort_keys=True
    ).encode()
    return hashlib.sha256(payload).hexdigest()[:16]


def log(level: str, source: str, message: str, data: dict | None = None) -> dict | None:
    global _entry_counter
    if not _should_record(level):
        return None

    with _lock:
        _entry_counter += 1
        ts = time.time()
        entry = {
            "id":      _entry_counter,
            "ts":      ts,
            "time":    time.strftime("%H:%M:%S", time.localtime(ts)),
            "level":   level,
            "source":  source,
            "message": message,
            "data":    data or {},
        }
        mode = cfg.get_section("logging").get("mode", "standard")
        if mode == "judicial":
            entry["hash"] = _integrity_hash(entry)

        _log_buffer.append(entry)
        return entry


def get_logs(level_filter: str | None = None,
             source_filter: str | None = None,
             limit: int = 200) -> list:
    with _lock:
        entries = list(_log_buffer)

    if level_filter:
        min_lvl = LEVELS.get(level_filter.upper(), 0)
        entries = [e for e in entries if LEVELS.get(e["level"], 0) >= min_lvl]
    if source_filter:
        entries = [e for e in entries if source_filter.lower() in e["source"].lower()]

    return entries[-limit:]


def clear_logs() -> None:
    with _lock:
        _log_buffer.clear()


def export_logs() -> str:
    """Return all logs as newline-delimited JSON."""
    if not cfg.get_section("logging").get("export_enabled", True):
        raise PermissionError("Log export is currently disabled.")
    with _lock:
        lines = [json.dumps(e) for e in _log_buffer]
    return "\n".join(lines)


# Convenience wrappers
def debug(source: str, msg: str, data: dict | None = None):
    return log("DEBUG", source, msg, data)

def info(source: str, msg: str, data: dict | None = None):
    return log("INFO", source, msg, data)

def warn(source: str, msg: str, data: dict | None = None):
    return log("WARN", source, msg, data)

def error(source: str, msg: str, data: dict | None = None):
    return log("ERROR", source, msg, data)

def audit(source: str, msg: str, data: dict | None = None):
    """Audit entries are always recorded regardless of log mode."""
    global _entry_counter
    with _lock:
        _entry_counter += 1
        ts = time.time()
        entry = {
            "id":      _entry_counter,
            "ts":      ts,
            "time":    time.strftime("%H:%M:%S", time.localtime(ts)),
            "level":   "AUDIT",
            "source":  source,
            "message": msg,
            "data":    data or {},
        }
        entry["hash"] = _integrity_hash(entry)
        _log_buffer.append(entry)
        return entry
