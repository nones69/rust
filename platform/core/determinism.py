"""
IntentOS Control Surface — Determinism engine.

Controls reproducibility guarantees for agent execution.

Modes:
  strict   — Fully deterministic. Same inputs always produce same outputs.
             Hash-locked execution.  Used in production and judicial review.
  relaxed  — Best-effort determinism.  Small variations in output permitted.
             Developer/research mode.
  sandbox  — Non-deterministic.  For testing only.  All constraints lifted.
             Requires explicit confirmation and developer mode.
"""

import hashlib
import json
import time
from . import config as cfg, logger as log


class DeterminismViolation(Exception):
    pass


def get_state() -> dict:
    return cfg.get_section("determinism")


def apply_patch(patch: dict, developer_mode: bool = False) -> dict:
    from .safety import validate_config_patch
    validate_config_patch("determinism", patch)

    mode = patch.get("mode", get_state().get("mode", "strict"))
    if mode == "sandbox" and not developer_mode:
        log.warn("determinism", "Sandbox mode requires developer mode — patch rejected")
        raise PermissionError("Sandbox determinism mode requires developer mode.")

    updated = cfg.update_section("determinism", patch)
    log.audit("determinism", f"Determinism mode updated to '{mode}'", {"patch": patch})
    return updated


def compute_execution_hash(inputs: dict) -> str:
    """
    Produce a stable hash of the inputs that uniquely identifies an
    execution context.  Used for hash-locked deterministic runs.
    """
    serialised = json.dumps(inputs, sort_keys=True, default=str).encode()
    return hashlib.sha256(serialised).hexdigest()


def validate_execution(inputs: dict, expected_hash: str | None = None) -> dict:
    """
    Validate that the execution context matches expectations.

    In strict mode, a stored hash (if provided) must match.
    In sandbox mode, always returns valid.
    """
    state = get_state()
    mode  = state.get("mode", "strict")

    if mode == "sandbox":
        log.debug("determinism", "Sandbox mode — validation skipped")
        return {"valid": True, "mode": mode, "hash": None}

    h = compute_execution_hash(inputs)

    if state.get("hash_locking") and expected_hash and h != expected_hash:
        log.error("determinism", "Hash mismatch — execution rejected",
                  {"expected": expected_hash, "got": h})
        raise DeterminismViolation(
            f"Execution hash mismatch.  Expected {expected_hash}, got {h}."
        )

    log.debug("determinism", f"Execution hash validated ({mode})", {"hash": h})
    return {"valid": True, "mode": mode, "hash": h}


def is_strict() -> bool:
    return get_state().get("mode", "strict") == "strict"


def is_sandbox() -> bool:
    return get_state().get("mode") == "sandbox"
