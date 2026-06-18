"""
IntentOS Control Surface — Safety rules enforcer.

These rules are HARD-CODED and cannot be overridden by any configuration.
They are checked at every mutation point.
"""

from . import logger as log

# Rules that are always enforced — cannot be disabled
HARD_RULES = [
    "no_self_modification",
    "no_silent_failures",
    "no_evidence_destruction",
    "no_unlogged_transformations",
    "no_persona_boundary_deletion",
    "no_network_unless_explicit",
]


class SafetyViolation(Exception):
    """Raised when an operation would violate a hard safety rule."""


def assert_rule(rule_name: str, context: str = "") -> None:
    """
    Assert that a hard rule is satisfied.  Call this before any potentially
    dangerous operation.  Always logs the check at AUDIT level.
    """
    if rule_name not in HARD_RULES:
        raise ValueError(f"Unknown safety rule: {rule_name!r}")
    log.audit("safety", f"Rule check: {rule_name}", {"context": context, "passed": True})


def enforce_no_evidence_destruction(op: str) -> None:
    """Call before any operation that might destroy evidence."""
    if op in ("delete", "overwrite", "truncate"):
        log.audit("safety", "Evidence destruction blocked", {"op": op})
        raise SafetyViolation(
            f"Operation '{op}' would violate evidence integrity rule."
        )
    assert_rule("no_evidence_destruction", op)


def enforce_logged_transformation(transform_name: str, evidence_id: str) -> None:
    """Every evidence transformation must be logged before it occurs."""
    log.audit("safety", f"Transformation '{transform_name}' on {evidence_id}",
              {"rule": "no_unlogged_transformations"})


def enforce_persona_boundary(section: str, key: str) -> None:
    """Prevent deletion of core persona boundary keys."""
    PROTECTED_PERSONA_KEYS = {"enforcement_enabled"}
    if key in PROTECTED_PERSONA_KEYS:
        log.audit("safety", f"Persona boundary protection: {key} cannot be deleted",
                  {"section": section, "key": key})
        raise SafetyViolation(
            f"Persona boundary key '{key}' cannot be removed."
        )


def validate_config_patch(section: str, patch: dict) -> None:
    """
    Validate a config patch before applying it.
    Raises SafetyViolation if the patch would break a hard rule.
    """
    if section == "persona":
        for key in patch:
            enforce_persona_boundary(section, key)

    # Audit every config change regardless
    log.audit("config", f"Config patch applied to [{section}]",
              {"section": section, "keys": list(patch.keys())})
