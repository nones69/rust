"""
IntentOS Control Surface — Persona boundary system.

Personas define what kinds of reasoning, output, and evidence interaction
the AI is permitted to perform.  Boundaries can be tightened or relaxed,
but the persona system itself can never be destroyed.
"""

from . import config as cfg, logger as log

PERSONA_DESCRIPTIONS = {
    "enforcement_enabled":    "Master switch — all persona rules active",
    "boundary_strictness":    "How strictly boundaries are enforced (1=loose, 5=strict)",
    "speculation_block":      "Block speculative / uncertain statements",
    "evidence_only_mode":     "Restrict all output to evidence-backed claims only",
    "emotional_content_block": "Block emotionally charged language",
    "creativity_block":       "Block creative/hypothetical reasoning",
    "override_enabled":       "[DEVELOPER ONLY] Allow persona override per request",
}


def get_state() -> dict:
    return cfg.get_section("persona")


def check_boundary(operation: str, context: dict | None = None) -> dict:
    """
    Check whether a given operation is permitted under the current persona.

    Returns:
        {"allowed": bool, "reason": str, "strictness": int}
    """
    state = get_state()

    if not state.get("enforcement_enabled", True):
        log.info("persona", f"Persona check bypassed (enforcement disabled): {operation}")
        return {"allowed": True, "reason": "enforcement_disabled", "strictness": 0}

    strictness = state.get("boundary_strictness", 3)
    reason = "allowed"
    allowed = True

    checks = {
        "speculate":       state.get("speculation_block", True),
        "hypothesize":     state.get("speculation_block", True),
        "express_emotion": state.get("emotional_content_block", False),
        "create_fiction":  state.get("creativity_block", False),
    }

    for trigger, blocked in checks.items():
        if blocked and trigger in operation.lower():
            allowed = False
            reason = f"blocked_by_persona_{trigger}"
            break

    if state.get("evidence_only_mode") and not (context or {}).get("has_evidence"):
        allowed = False
        reason = "evidence_only_mode_no_evidence"

    log.debug("persona", f"Boundary check: {operation}",
              {"allowed": allowed, "reason": reason, "strictness": strictness})

    return {"allowed": allowed, "reason": reason, "strictness": strictness}


def apply_patch(patch: dict, developer_mode: bool = False) -> dict:
    """Update persona configuration.  Developer-only fields require dev mode."""
    from .safety import validate_config_patch
    validate_config_patch("persona", patch)

    if "override_enabled" in patch and not developer_mode:
        log.warn("persona", "Attempted to enable persona override without developer mode")
        del patch["override_enabled"]

    updated = cfg.update_section("persona", patch)
    log.audit("persona", "Persona configuration updated", {"patch": patch})
    return updated
