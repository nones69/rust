"""
IntentOS Control Surface — Skill registry.

Skills are discrete capabilities exposed to agents.
Each skill can be independently enabled/disabled, domain-restricted,
and evidence-gated.
"""

from . import config as cfg, logger as log

SKILL_DESCRIPTIONS = {
    "ocr":            "Extract text from images and PDFs using optical character recognition.",
    "chronology":     "Build and validate chronological timelines from evidence.",
    "summarization":  "Produce concise summaries of long documents or agent outputs.",
    "classification": "Classify text, documents, or evidence by category.",
    "extraction":     "Extract structured data (entities, dates, amounts) from unstructured text.",
    "translation":    "Translate content between languages.",
    "reasoning":      "Apply logical inference and chain-of-thought reasoning.",
    "custom":         "User-defined custom skill (developer mode).",
}


def get_state() -> dict:
    return cfg.get_section("skills")


def apply_patch(skill_name: str, patch: dict, developer_mode: bool = False) -> dict:
    skills = cfg.get_section("skills")
    if skill_name == "custom" and not developer_mode:
        log.warn("skills", "Custom skill modification requires developer mode")
        raise PermissionError("Custom skill requires developer mode.")
    if skill_name not in skills:
        raise KeyError(f"Unknown skill: {skill_name!r}")
    from .safety import validate_config_patch
    validate_config_patch(f"skills.{skill_name}", patch)
    updated = cfg.update_section("skills", {skill_name: patch})
    log.audit("skills", f"Skill '{skill_name}' config updated", {"patch": patch})
    return updated[skill_name]


def can_use(skill_name: str, has_evidence: bool = False) -> dict:
    """
    Check whether a skill may be invoked.
    Returns {"allowed": bool, "reason": str}.
    """
    skills = cfg.get_section("skills")
    if skill_name not in skills:
        return {"allowed": False, "reason": "unknown_skill"}

    s = skills[skill_name]
    if not s.get("enabled", True):
        return {"allowed": False, "reason": "skill_disabled"}
    if s.get("requires_evidence") and not has_evidence:
        return {"allowed": False, "reason": "evidence_required"}

    return {"allowed": True, "reason": "ok"}


def invoke(skill_name: str, context: dict) -> dict:
    """Invoke a skill — checks permissions, then runs a simulation."""
    has_evidence = bool(context.get("evidence_count", 0))
    check = can_use(skill_name, has_evidence)
    if not check["allowed"]:
        log.warn("skills", f"Skill '{skill_name}' invocation denied", check)
        return {"skill": skill_name, "status": "denied", **check}

    log.info("skills", f"Skill '{skill_name}' invoked", {"context_keys": list(context.keys())})

    # Simulated skill outputs
    results = {
        "ocr":            {"pages_processed": 3, "text_chars": 4821},
        "chronology":     {"events": 7, "first_date": "2023-01-15", "last_date": "2024-11-20"},
        "summarization":  {"summary": "Key events documented across the period in question."},
        "classification": {"category": "legal_document", "confidence": 0.93},
        "extraction":     {"entities": ["John Doe", "Acme Corp"], "dates": ["2024-03-01"]},
        "translation":    {"detected_lang": "es", "translated_chars": 1200},
        "reasoning":      {"conclusion": "Evidence supports the primary claim.", "steps": 5},
        "custom":         {"output": "Custom skill executed."},
    }

    return {
        "skill":  skill_name,
        "status": "completed",
        "result": results.get(skill_name, {"output": "completed"}),
    }
