"""
IntentOS Control Surface — Control surface API blueprint.

Handles all configuration reads and writes for every subsystem.
"""

from flask import Blueprint, jsonify, request
from core import config as cfg, persona, agents, skills, determinism, safety, logger as log

control_bp = Blueprint("control", __name__)


def _json_error(msg: str, code: int = 400):
    return jsonify({"error": msg}), code


# -----------------------------------------------------------------------
# Global config
# -----------------------------------------------------------------------

@control_bp.get("/config")
def get_config():
    return jsonify(cfg.get_all())


@control_bp.post("/config/reset")
def reset_config():
    updated = cfg.reset_to_defaults()
    log.audit("api", "Configuration reset to defaults")
    return jsonify(updated)


@control_bp.get("/status")
def get_status():
    full = cfg.get_all()
    return jsonify({
        "mode":           full.get("mode", "simple"),
        "developer_mode": full.get("developer_mode", False),
        "safety_rules":   cfg.get_safety_rules(),
        "subsystems": {
            "persona":     full.get("persona", {}),
            "agents":      {k: {"enabled": v["enabled"]} for k, v in full.get("agents", {}).items()},
            "determinism": full.get("determinism", {}),
            "logging":     full.get("logging", {}),
        },
    })


# -----------------------------------------------------------------------
# Mode toggle (simple ↔ advanced)
# -----------------------------------------------------------------------

@control_bp.post("/config/mode")
def set_mode():
    data = request.get_json(force=True) or {}
    mode = data.get("mode")
    if mode not in ("simple", "advanced"):
        return _json_error("mode must be 'simple' or 'advanced'")
    cfg.update({"mode": mode})
    log.audit("api", f"UI mode switched to '{mode}'")
    return jsonify({"mode": mode})


# -----------------------------------------------------------------------
# Developer mode unlock
# -----------------------------------------------------------------------

@control_bp.post("/config/developer-mode")
def set_developer_mode():
    data = request.get_json(force=True) or {}
    enable = bool(data.get("enabled", False))
    confirm = data.get("confirm", False)
    if enable and not confirm:
        return _json_error("Must set confirm=true to enable developer mode", 403)
    cfg.update({"developer_mode": enable})
    log.audit("api", f"Developer mode {'enabled' if enable else 'disabled'}",
              {"by": "user"})
    return jsonify({"developer_mode": enable})


# -----------------------------------------------------------------------
# Persona controls
# -----------------------------------------------------------------------

@control_bp.get("/config/persona")
def get_persona():
    return jsonify({
        "state":        persona.get_state(),
        "descriptions": persona.PERSONA_DESCRIPTIONS,
    })


@control_bp.post("/config/persona")
def patch_persona():
    data = request.get_json(force=True) or {}
    dev  = cfg.get_all().get("developer_mode", False)
    try:
        updated = persona.apply_patch(data, developer_mode=dev)
        return jsonify(updated)
    except (PermissionError, safety.SafetyViolation) as e:
        return _json_error(str(e), 403)


# -----------------------------------------------------------------------
# Agent controls
# -----------------------------------------------------------------------

@control_bp.get("/config/agents")
def get_agents():
    return jsonify({
        "state":        agents.get_state(),
        "descriptions": agents.AGENT_DESCRIPTIONS,
    })


@control_bp.post("/config/agents/<agent_name>")
def patch_agent(agent_name: str):
    data = request.get_json(force=True) or {}
    try:
        updated = agents.apply_patch(agent_name, data)
        return jsonify(updated)
    except KeyError as e:
        return _json_error(str(e), 404)
    except safety.SafetyViolation as e:
        return _json_error(str(e), 403)


# -----------------------------------------------------------------------
# Skill controls
# -----------------------------------------------------------------------

@control_bp.get("/config/skills")
def get_skills():
    return jsonify({
        "state":        skills.get_state(),
        "descriptions": skills.SKILL_DESCRIPTIONS,
    })


@control_bp.post("/config/skills/<skill_name>")
def patch_skill(skill_name: str):
    data = request.get_json(force=True) or {}
    dev  = cfg.get_all().get("developer_mode", False)
    try:
        updated = skills.apply_patch(skill_name, data, developer_mode=dev)
        return jsonify(updated)
    except (KeyError, PermissionError) as e:
        return _json_error(str(e), 403)
    except safety.SafetyViolation as e:
        return _json_error(str(e), 403)


# -----------------------------------------------------------------------
# Determinism controls
# -----------------------------------------------------------------------

@control_bp.get("/config/determinism")
def get_determinism():
    return jsonify(determinism.get_state())


@control_bp.post("/config/determinism")
def patch_determinism():
    data = request.get_json(force=True) or {}
    dev  = cfg.get_all().get("developer_mode", False)
    try:
        updated = determinism.apply_patch(data, developer_mode=dev)
        return jsonify(updated)
    except (PermissionError, determinism.DeterminismViolation) as e:
        return _json_error(str(e), 403)


# -----------------------------------------------------------------------
# Evidence controls
# -----------------------------------------------------------------------

@control_bp.get("/config/evidence")
def get_evidence_config():
    return jsonify(cfg.get_section("evidence"))


@control_bp.post("/config/evidence")
def patch_evidence_config():
    data = request.get_json(force=True) or {}
    dev  = cfg.get_all().get("developer_mode", False)
    if data.get("transformation_mode") and not dev:
        return _json_error("transformation_mode requires developer mode", 403)
    try:
        safety.validate_config_patch("evidence", data)
        updated = cfg.update_section("evidence", data)
        return jsonify(updated)
    except safety.SafetyViolation as e:
        return _json_error(str(e), 403)


# -----------------------------------------------------------------------
# Logging controls
# -----------------------------------------------------------------------

@control_bp.get("/config/logging")
def get_logging_config():
    return jsonify(cfg.get_section("logging"))


@control_bp.post("/config/logging")
def patch_logging_config():
    data = request.get_json(force=True) or {}
    allowed_modes = ("judicial", "standard", "minimal", "none")
    if "mode" in data and data["mode"] not in allowed_modes:
        return _json_error(f"mode must be one of {allowed_modes}")
    if data.get("mode") == "none" and not cfg.get_all().get("developer_mode"):
        return _json_error("Log mode 'none' requires developer mode", 403)
    safety.validate_config_patch("logging", data)
    updated = cfg.update_section("logging", data)
    return jsonify(updated)


# -----------------------------------------------------------------------
# Execution controls
# -----------------------------------------------------------------------

@control_bp.get("/config/execution")
def get_execution_config():
    return jsonify(cfg.get_section("execution"))


@control_bp.post("/config/execution")
def patch_execution_config():
    data = request.get_json(force=True) or {}
    safety.validate_config_patch("execution", data)
    updated = cfg.update_section("execution", data)
    return jsonify(updated)
