"""
IntentOS Control Surface — Agent registry and lifecycle management.

Agents are named workers that operate within the orchestration loop.
Each agent can be enabled/disabled, prioritised, and given concurrency
and timeout limits.
"""

import threading
import time
import uuid
from . import config as cfg, logger as log, persona

AGENT_DESCRIPTIONS = {
    "strategist": "Plans the overall approach; allocates tasks to other agents.",
    "analyst":    "Deep-analyses evidence and produces structured findings.",
    "indexer":    "Indexes and retrieves evidence chunks for downstream agents.",
    "executor":   "Executes final actions based on the strategy and analysis.",
}


def get_state() -> dict:
    return cfg.get_section("agents")


def apply_patch(agent_name: str, patch: dict) -> dict:
    agents = cfg.get_section("agents")
    if agent_name not in agents:
        raise KeyError(f"Unknown agent: {agent_name!r}")
    from .safety import validate_config_patch
    validate_config_patch(f"agents.{agent_name}", patch)
    updated = cfg.update_section("agents", {agent_name: patch})
    log.audit("agents", f"Agent '{agent_name}' config updated", {"patch": patch})
    return updated[agent_name]


def run_agent(agent_name: str, context: dict) -> dict:
    """
    Simulate running a single agent step.
    Returns a trace entry with timing and outcome.
    """
    agents = cfg.get_section("agents")
    if agent_name not in agents:
        raise KeyError(f"Unknown agent: {agent_name!r}")

    agent_cfg = agents[agent_name]
    if not agent_cfg.get("enabled", True):
        log.warn("agents", f"Agent '{agent_name}' is disabled; skipping")
        return {"agent": agent_name, "status": "skipped", "reason": "disabled"}

    # Persona gate
    p_check = persona.check_boundary(f"agent:{agent_name}", context)
    if not p_check["allowed"]:
        log.warn("agents", f"Agent '{agent_name}' blocked by persona",
                 {"reason": p_check["reason"]})
        return {"agent": agent_name, "status": "blocked", "reason": p_check["reason"]}

    start = time.time()
    log.info("agents", f"Agent '{agent_name}' starting",
             {"priority": agent_cfg["priority"], "timeout": agent_cfg["timeout"]})

    # Simulated execution (replace with real agent logic)
    result = _simulate_agent(agent_name, context, agent_cfg)

    elapsed = round(time.time() - start, 3)
    log.info("agents", f"Agent '{agent_name}' completed in {elapsed}s",
             {"result_keys": list(result.keys()), "elapsed": elapsed})

    return {
        "agent":   agent_name,
        "status":  "completed",
        "elapsed": elapsed,
        "result":  result,
    }


def _simulate_agent(name: str, context: dict, agent_cfg: dict) -> dict:
    """
    Placeholder agent logic — produces deterministic simulated output.
    In a real deployment this would call the model/tool chain.
    """
    prompt = context.get("prompt", "")

    simulated = {
        "strategist": {
            "plan": [
                f"1. Analyse input: '{prompt[:60]}...' " if len(prompt) > 60 else f"1. Analyse input: '{prompt}'",
                "2. Index available evidence",
                "3. Run analyst pass",
                "4. Produce final report",
            ],
            "estimated_steps": 4,
        },
        "analyst": {
            "findings": [
                {"id": 1, "type": "key_fact",  "text": f"Primary subject identified in context"},
                {"id": 2, "type": "inference", "text": "Temporal ordering appears consistent"},
            ],
            "confidence": 0.87,
        },
        "indexer": {
            "indexed_chunks": context.get("evidence_count", 0),
            "index_size_kb":  context.get("evidence_count", 0) * 4,
        },
        "executor": {
            "output":  f"Execution complete for: {prompt[:80]}",
            "actions": ["generate_report"],
        },
    }

    return simulated.get(name, {"output": f"{name} executed successfully"})
