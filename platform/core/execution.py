"""
IntentOS Control Surface — Orchestration execution engine.

Coordinates agent loops, skill invocations, and evidence pipeline
under the current configuration constraints.
"""

import uuid
import time
import threading
from . import config as cfg, logger as log, agents, skills, determinism, persona, evidence

_runs: dict[str, dict] = {}
_runs_lock = threading.RLock()


def start_run(prompt: str, evidence_ids: list | None = None) -> dict:
    """
    Kick off a full agent orchestration run.

    Returns a run record with status, trace, and (when complete) result.
    The run executes synchronously for simplicity; in production this
    would be async/threaded.
    """
    run_id    = str(uuid.uuid4())[:8]
    ev_ids    = evidence_ids or []
    ev_count  = len(ev_ids)
    ctx       = {"prompt": prompt, "evidence_count": ev_count, "run_id": run_id}

    exec_cfg  = cfg.get_section("execution")
    det_state = determinism.get_state()

    run = {
        "id":          run_id,
        "prompt":      prompt,
        "started_at":  time.time(),
        "status":      "running",
        "trace":       [],
        "result":      None,
        "hash":        None,
    }

    with _runs_lock:
        _runs[run_id] = run

    log.audit("execution", f"Run {run_id} started", {"prompt": prompt[:100], "ev_count": ev_count})

    try:
        # Determinism validation
        det_result = determinism.validate_execution(ctx)
        run["hash"] = det_result["hash"]
        _trace(run, "system", "determinism_check", det_result)

        # Persona gate on the overall execution
        p_check = persona.check_boundary("execute:full_run", ctx)
        _trace(run, "persona", "boundary_check", p_check)
        if not p_check["allowed"]:
            run["status"] = "blocked"
            run["result"] = {"error": f"Persona blocked: {p_check['reason']}"}
            log.warn("execution", f"Run {run_id} blocked by persona", p_check)
            return _public_run(run)

        # Ordered agent loop (respects enabled/disabled state and priority)
        agent_order = _get_agent_order()

        for agent_name in agent_order:
            if exec_cfg.get("step_through"):
                _trace(run, "execution", "step_pause", {"agent": agent_name})

            result = agents.run_agent(agent_name, ctx)
            _trace(run, "agents", f"agent_{agent_name}", result)

            if result.get("status") == "blocked":
                break   # persona/safety blocked — stop the loop

        # Skill invocations (run enabled skills that can run on this context)
        skill_state = cfg.get_section("skills")
        for skill_name, s_cfg in skill_state.items():
            if not s_cfg.get("enabled"):
                continue
            s_result = skills.invoke(skill_name, ctx)
            _trace(run, "skills", f"skill_{skill_name}", s_result)

        run["status"] = "completed"
        run["result"] = {
            "summary":    f"Run {run_id} completed successfully.",
            "prompt":     prompt,
            "ev_count":   ev_count,
            "det_mode":   det_state.get("mode", "strict"),
            "trace_len":  len(run["trace"]),
        }
        log.info("execution", f"Run {run_id} completed",
                 {"elapsed": round(time.time() - run["started_at"], 3)})

    except Exception as exc:
        run["status"] = "error"
        run["result"] = {"error": str(exc)}
        log.error("execution", f"Run {run_id} error: {exc}")

    run["finished_at"] = time.time()
    return _public_run(run)


def get_run(run_id: str) -> dict | None:
    with _runs_lock:
        r = _runs.get(run_id)
    return _public_run(r) if r else None


def list_runs(limit: int = 20) -> list:
    with _runs_lock:
        runs = sorted(_runs.values(), key=lambda r: r["started_at"], reverse=True)
    return [_public_run(r) for r in runs[:limit]]


# -----------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------

def _trace(run: dict, source: str, event: str, data: dict) -> None:
    run["trace"].append({
        "ts":     round(time.time() - run["started_at"], 3),
        "source": source,
        "event":  event,
        "data":   data,
    })


def _get_agent_order() -> list:
    agent_cfg = cfg.get_section("agents")
    enabled = [(name, a["priority"])
               for name, a in agent_cfg.items()
               if a.get("enabled", True)]
    enabled.sort(key=lambda x: x[1])
    return [name for name, _ in enabled]


def _public_run(r: dict | None) -> dict | None:
    return r  # All fields are already safe to expose
