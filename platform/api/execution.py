"""
IntentOS Control Surface — Execution API blueprint.
"""

from flask import Blueprint, jsonify, request
from core import execution, evidence, logger as log

execution_bp = Blueprint("execution", __name__)


def _json_error(msg: str, code: int = 400):
    return jsonify({"error": msg}), code


@execution_bp.post("/execute")
def run_execution():
    data       = request.get_json(force=True) or {}
    prompt     = (data.get("prompt") or "").strip()
    ev_ids     = data.get("evidence_ids") or []

    if not prompt:
        return _json_error("prompt is required")

    result = execution.start_run(prompt, evidence_ids=ev_ids)
    return jsonify(result)


@execution_bp.get("/runs")
def list_runs():
    limit = int(request.args.get("limit", 20))
    return jsonify(execution.list_runs(limit=limit))


@execution_bp.get("/runs/<run_id>")
def get_run(run_id: str):
    run = execution.get_run(run_id)
    if not run:
        return _json_error(f"Run {run_id!r} not found", 404)
    return jsonify(run)


# -----------------------------------------------------------------------
# Evidence upload / list
# -----------------------------------------------------------------------

@execution_bp.post("/evidence")
def upload_evidence():
    if "file" not in request.files:
        return _json_error("No file uploaded")
    f = request.files["file"]
    content = f.read()
    record = evidence.ingest(f.filename or "upload", content)
    return jsonify(record), 201


@execution_bp.get("/evidence")
def list_evidence():
    return jsonify(evidence.list_all())


@execution_bp.get("/evidence/<ev_id>")
def get_evidence(ev_id: str):
    r = evidence.get(ev_id)
    if not r:
        return _json_error(f"Evidence {ev_id!r} not found", 404)
    return jsonify(r)
