"""
IntentOS Control Surface — Logs API blueprint.
"""

from flask import Blueprint, jsonify, request, Response
from core import logger as log

logs_bp = Blueprint("logs", __name__)


@logs_bp.get("/logs")
def get_logs():
    level  = request.args.get("level")
    source = request.args.get("source")
    limit  = int(request.args.get("limit", 200))
    return jsonify(log.get_logs(level_filter=level, source_filter=source, limit=limit))


@logs_bp.delete("/logs")
def clear_logs():
    log.clear_logs()
    log.audit("api", "Log buffer cleared by user")
    return jsonify({"cleared": True})


@logs_bp.get("/logs/export")
def export_logs():
    try:
        data = log.export_logs()
        return Response(data, mimetype="application/x-ndjson",
                        headers={"Content-Disposition": "attachment; filename=intentos_logs.ndjson"})
    except PermissionError as e:
        return jsonify({"error": str(e)}), 403
