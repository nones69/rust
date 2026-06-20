"""IntentKernel daemon health and status API."""

from __future__ import annotations

import socket
from flask import Blueprint, jsonify

daemons_bp = Blueprint("daemons", __name__)

DAEMON_PORTS = {
    "capd": 9101,
    "intentd": 9100,
    "leasebroker": 9102,
    "eventscope": 9103,
    "ikrl_ai": 9200,
    "ikrl_bridge": 9300,
}


def _tcp_reachable(host: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


@daemons_bp.get("/daemons/health")
def daemon_health():
    host = "127.0.0.1"
    statuses = {
        name: {"port": port, "up": _tcp_reachable(host, port)}
        for name, port in DAEMON_PORTS.items()
    }
    core = ["capd", "intentd", "leasebroker", "eventscope"]
    ready = all(statuses[n]["up"] for n in core)
    return jsonify({"ready": ready, "daemons": statuses})


@daemons_bp.get("/daemons/ports")
def daemon_ports():
    return jsonify(DAEMON_PORTS)