"""IP-Discrambler integration for IntentOS control surface."""

from __future__ import annotations

import asyncio
import ipaddress
import sys
from pathlib import Path

from flask import Blueprint, jsonify, request

ip_policy_bp = Blueprint("ip_policy", __name__)

_DISCRAMBLER_ROOT = Path(__file__).resolve().parents[2] / "tools" / "ip-discrambler" / "src"
if str(_DISCRAMBLER_ROOT) not in sys.path:
    sys.path.insert(0, str(_DISCRAMBLER_ROOT))


def _local_verdict(ip: str) -> dict:
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return {"ip": ip, "allowed": False, "threat": "high", "reason": "invalid IP"}

    if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_multicast:
        return {
            "ip": ip,
            "allowed": addr.is_loopback,
            "threat": "critical" if not addr.is_loopback else "low",
            "reason": "reserved/private address",
        }
    return {"ip": ip, "allowed": True, "threat": "low", "reason": "public unicast"}


def _threat_score_from_result(result) -> int:
    score = 0
    for report in getattr(result, "threat_reports", []) or []:
        score = max(score, int(getattr(report, "score", 0) or 0))
    return score


def _enrich_ip(ip: str) -> dict:
    verdict = _local_verdict(ip)
    enriched = {"verdict": verdict, "discrambler": None}

    try:
        from ip_discrambler import Discrambler

        async def _run():
            client = Discrambler(timeout=8.0, max_concurrency=4)
            return await client.lookup(ip)

        result = asyncio.run(_run())
        score = _threat_score_from_result(result)
        enriched["discrambler"] = {
            "country": result.country,
            "org": result.org,
            "asn": result.asn,
            "threat_score": score,
            "errors": result.errors,
        }
        if score >= 75:
            verdict["allowed"] = False
            verdict["threat"] = "critical"
            verdict["reason"] = f"IP-Discrambler threat score {score}"
        elif score >= 50:
            verdict["threat"] = "high"
            verdict["reason"] = f"elevated threat score {score}"
    except Exception as exc:  # noqa: BLE001 — enrichment is optional
        enriched["discrambler_error"] = str(exc)

    return enriched


@ip_policy_bp.get("/ip/lookup")
def lookup_ip():
    ip = (request.args.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip query parameter required"}), 400
    return jsonify(_enrich_ip(ip))


@ip_policy_bp.post("/ip/policy-check")
def policy_check():
    payload = request.get_json(force=True) or {}
    ip = (payload.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "ip required"}), 400
    data = _enrich_ip(ip)
    return jsonify({"allowed": data["verdict"]["allowed"], **data})