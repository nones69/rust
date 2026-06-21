"""Lightweight REST API server for IP-Discrambler (v1.1)."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import yaml

from . import Discrambler

_client = Discrambler()
_OPENAPI_PATH = Path(__file__).resolve().parent / "openapi.yaml"


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def _json(self, code: int, payload: object) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/health":
            self._json(200, {"status": "ok", "service": "ip-discrambler"})
            return

        if parsed.path == "/openapi.json":
            if not _OPENAPI_PATH.is_file():
                self._json(404, {"error": "openapi spec not found"})
                return
            spec = yaml.safe_load(_OPENAPI_PATH.read_text(encoding="utf-8"))
            self._json(200, spec)
            return

        if parsed.path == "/openapi.yaml":
            if not _OPENAPI_PATH.is_file():
                self._json(404, {"error": "openapi spec not found"})
                return
            body = _OPENAPI_PATH.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "application/yaml")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/lookup":
            ip = (qs.get("ip") or [""])[0].strip()
            if not ip:
                self._json(400, {"error": "ip query parameter required"})
                return
            result = _client.lookup_sync(ip, include_rdns=True)
            self._json(200, result.to_dict())
            return

        if parsed.path == "/subnet":
            cidr = (qs.get("cidr") or [""])[0].strip()
            if not cidr:
                self._json(400, {"error": "cidr query parameter required"})
                return
            summary = _client.analyze_subnet(cidr)
            self._json(200, summary.to_dict())
            return

        self._json(
            404,
            {
                "error": "not found",
                "paths": ["/health", "/lookup", "/subnet", "/openapi.yaml", "/openapi.json"],
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._json(400, {"error": "invalid JSON body"})
            return

        if parsed.path == "/policy-check":
            ip = str(body.get("ip", "")).strip()
            if not ip:
                self._json(400, {"error": "ip required"})
                return
            result = _client.lookup_sync(ip, include_rdns=False)
            score = int(result.threat_score)
            allowed = score < 75
            self._json(
                200,
                {
                    "allowed": allowed,
                    "ip": result.ip,
                    "threat_score": score,
                    "country": result.country,
                    "org": result.org,
                    "asn": result.asn,
                    "discrambler": result.to_dict(),
                },
            )
            return

        self._json(404, {"error": "not found", "paths": ["/policy-check"]})


def run_server(host: str = "127.0.0.1", port: int = 8765) -> tuple[str, int]:
    server = HTTPServer((host, port), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return host, server.server_port


def serve_forever(host: str = "127.0.0.1", port: int = 8765) -> None:
    server = HTTPServer((host, port), _Handler)
    print(f"IP-Discrambler REST API on http://{host}:{port}")
    print("  GET  /health")
    print("  GET  /lookup?ip=8.8.8.8")
    print("  GET  /subnet?cidr=10.0.0.0/8")
    print("  GET  /openapi.yaml  (OpenAPI 3.0 spec)")
    print("  POST /policy-check  {\"ip\": \"8.8.8.8\"}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutdown")
        server.server_close()
