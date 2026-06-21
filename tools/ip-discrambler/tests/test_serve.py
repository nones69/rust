"""REST server smoke tests."""

import json
from http.client import HTTPConnection

from ip_discrambler.serve import run_server


def test_health_and_openapi():
    host, port = run_server("127.0.0.1", 0)
    conn = HTTPConnection(host, port, timeout=5)
    try:
        conn.request("GET", "/health")
        resp = conn.getresponse()
        assert resp.status == 200
        body = json.loads(resp.read())
        assert body["status"] == "ok"

        conn.request("GET", "/openapi.json")
        resp = conn.getresponse()
        assert resp.status == 200
        spec = json.loads(resp.read())
        assert spec["openapi"].startswith("3.")
        assert "/lookup" in spec["paths"]
    finally:
        conn.close()
