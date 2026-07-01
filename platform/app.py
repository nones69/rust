"""
IntentOS Control Surface — Flask application entry point.

Run with:
    cd platform
    pip install -r requirements.txt
    python app.py

Then open http://localhost:5000 in your browser.

Security note
─────────────
This server **must** be bound to 127.0.0.1 (localhost) only.  It provides
unauthenticated access to daemon-control endpoints when no token is set, so
exposing it on any network interface — even a LAN — is an active security risk.

API authentication
──────────────────
Set the environment variable INTENTOS_API_TOKEN to a strong random secret.
All /api/* routes then require the header:

    Authorization: ******

If INTENTOS_API_TOKEN is not set, the server starts in WARNING mode: all
/api/* routes are accessible without a token, and a prominent warning is
printed at startup.  Never run without a token in a shared or networked
environment.
"""

import os
import sys

# Make sure `core` and `api` are importable when run from the platform/ dir
sys.path.insert(0, os.path.dirname(__file__))

from functools import wraps

from flask import Flask, jsonify, request, send_from_directory
from api.control    import control_bp
from api.daemons    import daemons_bp
from api.execution  import execution_bp
from api.ip_policy  import ip_policy_bp
from api.logs       import logs_bp

app = Flask(__name__, static_folder="ui", static_url_path="")

# ---------------------------------------------------------------------------
# Shared-secret bearer-token guard
# ---------------------------------------------------------------------------

_API_TOKEN: str | None = os.environ.get("INTENTOS_API_TOKEN") or None


def _require_api_token(f):
    """Decorator: reject requests that lack the correct bearer token.

    If INTENTOS_API_TOKEN is not set the check is skipped (dev convenience),
    but a warning is emitted at startup so operators know auth is disabled.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if _API_TOKEN is None:
            # Auth disabled — allow through (startup warning already printed).
            return f(*args, **kwargs)
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return jsonify({"error": "Unauthorized"}), 401
        if auth[len("Bearer "):] != _API_TOKEN:
            return jsonify({"error": "Forbidden"}), 403
        return f(*args, **kwargs)
    return wrapper


@app.before_request
def _api_auth_guard():
    """Apply bearer-token check to every /api/* route."""
    if request.path.startswith("/api/"):
        return _require_api_token(lambda: None)()


# Register API blueprints
app.register_blueprint(control_bp,    url_prefix="/api")
app.register_blueprint(daemons_bp,    url_prefix="/api")
app.register_blueprint(execution_bp,  url_prefix="/api")
app.register_blueprint(ip_policy_bp,  url_prefix="/api")
app.register_blueprint(logs_bp,       url_prefix="/api")


@app.route("/")
def index():
    return send_from_directory("ui", "index.html")


@app.route("/<path:path>")
def static_files(path):
    return send_from_directory("ui", path)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"\n  IntentOS Control Surface")
    print(f"  ─────────────────────────")
    print(f"  Open → http://localhost:{port}\n")
    if _API_TOKEN is None:
        print(
            "  ⚠  WARNING: INTENTOS_API_TOKEN is not set.\n"
            "     All /api/* routes are unauthenticated.\n"
            "     Set this variable before running in any shared or networked environment.\n"
        )
    else:
        print("  ✓  API bearer-token authentication enabled.\n")
    # Bind to loopback only — never expose the control plane to the network.
    app.run(host="127.0.0.1", port=port, debug=False)
