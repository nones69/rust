"""
IntentOS Control Surface — Flask application entry point.

Run with:
    cd platform
    pip install -r requirements.txt
    python app.py

Then open http://localhost:5000 in your browser.
"""

import os
import sys

# Make sure `core` and `api` are importable when run from the platform/ dir
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, send_from_directory
from api.control   import control_bp
from api.execution import execution_bp
from api.logs      import logs_bp

app = Flask(__name__, static_folder="ui", static_url_path="")

# Register API blueprints
app.register_blueprint(control_bp,   url_prefix="/api")
app.register_blueprint(execution_bp, url_prefix="/api")
app.register_blueprint(logs_bp,      url_prefix="/api")


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
    app.run(host="0.0.0.0", port=port, debug=False)
