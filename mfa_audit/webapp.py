"""
webapp.py
---------
Lightweight Flask wrapper around the MFA Audit Tool so it can be
demonstrated via a browser and deployed to Render / Railway.

The CLI remains the primary interface. This wrapper exposes the same
four-module pipeline over HTTP with a single-page form.
"""
import os
import uuid
import ipaddress
import socket
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, request, render_template
from jinja2 import Environment, FileSystemLoader, select_autoescape

from mfa_audit.discovery import DiscoveryModule
from mfa_audit.assessment import AssessmentEngine
from mfa_audit.analysis import AnalysisEngine
from mfa_audit.models import AssessmentResult

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", uuid.uuid4().hex)

# If ACCESS_CODE is set in the environment, visitors must supply it.
# Leave it unset only for local development.
ACCESS_CODE = os.environ.get("ACCESS_CODE", "")

REPORT_TEMPLATE_DIR = Path(__file__).parent / "mfa_audit" / "templates"


def _is_public_target(url: str):
    """Reject localhost / private IPs to prevent SSRF abuse on the hosted demo."""
    try:
        host = urlparse(url).hostname
        if not host:
            return False, "Invalid URL"
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return False, "Localhost targets are not permitted in the hosted demo."
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            return False, "Hostname could not be resolved."
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False, f"Private/reserved IP {ip} is not permitted."
        return True, ""
    except Exception as e:
        return False, f"Invalid target: {e}"


@app.route("/", methods=["GET"])
def home():
    return render_template("index.html", access_required=bool(ACCESS_CODE))


@app.route("/health", methods=["GET"])
def health():
    return {"status": "ok"}, 200


@app.route("/scan", methods=["POST"])
def scan():
    # 1. Access code gate (only if configured)
    if ACCESS_CODE and request.form.get("access_code", "") != ACCESS_CODE:
        return render_template("index.html", access_required=True,
                               error="Invalid access code."), 403

    # 2. Target validation
    target = request.form.get("target", "").strip()
    if not target:
        return render_template("index.html", access_required=bool(ACCESS_CODE),
                               error="Please enter a target URL."), 400
    if not target.startswith(("http://", "https://")):
        return render_template("index.html", access_required=bool(ACCESS_CODE),
                               error="Target must start with http:// or https://"), 400

    # 3. Authorization acknowledgement
    if request.form.get("authorized") != "yes":
        return render_template("index.html", access_required=bool(ACCESS_CODE),
                               error="You must confirm authorization."), 400

    # 4. SSRF guard
    ok, reason = _is_public_target(target)
    if not ok:
        return render_template("index.html", access_required=bool(ACCESS_CODE),
                               error=reason), 400

    # 5. Run the four-module pipeline
    try:
        result = AssessmentResult(target=target,
                                  scan_started=datetime.now(timezone.utc))
        result.endpoints = DiscoveryModule(target, timeout=8).run()
        engine = AssessmentEngine(target, timeout=8)
        result.findings = engine.run(result.endpoints)
        result = AnalysisEngine().run(result)
        result.scan_finished = datetime.now(timezone.utc)

        env = Environment(
            loader=FileSystemLoader(str(REPORT_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html"]),
        )
        tpl = env.get_template("report.html.j2")
        return tpl.render(r=result,
                          findings=[f.to_dict() for f in result.findings])
    except Exception as e:
        return render_template("index.html", access_required=bool(ACCESS_CODE),
                               error=f"Scan failed: {e}"), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)