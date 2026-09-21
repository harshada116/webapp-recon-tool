"""
app.py (Web Application Reconnaissance Tool)
----------------------------------------------
Run:
    cd recon_tool
    pip install -r ../requirements.txt
    python app.py
Then open http://127.0.0.1:5001

IMPORTANT: Only run this tool against targets you own or are explicitly
authorized to assess. Unauthorized scanning (including port scanning and
subdomain brute-forcing) of third-party systems may violate laws such as
the U.S. Computer Fraud and Abuse Act or the UK Computer Misuse Act.
"""

from __future__ import annotations

import os
import uuid

from flask import Flask, render_template, request, send_file, abort, flash, redirect, url_for

from recon import run_recon, ReconResult
import dashboard
import history_store
import report_generator

app = Flask(__name__)
app.secret_key = os.environ.get("RECON_TOOL_SECRET_KEY", os.urandom(24))

REPORTS_DIR = os.path.join(os.path.dirname(__file__), "reports")
SCREENSHOTS_DIR = os.path.join(os.path.dirname(__file__), "static", "screenshots")
os.makedirs(REPORTS_DIR, exist_ok=True)
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

_RESULT_CACHE: dict[str, ReconResult] = {}
_DASHBOARD_CACHE: dict[str, dict] = {}
_CACHE_MAX = 25


def _cache(report_id: str, result: ReconResult, dash: dict) -> None:
    if len(_RESULT_CACHE) >= _CACHE_MAX:
        oldest = next(iter(_RESULT_CACHE))
        _RESULT_CACHE.pop(oldest, None)
        _DASHBOARD_CACHE.pop(oldest, None)
    _RESULT_CACHE[report_id] = result
    _DASHBOARD_CACHE[report_id] = dash


def _build_dashboard(result: ReconResult) -> dict:
    """Record this scan in the host's history, then summarize the result."""
    history = []
    if not result.error and result.hostname:
        history = history_store.record_observation(
            result.hostname, dashboard.observation_from(result)
        )
    return dashboard.build_dashboard(result, history=history)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html", result=None)

    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Please enter a target URL or hostname.")
        return redirect(url_for("index"))

    enable_port_scan = request.form.get("enable_port_scan") == "on"
    enable_screenshot = request.form.get("enable_screenshot") == "on"
    enable_subdomains = request.form.get("enable_subdomains") == "on"

    result = run_recon(
        target,
        enable_port_scan=enable_port_scan,
        enable_screenshot=enable_screenshot,
        enable_subdomains=enable_subdomains,
    )

    dash = _build_dashboard(result)

    report_id = uuid.uuid4().hex[:12]
    _cache(report_id, result, dash)

    screenshot_rel = None
    shot = result.modules.get("screenshot") if result.modules else None
    if shot and shot.get("captured"):
        screenshot_rel = os.path.relpath(shot["path"], os.path.join(os.path.dirname(__file__), "static"))

    return render_template(
        "index.html",
        result=result,
        report_id=report_id,
        screenshot_rel=screenshot_rel,
        dashboard_html=report_generator.render_dashboard(dash),
        body_html=report_generator.render_body(result),
        dashboard_css=report_generator.DASHBOARD_CSS,
    )


@app.route("/dashboard/<report_id>")
def dashboard_view(report_id):
    """The site-report dashboard on its own, without the raw module dumps."""
    dash = _DASHBOARD_CACHE.get(report_id)
    if not dash:
        abort(404)
    return render_template(
        "dashboard.html",
        report_id=report_id,
        dashboard_html=report_generator.render_dashboard(dash),
        dashboard_css=report_generator.DASHBOARD_CSS,
    )


@app.route("/report/<report_id>.html")
def download_html(report_id):
    result = _RESULT_CACHE.get(report_id)
    if not result:
        abort(404)
    content = report_generator.render_html(result, dash=_DASHBOARD_CACHE.get(report_id))
    path = os.path.join(REPORTS_DIR, f"{report_id}.html")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)
    return send_file(path, as_attachment=True, download_name="recon-report.html")


@app.route("/report/<report_id>.pdf")
def download_pdf(report_id):
    result = _RESULT_CACHE.get(report_id)
    if not result:
        abort(404)
    path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")
    try:
        report_generator.render_pdf(result, path, dash=_DASHBOARD_CACHE.get(report_id))
    except ImportError as exc:
        flash(str(exc))
        return redirect(url_for("index"))
    return send_file(path, as_attachment=True, download_name="recon-report.pdf")


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=5001, debug=debug_mode)
