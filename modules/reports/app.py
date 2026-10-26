#!/usr/bin/env python3
"""Flask API wrapper for AEGIS Report Generator."""
from __future__ import annotations

import logging
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from flask import Flask, jsonify, make_response, request, send_file

from generator import generate_html_report, generate_json_report

LOGGER = logging.getLogger("aegis.reports.api")
app = Flask(__name__)

REPORTS_DIR = Path(os.getenv("REPORTS_DIR", "/reports"))
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://localhost:8080")


def _loopback_origin() -> str:
    """Reflect the Origin only for genuine loopback pages.

    A wildcard here lets any website the operator visits read responses from
    these local APIs. Only localhost/127.0.0.1/[::1] origins are echoed back.
    """
    from urllib.parse import urlsplit

    try:
        from flask import request
        origin = request.headers.get("Origin", "")
    except Exception:
        return ""
    if not origin or origin == "null":
        return ""
    try:
        host = urlsplit(origin).hostname
    except ValueError:
        return ""
    return origin if host in ("localhost", "127.0.0.1", "::1") else ""


@app.after_request
def _cors(response: Any) -> Any:
    _origin = _loopback_origin()
    if _origin:
        response.headers["Access-Control-Allow-Origin"] = _origin
        response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.route("/health", methods=["GET", "OPTIONS"])
def health() -> Any:
    return jsonify({"status": "healthy"})


@app.route("/report", methods=["GET", "POST", "OPTIONS"])
def report() -> Any:
    """
    Generate and return a security report.
    Query params:
      ?format=html|json   (default: html)
      ?save=1             (also save to disk)
    """
    fmt = request.args.get("format", "html").lower()
    save = request.args.get("save", "0") in ("1", "true")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    if fmt == "json":
        outpath = str(REPORTS_DIR / f"aegis_report_{ts}.json") if save else None
        report_data = generate_json_report(
            orchestrator_url=ORCHESTRATOR_URL, outpath=outpath
        )
        resp = make_response(jsonify(report_data))
        resp.headers["Content-Disposition"] = f"attachment; filename=aegis_report_{ts}.json"
        return resp
    else:
        outpath = str(REPORTS_DIR / f"aegis_report_{ts}.html") if save else None
        html = generate_html_report(
            orchestrator_url=ORCHESTRATOR_URL, outpath=outpath
        )
        resp = make_response(html)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        resp.headers["Content-Disposition"] = f"attachment; filename=aegis_report_{ts}.html"
        return resp


@app.route("/report/list", methods=["GET", "OPTIONS"])
def report_list() -> Any:
    """List previously saved reports."""
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    files = []
    for p in sorted(REPORTS_DIR.glob("aegis_report_*"), reverse=True)[:20]:
        files.append({
            "name": p.name,
            "size": p.stat().st_size,
            "created": datetime.fromtimestamp(p.stat().st_mtime).isoformat(),
        })
    return jsonify({"reports": files})


def main() -> int:
    logging.basicConfig(
        level=os.getenv("AEGIS_LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    port = int(os.getenv("REPORTS_API_PORT", "8086"))
    LOGGER.info("Reports module starting on port %d", port)
    BIND_HOST = os.getenv("REPORTS_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
