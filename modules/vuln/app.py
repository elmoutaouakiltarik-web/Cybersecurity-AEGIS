#!/usr/bin/env python3
"""Flask REST API wrapper for Cybersecurity-AEGIS Vulnerability Scanner."""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

from flask import Flask, jsonify, request

from scanner import VulnerabilityScanner

# The background worker queries the orchestrator for recent events; without
# this guard the loop raised NameError on every iteration and died silently.
try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover - requests is in requirements.txt
    requests = None  # type: ignore[assignment]

_REQUESTS = requests is not None

LOGGER = logging.getLogger("aegis.vuln.api")
app = Flask(__name__)

scanner: VulnerabilityScanner | None = None


# ── CORS ───────────────────────────────────────────────────────────────────────
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
def _add_cors(response: Any) -> Any:
    _origin = _loopback_origin()
    if _origin:
        response.headers["Access-Control-Allow-Origin"] = _origin
        response.headers["Vary"] = "Origin"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


# ── HEALTH ─────────────────────────────────────────────────────────────────────
@app.route("/health", methods=["GET", "OPTIONS"])
def health() -> Any:
    return jsonify({"status": "healthy"})


# ── STATUS ─────────────────────────────────────────────────────────────────────
@app.route("/status", methods=["GET", "OPTIONS"])
def status() -> Any:
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(scanner.status())


# ── DATA ───────────────────────────────────────────────────────────────────────
@app.route("/data", methods=["GET", "OPTIONS"])
def data() -> Any:
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    recent = [f.to_dict() for f in scanner.findings[-50:]]
    return jsonify({"findings": recent, "count": len(recent)})


# ── TRIGGER ────────────────────────────────────────────────────────────────────
@app.route("/trigger", methods=["POST", "OPTIONS"])
def trigger() -> Any:
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503

    body = request.get_json(silent=True) or {}
    target = body.get("target")
    ports = body.get("ports")

    def _immediate() -> None:
        try:
            if target:
                # ports may be "22,80,443" or list
                hints = None
                if ports:
                    if isinstance(ports, list):
                        hints = [int(p) for p in ports if str(p).isdigit()]
                    else:
                        hints = [int(p) for p in str(ports).split(",") if p.strip().isdigit()]
                scanner.scan_ip(str(target), hints=hints)  # type: ignore[union-attr]
                return

            # No explicit target -> derive from latest Network scan results
            # Expected shape: /api/scan/results returns {results:[{ip:...}]}
            if _REQUESTS:
                try:
                    orch = scanner.orchestrator_url  # type: ignore[union-attr]
                    # orchestrator short endpoint proxies to network module
                    r = requests.get(f"{orch}/api/scan/results", timeout=8)  # type: ignore[union-attr]
                    if r.ok:
                        payload = r.json() if isinstance(r.json(), dict) else {}
                        results = payload.get('results', []) if isinstance(payload, dict) else []
                    else:
                        results = []
                except Exception:
                    results = []

                targets = []
                for h in results[:200]:
                    ip = h.get('ip') if isinstance(h, dict) else None
                    if ip:
                        targets.append(str(ip))

                for ip in targets[:50]:
                    scanner.scan_ip(ip, hints=None)  # type: ignore[union-attr]
        except Exception as exc:
            LOGGER.error("Trigger scan failed: %s", exc)

    threading.Thread(target=_immediate, daemon=True).start()
    return jsonify({"status": "triggered", "message": "Scan started"})



# ── BATCH SCAN (from LAN discovery) ────────────────────────────────────────────
@app.route("/scan/batch", methods=["POST", "OPTIONS"])
def batch_scan() -> Any:
    """Scan multiple IPs from a list (e.g. from LAN discovery results).
    Body JSON: { "targets": ["192.168.1.1","192.168.1.2",...] }
    """
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    body = request.get_json(silent=True) or {}
    targets = body.get("targets", [])
    if not targets:
        return jsonify({"error": "no targets provided"}), 400

    def _run_batch() -> None:
        for ip in targets[:50]:  # cap at 50 hosts
            try:
                scanner.scan_ip(str(ip))  # type: ignore[union-attr]
            except Exception as exc:
                LOGGER.error("Batch scan error on %s: %s", ip, exc)

    threading.Thread(target=_run_batch, daemon=True).start()
    return jsonify({
        "status": "started",
        "targets_queued": len(targets[:50]),
        "message": f"Scanning {len(targets[:50])} hosts",
    }), 202


# ── FULL FINDINGS EXPORT ───────────────────────────────────────────────────────
@app.route("/findings", methods=["GET", "OPTIONS"])
def findings_all() -> Any:
    """Return all findings with optional severity filter."""
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    severity = request.args.get("severity")
    findings = scanner.findings
    if severity:
        findings = [f for f in findings if f.severity == severity]
    return jsonify({
        "count": len(findings),
        "findings": [f.to_dict() for f in findings[-200:]],
    })


# ── BACKGROUND WORKER ──────────────────────────────────────────────────────────
def _background_worker() -> None:
    """Background vulnerability evaluation.

    No demo injection: when there are no real targets discovered from events,
    the worker stays idle.
    """
    while True:
        try:
            LOGGER.info("Running scheduled vulnerability evaluation")
            # Scan from recent orchestrator events if possible
            if _REQUESTS:
                try:
                    resp = requests.get(f"{scanner.orchestrator_url}/api/v1/events?limit=100", timeout=5)  # type: ignore[name-defined,union-attr]
                    if resp.ok:
                        events = resp.json() if isinstance(resp.json(), list) else resp.json().get('events', [])
                    else:
                        events = []
                except Exception:
                    events = []

                if events:
                    for ev in events[-50:]:
                        try:
                            scanner.enrich_from_event(ev)  # type: ignore[union-attr]
                        except Exception as exc:
                            LOGGER.debug("enrich_from_event failed: %s", exc)
        except Exception as exc:
            LOGGER.error("Background scan failed: %s", exc)
        time.sleep(300)



# ── MAIN ───────────────────────────────────────────────────────────────────────
def main() -> int:
    log_level = os.getenv("AEGIS_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    global scanner
    scanner = VulnerabilityScanner({
        "orchestrator_url": os.getenv("ORCHESTRATOR_URL"),
        "active_scan": os.getenv("VULN_ACTIVE_SCAN", "").lower() in {"1", "true"},
    })

    t = threading.Thread(target=_background_worker, daemon=True)
    t.start()

    port = int(os.getenv("VULN_API_PORT", "8085"))
    BIND_HOST = os.getenv("VULN_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
