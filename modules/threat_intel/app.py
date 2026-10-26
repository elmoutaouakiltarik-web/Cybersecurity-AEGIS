#!/usr/bin/env python3
"""Flask REST API wrapper for Cybersecurity-AEGIS Threat Intelligence Service."""
from __future__ import annotations

import logging
import os
import random
import threading
import time
from typing import Any

from flask import Flask, jsonify, request

try:
    import requests  # type: ignore
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

from feeds import ThreatIntelService, MatchResult

LOGGER = logging.getLogger("aegis.threat_intel.api")
app = Flask(__name__)

service: ThreatIntelService | None = None
_recent_matches: list[dict[str, Any]] = []


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
    if service is None:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(service.stats())


# ── DATA ───────────────────────────────────────────────────────────────────────
@app.route("/data", methods=["GET", "OPTIONS"])
def data() -> Any:
    return jsonify({"matches": _recent_matches[-50:], "count": len(_recent_matches)})


# ── LOOKUP ─────────────────────────────────────────────────────────────────────
@app.route("/lookup", methods=["GET", "OPTIONS"])
def lookup() -> Any:
    if service is None:
        return jsonify({"error": "not initialized"}), 503

    ip = request.args.get("ip", "")
    domain = request.args.get("domain", "")
    result: dict[str, Any] = {"ip": ip, "domain": domain, "matches": []}

    if ip:
        ioc = service.registry.lookup_ip(ip)
        if ioc:
            result["matches"].append({
                "type": "ip",
                "value": ip,
                "ioc": ioc.to_dict(),
            })
    if domain:
        ioc = service.registry.lookup_domain(domain)
        if ioc:
            result["matches"].append({
                "type": "domain",
                "value": domain,
                "ioc": ioc.to_dict(),
            })

    result["matched"] = len(result["matches"]) > 0
    return jsonify(result)


# ── TRIGGER ────────────────────────────────────────────────────────────────────
@app.route("/trigger", methods=["POST", "OPTIONS"])
def trigger() -> Any:
    if service is None:
        return jsonify({"error": "not initialized"}), 503

    def _immediate() -> None:
        try:
            _process_events(count=3)
        except Exception as exc:
            LOGGER.error("Trigger enrichment failed: %s", exc)

    threading.Thread(target=_immediate, daemon=True).start()
    return jsonify({"status": "triggered", "message": "Enrichment cycle started"})


# ── BACKGROUND POLLING ─────────────────────────────────────────────────────────
def _fetch_orchestrator_events() -> list[dict[str, Any]]:
    url = f"{service.orchestrator_url}/api/v1/events"  # type: ignore[union-attr]
    if not _REQUESTS:
        return []
    try:
        resp = requests.get(url, timeout=3)
        if resp.status_code == 200:
            payload = resp.json()
            if isinstance(payload, list):
                return payload
            if isinstance(payload, dict) and "events" in payload:
                return payload["events"]
    except Exception:
        pass
    return []


def _process_events(count: int = 2) -> None:
    """Enrich real events from orchestrator.

    No synthetic/demo events.
    """
    events = _fetch_orchestrator_events()
    if not events:
        return

    for evt in events[-50:][:count]:
        enriched = service.enrich_event(evt)  # type: ignore[union-attr]
        if enriched.get("matched"):
            for match in enriched.get("matches", []):
                _recent_matches.append(match)



def _background_worker() -> None:
    """Poll orchestrator events every 10 seconds for enrichment."""
    while True:
        try:
            _process_events(count=2)
        except Exception as exc:
            LOGGER.error("Background enrichment failed: %s", exc)
        time.sleep(10)


# ── MAIN ───────────────────────────────────────────────────────────────────────
def main() -> int:
    log_level = os.getenv("AEGIS_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    global service
    service = ThreatIntelService({
        "orchestrator_url": os.getenv("ORCHESTRATOR_URL"),
        "feeds_dir": os.getenv("THREAT_INTEL_FEEDS_DIR", "feeds"),
    })

    t = threading.Thread(target=_background_worker, daemon=True)
    t.start()

    port = int(os.getenv("THREAT_INTEL_API_PORT", "8084"))
    BIND_HOST = os.getenv("THREAT_INTEL_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
