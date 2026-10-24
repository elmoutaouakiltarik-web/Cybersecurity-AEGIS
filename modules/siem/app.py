#!/usr/bin/env python3
"""Flask REST API wrapper for Cybersecurity-AEGIS SIEM Correlator."""
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

from correlator import SIEMCorrelator

LOGGER = logging.getLogger("aegis.siem.api")
app = Flask(__name__)

correlator: SIEMCorrelator | None = None


# ── CORS ───────────────────────────────────────────────────────────────────────
@app.after_request
def _add_cors(response: Any) -> Any:
    response.headers["Access-Control-Allow-Origin"] = "*"
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
    if correlator is None:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(correlator.status())


# ── DATA ───────────────────────────────────────────────────────────────────────
@app.route("/data", methods=["GET", "OPTIONS"])
def data() -> Any:
    if correlator is None:
        return jsonify({"error": "not initialized"}), 503
    recent = [i.to_dict() for i in correlator.incidents[-50:]]
    return jsonify({"incidents": recent, "count": len(recent)})


# ── TRIGGER ────────────────────────────────────────────────────────────────────
@app.route("/trigger", methods=["POST", "OPTIONS"])
def trigger() -> Any:
    if correlator is None:
        return jsonify({"error": "not initialized"}), 503

    def _immediate() -> None:
        # Correlate real events already ingested in orchestrator.
        try:
            events = _fetch_orchestrator_events()
            for evt in events:
                correlator.ingest(evt)  # type: ignore[union-attr]
        except Exception as exc:
            LOGGER.error("Trigger correlation failed: %s", exc)

    threading.Thread(target=_immediate, daemon=True).start()
    return jsonify({"status": "triggered", "message": "Correlation cycle started"})



# ── BACKGROUND POLLING ─────────────────────────────────────────────────────────
def _fetch_orchestrator_events() -> list[dict[str, Any]]:
    url = f"{correlator.orchestrator_url}/api/v1/events"  # type: ignore[union-attr]
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


def _inject_demo_events(count: int = 3) -> None:
    # Deprecated: the system must not inject demo data.
    return



def _background_worker() -> None:
    """Poll orchestrator events every 10 seconds and correlate."""
    while True:
        try:
            events = _fetch_orchestrator_events()
            if events:
                for evt in events:
                    correlator.ingest(evt)  # type: ignore[union-attr]
            # If there are no real events, do nothing (no demo injection)

        except Exception as exc:
            LOGGER.error("Background polling failed: %s", exc)
        time.sleep(10)


# ── MAIN ───────────────────────────────────────────────────────────────────────
def main() -> int:
    log_level = os.getenv("AEGIS_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    global correlator
    correlator = SIEMCorrelator({
        "orchestrator_url": os.getenv("ORCHESTRATOR_URL"),
        "rules_file": os.getenv("SIEM_RULES_FILE", "siem_rules.yaml"),
        "dedup_cooldown_sec": int(os.getenv("SIEM_DEDUP_COOLDOWN", "300")),
    })

    t = threading.Thread(target=_background_worker, daemon=True)
    t.start()

    port = int(os.getenv("SIEM_API_PORT", "8082"))
    BIND_HOST = os.getenv("SIEM_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
