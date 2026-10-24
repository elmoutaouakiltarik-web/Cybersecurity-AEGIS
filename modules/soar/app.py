#!/usr/bin/env python3
"""Flask REST API wrapper for Cybersecurity-AEGIS SOAR Playbook Executor."""
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

from executor import PlaybookExecutor

LOGGER = logging.getLogger("aegis.soar.api")
app = Flask(__name__)

executor: PlaybookExecutor | None = None


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
    if executor is None:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(executor.status())


# ── DATA ───────────────────────────────────────────────────────────────────────
@app.route("/data", methods=["GET", "OPTIONS"])
def data() -> Any:
    if executor is None:
        return jsonify({"error": "not initialized"}), 503
    recent = [e.to_dict() for e in executor.executions[-50:]]
    return jsonify({"executions": recent, "count": len(recent)})


# ── PLAYBOOKS ──────────────────────────────────────────────────────────────────
@app.route("/playbooks", methods=["GET", "OPTIONS"])
def playbooks() -> Any:
    if executor is None:
        return jsonify({"error": "not initialized"}), 503
    loaded = [
        {
            "id": pb.id,
            "name": pb.name,
            "description": pb.description,
            "enabled": pb.enabled,
            "dry_run": pb.dry_run,
            "severity_filter": pb.severity_filter,
            "category_filter": pb.category_filter,
        }
        for pb in executor.playbooks
    ]
    return jsonify({"playbooks": loaded, "count": len(loaded)})


# ── TRIGGER ────────────────────────────────────────────────────────────────────
@app.route("/trigger", methods=["POST", "OPTIONS"])
def trigger() -> Any:
    """Re-process recent high/critical events from the orchestrator through the
    playbook executor. Real events only — no demo injection.
    """
    if executor is None:
        return jsonify({"error": "not initialized"}), 503

    def _immediate() -> None:
        try:
            events = _fetch_orchestrator_high_critical_events()
            processed = 0
            for evt in events:
                executor.handle_event(evt)  # type: ignore[union-attr]
                processed += 1
            LOGGER.info("Trigger: processed %d real events", processed)
        except Exception as exc:
            LOGGER.error("Trigger execution failed: %s", exc)

    threading.Thread(target=_immediate, daemon=True).start()
    return jsonify({"status": "triggered",
                    "message": "Re-processing real high/critical events from orchestrator"})


# ── BACKGROUND POLLING ─────────────────────────────────────────────────────────
def _fetch_orchestrator_high_critical_events() -> list[dict[str, Any]]:
    url = f"{executor.orchestrator_url}/api/v1/events"  # type: ignore[union-attr]
    if not _REQUESTS:
        return []
    try:
        resp = requests.get(url, params={"severity": "high,critical"}, timeout=3)
        if resp.status_code == 200:
            payload = resp.json()
            if isinstance(payload, list):
                return payload
            if isinstance(payload, dict) and "events" in payload:
                return payload["events"]
    except Exception:
        pass
    return []


def _inject_demo_events(count: int = 2) -> None:
    """Disabled: the project requires real telemetry only (no synthetic events)."""
    return


def _background_worker() -> None:
    """Poll orchestrator high/critical events every 10s. No demo injection —
    when there are no real events, the worker simply waits."""
    while True:
        try:
            events = _fetch_orchestrator_high_critical_events()
            if events:
                for evt in events:
                    executor.handle_event(evt)  # type: ignore[union-attr]
        except Exception as exc:
            LOGGER.error("Background polling failed: %s", exc)
        time.sleep(10)


# ── MAIN ───────────────────────────────────────────────────────────────────────
def main() -> int:
    log_level = os.getenv("AEGIS_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    global executor
    executor = PlaybookExecutor({
        "orchestrator_url": os.getenv("ORCHESTRATOR_URL"),
        "playbooks_dir": os.getenv("SOAR_PLAYBOOKS_DIR", "playbooks"),
        "dry_run": os.getenv("SOAR_LIVE_MODE", "").lower() not in {"1", "true"},
    })

    t = threading.Thread(target=_background_worker, daemon=True)
    t.start()

    port = int(os.getenv("SOAR_API_PORT", "8083"))
    BIND_HOST = os.getenv("SOAR_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
