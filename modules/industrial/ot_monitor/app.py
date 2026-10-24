#!/usr/bin/env python3
"""Flask REST API wrapper for Cybersecurity-AEGIS OT/ICS Monitor."""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

from flask import Flask, jsonify, request

from main import OTMonitor

LOGGER = logging.getLogger("aegis.ot.api")
app = Flask(__name__)

monitor: OTMonitor | None = None


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
    if monitor is None:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(monitor.status())


# ── DATA ───────────────────────────────────────────────────────────────────────
@app.route("/data", methods=["GET", "OPTIONS"])
def data() -> Any:
    if monitor is None:
        return jsonify({"error": "not initialized"}), 503
    recent_alerts = [a.to_dict() for a in monitor.alerts[-50:]]
    assets = monitor.inventory.all_assets()
    return jsonify({"alerts": recent_alerts, "assets": assets, "alert_count": len(recent_alerts), "asset_count": len(assets)})


# ── TRIGGER ────────────────────────────────────────────────────────────────────
@app.route("/trigger", methods=["POST", "OPTIONS"])
def trigger() -> Any:
    if monitor is None:
        return jsonify({"error": "not initialized"}), 503

    def _immediate() -> None:
        try:
            monitor.run_simulation(cycles=10)  # type: ignore[union-attr]
        except Exception as exc:
            LOGGER.error("Trigger simulation failed: %s", exc)

    threading.Thread(target=_immediate, daemon=True).start()
    return jsonify({"status": "triggered", "message": "OT simulation cycle started"})


# ── BACKGROUND WORKER ──────────────────────────────────────────────────────────
def _background_worker() -> None:
    """Run OT simulation every 60 seconds."""
    while True:
        try:
            LOGGER.info("Running OT simulation cycle")
            monitor.run_simulation(cycles=10)  # type: ignore[union-attr]
        except Exception as exc:
            LOGGER.error("Background simulation failed: %s", exc)
        time.sleep(60)


# ── MAIN ───────────────────────────────────────────────────────────────────────
def main() -> int:
    log_level = os.getenv("AEGIS_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    global monitor
    monitor = OTMonitor({
        "interface": os.getenv("OT_MONITOR_INTERFACE"),
        "orchestrator_url": os.getenv("OT_ORCHESTRATOR_URL") or os.getenv("ORCHESTRATOR_URL"),
        "authorized_assets": [],
    })

    t = threading.Thread(target=_background_worker, daemon=True)
    t.start()

    port = int(os.getenv("OT_API_PORT", "8086"))
    BIND_HOST = os.getenv("OT_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
