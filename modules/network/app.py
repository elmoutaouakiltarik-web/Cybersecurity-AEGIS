#!/usr/bin/env python3
"""Flask REST API wrapper for Cybersecurity-AEGIS Network Traffic Analyzer."""
from __future__ import annotations

import logging
import os
import threading
import time
from typing import Any

from flask import Flask, jsonify, request

from analyzer import NetworkMonitor
from lan_scanner import LANScanner
from topology import TopologyMapper
from tls_inspector import TLSInspector
from intelligence.threat_fusion import ThreatFusionEngine

LOGGER = logging.getLogger("aegis.network.api")
app = Flask(__name__)

# Global instances (initialized in main)
monitor: NetworkMonitor | None = None
scanner: LANScanner | None = None
topology_mapper = TopologyMapper()
tls_inspector = TLSInspector()
fusion_engine: ThreatFusionEngine | None = None


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
    if monitor is None:
        return jsonify({"error": "not initialized"}), 503
    return jsonify(monitor.status())


# ── DATA ───────────────────────────────────────────────────────────────────────
@app.route("/data", methods=["GET", "OPTIONS"])
def data() -> Any:
    if monitor is None:
        return jsonify({"error": "not initialized"}), 503
    recent = [a.to_dict() for a in monitor.alerts[-50:]]
    return jsonify({"alerts": recent, "count": len(recent)})


# ── TRIGGER (deprecated — real scans go through /scan) ────────────────────────
@app.route("/trigger", methods=["POST", "OPTIONS"])
def trigger() -> Any:
    """Deprecated. Real network activity now requires an explicit /scan call
    against a real subnet. This endpoint no longer runs simulation cycles
    (real-data-only policy).
    """
    return jsonify({
        "status": "deprecated",
        "message": "Use POST /scan with a real target subnet. /trigger no longer simulates.",
    }), 410


# ── REAL LAN DISCOVERY ─────────────────────────────────────────────────────────
@app.route("/discover", methods=["GET", "OPTIONS"])
def discover() -> Any:
    """Return auto-detected local subnets."""
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    subnets = scanner.get_local_subnets()
    return jsonify({"subnets": subnets})


# ── START REAL SCAN ────────────────────────────────────────────────────────────
@app.route("/scan", methods=["POST", "OPTIONS"])
def start_scan() -> Any:
    """Launch a real LAN scan job.
    Body JSON: { "target": "192.168.1.0/24", "mode": "quick|full", "ports": [22,80,...] }
    """
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    body = request.get_json(silent=True) or {}

    # Auto-detect target if not provided
    target = body.get("target", "")
    if not target:
        subnets = scanner.get_local_subnets()
        target = subnets[0] if subnets else "192.168.1.0/24"

    mode = body.get("mode", "quick")
    custom_ports = body.get("ports")
    if custom_ports and isinstance(custom_ports, list):
        custom_ports = [int(p) for p in custom_ports if str(p).isdigit()]
    else:
        custom_ports = None

    timeout = body.get("timeout", 300)
    ot_mode = body.get("ot_mode", "normal")
    job = scanner.start_scan(target=target, mode=mode, ot_mode=ot_mode, custom_ports=custom_ports, timeout=float(timeout))
    if job.state == "error":
        return jsonify({
            "status": "rejected",
            "job_id": job.id,
            "error": job.error,
        }), 400
    return jsonify({
        "status": "started",
        "job_id": job.id,
        "target": job.target,
        "mode": job.mode,
        "ot_mode": job.ot_mode,
    }), 202


# ── SCAN STATUS ────────────────────────────────────────────────────────────────
@app.route("/scan/status", methods=["GET", "OPTIONS"])
def scan_status() -> Any:
    """Get status of last scan or specific job."""
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    job_id = request.args.get("job_id")
    if job_id:
        job = scanner.get_job(job_id)
    else:
        job = scanner.get_latest_job()
    if job is None:
        return jsonify({"state": "idle", "jobs": scanner.list_jobs()})
    return jsonify({
        "job_id": job.id,
        "state": job.state,
        "progress": job.progress,
        "target": job.target,
        "hosts_found": job.hosts_found,
        "hosts_scanned": job.hosts_scanned,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "error": job.error,
    })


# ── SCAN RESULTS ───────────────────────────────────────────────────────────────
@app.route("/scan/results", methods=["GET", "OPTIONS"])
def scan_results() -> Any:
    """Return full results of completed scan."""
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    job_id = request.args.get("job_id")
    if job_id:
        job = scanner.get_job(job_id)
    else:
        job = scanner.get_latest_job()
    if job is None:
        return jsonify({"results": [], "count": 0})
    return jsonify({
        "job_id": job.id,
        "state": job.state,
        "target": job.target,
        "count": len(job.results),
        "results": [r.to_dict() for r in job.results],
    })


# ── SCAN CANCEL ────────────────────────────────────────────────────────────────
@app.route("/scan/cancel", methods=["POST", "OPTIONS"])
def scan_cancel() -> Any:
    """Cancel a running or pending scan job."""
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    body = request.get_json(silent=True) or {}
    job_id = body.get("job_id", "")
    if not job_id:
        return jsonify({"error": "job_id required"}), 400
    ok = scanner.cancel_job(job_id)
    return jsonify({"cancelled": ok, "job_id": job_id})


# ── SCAN EXPORT ────────────────────────────────────────────────────────────────
@app.route("/scan/export", methods=["GET", "OPTIONS"])
def scan_export() -> Any:
    """Export scan results in JSON, CSV, or HTML.
    Query: ?job_id=<id>&format=json|csv|html
    """
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    job_id = request.args.get("job_id", "")
    fmt = request.args.get("format", "json")
    if not job_id:
        return jsonify({"error": "job_id required"}), 400
    try:
        data = scanner.export_job(job_id, fmt)
        mimetype = "application/json" if fmt == "json" else "text/csv" if fmt == "csv" else "text/html"
        from flask import Response
        return Response(data, mimetype=mimetype, headers={
            "Content-Disposition": f"attachment; filename=scan_{job_id}.{fmt}"
        })
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400


# ── SCAN JOBS LIST ─────────────────────────────────────────────────────────────
@app.route("/scan/jobs", methods=["GET", "OPTIONS"])
def scan_jobs() -> Any:
    if scanner is None:
        return jsonify({"error": "not initialized"}), 503
    return jsonify({"jobs": scanner.list_jobs()})


# ── NETWORK TOPOLOGY ───────────────────────────────────────────────────────────
@app.route("/topology", methods=["GET", "OPTIONS"])
def get_topology() -> Any:
    """Return current network topology graph (nodes + edges + attack paths)."""
    job_id = request.args.get("job_id")
    hosts = []
    if scanner is not None:
        if job_id:
            job = scanner.get_job(job_id)
        else:
            job = scanner.get_latest_job()
        if job and job.state == "done":
            hosts = [h.to_dict() for h in job.results]

    if not hosts:
        return jsonify({"nodes": [], "links": [], "attack_paths": [], "segmentation_gaps": [], "stats": {}})
    topo_graph = topology_mapper.build_from_scan_results(hosts)
    return jsonify(topo_graph.to_d3_json())


@app.route("/topology/attack-paths", methods=["GET", "OPTIONS"])
def get_attack_paths() -> Any:
    """Return calculated attack paths through the network."""
    job_id = request.args.get("job_id")
    hosts = []
    if scanner is not None:
        if job_id:
            job = scanner.get_job(job_id)
        else:
            job = scanner.get_latest_job()
        if job and job.state == "done":
            hosts = [h.to_dict() for h in job.results]

    if not hosts:
        return jsonify({"attack_paths": [], "segmentation_gaps": [], "count": 0})
    topo_graph = topology_mapper.build_from_scan_results(hosts)
    paths = topology_mapper.compute_attack_paths(topo_graph)
    gaps = [g.to_dict() for g in topo_graph.segmentation_gaps]
    return jsonify({
        "attack_paths": [p.to_dict() for p in paths],
        "segmentation_gaps": gaps,
        "count": len(paths),
    })


# ── TLS / SSL INSPECTION ───────────────────────────────────────────────────────
@app.route("/tls/inspect", methods=["POST", "OPTIONS"])
def tls_inspect() -> Any:
    """Inspect TLS configuration of a host.
    Body: { "ip": "1.2.3.4", "port": 443, "hostname": "example.com" }
    """
    body = request.get_json(silent=True) or {}
    ip = body.get("ip", "")
    if not ip:
        return jsonify({"error": "ip is required"}), 400
    port = int(body.get("port", 443))
    hostname = body.get("hostname", ip)
    result = tls_inspector.inspect(ip=ip, port=port, hostname=hostname)
    return jsonify({"result": result.to_dict()})


@app.route("/tls/batch", methods=["POST", "OPTIONS"])
def tls_batch() -> Any:
    """Batch-inspect TLS for multiple targets.
    Body: { "targets": [{"ip": "1.2.3.4", "port": 443}, ...] }
    """
    body = request.get_json(silent=True) or {}
    raw_targets = body.get("targets", [])
    if not raw_targets or not isinstance(raw_targets, list):
        return jsonify({"error": "targets list is required"}), 400
    targets = [(t["ip"], int(t.get("port", 443))) for t in raw_targets if "ip" in t]
    results = tls_inspector.inspect_batch(targets)
    return jsonify({
        "count": len(results),
        "results": [r.to_dict() for r in results],
    })


@app.route("/tls/scan-from-results", methods=["GET", "OPTIONS"])
def tls_scan_from_results() -> Any:
    """Auto-run TLS inspection on all HTTPS hosts found in the latest scan."""
    if scanner is None:
        return jsonify({"results": [], "message": "Scanner not initialized yet"})
    job = scanner.get_latest_job()
    if not job or job.state != "done":
        return jsonify({"results": [], "message": "No completed scan available yet"})

    targets = []
    for host in job.results:
        for port_result in host.ports:
            if port_result.state == "open" and port_result.service in {"https", "https-alt"}:
                targets.append((host.ip, port_result.port))

    if not targets:
        return jsonify({"results": [], "message": "No HTTPS hosts found in last scan"})

    results = tls_inspector.inspect_batch(targets, max_workers=6)
    return jsonify({
        "count": len(results),
        "results": [r.to_dict() for r in results],
    })


# ── THREAT FUSION ENGINE ───────────────────────────────────────────────────────
@app.route("/fusion/analyze", methods=["POST", "OPTIONS"])
def fusion_analyze() -> Any:
    """Run threat fusion analysis on provided events.
    Body: { "events": [...], "window_minutes": 10 }
    """
    if fusion_engine is None:
        return jsonify({"error": "fusion engine not initialized"}), 503
    body = request.get_json(silent=True) or {}
    raw_events = body.get("events", [])
    window = int(body.get("window_minutes", 10))
    if not isinstance(raw_events, list):
        return jsonify({"error": "events must be a list"}), 400

    campaigns = fusion_engine.analyze(raw_events, window_minutes=window)
    stats = fusion_engine.get_statistics(campaigns)
    return jsonify({
        "campaigns": [c.to_dict() for c in campaigns],
        "statistics": stats,
    })


@app.route("/fusion/live", methods=["GET", "OPTIONS"])
def fusion_live() -> Any:
    """Fetch live events from orchestrator and run fusion analysis."""
    if fusion_engine is None:
        return jsonify({"error": "fusion engine not initialized"}), 503
    window = int(request.args.get("window_minutes", 10))
    max_events = int(request.args.get("max_events", 500))
    campaigns = fusion_engine.fetch_and_analyze(
        window_minutes=window, max_events=max_events
    )
    stats = fusion_engine.get_statistics(campaigns)
    return jsonify({
        "campaigns": [c.to_dict() for c in campaigns],
        "statistics": stats,
    })


@app.route("/fusion/stats", methods=["GET", "OPTIONS"])
def fusion_stats() -> Any:
    """Get high-level fusion statistics (no campaign detail) for dashboard widget."""
    if fusion_engine is None:
        return jsonify({"error": "fusion engine not initialized"}), 503
    campaigns = fusion_engine.fetch_and_analyze(window_minutes=60, max_events=200)
    stats = fusion_engine.get_statistics(campaigns)
    return jsonify(stats)


# ── BACKGROUND WORKER ──────────────────────────────────────────────────────────
def _background_worker() -> None:
    """No-op: simulation cycle removed to comply with 'real data only' policy.
    The network module now only produces output in response to explicit
    scan/inspect API calls. Enable simulation by setting NETWORK_SIMULATE=1.
    """
    if os.getenv("NETWORK_SIMULATE", "").lower() not in {"1", "true", "yes"}:
        LOGGER.info("Network simulation disabled (set NETWORK_SIMULATE=1 to enable)")
        return
    while True:
        try:
            LOGGER.warning("Network simulation cycle (NETWORK_SIMULATE=1)")
            monitor.run_simulation(cycles=20)  # type: ignore[union-attr]
        except Exception as exc:
            LOGGER.error("Background simulation failed: %s", exc)
        time.sleep(60)


# ── MAIN ───────────────────────────────────────────────────────────────────────
def main() -> int:
    log_level = os.getenv("AEGIS_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level, format="%(asctime)s %(levelname)s %(name)s %(message)s"
    )

    global monitor, scanner, fusion_engine
    monitor = NetworkMonitor({
        "interface": os.getenv("NETWORK_INTERFACE"),
        "orchestrator_url": os.getenv("ORCHESTRATOR_URL"),
    })
    scanner = LANScanner(
        orchestrator_url=os.getenv("ORCHESTRATOR_URL", "http://localhost:8080"),
        allow_public=os.getenv("SCAN_ALLOW_PUBLIC", "").lower() in ("1", "true", "yes"),
        max_hosts=int(os.getenv("SCAN_MAX_HOSTS", "256")),
        max_concurrent=int(os.getenv("SCAN_MAX_CONCURRENT", "3")),
    )
    orchestrator_url = os.getenv("ORCHESTRATOR_URL", "http://localhost:8080")
    fusion_engine = ThreatFusionEngine(orchestrator_url=orchestrator_url)

    t = threading.Thread(target=_background_worker, daemon=True)
    t.start()

    port = int(os.getenv("NETWORK_API_PORT", "8081"))
    BIND_HOST = os.getenv("NETWORK_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
