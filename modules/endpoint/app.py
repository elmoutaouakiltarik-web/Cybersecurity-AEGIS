#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Endpoint Protection Module
=================================================
Flask service that runs NATIVE on the host (Windows recommended). Exposes
real telemetry: Microsoft Defender, Windows Firewall, BitLocker, accounts,
autoruns, listening ports, SMB shares, pending updates, telemetry settings,
PowerShell logging, processes, network connections.

Also exposes:
  - YARA file scanner            POST /scan/file        (multipart upload)
  - YARA directory walker        POST /scan/directory
  - Secrets sweeper (Gitleaks)   POST /scan/secrets
  - Hardening audit (Lynis-like) GET  /audit

No data is sent to any remote service unless the operator explicitly
forwards a finding via the AEGIS orchestrator.

Bind: 127.0.0.1 only by default. Set ENDPOINT_BIND_HOST=0.0.0.0 to expose
on the LAN (we strongly recommend keeping it on loopback and letting the
orchestrator proxy).
"""
from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request

# Local modules
from windows_audit import (
    run_hardening_audit, get_system_info,
    check_defender, check_firewall, check_bitlocker,
    check_local_accounts, check_smb_v1, check_rdp, check_uac,
    check_autoruns, check_listening_ports, check_shares,
    check_updates_pending, check_telemetry, check_powershell_logging,
)
from file_scanner import FileScanner
from secrets_scanner import scan_directory as secrets_scan_directory, scan_file as secrets_scan_file
from process_scanner import list_processes, list_connections
from tool_integrations import inventory_security_tools, run_clamav_scan
from threat_hunt import list_queries as hunt_list, run_query as hunt_run, run_all as hunt_run_all
from live_iocs import IOCDatabase
from realtime_monitor import RealtimeMonitor
from posture import compute_posture
import containment
from enhanced_audit import run_enhanced_audit, ENHANCED_CHECKS
from threat_intel_pro import (
    CISAKevCatalog, hibp_check_password,
    navigator_layer_from_findings, apt_groups_for_technique,
    crtsh_lookup,
)
from process_tree import (
    build_process_tree, RansomwareDetector,
    check_amsi, check_wdac_applocker,
)
from forensics import (
    analyze_powershell_logs, analyze_pe, analyze_pdf,
    analyze_office, analyze_email, check_doh_resolver,
)
from pro_audit import (
    check_email_auth, check_spf, check_dkim, check_dmarc,
    check_backup_health, csf_maturity,
    check_office_macro_security, check_smart_app_control, check_windows_hello,
)
from honeypot import HoneypotManager
from sigma_live import (
    SigmaLiveEngine, list_sigma_live_rules,
    list_atomic_tests, run_atomic_test,
    d3fend_for, d3fend_coverage, vt_lookup,
)
from exec_report import build_html_report

try:
    import requests
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

# Shared secret for orchestrator ingest endpoints (must match AEGIS_INGEST_KEY).
_INGEST_HEADERS = {"X-AEGIS-INGEST-KEY": os.environ.get("AEGIS_INGEST_KEY", "")}

LOGGER = logging.getLogger("aegis.endpoint")
app = Flask(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

VERSION = "1.0.0"
BIND_HOST = os.getenv("ENDPOINT_BIND_HOST", "127.0.0.1")
BIND_PORT = int(os.getenv("ENDPOINT_API_PORT", "8088"))
ORCHESTRATOR_URL = os.getenv("ORCHESTRATOR_URL", "http://127.0.0.1:8080")
YARA_RULES_DIR = os.getenv(
    "YARA_RULES_DIR",
    str(Path(__file__).resolve().parent.parent / "intelligence" / "yara" / "rules"),
)
HASH_DB = os.getenv("ENDPOINT_HASH_DB", "")  # optional malicious_hashes.txt
ENABLE_DEFENDER = os.getenv("ENDPOINT_USE_DEFENDER", "1").lower() in {"1", "true", "yes"}
ENABLE_INGEST = os.getenv("ENDPOINT_INGEST", "1").lower() in {"1", "true", "yes"}

scanner = FileScanner(
    yara_rules_dir=YARA_RULES_DIR,
    additional_hashes_file=HASH_DB or None,
    enable_defender=ENABLE_DEFENDER,
)

# IOC database (live feeds: URLhaus, FeodoTracker, MalwareBazaar, Tor, Spamhaus DROP)
IOC_CACHE_DIR = os.getenv("AEGIS_IOC_CACHE_DIR",
                          str(Path(__file__).resolve().parent.parent.parent / "data" / "iocs"))
ioc_db = IOCDatabase(cache_dir=IOC_CACHE_DIR, freshness_hours=12)

# Realtime monitor — started on demand via /realtime/start
realtime = RealtimeMonitor(
    orchestrator_url=ORCHESTRATOR_URL,
    poll_interval=float(os.getenv("REALTIME_INTERVAL", "15")),
)

# Auto-refresh IOC feeds at startup in a background thread (non-blocking).
def _bootstrap_iocs() -> None:
    try:
        LOGGER.info("Bootstrapping live IOC feeds (background)...")
        ioc_db.refresh_all(force=False)
    except Exception as e:
        LOGGER.warning("IOC bootstrap failed: %s", e)
threading.Thread(target=_bootstrap_iocs, daemon=True).start()

# CISA KEV catalog (Known Exploited Vulnerabilities)
KEV_CACHE_DIR = os.getenv("AEGIS_KEV_CACHE_DIR",
                           str(Path(__file__).resolve().parent.parent.parent / "data" / "kev"))
kev_catalog = CISAKevCatalog(cache_dir=KEV_CACHE_DIR)

# Ransomware real-time detector — emits events to orchestrator
def _ransom_emit(payload: Dict[str, Any]) -> None:
    if not _REQUESTS or not ENABLE_INGEST:
        return
    try:
        requests.post(f"{ORCHESTRATOR_URL}/api/v1/ingest/generic",
                       json=payload, timeout=4, headers=_INGEST_HEADERS)
    except Exception:
        pass
ransom_detector = RansomwareDetector(emit_callback=_ransom_emit)

# Honeypot manager
def _honey_emit(evt) -> None:
    if not _REQUESTS or not ENABLE_INGEST:
        return
    try:
        requests.post(f"{ORCHESTRATOR_URL}/api/v1/ingest/generic", json={
            "source":      "endpoint.honeypot",
            "category":    "honeypot",
            "severity":    "high",
            "title":       f"Honeypot hit: {evt.trap_name} from {evt.src_ip}",
            "description": f"Trap {evt.trap_type} on port {evt.listen_port} touched by {evt.src_ip}:{evt.src_port}. {evt.banner_exchange[:200]}",
            "tags":        ["honeypot", "deception", "real-time", evt.technique],
            "raw_data":    evt.to_dict(),
            "timestamp":   evt.timestamp,
        }, timeout=4, headers=_INGEST_HEADERS)
    except Exception:
        pass
honeypot = HoneypotManager(emit_callback=_honey_emit,
                             bind=os.getenv("HONEYPOT_BIND", "127.0.0.1"))

# Sigma live engine
def _sigma_emit(evt: Dict[str, Any]) -> None:
    if not _REQUESTS or not ENABLE_INGEST:
        return
    try:
        requests.post(f"{ORCHESTRATOR_URL}/api/v1/ingest/generic", json=evt, timeout=4, headers=_INGEST_HEADERS)
    except Exception:
        pass
sigma_engine = SigmaLiveEngine(
    interval_sec=int(os.getenv("SIGMA_LIVE_INTERVAL", "60")),
    emit_callback=_sigma_emit,
)
def _bootstrap_kev() -> None:
    try:
        LOGGER.info("Bootstrapping CISA KEV catalog...")
        kev_catalog.refresh(force=False)
    except Exception as e:
        LOGGER.warning("KEV bootstrap failed: %s", e)
threading.Thread(target=_bootstrap_kev, daemon=True).start()


# ── CORS ──────────────────────────────────────────────────────────────────────

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


# ── Health & info ─────────────────────────────────────────────────────────────

@app.route("/health", methods=["GET", "OPTIONS"])
def health():
    return jsonify({
        "status": "healthy",
        "version": VERSION,
        "platform": sys.platform,
        "yara_rules_dir": YARA_RULES_DIR,
        "yara_loaded": scanner._yara_rules is not None,
        "defender_enabled": scanner.enable_defender,
        "hash_iocs": len(scanner._hash_db),
    })


@app.route("/info", methods=["GET", "OPTIONS"])
def info():
    return jsonify(get_system_info())


@app.route("/integrations", methods=["GET", "OPTIONS"])
def integrations():
    """Inventory defensive tools that are really installed/configured."""
    timeout = float(request.args.get("timeout", "2.5"))
    return jsonify(inventory_security_tools(timeout=max(0.5, min(timeout, 10.0))))


# ── Individual Windows checks ─────────────────────────────────────────────────

@app.route("/defender", methods=["GET", "OPTIONS"])
def defender():
    return jsonify(check_defender())


@app.route("/firewall", methods=["GET", "OPTIONS"])
def firewall():
    return jsonify(check_firewall())


@app.route("/bitlocker", methods=["GET", "OPTIONS"])
def bitlocker():
    return jsonify(check_bitlocker())


@app.route("/accounts", methods=["GET", "OPTIONS"])
def accounts():
    return jsonify(check_local_accounts())


@app.route("/smb-v1", methods=["GET", "OPTIONS"])
def smb_v1():
    return jsonify(check_smb_v1())


@app.route("/rdp", methods=["GET", "OPTIONS"])
def rdp():
    return jsonify(check_rdp())


@app.route("/uac", methods=["GET", "OPTIONS"])
def uac():
    return jsonify(check_uac())


@app.route("/autoruns", methods=["GET", "OPTIONS"])
def autoruns():
    return jsonify(check_autoruns())


@app.route("/listening-ports", methods=["GET", "OPTIONS"])
def ports():
    return jsonify(check_listening_ports())


@app.route("/shares", methods=["GET", "OPTIONS"])
def shares():
    return jsonify(check_shares())


@app.route("/telemetry", methods=["GET", "OPTIONS"])
def telemetry():
    return jsonify(check_telemetry())


@app.route("/pslogging", methods=["GET", "OPTIONS"])
def pslogging():
    return jsonify(check_powershell_logging())


@app.route("/updates", methods=["GET", "OPTIONS"])
def updates():
    return jsonify(check_updates_pending())


# ── Hardening audit (Lynis-like) ──────────────────────────────────────────────

@app.route("/audit", methods=["GET", "POST", "OPTIONS"])
def audit():
    include_updates = (request.args.get("updates", "0") in {"1", "true", "yes"})
    result = run_hardening_audit(include_updates=include_updates)
    # Forward critical/high findings to orchestrator
    if ENABLE_INGEST and _REQUESTS:
        threading.Thread(
            target=_forward_findings,
            args=(result.get("findings", []), "hardening_audit"),
            daemon=True,
        ).start()
    return jsonify(result)


# ── Processes ─────────────────────────────────────────────────────────────────

@app.route("/processes", methods=["GET", "OPTIONS"])
def processes():
    top = int(request.args.get("top", "200"))
    return jsonify(list_processes(top_n=top))


@app.route("/connections", methods=["GET", "OPTIONS"])
def connections():
    return jsonify(list_connections())


# ── File scanner ──────────────────────────────────────────────────────────────

@app.route("/scan/file", methods=["POST", "OPTIONS"])
def scan_file_endpoint():
    """Upload a file via multipart-form 'file' OR pass JSON {path: '...'}.

    Returns the full scan result (YARA + hash + optional Defender).
    """
    run_defender = (request.args.get("defender", "0") in {"1", "true", "yes"})
    if "file" in request.files:
        upload = request.files["file"]
        # Read the entire upload into memory (cap at 200 MB) and scan in-RAM.
        # This avoids brittle Windows interactions with NamedTemporaryFile
        # under werkzeug threading where the same path is briefly held by two
        # handles.
        try:
            content = upload.stream.read(200 * 1024 * 1024 + 1)
        except Exception as e:
            return jsonify({"error": f"could not read upload: {e}"}), 400
        if len(content) > 200 * 1024 * 1024:
            return jsonify({"error": "File exceeds 200 MB limit"}), 413
        result = scanner.scan_bytes(content, label=upload.filename, run_defender=run_defender)
        d = result.to_dict()
        d["uploaded_filename"] = upload.filename
        d["file_path"] = upload.filename
        if ENABLE_INGEST and result.verdict in {"suspicious", "malicious"}:
            _ingest_event({
                "source": "endpoint",
                "category": "endpoint",
                "severity": "critical" if result.verdict == "malicious" else "high",
                "title": f"File scan: {upload.filename} → {result.verdict}",
                "description": result.summary,
                "tags": ["endpoint", "file_scan", "yara"],
                "raw_data": {"sha256": result.sha256, "verdict": result.verdict},
            })
        return jsonify(d)

    body = request.get_json(silent=True) or {}
    path = body.get("path", "")
    if not path:
        return jsonify({"error": "no file uploaded and no 'path' in body"}), 400
    result = scanner.scan(path, run_defender=run_defender)
    return jsonify(result.to_dict())


@app.route("/scan/directory", methods=["POST", "OPTIONS"])
def scan_directory_endpoint():
    body = request.get_json(silent=True) or {}
    directory = body.get("path") or body.get("directory") or ""
    if not directory:
        return jsonify({"error": "missing 'path'"}), 400
    max_files = int(body.get("max_files", 5000))
    extensions = body.get("extensions") or None
    run_defender = bool(body.get("defender", False))
    result = scanner.scan_directory(
        directory, max_files=max_files,
        extensions=extensions if isinstance(extensions, list) else None,
        run_defender=run_defender,
    )
    return jsonify(result)


# ── Secrets sweeper ───────────────────────────────────────────────────────────

@app.route("/scan/secrets", methods=["POST", "OPTIONS"])
def secrets_endpoint():
    body = request.get_json(silent=True) or {}
    directory = body.get("path") or body.get("directory") or ""
    if not directory:
        return jsonify({"error": "missing 'path'"}), 400
    max_files = int(body.get("max_files", 20000))
    include_dotfiles = bool(body.get("include_dotfiles", True))
    result = secrets_scan_directory(directory, max_files=max_files,
                                    include_dotfiles=include_dotfiles)
    if ENABLE_INGEST and result.get("total_findings", 0) > 0:
        threading.Thread(target=_ingest_secrets_summary, args=(result,), daemon=True).start()
    return jsonify(result)


@app.route("/scan/clamav", methods=["POST", "OPTIONS"])
def clamav_endpoint():
    """Run a real local ClamAV scan when clamscan/clamdscan is installed."""
    if request.method == "OPTIONS":
        return jsonify({"ok": True})
    body = request.get_json(silent=True) or {}
    path = body.get("path") or body.get("file") or body.get("directory") or ""
    if not path:
        return jsonify({"error": "missing 'path'"}), 400
    recursive = bool(body.get("recursive", True))
    timeout = int(body.get("timeout", os.getenv("CLAMAV_SCAN_TIMEOUT", "300")))
    result = run_clamav_scan(path, recursive=recursive, timeout=timeout)
    if ENABLE_INGEST and result.get("verdict") == "infected":
        threading.Thread(target=_ingest_clamav_summary, args=(result,), daemon=True).start()
    status = 200
    if result.get("error"):
        status = 503 if "clamav binary" in result.get("error", "").lower() else 400
    return jsonify(result), status


# ── Threat Hunting ────────────────────────────────────────────────────────────

@app.route("/hunt", methods=["GET", "OPTIONS"])
def hunt_catalog():
    """List all available threat hunting queries."""
    return jsonify({"queries": hunt_list(), "count": len(hunt_list())})


@app.route("/hunt/run", methods=["POST", "OPTIONS"])
def hunt_run_all_endpoint():
    """Execute every query in parallel and return aggregated findings."""
    body = request.get_json(silent=True) or {}
    parallel = bool(body.get("parallel", True))
    result = hunt_run_all(parallel=parallel)
    if ENABLE_INGEST and result.get("total_findings", 0) > 0:
        threading.Thread(target=_forward_findings,
                          args=(result["findings"], "threat_hunt"),
                          daemon=True).start()
    return jsonify(result)


@app.route("/hunt/<query_id>", methods=["GET", "POST", "OPTIONS"])
def hunt_run_one(query_id: str):
    res = hunt_run(query_id)
    if ENABLE_INGEST and res.get("findings"):
        threading.Thread(target=_forward_findings,
                          args=(res["findings"], f"hunt:{query_id}"),
                          daemon=True).start()
    return jsonify(res)


# ── IOC Feeds (live) ──────────────────────────────────────────────────────────

@app.route("/ioc/feeds", methods=["GET", "OPTIONS"])
def ioc_feeds_status():
    return jsonify({
        "stats": ioc_db.stats(),
        "feeds": list(ioc_db.feed_meta.values()),
    })


@app.route("/ioc/refresh", methods=["POST", "OPTIONS"])
def ioc_refresh():
    body = request.get_json(silent=True) or {}
    force = bool(body.get("force", False))
    return jsonify(ioc_db.refresh_all(force=force))


@app.route("/ioc/lookup", methods=["GET", "POST", "OPTIONS"])
def ioc_lookup():
    """Lookup an indicator: ?ip=... | ?domain=... | ?url=... | ?hash=..."""
    args = request.args if request.method == "GET" else (request.get_json(silent=True) or {})
    ip = (args.get("ip") or "").strip()
    domain = (args.get("domain") or "").strip()
    url = (args.get("url") or "").strip()
    h = (args.get("hash") or "").strip()
    matches = []
    if ip:
        m = ioc_db.lookup_ip(ip);     matches.append({"input": ip, "kind": "ip", "match": m})
    if domain:
        m = ioc_db.lookup_domain(domain); matches.append({"input": domain, "kind": "domain", "match": m})
    if url:
        m = ioc_db.lookup_url(url);   matches.append({"input": url, "kind": "url", "match": m})
    if h:
        m = ioc_db.lookup_hash(h);    matches.append({"input": h, "kind": "hash", "match": m})
    matched_any = any(m["match"] for m in matches)
    return jsonify({"matched": matched_any, "results": matches})


# ── Realtime monitor ──────────────────────────────────────────────────────────

@app.route("/realtime/status", methods=["GET", "OPTIONS"])
def realtime_status():
    return jsonify({"running": realtime.is_running(), "stats": realtime.stats})


@app.route("/realtime/start", methods=["POST", "OPTIONS"])
def realtime_start():
    realtime.start()
    return jsonify({"ok": True, "running": realtime.is_running(), "stats": realtime.stats})


@app.route("/realtime/stop", methods=["POST", "OPTIONS"])
def realtime_stop():
    realtime.stop()
    return jsonify({"ok": True, "running": realtime.is_running(), "stats": realtime.stats})


# ── Security Posture Score ────────────────────────────────────────────────────

@app.route("/posture", methods=["GET", "OPTIONS"])
def posture_endpoint():
    result = compute_posture(
        ioc_db=ioc_db,
        yara_loaded=scanner._yara_rules is not None,
    )
    if ENABLE_INGEST and result.get("top_actions"):
        threading.Thread(target=_forward_findings,
                          args=(result["top_actions"], "posture"),
                          daemon=True).start()
    return jsonify(result)


# ── Containment actions (dry-run by default) ──────────────────────────────────

def _confirm() -> bool:
    """True only if the caller explicitly sent X-AEGIS-Confirm: yes."""
    return (request.headers.get("X-AEGIS-Confirm", "").lower() in {"yes", "true", "1"})


@app.route("/contain/log", methods=["GET", "OPTIONS"])
def contain_log():
    return jsonify({"recent": containment.recent_log(limit=100)})


@app.route("/contain/block-ip", methods=["POST", "OPTIONS"])
def contain_block_ip():
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()
    direction = body.get("direction", "in")
    reason = body.get("reason", "manual via dashboard")
    if not ip:
        return jsonify({"ok": False, "error": "missing 'ip'"}), 400
    return jsonify(containment.action_block_ip(ip, direction, confirm=_confirm(), reason=reason))


@app.route("/contain/unblock-ip", methods=["POST", "OPTIONS"])
def contain_unblock_ip():
    body = request.get_json(silent=True) or {}
    ip = (body.get("ip") or "").strip()
    direction = body.get("direction", "in")
    if not ip:
        return jsonify({"ok": False, "error": "missing 'ip'"}), 400
    return jsonify(containment.action_unblock_ip(ip, direction, confirm=_confirm()))


@app.route("/contain/kill-pid", methods=["POST", "OPTIONS"])
def contain_kill_pid():
    body = request.get_json(silent=True) or {}
    pid = body.get("pid")
    reason = body.get("reason", "manual via dashboard")
    if pid is None:
        return jsonify({"ok": False, "error": "missing 'pid'"}), 400
    try:
        pid_int = int(pid)
    except Exception:
        return jsonify({"ok": False, "error": "invalid pid"}), 400
    return jsonify(containment.action_kill_pid(pid_int, confirm=_confirm(), reason=reason))


@app.route("/contain/quarantine", methods=["POST", "OPTIONS"])
def contain_quarantine():
    body = request.get_json(silent=True) or {}
    path = (body.get("path") or "").strip()
    reason = body.get("reason", "manual via dashboard")
    if not path:
        return jsonify({"ok": False, "error": "missing 'path'"}), 400
    return jsonify(containment.action_quarantine_file(path, confirm=_confirm(), reason=reason))


@app.route("/contain/disable-account", methods=["POST", "OPTIONS"])
def contain_disable_account():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    reason = body.get("reason", "manual via dashboard")
    if not name:
        return jsonify({"ok": False, "error": "missing 'name'"}), 400
    return jsonify(containment.action_disable_account(name, confirm=_confirm(), reason=reason))


@app.route("/contain/enable-account", methods=["POST", "OPTIONS"])
def contain_enable_account():
    body = request.get_json(silent=True) or {}
    name = (body.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "missing 'name'"}), 400
    return jsonify(containment.action_enable_account(name, confirm=_confirm()))


@app.route("/contain/isolate", methods=["POST", "OPTIONS"])
def contain_isolate():
    body = request.get_json(silent=True) or {}
    allow_ip = (body.get("allow_ip") or "").strip()
    reason = body.get("reason", "incident response — manual")
    return jsonify(containment.action_isolate_host(confirm=_confirm(), allow_ip=allow_ip, reason=reason))


@app.route("/contain/unisolate", methods=["POST", "OPTIONS"])
def contain_unisolate():
    return jsonify(containment.action_unisolate_host(confirm=_confirm()))


# ── Enhanced audit (TPM / Secure Boot / VBS / Sysmon / USB / WiFi / Browser / LAPS / Audit policy / Drivers)

@app.route("/enhanced/audit", methods=["GET", "POST", "OPTIONS"])
def enhanced_audit_endpoint():
    result = run_enhanced_audit()
    if ENABLE_INGEST and result.get("findings"):
        threading.Thread(target=_forward_findings,
                          args=(result["findings"], "enhanced_audit"),
                          daemon=True).start()
    return jsonify(result)


@app.route("/enhanced/<check_name>", methods=["GET", "OPTIONS"])
def enhanced_single(check_name: str):
    fn = ENHANCED_CHECKS.get(check_name)
    if not fn:
        return jsonify({"error": f"unknown check: {check_name}",
                         "available": list(ENHANCED_CHECKS.keys())}), 404
    try:
        return jsonify(fn())
    except Exception as e:
        return jsonify({"available": False, "error": str(e)}), 500


# ── CISA KEV catalog ──────────────────────────────────────────────────────────

@app.route("/kev/stats", methods=["GET", "OPTIONS"])
def kev_stats():
    return jsonify(kev_catalog.stats())


@app.route("/kev/refresh", methods=["POST", "OPTIONS"])
def kev_refresh():
    body = request.get_json(silent=True) or {}
    return jsonify(kev_catalog.refresh(force=bool(body.get("force", False))))


@app.route("/kev/lookup", methods=["GET", "OPTIONS"])
def kev_lookup():
    cve = (request.args.get("cve") or "").strip()
    if not cve:
        return jsonify({"error": "missing 'cve'"}), 400
    v = kev_catalog.lookup(cve)
    if v is None:
        return jsonify({"matched": False, "cve": cve.upper()})
    return jsonify({"matched": True, "cve": cve.upper(), "vulnerability": v})


@app.route("/kev/search", methods=["GET", "OPTIONS"])
def kev_search():
    vendor  = (request.args.get("vendor") or "").strip()
    product = (request.args.get("product") or "").strip()
    days = request.args.get("days")
    days_int = int(days) if days and days.isdigit() else None
    results = kev_catalog.search(vendor=vendor, product=product, days=days_int)
    return jsonify({"count": len(results), "results": results[:200]})


# ── HIBP password breach check (k-anonymity) ──────────────────────────────────

@app.route("/hibp/password", methods=["POST", "OPTIONS"])
def hibp_password():
    body = request.get_json(silent=True) or {}
    pw = body.get("password") or ""
    if not pw:
        return jsonify({"error": "missing 'password'"}), 400
    res = hibp_check_password(pw)
    return jsonify(res)


# ── MITRE ATT&CK Navigator export ─────────────────────────────────────────────

@app.route("/mitre/navigator-layer", methods=["POST", "GET", "OPTIONS"])
def mitre_navigator_layer():
    """Build a MITRE Navigator layer from passed findings, or pull from the
    last hunt/audit runs in memory.
    """
    body = request.get_json(silent=True) or {}
    findings: List[Dict[str, Any]] = body.get("findings") or []
    if not findings:
        # Run a fresh aggregate
        from threat_hunt import run_all as _run_all
        from windows_audit import run_hardening_audit
        try:
            hunt_res = _run_all(parallel=True)
            findings.extend(hunt_res.get("findings", []))
        except Exception as e:
            LOGGER.warning("hunt for navigator failed: %s", e)
        try:
            audit_res = run_hardening_audit()
            findings.extend(audit_res.get("findings", []))
        except Exception as e:
            LOGGER.warning("audit for navigator failed: %s", e)
    layer = navigator_layer_from_findings(
        findings,
        name=body.get("name", "AEGIS observed coverage"),
        description=body.get("description", "Auto-generated from hunt + audit findings"),
    )
    return jsonify(layer)


@app.route("/mitre/apt-for-technique", methods=["GET", "OPTIONS"])
def mitre_apt_for_technique():
    tid = (request.args.get("technique") or "").strip()
    if not tid:
        return jsonify({"error": "missing 'technique'"}), 400
    return jsonify({"technique": tid.upper(),
                     "groups": apt_groups_for_technique(tid)})


# ── Certificate Transparency lookup (crt.sh) ──────────────────────────────────

@app.route("/crt/lookup", methods=["GET", "OPTIONS"])
def crt_lookup():
    domain = (request.args.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "missing 'domain'"}), 400
    return jsonify(crtsh_lookup(domain,
                                  max_results=int(request.args.get("limit", "100"))))


# ── Process tree (SOC-grade visualization) ────────────────────────────────────

@app.route("/process-tree", methods=["GET", "OPTIONS"])
def process_tree_endpoint():
    top_n = int(request.args.get("top", "300"))
    return jsonify(build_process_tree(top_n=top_n))


# ── Ransomware real-time detector ─────────────────────────────────────────────

@app.route("/ransomware/status", methods=["GET", "OPTIONS"])
def ransom_status():
    return jsonify({
        "running":         ransom_detector.is_running(),
        "events_emitted":  ransom_detector.events_emitted,
        "last_poll_at":    ransom_detector.last_poll_at,
        "started_at":      ransom_detector.started_at,
    })

@app.route("/ransomware/start", methods=["POST", "OPTIONS"])
def ransom_start():
    ransom_detector.start()
    return jsonify({"ok": True, "running": ransom_detector.is_running()})

@app.route("/ransomware/stop", methods=["POST", "OPTIONS"])
def ransom_stop():
    ransom_detector.stop()
    return jsonify({"ok": True, "running": ransom_detector.is_running()})


# ── AMSI + WDAC + AppLocker ───────────────────────────────────────────────────

@app.route("/amsi", methods=["GET", "OPTIONS"])
def amsi_endpoint():
    return jsonify(check_amsi())

@app.route("/wdac-applocker", methods=["GET", "OPTIONS"])
def wdac_endpoint():
    return jsonify(check_wdac_applocker())


# ── PowerShell ScriptBlock log analyzer (Event 4104) ──────────────────────────

@app.route("/ps-log/analyze", methods=["GET", "OPTIONS"])
def pslog_endpoint():
    hours = int(request.args.get("hours", "24"))
    max_ev = int(request.args.get("max", "500"))
    res = analyze_powershell_logs(max_events=max_ev, hours=hours)
    if ENABLE_INGEST and res.get("findings"):
        threading.Thread(target=_forward_findings,
                          args=(res["findings"], "ps_log"),
                          daemon=True).start()
    return jsonify(res)


# ── File deep inspector (PE / PDF / Office / Email) ───────────────────────────

@app.route("/deep-inspect", methods=["POST", "OPTIONS"])
def deep_inspect():
    if "file" not in request.files:
        return jsonify({"error": "multipart 'file' required"}), 400
    upload = request.files["file"]
    content = upload.stream.read(200 * 1024 * 1024 + 1)
    if len(content) > 200 * 1024 * 1024:
        return jsonify({"error": "file > 200 MB"}), 413
    name = (upload.filename or "").lower()
    sha256 = hashlib.sha256(content).hexdigest() if (hashlib := __import__("hashlib")) else ""
    out = {
        "filename": upload.filename,
        "size": len(content),
        "sha256": sha256,
    }
    # Heuristic dispatch
    if content[:4] == b"%PDF":
        out["pdf"] = analyze_pdf(content)
    if content[:2] == b"MZ":
        out["pe"] = analyze_pe(content)
    if content[:2] == b"PK":
        out["office"] = analyze_office(content, filename=upload.filename or "")
    if name.endswith(".eml") or content[:4].lower() in (b"from", b"subj") or b"\nFrom:" in content[:2000]:
        out["email"] = analyze_email(content)
    if not any(k in out for k in ("pdf", "pe", "office", "email")):
        out["note"] = "Tipo non riconosciuto per deep inspect (supportati: PE, PDF, OOXML Office, .eml)"
    return jsonify(out)


# ── Email auth (SPF / DKIM / DMARC) ───────────────────────────────────────────

@app.route("/email-auth", methods=["GET", "OPTIONS"])
def email_auth_endpoint():
    domain = (request.args.get("domain") or "").strip()
    if not domain:
        return jsonify({"error": "missing 'domain'"}), 400
    return jsonify(check_email_auth(domain))


# ── DNS over HTTPS check ──────────────────────────────────────────────────────

@app.route("/doh/check", methods=["GET", "OPTIONS"])
def doh_endpoint():
    return jsonify(check_doh_resolver())


# ── Backup health (3-2-1 rule) ────────────────────────────────────────────────

@app.route("/backup/health", methods=["GET", "OPTIONS"])
def backup_endpoint():
    return jsonify(check_backup_health())


# ── NIST CSF maturity report ──────────────────────────────────────────────────

@app.route("/csf/maturity", methods=["GET", "OPTIONS"])
def csf_endpoint():
    return jsonify(csf_maturity())


# ── Office macro + Smart App Control + Windows Hello ──────────────────────────

@app.route("/office/macros", methods=["GET", "OPTIONS"])
def office_macros_endpoint():
    return jsonify(check_office_macro_security())

@app.route("/smart-app-control", methods=["GET", "OPTIONS"])
def smart_app_endpoint():
    return jsonify(check_smart_app_control())

@app.route("/hello", methods=["GET", "OPTIONS"])
def hello_endpoint():
    return jsonify(check_windows_hello())


# ── Honeypot (real socket listeners) ──────────────────────────────────────────

@app.route("/honeypot/status", methods=["GET", "OPTIONS"])
def hp_status():
    return jsonify(honeypot.status())

@app.route("/honeypot/start", methods=["POST", "OPTIONS"])
def hp_start():
    body = request.get_json(silent=True) or {}
    traps = body.get("traps")
    return jsonify(honeypot.start(traps))

@app.route("/honeypot/stop", methods=["POST", "OPTIONS"])
def hp_stop():
    body = request.get_json(silent=True) or {}
    name = body.get("name")
    return jsonify(honeypot.stop(name))


# ── Sigma Live Engine (Sysmon/Security log → match → ingest) ──────────────────

@app.route("/sigma-live/rules", methods=["GET", "OPTIONS"])
def sigma_live_rules():
    return jsonify({"rules": list_sigma_live_rules(),
                     "count": len(list_sigma_live_rules())})

@app.route("/sigma-live/status", methods=["GET", "OPTIONS"])
def sigma_live_status():
    return jsonify({
        "running":         sigma_engine.is_running(),
        "matches_count":   sigma_engine.matches_count,
        "last_run_at":     sigma_engine.last_run_at,
        "started_at":      sigma_engine.started_at,
        "last_results":    sigma_engine.last_results,
        "interval_sec":    sigma_engine.interval,
    })

@app.route("/sigma-live/start", methods=["POST", "OPTIONS"])
def sigma_live_start():
    sigma_engine.start()
    return jsonify({"ok": True, "running": sigma_engine.is_running()})

@app.route("/sigma-live/stop", methods=["POST", "OPTIONS"])
def sigma_live_stop():
    sigma_engine.stop()
    return jsonify({"ok": True, "running": sigma_engine.is_running()})


# ── Atomic Red Team safe tests ────────────────────────────────────────────────

@app.route("/atomic/tests", methods=["GET", "OPTIONS"])
def atomic_tests_list():
    return jsonify({"tests": list_atomic_tests()})

@app.route("/atomic/run/<test_id>", methods=["POST", "OPTIONS"])
def atomic_test_run(test_id: str):
    return jsonify(run_atomic_test(test_id))


# ── MITRE D3FEND mapping ──────────────────────────────────────────────────────

@app.route("/d3fend/for-technique", methods=["GET", "OPTIONS"])
def d3fend_endpoint():
    tid = (request.args.get("technique") or "").strip()
    if not tid:
        return jsonify({"error": "missing 'technique'"}), 400
    return jsonify({"technique": tid.upper(), "defenses": d3fend_for(tid)})

@app.route("/d3fend/coverage", methods=["POST", "OPTIONS"])
def d3fend_coverage_endpoint():
    body = request.get_json(silent=True) or {}
    findings = body.get("findings") or []
    return jsonify(d3fend_coverage(findings))


# ── VirusTotal lookup (requires VT_API_KEY env) ───────────────────────────────

@app.route("/vt/<kind>", methods=["GET", "POST", "OPTIONS"])
def vt_endpoint(kind: str):
    indicator = (request.args.get("indicator") or
                  (request.get_json(silent=True) or {}).get("indicator") or "").strip()
    if not indicator:
        return jsonify({"error": "missing 'indicator'"}), 400
    return jsonify(vt_lookup(kind, indicator))


# ── Executive HTML report ─────────────────────────────────────────────────────

_exec_report_cache: Dict[str, Any] = {"ts": 0, "html": ""}
_exec_report_lock = threading.Lock()

@app.route("/exec-report", methods=["GET", "OPTIONS"])
def exec_report_endpoint():
    """Build a self-contained HTML executive briefing. Print-to-PDF from any
    browser. Heavy audits run in PARALLEL and the entire report is cached
    for 5 minutes to keep latency on subsequent calls ~10ms."""
    from windows_audit import get_system_info, run_hardening_audit
    from posture import compute_posture
    from enhanced_audit import run_enhanced_audit
    from concurrent.futures import ThreadPoolExecutor

    force = request.args.get("force") in {"1", "true", "yes"}
    with _exec_report_lock:
        if not force and _exec_report_cache["html"] and (time.time() - _exec_report_cache["ts"] < 300):
            resp = app.response_class(_exec_report_cache["html"], mimetype="text/html")
            resp.headers["X-AEGIS-Cache"] = "HIT"
            resp.headers["Content-Disposition"] = 'inline; filename="aegis-exec-report.html"'
            return resp

    def _safe(fn, default):
        try:
            return fn()
        except Exception as e:
            LOGGER.warning("exec-report sub-task failed: %s", e)
            return default

    started = time.time()
    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="exec-report") as ex:
        fu_ps    = ex.submit(_safe, lambda: compute_posture(ioc_db=ioc_db,
                              yara_loaded=scanner._yara_rules is not None), {})
        fu_audit = ex.submit(_safe, lambda: run_hardening_audit().get("findings", []), [])
        fu_host  = ex.submit(_safe, get_system_info, {})
        fu_ioc   = ex.submit(_safe, lambda: ioc_db.stats(), {})
        # Heavy ones (skippable via ?quick=1)
        quick = request.args.get("quick") in {"1", "true", "yes"}
        fu_csf = None if quick else ex.submit(_safe, csf_maturity, {})
        fu_enh = None if quick else ex.submit(_safe, lambda: run_enhanced_audit().get("findings", []), [])

        ps        = fu_ps.result(timeout=60)
        audit_f   = fu_audit.result(timeout=60)
        host      = fu_host.result(timeout=30)
        ioc_stats = fu_ioc.result(timeout=10)
        csf       = fu_csf.result(timeout=90) if fu_csf else {}
        enh_f     = fu_enh.result(timeout=90) if fu_enh else []
    LOGGER.info("exec-report built in %.1fs (quick=%s)", time.time() - started, quick)

    html = build_html_report(
        posture=ps, csf=csf, ioc_stats=ioc_stats,
        audit_findings=audit_f, enhanced_findings=enh_f,
        host_info=host,
    )
    with _exec_report_lock:
        _exec_report_cache["ts"] = time.time()
        _exec_report_cache["html"] = html
    resp = app.response_class(html, mimetype="text/html")
    resp.headers["Content-Disposition"] = 'inline; filename="aegis-exec-report.html"'
    return resp


# ── Internal helpers ──────────────────────────────────────────────────────────

def _ingest_event(payload: Dict[str, Any]) -> None:
    """Best-effort POST to orchestrator /api/v1/ingest/generic."""
    if not _REQUESTS:
        return
    try:
        payload.setdefault("timestamp", datetime.now(timezone.utc).isoformat())
        requests.post(f"{ORCHESTRATOR_URL}/api/v1/ingest/generic",
                      json=payload, timeout=4, headers=_INGEST_HEADERS)
    except Exception as e:
        LOGGER.debug("ingest failed: %s", e)


def _forward_findings(findings: List[Dict[str, Any]], audit_type: str) -> None:
    """Forward only critical/high findings to keep the event bus useful."""
    important = [f for f in findings if f.get("severity") in {"critical", "high"}
                 and f.get("status") in {"warn", "fail"}]
    for f in important[:30]:
        _ingest_event({
            "source": "endpoint",
            "category": "endpoint",
            "severity": f.get("severity", "medium"),
            "title": f.get("title", "Endpoint audit finding"),
            "description": f.get("description", ""),
            "tags": ["endpoint", "hardening", audit_type, f.get("check", "")],
            "raw_data": {
                "check_id": f.get("check_id"),
                "remediation_key": f.get("remediation_key"),
                "value": f.get("value"),
            },
        })


def _ingest_secrets_summary(result: Dict[str, Any]) -> None:
    total = result.get("total_findings", 0)
    by_sev = result.get("by_severity", {})
    sev = "critical" if by_sev.get("critical") else "high" if by_sev.get("high") else "medium"
    _ingest_event({
        "source": "endpoint",
        "category": "endpoint",
        "severity": sev,
        "title": f"Secrets sweeper: {total} potential secrets in {result.get('directory')}",
        "description": f"By severity: {json.dumps(by_sev)}",
        "tags": ["endpoint", "secrets", "gitleaks"],
        "raw_data": {"directory": result.get("directory"), "by_severity": by_sev,
                     "by_rule": result.get("by_rule"), "top_files": result.get("top_files")},
    })


def _ingest_clamav_summary(result: Dict[str, Any]) -> None:
    _ingest_event({
        "source": "endpoint",
        "category": "endpoint",
        "severity": "critical",
        "title": f"ClamAV detected infected content in {result.get('path')}",
        "description": f"ClamAV infected count: {result.get('infected_count', 0)}",
        "tags": ["endpoint", "clamav", "malware"],
        "raw_data": {
            "path": result.get("path"),
            "scanner": result.get("scanner"),
            "infected_count": result.get("infected_count"),
            "exit_code": result.get("exit_code"),
        },
    })


# ── Registration with orchestrator on startup ────────────────────────────────

def _register_with_orchestrator() -> None:
    if not _REQUESTS or not ENABLE_INGEST:
        return
    try:
        requests.post(f"{ORCHESTRATOR_URL}/api/v1/ingest/generic", json={
            "source": "endpoint",
            "category": "endpoint",
            "severity": "info",
            "title": "Endpoint Protection module online",
            "description": f"Native endpoint module v{VERSION} on {sys.platform} reporting in.",
            "tags": ["endpoint", "startup"],
            "raw_data": {"host_info": get_system_info()},
        }, timeout=4, headers=_INGEST_HEADERS)
    except Exception:
        pass


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    log_level = os.getenv("AEGIS_LOG_LEVEL", "INFO").upper()
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    LOGGER.info("Endpoint Protection v%s starting on %s:%d", VERSION, BIND_HOST, BIND_PORT)
    LOGGER.info("YARA rules dir: %s (loaded=%s)", YARA_RULES_DIR, scanner._yara_rules is not None)
    LOGGER.info("Defender enabled: %s", scanner.enable_defender)
    LOGGER.info("Orchestrator URL: %s (ingest=%s)", ORCHESTRATOR_URL, ENABLE_INGEST)
    threading.Thread(target=_register_with_orchestrator, daemon=True).start()
    app.run(host=BIND_HOST, port=BIND_PORT, threaded=True, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
