"""
AEGIS-OMNI External Tool Integration Module
Checks presence, health and basic status of external OSS security tools.
Read-only probing; no configuration changes.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Tool registry: name -> check function
TOOLS: Dict[str, Any] = {}


def _run(cmd: List[str], timeout: float = 5.0) -> Optional[str]:
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def _tcp_check(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


def check_wazuh() -> Dict[str, Any]:
    present = shutil.which("wazuh-control") or shutil.which("wazuh-manager")
    service_up = False
    version = None
    if sys.platform != "win32":
        out = _run(["systemctl", "is-active", "wazuh-manager"], 3.0)
        service_up = out == "active"
        if not service_up:
            out = _run(["systemctl", "is-active", "wazuh-manager.service"], 3.0)
            service_up = out == "active"
    # Try API port 55000
    api_up = _tcp_check("127.0.0.1", 55000, 1.5)
    return {
        "name": "Wazuh",
        "category": "SIEM/XDR",
        "present": bool(present),
        "service_up": service_up,
        "api_up": api_up,
        "version": version,
        "ports": [1514, 1515, 55000],
        "note": "Backbone SIEM/XDR/HIDS. Install via wazuh-manager package."
    }


def check_suricata() -> Dict[str, Any]:
    present = shutil.which("suricata")
    version = None
    if present:
        out = _run(["suricata", "-V"], 3.0)
        if out:
            m = re.search(r"version\s+([\d.]+)", out)
            version = m.group(1) if m else out.splitlines()[0][:64]
    service_up = False
    if sys.platform != "win32":
        out = _run(["systemctl", "is-active", "suricata"], 3.0)
        service_up = out == "active"
    return {
        "name": "Suricata",
        "category": "NDR/NSM",
        "present": bool(present),
        "service_up": service_up,
        "version": version,
        "ports": ["af_packet/pcap"],
        "note": "IDS/IPS/NDR sensor. EVE JSON output compatible with AEGIS ingest."
    }


def check_zeek() -> Dict[str, Any]:
    present = shutil.which("zeek") or shutil.which("bro")
    version = None
    if present:
        out = _run(["zeek", "--version"], 3.0) if shutil.which("zeek") else _run(["bro", "--version"], 3.0)
        if out:
            m = re.search(r"([\d.]+)", out)
            version = m.group(1) if m else out.splitlines()[0][:64]
    return {
        "name": "Zeek",
        "category": "NDR/NSM",
        "present": bool(present),
        "version": version,
        "note": "Network analysis framework. High-fidelity metadata for IT and OT."
    }


def check_velociraptor() -> Dict[str, Any]:
    present = shutil.which("velociraptor")
    version = None
    gui_up = _tcp_check("127.0.0.1", 8889, 1.5)
    if present:
        out = _run(["velociraptor", "--version"], 3.0)
        if out:
            version = out.splitlines()[0][:64]
    return {
        "name": "Velociraptor",
        "category": "EDR/DFIR",
        "present": bool(present),
        "gui_up": gui_up,
        "version": version,
        "ports": [8889, 8000, 8001],
        "note": "DFIR and live endpoint response. AGPL-3.0; run as separate service."
    }


def check_openvas() -> Dict[str, Any]:
    present = shutil.which("openvas") or shutil.which("gvmd") or shutil.which("greenbone-scanner")
    service_up = False
    if sys.platform != "win32":
        for svc in ["openvas-scanner", "gvmd", "gsad", "ospd-openvas"]:
            out = _run(["systemctl", "is-active", svc], 2.0)
            if out == "active":
                service_up = True
                break
    return {
        "name": "Greenbone/OpenVAS",
        "category": "Vulnerability Management",
        "present": bool(present),
        "service_up": service_up,
        "ports": [9392, 443],
        "note": "Vulnerability scanner. Use safe profiles for OT networks."
    }


def check_misp() -> Dict[str, Any]:
    present = os.path.isdir("/var/www/MISP") or os.path.isdir("/usr/share/misp") or shutil.which("misp")
    api_up = _tcp_check("127.0.0.1", 443, 1.5)  # commonly on HTTPS
    return {
        "name": "MISP",
        "category": "Threat Intelligence",
        "present": bool(present),
        "api_up": api_up,
        "ports": [443, 80],
        "note": "Threat intelligence sharing platform. AGPL-3.0; run as separate service."
    }


def check_opencti() -> Dict[str, Any]:
    present = os.path.isdir("/opt/opencti") or os.path.isdir("/var/lib/docker/volumes/opencti") or shutil.which("opencti")
    api_up = _tcp_check("127.0.0.1", 8080, 1.5)
    return {
        "name": "OpenCTI",
        "category": "Threat Intelligence",
        "present": bool(present),
        "api_up": api_up,
        "ports": [8080, 4000],
        "note": "CTI knowledge graph. Requires Elasticsearch, Redis, MinIO, RabbitMQ."
    }


def check_stackstorm() -> Dict[str, Any]:
    present = shutil.which("st2") or os.path.isdir("/opt/stackstorm")
    service_up = False
    if sys.platform != "win32":
        out = _run(["systemctl", "is-active", "st2api"], 2.0)
        service_up = out == "active"
    return {
        "name": "StackStorm",
        "category": "SOAR/Automation",
        "present": bool(present),
        "service_up": service_up,
        "ports": [9100, 9101],
        "note": "Event-driven automation, sensors, rules, workflows."
    }


def check_keycloak() -> Dict[str, Any]:
    present = shutil.which("kc.sh") or shutil.which("standalone.sh") or os.path.isdir("/opt/keycloak")
    api_up = _tcp_check("127.0.0.1", 8080, 1.5) or _tcp_check("127.0.0.1", 8443, 1.5)
    return {
        "name": "Keycloak",
        "category": "IAM/SSO",
        "present": bool(present),
        "api_up": api_up,
        "ports": [8080, 8443],
        "note": "SSO, OIDC/OAuth2/SAML, federation with LDAP/AD."
    }


def check_packetfence() -> Dict[str, Any]:
    present = os.path.isdir("/usr/local/pf") or shutil.which("pfcmd")
    api_up = _tcp_check("127.0.0.1", 1443, 1.5)
    return {
        "name": "PacketFence",
        "category": "NAC",
        "present": bool(present),
        "api_up": api_up,
        "ports": [1443, 1812, 1813],
        "note": "NAC with 802.1X, RADIUS, VLAN enforcement. Pilot gradually."
    }


def check_step_ca() -> Dict[str, Any]:
    present = shutil.which("step-ca") or shutil.which("step")
    api_up = _tcp_check("127.0.0.1", 9000, 1.5)
    return {
        "name": "step-ca",
        "category": "PKI",
        "present": bool(present),
        "api_up": api_up,
        "ports": [9000],
        "note": "Private CA X.509/SSH/ACME. Central for mTLS service-to-service."
    }


def check_fleet() -> Dict[str, Any]:
    present = shutil.which("fleet") or os.path.isdir("/opt/fleet")
    api_up = _tcp_check("127.0.0.1", 8080, 1.5) or _tcp_check("127.0.0.1", 8412, 1.5)
    return {
        "name": "Fleet",
        "category": "Device Management",
        "present": bool(present),
        "api_up": api_up,
        "ports": [8080, 8412],
        "note": "Device management, software inventory, patching visibility via osquery."
    }


def check_opencanary() -> Dict[str, Any]:
    present = shutil.which("opencanary") or shutil.which("opencanaryd")
    version = None
    if present:
        out = _run(["opencanaryd", "--version"], 3.0) if shutil.which("opencanaryd") else None
        if out:
            version = out.splitlines()[0][:64]
    return {
        "name": "OpenCanary",
        "category": "Deception",
        "present": bool(present),
        "version": version,
        "note": "Modular honeypot IT. Distribute in DMZ, guest, decoy zones."
    }


def check_ghidra() -> Dict[str, Any]:
    present = shutil.which("ghidra") or os.path.isdir("/opt/ghidra")
    return {
        "name": "Ghidra",
        "category": "Reverse Engineering",
        "present": bool(present),
        "note": "NSA reverse engineering suite. Firmware/malware/plugin analysis."
    }


def check_volatility3() -> Dict[str, Any]:
    present = shutil.which("vol.py") or shutil.which("volatility3") or shutil.which("vol")
    version = None
    if present:
        cmd = ["volatility3", "--version"] if shutil.which("volatility3") else (["vol.py", "--version"] if shutil.which("vol.py") else ["vol", "--version"])
        out = _run(cmd, 3.0)
        if out:
            version = out.splitlines()[0][:64]
    return {
        "name": "Volatility 3",
        "category": "Memory Forensics",
        "present": bool(present),
        "version": version,
        "note": "Memory forensics for post-incident triage. Custom license; verify redistribution."
    }


def check_malcolm() -> Dict[str, Any]:
    present = os.path.isdir("/opt/malcolm") or os.path.isdir("/malcolm")
    # Malcolm is typically docker-compose based
    compose_present = os.path.isfile("/opt/malcolm/docker-compose.yml") if os.path.isdir("/opt/malcolm") else False
    return {
        "name": "Malcolm",
        "category": "NTA/PCAP/IR",
        "present": bool(present),
        "compose_present": compose_present,
        "note": "CISA NTA appliance. Zeek+Suricata+Arkime+OpenSearch. Use as IR/OT analytics module."
    }


def check_openplc() -> Dict[str, Any]:
    present = os.path.isdir("/opt/openplc") or os.path.isdir("/usr/local/openplc")
    api_up = _tcp_check("127.0.0.1", 8080, 1.5)
    return {
        "name": "OpenPLC Runtime v4",
        "category": "OT Lab/Digital Twin",
        "present": bool(present),
        "api_up": api_up,
        "ports": [8080, 502, 44818],
        "note": "IEC 61131-3 runtime lab. NOT a production PLC replacement. Use for training/twin."
    }


TOOL_CHECKS = [
    check_wazuh, check_suricata, check_zeek, check_velociraptor,
    check_openvas, check_misp, check_opencti, check_stackstorm,
    check_keycloak, check_packetfence, check_step_ca, check_fleet,
    check_opencanary, check_ghidra, check_volatility3, check_malcolm,
    check_openplc,
]


@app.route("/health", methods=["GET", "OPTIONS"])
def health():
    return jsonify({"status": "ok", "module": "integrations", "ts": datetime.now(timezone.utc).isoformat()})


@app.route("/tools", methods=["GET", "OPTIONS"])
def list_tools():
    results = [fn() for fn in TOOL_CHECKS]
    installed = [r for r in results if r.get("present") or r.get("service_up") or r.get("api_up")]
    return jsonify({
        "tools": results,
        "installed_count": len(installed),
        "total_count": len(results),
        "ts": datetime.now(timezone.utc).isoformat()
    })


@app.route("/tools/<tool_name>", methods=["GET", "OPTIONS"])
def tool_detail(tool_name: str):
    mapping = {
        "wazuh": check_wazuh, "suricata": check_suricata, "zeek": check_zeek,
        "velociraptor": check_velociraptor, "openvas": check_openvas,
        "misp": check_misp, "opencti": check_opencti, "stackstorm": check_stackstorm,
        "keycloak": check_keycloak, "packetfence": check_packetfence,
        "step-ca": check_step_ca, "fleet": check_fleet, "opencanary": check_opencanary,
        "ghidra": check_ghidra, "volatility3": check_volatility3,
        "malcolm": check_malcolm, "openplc": check_openplc,
    }
    fn = mapping.get(tool_name.lower())
    if not fn:
        return jsonify({"error": "unknown tool"}), 404
    return jsonify(fn())


@app.route("/ingest/suricata_eve", methods=["POST", "OPTIONS"])
def ingest_suricata_eve():
    """Accept Suricata EVE JSON line(s) and normalize to AEGIS event format."""
    data = request.get_json(force=True, silent=True) or {}
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return jsonify({"error": "expected JSON object or array"}), 400
    normalized = []
    for evt in data:
        if not isinstance(evt, dict):
            continue
        if evt.get("event_type") != "alert":
            continue
        normalized.append({
            "timestamp": evt.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "severity": _map_suricata_severity(evt.get("alert", {}).get("severity", 3)),
            "category": "network",
            "source": "suricata",
            "title": evt.get("alert", {}).get("signature", "Suricata alert"),
            "description": f"Suricata {evt.get('alert',{}).get('action','alert')}: {evt.get('alert',{}).get('signature','')}",
            "src_ip": evt.get("src_ip"),
            "dest_ip": evt.get("dest_ip"),
            "src_port": evt.get("src_port"),
            "dest_port": evt.get("dest_port"),
            "proto": evt.get("proto"),
            "sid": evt.get("alert", {}).get("signature_id"),
            "gid": evt.get("alert", {}).get("gid"),
            "raw": evt,
        })
    return jsonify({"normalized": normalized, "count": len(normalized)})


def _map_suricata_severity(sev: int) -> str:
    return {1: "critical", 2: "high", 3: "medium"}.get(sev, "low")


@app.route("/ingest/zeek", methods=["POST", "OPTIONS"])
def ingest_zeek():
    """Accept Zeek JSON logs and normalize."""
    data = request.get_json(force=True, silent=True) or {}
    if isinstance(data, dict):
        data = [data]
    normalized = []
    for evt in data:
        if not isinstance(evt, dict):
            continue
        normalized.append({
            "timestamp": evt.get("ts") or datetime.now(timezone.utc).isoformat(),
            "severity": "info",
            "category": "network",
            "source": "zeek",
            "title": f"Zeek {evt.get('_path','log')}",
            "description": json.dumps(evt)[:500],
            "raw": evt,
        })
    return jsonify({"normalized": normalized, "count": len(normalized)})


# ============== NATIVE API PROXIES (read-only) ==============

@app.route("/wazuh/agents", methods=["GET", "OPTIONS"])
def wazuh_agents():
    """Proxy to Wazuh API /agents if available."""
    if not _tcp_check("127.0.0.1", 55000, 2.0):
        return jsonify({"error": "Wazuh API not reachable on :55000", "note": "Ensure wazuh-manager is running and API is enabled."}), 503
    try:
        import requests
        # Wazuh API requires JWT auth; without credentials we return advisory
        return jsonify({
            "note": "Wazuh API detected. To list agents, configure WAZUH_API_USER/WAZUH_API_PASSWORD and call GET https://localhost:55000/agents",
            "api_url": "https://127.0.0.1:55000",
            "status": "reachable",
            "next_step": "Set credentials in environment and use a dedicated Wazuh connector pack."
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/velociraptor/hunts", methods=["GET", "OPTIONS"])
def velociraptor_hunts():
    if not _tcp_check("127.0.0.1", 8889, 2.0):
        return jsonify({"error": "Velociraptor GUI not reachable on :8889", "note": "Ensure Velociraptor server is running."}), 503
    return jsonify({
        "note": "Velociraptor detected. Use velociraptor-client or gRPC API for hunt management.",
        "gui": "https://127.0.0.1:8889",
        "status": "reachable",
        "next_step": "Use Velociraptor API client with proper ACLs for hunt listing and artifact collection."
    })


@app.route("/stackstorm/packs", methods=["GET", "OPTIONS"])
def stackstorm_packs():
    if not _tcp_check("127.0.0.1", 9101, 2.0):
        return jsonify({"error": "StackStorm API not reachable on :9101", "note": "Ensure st2api is running."}), 503
    return jsonify({
        "note": "StackStorm API detected. Authenticate via ST2 auth token to list packs/rules.",
        "api_url": "https://127.0.0.1:9101",
        "status": "reachable",
        "next_step": "Set ST2_API_KEY or use 'st2' CLI for pack/rule/workflow management."
    })


@app.route("/fleet/hosts", methods=["GET", "OPTIONS"])
def fleet_hosts():
    if not _tcp_check("127.0.0.1", 8080, 2.0):
        return jsonify({"error": "Fleet API not reachable on :8080", "note": "Ensure Fleet server is running."}), 503
    return jsonify({
        "note": "Fleet detected. Use Fleet API token to list enrolled hosts and query results.",
        "api_url": "https://127.0.0.1:8080",
        "status": "reachable",
        "next_step": "Configure FLEET_API_TOKEN and call /api/v1/fleet/hosts for host inventory."
    })


if __name__ == "__main__":
    port = int(os.environ.get("INTEGRATIONS_PORT", "8090"))
    BIND_HOST = os.environ.get("INTEGRATIONS_BIND_HOST", "127.0.0.1")
    app.run(host=BIND_HOST, port=port, threaded=True, use_reloader=False)
