#!/usr/bin/env python3
"""
Cybersecurity-AEGIS endpoint tool integrations.

This module only reports and runs tools that are actually present on the host.
It does not fabricate posture data and it never downloads or installs tools.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "id": "wazuh",
        "name": "Wazuh Agent/Manager",
        "layer": "endpoint",
        "role": "FIM, rootkit detection, endpoint telemetry",
        "binaries": ["wazuh-agent", "wazuh-control", "agent_control"],
        "version_args": ["-V"],
        "service_url_env": "WAZUH_MANAGER_URL",
        "notes": "External Wazuh alerts can be ingested through /api/v1/ingest/wazuh.",
    },
    {
        "id": "osquery",
        "name": "OSQuery",
        "layer": "endpoint",
        "role": "SQL endpoint inventory and threat hunting",
        "binaries": ["osqueryi"],
        "version_args": ["--version"],
        "notes": "The local agent uses osqueryi when it is installed.",
    },
    {
        "id": "clamav",
        "name": "ClamAV",
        "layer": "endpoint",
        "role": "Local antivirus scanning",
        "binaries": ["clamdscan", "clamscan"],
        "version_args": ["--version"],
        "notes": "Use /scan/clamav to scan a real file, directory, or reachable UNC path.",
    },
    {
        "id": "crowdsec",
        "name": "CrowdSec",
        "layer": "perimeter",
        "role": "Collaborative reputation and local decisions",
        "binaries": ["cscli", "crowdsec"],
        "version_args": ["version"],
        "notes": "CrowdSec events can be ingested through /api/v1/ingest/crowdsec.",
    },
    {
        "id": "suricata",
        "name": "Suricata",
        "layer": "network",
        "role": "IDS/IPS and EVE JSON alerts",
        "binaries": ["suricata"],
        "version_args": ["--build-info"],
        "notes": "Suricata events can be ingested through /api/v1/ingest/suricata.",
    },
    {
        "id": "nmap",
        "name": "Nmap",
        "layer": "network",
        "role": "Authorized service discovery",
        "binaries": ["nmap"],
        "version_args": ["--version"],
        "notes": "The network module enriches scans with Nmap when python-nmap and nmap are installed.",
    },
    {
        "id": "rustscan",
        "name": "RustScan",
        "layer": "network",
        "role": "Fast authorized port discovery",
        "binaries": ["rustscan"],
        "version_args": ["--version"],
        "notes": "Optional scanner; AEGIS keeps OT-safe mode read-only by default.",
    },
    {
        "id": "openvas_gvm",
        "name": "OpenVAS / GVM",
        "layer": "intelligence",
        "role": "Authenticated vulnerability scanning",
        "binaries": ["gvm-cli", "gvmd", "openvas"],
        "version_args": ["--version"],
        "service_url_env": "GVM_URL",
        "notes": "Use only against owned or explicitly authorized assets.",
    },
    {
        "id": "nikto",
        "name": "Nikto",
        "layer": "intelligence",
        "role": "Owned web server misconfiguration checks",
        "binaries": ["nikto", "nikto.pl"],
        "version_args": ["-Version"],
        "notes": "Not launched automatically; target authorization remains operator responsibility.",
    },
    {
        "id": "gitleaks",
        "name": "Gitleaks",
        "layer": "identity",
        "role": "Repository and filesystem secret scanning",
        "binaries": ["gitleaks"],
        "version_args": ["version"],
        "notes": "The endpoint secrets sweeper also has a stdlib fallback with masked findings.",
    },
    {
        "id": "trufflehog",
        "name": "TruffleHog",
        "layer": "identity",
        "role": "Secret verification and filesystem secret scanning",
        "binaries": ["trufflehog"],
        "version_args": ["--version"],
        "notes": "Detected as an optional external verifier.",
    },
    {
        "id": "yara",
        "name": "YARA",
        "layer": "intelligence",
        "role": "Malware rule matching",
        "binaries": ["yara"],
        "version_args": ["--version"],
        "notes": "The endpoint module uses yara-python when available.",
    },
    {
        "id": "lynis",
        "name": "Lynis",
        "layer": "hardening",
        "role": "Linux/macOS/Unix hardening audit",
        "binaries": ["lynis"],
        "version_args": ["show", "version"],
        "notes": "Windows uses the native AEGIS hardening audit; Lynis is for Unix-like hosts.",
    },
    {
        "id": "wireguard",
        "name": "WireGuard",
        "layer": "perimeter",
        "role": "Private VPN tunnel for administration",
        "binaries": ["wg", "wg.exe"],
        "version_args": ["--version"],
        "notes": "AEGIS reports availability; it does not create tunnels without explicit operator action.",
    },
    {
        "id": "vaultwarden",
        "name": "Vaultwarden",
        "layer": "identity",
        "role": "Self-hosted Bitwarden-compatible vault",
        "binaries": ["vaultwarden"],
        "version_args": ["--version"],
        "service_url_env": "VAULTWARDEN_URL",
        "health_paths": ["/alive", "/api/alive"],
        "notes": "Set VAULTWARDEN_URL to include service health in this inventory.",
    },
    {
        "id": "openbao",
        "name": "OpenBao / Vault",
        "layer": "identity",
        "role": "Local secrets management API",
        "binaries": ["bao", "vault"],
        "version_args": ["version"],
        "service_url_env": "OPENBAO_ADDR",
        "health_paths": ["/v1/sys/health"],
        "notes": "Set OPENBAO_ADDR or VAULT_ADDR to include API health.",
    },
]


def inventory_security_tools(timeout: float = 2.5) -> Dict[str, Any]:
    """Return the actual local availability of supported defensive tools."""
    tools = [_probe_tool(defn, timeout=timeout) for defn in TOOL_DEFINITIONS]
    installed = [t for t in tools if t["installed"]]
    by_layer: Dict[str, Dict[str, int]] = {}
    for t in tools:
        layer = t["layer"]
        by_layer.setdefault(layer, {"available": 0, "total": 0})
        by_layer[layer]["total"] += 1
        if t["installed"] or t.get("service", {}).get("reachable"):
            by_layer[layer]["available"] += 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "platform": sys.platform,
        "installed_count": len(installed),
        "total_count": len(tools),
        "by_layer": by_layer,
        "tools": tools,
    }


def run_clamav_scan(path: str, recursive: bool = True, timeout: Optional[int] = None) -> Dict[str, Any]:
    """Run a local ClamAV scan if clamdscan or clamscan is installed.

    The scan is read-only: no quarantine/removal flags are passed.
    """
    target = Path(path)
    if not path or not target.exists():
        return {
            "available": False,
            "error": f"path not found: {path}",
            "path": path,
        }

    scanner = shutil.which("clamdscan") or shutil.which("clamscan")
    if not scanner:
        return {
            "available": False,
            "error": "ClamAV binary not found. Install clamscan or clamdscan and ensure it is in PATH.",
            "path": str(target),
        }

    timeout = timeout or int(os.getenv("CLAMAV_SCAN_TIMEOUT", "300"))
    cmd = [scanner]
    name = Path(scanner).name.lower()
    if "clamscan" in name and recursive and target.is_dir():
        cmd.append("-r")
    if "clamdscan" in name:
        cmd.append("--no-summary")
    cmd.append(str(target))

    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        report = ((proc.stdout or "") + (proc.stderr or "")).strip()
        infected = _parse_clamav_infected(report)
        verdict = "infected" if proc.returncode == 1 or infected else "clean"
        if proc.returncode not in (0, 1):
            verdict = "error"
        return {
            "available": True,
            "scanner": scanner,
            "path": str(target),
            "recursive": bool(recursive and target.is_dir()),
            "started_at": datetime.now(timezone.utc).isoformat(),
            "duration_seconds": round(time.time() - started, 3),
            "exit_code": proc.returncode,
            "verdict": verdict,
            "infected_count": infected,
            "report": report[:12000],
            "command": [Path(scanner).name] + cmd[1:],
        }
    except subprocess.TimeoutExpired:
        return {
            "available": True,
            "scanner": scanner,
            "path": str(target),
            "verdict": "timeout",
            "error": f"ClamAV scan exceeded {timeout}s timeout",
        }
    except Exception as exc:
        return {
            "available": True,
            "scanner": scanner,
            "path": str(target),
            "verdict": "error",
            "error": str(exc),
        }


def _probe_tool(defn: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    binary = _find_first(defn.get("binaries", []))
    service = _probe_service(defn, timeout=timeout)
    result = {
        "id": defn["id"],
        "name": defn["name"],
        "layer": defn["layer"],
        "role": defn["role"],
        "installed": binary is not None,
        "binary": binary,
        "version": None,
        "version_error": None,
        "service": service,
        "notes": defn.get("notes", ""),
    }
    if binary:
        version = _run_version(binary, defn.get("version_args", ["--version"]), timeout=timeout)
        result["version"] = version.get("version")
        result["version_error"] = version.get("error")
    return result


def _find_first(names: List[str]) -> Optional[str]:
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def _run_version(binary: str, args: List[str], timeout: float) -> Dict[str, Optional[str]]:
    try:
        proc = subprocess.run(
            [binary] + list(args),
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        text = ((proc.stdout or "") + (proc.stderr or "")).strip()
        line = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")
        return {"version": line[:240] if line else None, "error": None if proc.returncode in (0, 1) else f"exit {proc.returncode}"}
    except Exception as exc:
        return {"version": None, "error": str(exc)}


def _probe_service(defn: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    env_name = defn.get("service_url_env")
    url = os.getenv(env_name or "") if env_name else ""
    if defn["id"] == "openbao" and not url:
        url = os.getenv("VAULT_ADDR", "")
        env_name = "VAULT_ADDR" if url else env_name
    if not url:
        return {"configured": False, "reachable": False}
    base = url.rstrip("/")
    paths = defn.get("health_paths", ["/"])
    last_error = ""
    for path in paths:
        try:
            req = urllib.request.Request(base + path, method="GET")
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return {
                    "configured": True,
                    "reachable": True,
                    "url_env": env_name,
                    "url": base,
                    "path": path,
                    "status_code": resp.status,
                }
        except urllib.error.HTTPError as exc:
            # Vault/OpenBao health uses meaningful non-2xx status codes.
            if defn["id"] == "openbao" and exc.code in {429, 472, 473, 501, 503}:
                return {
                    "configured": True,
                    "reachable": True,
                    "url_env": env_name,
                    "url": base,
                    "path": path,
                    "status_code": exc.code,
                }
            last_error = f"HTTP {exc.code}"
        except Exception as exc:
            last_error = str(exc)
    return {
        "configured": True,
        "reachable": False,
        "url_env": env_name,
        "url": base,
        "error": last_error,
    }


def _parse_clamav_infected(report: str) -> int:
    infected = 0
    for line in report.splitlines():
        stripped = line.strip()
        if stripped.endswith("FOUND"):
            infected += 1
        if stripped.lower().startswith("infected files:"):
            try:
                infected = max(infected, int(stripped.split(":", 1)[1].strip().split()[0]))
            except Exception:
                pass
    return infected
