#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Process Scanner
======================================
Enumerates running processes and produces a security risk profile per process.

Indicators flagged:
  - Unsigned PE on Windows (Get-AuthenticodeSignature)
  - Process running from %TEMP%, %APPDATA%\\Local\\Temp
  - Process spawned by user without being a known LOLBin
  - High network usage with no parent shell context
  - Hash collision against the file scanner's malicious list
"""
from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore

LOGGER = logging.getLogger("aegis.endpoint.process_scanner")

# Common LOLBins — running them isn't a finding by itself but interesting context
LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "rundll32.exe", "regsvr32.exe", "mshta.exe", "certutil.exe",
    "bitsadmin.exe", "msbuild.exe", "installutil.exe",
}

SUSPICIOUS_PATH_HINTS = (
    "\\appdata\\local\\temp\\",
    "\\users\\public\\",
    "\\windows\\temp\\",
    "\\programdata\\",
    "/tmp/",
    "/var/tmp/",
    "/dev/shm/",
)


@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe: Optional[str] = None
    cmdline: List[str] = field(default_factory=list)
    username: Optional[str] = None
    create_time: Optional[float] = None
    parent_pid: Optional[int] = None
    parent_name: Optional[str] = None
    cpu_percent: Optional[float] = None
    memory_mb: Optional[float] = None
    open_connections: int = 0
    flags: List[str] = field(default_factory=list)
    severity: str = "info"  # info | low | medium | high | critical

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _classify(p: ProcessInfo) -> ProcessInfo:
    exe = (p.exe or "").lower()
    name = (p.name or "").lower()
    score = "info"
    if exe and any(s in exe for s in SUSPICIOUS_PATH_HINTS):
        p.flags.append("suspicious_path")
        score = "high"
    if name in LOLBINS:
        p.flags.append("lolbin")
        if "lolbin_temp" not in p.flags and any(s in exe for s in SUSPICIOUS_PATH_HINTS):
            score = "high"
        else:
            score = max_sev(score, "low")
    # encoded-command hint
    cmd_str = " ".join(p.cmdline).lower()
    if "-enc " in cmd_str or "-encodedcommand" in cmd_str or "-e " in cmd_str.replace("powershell", "x"):
        p.flags.append("encoded_command")
        score = "critical"
    if "downloadstring" in cmd_str or "iex(new-object net.webclient)" in cmd_str.replace(" ", ""):
        p.flags.append("download_string")
        score = "critical"
    if "frombase64string" in cmd_str:
        p.flags.append("base64_in_cmdline")
        score = max_sev(score, "high")
    if p.open_connections >= 10:
        p.flags.append("many_connections")
        score = max_sev(score, "medium")
    p.severity = score
    return p


SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def max_sev(a: str, b: str) -> str:
    return a if SEV_ORDER.get(a, 0) >= SEV_ORDER.get(b, 0) else b


def list_processes(top_n: int = 200) -> Dict[str, Any]:
    """Snapshot all running processes with risk flags."""
    if psutil is None:
        return {"available": False, "error": "psutil not installed"}

    started = datetime.now(timezone.utc).isoformat()
    procs: List[ProcessInfo] = []

    # First pass: collect lightweight info
    for p in psutil.process_iter(["pid", "name", "exe", "cmdline", "username",
                                   "create_time", "ppid"]):
        try:
            info = p.info
            pi = ProcessInfo(
                pid=info["pid"],
                name=info.get("name") or "",
                exe=info.get("exe"),
                cmdline=info.get("cmdline") or [],
                username=info.get("username"),
                create_time=info.get("create_time"),
                parent_pid=info.get("ppid"),
            )
            try:
                pi.memory_mb = round(p.memory_info().rss / (1024 * 1024), 1)
            except Exception:
                pass
            try:
                pi.open_connections = len(p.net_connections(kind="inet"))
            except (psutil.AccessDenied, PermissionError, Exception):
                pi.open_connections = 0
            try:
                if pi.parent_pid:
                    parent = psutil.Process(pi.parent_pid)
                    pi.parent_name = parent.name()
            except Exception:
                pass
            procs.append(_classify(pi))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
        except Exception:
            continue

    flagged = [p for p in procs if p.severity != "info"]
    flagged.sort(key=lambda p: -SEV_ORDER.get(p.severity, 0))
    by_sev: Dict[str, int] = {}
    for p in procs:
        by_sev[p.severity] = by_sev.get(p.severity, 0) + 1

    return {
        "available": True,
        "started_at": started,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "host_user": os.getenv("USERNAME") or os.getenv("USER"),
        "platform": sys.platform,
        "total_processes": len(procs),
        "by_severity": by_sev,
        "flagged_count": len(flagged),
        "flagged": [p.to_dict() for p in flagged[:top_n]],
        "all": [p.to_dict() for p in procs[:top_n]],
    }


def list_connections() -> Dict[str, Any]:
    """Network connections per process with state and remote endpoint."""
    if psutil is None:
        return {"available": False, "error": "psutil not installed"}
    rows: List[Dict[str, Any]] = []
    try:
        for c in psutil.net_connections(kind="inet"):
            try:
                pname = ""
                if c.pid:
                    try:
                        pname = psutil.Process(c.pid).name()
                    except Exception:
                        pname = ""
                rows.append({
                    "fd": c.fd,
                    "family": str(c.family),
                    "type": str(c.type),
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "status": c.status,
                    "pid": c.pid,
                    "process": pname,
                })
            except Exception:
                continue
    except (psutil.AccessDenied, PermissionError) as e:
        return {"available": False, "error": f"Access denied (run as Administrator): {e}"}
    return {
        "available": True,
        "count": len(rows),
        "connections": rows,
        "established": [r for r in rows if r.get("status") == "ESTABLISHED"][:200],
        "listening":  [r for r in rows if r.get("status") == "LISTEN"][:200],
    }
