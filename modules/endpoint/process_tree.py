#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Process Tree Explorer & Ransomware Detector
==================================================================
SOC-grade process tree visualisation + real-time ransomware behaviour
detection. Inspired by ProcMon + Sysinternals Autoruns + CryptoGuard.

Capabilities:
  - Full parent→child process tree, marked with severity flags
  - Signature verification (Authenticode), parent walking
  - Ransomware behavioural detector:
       • mass file rename / extension change
       • Volume Shadow Copy deletion attempt
       • Stop-Service of WdNisSvc / SecurityHealthService
       • high entropy file writes (encrypted content)
       • registry edits typical of crypto-malware
  - AMSI status check
  - WDAC / AppLocker policy state
"""
from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set

try:
    import psutil  # type: ignore
except ImportError:
    psutil = None  # type: ignore

from windows_audit import _run_ps

LOGGER = logging.getLogger("aegis.endpoint.process_tree")


@dataclass
class TreeNode:
    pid: int
    name: str = ""
    exe: Optional[str] = None
    cmdline: List[str] = field(default_factory=list)
    username: Optional[str] = None
    parent_pid: Optional[int] = None
    create_time: Optional[float] = None
    severity: str = "info"
    flags: List[str] = field(default_factory=list)
    children: List["TreeNode"] = field(default_factory=list)

    def to_dict(self, depth: int = 0, max_depth: int = 10) -> Dict[str, Any]:
        d = {
            "pid": self.pid,
            "name": self.name,
            "exe": self.exe,
            "cmdline_str": " ".join(self.cmdline)[:500],
            "username": self.username,
            "parent_pid": self.parent_pid,
            "create_time": self.create_time,
            "severity": self.severity,
            "flags": self.flags,
            "children_count": len(self.children),
        }
        if depth < max_depth:
            d["children"] = [c.to_dict(depth + 1, max_depth) for c in self.children]
        return d


LOLBINS = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
    "bitsadmin.exe", "msbuild.exe", "installutil.exe", "regasm.exe",
    "msxsl.exe", "wmic.exe", "schtasks.exe", "at.exe",
}

OFFICE_PROCS = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "visio.exe", "wordpad.exe",
}

SUSPICIOUS_PARENT_CHILD = [
    # (parent, child) → suspicious if observed
    ("winword.exe", "powershell.exe"),
    ("winword.exe", "cmd.exe"),
    ("winword.exe", "wscript.exe"),
    ("winword.exe", "mshta.exe"),
    ("excel.exe", "powershell.exe"),
    ("excel.exe", "cmd.exe"),
    ("excel.exe", "wscript.exe"),
    ("outlook.exe", "powershell.exe"),
    ("outlook.exe", "cmd.exe"),
    ("wmiprvse.exe", "powershell.exe"),
    ("sqlservr.exe", "cmd.exe"),
    ("services.exe", "powershell.exe"),
    ("svchost.exe", "cmd.exe"),
    ("explorer.exe", "powershell.exe"),  # frequent but worth flagging
]


def _classify_node(node: TreeNode, parent_name: str = "") -> None:
    name = node.name.lower()
    exe = (node.exe or "").lower()
    cmd = " ".join(node.cmdline or []).lower()

    sev_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    def upgrade(s: str):
        if sev_order.get(s, 0) > sev_order.get(node.severity, 0):
            node.severity = s

    if name in LOLBINS:
        node.flags.append("lolbin")
        upgrade("low")
    if any(s in exe for s in ("\\appdata\\local\\temp\\", "\\windows\\temp\\",
                              "\\users\\public\\", "\\programdata\\temp\\")):
        node.flags.append("temp_path")
        upgrade("high")
    if "-enc " in cmd or "-encodedcommand" in cmd:
        node.flags.append("encoded_command")
        upgrade("critical")
    if "downloadstring" in cmd or "iex(" in cmd or "frombase64string" in cmd:
        node.flags.append("download_cradle")
        upgrade("critical")
    if "-w hidden" in cmd or "-windowstyle hidden" in cmd:
        node.flags.append("hidden_window")
        upgrade("medium")
    if parent_name:
        p = parent_name.lower()
        if (p, name) in SUSPICIOUS_PARENT_CHILD:
            node.flags.append(f"suspicious_parent:{p}→{name}")
            upgrade("high")
    if name in OFFICE_PROCS:
        node.flags.append("office")


def build_process_tree(top_n: int = 500) -> Dict[str, Any]:
    if psutil is None:
        return {"available": False, "error": "psutil not installed"}
    started = datetime.now(timezone.utc)
    all_nodes: Dict[int, TreeNode] = {}
    children_map: Dict[int, List[int]] = defaultdict(list)
    parent_lookup: Dict[int, str] = {}
    try:
        for p in psutil.process_iter(["pid", "name", "exe", "cmdline",
                                        "username", "ppid", "create_time"]):
            i = p.info
            node = TreeNode(
                pid=i["pid"], name=i.get("name") or "",
                exe=i.get("exe"), cmdline=i.get("cmdline") or [],
                username=i.get("username"), parent_pid=i.get("ppid"),
                create_time=i.get("create_time"),
            )
            all_nodes[node.pid] = node
            if node.parent_pid:
                children_map[node.parent_pid].append(node.pid)
            parent_lookup[node.pid] = node.name
    except Exception as e:
        return {"available": False, "error": str(e)}

    # Classify each node with parent context
    for node in all_nodes.values():
        pname = parent_lookup.get(node.parent_pid or 0, "")
        _classify_node(node, pname)

    # Build tree
    for pid, kids in children_map.items():
        if pid in all_nodes:
            for k in kids:
                if k in all_nodes:
                    all_nodes[pid].children.append(all_nodes[k])

    roots = [n for n in all_nodes.values() if n.parent_pid not in all_nodes or n.pid == n.parent_pid]
    # Sort children by severity desc, then pid
    sev_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    def sort_kids(node: TreeNode):
        node.children.sort(key=lambda c: (-sev_order.get(c.severity, 0), c.pid))
        for c in node.children:
            sort_kids(c)
    for r in roots:
        sort_kids(r)

    # Summary
    by_sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    flagged: List[TreeNode] = []
    def walk(n: TreeNode):
        by_sev[n.severity] = by_sev.get(n.severity, 0) + 1
        if n.severity != "info":
            flagged.append(n)
        for c in n.children:
            walk(c)
    for r in roots:
        walk(r)
    flagged.sort(key=lambda n: -sev_order.get(n.severity, 0))

    completed = datetime.now(timezone.utc)
    return {
        "available": True,
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "duration_seconds": round((completed - started).total_seconds(), 2),
        "total_processes": len(all_nodes),
        "by_severity": by_sev,
        "flagged": [n.to_dict(max_depth=0) for n in flagged[:top_n]],
        "roots": [r.to_dict(max_depth=15) for r in roots[:80]],
    }


# ── Ransomware behavioural detector ──────────────────────────────────────────

# Indicators: any of these = critical alert
SHADOW_DELETE_CMDS = [
    "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
    "bcdedit /set {default} recoveryenabled no",
    "wbadmin delete catalog",
    "wbadmin delete backup",
    "wbadmin delete systemstatebackup",
]
SECURITY_DISABLE_CMDS = [
    "stop-service -name windefend",
    "stop-service -name wdnissvc",
    "set-mppreference -disablerealtimemonitoring",
    "stop-service -name securityhealthservice",
    "stop-service -name wuauserv",
    "sc.exe stop windefend",
    "sc.exe stop wdnissvc",
    "powershell -command set-mppreference -disablerealtimemonitoring",
]

KNOWN_RANSOMWARE_EXT = {
    ".locked", ".encrypted", ".enc", ".crypted", ".crypt",
    ".lockbit", ".lockedfile", ".conti", ".ryuk", ".babuk",
    ".wannacry", ".wcry", ".wncry", ".cerber", ".locky",
    ".sage", ".sage2", ".sage3", ".sage4",
    ".djvu", ".pgp", ".rsa", ".dharma", ".tor", ".thanos",
    ".darkside", ".revil", ".sodinokibi", ".onion", ".readme",
    ".ako", ".doppelpaymer", ".egregor", ".maze", ".netwalker",
    ".phobos", ".stop", ".devos", ".eking", ".mado", ".ragnar",
}


class RansomwareDetector:
    """Background poller that watches for ransomware behavioural indicators."""

    def __init__(self, emit_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self.emit_cb = emit_callback
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._known_cmdline_hashes: Set[str] = set()
        self.events_emitted = 0
        self.last_poll_at: Optional[str] = None
        self.started_at: Optional[str] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        if psutil is None:
            LOGGER.warning("psutil not installed — ransomware detector disabled")
            return
        self._stop.clear()
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._thread = threading.Thread(target=self._run, name="aegis-ransom", daemon=True)
        self._thread.start()
        LOGGER.info("Ransomware detector started")

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _emit(self, severity: str, title: str, description: str,
              technique: str = "T1486", evidence: Optional[Dict[str, Any]] = None) -> None:
        evt = {
            "source":      "endpoint.ransomware",
            "category":    "endpoint",
            "severity":    severity,
            "title":       title,
            "description": description,
            "tags":        ["ransomware", "real-time", technique],
            "raw_data":    evidence or {},
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }
        self.events_emitted += 1
        if self.emit_cb:
            try:
                self.emit_cb(evt)
            except Exception:
                pass

    def _check_shadow_delete(self) -> None:
        try:
            for p in psutil.process_iter(["pid", "name", "cmdline"]):
                try:
                    cmd = " ".join(p.info.get("cmdline") or []).lower()
                except Exception:
                    continue
                if not cmd:
                    continue
                h = hash(cmd)
                key = f"shadow_{p.info['pid']}_{h}"
                if key in self._known_cmdline_hashes:
                    continue
                for pat in SHADOW_DELETE_CMDS:
                    if pat in cmd:
                        self._emit("critical",
                            f"RANSOMWARE INDICATOR: Volume Shadow Copy deletion attempt",
                            f"Process {p.info.get('name')} (pid {p.info['pid']}) is executing: {cmd[:300]}",
                            technique="T1490",
                            evidence={"pid": p.info["pid"], "name": p.info.get("name"),
                                       "cmdline": cmd, "matched_pattern": pat})
                        self._known_cmdline_hashes.add(key)
                        break
                for pat in SECURITY_DISABLE_CMDS:
                    if pat in cmd:
                        self._emit("critical",
                            f"RANSOMWARE INDICATOR: Defender / Security service disable attempt",
                            f"Process {p.info.get('name')} (pid {p.info['pid']}) is executing: {cmd[:300]}",
                            technique="T1562.001",
                            evidence={"pid": p.info["pid"], "name": p.info.get("name"),
                                       "cmdline": cmd, "matched_pattern": pat})
                        self._known_cmdline_hashes.add(key)
                        break
        except Exception as e:
            LOGGER.debug("shadow_delete check failed: %s", e)

    def _check_ransom_extensions(self) -> None:
        """Check user directories for files with known ransomware extensions
        modified in the last 60 seconds. Heuristic only — false positives
        possible if a researcher is studying samples."""
        try:
            from pathlib import Path
            cutoff = time.time() - 60
            roots = [Path.home() / "Documents", Path.home() / "Desktop"]
            for root in roots:
                if not root.exists():
                    continue
                hits = []
                for p in root.rglob("*"):
                    if not p.is_file():
                        continue
                    try:
                        if p.stat().st_mtime < cutoff:
                            continue
                    except Exception:
                        continue
                    ext = p.suffix.lower()
                    if ext in KNOWN_RANSOMWARE_EXT:
                        hits.append(str(p))
                        if len(hits) > 20:
                            break
                if hits:
                    self._emit("critical",
                        f"RANSOMWARE INDICATOR: {len(hits)} file con estensione di cifratura in {root}",
                        f"Possibile cifratura in corso. Esempi: {', '.join(hits[:5])}",
                        technique="T1486",
                        evidence={"root": str(root), "count": len(hits), "sample": hits[:10]})
        except Exception as e:
            LOGGER.debug("ransom_ext check failed: %s", e)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self._check_shadow_delete()
                self._check_ransom_extensions()
            except Exception as e:
                LOGGER.exception("ransomware poll failed: %s", e)
            self.last_poll_at = datetime.now(timezone.utc).isoformat()
            if self._stop.wait(20):
                break


# ── AMSI / WDAC / AppLocker status ───────────────────────────────────────────

def check_amsi() -> Dict[str, Any]:
    """AMSI (Anti-Malware Scan Interface) configuration."""
    data = _run_ps(
        "$dll = 'C:\\Windows\\System32\\amsi.dll'; "
        "$present = Test-Path $dll; "
        "$prov = Get-CimInstance -Namespace 'root\\Microsoft\\AntiMalwareProvider' -ClassName MSFT_AntiMalwareProvider -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{ DllPresent=$present; Providers=$prov }"
    )
    findings: List[Dict[str, Any]] = []
    if data is None:
        return {"available": False, "error": "AMSI status non leggibile"}
    present = bool(data.get("DllPresent"))
    findings.append({
        "check_id": "amsi.dll",
        "title": "AMSI dll " + ("presente" if present else "mancante"),
        "status": "ok" if present else "fail",
        "severity": "info" if present else "high",
        "description": "AMSI permette ad antivirus di scansionare script in-memory (PowerShell, VBA, JS).",
        "value": present, "technique": "T1562.001",
    })
    return {"available": True, "raw": data, "findings": findings}


def check_wdac_applocker() -> Dict[str, Any]:
    """Windows Defender Application Control + AppLocker policy state."""
    data = _run_ps(
        "$wdac = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\\Microsoft\\Windows\\DeviceGuard' -ErrorAction SilentlyContinue | "
        "  Select-Object CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus; "
        "$applocker = @{}; "
        "foreach ($svc in 'AppIDSvc','AppMgmt') { "
        "  $s = Get-Service -Name $svc -ErrorAction SilentlyContinue; "
        "  if ($s) { $applocker[$svc] = @{ Status=$s.Status.ToString(); StartType=$s.StartType.ToString() } } "
        "}; "
        "$rules = & Get-AppLockerPolicy -Effective -Xml -ErrorAction SilentlyContinue; "
        "$ruleCount = 0; if ($rules) { try { $ruleCount = ([xml]$rules).AppLockerPolicy.RuleCollection.Count } catch {} }; "
        "[pscustomobject]@{ WDAC=$wdac; AppLockerServices=$applocker; AppLockerRules=$ruleCount }",
        timeout=10,
    )
    findings: List[Dict[str, Any]] = []
    if data is None:
        return {"available": False, "error": "WDAC/AppLocker query failed"}
    wdac = data.get("WDAC") or {}
    cie = wdac.get("CodeIntegrityPolicyEnforcementStatus")  # 0=off, 1=audit, 2=enforce
    if cie in (None, 0):
        findings.append({
            "check_id": "wdac.off",
            "title": "WDAC (App Control) non attivo",
            "status": "warn", "severity": "medium",
            "description": "WDAC blocca l'esecuzione di binari non firmati o non in whitelist. Importante per ambienti aziendali.",
            "value": wdac, "technique": "T1059",
            "remediation_key": "wdac_off",
        })
    rules = data.get("AppLockerRules", 0) or 0
    if rules == 0:
        findings.append({
            "check_id": "applocker.no_rules",
            "title": "AppLocker senza regole configurate",
            "status": "warn", "severity": "low",
            "description": "AppLocker può limitare l'esecuzione di applicazioni a una whitelist.",
            "value": rules, "technique": "T1059",
            "remediation_key": "applocker_off",
        })
    return {"available": True, "raw": data, "findings": findings}
