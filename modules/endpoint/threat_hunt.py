#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Threat Hunting Library
=============================================
A catalog of read-only Windows hunting queries inspired by:
  - Sigma rules (https://github.com/SigmaHQ/sigma)
  - Velociraptor artifacts
  - osquery scheduled queries
  - MITRE ATT&CK (T1053 scheduled tasks, T1547 boot/logon persistence,
    T1546 event-triggered execution, T1059 command interpreters, ...)

Every query returns:
  - rows:        the raw evidence
  - findings:    enriched events with severity + remediation hint
  - meta:        query id, title, MITRE technique, description, runtime

The hunt is exposed via /hunt and /hunt/<id> in the endpoint module.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

from windows_audit import _run_ps  # reuse the PowerShell helper

LOGGER = logging.getLogger("aegis.endpoint.hunt")


@dataclass
class HuntFinding:
    title: str
    severity: str           # info|low|medium|high|critical
    technique: str          # MITRE ATT&CK technique id
    evidence: Dict[str, Any]
    remediation_key: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Query helpers ────────────────────────────────────────────────────────────

def _ps(script: str, timeout: int = 15) -> Any:
    """Wrapper that returns [] instead of None to simplify list handling."""
    out = _run_ps(script, timeout=timeout)
    if out is None:
        return []
    return out if isinstance(out, list) else [out]


def _is_signed(path: str) -> Optional[bool]:
    """Authenticode signature check. None if unable to verify."""
    out = _run_ps(
        f"(Get-AuthenticodeSignature -LiteralPath '{path.replace(chr(39), chr(39)*2)}' "
        "-ErrorAction SilentlyContinue).Status | "
        "ForEach-Object { $_.ToString() }",
        timeout=5,
    )
    if out is None:
        return None
    return str(out).lower() == "valid"


# ── Individual hunting queries ───────────────────────────────────────────────

def hunt_unsigned_processes_in_temp() -> Dict[str, Any]:
    """T1036.005 — Match Legitimate Name / Location: binaries from %TEMP%, %APPDATA%."""
    rows = _ps(
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.ExecutablePath -match '\\\\(Temp|AppData\\\\Local\\\\Temp|ProgramData)\\\\' -or "
        "               $_.ExecutablePath -match '\\\\Users\\\\Public\\\\' } | "
        "Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CommandLine,CreationDate"
    )
    findings: List[HuntFinding] = []
    for r in rows:
        if not isinstance(r, dict) or not r.get("ExecutablePath"):
            continue
        signed = _is_signed(r["ExecutablePath"])
        sev = "high" if signed is False else "medium"
        findings.append(HuntFinding(
            title=f"Process {r.get('Name','?')} running from temp path",
            severity=sev,
            technique="T1036.005",
            evidence={
                "pid": r.get("ProcessId"),
                "ppid": r.get("ParentProcessId"),
                "path": r.get("ExecutablePath"),
                "cmdline": r.get("CommandLine"),
                "signed": signed,
            },
            remediation_key="autorun_suspicious",
        ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


def hunt_orphan_processes() -> Dict[str, Any]:
    """Processes whose parent has exited — common after process hollowing."""
    rows = _ps(
        "$all = Get-CimInstance Win32_Process; "
        "$pids = $all.ProcessId; "
        "$all | Where-Object { $_.ParentProcessId -ne 0 -and ($_.ParentProcessId -notin $pids) } | "
        "Select-Object Name,ProcessId,ParentProcessId,ExecutablePath,CreationDate"
    )
    findings: List[HuntFinding] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        # System idle / 4 / etc are normal — filter out kernel orphans
        if r.get("ProcessId") in (0, 4):
            continue
        findings.append(HuntFinding(
            title=f"Orphan process {r.get('Name')} (ppid {r.get('ParentProcessId')})",
            severity="medium",
            technique="T1055",  # Process Injection / Hollowing
            evidence=r,
        ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


def hunt_scheduled_tasks_recent() -> Dict[str, Any]:
    """T1053.005 — Scheduled tasks created or modified in the last 30 days."""
    rows = _ps(
        "Get-ScheduledTask -ErrorAction SilentlyContinue | ForEach-Object { "
        "  try { $i = $_ | Get-ScheduledTaskInfo -ErrorAction SilentlyContinue; "
        "        if ($i -and $_.Date) { "
        "          $age = ((Get-Date) - [datetime]$_.Date).Days; "
        "          if ($age -le 30) { "
        "            [pscustomobject]@{ "
        "              TaskName=$_.TaskName; TaskPath=$_.TaskPath; "
        "              Author=$_.Author; State=$_.State; "
        "              Date=$_.Date; AgeDays=$age; "
        "              Actions=($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) "
        "            } "
        "          } "
        "        } "
        "  } catch { } "
        "}",
        timeout=20,
    )
    findings: List[HuntFinding] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        author = str(r.get("Author") or "").lower()
        actions_str = " ".join(r.get("Actions") or []).lower() if isinstance(r.get("Actions"), list) else str(r.get("Actions") or "").lower()
        suspicious = (
            "\\temp\\" in actions_str or "\\appdata\\" in actions_str
            or "powershell" in actions_str and ("-enc" in actions_str or "-w hidden" in actions_str or "bypass" in actions_str)
            or "mshta" in actions_str
            or "rundll32" in actions_str and ".dll," in actions_str
        )
        sev = "high" if suspicious else "low"
        findings.append(HuntFinding(
            title=f"Recent scheduled task: {r.get('TaskName')} (created {r.get('AgeDays')}d ago)",
            severity=sev,
            technique="T1053.005",
            evidence=r,
            remediation_key="autorun_suspicious" if suspicious else None,
        ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


def hunt_wmi_persistence() -> Dict[str, Any]:
    """T1546.003 — Windows Management Instrumentation Event Subscription."""
    rows = _ps(
        "Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | "
        "Select-Object Name,Query,QueryLanguage,EventNamespace"
    )
    consumers = _ps(
        "Get-CimInstance -Namespace root\\subscription -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue | "
        "Select-Object Name,CommandLineTemplate,WorkingDirectory"
    )
    bindings = _ps(
        "Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue | "
        "Select-Object @{N='FilterName';E={($_.Filter -split '\"')[1]}}, @{N='ConsumerName';E={($_.Consumer -split '\"')[1]}}"
    )
    findings: List[HuntFinding] = []
    for c in consumers:
        if isinstance(c, dict) and c.get("CommandLineTemplate"):
            findings.append(HuntFinding(
                title=f"WMI persistence: CommandLineEventConsumer '{c.get('Name')}'",
                severity="critical",
                technique="T1546.003",
                evidence=c,
                remediation_key="wmi_persistence",
            ))
    return {"rows": {"filters": rows, "consumers": consumers, "bindings": bindings},
            "findings": [f.to_dict() for f in findings]}


def hunt_unusual_services() -> Dict[str, Any]:
    """Services whose binary path is not in System32/Program Files or unsigned."""
    rows = _ps(
        "Get-CimInstance Win32_Service | "
        "Where-Object { $_.PathName -and $_.State -eq 'Running' -and "
        "               $_.PathName -notmatch '^\"?C:\\\\Windows\\\\' -and "
        "               $_.PathName -notmatch '^\"?C:\\\\Program Files' } | "
        "Select-Object Name,DisplayName,PathName,StartMode,StartName,State"
    )
    findings: List[HuntFinding] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        path = re.sub(r'^"?([^"]+\.exe).*$', r'\1', str(r.get("PathName") or ""))
        signed = _is_signed(path) if path else None
        sev = "high" if signed is False else "medium"
        findings.append(HuntFinding(
            title=f"Service '{r.get('Name')}' running from unusual path",
            severity=sev,
            technique="T1543.003",  # Windows Service
            evidence={**r, "extracted_path": path, "signed": signed},
            remediation_key="unusual_service",
        ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


def hunt_event_log_failed_logons() -> Dict[str, Any]:
    """T1110 — Brute force / Password spray (Event 4625 last 24h)."""
    rows = _ps(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; StartTime=(Get-Date).AddHours(-24)} "
        "-MaxEvents 200 -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        "  $xml = [xml]$_.ToXml(); "
        "  $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }; "
        "  [pscustomobject]@{ "
        "    TimeCreated=$_.TimeCreated; "
        "    TargetUser=$data['TargetUserName']; "
        "    TargetDomain=$data['TargetDomainName']; "
        "    IpAddress=$data['IpAddress']; "
        "    LogonType=$data['LogonType']; "
        "    Status=$data['Status'] "
        "  } "
        "}",
        timeout=20,
    )
    findings: List[HuntFinding] = []
    # Group by source IP and count
    by_ip: Dict[str, int] = {}
    by_user: Dict[str, int] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        ip = r.get("IpAddress") or "?"
        user = r.get("TargetUser") or "?"
        by_ip[ip] = by_ip.get(ip, 0) + 1
        by_user[user] = by_user.get(user, 0) + 1
    for ip, count in by_ip.items():
        if count >= 5 and ip not in ("-", "?", "::1", "127.0.0.1"):
            findings.append(HuntFinding(
                title=f"Brute force: {count} failed logons from {ip}",
                severity="critical" if count >= 20 else "high",
                technique="T1110",
                evidence={"src_ip": ip, "count": count, "window_h": 24},
                remediation_key="bruteforce_source",
            ))
    for user, count in by_user.items():
        if count >= 10:
            findings.append(HuntFinding(
                title=f"Password spray candidate: {count} failed logons for '{user}'",
                severity="high",
                technique="T1110.003",
                evidence={"target_user": user, "count": count, "window_h": 24},
                remediation_key="password_spray",
            ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings],
            "stats": {"by_ip": by_ip, "by_user": by_user, "total": len(rows)}}


def hunt_event_log_user_changes() -> Dict[str, Any]:
    """T1136 — User accounts created (4720) or added to admin group (4732) in last 7 days."""
    rows = _ps(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720,4732,4724,4738; StartTime=(Get-Date).AddDays(-7)} "
        "-MaxEvents 200 -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        "  [pscustomobject]@{ "
        "    Id=$_.Id; TimeCreated=$_.TimeCreated; "
        "    Message=($_.Message -split '\\r?\\n' | Select-Object -First 3) -join ' | ' "
        "  } "
        "}",
        timeout=20,
    )
    findings: List[HuntFinding] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        eid = r.get("Id")
        title_map = {
            4720: "User account created",
            4724: "User password reset (administrator action)",
            4732: "User added to security-enabled local group",
            4738: "User account changed",
        }
        sev_map = {4720: "high", 4732: "critical", 4724: "medium", 4738: "low"}
        findings.append(HuntFinding(
            title=f"{title_map.get(eid, 'User change')} (event {eid})",
            severity=sev_map.get(eid, "medium"),
            technique="T1136" if eid == 4720 else "T1098",
            evidence=r,
            remediation_key="account_change",
        ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


def hunt_lolbins_running() -> Dict[str, Any]:
    """T1218 — LOLBins currently executing with suspicious arguments."""
    rows = _ps(
        "Get-CimInstance Win32_Process | "
        "Where-Object { $_.Name -in @('powershell.exe','pwsh.exe','cmd.exe','wscript.exe','cscript.exe',"
        "'mshta.exe','regsvr32.exe','rundll32.exe','certutil.exe','bitsadmin.exe','msbuild.exe',"
        "'installutil.exe','regasm.exe','regsvcs.exe','msxsl.exe','wmic.exe') } | "
        "Select-Object Name,ProcessId,CommandLine,ExecutablePath"
    )
    findings: List[HuntFinding] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        cmd = (r.get("CommandLine") or "").lower()
        bad_patterns = [
            ("-enc ", "encoded_command", "critical"),
            ("-encodedcommand", "encoded_command", "critical"),
            ("downloadstring", "powershell_download_cradle", "critical"),
            ("invoke-expression", "iex_invoke", "high"),
            ("iex(", "iex_invoke", "high"),
            (".downloadfile(", "download_cradle", "critical"),
            ("frombase64string", "base64_inline", "high"),
            ("-w hidden", "hidden_window", "medium"),
            ("-windowstyle hidden", "hidden_window", "medium"),
            ("-nop", "nop_profile", "medium"),
            ("certutil -urlcache", "certutil_download", "critical"),
            ("certutil -decode", "certutil_decode", "high"),
            ("bitsadmin /transfer", "bitsadmin_transfer", "high"),
            ("regsvr32 /s /n /u /i:http", "squiblydoo", "critical"),
            ("rundll32 javascript:", "rundll32_js", "critical"),
            ("mshta http", "mshta_http", "critical"),
            ("msxsl ", "msxsl_proxy", "high"),
        ]
        for pat, key, sev in bad_patterns:
            if pat in cmd:
                findings.append(HuntFinding(
                    title=f"LOLBin abuse: {r.get('Name')} → {key}",
                    severity=sev,
                    technique="T1218",
                    evidence={"pid": r.get("ProcessId"), "cmdline": r.get("CommandLine")[:300]},
                    remediation_key="lolbin_abuse",
                ))
                break
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


def hunt_unusual_dns_queries() -> Dict[str, Any]:
    """T1071.004 — DNS tunneling / DGA candidates via DNS Client log."""
    rows = _ps(
        "Get-WinEvent -LogName 'Microsoft-Windows-DNS-Client/Operational' "
        "-MaxEvents 500 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Id -eq 3018 } | "
        "ForEach-Object { "
        "  $xml = [xml]$_.ToXml(); "
        "  $name = ($xml.Event.EventData.Data | Where-Object { $_.Name -eq 'QueryName' }).'#text'; "
        "  [pscustomobject]@{ Time=$_.TimeCreated; Query=$name } "
        "}",
        timeout=15,
    )
    findings: List[HuntFinding] = []
    seen: Dict[str, int] = {}
    for r in rows:
        if not isinstance(r, dict):
            continue
        q = (r.get("Query") or "").lower()
        if not q:
            continue
        seen[q] = seen.get(q, 0) + 1
        # Heuristic: long random subdomain + high entropy
        parts = q.split(".")
        if parts and len(parts[0]) >= 25:
            entropy_chars = sum(1 for c in parts[0] if c.isalnum())
            if entropy_chars >= 25:
                findings.append(HuntFinding(
                    title=f"DNS tunnelling candidate: {q[:60]}",
                    severity="high",
                    technique="T1071.004",
                    evidence={"query": q, "length": len(parts[0])},
                    remediation_key="dns_tunnel",
                ))
    return {"rows": rows[:200], "findings": [f.to_dict() for f in findings],
            "top_queries": sorted(seen.items(), key=lambda kv: -kv[1])[:20]}


def hunt_rdp_logons_external() -> Dict[str, Any]:
    """T1021.001 — RDP logons (event 4624 logon type 10) from external IPs."""
    rows = _ps(
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; StartTime=(Get-Date).AddDays(-7)} "
        "-MaxEvents 500 -ErrorAction SilentlyContinue | "
        "ForEach-Object { "
        "  $xml = [xml]$_.ToXml(); "
        "  $data = @{}; foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }; "
        "  if ($data['LogonType'] -eq '10') { "
        "    [pscustomobject]@{ "
        "      TimeCreated=$_.TimeCreated; "
        "      TargetUser=$data['TargetUserName']; "
        "      IpAddress=$data['IpAddress']; "
        "      LogonType=$data['LogonType']; "
        "    } "
        "  } "
        "}",
        timeout=20,
    )
    findings: List[HuntFinding] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        ip = r.get("IpAddress") or ""
        is_internal = (ip.startswith("10.") or ip.startswith("192.168.")
                       or ip.startswith("172.") or ip in ("127.0.0.1", "::1", "-"))
        if not is_internal:
            findings.append(HuntFinding(
                title=f"External RDP logon: {r.get('TargetUser')} from {ip}",
                severity="critical",
                technique="T1021.001",
                evidence=r,
                remediation_key="rdp_external_logon",
            ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


def hunt_recent_dll_modifications() -> Dict[str, Any]:
    """T1574 — DLL hijacking candidates: recent DLL writes in critical dirs."""
    rows = _ps(
        "Get-ChildItem -Path 'C:\\Windows\\System32','C:\\Windows\\SysWOW64' "
        "-Filter '*.dll' -ErrorAction SilentlyContinue | "
        "Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) } | "
        "Select-Object FullName,LastWriteTime,Length",
        timeout=20,
    )
    findings: List[HuntFinding] = []
    for r in rows:
        if not isinstance(r, dict):
            continue
        signed = _is_signed(r.get("FullName") or "")
        if signed is False:
            findings.append(HuntFinding(
                title=f"Unsigned DLL recently modified: {r.get('FullName')}",
                severity="critical",
                technique="T1574.002",
                evidence={**r, "signed": False},
                remediation_key="unsigned_dll",
            ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


def hunt_named_pipes() -> Dict[str, Any]:
    """T1559.001 — Unusual named pipes (Cobalt Strike default patterns)."""
    rows = _ps(
        "Get-ChildItem \\\\.\\pipe\\ -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Name",
        timeout=8,
    )
    suspicious_patterns = [
        r"msagent_[a-f0-9]{2}",       # Cobalt Strike default
        r"^postex_[a-f0-9]{4}",       # Cobalt Strike postex
        r"status_[0-9]{2}",           # Cobalt Strike status
        r"MSSE-[0-9a-f-]+",           # Meterpreter-style
        r"^\\?\\GLOBAL_[0-9]+_PIPE", # Generic suspicious
    ]
    findings: List[HuntFinding] = []
    for name in rows:
        if not isinstance(name, str):
            continue
        for pat in suspicious_patterns:
            if re.search(pat, name, re.IGNORECASE):
                findings.append(HuntFinding(
                    title=f"Suspicious named pipe: {name}",
                    severity="critical",
                    technique="T1559.001",
                    evidence={"pipe": name, "matched_pattern": pat},
                    remediation_key="cobalt_strike_pipe",
                ))
                break
    return {"rows": rows[:200], "findings": [f.to_dict() for f in findings]}


def hunt_registry_persistence() -> Dict[str, Any]:
    """T1547.001 — Registry Run keys (HKLM + HKCU) including obscure locations."""
    locations = [
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunServices",
        "HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders",
        "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
        "HKLM:\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
        "HKLM:\\System\\CurrentControlSet\\Control\\Session Manager\\BootExecute",
        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    ]
    rows: List[Dict[str, Any]] = []
    for loc in locations:
        try:
            data = _run_ps(
                f"$p = Get-ItemProperty '{loc}' -ErrorAction SilentlyContinue; "
                "if ($p) { foreach ($n in ($p | Get-Member -MemberType NoteProperty | Where-Object Name -notmatch '^PS').Name) {"
                f" [pscustomobject]@{{ Location='{loc}'; Name=$n; Value=$p.$n }} }} }}",
                timeout=4,
            )
            if data is None:
                continue
            items = data if isinstance(data, list) else [data]
            rows.extend(items)
        except Exception:
            continue

    findings: List[HuntFinding] = []
    sus_keywords = ("\\temp\\", "\\appdata\\local\\temp\\", "powershell -enc",
                    "powershell -e ", ".vbs", ".js", "rundll32",
                    "mshta", "wscript", "frombase64string")
    for it in rows:
        if not isinstance(it, dict):
            continue
        val = str(it.get("Value", "")).lower()
        if any(k in val for k in sus_keywords):
            findings.append(HuntFinding(
                title=f"Suspicious persistence: {it.get('Name')}",
                severity="high",
                technique="T1547.001",
                evidence=it,
                remediation_key="autorun_suspicious",
            ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


def hunt_network_outbound_top_remote() -> Dict[str, Any]:
    """T1041 — Top outbound connections; flag non-RFC1918 destinations on non-standard ports."""
    rows = _ps(
        "Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | "
        "Where-Object { $_.RemoteAddress -notmatch '^(10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|127\\.|::1|fe80)' } | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess"
    )
    findings: List[HuntFinding] = []
    suspicious_ports = {4444, 4445, 8888, 9001, 50050, 6666, 6667, 31337, 8443, 53}
    for r in rows:
        if not isinstance(r, dict):
            continue
        port = r.get("RemotePort")
        if port in suspicious_ports:
            findings.append(HuntFinding(
                title=f"Outbound to suspicious port: {r.get('RemoteAddress')}:{port}",
                severity="high",
                technique="T1041",
                evidence=r,
                remediation_key="malicious_ip",
            ))
    return {"rows": rows, "findings": [f.to_dict() for f in findings]}


# ── Catalog ──────────────────────────────────────────────────────────────────

QUERIES: Dict[str, Dict[str, Any]] = {
    "unsigned_temp": {
        "title": "Processi non firmati in path temp",
        "description": "Rileva binari in esecuzione da %TEMP%, %APPDATA%\\Local\\Temp, ProgramData, Users\\Public.",
        "technique": "T1036.005",
        "fn": hunt_unsigned_processes_in_temp,
    },
    "orphan_processes": {
        "title": "Processi orfani (parent terminato)",
        "description": "Trova processi il cui parent non esiste più — possibile process hollowing.",
        "technique": "T1055",
        "fn": hunt_orphan_processes,
    },
    "scheduled_tasks_recent": {
        "title": "Scheduled tasks creati di recente",
        "description": "Task creati negli ultimi 30 giorni con flag su pattern di abuse.",
        "technique": "T1053.005",
        "fn": hunt_scheduled_tasks_recent,
    },
    "wmi_persistence": {
        "title": "WMI Event Subscription persistence",
        "description": "FilterToConsumerBinding nel namespace root\\subscription (classic APT TTP).",
        "technique": "T1546.003",
        "fn": hunt_wmi_persistence,
    },
    "unusual_services": {
        "title": "Servizi con path inusuali / non firmati",
        "description": "Servizi running con executable non in System32/Program Files.",
        "technique": "T1543.003",
        "fn": hunt_unusual_services,
    },
    "failed_logons": {
        "title": "Brute force / Password spray (4625)",
        "description": "Logon falliti negli ultimi 24h aggregati per IP sorgente e utente target.",
        "technique": "T1110",
        "fn": hunt_event_log_failed_logons,
    },
    "user_changes": {
        "title": "Modifiche account utente (7d)",
        "description": "Eventi 4720/4724/4732/4738: creazione, reset password, aggiunta a gruppi privilegiati.",
        "technique": "T1136",
        "fn": hunt_event_log_user_changes,
    },
    "lolbins": {
        "title": "LOLBins con argomenti sospetti",
        "description": "powershell/cmd/regsvr32/rundll32/mshta/certutil/bitsadmin in esecuzione con pattern di abuse.",
        "technique": "T1218",
        "fn": hunt_lolbins_running,
    },
    "dns_tunnel": {
        "title": "DNS tunnelling / DGA candidates",
        "description": "Query DNS con subdomain anomale (alta entropia, lunghi).",
        "technique": "T1071.004",
        "fn": hunt_unusual_dns_queries,
    },
    "rdp_external": {
        "title": "RDP logons da IP esterni",
        "description": "Eventi 4624 logon type 10 con IP sorgente non-RFC1918 nelle ultime 7 settimane.",
        "technique": "T1021.001",
        "fn": hunt_rdp_logons_external,
    },
    "recent_dll": {
        "title": "DLL modificate di recente in System32",
        "description": "DLL scritte negli ultimi 7 giorni; flag se non firmate.",
        "technique": "T1574.002",
        "fn": hunt_recent_dll_modifications,
    },
    "named_pipes": {
        "title": "Named pipes sospette (Cobalt Strike / Meterpreter)",
        "description": "Pipe con pattern noti dei framework C2.",
        "technique": "T1559.001",
        "fn": hunt_named_pipes,
    },
    "registry_persistence": {
        "title": "Registry Run keys + obscure persistence",
        "description": "10 location registry (Run, RunOnce, Winlogon, IFEO, BootExecute) con flag su pattern di abuse.",
        "technique": "T1547.001",
        "fn": hunt_registry_persistence,
    },
    "outbound_suspicious_ports": {
        "title": "Connessioni outbound verso porte tipiche C2",
        "description": "Connessioni TCP established verso 4444/4445/8888/9001/50050 ecc. su IP non-RFC1918.",
        "technique": "T1041",
        "fn": hunt_network_outbound_top_remote,
    },
}


# ── Public API ───────────────────────────────────────────────────────────────

def list_queries() -> List[Dict[str, Any]]:
    return [{"id": k, "title": v["title"], "description": v["description"],
             "technique": v["technique"]} for k, v in QUERIES.items()]


def run_query(query_id: str) -> Dict[str, Any]:
    q = QUERIES.get(query_id)
    if not q:
        return {"error": f"unknown query: {query_id}"}
    started = datetime.now(timezone.utc)
    try:
        result = q["fn"]()
    except Exception as e:
        LOGGER.exception("Hunt query %s failed", query_id)
        return {
            "id": query_id, "title": q["title"], "technique": q["technique"],
            "error": str(e),
        }
    completed = datetime.now(timezone.utc)
    return {
        "id": query_id,
        "title": q["title"],
        "description": q["description"],
        "technique": q["technique"],
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "duration_seconds": round((completed - started).total_seconds(), 2),
        **result,
    }


def run_all(parallel: bool = True) -> Dict[str, Any]:
    """Run the entire catalog. Parallel for speed."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    started = datetime.now(timezone.utc)
    results: Dict[str, Any] = {}
    if parallel:
        with ThreadPoolExecutor(max_workers=6, thread_name_prefix="hunt") as ex:
            futs = {ex.submit(run_query, qid): qid for qid in QUERIES}
            for fut in as_completed(futs, timeout=180):
                results[futs[fut]] = fut.result()
    else:
        for qid in QUERIES:
            results[qid] = run_query(qid)

    # Aggregate findings across queries
    all_findings: List[Dict[str, Any]] = []
    for qid, r in results.items():
        for f in r.get("findings", []) if isinstance(r, dict) else []:
            all_findings.append({**f, "query": qid})

    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    completed = datetime.now(timezone.utc)
    return {
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "duration_seconds": round((completed - started).total_seconds(), 2),
        "query_count": len(QUERIES),
        "total_findings": len(all_findings),
        "by_severity": counts,
        "findings": all_findings,
        "results": results,
    }
