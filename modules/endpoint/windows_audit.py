#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Windows Endpoint Audit
=============================================
Real-time inspection of the Windows host that runs this module.

All checks are READ-ONLY. No registry writes, no service stops, no firewall
changes. The module returns structured findings; remediation is intentionally
left to the operator via the dashboard's `Fix` button (which queries the
orchestrator's /api/v1/remediation knowledge base).

Implementation: shells out to PowerShell. We deliberately do not depend on
WMI/CIM Python bindings — PowerShell is universally available on Win10+ and
gives consistent output across editions.
"""
from __future__ import annotations

import json
import logging
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

LOGGER = logging.getLogger("aegis.endpoint.audit")

PWSH = shutil.which("pwsh") or shutil.which("powershell") or "powershell"
PWSH_FLAGS = ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]


def _run_ps(script: str, timeout: int = 15) -> Optional[Any]:
    """Execute a PowerShell snippet that emits JSON and return the parsed value.

    Returns None on any failure. Errors are logged at DEBUG so a sequence of
    checks (some inevitably unavailable on a given SKU) does not spam the
    logs.
    """
    if sys.platform != "win32":
        return None
    wrapped = script + " | ConvertTo-Json -Depth 8 -Compress"
    try:
        proc = subprocess.run(
            [PWSH, *PWSH_FLAGS, "-Command", wrapped],
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
        )
        if proc.returncode != 0:
            LOGGER.debug("PowerShell exit %d: %s", proc.returncode, proc.stderr.strip()[:300])
            return None
        out = proc.stdout.strip()
        if not out:
            return None
        return json.loads(out)
    except subprocess.TimeoutExpired:
        LOGGER.warning("PowerShell timeout after %ds: %s", timeout, script[:80])
        return None
    except json.JSONDecodeError as e:
        LOGGER.debug("PowerShell non-JSON output: %s | %s", e, out[:200] if 'out' in locals() else '')
        return None
    except Exception as e:
        LOGGER.debug("PowerShell error: %s", e)
        return None


# ── Result types ─────────────────────────────────────────────────────────────

@dataclass
class Finding:
    """A single audit finding with severity and a remediation hint."""
    check_id: str
    title: str
    status: str                # ok | warn | fail | info
    severity: str              # info | low | medium | high | critical
    description: str = ""
    value: Any = None
    remediation_key: Optional[str] = None  # maps to /api/v1/remediation lookup
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Individual checks ────────────────────────────────────────────────────────

def check_defender() -> Dict[str, Any]:
    """Microsoft Defender state: signature freshness, real-time, tamper protection."""
    data = _run_ps(
        "Get-MpComputerStatus | "
        "Select-Object AntivirusEnabled,AMServiceEnabled,RealTimeProtectionEnabled,"
        "IoavProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected,"
        "AntivirusSignatureLastUpdated,AntivirusSignatureVersion,QuickScanStartTime,"
        "FullScanStartTime,NISEnabled,OnAccessProtectionEnabled"
    )
    if data is None:
        return {"available": False, "error": "Microsoft Defender state not available (admin rights or non-Windows)"}

    findings: List[Finding] = []
    rt = bool(data.get("RealTimeProtectionEnabled"))
    findings.append(Finding(
        check_id="defender.realtime",
        title="Real-time protection",
        status="ok" if rt else "fail",
        severity="critical" if not rt else "info",
        description="Defender real-time scanning blocks malicious files at execution.",
        value=rt,
        remediation_key=None if rt else "defender_realtime_off",
    ))
    tp = bool(data.get("IsTamperProtected"))
    findings.append(Finding(
        check_id="defender.tamper",
        title="Tamper protection",
        status="ok" if tp else "warn",
        severity="info" if tp else "medium",
        description="Prevents malware from disabling Defender.",
        value=tp,
        remediation_key=None if tp else "defender_tamper_off",
    ))
    sig_age_h = None
    last_sig = data.get("AntivirusSignatureLastUpdated")
    if last_sig:
        try:
            # PowerShell ConvertTo-Json emits dates like /Date(1700000000000)/
            from re import match as _m
            mm = _m(r"^/Date\((\d+)\)/$", str(last_sig))
            if mm:
                ts = int(mm.group(1)) / 1000.0
                sig_age_h = (time.time() - ts) / 3600.0
        except Exception:
            pass
    if sig_age_h is not None:
        too_old = sig_age_h > 72
        findings.append(Finding(
            check_id="defender.signatures",
            title="AV signature freshness",
            status="warn" if too_old else "ok",
            severity="high" if too_old else "info",
            description=f"Signatures updated {sig_age_h:.1f}h ago (threshold 72h).",
            value={"hours_old": round(sig_age_h, 1), "version": data.get("AntivirusSignatureVersion")},
            remediation_key="defender_signatures_stale" if too_old else None,
        ))

    return {
        "available": True,
        "raw": data,
        "findings": [f.to_dict() for f in findings],
    }


def check_firewall() -> Dict[str, Any]:
    """Windows Defender Firewall profile state."""
    data = _run_ps(
        "Get-NetFirewallProfile | "
        "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,LogAllowed,LogBlocked"
    )
    if data is None:
        return {"available": False, "error": "Get-NetFirewallProfile failed"}
    profiles = data if isinstance(data, list) else [data]
    findings: List[Finding] = []
    for p in profiles:
        name = p.get("Name") or "?"
        enabled = bool(p.get("Enabled"))
        findings.append(Finding(
            check_id=f"firewall.{str(name).lower()}.enabled",
            title=f"Firewall '{name}' enabled",
            status="ok" if enabled else "fail",
            severity="critical" if not enabled else "info",
            description=f"Default inbound: {p.get('DefaultInboundAction')}; Outbound: {p.get('DefaultOutboundAction')}.",
            value=p,
            remediation_key=None if enabled else "firewall_profile_disabled",
        ))
    return {"available": True, "profiles": profiles, "findings": [f.to_dict() for f in findings]}


def check_bitlocker() -> Dict[str, Any]:
    """BitLocker volume encryption.

    Strategy:
      1) Get-BitLockerVolume (cmdlet available on Pro/Enterprise).
      2) Fall back to `manage-bde -status` (works on Windows Home with
         Device Encryption, since manage-bde.exe ships with every SKU).
      3) Finally, check the Win32_EncryptableVolume CIM class.
    """
    data = _run_ps(
        "Get-BitLockerVolume -ErrorAction Stop | "
        "Select-Object MountPoint,VolumeStatus,EncryptionPercentage,ProtectionStatus,EncryptionMethod,KeyProtector"
    )
    if data is None:
        # Fallback: manage-bde.exe outputs human text; parse it for the
        # C: drive status. Available on every Windows edition.
        parsed = _run_ps(
            "$out = & manage-bde -status 2>&1; "
            "$txt = ($out | Out-String); "
            "$volumes = @(); "
            "$blocks = $txt -split 'Volume '; "
            "foreach ($b in $blocks) { "
            "  if ($b -match '([A-Z]:)\\s'){ "
            "    $mp = $matches[1]; "
            "    $prot = if ($b -match 'Protection Status:\\s+Protection (On|Off)') { if ($matches[1] -eq 'On') { 1 } else { 0 } } else { $null }; "
            "    $pct  = if ($b -match 'Percentage Encrypted:\\s+([0-9]+)') { [int]$matches[1] } else { $null }; "
            "    $vs   = if ($b -match 'Conversion Status:\\s+(.+?)\\s*\\r?\\n') { $matches[1] } else { 'unknown' }; "
            "    $em   = if ($b -match 'Encryption Method:\\s+(.+?)\\s*\\r?\\n') { $matches[1] } else { 'unknown' }; "
            "    $volumes += [pscustomobject]@{ MountPoint=$mp; VolumeStatus=$vs; EncryptionPercentage=$pct; ProtectionStatus=$prot; EncryptionMethod=$em; KeyProtector=$null } "
            "  } "
            "}; "
            "$volumes",
            timeout=10,
        )
        data = parsed
    if data is None:
        # Third fallback: Win32_EncryptableVolume (last resort).
        data = _run_ps(
            "Get-CimInstance -Namespace root\\cimv2\\Security\\MicrosoftVolumeEncryption "
            "-ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue | "
            "Select-Object DriveLetter,@{N='MountPoint';E={$_.DriveLetter}}, "
            "@{N='ProtectionStatus';E={$_.ProtectionStatus}}, "
            "@{N='EncryptionPercentage';E={$null}}, "
            "@{N='VolumeStatus';E={if ($_.ProtectionStatus -eq 1) {'FullyEncrypted'} else {'Unknown'}}}, "
            "@{N='EncryptionMethod';E={$null}}, "
            "@{N='KeyProtector';E={$null}}"
        )
    if data is None:
        return {
            "available": False,
            "error": "BitLocker non leggibile (nemmeno via manage-bde o WMI). Avvia il modulo con privilegi admin (aegis-endpoint.ps1 -Admin)."
        }
    vols = data if isinstance(data, list) else [data]
    findings: List[Finding] = []
    for v in vols:
        if not isinstance(v, dict):
            continue
        mp = v.get("MountPoint") or "?"
        prot = v.get("ProtectionStatus")
        pct = v.get("EncryptionPercentage") or 0
        encrypted = prot in (1, "On") and pct == 100
        findings.append(Finding(
            check_id=f"bitlocker.{mp}",
            title=f"BitLocker {mp}",
            status="ok" if encrypted else "warn",
            severity="info" if encrypted else "high",
            description=f"Protection: {prot}; Encryption: {pct}%.",
            value=v,
            remediation_key=None if encrypted else "bitlocker_off",
        ))
    return {"available": True, "volumes": vols, "findings": [f.to_dict() for f in findings]}


def check_local_accounts() -> Dict[str, Any]:
    """Local accounts: detect enabled-but-suspicious, no-password, stale, admin.

    Strategy:
      1) Try Get-LocalUser (Microsoft.PowerShell.LocalAccounts) — preferred.
      2) Fall back to Get-CimInstance Win32_UserAccount — works on every SKU
         including Windows Home where LocalAccounts module is unavailable.
    """
    data = _run_ps(
        "Get-LocalUser -ErrorAction Stop | "
        "Select-Object Name,Enabled,PasswordRequired,PasswordExpires,LastLogon,Description,SID"
    )
    if data is None:
        # Fallback for Windows Home / locked-down SKUs.
        data = _run_ps(
            "Get-CimInstance Win32_UserAccount -Filter \"LocalAccount=True\" -ErrorAction SilentlyContinue | "
            "Select-Object @{N='Name';E={$_.Name}}, "
            "@{N='Enabled';E={-not $_.Disabled}}, "
            "@{N='PasswordRequired';E={$_.PasswordRequired}}, "
            "@{N='PasswordExpires';E={-not $_.PasswordExpires}}, "
            "@{N='LastLogon';E={$null}}, "
            "@{N='Description';E={$_.Description}}, "
            "@{N='SID';E={$_.SID}}"
        )
    if data is None:
        return {
            "available": False,
            "error": "Né Get-LocalUser né Get-CimInstance Win32_UserAccount sono disponibili. Esegui con privilegi admin: aegis-endpoint.ps1 -Admin."
        }
    users = data if isinstance(data, list) else [data]
    admins = _run_ps(
        "Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue | "
        "Select-Object Name,ObjectClass,PrincipalSource"
    ) or []
    if isinstance(admins, dict):
        admins = [admins]

    findings: List[Finding] = []
    admin_names = {str(a.get("Name") or "").split("\\")[-1].lower() for a in admins if isinstance(a, dict)}

    for u in users:
        if not isinstance(u, dict):
            continue
        name = u.get("Name") or "?"
        enabled = bool(u.get("Enabled"))
        pw_req = bool(u.get("PasswordRequired"))
        is_admin = name.lower() in admin_names
        if enabled and not pw_req:
            findings.append(Finding(
                check_id=f"account.no_password.{name}",
                title=f"Account without password: {name}",
                status="fail", severity="critical",
                description="Local account does not require a password — anyone at console can log in.",
                value=u,
                remediation_key="account_no_password",
            ))
        if enabled and is_admin and name.lower() not in {"administrator"}:
            findings.append(Finding(
                check_id=f"account.admin.{name}",
                title=f"Admin account: {name}",
                status="info", severity="medium",
                description=f"User '{name}' is member of local Administrators group.",
                value=u,
                remediation_key="account_admin_review",
            ))
    return {
        "available": True,
        "users": users,
        "admins": admins,
        "findings": [f.to_dict() for f in findings],
    }


def check_smb_v1() -> Dict[str, Any]:
    """SMBv1 must be disabled (EternalBlue / WannaCry vector)."""
    data = _run_ps(
        "(Get-SmbServerConfiguration -ErrorAction SilentlyContinue).EnableSMB1Protocol"
    )
    if data is None:
        return {"available": False, "error": "Get-SmbServerConfiguration failed"}
    enabled = bool(data)
    f = Finding(
        check_id="smb.v1",
        title="SMBv1 protocol",
        status="fail" if enabled else "ok",
        severity="critical" if enabled else "info",
        description="SMBv1 is the EternalBlue / WannaCry attack surface and must be disabled.",
        value=enabled,
        remediation_key="smb_v1_enabled" if enabled else None,
    )
    return {"available": True, "enabled": enabled, "findings": [f.to_dict()]}


def check_rdp() -> Dict[str, Any]:
    """RDP exposure & NLA."""
    data = _run_ps(
        "$rdp = Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue; "
        "$nla = Get-ItemProperty 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{ DenyTSConnections = $rdp.fDenyTSConnections; UserAuthentication = $nla.UserAuthentication }"
    )
    if data is None:
        return {"available": False, "error": "RDP registry read failed"}
    deny = data.get("DenyTSConnections")
    nla = data.get("UserAuthentication")
    enabled = (deny == 0)
    nla_on = (nla == 1)
    findings: List[Finding] = []
    if enabled:
        findings.append(Finding(
            check_id="rdp.enabled",
            title="RDP enabled",
            status="warn", severity="high",
            description="Remote Desktop is enabled. Ensure it is not exposed to Internet (use VPN+NLA+MFA).",
            value={"enabled": True, "nla": nla_on},
            remediation_key="rdp_enabled",
        ))
        if not nla_on:
            findings.append(Finding(
                check_id="rdp.nla",
                title="RDP without NLA",
                status="fail", severity="critical",
                description="Network Level Authentication disabled — pre-auth attacks possible (BlueKeep).",
                value={"nla": False},
                remediation_key="rdp_nla_off",
            ))
    else:
        findings.append(Finding(
            check_id="rdp.enabled",
            title="RDP disabled", status="ok", severity="info",
            description="Remote Desktop is disabled on this host.", value=False,
        ))
    return {"available": True, "enabled": enabled, "nla": nla_on, "findings": [f.to_dict() for f in findings]}


def check_uac() -> Dict[str, Any]:
    """UAC: must be at highest level on workstations."""
    data = _run_ps(
        "Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object EnableLUA,ConsentPromptBehaviorAdmin,PromptOnSecureDesktop"
    )
    if data is None:
        return {"available": False, "error": "UAC registry read failed"}
    enabled = data.get("EnableLUA") == 1
    secure_desktop = data.get("PromptOnSecureDesktop") == 1
    findings: List[Finding] = []
    if not enabled:
        findings.append(Finding(
            check_id="uac.disabled",
            title="UAC disabled",
            status="fail", severity="critical",
            description="User Account Control is OFF — privilege escalation has no friction.",
            value=data,
            remediation_key="uac_disabled",
        ))
    elif not secure_desktop:
        findings.append(Finding(
            check_id="uac.no_secure_desktop",
            title="UAC without secure desktop",
            status="warn", severity="medium",
            description="UAC prompts on user desktop can be hijacked by malware.",
            value=data,
            remediation_key="uac_secure_desktop_off",
        ))
    else:
        findings.append(Finding(
            check_id="uac.ok",
            title="UAC at proper level",
            status="ok", severity="info",
            description="UAC enabled with secure desktop prompt.",
            value=data,
        ))
    return {"available": True, "config": data, "findings": [f.to_dict() for f in findings]}


def check_autoruns() -> Dict[str, Any]:
    """Startup items: Run, RunOnce, scheduled tasks at logon. Surface suspicious paths."""
    data = _run_ps(
        "$keys = @("
        "  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "  'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',"
        "  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',"
        "  'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce'"
        "); "
        "$out = @(); "
        "foreach($k in $keys){ "
        "  $p = Get-ItemProperty $k -ErrorAction SilentlyContinue; "
        "  if($p){ foreach($n in ($p | Get-Member -MemberType NoteProperty | Where-Object Name -notmatch '^PS').Name){ "
        "    $out += [pscustomobject]@{ Location=$k; Name=$n; Command=$p.$n } "
        "  } } "
        "}; "
        "$out"
    )
    if data is None:
        return {"available": False, "error": "Autoruns read failed"}
    items = data if isinstance(data, list) else [data] if data else []
    suspicious = []
    findings: List[Finding] = []
    sus_keywords = ("\\temp\\", "\\appdata\\local\\temp\\", "powershell -enc", "powershell -e ", "cmd /c", ".vbs", ".js")
    for it in items:
        if not isinstance(it, dict):
            continue
        cmd = str(it.get("Command", "")).lower()
        if any(k in cmd for k in sus_keywords):
            suspicious.append(it)
            findings.append(Finding(
                check_id=f"autorun.suspicious.{it.get('Name','?')}",
                title=f"Suspicious autorun: {it.get('Name')}",
                status="warn", severity="high",
                description=f"Autorun entry contains suspicious pattern in command: {it.get('Command')[:120]}",
                value=it,
                remediation_key="autorun_suspicious",
            ))
    return {
        "available": True,
        "items": items,
        "suspicious": suspicious,
        "count": len(items),
        "findings": [f.to_dict() for f in findings],
    }


def check_listening_ports() -> Dict[str, Any]:
    """TCP listening sockets. Flag risky ports exposed on non-loopback."""
    data = _run_ps(
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress,LocalPort,OwningProcess"
    )
    if data is None:
        return {"available": False, "error": "Get-NetTCPConnection failed"}
    conns = data if isinstance(data, list) else [data]
    # Resolve PIDs → process names
    pid_set = {c.get("OwningProcess") for c in conns if isinstance(c, dict)}
    pid_list = ",".join(str(p) for p in pid_set if p)
    procs = []
    if pid_list:
        procs = _run_ps(
            f"Get-Process -Id @({pid_list}) -ErrorAction SilentlyContinue | "
            "Select-Object Id,ProcessName,Path"
        ) or []
        if isinstance(procs, dict):
            procs = [procs]
    pmap = {p.get("Id"): p for p in procs if isinstance(p, dict)}

    risky_ports = {21: "ftp", 23: "telnet", 135: "rpc", 139: "netbios",
                   445: "smb", 1433: "mssql", 1521: "oracle", 2049: "nfs",
                   3306: "mysql", 3389: "rdp", 5432: "postgresql",
                   5900: "vnc", 6379: "redis", 27017: "mongodb"}
    findings: List[Finding] = []
    enriched = []
    for c in conns:
        if not isinstance(c, dict):
            continue
        port = c.get("LocalPort")
        addr = c.get("LocalAddress")
        is_loopback = str(addr).startswith("127.") or addr == "::1"
        proc = pmap.get(c.get("OwningProcess"), {})
        row = {**c, "process_name": proc.get("ProcessName"), "process_path": proc.get("Path")}
        enriched.append(row)
        if port in risky_ports and not is_loopback:
            svc = risky_ports[port]
            findings.append(Finding(
                check_id=f"port.{port}.{svc}",
                title=f"Risky port {port}/{svc} listening on {addr}",
                status="warn",
                severity="critical" if port in (23, 445, 3389) else "high",
                description=f"Port {port} ({svc}) is bound to {addr} (process: {proc.get('ProcessName','?')}, PID {c.get('OwningProcess')}).",
                value=row,
                remediation_key=f"service:{svc}",
            ))
    return {
        "available": True,
        "connections": enriched,
        "count": len(enriched),
        "findings": [f.to_dict() for f in findings],
    }


def check_shares() -> Dict[str, Any]:
    """SMB shares — flag everyone-readable, hidden shares, sensitive paths."""
    data = _run_ps(
        "Get-SmbShare -ErrorAction SilentlyContinue | "
        "Select-Object Name,Path,ShareType,Description,CurrentUsers"
    )
    if data is None:
        return {"available": False, "error": "Get-SmbShare failed"}
    shares = data if isinstance(data, list) else [data]
    findings: List[Finding] = []
    for s in shares:
        if not isinstance(s, dict):
            continue
        name = s.get("Name") or ""
        # Skip admin default shares (C$, IPC$, ADMIN$) — they are not removable
        if name.endswith("$"):
            continue
        findings.append(Finding(
            check_id=f"share.{name}",
            title=f"Network share: {name}",
            status="info", severity="medium",
            description=f"Share '{name}' published at '{s.get('Path')}'. Verify ACLs.",
            value=s,
            remediation_key="smb_share_review",
        ))
    return {"available": True, "shares": shares, "findings": [f.to_dict() for f in findings]}


def check_updates_pending() -> Dict[str, Any]:
    """Pending Windows updates via COM (read-only)."""
    data = _run_ps(
        "$s = New-Object -ComObject Microsoft.Update.Session; "
        "$searcher = $s.CreateUpdateSearcher(); "
        "$r = $searcher.Search('IsInstalled=0 and Type=\\'Software\\''); "
        "$r.Updates | ForEach-Object { [pscustomobject]@{ Title=$_.Title; Severity=$_.MsrcSeverity; Categories=($_.Categories | ForEach-Object Name) } }",
        timeout=45,
    )
    if data is None:
        return {"available": False, "error": "Microsoft.Update.Session unavailable or admin required"}
    updates = data if isinstance(data, list) else [data] if data else []
    findings: List[Finding] = []
    critical = [u for u in updates if isinstance(u, dict) and str(u.get("Severity", "")).lower() in {"critical", "important"}]
    if critical:
        findings.append(Finding(
            check_id="updates.critical_pending",
            title=f"{len(critical)} critical/important updates pending",
            status="fail", severity="high",
            description="Patch immediately via Windows Update.",
            value={"count": len(critical), "sample": critical[:5]},
            remediation_key="updates_critical_pending",
        ))
    elif updates:
        findings.append(Finding(
            check_id="updates.pending",
            title=f"{len(updates)} non-critical updates pending",
            status="warn", severity="medium",
            description="Schedule installation in next maintenance window.",
            value={"count": len(updates)},
            remediation_key="updates_pending",
        ))
    else:
        findings.append(Finding(
            check_id="updates.ok",
            title="Windows fully patched", status="ok", severity="info",
            description="No pending software updates found.", value=None,
        ))
    return {"available": True, "updates": updates[:50], "count": len(updates),
            "findings": [f.to_dict() for f in findings]}


def check_telemetry() -> Dict[str, Any]:
    """Windows telemetry level (CIS hardening)."""
    data = _run_ps(
        "Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\DataCollection' "
        "-Name AllowTelemetry -ErrorAction SilentlyContinue | Select-Object AllowTelemetry"
    )
    if data is None:
        return {"available": False, "error": "DataCollection policy not set"}
    lvl = data.get("AllowTelemetry")
    findings: List[Finding] = []
    if lvl is None or lvl > 1:
        findings.append(Finding(
            check_id="telemetry.high",
            title=f"Windows telemetry level: {lvl if lvl is not None else 'default'}",
            status="warn", severity="low",
            description="Consider setting AllowTelemetry=1 (basic) via Group Policy.",
            value=lvl,
            remediation_key="telemetry_high",
        ))
    else:
        findings.append(Finding(
            check_id="telemetry.basic",
            title="Telemetry at basic level", status="ok", severity="info",
            description="AllowTelemetry=1.", value=lvl,
        ))
    return {"available": True, "level": lvl, "findings": [f.to_dict() for f in findings]}


def check_powershell_logging() -> Dict[str, Any]:
    """ScriptBlock + Module logging — needed for forensics."""
    data = _run_ps(
        "$sb = (Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging; "
        "$ml = (Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging' -ErrorAction SilentlyContinue).EnableModuleLogging; "
        "[pscustomobject]@{ ScriptBlockLogging=$sb; ModuleLogging=$ml }"
    )
    if data is None:
        return {"available": False, "error": "PS logging registry read failed"}
    sb = data.get("ScriptBlockLogging") == 1
    ml = data.get("ModuleLogging") == 1
    findings: List[Finding] = []
    if not sb:
        findings.append(Finding(
            check_id="pslogging.scriptblock",
            title="PowerShell ScriptBlock logging disabled",
            status="warn", severity="medium",
            description="Without ScriptBlock logging, malicious encoded commands cannot be reviewed.",
            value=data, remediation_key="pslogging_off",
        ))
    if not ml:
        findings.append(Finding(
            check_id="pslogging.module",
            title="PowerShell Module logging disabled",
            status="warn", severity="low",
            description="Module logging adds forensics over imported modules.",
            value=data, remediation_key="pslogging_off",
        ))
    if sb and ml:
        findings.append(Finding(
            check_id="pslogging.ok",
            title="PowerShell logging enabled", status="ok", severity="info",
            value=data,
        ))
    return {"available": True, "config": data, "findings": [f.to_dict() for f in findings]}


def get_system_info() -> Dict[str, Any]:
    """Pure-Python host info (no PowerShell)."""
    import os, socket
    info = {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version.split()[0],
        "is_windows": sys.platform == "win32",
        "cwd": os.getcwd(),
        "user": os.getenv("USERNAME") or os.getenv("USER"),
    }
    if sys.platform == "win32":
        ps_info = _run_ps(
            "$os = Get-CimInstance Win32_OperatingSystem; "
            "$cs = Get-CimInstance Win32_ComputerSystem; "
            "[pscustomobject]@{ "
            "  OSCaption=$os.Caption; OSVersion=$os.Version; OSBuild=$os.BuildNumber; "
            "  Domain=$cs.Domain; Manufacturer=$cs.Manufacturer; Model=$cs.Model; "
            "  TotalPhysicalMemoryGB=[math]::Round($cs.TotalPhysicalMemory/1GB,1); "
            "  InstallDate=$os.InstallDate; LastBootUpTime=$os.LastBootUpTime; "
            "  NumberOfProcessors=$cs.NumberOfProcessors "
            "}"
        )
        if ps_info:
            info["windows"] = ps_info
    return info


# ── Orchestrating helpers ────────────────────────────────────────────────────

ALL_CHECKS = {
    "defender":  check_defender,
    "firewall":  check_firewall,
    "bitlocker": check_bitlocker,
    "accounts":  check_local_accounts,
    "smb_v1":    check_smb_v1,
    "rdp":       check_rdp,
    "uac":       check_uac,
    "autoruns":  check_autoruns,
    "ports":     check_listening_ports,
    "shares":    check_shares,
    "telemetry": check_telemetry,
    "pslogging": check_powershell_logging,
}

OPTIONAL_CHECKS = {
    "updates":   check_updates_pending,
}


def run_hardening_audit(include_updates: bool = False) -> Dict[str, Any]:
    """Runs the full audit suite and computes a 0-100 hardening score.

    Checks run in parallel (PowerShell processes are independent) so the full
    audit completes in a few seconds rather than tens of seconds.

    Score weights: critical=20, high=8, medium=3, low=1. Starting at 100,
    each finding subtracts its weight, floored at 0.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed
    started = datetime.now(timezone.utc).isoformat()
    results: Dict[str, Any] = {}
    all_findings: List[Dict[str, Any]] = []
    checks = dict(ALL_CHECKS)
    if include_updates:
        checks.update(OPTIONAL_CHECKS)

    # Run independent PowerShell-driven checks in parallel.
    max_workers = min(8, len(checks))
    with ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="audit") as ex:
        futures = {ex.submit(fn): name for name, fn in checks.items()}
        for fut in as_completed(futures, timeout=120):
            name = futures[fut]
            try:
                res = fut.result()
                results[name] = res
                for f in res.get("findings", []) if isinstance(res, dict) else []:
                    all_findings.append({**f, "check": name})
            except Exception as e:
                LOGGER.exception("Check %s failed", name)
                results[name] = {"available": False, "error": str(e)}

    weights = {"critical": 20, "high": 8, "medium": 3, "low": 1, "info": 0}
    score = 100
    for f in all_findings:
        if f.get("status") in ("warn", "fail"):
            score -= weights.get(f.get("severity", "info"), 0)
    score = max(0, score)

    summary = {
        "total": len(all_findings),
        "critical": sum(1 for f in all_findings if f.get("severity") == "critical" and f.get("status") in ("warn", "fail")),
        "high":     sum(1 for f in all_findings if f.get("severity") == "high" and f.get("status") in ("warn", "fail")),
        "medium":   sum(1 for f in all_findings if f.get("severity") == "medium" and f.get("status") in ("warn", "fail")),
        "low":      sum(1 for f in all_findings if f.get("severity") == "low" and f.get("status") in ("warn", "fail")),
        "ok":       sum(1 for f in all_findings if f.get("status") == "ok"),
    }
    return {
        "score": score,
        "started_at": started,
        "completed_at": datetime.now(timezone.utc).isoformat(),
        "host": get_system_info(),
        "summary": summary,
        "checks": results,
        "findings": all_findings,
    }
