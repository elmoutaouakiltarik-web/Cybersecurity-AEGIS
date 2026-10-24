#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Enhanced Windows Audit
=============================================
Adds deep, enterprise-grade Windows security checks beyond the baseline
hardening audit:

  - TPM 2.0 presence + activation
  - Secure Boot + UEFI status
  - Sysmon installation + service status
  - USB device connection history (forensics)
  - Wi-Fi profiles + WPA version audit
  - Browser extension inventory (Chrome / Edge)
  - Hyper-V / Virtualisation Based Security (VBS) / Credential Guard
  - LAPS (Local Administrator Password Solution) presence
  - Audit policy (auditpol /get)
  - Recent driver installations (last 30 days, unsigned highlighted)

All checks are READ-ONLY. Findings ship with MITRE technique mapping and a
remediation_key the dashboard can resolve via /api/v1/remediation.
"""
from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from windows_audit import _run_ps

LOGGER = logging.getLogger("aegis.endpoint.enhanced")


def _finding(check_id: str, title: str, status: str, severity: str,
             description: str, value: Any = None,
             remediation_key: Optional[str] = None,
             technique: str = "") -> Dict[str, Any]:
    return {
        "check_id": check_id,
        "title": title,
        "status": status,        # ok | warn | fail | info
        "severity": severity,    # info | low | medium | high | critical
        "description": description,
        "value": value,
        "remediation_key": remediation_key,
        "technique": technique,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ── TPM ────────────────────────────────────────────────────────────────────

def check_tpm() -> Dict[str, Any]:
    """TPM 2.0 presence + activation + version."""
    data = _run_ps(
        "Get-CimInstance -Namespace 'root\\cimv2\\Security\\MicrosoftTpm' "
        "-ClassName Win32_Tpm -ErrorAction SilentlyContinue | "
        "Select-Object IsEnabled_InitialValue, IsActivated_InitialValue, "
        "IsOwned_InitialValue, SpecVersion, PhysicalPresenceVersionInfo, ManufacturerVersion"
    )
    findings: List[Dict[str, Any]] = []
    if data is None:
        return {"available": False,
                "error": "TPM non rilevato. Verifica BIOS/UEFI o platform support."}
    if isinstance(data, list) and len(data) > 0:
        data = data[0]
    if not isinstance(data, dict):
        return {"available": False, "error": "TPM query format inattesa"}
    enabled = bool(data.get("IsEnabled_InitialValue"))
    activated = bool(data.get("IsActivated_InitialValue"))
    spec = str(data.get("SpecVersion") or "")
    is_tpm2 = spec.startswith("2.")
    findings.append(_finding(
        "tpm.present", f"TPM {spec or '?'} present",
        "ok" if enabled else "fail",
        "info" if enabled else "high",
        "TPM è il root-of-trust hardware per BitLocker, Windows Hello e attestazione VBS.",
        value=data, technique="T1542",
        remediation_key=None if enabled else "tpm_disabled",
    ))
    if enabled and not is_tpm2:
        findings.append(_finding(
            "tpm.legacy", "TPM 1.2 obsoleto",
            "warn", "medium",
            "TPM 1.2 non supporta gli algoritmi richiesti da Windows 11 e BitLocker moderno.",
            value=spec, remediation_key="tpm_legacy", technique="T1542",
        ))
    if enabled and not activated:
        findings.append(_finding(
            "tpm.inactive", "TPM presente ma non attivato",
            "warn", "high",
            "Attiva il TPM da BIOS/UEFI o usa tpm.msc → 'Prepare the TPM'.",
            value=data, remediation_key="tpm_inactive", technique="T1542",
        ))
    return {"available": True, "raw": data, "findings": findings}


# ── Secure Boot + UEFI ────────────────────────────────────────────────────

def check_secure_boot() -> Dict[str, Any]:
    """Secure Boot enabled and UEFI firmware mode."""
    sb = _run_ps("Confirm-SecureBootUEFI -ErrorAction SilentlyContinue")
    firmware = _run_ps(
        "(Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).BootupState; "
        "$env:firmware_type"
    )
    findings: List[Dict[str, Any]] = []
    if sb is None:
        return {"available": False,
                "error": "Confirm-SecureBootUEFI non disponibile (probabilmente BIOS legacy)."}
    sb_on = bool(sb)
    findings.append(_finding(
        "secureboot.enabled", "Secure Boot " + ("ON" if sb_on else "OFF"),
        "ok" if sb_on else "fail",
        "info" if sb_on else "high",
        "Secure Boot impedisce il caricamento di bootloader non firmati (bootkit, ToxicEel, Black Lotus).",
        value=sb_on,
        remediation_key=None if sb_on else "secureboot_off",
        technique="T1542.003",
    ))
    return {"available": True, "raw": {"secure_boot": sb_on, "firmware": firmware},
            "findings": findings}


# ── VBS / Credential Guard / HVCI ─────────────────────────────────────────

def check_vbs() -> Dict[str, Any]:
    """Virtualization Based Security / Credential Guard / HVCI."""
    data = _run_ps(
        "Get-CimInstance -ClassName Win32_DeviceGuard -Namespace 'root\\Microsoft\\Windows\\DeviceGuard' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object VirtualizationBasedSecurityStatus, "
        "SecurityServicesConfigured, SecurityServicesRunning, "
        "CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus"
    )
    findings: List[Dict[str, Any]] = []
    if data is None:
        return {"available": False,
                "error": "Win32_DeviceGuard non disponibile (server core o Home edition)."}
    if isinstance(data, list):
        data = data[0] if data else {}
    if not isinstance(data, dict):
        return {"available": False, "error": "VBS query format inattesa"}
    vbs_status = data.get("VirtualizationBasedSecurityStatus")  # 0=off, 1=configured, 2=running
    services_running = data.get("SecurityServicesRunning") or []
    if isinstance(services_running, int):
        services_running = [services_running]
    has_credguard = 1 in services_running
    has_hvci = 2 in services_running

    findings.append(_finding(
        "vbs.status",
        f"VBS {'RUNNING' if vbs_status == 2 else 'CONFIGURED' if vbs_status == 1 else 'OFF'}",
        "ok" if vbs_status == 2 else "warn",
        "info" if vbs_status == 2 else "medium",
        "Virtualization Based Security isola componenti critici in un mini-hypervisor.",
        value=data, remediation_key="vbs_off" if vbs_status != 2 else None,
        technique="T1547",
    ))
    findings.append(_finding(
        "vbs.credguard",
        "Credential Guard " + ("ON" if has_credguard else "OFF"),
        "ok" if has_credguard else "warn",
        "info" if has_credguard else "high",
        "Credential Guard protegge LSASS da Mimikatz, pass-the-hash, pass-the-ticket.",
        value=has_credguard,
        remediation_key="credguard_off" if not has_credguard else None,
        technique="T1003.001",
    ))
    findings.append(_finding(
        "vbs.hvci",
        "Memory Integrity (HVCI) " + ("ON" if has_hvci else "OFF"),
        "ok" if has_hvci else "warn",
        "info" if has_hvci else "medium",
        "HVCI verifica l'integrità dei driver kernel — blocca i rootkit driver-based.",
        value=has_hvci,
        remediation_key="hvci_off" if not has_hvci else None,
        technique="T1014",
    ))
    return {"available": True, "raw": data, "findings": findings}


# ── Sysmon ─────────────────────────────────────────────────────────────────

def check_sysmon() -> Dict[str, Any]:
    """Sysinternals Sysmon installation + service state."""
    svc = _run_ps(
        "Get-Service -Name Sysmon,Sysmon64 -ErrorAction SilentlyContinue | "
        "Select-Object Name,Status,StartType"
    )
    findings: List[Dict[str, Any]] = []
    installed = svc is not None and (
        (isinstance(svc, dict) and svc.get("Status") is not None) or
        (isinstance(svc, list) and len(svc) > 0)
    )
    if not installed:
        findings.append(_finding(
            "sysmon.missing", "Sysmon non installato",
            "warn", "medium",
            "Sysmon (Sysinternals) fornisce telemetria di process creation, network connections, file integrity, registry — essenziale per DFIR. Installa con SwiftOnSecurity config: https://github.com/SwiftOnSecurity/sysmon-config",
            value=None, remediation_key="sysmon_missing", technique="T1562.002",
        ))
        return {"available": True, "raw": None, "findings": findings}

    if isinstance(svc, dict):
        svc = [svc]
    for s in svc:
        if not isinstance(s, dict):
            continue
        running = (s.get("Status") == 4 or str(s.get("Status")).lower() == "running")
        if not running:
            findings.append(_finding(
                f"sysmon.{s.get('Name')}.stopped",
                f"Sysmon service {s.get('Name')} non running",
                "fail", "high",
                "Avvia il servizio: Start-Service Sysmon64",
                value=s, remediation_key="sysmon_stopped", technique="T1562.002",
            ))
        else:
            findings.append(_finding(
                f"sysmon.{s.get('Name')}.ok",
                f"Sysmon {s.get('Name')} running",
                "ok", "info",
                "Service attivo.",
                value=s,
            ))
    # Config dump (eventi configurati)
    try:
        sysmon_exe = _run_ps(
            "(Get-Command sysmon64.exe -ErrorAction SilentlyContinue).Source ?? "
            "(Get-Command sysmon.exe -ErrorAction SilentlyContinue).Source"
        )
        if sysmon_exe:
            # Conta event filter rules dal log
            event_count = _run_ps(
                "(Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                "-MaxEvents 1 -ErrorAction SilentlyContinue).Count"
            )
            findings.append(_finding(
                "sysmon.log_active",
                "Sysmon event log " + ("attivo" if event_count else "vuoto"),
                "ok" if event_count else "warn",
                "info" if event_count else "medium",
                "Verifica con: Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational'.",
                value=event_count,
            ))
    except Exception:
        pass
    return {"available": True, "raw": svc, "findings": findings}


# ── USB device history (forensics) ─────────────────────────────────────────

def check_usb_history() -> Dict[str, Any]:
    """All USB devices ever connected (forensic value: T1052 data exfil via USB)."""
    data = _run_ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\*\\*' "
        "-ErrorAction SilentlyContinue | "
        "Select-Object FriendlyName, Service, ContainerID, ParentIdPrefix"
    )
    findings: List[Dict[str, Any]] = []
    if data is None:
        return {"available": False, "error": "USBSTOR registry non leggibile (admin required?)."}
    if isinstance(data, dict):
        data = [data]
    if not data:
        return {"available": True, "raw": [], "findings": [],
                "summary": {"total": 0}}
    findings.append(_finding(
        "usb.history",
        f"{len(data)} dispositivi USB storage in storico",
        "info", "info",
        "Lista USB drive collegati storicamente. Confronta con whitelist aziendale.",
        value={"count": len(data), "sample": data[:10]},
        technique="T1052.001",
    ))
    # Flag any device with "phone" in name (potential exfil channel)
    for d in data:
        if isinstance(d, dict):
            name = str(d.get("FriendlyName") or "").lower()
            if any(k in name for k in ("phone", "android", "iphone", "ipad")):
                findings.append(_finding(
                    f"usb.mobile.{name[:30]}",
                    f"Mobile device collegato: {d.get('FriendlyName')}",
                    "info", "low",
                    "Smartphone come storage USB può essere vettore di exfiltration.",
                    value=d, technique="T1052.001",
                ))
    return {"available": True, "raw": data, "findings": findings,
            "summary": {"total": len(data)}}


# ── Wi-Fi profiles ────────────────────────────────────────────────────────

def check_wifi_profiles() -> Dict[str, Any]:
    """Saved Wi-Fi profiles + auth method (WEP/WPA/WPA2/WPA3)."""
    raw = _run_ps(
        "$profiles = & netsh wlan show profiles; "
        "$names = $profiles | Select-String -Pattern 'All User Profile\\s+:\\s+(.+)' | "
        "ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() }; "
        "$out = @(); "
        "foreach ($n in $names) { "
        "  $det = & netsh wlan show profile name=\"$n\" key=clear 2>&1; "
        "  $auth = ($det | Select-String 'Authentication\\s+:\\s+(.+)' | "
        "    ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } | Select-Object -First 1); "
        "  $cipher = ($det | Select-String 'Cipher\\s+:\\s+(.+)' | "
        "    ForEach-Object { $_.Matches[0].Groups[1].Value.Trim() } | Select-Object -First 1); "
        "  $out += [pscustomobject]@{ Name=$n; Authentication=$auth; Cipher=$cipher } "
        "}; "
        "$out",
        timeout=20,
    )
    findings: List[Dict[str, Any]] = []
    if raw is None:
        return {"available": False,
                "error": "netsh wlan non disponibile (adapter Wi-Fi assente o admin required)."}
    if isinstance(raw, dict):
        raw = [raw]
    if not raw:
        return {"available": True, "raw": [], "findings": [],
                "summary": {"total": 0}}
    weak_count = 0
    for p in raw:
        if not isinstance(p, dict):
            continue
        auth = str(p.get("Authentication") or "").lower()
        if any(k in auth for k in ("open", "wep", "shared")):
            weak_count += 1
            findings.append(_finding(
                f"wifi.weak.{p.get('Name')}",
                f"Wi-Fi insicuro: {p.get('Name')} ({auth})",
                "fail", "high",
                "Profilo Wi-Fi con autenticazione debole (Open/WEP). Rimuovi o aggiorna a WPA2/WPA3.",
                value=p, remediation_key="wifi_weak_profile", technique="T1078.001",
            ))
        elif "wpa3" in auth:
            findings.append(_finding(
                f"wifi.ok.{p.get('Name')}",
                f"Wi-Fi WPA3: {p.get('Name')}",
                "ok", "info", "Cipher moderno.", value=p,
            ))
    findings.append(_finding(
        "wifi.profiles.count",
        f"{len(raw)} profili Wi-Fi salvati ({weak_count} insicuri)",
        "info" if weak_count == 0 else "warn",
        "info" if weak_count == 0 else "medium",
        "Profili Wi-Fi memorizzati nel sistema con relativa autenticazione.",
        value={"count": len(raw), "weak": weak_count},
    ))
    return {"available": True, "raw": raw, "findings": findings,
            "summary": {"total": len(raw), "weak": weak_count}}


# ── Browser extensions (Chrome / Edge) ────────────────────────────────────

def check_browser_extensions() -> Dict[str, Any]:
    """Installed extensions in Chrome and Edge user data dirs."""
    findings: List[Dict[str, Any]] = []
    all_exts: List[Dict[str, Any]] = []

    browsers = {
        "Chrome": Path(os.environ.get("LOCALAPPDATA", "")) / "Google" / "Chrome" / "User Data" / "Default" / "Extensions",
        "Edge":   Path(os.environ.get("LOCALAPPDATA", "")) / "Microsoft" / "Edge" / "User Data" / "Default" / "Extensions",
    }
    # Known-bad extension IDs (a tiny sample of historical malicious extensions)
    KNOWN_BAD = {
        "iblpehoogmodaakkmpfaagoiamoenidd": "Crypto miner",
        "ojhmphdkpgbibohbnpbfiefkgieacjmh": "Banking trojan",
        "fpbohnplhcfkajmpefnopffpcoidbnmf": "Adware",
    }

    for name, root in browsers.items():
        if not root.exists():
            continue
        for ext_id_dir in root.iterdir():
            if not ext_id_dir.is_dir():
                continue
            ext_id = ext_id_dir.name
            # Find manifest in any version sub-folder
            manifest = None
            for ver_dir in ext_id_dir.iterdir():
                if not ver_dir.is_dir():
                    continue
                m = ver_dir / "manifest.json"
                if m.exists():
                    try:
                        manifest = json.loads(m.read_text(encoding="utf-8", errors="replace"))
                        break
                    except Exception:
                        continue
            ext_info = {
                "browser": name,
                "id": ext_id,
                "name": (manifest or {}).get("name", "(unknown)"),
                "version": (manifest or {}).get("version", ""),
                "permissions": (manifest or {}).get("permissions", []) if manifest else [],
            }
            all_exts.append(ext_info)
            if ext_id in KNOWN_BAD:
                findings.append(_finding(
                    f"browser.malicious.{ext_id}",
                    f"Estensione MALEVOLA nota in {name}: {ext_info['name']}",
                    "fail", "critical",
                    f"Indicator: {KNOWN_BAD[ext_id]}. Rimuovi immediatamente.",
                    value=ext_info, remediation_key="browser_malicious_ext",
                    technique="T1176",
                ))
            # Excessive permissions
            risky_perms = ["<all_urls>", "tabs", "history", "cookies", "webRequest",
                            "webRequestBlocking", "proxy", "management"]
            granted_risky = [p for p in ext_info["permissions"]
                              if isinstance(p, str) and p in risky_perms]
            if len(granted_risky) >= 4:
                findings.append(_finding(
                    f"browser.risky.{ext_id}",
                    f"Estensione con permessi alti: {ext_info['name']} ({name})",
                    "warn", "medium",
                    f"Permessi: {', '.join(granted_risky)}. Verifica reputazione su Chrome Web Store.",
                    value=ext_info, remediation_key="browser_risky_ext",
                    technique="T1176",
                ))

    return {
        "available": True,
        "extensions": all_exts,
        "findings": findings,
        "summary": {"total": len(all_exts), "browsers": list(browsers.keys())},
    }


# ── LAPS check ────────────────────────────────────────────────────────────

def check_laps() -> Dict[str, Any]:
    """Local Administrator Password Solution presence (enterprise)."""
    data = _run_ps(
        "$svc = Get-Service -Name AdmPwdAgent,LapsCS,LapsAgent -ErrorAction SilentlyContinue; "
        "$reg = Get-ItemProperty 'HKLM:\\Software\\Policies\\Microsoft Services\\AdmPwd' -ErrorAction SilentlyContinue; "
        "$regnew = Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Policies\\LAPS' -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{ Services=$svc; LegacyPolicy=$reg; ModernPolicy=$regnew }"
    )
    findings: List[Dict[str, Any]] = []
    if data is None:
        return {"available": False, "error": "LAPS query failed"}
    has_legacy = bool(data.get("LegacyPolicy"))
    has_modern = bool(data.get("ModernPolicy"))
    if not has_legacy and not has_modern:
        findings.append(_finding(
            "laps.missing", "LAPS non configurato",
            "warn", "medium",
            "LAPS (Local Administrator Password Solution) ruota automaticamente le password admin. Critico per ambienti aziendali.",
            value=data, remediation_key="laps_missing", technique="T1078.003",
        ))
    else:
        findings.append(_finding(
            "laps.present", "LAPS attivo",
            "ok", "info",
            "Password admin gestita centralmente.", value=data,
        ))
    return {"available": True, "raw": data, "findings": findings}


# ── Audit policy ──────────────────────────────────────────────────────────

def check_audit_policy() -> Dict[str, Any]:
    """Windows Security Auditing policy (auditpol)."""
    data = _run_ps(
        "$out = & auditpol /get /category:* 2>&1 | Out-String; "
        "$lines = $out -split '\\r?\\n' | Where-Object { $_ -match '^\\s+\\S' }; "
        "$entries = @(); "
        "foreach ($l in $lines) { "
        "  if ($l -match '^\\s{2}(.+?)\\s{2,}(.+)$') { "
        "    $entries += [pscustomobject]@{ Subcategory=$matches[1].Trim(); Setting=$matches[2].Trim() } "
        "  } "
        "}; "
        "$entries",
        timeout=10,
    )
    findings: List[Dict[str, Any]] = []
    if data is None:
        return {"available": False, "error": "auditpol non eseguibile (admin required)."}
    if isinstance(data, dict):
        data = [data]
    # Critical subcategories that should be enabled
    critical = {
        "Logon": "Success and Failure",
        "Process Creation": "Success",
        "Special Logon": "Success",
        "Security Group Management": "Success and Failure",
        "User Account Management": "Success and Failure",
        "Credential Validation": "Success and Failure",
        "Audit Policy Change": "Success and Failure",
        "Sensitive Privilege Use": "Success and Failure",
    }
    settings_map = {}
    for e in data:
        if isinstance(e, dict):
            settings_map[e.get("Subcategory")] = e.get("Setting")
    not_audited = []
    for sub, expected in critical.items():
        actual = settings_map.get(sub, "")
        if "no auditing" in str(actual).lower() or not actual:
            not_audited.append(sub)
    if not_audited:
        findings.append(_finding(
            "audit.policy.gaps",
            f"{len(not_audited)} subcategorie critiche non auditate",
            "warn", "high",
            f"Subcategorie senza audit: {', '.join(not_audited[:5])}. Configura con auditpol /set.",
            value={"missing": not_audited, "total_critical": len(critical)},
            remediation_key="audit_policy_gaps", technique="T1562.008",
        ))
    else:
        findings.append(_finding(
            "audit.policy.ok",
            "Audit policy configurata correttamente",
            "ok", "info",
            f"Tutte le {len(critical)} subcategorie critiche sono auditate.",
            value=settings_map,
        ))
    return {"available": True, "raw": data, "findings": findings,
            "critical_settings": {k: settings_map.get(k, "missing") for k in critical}}


# ── Recent driver installations ───────────────────────────────────────────

def check_recent_drivers() -> Dict[str, Any]:
    """Drivers installed in the last 30 days; flag unsigned ones."""
    data = _run_ps(
        "Get-CimInstance Win32_PnPSignedDriver | "
        "Where-Object { $_.DriverDate -and "
        "  ([Management.ManagementDateTimeConverter]::ToDateTime($_.DriverDate)) -gt (Get-Date).AddDays(-30) } | "
        "Select-Object DeviceName, Manufacturer, DriverVersion, DriverDate, IsSigned, Signer | "
        "Sort-Object DriverDate -Descending",
        timeout=20,
    )
    findings: List[Dict[str, Any]] = []
    if data is None:
        return {"available": False, "error": "WMI driver query fallita"}
    if isinstance(data, dict):
        data = [data]
    unsigned = [d for d in data if isinstance(d, dict) and d.get("IsSigned") is False]
    if unsigned:
        findings.append(_finding(
            "drivers.unsigned",
            f"{len(unsigned)} driver non firmati installati negli ultimi 30 giorni",
            "warn", "high",
            "Driver non firmati possono essere rootkit (BYOVD attack — Bring Your Own Vulnerable Driver).",
            value={"unsigned": unsigned[:10], "total_recent": len(data)},
            remediation_key="unsigned_driver", technique="T1547.006",
        ))
    findings.append(_finding(
        "drivers.recent",
        f"{len(data)} driver installati ultimi 30gg",
        "info", "info",
        "Lista driver recenti per audit forensico.",
        value={"count": len(data)},
    ))
    return {"available": True, "raw": data[:20] if data else [],
            "findings": findings}


# ── Orchestrator ──────────────────────────────────────────────────────────

ENHANCED_CHECKS = {
    "tpm":            check_tpm,
    "secure_boot":    check_secure_boot,
    "vbs":            check_vbs,
    "sysmon":         check_sysmon,
    "usb_history":    check_usb_history,
    "wifi_profiles":  check_wifi_profiles,
    "browser_exts":   check_browser_extensions,
    "laps":           check_laps,
    "audit_policy":   check_audit_policy,
    "recent_drivers": check_recent_drivers,
}


def run_enhanced_audit() -> Dict[str, Any]:
    """Run all enhanced checks in parallel."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    started = datetime.now(timezone.utc)
    results: Dict[str, Any] = {}
    all_findings: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=6, thread_name_prefix="enhanced") as ex:
        futures = {ex.submit(fn): name for name, fn in ENHANCED_CHECKS.items()}
        for fut in as_completed(futures, timeout=120):
            name = futures[fut]
            try:
                res = fut.result()
                results[name] = res
                for f in res.get("findings", []) if isinstance(res, dict) else []:
                    all_findings.append({**f, "check": name})
            except Exception as e:
                LOGGER.exception("Enhanced check %s failed", name)
                results[name] = {"available": False, "error": str(e)}

    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = f.get("severity", "info")
        if f.get("status") in ("warn", "fail"):
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

    completed = datetime.now(timezone.utc)
    return {
        "started_at": started.isoformat(),
        "completed_at": completed.isoformat(),
        "duration_seconds": round((completed - started).total_seconds(), 2),
        "checks_run": list(ENHANCED_CHECKS.keys()),
        "by_severity": sev_counts,
        "total_findings": sum(1 for f in all_findings if f.get("status") in ("warn", "fail")),
        "findings": all_findings,
        "checks": results,
    }
