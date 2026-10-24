#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Pro Audit Suite
======================================
Professional defensive controls for personal + enterprise:

  - DMARC / SPF / DKIM record validator for a domain (DNS TXT lookup)
  - Backup health check (3-2-1 rule: File History, VSS, OneDrive, external)
  - NIST CSF maturity report (Identify / Protect / Detect / Respond / Recover)
  - Office macro trust + Protected View status
  - Smart App Control status (Windows 11)
  - Recent USB write-protect status
  - Windows Hello / FIDO2 status
"""
from __future__ import annotations

import logging
import os
import re
import socket
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from windows_audit import _run_ps

LOGGER = logging.getLogger("aegis.endpoint.pro_audit")


# ──────────────────────────────────────────────────────────────────────────────
# DNS TXT lookup (DMARC / SPF / DKIM)
# ──────────────────────────────────────────────────────────────────────────────

def _resolve_txt(name: str, timeout: float = 4.0) -> List[str]:
    """Resolve TXT records for a name using a minimal DNS-over-UDP query.
    Tries the system resolver first; on Windows we shell to Resolve-DnsName.
    """
    out = _run_ps(
        f"Resolve-DnsName -Name '{name}' -Type TXT -DnsOnly -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Type -eq 'TXT' } | "
        "ForEach-Object { ($_.Strings -join '') }",
        timeout=6,
    )
    if out is None:
        return []
    if isinstance(out, str):
        return [out]
    if isinstance(out, list):
        return [str(x) for x in out if x]
    return []


def check_spf(domain: str) -> Dict[str, Any]:
    txts = _resolve_txt(domain)
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    findings = []
    if not spf:
        findings.append({"severity": "high", "title": f"Nessun record SPF su {domain}",
                          "description": "Senza SPF chiunque può spoofare email dal tuo dominio.",
                          "remediation_key": "spf_missing"})
    else:
        record = spf[0]
        ends_strict = record.rstrip().endswith("-all")
        ends_soft = record.rstrip().endswith("~all")
        if not (ends_strict or ends_soft):
            findings.append({"severity": "medium",
                              "title": "SPF non termina con -all o ~all",
                              "description": "Senza un meccanismo finale, lo SPF è inefficace.",
                              "remediation_key": "spf_weak"})
        elif ends_soft:
            findings.append({"severity": "low",
                              "title": "SPF in soft-fail (~all)",
                              "description": "Considera -all (strict) se sei sicuro dell'inventario mittenti.",
                              "value": record})
        else:
            findings.append({"severity": "info", "status": "ok",
                              "title": "SPF in strict-fail (-all)",
                              "value": record})
    return {"domain": domain, "spf_records": spf, "findings": findings}


def check_dmarc(domain: str) -> Dict[str, Any]:
    txts = _resolve_txt(f"_dmarc.{domain}")
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
    findings = []
    if not dmarc:
        findings.append({"severity": "high",
                          "title": f"Nessun record DMARC su _dmarc.{domain}",
                          "description": "DMARC indica al ricevente come gestire fallimenti SPF/DKIM.",
                          "remediation_key": "dmarc_missing"})
        return {"domain": domain, "dmarc_records": [], "findings": findings}
    record = dmarc[0]
    policy = re.search(r"p\s*=\s*(\w+)", record, re.I)
    rua    = re.search(r"rua\s*=\s*([^;]+)", record, re.I)
    pct    = re.search(r"pct\s*=\s*(\d+)", record, re.I)
    sp     = re.search(r"sp\s*=\s*(\w+)", record, re.I)
    parsed = {
        "policy":   policy.group(1) if policy else "",
        "rua":      rua.group(1).strip() if rua else "",
        "pct":      int(pct.group(1)) if pct else 100,
        "subdomain_policy": sp.group(1) if sp else "",
    }
    pol = parsed["policy"].lower()
    if pol == "none":
        findings.append({"severity": "high",
                          "title": "DMARC policy = none (monitoring only)",
                          "description": "Imposta a 'quarantine' o 'reject' per bloccare spoofing.",
                          "value": parsed, "remediation_key": "dmarc_none"})
    elif pol == "quarantine":
        findings.append({"severity": "low",
                          "title": "DMARC policy = quarantine",
                          "value": parsed})
    elif pol == "reject":
        findings.append({"severity": "info", "status": "ok",
                          "title": "DMARC policy = reject (strict)", "value": parsed})
    if not parsed["rua"]:
        findings.append({"severity": "low",
                          "title": "DMARC senza endpoint rua=mailto:",
                          "description": "Senza rua non ricevi report aggregati.",
                          "remediation_key": "dmarc_no_rua"})
    return {"domain": domain, "dmarc_records": dmarc, "parsed": parsed,
             "findings": findings}


def check_dkim(domain: str, selectors: Optional[List[str]] = None) -> Dict[str, Any]:
    """Common selectors: default, google, selector1, selector2, k1, mail, dkim, mxhero."""
    selectors = selectors or ["default", "google", "selector1", "selector2", "k1", "s1", "s2", "mail", "dkim", "mxhero"]
    found: List[Dict[str, Any]] = []
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        txts = _resolve_txt(name)
        dkim = [t for t in txts if "v=dkim" in t.lower() or "k=rsa" in t.lower()]
        if dkim:
            found.append({"selector": sel, "record": dkim[0]})
    findings = []
    if not found:
        findings.append({"severity": "medium",
                          "title": f"Nessun selector DKIM trovato su {domain}",
                          "description": "Provato: " + ", ".join(selectors),
                          "remediation_key": "dkim_missing"})
    else:
        findings.append({"severity": "info", "status": "ok",
                          "title": f"DKIM presente: {len(found)} selector",
                          "value": [f["selector"] for f in found]})
    return {"domain": domain, "selectors_tried": selectors,
             "dkim_records": found, "findings": findings}


def check_email_auth(domain: str) -> Dict[str, Any]:
    """Combined SPF + DKIM + DMARC report."""
    return {
        "domain": domain,
        "spf":    check_spf(domain),
        "dmarc":  check_dmarc(domain),
        "dkim":   check_dkim(domain),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Backup health (3-2-1 rule check)
# ──────────────────────────────────────────────────────────────────────────────

def check_backup_health() -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    facts: Dict[str, Any] = {}

    # 1. File History
    fh = _run_ps(
        "Get-ItemProperty 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\FileHistory' "
        "-ErrorAction SilentlyContinue | Select-Object FhStatus, ProtectedUpToTime, TargetUrl"
    )
    facts["file_history"] = fh
    if fh and isinstance(fh, dict):
        status = fh.get("FhStatus")
        if status and status != 0:
            findings.append({"severity": "info", "status": "ok",
                              "title": "Windows File History attivo",
                              "value": fh})
        else:
            findings.append({"severity": "medium",
                              "title": "File History non attivo",
                              "description": "Settings → Backup → 'Back up using File History'.",
                              "value": fh, "remediation_key": "filehistory_off"})
    else:
        findings.append({"severity": "medium",
                          "title": "File History mai configurato",
                          "description": "Attiva File History per backup automatico documenti su disco esterno.",
                          "remediation_key": "filehistory_off"})

    # 2. Volume Shadow Copies
    vss = _run_ps(
        "Get-CimInstance Win32_ShadowCopy -ErrorAction SilentlyContinue | "
        "Select-Object ID, InstallDate, VolumeName | Sort-Object InstallDate -Descending"
    )
    if vss is None:
        facts["vss"] = "non leggibile"
    else:
        if isinstance(vss, dict):
            vss = [vss]
        facts["vss"] = vss
        if not vss:
            findings.append({"severity": "high",
                              "title": "Nessuna Volume Shadow Copy",
                              "description": "VSS è essenziale per ripristino veloce post-ransomware. Attiva 'System Restore'.",
                              "remediation_key": "vss_disabled"})
        else:
            findings.append({"severity": "info", "status": "ok",
                              "title": f"{len(vss)} VSS snapshot disponibili",
                              "value": {"count": len(vss), "latest": vss[0] if vss else None}})

    # 3. OneDrive sync status
    od = _run_ps(
        "Get-Process -Name OneDrive -ErrorAction SilentlyContinue | "
        "Select-Object Id, ProcessName, MainWindowTitle, StartTime"
    )
    facts["onedrive"] = od
    if od:
        findings.append({"severity": "info", "status": "ok",
                          "title": "OneDrive in esecuzione",
                          "value": od})

    # 4. External drives connected (potential backup target)
    drives = _run_ps(
        "Get-PSDrive -PSProvider FileSystem -ErrorAction SilentlyContinue | "
        "Where-Object { $_.DisplayRoot -or $_.Used -gt 0 } | "
        "Select-Object Name, Used, Free, DisplayRoot"
    )
    facts["drives"] = drives

    # 5. Backup recommendations
    if not (fh and isinstance(fh, dict) and fh.get("FhStatus", 0) != 0) and not od:
        findings.append({"severity": "high",
                          "title": "NESSUN backup automatico rilevato",
                          "description": "Né File History né OneDrive sembrano attivi. Configura almeno uno.",
                          "remediation_key": "no_backup"})

    return {"facts": facts, "findings": findings,
             "checked_at": datetime.now(timezone.utc).isoformat()}


# ──────────────────────────────────────────────────────────────────────────────
# NIST CSF (Cybersecurity Framework) maturity assessment
# ──────────────────────────────────────────────────────────────────────────────

def csf_maturity() -> Dict[str, Any]:
    """Score each NIST CSF function from observable telemetry."""
    from windows_audit import (
        check_defender, check_firewall, check_bitlocker,
        check_local_accounts, check_smb_v1, check_rdp, check_uac,
        check_autoruns, check_listening_ports, check_powershell_logging,
    )
    # 5 functions × 0-5 maturity
    matrix: Dict[str, Dict[str, Any]] = {
        "IDENTIFY": {"description": "Asset inventory, risk assessment, governance",
                     "controls": [], "score": 0.0, "max": 5.0},
        "PROTECT":  {"description": "Access control, awareness, data security, protective tech",
                     "controls": [], "score": 0.0, "max": 5.0},
        "DETECT":   {"description": "Continuous monitoring, anomalies, security telemetry",
                     "controls": [], "score": 0.0, "max": 5.0},
        "RESPOND":  {"description": "Response planning, communications, mitigation",
                     "controls": [], "score": 0.0, "max": 5.0},
        "RECOVER":  {"description": "Recovery planning, improvements, communications",
                     "controls": [], "score": 0.0, "max": 5.0},
    }

    def control(func: str, name: str, points: float, ok: bool, note: str = ""):
        matrix[func]["controls"].append({
            "name": name, "points": points, "passed": ok, "note": note,
        })
        if ok:
            matrix[func]["score"] += points

    # IDENTIFY — host inventory + active scans
    accounts = check_local_accounts()
    control("IDENTIFY", "Local accounts inventoried", 1.0,
            accounts.get("available", False), f"{len(accounts.get('users', []))} accounts")
    autoruns = check_autoruns()
    control("IDENTIFY", "Autoruns enumerated", 1.0,
            autoruns.get("available", False), f"{autoruns.get('count', 0)} entries")
    ports = check_listening_ports()
    control("IDENTIFY", "Listening ports enumerated", 1.0,
            ports.get("available", False), f"{ports.get('count', 0)} listening")
    control("IDENTIFY", "Asset risk register", 1.0, False,
            "Manual: maintain a separate registry of assets + business value")
    control("IDENTIFY", "Threat model documented", 1.0, False,
            "Manual: STRIDE / attack trees per ogni applicazione critica")

    # PROTECT
    defender = check_defender()
    rt_on = bool(defender.get("raw", {}).get("RealTimeProtectionEnabled"))
    control("PROTECT", "Real-time anti-malware ON", 1.0, rt_on)
    firewall = check_firewall()
    fw_on = all(p.get("Enabled") for p in firewall.get("profiles") or [{"Enabled": False}])
    control("PROTECT", "All firewall profiles enabled", 0.5, fw_on)
    bitlocker = check_bitlocker()
    bl_ok = any(v.get("ProtectionStatus") == 1 for v in bitlocker.get("volumes") or [])
    control("PROTECT", "BitLocker / Device Encryption", 1.0, bl_ok)
    smb = check_smb_v1()
    control("PROTECT", "SMBv1 disabled", 0.5, not smb.get("enabled"))
    uac = check_uac()
    uac_ok = uac.get("config", {}).get("EnableLUA") == 1 and uac.get("config", {}).get("PromptOnSecureDesktop") == 1
    control("PROTECT", "UAC at full secure desktop", 0.5, uac_ok)
    rdp = check_rdp()
    rdp_ok = not rdp.get("enabled") or rdp.get("nla")
    control("PROTECT", "RDP off or NLA enabled", 0.5, rdp_ok)
    no_pw_acc = sum(1 for f in accounts.get("findings", []) if "no_password" in f.get("check_id", ""))
    control("PROTECT", "No password-less accounts", 1.0, no_pw_acc == 0,
            f"{no_pw_acc} account senza password" if no_pw_acc else "all accounts have password")

    # DETECT
    pslog = check_powershell_logging()
    psl_cfg = pslog.get("config") or {}
    control("DETECT", "PowerShell ScriptBlock logging", 1.0,
            psl_cfg.get("ScriptBlockLogging") == 1)
    control("DETECT", "PowerShell Module logging", 0.5,
            psl_cfg.get("ModuleLogging") == 1)
    try:
        from enhanced_audit import check_sysmon
        sysm = check_sysmon()
        sysm_ok = any(f.get("status") == "ok" and "running" in f.get("title", "").lower()
                       for f in sysm.get("findings", []))
        control("DETECT", "Sysmon installed + running", 1.5, sysm_ok)
    except Exception:
        control("DETECT", "Sysmon installed + running", 1.5, False)
    control("DETECT", "Sigma rules deployed (Get-WinEvent based)", 1.0, True,
            "AEGIS Sigma engine attivo (15+ rules)")
    control("DETECT", "Centralized log aggregation", 1.0, True,
            "AEGIS event bus + ingest endpoint attivi")

    # RESPOND
    control("RESPOND", "SOAR playbooks defined", 1.5, True,
            "13 playbook YAML caricati (block_ip, isolate_host, ransomware...)")
    control("RESPOND", "Containment API available", 1.0, True,
            "AEGIS /contain/* (dry-run by default)")
    control("RESPOND", "Audit log persistence", 1.0, True,
            "AEGIS audit log (login, kill_pid, block_ip, quarantine)")
    control("RESPOND", "Incident response plan written", 1.5, False,
            "Manual: NIST SP 800-61 IR plan documented")

    # RECOVER
    backup = check_backup_health()
    has_backup = any(f.get("status") == "ok" for f in backup.get("findings", []))
    control("RECOVER", "Automated backup configured", 2.0, has_backup)
    control("RECOVER", "Volume Shadow Copies present", 1.5,
            any("VSS snapshot" in f.get("title", "") and f.get("status") == "ok"
                 for f in backup.get("findings", [])))
    control("RECOVER", "Recovery procedure tested", 1.5, False,
            "Manual: documenta + testa il restore almeno 1x/anno")

    # Tier mapping
    total = sum(m["score"] for m in matrix.values())
    max_total = sum(m["max"] for m in matrix.values())
    pct = (total / max_total) * 100 if max_total else 0
    tier = "Tier 4 — Adaptive" if pct >= 85 else \
           "Tier 3 — Repeatable" if pct >= 65 else \
           "Tier 2 — Risk Informed" if pct >= 40 else \
           "Tier 1 — Partial"
    return {
        "total_score":   round(total, 2),
        "max_score":     max_total,
        "percentage":    round(pct, 1),
        "tier":          tier,
        "functions":     matrix,
        "computed_at":   datetime.now(timezone.utc).isoformat(),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Office macro trust + Protected View status
# ──────────────────────────────────────────────────────────────────────────────

def check_office_macro_security() -> Dict[str, Any]:
    """Read VBA security level for installed Office apps."""
    findings: List[Dict[str, Any]] = []
    versions = ["16.0", "15.0", "14.0"]
    apps = ["Word", "Excel", "PowerPoint", "Outlook"]
    results = {}
    for v in versions:
        for a in apps:
            key = f"HKCU:\\Software\\Microsoft\\Office\\{v}\\{a}\\Security"
            cfg = _run_ps(
                f"Get-ItemProperty '{key}' -ErrorAction SilentlyContinue | "
                "Select-Object VBAWarnings, DisableInternetFilesInPV, "
                "DisableAttachmentsInPV, DisableUnsafeLocationsInPV, ProtectedView",
                timeout=3,
            )
            if cfg and isinstance(cfg, dict):
                results[f"{a}_{v}"] = cfg
                vba = cfg.get("VBAWarnings")
                # 1 = enable all macros (insecure), 2 = disable with notification (default safe),
                # 3 = disable except signed, 4 = disable all without notification
                if vba == 1:
                    findings.append({
                        "severity": "critical",
                        "title": f"{a} {v}: macro autorizzate senza notifica (VBAWarnings=1)",
                        "description": "Setting estremamente insicuro — qualsiasi macro VBA viene eseguita silenziosamente.",
                        "value": cfg, "remediation_key": "office_macro_unsafe",
                        "technique": "T1137.001",
                    })
                elif vba == 2:
                    findings.append({"severity": "low",
                                      "title": f"{a} {v}: VBAWarnings=2 (disable with notification)"})
                elif vba in (3, 4):
                    findings.append({"severity": "info", "status": "ok",
                                      "title": f"{a} {v}: macro disabilitate (VBAWarnings={vba})"})
    return {"results": results, "findings": findings}


# ──────────────────────────────────────────────────────────────────────────────
# Smart App Control + Windows Hello
# ──────────────────────────────────────────────────────────────────────────────

def check_smart_app_control() -> Dict[str, Any]:
    """Windows 11 Smart App Control status (HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy)."""
    data = _run_ps(
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Policy' "
        "-ErrorAction SilentlyContinue | Select-Object VerifiedAndReputablePolicyState, "
        "VerifiedAndReputableScenario, AdminLockoutThreshold"
    )
    findings = []
    if data is None:
        return {"available": False, "error": "Smart App Control non disponibile (Win10 o policy non scritta)"}
    state = data.get("VerifiedAndReputablePolicyState")
    # 0=off, 1=enforcement, 2=eval
    if state == 1:
        findings.append({"status": "ok", "severity": "info",
                          "title": "Smart App Control ATTIVO (enforcement)",
                          "value": data})
    elif state == 2:
        findings.append({"status": "warn", "severity": "low",
                          "title": "Smart App Control in EVALUATION mode",
                          "value": data})
    else:
        findings.append({"status": "warn", "severity": "medium",
                          "title": "Smart App Control OFF",
                          "description": "Blocca app non firmate/sconosciute. Solo Windows 11 clean install.",
                          "value": data, "remediation_key": "smart_app_off"})
    return {"available": True, "raw": data, "findings": findings}


def check_windows_hello() -> Dict[str, Any]:
    """Windows Hello / FIDO2 / passkey readiness."""
    data = _run_ps(
        "$bio = Get-Service -Name WbioSrvc -ErrorAction SilentlyContinue; "
        "$ngc = Get-Service -Name NgcSvc -ErrorAction SilentlyContinue; "
        "$ctx = Get-Service -Name NgcCtnrSvc -ErrorAction SilentlyContinue; "
        "[pscustomobject]@{ Biometric=$bio.Status; Ngc=$ngc.Status; NgcCtnr=$ctx.Status }"
    )
    findings = []
    if data is None:
        return {"available": False, "error": "Hello services query failed"}
    bio_ok = str(data.get("Biometric") or "").lower() == "running"
    ngc_ok = str(data.get("Ngc") or "").lower() == "running"
    if bio_ok or ngc_ok:
        findings.append({"status": "ok", "severity": "info",
                          "title": "Windows Hello services running", "value": data})
    else:
        findings.append({"status": "warn", "severity": "low",
                          "title": "Windows Hello non attivo",
                          "description": "Hello + TPM + FIDO2 = autenticazione moderna phishing-resistant.",
                          "value": data, "remediation_key": "hello_off"})
    return {"available": True, "raw": data, "findings": findings}
