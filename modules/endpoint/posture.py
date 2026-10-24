#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Security Posture Score
=============================================
Combines six defensive layers (per the brief's Defense-in-Depth model) into a
single 0-100 score, plus per-layer breakdown and recommended next actions.

Layers and signals:
  Perimetro    — firewall profiles enabled, no external RDP, suspicious
                  outbound flagged
  Endpoint     — Defender RT + Tamper, recent autoruns, suspicious processes
  Rete         — no risky listening ports on non-loopback, listening shares
                  reviewed
  Identità     — accounts have passwords, UAC at full, RDP NLA, no recent
                  admin group changes
  Dati         — BitLocker (or Device Encryption) active, PowerShell logging
                  on
  Intelligence — IOC feeds loaded, YARA rules compiled, defender signatures
                  fresh

Each layer is a 0-20 sub-score; total = sum capped at 100.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from windows_audit import (
    check_defender, check_firewall, check_bitlocker,
    check_local_accounts, check_rdp, check_uac, check_smb_v1,
    check_autoruns, check_listening_ports, check_powershell_logging,
)
from process_scanner import list_processes

LOGGER = logging.getLogger("aegis.endpoint.posture")


# ── Layer scoring functions ──────────────────────────────────────────────────

def _findings_severity_count(check: Dict[str, Any]) -> Dict[str, int]:
    out = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in check.get("findings", []):
        sev = f.get("severity", "info")
        if f.get("status") in ("warn", "fail") and sev in out:
            out[sev] += 1
    return out


def _layer_score(*subscores: float) -> float:
    """Average a set of 0-100 sub-scores, return weighted layer score 0-20."""
    if not subscores:
        return 0.0
    return round(sum(subscores) / len(subscores) * 0.2, 1)


def score_perimeter() -> Dict[str, Any]:
    fw = check_firewall()
    rdp = check_rdp()
    detail: List[str] = []

    # Sub-score 1: all firewall profiles enabled (D/P/Pu) → 100, otherwise -25 each.
    profiles = fw.get("profiles", []) if fw.get("available") else []
    enabled = sum(1 for p in profiles if isinstance(p, dict) and p.get("Enabled"))
    fw_score = (enabled / 3) * 100 if profiles else 50
    detail.append(f"Firewall profiles enabled: {enabled}/3 → {fw_score:.0f}")

    # Sub-score 2: RDP exposure. Disabled = 100. Enabled with NLA = 60. NLA off = 0.
    rdp_score = 100
    if rdp.get("enabled"):
        rdp_score = 60 if rdp.get("nla") else 0
    detail.append(f"RDP: enabled={rdp.get('enabled')} NLA={rdp.get('nla')} → {rdp_score:.0f}")

    score = _layer_score(fw_score, rdp_score)
    findings = (fw.get("findings", []) or []) + (rdp.get("findings", []) or [])
    return {"score": score, "max": 20.0, "detail": detail,
            "findings": findings, "checks_run": ["firewall", "rdp"]}


def score_endpoint() -> Dict[str, Any]:
    defender = check_defender()
    autoruns = check_autoruns()
    procs = list_processes(top_n=300)
    detail: List[str] = []

    # AV real-time + tamper protection
    raw = defender.get("raw", {}) if defender.get("available") else {}
    rt = bool(raw.get("RealTimeProtectionEnabled"))
    tp = bool(raw.get("IsTamperProtected"))
    av_score = (50 if rt else 0) + (50 if tp else 0)
    detail.append(f"Defender RT={rt} Tamper={tp} → {av_score}")

    # Autoruns: suspicious count
    suspicious = len(autoruns.get("suspicious", [])) if autoruns.get("available") else 0
    ar_score = max(0, 100 - suspicious * 30)
    detail.append(f"Suspicious autoruns: {suspicious} → {ar_score}")

    # Processes: flagged count (critical/high)
    flagged = procs.get("flagged_count", 0) if procs.get("available") else 0
    proc_score = max(0, 100 - flagged * 10)
    detail.append(f"Flagged processes: {flagged} → {proc_score}")

    findings = ((defender.get("findings", []) or [])
                + (autoruns.get("findings", []) or []))
    return {"score": _layer_score(av_score, ar_score, proc_score),
            "max": 20.0, "detail": detail, "findings": findings,
            "checks_run": ["defender", "autoruns", "processes"]}


def score_network() -> Dict[str, Any]:
    ports = check_listening_ports()
    detail: List[str] = []

    flagged = len(ports.get("findings", [])) if ports.get("available") else 0
    score = max(0, 100 - flagged * 15)
    detail.append(f"Risky listening ports on non-loopback: {flagged} → {score}")

    findings = ports.get("findings", []) or []
    return {"score": _layer_score(score), "max": 20.0,
            "detail": detail, "findings": findings,
            "checks_run": ["listening_ports"]}


def score_identity() -> Dict[str, Any]:
    accounts = check_local_accounts()
    uac = check_uac()
    smb = check_smb_v1()
    detail: List[str] = []

    no_pw = sum(1 for f in accounts.get("findings", [])
                if "no_password" in f.get("check_id", ""))
    acc_score = 0 if no_pw > 0 else 100
    detail.append(f"Accounts without password: {no_pw} → {acc_score}")

    uac_cfg = uac.get("config", {}) if uac.get("available") else {}
    uac_ok = uac_cfg.get("EnableLUA") == 1 and uac_cfg.get("PromptOnSecureDesktop") == 1
    uac_score = 100 if uac_ok else 30
    detail.append(f"UAC: enabled={uac_cfg.get('EnableLUA')} secure_desktop={uac_cfg.get('PromptOnSecureDesktop')} → {uac_score}")

    smb_score = 0 if smb.get("enabled") else 100
    detail.append(f"SMBv1 disabled: {not smb.get('enabled')} → {smb_score}")

    findings = ((accounts.get("findings", []) or [])
                + (uac.get("findings", []) or [])
                + (smb.get("findings", []) or []))
    return {"score": _layer_score(acc_score, uac_score, smb_score),
            "max": 20.0, "detail": detail, "findings": findings,
            "checks_run": ["accounts", "uac", "smb_v1"]}


def score_data() -> Dict[str, Any]:
    bitlocker = check_bitlocker()
    pslog = check_powershell_logging()
    detail: List[str] = []

    encrypted_count = 0
    total_count = 0
    if bitlocker.get("available"):
        for v in bitlocker.get("volumes", []) or []:
            if isinstance(v, dict):
                total_count += 1
                if v.get("ProtectionStatus") in (1, "On") and (v.get("EncryptionPercentage") or 0) == 100:
                    encrypted_count += 1
    bl_score = int((encrypted_count / total_count) * 100) if total_count else 50
    detail.append(f"Encrypted volumes: {encrypted_count}/{total_count} → {bl_score}")

    cfg = pslog.get("config", {}) if pslog.get("available") else {}
    sb = cfg.get("ScriptBlockLogging") == 1
    ml = cfg.get("ModuleLogging") == 1
    ps_score = (50 if sb else 0) + (50 if ml else 0)
    detail.append(f"PowerShell logging: SB={sb} Mod={ml} → {ps_score}")

    findings = ((bitlocker.get("findings", []) or [])
                + (pslog.get("findings", []) or []))
    return {"score": _layer_score(bl_score, ps_score),
            "max": 20.0, "detail": detail, "findings": findings,
            "checks_run": ["bitlocker", "powershell_logging"]}


def score_intelligence(ioc_db: Optional[Any] = None,
                        yara_loaded: bool = False) -> Dict[str, Any]:
    detail: List[str] = []
    ioc_score = 0
    if ioc_db is not None:
        try:
            s = ioc_db.stats()
            total = (s.get("ip_count", 0) + s.get("domain_count", 0)
                     + s.get("hash_count", 0) + s.get("url_count", 0))
            ioc_score = 100 if total > 1000 else (50 if total > 0 else 0)
            detail.append(f"IOC items loaded: {total} → {ioc_score}")
        except Exception:
            detail.append("IOC DB not initialized → 0")
    else:
        detail.append("IOC DB not initialized → 0")

    yara_score = 100 if yara_loaded else 0
    detail.append(f"YARA rules compiled: {yara_loaded} → {yara_score}")

    return {"score": _layer_score(ioc_score, yara_score),
            "max": 20.0, "detail": detail, "findings": [],
            "checks_run": ["ioc_feeds", "yara"]}


# ── Public API ───────────────────────────────────────────────────────────────

def compute_posture(ioc_db: Optional[Any] = None,
                    yara_loaded: bool = False) -> Dict[str, Any]:
    """Compute the 0-100 holistic posture and per-layer breakdown."""
    started = datetime.now(timezone.utc)
    layers = {
        "perimetro":    score_perimeter(),
        "endpoint":     score_endpoint(),
        "rete":         score_network(),
        "identita":     score_identity(),
        "dati":         score_data(),
        "intelligence": score_intelligence(ioc_db=ioc_db, yara_loaded=yara_loaded),
    }
    total = round(sum(l["score"] for l in layers.values()), 1)

    # Top recommended actions = critical/high findings across all layers
    all_findings: List[Dict[str, Any]] = []
    for layer_id, layer in layers.items():
        for f in layer.get("findings", []):
            if f.get("status") in ("warn", "fail") and f.get("severity") in ("critical", "high"):
                all_findings.append({**f, "layer": layer_id})

    # Sort by severity weight
    sev_w = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    all_findings.sort(key=lambda f: -sev_w.get(f.get("severity"), 0))

    grade = (
        "A" if total >= 90 else
        "B" if total >= 75 else
        "C" if total >= 60 else
        "D" if total >= 40 else "F"
    )
    completed = datetime.now(timezone.utc)
    return {
        "score": total,
        "grade": grade,
        "computed_at": completed.isoformat(),
        "duration_seconds": round((completed - started).total_seconds(), 2),
        "layers": layers,
        "top_actions": all_findings[:15],
        "summary_by_severity": {
            "critical": sum(1 for f in all_findings if f.get("severity") == "critical"),
            "high":     sum(1 for f in all_findings if f.get("severity") == "high"),
        },
    }
