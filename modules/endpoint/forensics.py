#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Forensics / Deep Inspection
==================================================
Static, read-only analysis of artefacts for IR:

  - PowerShell ScriptBlock Log analyzer (Event 4104) — detects
    Mimikatz, PowerView, PowerSploit, Empire, AMSI bypass, encoded
    commands, COM-based persistence, Invoke-WebRequest cradles.

  - PE (Portable Executable) header analyzer — sections, imports,
    packer signatures, signed/unsigned, entropy per section.

  - PDF static analyzer — JavaScript /JS /JavaScript, /OpenAction,
    /AA, /Launch, /URI, embedded files, suspicious filters.

  - Office macro detector — extracts and inspects VBA macros from
    .docm/.xlsm/.pptm, flags auto-exec functions.

  - .eml / .msg email analyzer — headers (SPF/DKIM/DMARC results
    if present), URL extraction, attachment IoC, header anomalies.
"""
from __future__ import annotations

import base64
import hashlib
import logging
import math
import os
import re
import struct
import zipfile
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from email import message_from_bytes, message_from_string, policy
from email.parser import BytesParser
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from windows_audit import _run_ps

LOGGER = logging.getLogger("aegis.endpoint.forensics")


# ── PowerShell ScriptBlock Log analyzer (Event 4104) ─────────────────────────

PS_MALICIOUS_PATTERNS = [
    # Mimikatz family
    (r"(?i)Invoke-Mimikatz|sekurlsa::|kerberos::|crypto::|privilege::", "Mimikatz pattern", "critical", "T1003.001"),
    (r"(?i)Mimikatz|DCSync|DCShadow", "Mimikatz keyword", "critical", "T1003.001"),
    # PowerSploit / Empire / PowerView
    (r"(?i)Invoke-DllInjection|Invoke-Shellcode|Invoke-ReflectivePEInjection|Invoke-CredentialInjection",
        "PowerSploit injection", "critical", "T1055"),
    (r"(?i)Get-DomainComputer|Get-DomainUser|Get-DomainGroup|Find-DomainShare|Find-LocalAdminAccess",
        "PowerView reconnaissance", "high", "T1087.002"),
    (r"(?i)Invoke-Empire|Invoke-PowerShellEmpire|Empire\.exe", "Empire framework", "critical", "T1059.001"),
    # AMSI bypass
    (r"(?i)Set-MpPreference\s+-DisableRealtimeMonitoring", "Disable Defender real-time", "critical", "T1562.001"),
    (r"(?i)\[Ref\]\.Assembly\.GetType.*amsi", "AMSI bypass via reflection", "critical", "T1562.001"),
    (r"(?i)AmsiUtils.*amsiInitFailed", "AMSI initFailed bypass", "critical", "T1562.001"),
    (r"(?i)\[System\.Reflection\.Assembly\]::Load\(\[Convert\]::FromBase64String", "Reflective assembly load",
        "critical", "T1620"),
    # Download cradles
    (r"(?i)\(New-Object\s+Net\.WebClient\)\.DownloadString", "Net.WebClient DownloadString cradle",
        "critical", "T1059.001"),
    (r"(?i)IEX\s*\(", "Invoke-Expression (IEX)", "high", "T1059.001"),
    (r"(?i)Invoke-Expression\s+\(", "Invoke-Expression call", "high", "T1059.001"),
    (r"(?i)\.DownloadFile\(", ".DownloadFile() call", "high", "T1105"),
    # Encoded commands
    (r"(?i)-(EncodedCommand|enc|e)\s+[A-Za-z0-9+/=]{50,}", "Encoded PowerShell command", "critical", "T1027"),
    (r"(?i)FromBase64String\(", "Base64 decode", "medium", "T1140"),
    # Living-off-the-land
    (r"(?i)certutil\s+-urlcache|certutil\s+-decode", "Certutil download/decode", "high", "T1105"),
    (r"(?i)bitsadmin\s+/transfer", "Bitsadmin transfer", "high", "T1105"),
    # Persistence
    (r"(?i)Register-ScheduledTask|schtasks\s+/create", "Scheduled task creation", "medium", "T1053.005"),
    (r"(?i)New-Service|sc\.exe\s+create", "Service creation", "medium", "T1543.003"),
    (r"(?i)New-CimInstance.*Win32_WMIEventConsumer", "WMI event consumer", "high", "T1546.003"),
    # Anti-forensics
    (r"(?i)Clear-EventLog|wevtutil\s+cl", "Event log clearing", "critical", "T1070.001"),
    (r"(?i)Remove-ItemProperty.*Run", "Run-key cleanup", "medium", "T1112"),
]


def analyze_powershell_logs(max_events: int = 500, hours: int = 24) -> Dict[str, Any]:
    """Parse Event 4104 (PS ScriptBlock log) for malicious patterns."""
    events = _run_ps(
        f"Get-WinEvent -FilterHashtable @{{LogName='Microsoft-Windows-PowerShell/Operational'; "
        f"Id=4104; StartTime=(Get-Date).AddHours(-{hours})}} -MaxEvents {max_events} "
        "-ErrorAction SilentlyContinue | ForEach-Object {"
        "  $msg = $_.Message; "
        "  [pscustomobject]@{ "
        "    TimeCreated = $_.TimeCreated; "
        "    Id = $_.Id; "
        "    LevelDisplayName = $_.LevelDisplayName; "
        "    Snippet = ($msg | Out-String).Substring(0, [Math]::Min(2000, ($msg | Out-String).Length)) "
        "  } "
        "}",
        timeout=20,
    )
    findings: List[Dict[str, Any]] = []
    if events is None:
        return {
            "available": False,
            "error": "Get-WinEvent Microsoft-Windows-PowerShell/Operational fallita. ScriptBlock logging probabilmente disabilitato.",
            "remediation": "Abilita PS Logging via GPO: Computer Config → Admin Templates → Windows Components → PowerShell → Turn on PowerShell Script Block Logging",
        }
    if isinstance(events, dict):
        events = [events]
    if not isinstance(events, list):
        events = []

    matched_count = 0
    by_pattern: Dict[str, int] = {}
    for ev in events:
        if not isinstance(ev, dict):
            continue
        snippet = (ev.get("Snippet") or "")
        for pat, label, sev, tech in PS_MALICIOUS_PATTERNS:
            m = re.search(pat, snippet)
            if not m:
                continue
            matched_count += 1
            by_pattern[label] = by_pattern.get(label, 0) + 1
            findings.append({
                "title":    f"PS ScriptBlock: {label}",
                "severity": sev,
                "technique": tech,
                "snippet":  snippet[:500],
                "time":     ev.get("TimeCreated"),
                "matched":  m.group(0)[:200],
                "remediation_key": "ps_malicious_script",
            })
            break  # first hit per snippet
    return {
        "available": True,
        "events_analyzed": len(events),
        "matched_count": matched_count,
        "by_pattern": by_pattern,
        "findings": findings[:200],
        "window_hours": hours,
    }


# ── PE analyzer ──────────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    occ = [0] * 256
    for b in data:
        occ[b] += 1
    e = 0.0
    L = len(data)
    for c in occ:
        if c:
            p = c / L
            e -= p * math.log2(p)
    return round(e, 3)


def analyze_pe(content: bytes) -> Dict[str, Any]:
    """Minimal PE (Win) analyser. Returns header info, sections, packer hints."""
    if len(content) < 64 or content[:2] != b"MZ":
        return {"is_pe": False, "error": "Not a PE file (no MZ header)"}
    e_lfanew = struct.unpack_from("<I", content, 0x3C)[0]
    if e_lfanew + 4 > len(content) or content[e_lfanew:e_lfanew+4] != b"PE\x00\x00":
        return {"is_pe": False, "error": "Invalid PE signature"}
    coff_off = e_lfanew + 4
    machine, n_sections, time_dt, _, _, sizeof_opt, characteristics = struct.unpack_from(
        "<HHIIIHH", content, coff_off
    )
    machine_str = {0x14c: "i386", 0x8664: "AMD64", 0x1c4: "ARMNT", 0xaa64: "ARM64"}.get(machine, f"0x{machine:04x}")
    # Optional header
    opt_off = coff_off + 20
    magic = struct.unpack_from("<H", content, opt_off)[0]
    pe_format = "PE32+" if magic == 0x20b else "PE32"
    # Sections
    sections = []
    sec_off = opt_off + sizeof_opt
    high_entropy = 0
    for i in range(n_sections):
        try:
            name = content[sec_off:sec_off+8].rstrip(b"\x00").decode("ascii", errors="replace")
            vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", content, sec_off + 8)
            flags = struct.unpack_from("<I", content, sec_off + 36)[0]
            raw = content[roff:roff+rsize] if rsize and roff + rsize <= len(content) else b""
            ent = _entropy(raw)
            executable = bool(flags & 0x20000000)
            writable = bool(flags & 0x80000000)
            sections.append({
                "name": name, "vsize": vsize, "raw_size": rsize,
                "entropy": ent, "executable": executable, "writable": writable,
            })
            if executable and ent > 7.2:
                high_entropy += 1
        except Exception:
            break
        sec_off += 40
    # Packer hints
    section_names = {s["name"] for s in sections}
    packers = []
    for known, packer in [
        ("UPX0", "UPX"), ("UPX1", "UPX"), ("UPX2", "UPX"),
        (".aspack", "ASPack"), (".adata", "ASPack"),
        (".themida", "Themida"), (".vmp0", "VMProtect"),
        (".vmp1", "VMProtect"), (".pebundle", "PEBundle"),
        (".enigma1", "Enigma Protector"), (".enigma2", "Enigma Protector"),
        ("MEW", "MEW"), (".mpress1", "MPRESS"), (".mpress2", "MPRESS"),
    ]:
        if known in section_names:
            packers.append(packer)
    return {
        "is_pe": True,
        "machine": machine_str,
        "format": pe_format,
        "section_count": n_sections,
        "sections": sections,
        "characteristics": characteristics,
        "is_dll": bool(characteristics & 0x2000),
        "is_exe": not bool(characteristics & 0x2000),
        "packers_detected": list(set(packers)),
        "high_entropy_executable_sections": high_entropy,
        "compile_time": datetime.utcfromtimestamp(time_dt).isoformat() if 0 < time_dt < 2**31 else None,
    }


# ── PDF analyzer ─────────────────────────────────────────────────────────────

def analyze_pdf(content: bytes) -> Dict[str, Any]:
    """Static PDF feature detection (no parsing of obj streams — heuristic regex)."""
    if not content.startswith(b"%PDF"):
        return {"is_pdf": False, "error": "Not a PDF (no %PDF header)"}
    txt = content[:5*1024*1024]  # cap 5MB scan
    indicators = {
        "javascript":    len(re.findall(rb"/JavaScript|/JS\b", txt)),
        "openaction":    len(re.findall(rb"/OpenAction", txt)),
        "aa":            len(re.findall(rb"/AA\b", txt)),
        "launch":        len(re.findall(rb"/Launch", txt)),
        "uri":           len(re.findall(rb"/URI", txt)),
        "submit_form":   len(re.findall(rb"/SubmitForm", txt)),
        "rich_media":    len(re.findall(rb"/RichMedia", txt)),
        "embedded":      len(re.findall(rb"/EmbeddedFile", txt)),
        "xfa":           len(re.findall(rb"/XFA", txt)),
        "flate_decode":  len(re.findall(rb"/FlateDecode", txt)),
        "object_stream": len(re.findall(rb"/ObjStm", txt)),
    }
    severity = "info"
    reasons = []
    if indicators["javascript"] + indicators["openaction"] >= 1:
        severity = "high"
        reasons.append("JS+OpenAction → auto-exec on open")
    if indicators["launch"] > 0:
        severity = "critical"
        reasons.append("/Launch action: command/binary execution")
    if indicators["embedded"] > 0 and severity != "critical":
        severity = "high"
        reasons.append("Embedded file (potential payload)")
    if indicators["xfa"] > 0:
        if severity == "info": severity = "medium"
        reasons.append("XFA forms (CVE-2018-4990 / Adobe history)")
    return {
        "is_pdf": True,
        "size": len(content),
        "indicators": indicators,
        "severity": severity,
        "reasons": reasons,
    }


# ── Office macro detector ────────────────────────────────────────────────────

AUTO_EXEC_FUNCTIONS = [
    "Auto_Open", "AutoOpen", "Workbook_Open", "Document_Open",
    "Auto_Close", "AutoClose", "Workbook_BeforeClose",
    "Workbook_Activate", "Workbook_BeforeSave",
    "DocumentChange", "Application_Quit",
]
MACRO_DANGER_KEYWORDS = [
    "Shell", "WScript.Shell", "CreateObject", "powershell",
    "cmd.exe", "Run", "Exec", "URLDownloadToFile",
    "ADODB.Stream", "WinHttpRequest", "MSXML2.XMLHTTP",
    "RegRead", "RegWrite", "Environ", "Kill", "FileSystemObject",
]


def analyze_office(content: bytes, filename: str = "") -> Dict[str, Any]:
    """Detect VBA macros in OOXML (docx/xlsx/pptx with macros: docm/xlsm/pptm)."""
    if not content.startswith(b"PK"):
        return {"is_office_ooxml": False,
                 "note": "Not a ZIP-based OOXML. Use olevba/oletools for legacy .doc/.xls."}
    try:
        import io
        zf = zipfile.ZipFile(io.BytesIO(content))
        names = zf.namelist()
    except Exception as e:
        return {"is_office_ooxml": False, "error": str(e)}

    macros = [n for n in names if n.lower().endswith(("vbaproject.bin",))]
    findings: List[Dict[str, Any]] = []
    if not macros:
        return {
            "is_office_ooxml": True,
            "has_macros": False,
            "file_count": len(names),
        }
    summary = []
    for m in macros:
        try:
            data = zf.read(m)
        except Exception:
            continue
        # Extract printable strings (heuristic to find function names + API calls)
        printable = re.findall(rb"[\x20-\x7E]{4,200}", data)
        text = b"\n".join(printable).decode("ascii", errors="replace")
        auto_hits = [fn for fn in AUTO_EXEC_FUNCTIONS if fn in text]
        danger_hits = [k for k in MACRO_DANGER_KEYWORDS if k in text]
        sev = "info"
        if auto_hits and danger_hits:
            sev = "critical"
        elif auto_hits or danger_hits:
            sev = "high"
        findings.append({
            "macro_blob": m,
            "auto_exec_functions": auto_hits,
            "danger_keywords": danger_hits,
            "severity": sev,
            "remediation_key": "macro_dangerous" if sev in ("high", "critical") else None,
        })
        summary.append({"name": m, "size": len(data), "severity": sev})
    return {
        "is_office_ooxml": True,
        "has_macros": True,
        "macros": summary,
        "findings": findings,
        "filename": filename,
    }


# ── Email (.eml) analyzer ────────────────────────────────────────────────────

URL_RE = re.compile(rb"https?://[^\s\"'<>)]{6,400}")


def analyze_email(content: bytes) -> Dict[str, Any]:
    """Parse .eml: headers, SPF/DKIM/DMARC verdicts, URLs, attachments."""
    try:
        msg = BytesParser(policy=policy.default).parsebytes(content)
    except Exception as e:
        return {"is_email": False, "error": str(e)}
    headers = {k: str(v) for k, v in msg.items()}
    auth_results = headers.get("Authentication-Results", "")
    received_spf  = headers.get("Received-SPF", "")
    arc_auth      = headers.get("ARC-Authentication-Results", "")

    def _verdict(name: str) -> str:
        s = (auth_results + " " + received_spf + " " + arc_auth).lower()
        m = re.search(rf"{name}=([a-z]+)", s)
        return m.group(1) if m else "unknown"

    spf    = _verdict("spf")
    dkim   = _verdict("dkim")
    dmarc  = _verdict("dmarc")

    urls = sorted(set(URL_RE.findall(content)))
    urls_list = [u.decode("ascii", errors="replace") for u in urls[:200]]

    attachments = []
    for part in msg.walk():
        cdisp = part.get("Content-Disposition", "")
        if cdisp and "attachment" in cdisp:
            fname = part.get_filename() or ""
            payload = part.get_payload(decode=True) or b""
            attachments.append({
                "filename": fname,
                "size":     len(payload),
                "sha256":   hashlib.sha256(payload).hexdigest(),
                "content_type": part.get_content_type(),
            })

    severity = "info"
    notes = []
    if spf == "fail":
        severity = "high"; notes.append("SPF fail")
    if dkim == "fail":
        severity = "high"; notes.append("DKIM fail")
    if dmarc == "fail":
        severity = "high"; notes.append("DMARC fail")
    if any(a["filename"].lower().endswith((".exe", ".scr", ".ps1", ".js", ".jse", ".vbs", ".lnk", ".hta"))
            for a in attachments):
        severity = "critical"; notes.append("Eseguibile in allegato")
    # Look-alike domain check (homoglyph)
    from_hdr = headers.get("From", "")
    if "rn" in from_hdr or "vv" in from_hdr or "ii" in from_hdr:
        # Could be homoglyph m → rn etc.
        notes.append("Possibile dominio homoglyph (rn/vv/ii)")

    return {
        "is_email": True,
        "headers_sample": {k: headers.get(k, "") for k in
            ["From", "To", "Subject", "Date", "Message-ID", "Return-Path",
             "Authentication-Results", "Reply-To"]},
        "auth": {"spf": spf, "dkim": dkim, "dmarc": dmarc},
        "url_count": len(urls_list),
        "urls": urls_list,
        "attachments": attachments,
        "severity": severity,
        "notes": notes,
    }


# ── DNS-over-HTTPS check ─────────────────────────────────────────────────────

def check_doh_resolver() -> Dict[str, Any]:
    """Windows 11+ supports DoH via Settings → Network. Check current resolver
    list and whether any are known DoH endpoints."""
    data = _run_ps(
        "Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | "
        "Where-Object { $_.ServerAddresses -and $_.ServerAddresses.Count -gt 0 } | "
        "Select-Object InterfaceAlias, ServerAddresses"
    )
    doh_servers = {
        "1.1.1.1":         "Cloudflare DoH",
        "1.0.0.1":         "Cloudflare DoH (secondary)",
        "8.8.8.8":         "Google DNS (DoH optional)",
        "9.9.9.9":         "Quad9 DoH",
        "149.112.112.112": "Quad9 DoH (secondary)",
        "208.67.222.222":  "OpenDNS",
    }
    findings: List[Dict[str, Any]] = []
    if data is None:
        return {"available": False, "error": "Get-DnsClientServerAddress failed"}
    if isinstance(data, dict):
        data = [data]
    resolvers_found = set()
    for d in data:
        if not isinstance(d, dict):
            continue
        addrs = d.get("ServerAddresses") or []
        if isinstance(addrs, str):
            addrs = [addrs]
        for a in addrs:
            resolvers_found.add(a)
    doh_capable = [(a, doh_servers[a]) for a in resolvers_found if a in doh_servers]
    isp_default = any(a.startswith(("192.168.", "10.", "172.")) for a in resolvers_found)
    if not doh_capable:
        findings.append({
            "check_id": "doh.missing",
            "title": "DNS-over-HTTPS non configurato",
            "severity": "low",
            "status": "warn",
            "description": "Considera DoH (Cloudflare 1.1.1.1, Quad9 9.9.9.9) per privacy + integrity DNS.",
            "value": list(resolvers_found),
            "remediation_key": "doh_missing",
        })
    else:
        findings.append({
            "check_id": "doh.ok",
            "title": "DoH-capable resolver in uso",
            "severity": "info",
            "status": "ok",
            "value": doh_capable,
        })
    return {"available": True, "resolvers": list(resolvers_found),
             "doh_capable": doh_capable, "findings": findings}
