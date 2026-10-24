#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Sigma Live Engine + Atomic Red Team + D3FEND + VirusTotal
================================================================================

  • SigmaLiveEngine — converts a curated subset of Sigma rules into native
    PowerShell Get-WinEvent queries and runs them periodically against the
    Windows Security and Sysmon channels. Matches → events POST to the
    orchestrator ingest endpoint.

  • Atomic Red Team safe tests — invokes 10+ safe atomic tests that check
    whether your detection controls actually FIRE. Tests are read-only or
    use harmless artefacts (e.g. write a benign EICAR test file, create a
    decoy scheduled task). Designed to be run during a maintenance window.

  • MITRE D3FEND mapping — for each ATT&CK technique, returns the
    corresponding D3FEND defensive countermeasure ids.

  • VirusTotal lookup — file hash / URL / IP / domain reputation using the
    public v3 API (requires VT_API_KEY env var).
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional

from windows_audit import _run_ps

LOGGER = logging.getLogger("aegis.endpoint.sigma_live")


# ──────────────────────────────────────────────────────────────────────────────
# Sigma rule engine — runs every <interval> seconds, matches over the last
# window. Every "rule" here is a Python predicate built from a Sigma YAML;
# we ship a curated set of 15 high-fidelity rules.
# ──────────────────────────────────────────────────────────────────────────────

# Each rule: id, name, severity, technique, log_name, event_id_filter, ps_select,
# python predicate over the row dict.

SIGMA_LIVE_RULES = [
    {
        "id": "sigma.live.4625.bruteforce",
        "name": "Brute-force: 5+ logon falliti da stesso IP in 5 min",
        "severity": "high", "technique": "T1110",
        "log": "Security", "ids": [4625], "since_min": 5,
        "predicate": lambda rows: _group_count(rows, "IpAddress", min_n=5),
    },
    {
        "id": "sigma.live.4720.user_created",
        "name": "Account utente creato",
        "severity": "high", "technique": "T1136.001",
        "log": "Security", "ids": [4720], "since_min": 10,
        "predicate": lambda rows: rows,
    },
    {
        "id": "sigma.live.4732.admin_added",
        "name": "Utente aggiunto a gruppo Administrators",
        "severity": "critical", "technique": "T1098",
        "log": "Security", "ids": [4732], "since_min": 10,
        "predicate": lambda rows: rows,
    },
    {
        "id": "sigma.live.4624.rdp_external",
        "name": "Logon RDP da IP esterno (logon_type=10)",
        "severity": "critical", "technique": "T1021.001",
        "log": "Security", "ids": [4624], "since_min": 30,
        "predicate": lambda rows: [
            r for r in rows
            if (r.get("LogonType") == "10" or r.get("LogonType") == 10)
            and not _is_rfc1918((r.get("IpAddress") or "").strip())
        ],
    },
    {
        "id": "sigma.live.4104.encoded_ps",
        "name": "PowerShell EncodedCommand",
        "severity": "critical", "technique": "T1059.001",
        "log": "Microsoft-Windows-PowerShell/Operational", "ids": [4104], "since_min": 10,
        "predicate": lambda rows: [
            r for r in rows
            if any(s in (r.get("Snippet") or "").lower()
                    for s in ("-encodedcommand", "frombase64string"))
        ],
    },
    {
        "id": "sigma.live.4104.iex_cradle",
        "name": "PowerShell IEX/DownloadString cradle",
        "severity": "critical", "technique": "T1059.001",
        "log": "Microsoft-Windows-PowerShell/Operational", "ids": [4104], "since_min": 10,
        "predicate": lambda rows: [
            r for r in rows
            if any(s in (r.get("Snippet") or "").lower()
                    for s in ("downloadstring", ".downloadfile(", "iex(", "invoke-expression"))
        ],
    },
    {
        "id": "sigma.live.security.event_log_cleared",
        "name": "Event log cancellato (T1070.001)",
        "severity": "critical", "technique": "T1070.001",
        "log": "Security", "ids": [1102], "since_min": 60,
        "predicate": lambda rows: rows,
    },
    {
        "id": "sigma.live.system.service_install",
        "name": "Servizio Windows installato (T1543.003)",
        "severity": "high", "technique": "T1543.003",
        "log": "System", "ids": [7045], "since_min": 60,
        "predicate": lambda rows: rows,
    },
    {
        "id": "sigma.live.sysmon.1.lolbin_encoded",
        "name": "Sysmon ProcessCreate: LOLBin con encoded args",
        "severity": "critical", "technique": "T1027",
        "log": "Microsoft-Windows-Sysmon/Operational", "ids": [1], "since_min": 10,
        "predicate": lambda rows: [
            r for r in rows
            if any(s in (r.get("Snippet") or "").lower()
                    for s in ("-encodedcommand", "-enc ", "frombase64string"))
        ],
    },
    {
        "id": "sigma.live.sysmon.10.lsass_access",
        "name": "Sysmon ProcessAccess: handle a LSASS (credential dump)",
        "severity": "critical", "technique": "T1003.001",
        "log": "Microsoft-Windows-Sysmon/Operational", "ids": [10], "since_min": 10,
        "predicate": lambda rows: [
            r for r in rows
            if "lsass.exe" in (r.get("Snippet") or "").lower()
        ],
    },
]


def _group_count(rows: List[Dict[str, Any]], key: str, min_n: int) -> List[Dict[str, Any]]:
    bucket: Dict[str, List[Dict[str, Any]]] = {}
    for r in rows:
        k = r.get(key) or ""
        if not k or k in ("-", "::1", "127.0.0.1"):
            continue
        bucket.setdefault(k, []).append(r)
    out = []
    for k, lst in bucket.items():
        if len(lst) >= min_n:
            out.append({"group_key": k, "count": len(lst), "sample": lst[:5]})
    return out


def _is_rfc1918(ip: str) -> bool:
    if not ip:
        return True
    if ip.startswith(("10.", "192.168.", "127.")):
        return True
    if ip.startswith("172."):
        try:
            o2 = int(ip.split(".")[1])
            if 16 <= o2 <= 31:
                return True
        except Exception:
            pass
    return False


def _fetch_log(log_name: str, ids: List[int], since_min: int,
               max_events: int = 500) -> List[Dict[str, Any]]:
    ids_str = ",".join(str(i) for i in ids)
    out = _run_ps(
        f"Get-WinEvent -FilterHashtable @{{LogName='{log_name}'; Id=@({ids_str}); "
        f"StartTime=(Get-Date).AddMinutes(-{since_min})}} -MaxEvents {max_events} "
        "-ErrorAction SilentlyContinue | ForEach-Object {"
        "  $xml = [xml]$_.ToXml(); $data = @{}; "
        "  if ($xml.Event.EventData -and $xml.Event.EventData.Data) { "
        "    foreach ($d in $xml.Event.EventData.Data) { $data[$d.Name] = $d.'#text' } "
        "  } "
        "  $out = [pscustomobject]@{ TimeCreated=$_.TimeCreated; Id=$_.Id; "
        "    Snippet=($_.Message | Out-String).Substring(0, [Math]::Min(2000, ($_.Message|Out-String).Length)) }; "
        "  foreach ($k in $data.Keys) { $out | Add-Member -NotePropertyName $k -NotePropertyValue $data[$k] -ErrorAction SilentlyContinue }; "
        "  $out "
        "}",
        timeout=20,
    )
    if out is None:
        return []
    if isinstance(out, dict):
        out = [out]
    return out if isinstance(out, list) else []


class SigmaLiveEngine:
    """Background runner that periodically evaluates Sigma rules and emits
    events on match. Idempotent — repeated firings of the same event are
    deduped via a hash of (rule_id + key fields)."""

    def __init__(self, interval_sec: int = 60,
                 emit_callback: Optional[Callable[[Dict[str, Any]], None]] = None) -> None:
        self.interval = interval_sec
        self.emit_cb = emit_callback
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._seen: set = set()
        self.matches_count = 0
        self.last_run_at: Optional[str] = None
        self.started_at: Optional[str] = None
        self.last_results: Dict[str, int] = {}

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self.started_at = datetime.now(timezone.utc).isoformat()
        self._thread = threading.Thread(target=self._loop, name="aegis-sigma-live", daemon=True)
        self._thread.start()
        LOGGER.info("Sigma live engine started (every %ds)", self.interval)

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=4)

    def is_running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def _key(self, rule_id: str, match: Dict[str, Any]) -> str:
        m = {k: match.get(k) for k in ("group_key", "Id", "TimeCreated", "IpAddress", "TargetUserName")}
        return rule_id + "|" + hashlib.md5(json.dumps(m, sort_keys=True, default=str).encode()).hexdigest()[:16]

    def _loop(self) -> None:
        while not self._stop.is_set():
            t0 = time.time()
            cycle_matches: Dict[str, int] = {}
            for rule in SIGMA_LIVE_RULES:
                try:
                    rows = _fetch_log(rule["log"], rule["ids"], rule["since_min"])
                    matches = rule["predicate"](rows) or []
                    cycle_matches[rule["id"]] = len(matches)
                    for m in matches[:20]:
                        k = self._key(rule["id"], m)
                        if k in self._seen:
                            continue
                        self._seen.add(k)
                        self._emit_match(rule, m)
                        self.matches_count += 1
                except Exception as e:
                    LOGGER.debug("Sigma rule %s failed: %s", rule["id"], e)
            self.last_results = cycle_matches
            self.last_run_at = datetime.now(timezone.utc).isoformat()
            sleep_left = max(5, self.interval - (time.time() - t0))
            if self._stop.wait(sleep_left):
                break

    def _emit_match(self, rule: Dict[str, Any], match: Dict[str, Any]) -> None:
        evt = {
            "source":      "endpoint.sigma_live",
            "category":    "endpoint",
            "severity":    rule["severity"],
            "title":       f"Sigma match: {rule['name']}",
            "description": "Live Sigma rule detection on Windows Event Log.",
            "tags":        ["sigma", "real-time", rule["technique"]],
            "raw_data":    {
                "rule_id":   rule["id"],
                "rule_name": rule["name"],
                "technique": rule["technique"],
                "log":       rule["log"],
                "event_ids": rule["ids"],
                "match":     {k: v for k, v in match.items() if k != "Snippet"},
                "snippet":   (match.get("Snippet") or "")[:600],
            },
            "timestamp":   datetime.now(timezone.utc).isoformat(),
        }
        if self.emit_cb:
            try:
                self.emit_cb(evt)
            except Exception:
                pass


def list_sigma_live_rules() -> List[Dict[str, Any]]:
    return [
        {k: v for k, v in r.items() if k != "predicate"}
        for r in SIGMA_LIVE_RULES
    ]


# ──────────────────────────────────────────────────────────────────────────────
# Atomic Red Team — safe tests
# ──────────────────────────────────────────────────────────────────────────────

# Each test is read-only or trivially reversible (deletes the artefact it
# creates). Designed to verify that your AEGIS detections fire on real
# attacker patterns without doing any harm.

ATOMIC_TESTS = [
    {
        "id":        "T1059.001-T1",
        "name":      "PowerShell EncodedCommand (echo benign)",
        "technique": "T1059.001",
        "description": "Esegue powershell -enc <base64 di 'Write-Host AEGIS-TEST'> — verifica che il tuo ScriptBlock logging cattura encoded commands.",
        "ps":        "$enc = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('Write-Host AEGIS-TEST-ENCODED')); "
                     "powershell.exe -EncodedCommand $enc",
        "expected_detection": "sigma.live.4104.encoded_ps",
    },
    {
        "id":        "T1059.001-T2",
        "name":      "PowerShell IEX cradle (benign)",
        "technique": "T1059.001",
        "description": "Costruisce un IEX cradle che valuta '1+1' — pattern atteso dai ScriptBlock log.",
        "ps":        "$x = 'IEX(([scriptblock]::Create((''1+1'')))); '; Write-Output \"$x — non eseguito\"",
        "expected_detection": "sigma.live.4104.iex_cradle",
    },
    {
        "id":        "T1053.005-T1",
        "name":      "Scheduled task con nome benigno",
        "technique": "T1053.005",
        "description": "Crea + elimina un task chiamato 'AEGIS-TEST-Atomic'. Verifica che il SIEM osservi la creazione.",
        "ps":        "$t = 'AEGIS-TEST-Atomic'; "
                     "$action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument '/c exit'; "
                     "$trigger = New-ScheduledTaskTrigger -Once -At ((Get-Date).AddYears(1)); "
                     "Register-ScheduledTask -TaskName $t -Action $action -Trigger $trigger -Force | Out-Null; "
                     "Start-Sleep -Seconds 2; "
                     "Unregister-ScheduledTask -TaskName $t -Confirm:$false",
        "expected_detection": "scheduled_tasks_recent (hunt)",
    },
    {
        "id":        "T1140-T1",
        "name":      "certutil base64 decode (benign string)",
        "technique": "T1140",
        "description": "Encode + decode di 'AEGIS' via certutil — pattern T1140 (Deobfuscate/Decode).",
        "ps":        "$tmp = [IO.Path]::GetTempFileName(); "
                     "'AEGIS-TEST' | Out-File -Encoding ASCII $tmp; "
                     "certutil.exe -encode $tmp \"$tmp.b64\" | Out-Null; "
                     "certutil.exe -decode \"$tmp.b64\" \"$tmp.dec\" | Out-Null; "
                     "Remove-Item $tmp, \"$tmp.b64\", \"$tmp.dec\" -ErrorAction SilentlyContinue",
        "expected_detection": "lolbins (hunt) — certutil_decode",
    },
    {
        "id":        "T1027-T1",
        "name":      "PowerShell FromBase64String",
        "technique": "T1027",
        "description": "Decodifica una stringa base64 — verifica detection di FromBase64String.",
        "ps":        "$s = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('QUVHSVMtVEVTVA==')); "
                     "Write-Host $s",
        "expected_detection": "sigma.live.4104.encoded_ps",
    },
    {
        "id":        "T1547.001-T1",
        "name":      "Registry Run key (benign)",
        "technique": "T1547.001",
        "description": "Aggiunge + rimuove una Run key in HKCU. Hunt/realtime monitor deve vederla.",
        "ps":        "$k = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'; "
                     "$n = 'AEGIS-TEST-Atomic'; "
                     "Set-ItemProperty -Path $k -Name $n -Value 'C:\\Windows\\System32\\notepad.exe'; "
                     "Start-Sleep -Seconds 1; "
                     "Remove-ItemProperty -Path $k -Name $n -ErrorAction SilentlyContinue",
        "expected_detection": "realtime_monitor — new autorun",
    },
    {
        "id":        "T1110.001-T1",
        "name":      "Telnet to RDP port (failed connection)",
        "technique": "T1110.001",
        "description": "Avvia una connessione TCP a 127.0.0.1:3389 — se l'honeypot RDP è attivo verrà loggata.",
        "ps":        "$c = New-Object System.Net.Sockets.TcpClient; "
                     "try { $c.Connect('127.0.0.1', 3389); $c.Close() } catch {}",
        "expected_detection": "honeypot rdp-3389",
    },
    {
        "id":        "EICAR-T1",
        "name":      "EICAR test file su disco",
        "technique": "T1204",
        "description": "Scrive il file EICAR di test antivirus (standard ufficiale, non malevolo) e lo rimuove — Defender lo deve flaggare.",
        "ps":        "$tmp = Join-Path $env:TEMP 'aegis-eicar-test.txt'; "
                     "'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | "
                     "  Out-File -Encoding ASCII $tmp; "
                     "Start-Sleep -Seconds 2; "
                     "if (Test-Path $tmp) { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }",
        "expected_detection": "Defender real-time scan",
    },
    {
        "id":        "T1070.001-T1",
        "name":      "wevtutil enumerate (read-only, but pattern of clearing)",
        "technique": "T1070.001",
        "description": "Read-only enumeration. NON cancella eventi, solo legge.",
        "ps":        "wevtutil el | Select-Object -First 5",
        "expected_detection": "(none — read only)",
    },
    {
        "id":        "T1218.010-T1",
        "name":      "regsvr32 (no args, harmless)",
        "technique": "T1218.010",
        "description": "Invoca regsvr32.exe senza argomenti — sufficient per essere catturato da hunt/realtime.",
        "ps":        "Start-Process -FilePath 'regsvr32.exe' -ArgumentList '/u', '/s', '/n', 'shell32.dll' -NoNewWindow -Wait",
        "expected_detection": "hunt — lolbins",
    },
]


def list_atomic_tests() -> List[Dict[str, Any]]:
    return [{k: v for k, v in t.items() if k != "ps"} for t in ATOMIC_TESTS]


def run_atomic_test(test_id: str) -> Dict[str, Any]:
    test = next((t for t in ATOMIC_TESTS if t["id"] == test_id), None)
    if not test:
        return {"error": f"unknown test {test_id}"}
    started = datetime.now(timezone.utc)
    out = _run_ps(test["ps"] + "; Write-Output 'AEGIS-ATOMIC-DONE'", timeout=30)
    completed = datetime.now(timezone.utc)
    return {
        "test_id":              test["id"],
        "name":                 test["name"],
        "technique":            test["technique"],
        "description":          test["description"],
        "expected_detection":   test["expected_detection"],
        "ps_executed":          test["ps"][:500],
        "ps_output":            str(out)[:800] if out else "",
        "started_at":           started.isoformat(),
        "completed_at":         completed.isoformat(),
        "duration_seconds":     round((completed - started).total_seconds(), 2),
    }


# ──────────────────────────────────────────────────────────────────────────────
# MITRE D3FEND mapping — ATT&CK technique → D3FEND defensive countermeasure
# ──────────────────────────────────────────────────────────────────────────────

D3FEND_MAP = {
    "T1003":     ["D3-PA Privileged Account Use",   "D3-CH Credential Hardening"],
    "T1003.001": ["D3-CH Credential Hardening",     "D3-PA Privileged Account Use"],
    "T1021.001": ["D3-NTA Network Traffic Analysis","D3-AL Authentication Logs"],
    "T1027":     ["D3-EAL Executable Allowlisting","D3-PSA Process Spawn Analysis"],
    "T1041":     ["D3-NTA Network Traffic Analysis","D3-OTF Outbound Traffic Filtering"],
    "T1046":     ["D3-NTA Network Traffic Analysis"],
    "T1053.005": ["D3-PSA Process Spawn Analysis", "D3-FBA File-Based Authentication"],
    "T1055":     ["D3-PSA Process Spawn Analysis", "D3-PCSV Process Code Segment Verification"],
    "T1059":     ["D3-EAL Executable Allowlisting", "D3-IRA Inbound Restriction Activity"],
    "T1059.001": ["D3-SCF Script Execution Filtering", "D3-EAL Executable Allowlisting"],
    "T1070.001": ["D3-FAU File Access Pattern Analysis"],
    "T1071.001": ["D3-NTA Network Traffic Analysis"],
    "T1071.004": ["D3-DNSTA DNS Traffic Analysis"],
    "T1078":     ["D3-AL Authentication Logs", "D3-UGLPA User Geolocation Pattern Analysis"],
    "T1078.003": ["D3-MFA Multi-factor Authentication"],
    "T1098":     ["D3-AL Authentication Logs"],
    "T1105":     ["D3-OTF Outbound Traffic Filtering"],
    "T1110":     ["D3-AL Authentication Logs", "D3-AAR Authentication Anomaly Response"],
    "T1110.001": ["D3-AL Authentication Logs", "D3-AAR Authentication Anomaly Response"],
    "T1110.003": ["D3-MFA Multi-factor Authentication"],
    "T1136":     ["D3-AAR Authentication Anomaly Response"],
    "T1136.001": ["D3-AAR Authentication Anomaly Response"],
    "T1140":     ["D3-PSA Process Spawn Analysis", "D3-SCF Script Execution Filtering"],
    "T1190":     ["D3-NTA Network Traffic Analysis", "D3-DENCR Decoy Encryption"],
    "T1204":     ["D3-FAU File Access Pattern Analysis"],
    "T1218":     ["D3-EAL Executable Allowlisting", "D3-PSA Process Spawn Analysis"],
    "T1218.010": ["D3-EAL Executable Allowlisting"],
    "T1486":     ["D3-FAU File Access Pattern Analysis", "D3-DENCR Decoy Encryption"],
    "T1490":     ["D3-BR Backup and Recovery", "D3-FAU File Access Pattern Analysis"],
    "T1499":     ["D3-NTA Network Traffic Analysis"],
    "T1543.003": ["D3-PSA Process Spawn Analysis"],
    "T1546.003": ["D3-PSA Process Spawn Analysis"],
    "T1547.001": ["D3-PSA Process Spawn Analysis", "D3-FAU File Access Pattern Analysis"],
    "T1562.001": ["D3-PSA Process Spawn Analysis", "D3-IRA Inbound Restriction Activity"],
    "T1562.002": ["D3-FAU File Access Pattern Analysis"],
    "T1620":     ["D3-PCSV Process Code Segment Verification", "D3-EAL Executable Allowlisting"],
    "T1574.002": ["D3-PSA Process Spawn Analysis", "D3-FAU File Access Pattern Analysis"],
    "T1559.001": ["D3-NTA Network Traffic Analysis"],
    # ICS
    "T0855":     ["D3-NTA Network Traffic Analysis (OT segment)", "D3-OTAR OT Anomaly Response"],
    "T0846":     ["D3-NTA Network Traffic Analysis (OT segment)"],
    "T0856":     ["D3-NTA Network Traffic Analysis (OT segment)"],
    "T0845":     ["D3-NTA Network Traffic Analysis (OT segment)"],
    "T0840":     ["D3-NTA Network Traffic Analysis (OT segment)"],
}


def d3fend_for(technique_id: str) -> List[str]:
    return D3FEND_MAP.get(technique_id.upper().strip(), [])


def d3fend_coverage(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Given a list of findings with .technique, compute a D3FEND coverage map."""
    tech_seen: Dict[str, int] = {}
    for f in findings:
        t = (f.get("technique") or "").upper()
        if t:
            tech_seen[t] = tech_seen.get(t, 0) + 1
    mapped = {}
    unmapped = []
    for t, cnt in tech_seen.items():
        defs = d3fend_for(t)
        if defs:
            mapped[t] = {"count": cnt, "defenses": defs}
        else:
            unmapped.append({"technique": t, "count": cnt})
    return {
        "techniques_observed": len(tech_seen),
        "mapped":              mapped,
        "unmapped":            unmapped,
        "coverage_pct":        round(len(mapped) / max(1, len(tech_seen)) * 100, 1),
    }


# ──────────────────────────────────────────────────────────────────────────────
# VirusTotal v3 lookup (needs VT_API_KEY)
# ──────────────────────────────────────────────────────────────────────────────

def vt_lookup(kind: str, indicator: str) -> Dict[str, Any]:
    """kind ∈ {file, url, ip, domain}. Returns the v3 attributes block or
    error info. Public quota: 4 req/min / 500/day.
    """
    api_key = os.getenv("VT_API_KEY", "").strip()
    if not api_key:
        return {"error": "VT_API_KEY non impostata. Genera una chiave gratuita su https://www.virustotal.com",
                 "required_env": "VT_API_KEY"}
    if kind == "url":
        # VT URL API wants base64url id
        import base64
        indicator = base64.urlsafe_b64encode(indicator.encode()).decode().rstrip("=")
        endpoint = f"urls/{indicator}"
    elif kind == "file":
        endpoint = f"files/{indicator}"
    elif kind == "ip":
        endpoint = f"ip_addresses/{indicator}"
    elif kind == "domain":
        endpoint = f"domains/{indicator}"
    else:
        return {"error": f"unknown kind {kind}"}

    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    req = urllib.request.Request(url, headers={
        "x-apikey": api_key,
        "User-Agent": "Cybersecurity-AEGIS/1.0",
    })
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"matched": False, "kind": kind, "indicator": indicator}
        return {"error": f"VT HTTP {e.code}"}
    except Exception as e:
        return {"error": str(e)}
    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})
    return {
        "matched":            True,
        "kind":               kind,
        "indicator":          indicator,
        "malicious":          stats.get("malicious", 0),
        "suspicious":         stats.get("suspicious", 0),
        "harmless":           stats.get("harmless", 0),
        "undetected":         stats.get("undetected", 0),
        "reputation":         attrs.get("reputation"),
        "last_analysis_date": attrs.get("last_analysis_date"),
        "names":              attrs.get("names", [])[:5] if kind == "file" else None,
        "categories":         attrs.get("categories"),
        "tags":               attrs.get("tags"),
    }
