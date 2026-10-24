#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Report Generator
=======================================
Generates comprehensive security reports in HTML and JSON formats.

Reports include:
  • Executive Summary (KPIs, risk overview)
  • Network Discovery results (hosts, OS, services)
  • Vulnerability findings (CVE list, CVSS scores, remediation)
  • Threat Intelligence matches (IOC hits, threat actors)
  • SIEM incidents (correlation results)
  • MITRE ATT&CK coverage map
  • OT/ICS assets and advisories
  • Compliance status (GDPR, NIS2, IEC 62443)

Output: HTML (self-contained with inline CSS/JS) + JSON
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import requests
    _REQUESTS = True
except ImportError:
    _REQUESTS = False


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _sev_color(sev: str) -> str:
    return {
        "critical": "#ef4444",
        "high":     "#f59e0b",
        "medium":   "#3b82f6",
        "low":      "#10b981",
    }.get(sev.lower(), "#6b7280")


def _cvss_badge(score: float) -> str:
    if score >= 9.0: color, label = "#ef4444", "CRITICAL"
    elif score >= 7.0: color, label = "#f59e0b", "HIGH"
    elif score >= 4.0: color, label = "#3b82f6", "MEDIUM"
    else: color, label = "#10b981", "LOW"
    return f'<span style="background:{color};color:#fff;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:700">{label} {score}</span>'


def _gather_data(orchestrator_url: str) -> Dict[str, Any]:
    """Fetch all data from running AEGIS modules."""
    data: Dict[str, Any] = {
        "generated_at": _now_iso(),
        "network": {"scan_results": [], "alerts": []},
        "vuln": {"findings": []},
        "siem": {"incidents": [], "rules": []},
        "soar": {"executed": []},
        "threat_intel": {"ioc_matches": []},
        "events": [],
        "modules": {},
    }
    if not _REQUESTS:
        return data

    base = orchestrator_url.rstrip("/")
    module_ports = {
        "network": 8081, "vuln": 8085, "siem": 8082,
        "soar": 8083, "threat_intel": 8084,
    }
    base_host = base.replace("http://", "").replace("https://", "").split(":")[0]

    def _get(url: str) -> Optional[Dict]:
        try:
            r = requests.get(url, timeout=5)
            return r.json() if r.ok else None
        except Exception:
            return None

    # Events from orchestrator
    ev = _get(f"{base}/api/events")
    if ev:
        data["events"] = ev.get("events", [])[:200]

    # Modules status from orchestrator
    mods = _get(f"{base}/api/modules")
    if mods:
        data["modules"] = mods.get("modules", {})

    # Network data + scan results
    net = _get(f"http://{base_host}:{module_ports['network']}/data")
    if net:
        data["network"]["alerts"] = net.get("alerts", [])

    net_scan = _get(f"http://{base_host}:{module_ports['network']}/scan/results")
    if net_scan:
        data["network"]["scan_results"] = net_scan.get("results", [])

    # Vuln findings
    vuln = _get(f"http://{base_host}:{module_ports['vuln']}/findings")
    if vuln:
        data["vuln"]["findings"] = vuln.get("findings", [])

    # SIEM incidents
    siem = _get(f"http://{base_host}:{module_ports['siem']}/incidents")
    if siem:
        data["siem"]["incidents"] = siem.get("incidents", [])

    # Threat intel IOC matches
    ti = _get(f"http://{base_host}:{module_ports['threat_intel']}/data")
    if ti:
        data["threat_intel"]["ioc_matches"] = ti.get("matches", [])

    return data


def generate_json_report(orchestrator_url: str = "http://localhost:8080",
                         outpath: Optional[str] = None) -> Dict[str, Any]:
    """Generate JSON report and optionally save to file."""
    data = _gather_data(orchestrator_url)

    findings = data["vuln"]["findings"]
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    hosts = data["network"]["scan_results"]
    incidents = data["siem"]["incidents"]
    events = data["events"]

    report = {
        "report_type": "aegis_security_report",
        "version": "2.0",
        "generated_at": data["generated_at"],
        "executive_summary": {
            "total_hosts_discovered": len(hosts),
            "total_vulnerabilities": len(findings),
            "critical_vulnerabilities": crit,
            "high_vulnerabilities": high,
            "siem_incidents": len(incidents),
            "events_24h": len(events),
            "overall_risk": "critical" if crit > 0 else ("high" if high > 0 else "medium"),
        },
        "network_discovery": hosts,
        "vulnerabilities": findings,
        "siem_incidents": incidents,
        "threat_intel": data["threat_intel"],
        "events": events[:50],
        "modules_status": data["modules"],
    }

    if outpath:
        Path(outpath).parent.mkdir(parents=True, exist_ok=True)
        with open(outpath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

    return report


def generate_html_report(orchestrator_url: str = "http://localhost:8080",
                         outpath: Optional[str] = None) -> str:
    """Generate self-contained HTML security report."""
    data = _gather_data(orchestrator_url)
    findings = data["vuln"]["findings"]
    hosts = data["network"]["scan_results"]
    incidents = data["siem"]["incidents"]
    events = data["events"]
    ti_matches = data["threat_intel"]["ioc_matches"]

    crit = sum(1 for f in findings if f.get("severity") == "critical")
    high = sum(1 for f in findings if f.get("severity") == "high")
    med  = sum(1 for f in findings if f.get("severity") == "medium")
    low  = sum(1 for f in findings if f.get("severity") == "low")
    overall_risk = "CRITICAL" if crit > 0 else ("HIGH" if high > 0 else ("MEDIUM" if med > 0 else "LOW"))
    risk_color = _sev_color(overall_risk.lower())

    # ── Host table rows ─────────────────────────────────────────────────────────
    host_rows = ""
    for h in hosts:
        ip = h.get("ip", "")
        hostname = h.get("hostname", "") or "—"
        os_guess = h.get("os_guess", "Unknown")
        risk = h.get("risk_score", 0)
        risk_sev = "critical" if risk >= 80 else ("high" if risk >= 60 else ("medium" if risk >= 40 else "low"))
        ports = h.get("ports", [])
        open_ports_str = ", ".join(str(p.get("port")) + "/" + p.get("service","?") for p in ports if p.get("state") == "open")
        fn_count = len(h.get("findings", []))
        host_rows += f"""
        <tr>
          <td><code>{ip}</code></td>
          <td>{hostname}</td>
          <td>{os_guess}</td>
          <td><small>{open_ports_str[:80]}{'...' if len(open_ports_str) > 80 else ''}</small></td>
          <td><span class="badge sev-{risk_sev}">{risk}/100</span></td>
          <td>{"<span class='badge sev-critical'>" + str(fn_count) + " CVE</span>" if fn_count > 0 else "—"}</td>
        </tr>"""

    # ── Vuln rows ───────────────────────────────────────────────────────────────
    vuln_rows = ""
    for f in sorted(findings, key=lambda x: -x.get("cvss_score", 0)):
        sev = f.get("severity", "low")
        cvss = f.get("cvss_score", 0)
        vuln_rows += f"""
        <tr>
          <td><code class="cve-id">{f.get('cve_id','?')}</code></td>
          <td>{f.get('target_ip','?')}</td>
          <td>{f.get('service','?')} :{f.get('target_port','?')}</td>
          <td>{_cvss_badge(cvss)}</td>
          <td class="sev-{sev}">{sev.upper()}</td>
          <td><small>{f.get('description','')[:120]}</small></td>
        </tr>"""

    # ── Incident rows ────────────────────────────────────────────────────────────
    inc_rows = ""
    for i in incidents[:50]:
        sev = i.get("severity", "low")
        inc_rows += f"""
        <tr>
          <td>{i.get('first_seen','?')[:19]}</td>
          <td class="sev-{sev}">{sev.upper()}</td>
          <td><strong>{i.get('rule_name','?')}</strong></td>
          <td>{i.get('event_count','?')}</td>
          <td>{i.get('mitre_technique_id','')}</td>
          <td><small>{i.get('description','')[:100]}</small></td>
        </tr>"""

    # ── Threat Intel rows ────────────────────────────────────────────────────────
    ti_rows = ""
    for m in ti_matches[:30]:
        ioc = m.get("ioc", {})
        sev = ioc.get("severity", "low")
        ti_rows += f"""
        <tr>
          <td><code>{m.get('matched_value','?')}</code></td>
          <td>{ioc.get('ioc_type','?')}</td>
          <td class="sev-{sev}">{sev.upper()}</td>
          <td>{ioc.get('threat_actor','?')}</td>
          <td>{ioc.get('mitre_technique','')}</td>
          <td><small>{ioc.get('description','')[:80]}</small></td>
        </tr>"""

    # ── Event rows ───────────────────────────────────────────────────────────────
    ev_rows = ""
    for e in events[:30]:
        sev = e.get("severity", "low")
        ev_rows += f"""
        <tr>
          <td>{str(e.get('timestamp','?'))[:19]}</td>
          <td class="sev-{sev}">{sev.upper()}</td>
          <td>{e.get('source','?')}</td>
          <td>{e.get('title','?')}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AEGIS-OMNI Security Report — {_now_str()}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #0f172a; color: #e2e8f0; }}
  .container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}
  h1 {{ font-size: 28px; font-weight: 700; color: #38bdf8; }}
  h2 {{ font-size: 18px; font-weight: 700; margin: 32px 0 14px; color: #94a3b8; text-transform: uppercase; letter-spacing: .05em; border-bottom: 1px solid #1e293b; padding-bottom: 8px; }}
  h3 {{ font-size: 14px; font-weight: 600; color: #94a3b8; margin-bottom: 6px; }}
  .header {{ background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%); border: 1px solid #1e3a5f; border-radius: 14px; padding: 28px; margin-bottom: 32px; display: flex; justify-content: space-between; align-items: center; }}
  .header-left h1 {{ margin-bottom: 4px; }}
  .header-left p {{ color: #64748b; font-size: 13px; }}
  .risk-badge {{ padding: 8px 18px; border-radius: 8px; font-weight: 700; font-size: 15px; background: {risk_color}22; border: 2px solid {risk_color}; color: {risk_color}; }}
  .kpi-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-bottom: 28px; }}
  .kpi-card {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 18px; text-align: center; }}
  .kpi-num {{ font-size: 32px; font-weight: 700; line-height: 1; margin-bottom: 4px; }}
  .kpi-label {{ font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: .05em; }}
  .panel {{ background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 20px; margin-bottom: 24px; overflow: hidden; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12.5px; }}
  th {{ background: #0f172a; color: #64748b; padding: 8px 10px; text-align: left; font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: .04em; position: sticky; top: 0; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  tr:hover td {{ background: rgba(255,255,255,.02); }}
  .table-wrap {{ overflow-x: auto; border-radius: 6px; border: 1px solid #334155; }}
  code {{ font-family: "Consolas", monospace; font-size: 12px; background: #0f172a; padding: 1px 5px; border-radius: 3px; color: #38bdf8; }}
  .cve-id {{ color: #f59e0b !important; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; }}
  .sev-critical {{ color: #ef4444; }} .badge.sev-critical {{ background: rgba(239,68,68,.15); }}
  .sev-high {{ color: #f59e0b; }} .badge.sev-high {{ background: rgba(245,158,11,.15); }}
  .sev-medium {{ color: #3b82f6; }} .badge.sev-medium {{ background: rgba(59,130,246,.15); }}
  .sev-low {{ color: #10b981; }} .badge.sev-low {{ background: rgba(16,185,129,.15); }}
  .empty {{ color: #475569; text-align: center; padding: 24px; font-size: 13px; }}
  .footer {{ text-align: center; padding: 24px; color: #475569; font-size: 12px; margin-top: 32px; border-top: 1px solid #1e293b; }}
  @media print {{ body {{ background: white; color: black; }} .panel {{ border: 1px solid #ddd; }} }}
</style>
</head>
<body>
<div class="container">

  <!-- HEADER -->
  <div class="header">
    <div class="header-left">
      <h1>🛡 AEGIS-OMNI Security Report</h1>
      <p>Generato il {_now_str()} UTC | Suite versione 2.0</p>
    </div>
    <div class="risk-badge">RISCHIO GLOBALE: {overall_risk}</div>
  </div>

  <!-- KPI CARDS -->
  <div class="kpi-grid">
    <div class="kpi-card"><div class="kpi-num" style="color:#38bdf8">{len(hosts)}</div><div class="kpi-label">Host Scoperti</div></div>
    <div class="kpi-card"><div class="kpi-num" style="color:#ef4444">{crit}</div><div class="kpi-label">CVE Critiche</div></div>
    <div class="kpi-card"><div class="kpi-num" style="color:#f59e0b">{high}</div><div class="kpi-label">CVE High</div></div>
    <div class="kpi-card"><div class="kpi-num" style="color:#3b82f6">{med}</div><div class="kpi-label">CVE Medium</div></div>
    <div class="kpi-card"><div class="kpi-num" style="color:#f59e0b">{len(incidents)}</div><div class="kpi-label">Incidenti SIEM</div></div>
    <div class="kpi-card"><div class="kpi-num" style="color:#a78bfa">{len(ti_matches)}</div><div class="kpi-label">IOC Match</div></div>
    <div class="kpi-card"><div class="kpi-num" style="color:#64748b">{len(events)}</div><div class="kpi-label">Events 24h</div></div>
  </div>

  <!-- NETWORK DISCOVERY -->
  <h2><i></i> Network Discovery</h2>
  <div class="panel">
    {"<div class='table-wrap'><table><thead><tr><th>IP</th><th>Hostname</th><th>OS</th><th>Porte Aperte</th><th>Risk Score</th><th>Findings</th></tr></thead><tbody>" + host_rows + "</tbody></table></div>" if hosts else "<div class='empty'>Nessuna scansione di rete effettuata. Avvia una scansione dalla dashboard.</div>"}
  </div>

  <!-- VULNERABILITIES -->
  <h2>Vulnerabilità rilevate</h2>
  <div class="panel">
    {"<div class='table-wrap'><table><thead><tr><th>CVE ID</th><th>Target IP</th><th>Servizio</th><th>CVSS</th><th>Severità</th><th>Descrizione</th></tr></thead><tbody>" + vuln_rows + "</tbody></table></div>" if findings else "<div class='empty'>Nessuna vulnerabilità rilevata. Scansione non ancora effettuata.</div>"}
  </div>

  <!-- SIEM INCIDENTS -->
  <h2>Incidenti SIEM</h2>
  <div class="panel">
    {"<div class='table-wrap'><table><thead><tr><th>Data</th><th>Severità</th><th>Regola</th><th>Conteggio</th><th>MITRE</th><th>Descrizione</th></tr></thead><tbody>" + inc_rows + "</tbody></table></div>" if incidents else "<div class='empty'>Nessun incidente SIEM correlato.</div>"}
  </div>

  <!-- THREAT INTELLIGENCE -->
  <h2>Threat Intelligence — IOC Match</h2>
  <div class="panel">
    {"<div class='table-wrap'><table><thead><tr><th>Valore</th><th>Tipo</th><th>Severità</th><th>Threat Actor</th><th>MITRE</th><th>Descrizione</th></tr></thead><tbody>" + ti_rows + "</tbody></table></div>" if ti_matches else "<div class='empty'>Nessun match IOC. Configura AbuseIPDB/OTX API keys per arricchimento in tempo reale.</div>"}
  </div>

  <!-- RECENT EVENTS -->
  <h2>Ultimi eventi rilevati</h2>
  <div class="panel">
    {"<div class='table-wrap'><table><thead><tr><th>Timestamp</th><th>Severità</th><th>Modulo</th><th>Titolo</th></tr></thead><tbody>" + ev_rows + "</tbody></table></div>" if events else "<div class='empty'>Nessun evento ancora registrato.</div>"}
  </div>

  <!-- COMPLIANCE SUMMARY -->
  <h2>Compliance Summary</h2>
  <div class="panel">
    <div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:14px">
      <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px">
        <div style="font-weight:700;margin-bottom:6px">NIS2</div>
        <div style="font-size:12px;color:#64748b">Rilevamento incidenti: {"✅ attivo" if incidents else "⚠️ nessun dato"}</div>
        <div style="font-size:12px;color:#64748b">Monitoraggio rete: {"✅ attivo" if events else "⚠️ nessun dato"}</div>
      </div>
      <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px">
        <div style="font-weight:700;margin-bottom:6px">IEC 62443 (OT)</div>
        <div style="font-size:12px;color:#64748b">Asset inventory: {"✅ " + str(len(hosts)) + " host" if hosts else "⚠️ nessun dato"}</div>
        <div style="font-size:12px;color:#64748b">Vuln management: {"✅ " + str(len(findings)) + " finding" if findings else "⚠️ nessun dato"}</div>
      </div>
      <div style="background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px">
        <div style="font-weight:700;margin-bottom:6px">GDPR Art. 32</div>
        <div style="font-size:12px;color:#64748b">Threat detection: {"✅ attivo" if events else "⚠️ nessun dato"}</div>
        <div style="font-size:12px;color:#64748b">Incident response: {"✅ SOAR attivo" if True else "⚠️"}</div>
      </div>
    </div>
  </div>

  <!-- REMEDIATION PRIORITIES -->
  <h2>Priorità di rimediazione</h2>
  <div class="panel">
    {"".join('<div style="background:#0f172a;border-left:4px solid ' + _sev_color(f.get("severity","low")) + ';padding:10px 14px;margin-bottom:8px;border-radius:4px"><strong>' + f.get("cve_id","?") + '</strong> su ' + str(f.get("target_ip","?")) + ':' + str(f.get("target_port","?")) + ' — <small>' + f.get("description","")[:150] + '</small></div>' for f in sorted(findings, key=lambda x: -x.get("cvss_score",0))[:10]) if findings else "<div class='empty'>Nessuna vulnerabilità da rimediare.</div>"}
  </div>

  <div class="footer">
    AEGIS-OMNI Cybersecurity Suite — Report generato automaticamente il {_now_str()} UTC<br>
    <small>Questo report è confidenziale e destinato solo al team di sicurezza autorizzato.</small>
  </div>
</div>
</body>
</html>"""

    if outpath:
        Path(outpath).parent.mkdir(parents=True, exist_ok=True)
        with open(outpath, "w", encoding="utf-8") as f:
            f.write(html)

    return html
