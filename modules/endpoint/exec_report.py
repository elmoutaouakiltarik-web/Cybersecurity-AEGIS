#!/usr/bin/env python3
"""
Cybersecurity-AEGIS — Executive Report Generator
==================================================
Stdlib-only HTML report builder that produces a clean, self-contained
"executive briefing" page for board / IT-lead consumption. The HTML can be
printed-to-PDF from any browser with Ctrl+P (no reportlab dependency).

Sections:
  • Header — generated_at, host, version
  • Posture score gauge + grade
  • Critical / high actions table
  • NIST CSF maturity (5 functions)
  • IOC feed status
  • Recent ransomware indicators
  • Hardening + Enhanced audit summary
  • Recommendations (top 10)
"""
from __future__ import annotations

import html
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

LOGGER = logging.getLogger("aegis.endpoint.exec_report")


def _safe(s: Any) -> str:
    if s is None:
        return ""
    return html.escape(str(s))


def _gauge_svg(score: float, max_score: float = 100) -> str:
    pct = max(0, min(100, (score / max_score) * 100 if max_score else 0))
    color = "#16a34a" if pct >= 80 else ("#f59e0b" if pct >= 60 else "#ef4444")
    # Semi-circular gauge: 180° arc
    angle = (pct / 100) * 180
    import math
    r = 90
    cx, cy = 110, 110
    end_x = cx + r * math.cos(math.radians(180 - angle))
    end_y = cy - r * math.sin(math.radians(180 - angle))
    large = 1 if angle > 180 else 0
    return f'''
    <svg width="220" height="130" viewBox="0 0 220 130" xmlns="http://www.w3.org/2000/svg">
      <path d="M 20 110 A 90 90 0 0 1 200 110" fill="none" stroke="#e5e7eb" stroke-width="18"/>
      <path d="M 20 110 A 90 90 0 {large} 1 {end_x:.1f} {end_y:.1f}" fill="none" stroke="{color}" stroke-width="18" stroke-linecap="round"/>
      <text x="110" y="95" text-anchor="middle" font-family="-apple-system,Segoe UI,sans-serif" font-size="36" font-weight="700" fill="{color}">{int(pct)}</text>
      <text x="110" y="118" text-anchor="middle" font-family="-apple-system,Segoe UI,sans-serif" font-size="11" fill="#64748b">/100</text>
    </svg>
    '''


def build_html_report(posture: Dict[str, Any] = None,
                        csf: Dict[str, Any] = None,
                        ioc_stats: Dict[str, Any] = None,
                        audit_findings: List[Dict[str, Any]] = None,
                        enhanced_findings: List[Dict[str, Any]] = None,
                        host_info: Dict[str, Any] = None) -> str:
    posture = posture or {}
    csf = csf or {}
    ioc_stats = ioc_stats or {}
    audit_findings = audit_findings or []
    enhanced_findings = enhanced_findings or []
    host_info = host_info or {}

    now = datetime.now(timezone.utc)

    # Pull pieces
    posture_score = posture.get("score", 0)
    posture_grade = posture.get("grade", "—")
    top_actions   = posture.get("top_actions", [])[:15]

    csf_score = csf.get("total_score", 0)
    csf_pct   = csf.get("percentage", 0)
    csf_tier  = csf.get("tier", "—")
    csf_funcs = csf.get("functions", {})

    # Severity buckets
    all_findings = (audit_findings or []) + (enhanced_findings or [])
    sev_count = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in all_findings:
        s = f.get("severity")
        if s in sev_count and f.get("status") in ("warn", "fail"):
            sev_count[s] += 1

    # CSS — clean printable
    css = """
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system,'Segoe UI',sans-serif; color: #0f172a; background: #f8fafc;
           line-height: 1.5; padding: 32px; }
    .page { max-width: 920px; margin: 0 auto; background: white; box-shadow: 0 4px 20px rgba(0,0,0,0.08);
            border-radius: 12px; overflow: hidden; }
    header { background: linear-gradient(135deg,#0f172a 0%,#1e3a8a 100%); color: white; padding: 32px; }
    header h1 { font-size: 28px; font-weight: 800; letter-spacing: -0.5px; }
    header .sub { opacity: 0.7; font-size: 13px; margin-top: 4px; }
    .meta { display: flex; gap: 24px; margin-top: 16px; font-size: 12px; opacity: 0.9; }
    section { padding: 24px 32px; border-bottom: 1px solid #e5e7eb; }
    section h2 { font-size: 18px; font-weight: 700; margin-bottom: 14px; color: #0f172a;
                  display: flex; align-items: center; gap: 8px; }
    .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; }
    .kpi { background: #f8fafc; border-radius: 8px; padding: 14px; }
    .kpi .label { font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; color: #64748b; }
    .kpi .val { font-size: 28px; font-weight: 700; margin-top: 4px; }
    .kpi.crit .val { color: #ef4444; }
    .kpi.high .val { color: #f59e0b; }
    .kpi.med .val { color: #3b82f6; }
    .kpi.ok .val { color: #16a34a; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th { text-align: left; padding: 8px 12px; background: #f1f5f9; font-weight: 600; color: #475569; }
    td { padding: 10px 12px; border-bottom: 1px solid #e5e7eb; }
    .badge { display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }
    .badge.critical { background: #fee2e2; color: #dc2626; }
    .badge.high { background: #fed7aa; color: #ea580c; }
    .badge.medium { background: #dbeafe; color: #2563eb; }
    .badge.low { background: #dcfce7; color: #16a34a; }
    .layer-row { display: flex; align-items: center; gap: 12px; padding: 8px 0; }
    .layer-row .layer-name { width: 130px; font-weight: 600; text-transform: uppercase; font-size: 11px; color: #475569; }
    .layer-row .bar { flex: 1; height: 8px; background: #e5e7eb; border-radius: 4px; overflow: hidden; }
    .layer-row .bar-fill { height: 100%; background: linear-gradient(90deg,#10b981,#3b82f6); border-radius: 4px; }
    .layer-row .score { width: 60px; text-align: right; font-family: monospace; font-weight: 700; color: #0f172a; }
    .gauge-wrap { display: flex; align-items: center; gap: 24px; }
    .gauge-wrap .meta-side { font-size: 13px; color: #64748b; }
    .gauge-wrap .meta-side strong { color: #0f172a; font-size: 20px; display: block; margin-bottom: 4px; }
    footer { padding: 20px 32px; background: #0f172a; color: #94a3b8; font-size: 11px; text-align: center; }
    footer a { color: #60a5fa; text-decoration: none; }
    @media print {
      body { background: white; padding: 0; }
      .page { box-shadow: none; }
      section { break-inside: avoid; }
    }
    """

    actions_html = "\n".join(
        f"<tr><td><span class='badge {_safe(a.get('severity', 'info'))}'>{_safe(a.get('severity'))}</span></td>"
        f"<td>{_safe(a.get('title'))}</td>"
        f"<td style='font-size:11px;color:#64748b'>{_safe((a.get('description') or '')[:120])}</td>"
        f"<td><code style='font-size:11px'>{_safe(a.get('technique') or a.get('check_id', ''))}</code></td></tr>"
        for a in top_actions
    ) or "<tr><td colspan='4' style='text-align:center;color:#64748b'>Nessuna azione critica.</td></tr>"

    csf_rows_html = "\n".join(
        f"<div class='layer-row'>"
        f"<div class='layer-name'>{_safe(name)}</div>"
        f"<div class='bar'><div class='bar-fill' style='width:{(data.get('score',0)/data.get('max',5))*100:.0f}%'></div></div>"
        f"<div class='score'>{data.get('score',0):.1f} / {data.get('max',5)}</div>"
        f"</div>"
        for name, data in (csf_funcs.items() if isinstance(csf_funcs, dict) else [])
    ) or "<p style='color:#64748b'>CSF non calcolato</p>"

    ioc_html = f"""
    <div class='grid-4'>
      <div class='kpi'><div class='label'>IP malicious</div><div class='val'>{ioc_stats.get('ip_count', 0):,}</div></div>
      <div class='kpi'><div class='label'>Domini</div><div class='val'>{ioc_stats.get('domain_count', 0):,}</div></div>
      <div class='kpi'><div class='label'>Hash malware</div><div class='val'>{ioc_stats.get('hash_count', 0):,}</div></div>
      <div class='kpi'><div class='label'>CIDR Spamhaus</div><div class='val'>{ioc_stats.get('cidr_count', 0):,}</div></div>
    </div>
    """

    host_block = f"""
    <div class='meta'>
      <div><strong>Host:</strong> {_safe(host_info.get('hostname'))}</div>
      <div><strong>User:</strong> {_safe(host_info.get('user'))}</div>
      <div><strong>OS:</strong> {_safe((host_info.get('windows') or {}).get('OSCaption') or host_info.get('platform'))}</div>
      <div><strong>Build:</strong> {_safe((host_info.get('windows') or {}).get('OSBuild'))}</div>
    </div>
    """

    return f"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<title>AEGIS — Executive Security Briefing</title>
<style>{css}</style>
</head>
<body>
<div class="page">
  <header>
    <h1>🛡 AEGIS Executive Security Briefing</h1>
    <div class="sub">Cybersecurity-AEGIS / AEGIS-OMNI — confidential</div>
    {host_block}
    <div class="meta">
      <div><strong>Report generated:</strong> {now.strftime('%Y-%m-%d %H:%M UTC')}</div>
      <div><strong>Posture score:</strong> {posture_score}/100 ({_safe(posture_grade)})</div>
    </div>
  </header>

  <section>
    <h2>📊 Defensive Posture</h2>
    <div class="gauge-wrap">
      {_gauge_svg(posture_score)}
      <div class="meta-side">
        <strong>Grade {_safe(posture_grade)}</strong>
        Score olistico combinato (perimetro / endpoint / rete / identità / dati / intelligence).
        <br><br>
        NIST CSF Tier: <strong>{_safe(csf_tier)}</strong> ({csf_pct}%)
      </div>
    </div>
  </section>

  <section>
    <h2>🚨 Findings per severity</h2>
    <div class="grid-4">
      <div class="kpi crit"><div class="label">Critical</div><div class="val">{sev_count['critical']}</div></div>
      <div class="kpi high"><div class="label">High</div><div class="val">{sev_count['high']}</div></div>
      <div class="kpi med"><div class="label">Medium</div><div class="val">{sev_count['medium']}</div></div>
      <div class="kpi ok"><div class="label">Low</div><div class="val">{sev_count['low']}</div></div>
    </div>
  </section>

  <section>
    <h2>🎯 Top 15 azioni prioritarie</h2>
    <table>
      <thead><tr><th>Severity</th><th>Title</th><th>Description</th><th>Technique</th></tr></thead>
      <tbody>{actions_html}</tbody>
    </table>
  </section>

  <section>
    <h2>📋 NIST CSF Maturity ({csf_score:.1f}/25 — {_safe(csf_tier)})</h2>
    {csf_rows_html}
  </section>

  <section>
    <h2>🌐 Threat Intelligence Feeds</h2>
    {ioc_html}
    <p style='font-size:12px;color:#64748b;margin-top:8px'>
      Live feed: CISA KEV, Abuse.ch URLhaus, FeodoTracker C2, MalwareBazaar SHA-256, Tor exit nodes, Spamhaus DROP.
    </p>
  </section>

  <footer>
    Cybersecurity-AEGIS / AEGIS-OMNI Executive Report —
    Generated by AEGIS Endpoint v1.0 on {now.isoformat()}<br>
    Defensive-Only · Zero-Trust · IT+OT
  </footer>
</div>
</body>
</html>"""
