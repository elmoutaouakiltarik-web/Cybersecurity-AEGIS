"""Report di assessment industriale in Markdown, HTML e JSON.

Il report e' il vero prodotto della consulenza: deve essere leggibile da un
responsabile di stabilimento (sintesi, cosa fare subito) e verificabile da un
tecnico OT (evidenze, copertura, limiti). Per questo ogni finding dichiara se
la remediation e' applicabile in produzione o richiede una fermata.
"""
from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .models import SEVERITIES, AssessmentResult, severity_rank

SEV_LABEL_IT = {
    "critical": "Critico",
    "high": "Alto",
    "medium": "Medio",
    "low": "Basso",
    "info": "Informativo",
}

MODE_LABEL_IT = {
    "passive": "Passivo — nessun pacchetto inviato alla rete dell'impianto",
    "readonly": "Sola lettura — identificazione e scansione TCP, nessuna scrittura di processo",
    "active": "Fingerprint esteso — banner e versioni, nessuna scrittura di processo",
}

EMPTY = "—"


# ── helper ────────────────────────────────────────────────────────────────────
def _s(value: Any, default: str = EMPTY) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _sev(severity: Any) -> str:
    sev = str(severity or "info").lower()
    return sev if sev in SEVERITIES else "info"


def _sev_label(severity: Any) -> str:
    return SEV_LABEL_IT.get(_sev(severity), "Informativo")


def _esc(value: Any) -> str:
    return html.escape(_s(value), quote=True)


def _md_cell(value: Any) -> str:
    return _s(value).replace("|", "\\|").replace("\n", " ").replace("\r", " ")


def _score_judgement(score: Optional[int]) -> str:
    try:
        value = int(score if score is not None else 0)
    except (TypeError, ValueError):
        value = 0
    if value >= 85:
        return "buono"
    if value >= 70:
        return "discreto"
    if value >= 50:
        return "critico"
    return "grave"


def _score_class(score: Optional[int]) -> str:
    try:
        value = int(score if score is not None else 0)
    except (TypeError, ValueError):
        value = 0
    if value >= 85:
        return "good"
    if value >= 70:
        return "warn"
    return "bad"


def _duration(result: AssessmentResult) -> str:
    try:
        seconds = float(result.duration_s or 0)
    except (TypeError, ValueError):
        seconds = 0.0
    if seconds < 60:
        return f"{seconds:.0f} s"
    if seconds < 3600:
        return f"{seconds / 60:.1f} min"
    return f"{seconds / 3600:.1f} h"


def _asset_label(result: AssessmentResult, ip: str) -> str:
    if not ip:
        return EMPTY
    asset = result.asset_by_ip(ip)
    if asset is None:
        return ip
    name = asset.hostname or asset.vendor or asset.device_type
    return f"{ip} ({name})" if name and name != "unknown" else ip


def _inventory_rows(result: AssessmentResult) -> List[List[str]]:
    rows: List[List[str]] = []
    for asset in sorted(result.assets, key=lambda a: (a.purdue_level or 0, a.ip)):
        ports = ", ".join(
            f"{p.port}/{p.service or p.proto}"
            for p in sorted(asset.ports, key=lambda p: p.port)
            if p.state == "open"
        )
        rows.append([
            _s(asset.ip),
            _s(asset.mac),
            _s(asset.hostname),
            _s(asset.vendor),
            _s(asset.device_type),
            _s(asset.zone),
            str(asset.purdue_level or 0),
            _s(", ".join(asset.protocols)),
            _s(ports),
            str(asset.risk_score or 0),
        ])
    return rows


def _zone_flow_summary(result: AssessmentResult) -> List[Dict[str, Any]]:
    """Flussi est-ovest tra zone, calcolati dalle conversazioni osservate."""
    if not result.conversations:
        return []
    zones = {a.ip: (a.zone or "non classificata") for a in result.assets}
    counts: Dict[tuple, int] = {}
    for conv in result.conversations:
        src = zones.get(conv.src_ip, "non classificata")
        dst = zones.get(conv.dst_ip, "non classificata")
        counts[(src, dst)] = counts.get((src, dst), 0) + 1
    out = [
        {"src_zone": src, "dst_zone": dst, "flows": n, "cross_zone": src != dst}
        for (src, dst), n in counts.items()
    ]
    return sorted(out, key=lambda row: (-row["flows"], row["src_zone"], row["dst_zone"]))


def _summary_line(result: AssessmentResult) -> str:
    counts = result.severity_counts()
    ot_count = len(result.ot_assets())
    return (
        f"{len(result.assets)} asset osservati ({ot_count} classificati OT), "
        f"{counts.get('critical', 0)} critici, {counts.get('high', 0)} alti, "
        f"{counts.get('medium', 0)} medi, {counts.get('low', 0)} bassi."
    )


def _write_node_count(result: AssessmentResult) -> int:
    return sum(1 for a in result.anomalies if a.kind == "ot_write_command")


# ── Markdown ──────────────────────────────────────────────────────────────────
def build_markdown(result: AssessmentResult) -> str:
    lines: List[str] = []
    add = lines.append

    title_site = _s(result.site, "sito non specificato")
    add(f"# Assessment di sicurezza industriale — {title_site}")
    add("")
    add("| Campo | Valore |")
    add("|---|---|")
    add(f"| Cliente | {_md_cell(result.client)} |")
    add(f"| Sito / impianto | {_md_cell(result.site)} |")
    add(f"| Operatore | {_md_cell(result.operator)} |")
    add(f"| Riferimento autorizzazione | {_md_cell(result.authorization_ref)} |")
    add(f"| Modalita' | {MODE_LABEL_IT.get(result.mode, _s(result.mode))} |")
    add(f"| Inizio | {_md_cell(result.started_at)} |")
    add(f"| Fine | {_md_cell(result.finished_at)} |")
    add(f"| Durata | {_duration(result)} |")
    add(f"| Punteggio postura | **{result.site_score}/100** ({_score_judgement(result.site_score)}) |")
    add(f"| ID assessment | `{_md_cell(result.id)}` |")
    add("")

    # Sintesi esecutiva
    add("## Sintesi esecutiva")
    add("")
    add(f"- {_summary_line(result)}")
    top = result.sorted_findings()[:3]
    if top:
        for finding in top:
            add(
                f"- **[{_sev_label(finding.severity)}] {finding.title}** "
                f"su {_asset_label(result, finding.asset_ip)} — {_s(finding.why, finding.evidence)}"
            )
    else:
        add("- Nessun finding rilevato con le verifiche eseguite (vedere la sezione copertura e limiti).")
    write_nodes = _write_node_count(result)
    if write_nodes:
        add(
            f"- **{write_nodes} comandi di scrittura OT osservati nel traffico**: e' l'indicatore "
            "piu' diretto di un comando malevolo o di un HMI/configurazione errata. "
            "Verificare immediatamente chi li ha generati."
        )
    add(
        f"- Punteggio di postura **{result.site_score}/100**: {_score_judgement(result.site_score)}. "
        "Il punteggio pesa gravita' e confidenza delle findings sul numero di asset."
    )
    if result.baseline_diff.get("has_drift"):
        add("- **Variazioni rispetto alla baseline**: nuovi asset o nuove porte rispetto allo snapshot precedente (vedere sezione dedicata).")
    add("")

    # Cosa fare subito
    now = [f for f in result.sorted_findings() if f.production_safe]
    add("## Cosa fare subito (senza fermare la produzione)")
    add("")
    if now:
        add("Azioni a basso impatto, applicabili durante l'esercizio. Verificare comunque con il responsabile di produzione prima di modificare configurazioni su apparati attivi.")
        add("")
        for f in now:
            refs = f" — rif. {f.iec62443}" if f.iec62443 else ""
            add(
                f"- **[{_sev_label(f.severity)}] {f.title}** "
                f"({_asset_label(result, f.asset_ip)}, score {f.score:.1f}) — "
                f"{_s(f.remediation, 'Definire una remediation con il team OT.')}{refs}"
            )
    else:
        add("Nessuna azione immediata classificata come sicura in produzione.")
    add("")

    # Fermata
    later = [f for f in result.sorted_findings() if not f.production_safe]
    add("## Cosa pianificare in fermata")
    add("")
    if later:
        add("Interventi che possono interrompere la comunicazione o richiedere il riavvio di un apparato: vanno pianificati in una finestra di manutenzione concordata.")
        add("")
        for f in later:
            add(
                f"- **[{_sev_label(f.severity)}] {f.title}** "
                f"({_asset_label(result, f.asset_ip)}, score {f.score:.1f}) — "
                f"{_s(f.remediation, 'Pianificare lintervento in fermata.')}"
            )
    else:
        add("Nessun intervento classificato come critico per la continuita' produttiva.")
    add("")

    # Inventario
    add("## Inventario asset")
    add("")
    rows = _inventory_rows(result)
    if rows:
        add("| IP | MAC | Nome | Vendor | Tipo | Zona | Purdue | Protocolli | Porte | Rischio |")
        add("|---|---|---|---|---|---|---|---|---|---|")
        for row in rows:
            add("| " + " | ".join(_md_cell(c) for c in row) + " |")
    else:
        add("_Nessun asset osservato. In modalita' passiva serve traffico reale durante la cattura; "
            "in modalita' sola lettura verificare che i target siano raggiungibili._")
    add("")

    # Findings dettagliati
    add("## Risultati dettagliati")
    add("")
    if result.findings:
        for f in result.sorted_findings():
            add(f"### [{_sev_label(f.severity)}] {f.title}")
            add("")
            add(f"- **Score:** {f.score:.1f}/10 · **Categoria:** {_s(f.category)} · "
                f"**Confidenza:** {_s(f.confidence)}")
            add(f"- **Asset:** {_asset_label(result, f.asset_ip)}")
            if f.asset_label:
                add(f"- **Etichetta asset:** {f.asset_label}")
            add(f"- **Evidenza:** {_s(f.evidence, 'non disponibile')}")
            add(f"- **Perche' conta:** {_s(f.why, 'Impatto non descritto.')}")
            add(f"- **Remediation:** {_s(f.remediation, 'Da definire con il team OT.')}")
            add(f"- **Applicabile in produzione:** {'si' if f.production_safe else 'no — richiede fermata/manutenzione'}")
            if f.mitre_ics:
                add(f"- **MITRE ATT&CK for ICS:** {f.mitre_ics}")
            if f.iec62443:
                add(f"- **IEC 62443:** {f.iec62443}")
            if f.references:
                add(f"- **Riferimenti:** {', '.join(str(r) for r in f.references)}")
            add("")
    else:
        add("_Nessun finding prodotto dalle verifiche eseguite._")
        add("")

    # Anomalie
    add("## Anomalie di traffico")
    add("")
    if result.anomalies:
        add("| Severita' | Tipo | Titolo | Sorgente | Destinazione | Evidenza |")
        add("|---|---|---|---|---|---|")
        for a in sorted(result.anomalies, key=lambda x: (severity_rank(x.severity), x.title)):
            add(
                f"| {_sev_label(a.severity)} | {_md_cell(a.kind)} | {_md_cell(a.title)} | "
                f"{_md_cell(a.src_ip)} | {_md_cell(a.dst_ip)} | {_md_cell(a.evidence)} |"
            )
        add("")
        write_anomalies = [a for a in result.anomalies if a.kind == "ot_write_command"]
        if write_anomalies:
            add("> **Comandi di scrittura verso il processo.** Le anomalie di tipo `ot_write_command` "
                "non sono vulnerabilita' teoriche: qualcuno o qualcosa ha inviato un comando capace di "
                "muovere un attuatore. Correlare con i log del SCADA e con le finestre di manutenzione.")
            add("")
    else:
        add("_Nessuna anomalia di traffico rilevata nella finestra osservata._")
        add("")

    # Segmentazione
    add("## Segmentazione tra zone")
    add("")
    if result.zones:
        add("| Zona | Purdue | Reti | Asset |")
        add("|---|---|---|---|")
        for z in result.zones:
            add(f"| {_md_cell(z.name)} | {z.purdue_level} | {_md_cell(', '.join(z.cidrs))} | {z.asset_count} |")
        add("")
    flows = _zone_flow_summary(result)
    if flows:
        add("| Zona sorgente | Zona destinazione | Flussi | Attraversa zone |")
        add("|---|---|---|---|")
        for row in flows:
            add(
                f"| {_md_cell(row['src_zone'])} | {_md_cell(row['dst_zone'])} | {row['flows']} | "
                f"{'si' if row['cross_zone'] else 'no'} |"
            )
        cross = sum(row["flows"] for row in flows if row["cross_zone"])
        add("")
        add(f"Totale flussi tra zone diverse: **{cross}**. Ogni flusso tra Purdue 3/4 e Purdue 1/2 "
            "dovrebbe passare da un firewall industriale o da un data diode, non da uno switch condiviso.")
    elif not result.zones:
        add("_Dato non disponibile in questa modalita': la matrice dei flussi richiede una cattura passiva "
            "del traffico oppure la definizione delle zone nell'engagement._")
    add("")

    # Baseline
    diff = result.baseline_diff or {}
    if diff:
        add("## Variazioni rispetto alla baseline")
        add("")
        add(f"- Baseline generata: {_md_cell(diff.get('generated_at'))}")
        add(f"- Drift rilevato: {'si' if diff.get('has_drift') else 'no'}")
        for item in diff.get("new_assets", []) or []:
            add(f"- **Nuovo asset:** {_md_cell(item.get('ip'))} {_md_cell(item.get('label'))}")
        for item in diff.get("removed_assets", []) or []:
            add(f"- **Asset scomparso:** {_md_cell(item.get('ip'))} {_md_cell(item.get('label'))}")
        for item in diff.get("new_ports", []) or []:
            add(f"- **Nuova porta:** {_md_cell(item.get('ip'))} → {_md_cell(item.get('port'))}/{_md_cell(item.get('service'))}")
        for item in diff.get("changed_identities", []) or []:
            add(f"- **Identita' cambiata:** {_md_cell(item.get('ip'))} — {_md_cell(item.get('detail'))}")
        add("")

    # Copertura
    add("## Copertura e limiti")
    add("")
    cov = result.coverage
    add(f"- Modalita': **{MODE_LABEL_IT.get(cov.mode or result.mode, _s(cov.mode))}**")
    add(f"- Target dichiarati: {_md_cell(', '.join(cov.targets)) if cov.targets else EMPTY}")
    add(f"- Interfacce: {_md_cell(', '.join(cov.interfaces)) if cov.interfaces else EMPTY}")
    add(f"- Pacchetti analizzati: {cov.packets_analyzed}")
    add(f"- Host scoperti: {cov.hosts_discovered} · fingerprintati: {cov.hosts_fingerprinted}")
    add(f"- Porte aperte rilevate: {cov.open_ports_found}")
    add(f"- Protocolli identificati: {_md_cell(', '.join(cov.protocols_identified)) if cov.protocols_identified else EMPTY}")
    if cov.checks_run:
        add("")
        add("Verifiche eseguite:")
        for check in cov.checks_run:
            add(f"- {check}")
    if cov.checks_skipped:
        add("")
        add("Verifiche non eseguite:")
        for item in cov.checks_skipped:
            add(f"- **{_md_cell(item.get('check'))}** — {_md_cell(item.get('reason'))}")
    if cov.limitations:
        add("")
        add("Limiti dichiarati:")
        for limitation in cov.limitations:
            add(f"- {limitation}")
    add("")
    add("> L'assenza di findings non dimostra l'assenza di vulnerabilita': un assessment e' una "
        "fotografia di una finestra temporale, non una garanzia. Le verifiche non eseguite sono "
        "elencate sopra e vanno coperte in un ciclo successivo.")
    add("")

    # Appendice
    add("## Appendice: metodologia e note legali")
    add("")
    add("- Riferimenti metodologici: NIST SP 800-82 Rev. 3, IEC 62443-3-3, ISA/IEC 62443-2-4.")
    add("- Politica di sicurezza applicata: nessuna funzione di scrittura sui protocolli di processo "
        "(Modbus FC5/6/15/16, S7 Write/Download, DNP3 Operate, IEC104 comandi, BACnet WriteProperty, "
        "PROFINET DCP Set, CIP Write) viene mai generata dal tool.")
    add("- Ogni azione di rete e' tracciata in un audit log con riferimento all'autorizzazione.")
    add(f"- Autorizzazione dichiarata: {_md_cell(result.authorization_ref)}. "
        "L'assessment e' valido solo entro la finestra e lo scope autorizzati.")
    add("- I dati contenuti in questo report sono informazioni riservate del cliente e vanno "
        "conservati secondo la policy aziendale.")
    add("")
    return "\n".join(lines)


# ── HTML ──────────────────────────────────────────────────────────────────────
_CSS = """
:root{--bg:#f7f8fa;--card:#ffffff;--text:#1c2330;--muted:#5b6676;--border:#dde2ea;
--crit:#b3261e;--high:#c2410c;--med:#a16207;--low:#2563eb;--ok:#15803d;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
font-size:14px;line-height:1.55}
.cover{background:linear-gradient(135deg,#101828,#1f3a5f);color:#fff;padding:34px 40px}
.cover h1{margin:0 0 6px;font-size:26px;letter-spacing:-.3px}
.cover .sub{color:#c7d2e0;font-size:14px}
.cover-row{display:flex;flex-wrap:wrap;gap:28px;align-items:center;justify-content:space-between}
.score{min-width:132px;text-align:center;padding:14px 18px;border-radius:12px;background:rgba(255,255,255,.1)}
.score .n{font-size:34px;font-weight:800;line-height:1}
.score .l{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#c7d2e0;margin-top:6px}
.score.good .n{color:#6ee7a8}.score.warn .n{color:#fbbf24}.score.bad .n{color:#fda4a0}
main{max-width:1180px;margin:0 auto;padding:26px 20px 60px}
section{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:22px 24px;margin-bottom:18px}
h2{font-size:18px;margin:0 0 14px;padding-bottom:8px;border-bottom:1px solid var(--border)}
h3{font-size:15px;margin:18px 0 8px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(132px,1fr));gap:12px}
.kpi{background:#f2f5f9;border-radius:10px;padding:12px 14px}
.kpi .v{font-size:24px;font-weight:700}
.kpi .k{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:12.5px}
.scroll{overflow-x:auto}
th{text-align:left;padding:8px 10px;color:var(--muted);font-weight:600;border-bottom:1px solid var(--border);white-space:nowrap}
td{padding:8px 10px;border-bottom:1px solid #eef1f5;vertical-align:top}
tr:last-child td{border-bottom:none}
code{background:#eef1f5;padding:1px 5px;border-radius:4px;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700;color:#fff}
.sev-critical{background:var(--crit)}.sev-high{background:var(--high)}
.sev-medium{background:var(--med)}.sev-low{background:var(--low)}.sev-info{background:#475569}
.finding{border:1px solid var(--border);border-left:4px solid var(--low);border-radius:10px;padding:14px 16px;margin:12px 0;background:#fcfdff}
.finding.sev-critical{border-left-color:var(--crit)}
.finding.sev-high{border-left-color:var(--high)}
.finding.sev-medium{border-left-color:var(--med)}
.finding.sev-info{border-left-color:#475569}
.finding h3{margin:0 0 6px;display:flex;gap:8px;align-items:center;flex-wrap:wrap}
dl{margin:8px 0 0;display:grid;grid-template-columns:170px 1fr;gap:6px 14px;font-size:13px}
dt{color:var(--muted);font-weight:600}
dd{margin:0}
.action{border-left:3px solid var(--ok);background:#f2fbf5;padding:10px 14px;border-radius:8px;margin:8px 0}
.action.hold{border-left-color:var(--med);background:#fffbeb}
.note{background:#f2f5f9;border-left:3px solid #94a3b8;padding:10px 14px;border-radius:8px;color:#334155}
.warn{background:#fff7ed;border-left:3px solid var(--high);padding:10px 14px;border-radius:8px}
.muted{color:var(--muted)}
footer{max-width:1180px;margin:0 auto;padding:0 20px 40px;color:var(--muted);font-size:12px}
ul{margin:8px 0;padding-left:20px}
@media print{body{background:#fff}section{break-inside:avoid;border:none;padding:0 0 14px;margin:0 0 14px}
.cover{background:#101828 !important;-webkit-print-color-adjust:exact;print-color-adjust:exact}
main,footer{max-width:none;padding:0 12px}}
"""


def _badge(severity: Any) -> str:
    sev = _sev(severity)
    return f'<span class="badge sev-{sev}">{_esc(_sev_label(sev))}</span>'


def _html_table(headers: Iterable[str], rows: Iterable[Iterable[Any]],
                empty: str = "Nessun dato.") -> str:
    rows = list(rows)
    if not rows:
        return f'<p class="muted">{_esc(empty)}</p>'
    head = "".join(f"<th>{_esc(h)}</th>" for h in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_esc(cell)}</td>" for cell in row) + "</tr>" for row in rows
    )
    return f'<div class="scroll"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def _finding_html(result: AssessmentResult, f) -> str:
    sev = _sev(f.severity)
    why = _s(f.why, "Impatto non descritto.")
    remediation = _s(f.remediation, "Da definire con il team OT.")
    rows = [
        ("Score", f"{float(f.score or 0):.1f}/10"),
        ("Categoria", _s(f.category)),
        ("Asset", _asset_label(result, f.asset_ip)),
        ("Confidenza", _s(f.confidence)),
        ("Evidenza", _s(f.evidence, "non disponibile")),
        ("Perche' conta", why),
        ("Remediation", remediation),
        ("In produzione", "si" if f.production_safe else "no — richiede fermata/manutenzione"),
    ]
    if f.mitre_ics:
        rows.append(("MITRE ATT&CK ICS", f.mitre_ics))
    if f.iec62443:
        rows.append(("IEC 62443", f.iec62443))
    if f.references:
        rows.append(("Riferimenti", ", ".join(str(r) for r in f.references)))
    dl = "".join(f"<dt>{_esc(k)}</dt><dd>{_esc(v)}</dd>" for k, v in rows)
    return (
        f'<article class="finding sev-{sev}">'
        f'<h3>{_badge(sev)} <span>{_esc(f.title)}</span></h3>'
        f"<dl>{dl}</dl></article>"
    )


def build_html(result: AssessmentResult) -> str:
    counts = result.severity_counts()
    cov = result.coverage
    score_class = _score_class(result.site_score)

    kpis = [
        ("Asset", len(result.assets)),
        ("Asset OT", len(result.ot_assets())),
        ("Critici", counts.get("critical", 0)),
        ("Alti", counts.get("high", 0)),
        ("Medi", counts.get("medium", 0)),
        ("Bassi", counts.get("low", 0)),
        ("Anomalie", len(result.anomalies)),
        ("Comandi OT", _write_node_count(result)),
    ]
    kpi_html = "".join(
        f'<div class="kpi"><div class="v">{_esc(v)}</div><div class="k">{_esc(k)}</div></div>'
        for k, v in kpis
    )

    summary_items: List[str] = [f"<li>{_esc(_summary_line(result))}</li>"]
    for finding in result.sorted_findings()[:3]:
        summary_items.append(
            f"<li>{_badge(finding.severity)} <strong>{_esc(finding.title)}</strong> — "
            f"{_esc(_asset_label(result, finding.asset_ip))}: {_esc(_s(finding.why, finding.evidence))}</li>"
        )
    if not result.findings:
        summary_items.append("<li>Nessun finding rilevato con le verifiche eseguite (vedere copertura e limiti).</li>")
    if _write_node_count(result):
        summary_items.append(
            f"<li><strong>{_write_node_count(result)} comandi di scrittura OT osservati.</strong> "
            "E' l'indicatore piu' diretto di comando malevolo o configurazione errata.</li>"
        )
    summary_items.append(
        f"<li>Punteggio di postura <strong>{result.site_score}/100</strong> "
        f"({_esc(_score_judgement(result.site_score))}).</li>"
    )

    now = [f for f in result.sorted_findings() if f.production_safe]
    later = [f for f in result.sorted_findings() if not f.production_safe]

    def action_list(items, css):
        if not items:
            return '<p class="muted">Nessuna voce in questa categoria.</p>'
        return "".join(
            f'<div class="action {css}">{_badge(f.severity)} <strong>{_esc(f.title)}</strong> '
            f'<span class="muted">({_esc(_asset_label(result, f.asset_ip))}, score {float(f.score or 0):.1f})</span>'
            f"<div>{_esc(_s(f.remediation, 'Da definire con il team OT.'))}</div></div>"
            for f in items
        )

    inventory = _html_table(
        ["IP", "MAC", "Nome", "Vendor", "Tipo", "Zona", "Purdue", "Protocolli", "Porte", "Rischio"],
        _inventory_rows(result),
        "Nessun asset osservato. In modalita' passiva serve traffico reale durante la cattura.",
    )

    findings_html = "".join(_finding_html(result, f) for f in result.sorted_findings()) or (
        '<p class="muted">Nessun finding prodotto dalle verifiche eseguite.</p>'
    )

    anomalies_html = _html_table(
        ["Severita'", "Tipo", "Titolo", "Sorgente", "Destinazione", "Evidenza"],
        [
            [_sev_label(a.severity), a.kind, a.title, a.src_ip, a.dst_ip, a.evidence]
            for a in sorted(result.anomalies, key=lambda x: (severity_rank(x.severity), x.title))
        ],
        "Nessuna anomalia di traffico rilevata nella finestra osservata.",
    )
    if _write_node_count(result):
        anomalies_html += (
            '<p class="warn"><strong>Comandi di scrittura verso il processo.</strong> '
            "Le anomalie <code>ot_write_command</code> indicano comandi capaci di muovere un attuatore: "
            "correlare con i log SCADA e con le finestre di manutenzione.</p>"
        )

    zones_rows = [
        [z.name, z.purdue_level, ", ".join(z.cidrs), z.asset_count] for z in result.zones
    ]
    zones_html = _html_table(["Zona", "Purdue", "Reti", "Asset"], zones_rows,
                             "Zone non definite nell'engagement.") if result.zones else ""
    flows = _zone_flow_summary(result)
    flows_html = _html_table(
        ["Zona sorgente", "Zona destinazione", "Flussi", "Attraversa zone"],
        [[r["src_zone"], r["dst_zone"], r["flows"], "si" if r["cross_zone"] else "no"] for r in flows],
    ) if flows else (
        '<p class="muted">Dato non disponibile in questa modalita\': la matrice dei flussi richiede '
        "una cattura passiva o la definizione delle zone.</p>"
    )

    diff = result.baseline_diff or {}
    diff_html = ""
    if diff:
        items = [f"<li>Baseline: {_esc(_s(diff.get('generated_at')))} — drift: "
                 f"{'si' if diff.get('has_drift') else 'no'}</li>"]
        for item in diff.get("new_assets", []) or []:
            items.append(f"<li>Nuovo asset: {_esc(item.get('ip'))} {_esc(item.get('label'))}</li>")
        for item in diff.get("removed_assets", []) or []:
            items.append(f"<li>Asset scomparso: {_esc(item.get('ip'))} {_esc(item.get('label'))}</li>")
        for item in diff.get("new_ports", []) or []:
            items.append(
                f"<li>Nuova porta: {_esc(item.get('ip'))} → {_esc(item.get('port'))}/{_esc(item.get('service'))}</li>"
            )
        for item in diff.get("changed_identities", []) or []:
            items.append(f"<li>Identita' cambiata: {_esc(item.get('ip'))} — {_esc(item.get('detail'))}</li>")
        diff_html = (
            "<section><h2>Variazioni rispetto alla baseline</h2>"
            f"<ul>{''.join(items)}</ul></section>"
        )

    checks_run = "".join(f"<li>{_esc(c)}</li>" for c in cov.checks_run) or "<li class='muted'>nessuna</li>"
    checks_skipped = "".join(
        f"<li><strong>{_esc(i.get('check'))}</strong> — {_esc(i.get('reason'))}</li>"
        for i in cov.checks_skipped
    ) or "<li class='muted'>nessuna</li>"
    limitations = "".join(f"<li>{_esc(item)}</li>" for item in cov.limitations) or (
        "<li class='muted'>nessuno dichiarato</li>"
    )

    return f"""<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Assessment di sicurezza industriale — {_esc(result.site)}</title>
<style>{_CSS}</style>
</head>
<body>
<header class="cover">
  <div class="cover-row">
    <div>
      <h1>Assessment di sicurezza industriale</h1>
      <div class="sub">{_esc(_s(result.site, "sito non specificato"))} · {_esc(_s(result.client, "cliente non specificato"))}</div>
      <div class="sub">Modalita': {_esc(MODE_LABEL_IT.get(result.mode, _s(result.mode)))} · ID <code>{_esc(result.id)}</code></div>
    </div>
    <div class="score {score_class}">
      <div class="n">{_esc(result.site_score)}</div>
      <div class="l">postura /100 · {_esc(_score_judgement(result.site_score))}</div>
    </div>
  </div>
</header>
<main>
  <section>
    <h2>Dati dell'incarico</h2>
    <dl>
      <dt>Cliente</dt><dd>{_esc(_s(result.client))}</dd>
      <dt>Sito / impianto</dt><dd>{_esc(_s(result.site))}</dd>
      <dt>Operatore</dt><dd>{_esc(_s(result.operator))}</dd>
      <dt>Autorizzazione</dt><dd>{_esc(_s(result.authorization_ref))}</dd>
      <dt>Inizio</dt><dd>{_esc(_s(result.started_at))}</dd>
      <dt>Fine</dt><dd>{_esc(_s(result.finished_at))}</dd>
      <dt>Durata</dt><dd>{_esc(_duration(result))}</dd>
    </dl>
  </section>

  <section>
    <h2>Sintesi esecutiva</h2>
    <div class="kpis">{kpi_html}</div>
    <ul>{''.join(summary_items)}</ul>
  </section>

  <section>
    <h2>Cosa fare subito (senza fermare la produzione)</h2>
    {action_list(now, "")}
  </section>

  <section>
    <h2>Cosa pianificare in fermata</h2>
    {action_list(later, "hold")}
  </section>

  <section>
    <h2>Inventario asset</h2>
    {inventory}
  </section>

  <section>
    <h2>Risultati dettagliati</h2>
    {findings_html}
  </section>

  <section>
    <h2>Anomalie di traffico</h2>
    {anomalies_html}
  </section>

  <section>
    <h2>Segmentazione tra zone</h2>
    {zones_html}
    {flows_html}
    <p class="note">Ogni flusso tra Purdue 3/4 e Purdue 1/2 dovrebbe attraversare un firewall
    industriale o un data diode, non uno switch condiviso.</p>
  </section>

  {diff_html}

  <section>
    <h2>Copertura e limiti</h2>
    <dl>
      <dt>Modalita'</dt><dd>{_esc(MODE_LABEL_IT.get(cov.mode or result.mode, _s(cov.mode)))}</dd>
      <dt>Target</dt><dd>{_esc(", ".join(cov.targets) if cov.targets else EMPTY)}</dd>
      <dt>Interfacce</dt><dd>{_esc(", ".join(cov.interfaces) if cov.interfaces else EMPTY)}</dd>
      <dt>Pacchetti analizzati</dt><dd>{_esc(cov.packets_analyzed)}</dd>
      <dt>Host scoperti / fingerprintati</dt><dd>{_esc(cov.hosts_discovered)} / {_esc(cov.hosts_fingerprinted)}</dd>
      <dt>Porte aperte</dt><dd>{_esc(cov.open_ports_found)}</dd>
      <dt>Protocolli</dt><dd>{_esc(", ".join(cov.protocols_identified) if cov.protocols_identified else EMPTY)}</dd>
    </dl>
    <h3>Verifiche eseguite</h3><ul>{checks_run}</ul>
    <h3>Verifiche non eseguite</h3><ul>{checks_skipped}</ul>
    <h3>Limiti dichiarati</h3><ul>{limitations}</ul>
    <p class="warn">L'assenza di findings non dimostra l'assenza di vulnerabilita': un assessment e'
    una fotografia di una finestra temporale, non una garanzia.</p>
  </section>

  <section>
    <h2>Appendice: metodologia e note legali</h2>
    <ul>
      <li>Riferimenti: NIST SP 800-82 Rev. 3, IEC 62443-3-3, ISA/IEC 62443-2-4.</li>
      <li>Politica di sicurezza: nessuna funzione di scrittura sui protocolli di processo viene mai generata
      (Modbus FC5/6/15/16, S7 Write/Download, DNP3 Operate, IEC104 comandi, BACnet WriteProperty,
      PROFINET DCP Set, CIP Write).</li>
      <li>Ogni azione di rete e' tracciata in un audit log con riferimento all'autorizzazione.</li>
      <li>Autorizzazione dichiarata: {_esc(_s(result.authorization_ref))}. L'assessment e' valido solo
      entro la finestra e lo scope autorizzati.</li>
      <li>Informazioni riservate del cliente: conservare secondo la policy aziendale.</li>
    </ul>
  </section>
</main>
<footer>Cybersecurity-AEGIS · Industrial Site Assessment · report generato il
{_esc(datetime.now().strftime('%Y-%m-%d %H:%M'))}</footer>
</body>
</html>
"""


# ── JSON e scrittura su disco ─────────────────────────────────────────────────
def build_json(result: AssessmentResult, indent: int = 2) -> str:
    return json.dumps(result.to_dict(), indent=indent, ensure_ascii=False)


def _default_basename(result: AssessmentResult) -> str:
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    ident = (result.id or "assessment").replace("/", "-").replace("\\", "-")
    return f"assessment-{ident}-{stamp}"


def write_reports(result: AssessmentResult, outdir: str, basename: str = "") -> Dict[str, str]:
    """Scrive JSON, Markdown e HTML nella cartella indicata."""
    directory = Path(outdir)
    directory.mkdir(parents=True, exist_ok=True)
    name = (basename or _default_basename(result)).strip()
    safe = "".join(ch for ch in name if ch.isalnum() or ch in "-_.") or "assessment"

    paths = {
        "json": directory / f"{safe}.json",
        "md": directory / f"{safe}.md",
        "html": directory / f"{safe}.html",
    }
    paths["json"].write_text(build_json(result), encoding="utf-8")
    paths["md"].write_text(build_markdown(result), encoding="utf-8")
    paths["html"].write_text(build_html(result), encoding="utf-8")
    return {key: str(path) for key, path in paths.items()}
