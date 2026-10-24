"""CLI per l'assessment di siti industriali.

Pensata per l'uso sul campo:

    cd modules/industrial
    python -m site_assessment preflight
    python -m site_assessment assess --site "Linea 2" --auth-ref "WO-2026-014" \\
        --target 192.168.10.0/24 --pcap cattura.pcapng
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import __version__, baseline as baseline_mod
from .assessor import AssessmentJob, SiteAssessor
from .models import AssessmentResult
from .report import write_reports
from .safety import Engagement, ScopeViolation


# ── output ───────────────────────────────────────────────────────────────────
def _c(text: str, color: str) -> str:
    if not sys.stdout.isatty() or os.getenv("NO_COLOR"):
        return text
    codes = {"red": "31", "green": "32", "yellow": "33", "cyan": "36", "bold": "1", "dim": "2"}
    return f"\033[{codes.get(color, '0')}m{text}\033[0m"


def _severity_color(severity: str) -> str:
    return {"critical": "red", "high": "yellow", "medium": "cyan", "low": "dim", "info": "dim"}.get(
        severity, "dim"
    )


def _configure_stdio() -> None:
    """Console Windows (cp1252) non digerisce i caratteri box-drawing."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except Exception:
            pass


def _print_summary(result: AssessmentResult) -> None:
    counts = result.severity_counts()
    print()
    print(_c("=" * 70, "bold"))
    print(_c(f"  ASSESSMENT {result.id} - {result.site or 'sito non specificato'}", "bold"))
    print(_c("=" * 70, "bold"))
    print(f"  Cliente        : {result.client or '-'}")
    print(f"  Autorizzazione : {result.authorization_ref}")
    print(f"  Modalita'      : {result.mode}")
    print(f"  Durata         : {result.duration_s:.1f}s")
    print(f"  Punteggio      : {result.site_score}/100 ({_score_label(result.site_score)})")
    print(f"  Asset          : {len(result.assets)} ({len(result.ot_assets())} OT)")
    print(f"  Anomalie       : {len(result.anomalies)}")
    print(f"  Finding        : {counts['critical']} critici, {counts['high']} alti, "
          f"{counts['medium']} medi, {counts['low']} bassi")
    if result.findings:
        print()
        print(_c("  Priorita' immediate:", "bold"))
        for finding in result.sorted_findings()[:8]:
            safe = "produzione" if finding.production_safe else "fermata"
            print(f"   [{_c(finding.severity.upper(), _severity_color(finding.severity)):>12}] "
                  f"{finding.title} — {finding.asset_ip or 'sito'} ({safe})")
    else:
        print()
        print(_c("  Nessun finding: verificare la copertura nel report prima di concludere.", "yellow"))
    if result.error:
        print(_c(f"  Errore: {result.error}", "red"))
    print()


def _score_label(score: int) -> str:
    if score >= 85:
        return "buono"
    if score >= 70:
        return "discreto"
    if score >= 50:
        return "critico"
    return "grave"


# ── comandi ──────────────────────────────────────────────────────────────────
def cmd_preflight(args: argparse.Namespace) -> int:
    assessor = SiteAssessor()
    info = assessor.preflight()
    if args.json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return 0
    print(_c("Preflight assessment industriale", "bold"))
    print(f"  Engine        : {info.get('version', '-')} (v{info.get('engine_version')})")
    print(f"  Piattaforma   : {info.get('platform')}")
    print(f"  Python        : {info.get('python')}")
    print(f"  Scapy         : {'sì' if info.get('scapy') else 'no'}")
    print(f"  Privilegi      : {'admin/root' if info.get('is_admin') else 'utente normale'}")
    print(f"  nmap          : {info.get('nmap') or 'non installato (opzionale)'}")
    print(f"  Cattura live  : {'disponibile' if info.get('pcap_capture') else 'non disponibile'}")
    print(f"  Data dir      : {info.get('data_dir')}")
    print(f"  Profili porte : {info.get('default_profiles')}")
    print(f"  Regole rischio: {len(info.get('risk_rules', []))}")
    print()
    print("  Interfacce:")
    for iface in info.get("interfaces", []):
        print(f"   - {iface.get('name')}: {iface.get('ip')} ({iface.get('cidr')})")
    for note in info.get("notes", []):
        print(_c(f"  nota: {note}", "yellow"))
    return 0


def cmd_interfaces(args: argparse.Namespace) -> int:
    assessor = SiteAssessor()
    data = assessor.interfaces()
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return 0
    if not data:
        print("Nessuna interfaccia IPv4 rilevata.")
        return 1
    for iface in data:
        print(f"{iface['name']:<28} {iface['ip']:<16} {iface['cidr']}")
    return 0


def cmd_assess(args: argparse.Namespace) -> int:
    allowed = args.allowed or args.target
    engagement = Engagement(
        client=args.client,
        site=args.site,
        operator=args.operator or os.getenv("USERNAME") or os.getenv("USER") or "operatore",
        authorization_ref=args.auth_ref,
        mode=args.mode,
        allowed_cidrs=list(allowed),
        excluded_ips=list(args.exclude or []),
        max_hosts=args.max_hosts,
        max_pps=args.max_pps,
        allow_public=bool(args.allow_public),
        expires_at=args.expires or "",
        zones=_load_zones(args.zones),
        notes=args.notes or "",
    )

    problems = engagement.validate()
    if problems:
        print(_c("Autorizzazione non valida:", "red"))
        for problem in problems:
            print(f"  - {problem}")
        return 2

    assessor = SiteAssessor()
    try:
        job = assessor.start(
            engagement,
            targets=list(args.target),
            profile=args.profile,
            pcap=args.pcap or "",
            interface=args.iface or "",
            duration_s=args.duration or 0.0,
            deep=not args.shallow,
            baseline_path=args.baseline or "",
        )
    except (ScopeViolation, ValueError) as exc:
        print(_c(f"Impossibile avviare l'assessment: {exc}", "red"))
        return 2

    print(_c(f"Assessment {job.id} avviato ({engagement.mode}, profilo {args.profile})", "bold"))
    result = _wait(job, assessor)
    if result is None:
        return 1

    _print_summary(result)

    if args.json:
        print(result.to_json())

    if args.out:
        paths = write_reports(result, args.out)
        print(_c("Report scritti:", "green"))
        for kind, path in paths.items():
            print(f"  {kind:<5} {path}")
        if baseline_path := args.save_baseline:
            baseline_mod.save(result, baseline_path)
            print(_c(f"Baseline salvata: {baseline_path}", "green"))

    return 0 if result.status == "done" else 1


def _wait(job: AssessmentJob, assessor: SiteAssessor) -> Optional[AssessmentResult]:
    last_stage = ""
    while job.status in ("pending", "running"):
        if job.stage != last_stage:
            print(f"  … {job.stage} ({job.progress}%)")
            last_stage = job.stage
        time.sleep(0.4)
        current = assessor.get(job.id)
        if current is not None:
            job = current

    if job.result is None:
        print(_c(f"Assessment terminato senza risultato: {job.error}", "red"))
        return None
    if job.status == "error":
        print(_c(f"Assessment fallito: {job.error}", "red"))
        return None
    return job.result


def cmd_selftest(args: argparse.Namespace) -> int:
    from .demo import demo_engagement, demo_frames
    from .passive import PassiveAnalyzer
    from .risk import RiskEngine

    engagement = demo_engagement()
    analyzer = PassiveAnalyzer(None, engagement)
    for ts, frame in demo_frames():
        analyzer.feed(frame, ts)
    snapshot = analyzer.finalize()

    result = AssessmentResult(
        id="selftest",
        site=engagement.site,
        client=engagement.client,
        operator="self-test",
        authorization_ref=engagement.authorization_ref,
        mode="passive",
        status="done",
        assets=list(snapshot.assets),
        conversations=snapshot.conversations,
        anomalies=snapshot.anomalies,
        zones=[],
    )
    result.coverage.mode = "passive"
    result.coverage.packets_analyzed = snapshot.packets
    result.coverage.hosts_discovered = len(snapshot.assets)
    result.coverage.open_ports_found = sum(len(a.open_ports()) for a in snapshot.assets)
    result.coverage.checks_run = list(RiskEngine.RULES)
    result.findings = RiskEngine(engagement).evaluate(
        list(snapshot.assets), snapshot.conversations, snapshot.anomalies,
        broadcast_ratio=snapshot.broadcast_ratio, protocols=snapshot.protocol_counts,
    )
    result.site_score = result.compute_site_score()
    result.finished_at = result.started_at

    if args.json:
        print(result.to_json())
        return 0

    _print_summary(result)
    kinds = sorted({a.kind for a in result.anomalies})
    print(_c("Anomalie rilevate (traffico sintetico):", "bold"))
    for anomaly in result.anomalies:
        print(f"  [{_c(anomaly.severity.upper(), _severity_color(anomaly.severity))}] "
              f"{anomaly.kind}: {anomaly.title}")
    expected = {"ot_write_command", "arp_conflict", "ot_internet_egress", "zone_violation"}
    missing = expected - set(kinds)
    if missing:
        print(_c(f"ATTENZIONE: self-test incompleto, mancano {sorted(missing)}", "red"))
        return 1

    if args.out:
        paths = write_reports(result, args.out, basename="demo-assessment")
        print(_c("Report demo scritti:", "green"))
        for kind, path in paths.items():
            print(f"  {kind:<5} {path}")
    print(_c("Self-test superato.", "green"))
    return 0


def cmd_baseline(args: argparse.Namespace) -> int:
    if args.action == "save":
        result = _load_result(args.result)
        path = baseline_mod.save(result, args.out)
        print(f"Baseline salvata: {path}")
        return 0
    if args.action == "diff":
        current = _load_result(args.result)
        diff = baseline_mod.diff_with_file(current, args.baseline)
        if args.json:
            print(json.dumps(diff, indent=2, ensure_ascii=False))
        else:
            print(diff.get("summary", ""))
            for item in diff.get("new_assets", []):
                print(f"  + nuovo asset  {item['ip']} ({item.get('label','')})")
            for item in diff.get("removed_assets", []):
                print(f"  - asset sparito {item['ip']}")
            for item in diff.get("new_ports", []):
                print(f"  + porta        {item['ip']}:{item['port']} ({item.get('service','')})")
            for item in diff.get("changed_identities", []):
                print(f"  ~ {item['ip']} {item['field']}: {item['before']} -> {item['after']}")
        return 0
    return 1


def cmd_report(args: argparse.Namespace) -> int:
    result = _load_result(args.result)
    paths = write_reports(result, args.out)
    for kind, path in paths.items():
        print(f"{kind:<5} {path}")
    return 0


def _load_result(path: str) -> AssessmentResult:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    return AssessmentResult.from_dict(raw)


def _load_zones(path: Optional[str]) -> List[Dict[str, Any]]:
    if not path:
        return []
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("zones", [])
    return list(data)


# ── parser ───────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="site_assessment",
        description="Cybersecurity-AEGIS — assessment sicuro di reti industriali",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("preflight", help="verifica capacita' della macchina e interfacce")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_preflight)

    p = sub.add_parser("interfaces", help="elenca le interfacce IPv4")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_interfaces)

    p = sub.add_parser("assess", help="esegue un assessment completo")
    p.add_argument("--site", required=True, help="nome impianto/linea")
    p.add_argument("--auth-ref", required=True, help="riferimento autorizzazione scritta")
    p.add_argument("--client", default="", help="cliente/proprietario")
    p.add_argument("--operator", default="", help="operatore che esegue")
    p.add_argument("--target", action="append", default=[], required=True,
                   help="IP o CIDR autorizzato (ripetibile)")
    p.add_argument("--allowed", action="append", default=[],
                   help="rete autorizzata piu' ampia del target (ripetibile)")
    p.add_argument("--exclude", action="append", default=[], help="IP/CIDR da escludere")
    p.add_argument("--mode", choices=["passive", "readonly", "active"], default="readonly")
    p.add_argument("--profile", choices=["ot", "it", "common", "full"], default="ot")
    p.add_argument("--pcap", default="", help="file pcap/pcapng da analizzare")
    p.add_argument("--iface", default="", help="interfaccia per cattura live")
    p.add_argument("--duration", type=float, default=0.0, help="secondi di cattura live")
    p.add_argument("--baseline", default="", help="baseline JSON per il confronto")
    p.add_argument("--save-baseline", default="", help="salva la baseline di questo run")
    p.add_argument("--zones", default="", help="file JSON con zone Purdue")
    p.add_argument("--out", default="", help="cartella per i report")
    p.add_argument("--json", action="store_true", help="stampa il risultato JSON")
    p.add_argument("--shallow", action="store_true", help="fingerprint solo sugli asset OT")
    p.add_argument("--max-hosts", type=int, default=512)
    p.add_argument("--max-pps", type=float, default=200.0)
    p.add_argument("--allow-public", action="store_true")
    p.add_argument("--expires", default="", help="scadenza autorizzazione (ISO-8601)")
    p.add_argument("--notes", default="")
    p.set_defaults(func=cmd_assess)

    p = sub.add_parser("selftest", help="verifica installazione su traffico sintetico")
    p.add_argument("--out", default="", help="cartella per il report demo")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_selftest)

    p = sub.add_parser("baseline", help="salva o confronta una baseline")
    p.add_argument("action", choices=["save", "diff"])
    p.add_argument("--result", required=True, help="assessment JSON")
    p.add_argument("--baseline", default="", help="baseline JSON (per diff)")
    p.add_argument("--out", default="baseline.json", help="file di output (per save)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_baseline)

    p = sub.add_parser("report", help="rigenera i report da un assessment JSON")
    p.add_argument("--result", required=True)
    p.add_argument("--out", default="reports/site-assessment")
    p.set_defaults(func=cmd_report)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except ScopeViolation as exc:
        print(_c(f"Operazione bloccata dal safety gate: {exc}", "red"))
        return 2
    except KeyboardInterrupt:
        print("\nInterrotto dall'utente.")
        return 130
    except FileNotFoundError as exc:
        print(_c(f"File non trovato: {exc}", "red"))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
