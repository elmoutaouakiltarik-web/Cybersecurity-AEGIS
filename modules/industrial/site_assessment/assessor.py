"""Orchestrazione di un assessment di sito industriale.

Flusso (identico a quello che farebbe un consulente sul campo):

1. **preflight** — verifica autorizzazione, capacita' della macchina, interfacce;
2. **passivo** — analizza pcap o cattura live per N secondi (zero pacchetti inviati);
3. **discovery** — unisce gli asset visti passivamente e verifica i target autorizzati;
4. **port scan** — TCP connect con rate limit, profilo OT/IT/common/full;
5. **fingerprint** — sonde read-only sui protocolli identificati;
6. **rischio** — regole IEC 62443 / Purdue / MITRE ICS;
7. **baseline** — confronto con lo snapshot precedente;
8. **report** — JSON, Markdown, HTML.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import json
import logging
import os
import threading
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import baseline as baseline_mod
from . import fingerprint, scan
from .models import (
    Asset,
    AssessmentResult,
    Coverage,
    Zone,
    stable_id,
    utcnow_iso,
)
from .passive import PassiveAnalyzer
from .risk import RiskEngine
from .safety import (
    AuditLog,
    Engagement,
    SafetyGuard,
    ScopeViolation,
    list_interfaces,
    preflight,
)

LOGGER = logging.getLogger("aegis.site.assessor")
ENGINE_VERSION = "1.0.0"

def _default_data_dir() -> str:
    """`<repo>/data/site_assessment`, indipendente dalla cwd."""
    return str(Path(__file__).resolve().parents[3] / "data" / "site_assessment")


DEFAULT_DATA_DIR = os.getenv("AEGIS_ASSESS_DATA_DIR") or _default_data_dir()
MAX_CONCURRENT = int(os.getenv("AEGIS_ASSESS_MAX_CONCURRENT", "1"))

ZONE_NAMES = {
    0: ("Livello 0 - Processo", "Sensori e attuatori fisici"),
    1: ("Livello 1 - Controllo", "PLC, RTU, drive, I/O remoti"),
    2: ("Livello 2 - Supervisione", "HMI, SCADA locale, switch di cella"),
    3: ("Livello 3 - Operations", "Server SCADA, historian, engineering workstation"),
    4: ("Livello 4 - Enterprise", "ERP, MES, rete office"),
    5: ("Livello 5 - Esterno", "Cloud, fornitori, accesso remoto"),
}


@dataclass
class AssessmentJob:
    id: str
    engagement: Engagement
    targets: List[str] = field(default_factory=list)
    profile: str = "ot"
    pcap: str = ""
    interface: str = ""
    duration_s: float = 0.0
    deep: bool = True
    baseline_path: str = ""
    status: str = "pending"
    stage: str = "in coda"
    progress: int = 0
    error: str = ""
    created_at: str = field(default_factory=utcnow_iso)
    started_at: str = ""
    finished_at: str = ""
    result: Optional[AssessmentResult] = None
    _cancel: threading.Event = field(default_factory=threading.Event, repr=False)

    def to_dict(self, include_result: bool = False) -> Dict[str, Any]:
        payload: Dict[str, Any] = {
            "id": self.id,
            "site": self.engagement.site,
            "client": self.engagement.client,
            "mode": self.engagement.mode,
            "authorization_ref": self.engagement.authorization_ref,
            "targets": self.targets,
            "profile": self.profile,
            "status": self.status,
            "stage": self.stage,
            "progress": self.progress,
            "error": self.error,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
        }
        if include_result and self.result is not None:
            payload["result"] = self.result.to_dict()
        elif self.result is not None:
            payload["summary"] = {
                "assets": len(self.result.assets),
                "findings": len(self.result.findings),
                "site_score": self.result.site_score,
                "severity_counts": self.result.severity_counts(),
            }
        return payload


class SiteAssessor:
    """Gestisce job di assessment in background e ne conserva i risultati."""

    def __init__(self, data_dir: Optional[str] = None) -> None:
        self.data_dir = Path(data_dir or DEFAULT_DATA_DIR)
        self.jobs: "OrderedDict[str, AssessmentJob]" = OrderedDict()
        self._lock = threading.Lock()
        self._sem = threading.Semaphore(max(1, MAX_CONCURRENT))
        try:
            self.data_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            LOGGER.warning("data dir non scrivibile (%s): risultati solo in memoria", exc)

    # ── info ────────────────────────────────────────────────────────────────
    def preflight(self) -> Dict[str, Any]:
        info = preflight()
        info["engine_version"] = ENGINE_VERSION
        info["risk_rules"] = RiskEngine.RULES
        info["data_dir"] = str(self.data_dir)
        info["default_profiles"] = {k: len(v) for k, v in scan.PORT_PROFILES.items()}
        return info

    def interfaces(self) -> List[Dict[str, str]]:
        return list_interfaces()

    # ── job lifecycle ───────────────────────────────────────────────────────
    def start(self, engagement: Engagement, targets: Optional[List[str]] = None,
              profile: str = "ot", pcap: str = "", interface: str = "",
              duration_s: float = 0.0, deep: bool = True,
              baseline_path: str = "") -> AssessmentJob:
        problems = engagement.validate()
        if problems:
            raise ScopeViolation("; ".join(problems))
        if profile not in scan.PORT_PROFILES:
            raise ValueError(f"profilo sconosciuto: {profile}")
        if not pcap and not interface and engagement.mode == "passive" and not targets:
            raise ValueError(
                "modalita' passiva: indicare un file pcap o un'interfaccia da ascoltare"
            )

        job = AssessmentJob(
            id=uuid.uuid4().hex[:12],
            engagement=engagement,
            targets=targets or list(engagement.allowed_cidrs),
            profile=profile,
            pcap=pcap,
            interface=interface,
            duration_s=float(duration_s or 0.0),
            deep=deep,
            baseline_path=baseline_path,
        )
        for target in job.targets:
            ok, reason = engagement.check_target(target)
            if not ok:
                raise ScopeViolation(reason)

        with self._lock:
            self.jobs[job.id] = job
            while len(self.jobs) > 50:
                self.jobs.popitem(last=False)

        threading.Thread(target=self._run_guarded, args=(job,), daemon=True,
                         name=f"aegis-assess-{job.id}").start()
        return job

    def _run_guarded(self, job: AssessmentJob) -> None:
        with self._sem:
            self._run(job)

    def get(self, job_id: str) -> Optional[AssessmentJob]:
        with self._lock:
            return self.jobs.get(job_id)

    def latest(self) -> Optional[AssessmentJob]:
        with self._lock:
            return next(reversed(self.jobs.values()), None) if self.jobs else None

    def list(self) -> List[Dict[str, Any]]:
        with self._lock:
            return [job.to_dict(include_result=False) for job in reversed(self.jobs.values())]

    def cancel(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None:
            return False
        job._cancel.set()
        if job.status in ("pending", "running"):
            job.status = "cancelled"
            job.stage = "annullato dall'utente"
        return True

    # ── esecuzione ──────────────────────────────────────────────────────────
    def _run(self, job: AssessmentJob) -> None:
        started = time.time()
        job.status = "running"
        job.started_at = utcnow_iso()
        job.stage = "verifica autorizzazione"
        job.progress = 2

        result = AssessmentResult(
            id=job.id,
            site=job.engagement.site,
            client=job.engagement.client,
            engagement_id=stable_id(job.engagement.authorization_ref, job.engagement.site),
            operator=job.engagement.operator,
            authorization_ref=job.engagement.authorization_ref,
            mode=job.engagement.mode,
            status="running",
        )
        coverage = result.coverage
        coverage.mode = job.engagement.mode
        coverage.targets = list(job.targets)
        if job.interface:
            coverage.interfaces = [job.interface]

        guard = SafetyGuard(job.engagement, audit=AuditLog(), cancel_event=job._cancel)
        try:
            guard.require_valid_engagement()
            guard.record("assessment_start", job_id=job.id, targets=job.targets,
                         profile=job.profile, pcap=job.pcap, interface=job.interface)

            analyzer = PassiveAnalyzer(guard, job.engagement)

            # ── fase 1: passivo ────────────────────────────────────────────
            job.stage = "analisi traffico passivo"
            job.progress = 8
            if job.pcap:
                analyzer.feed_file(job.pcap)
            elif job.interface and job.duration_s > 0:
                self._capture_live(job, analyzer, guard, coverage)
            else:
                coverage.skip("cattura passiva", "nessun pcap o interfaccia indicata")

            snapshot = analyzer.finalize()
            coverage.packets_analyzed = snapshot.packets
            guard.record("passive_complete", packets=snapshot.packets,
                         assets=len(snapshot.assets), anomalies=len(snapshot.anomalies))

            assets: Dict[str, Asset] = {a.ip: a for a in snapshot.assets if a.ip}

            # ── fase 2: discovery attiva ───────────────────────────────────
            job.stage = "discovery host"
            job.progress = 22
            if job.engagement.mode == "passive":
                coverage.skip("port scan", "modalita' passiva: nessun pacchetto inviato")
                coverage.skip("fingerprint attivo", "modalita' passiva")
            else:
                self._discover(job, guard, assets)

            # ── fase 3: port scan ──────────────────────────────────────────
            if job.engagement.mode != "passive":
                job.stage = "scansione porte"
                job.progress = 35
                self._scan(job, guard, assets, coverage)
            job.progress = 70

            # ── fase 4: fingerprint ────────────────────────────────────────
            if job.engagement.mode != "passive":
                job.stage = "fingerprint protocolli industriali"
                job.progress = 72
                self._fingerprint(job, guard, assets)
            else:
                for asset in assets.values():
                    if asset.is_ot:
                        asset.confidence = "medium"

            # ── fase 5: rischio ────────────────────────────────────────────
            job.stage = "valutazione del rischio"
            job.progress = 88
            zones = self._build_zones(job.engagement, assets)
            engine = RiskEngine(job.engagement)
            findings = engine.evaluate(
                assets=list(assets.values()),
                conversations=snapshot.conversations,
                anomalies=snapshot.anomalies,
                zones=zones,
                baseline_diff={},
                broadcast_ratio=snapshot.broadcast_ratio,
                protocols=snapshot.protocol_counts,
            )

            # ── fase 6: baseline ───────────────────────────────────────────
            result.assets = sorted(assets.values(), key=lambda a: (a.purdue_level, a.ip))
            result.conversations = snapshot.conversations[:1000]
            result.anomalies = snapshot.anomalies
            result.zones = zones
            result.findings = findings
            result.baseline_diff = {}
            if job.baseline_path:
                try:
                    result.baseline_diff = baseline_mod.diff_with_file(result, job.baseline_path)
                    if result.baseline_diff.get("has_drift"):
                        # Le deviazioni diventano finding e vanno rivalutate.
                        extra = engine.evaluate(
                            assets=list(assets.values()), conversations=snapshot.conversations,
                            anomalies=snapshot.anomalies, zones=zones,
                            baseline_diff=result.baseline_diff,
                            broadcast_ratio=snapshot.broadcast_ratio,
                            protocols=snapshot.protocol_counts,
                        )
                        result.findings = extra
                except Exception as exc:
                    coverage.skip("confronto baseline", f"errore: {exc}")

            # ── chiusura ───────────────────────────────────────────────────
            coverage.hosts_discovered = len(result.assets)
            coverage.hosts_fingerprinted = sum(1 for a in result.assets if a.identities)
            coverage.open_ports_found = sum(len(a.open_ports()) for a in result.assets)
            coverage.protocols_identified = sorted({
                p for asset in result.assets for p in asset.protocols
            })
            coverage.checks_run = list(RiskEngine.RULES)
            for proto, reason in fingerprint.NO_PROBE_PROTOCOLS.items():
                if proto in coverage.protocols_identified:
                    coverage.skip(f"fingerprint {proto}", reason)
            coverage.limitations = [
                "L'assenza di finding non dimostra l'assenza di vulnerabilita': "
                "copre solo cio' che era osservabile e raggiungibile durante la finestra.",
                "Nessuna prova di exploitation e' stata eseguita (per scelta: ambiente di produzione).",
                "Le versioni firmware sono lette solo se il device le espone in modo read-only.",
            ]
            if job.engagement.mode == "readonly":
                coverage.limitations.append(
                    "Modalita' readonly: nessuna richiesta di scrittura, nessun test distruttivo."
                )

            result.engine = {
                "name": "Cybersecurity-AEGIS Site Assessment",
                "version": ENGINE_VERSION,
                "mode": job.engagement.mode,
                "profile": job.profile,
                "fingerprint_probes": list(fingerprint.PROBE_BY_PORT.values()),
                "risk_rules": list(RiskEngine.RULES),
                "capabilities": preflight(),
                "blocked_write_attempts": guard.blocked_attempts,
            }
            result.site_score = result.compute_site_score()
            result.status = "done"
            result.finished_at = utcnow_iso()
            result.duration_s = time.time() - started
            job.result = result
            job.status = "done"
            job.stage = "completato"
            job.progress = 100
            job.finished_at = result.finished_at
            guard.record("assessment_done", job_id=job.id, findings=len(result.findings),
                         score=result.site_score)
            self._persist(result)

        except ScopeViolation as exc:
            job.status = "cancelled" if job._cancel.is_set() else "error"
            job.error = str(exc)
            job.stage = "interrotto"
            result.status = job.status
            result.error = str(exc)
            result.finished_at = utcnow_iso()
            result.duration_s = time.time() - started
            job.result = result
            job.finished_at = result.finished_at
            LOGGER.warning("assessment %s interrotto: %s", job.id, exc)
        except Exception as exc:  # pragma: no cover - rete/ambiente
            job.status = "error"
            job.error = f"{type(exc).__name__}: {exc}"
            job.stage = "errore"
            result.status = "error"
            result.error = job.error
            result.finished_at = utcnow_iso()
            result.duration_s = time.time() - started
            job.result = result
            job.finished_at = result.finished_at
            LOGGER.exception("assessment %s fallito", job.id)

    # ── fasi ────────────────────────────────────────────────────────────────
    def _capture_live(self, job: AssessmentJob, analyzer: PassiveAnalyzer,
                      guard: SafetyGuard, coverage: Coverage) -> None:
        try:
            from scapy.all import sniff  # type: ignore
        except Exception:
            coverage.skip("cattura live", "scapy non installato: usare un pcap esportato")
            return

        def handle(packet) -> None:  # pragma: no cover - richiede rete reale
            try:
                analyzer.feed(bytes(packet), float(getattr(packet, "time", 0) or 0))
            except Exception:
                pass

        LOGGER.info("Cattura passiva su %s per %.0fs", job.interface, job.duration_s)
        try:
            sniff(iface=job.interface or None, timeout=job.duration_s, prn=handle,
                  store=False, filter="ip or arp or ether proto 0x88cc or ether proto 0x8892")
        except Exception as exc:
            LOGGER.warning("cattura live fallita: %s", exc)
            analyzer._anomaly(
                kind="capture_failed", severity="info",
                title="Cattura live non riuscita",
                description=(
                    f"Interfaccia {job.interface}: {exc}. Su Windows serve Npcap e "
                    f"privilegi di amministratore; in alternativa esportare un pcap."
                ),
            )

    def _discover(self, job: AssessmentJob, guard: SafetyGuard,
                  assets: Dict[str, Asset]) -> None:
        if not job.targets:
            return
        hosts: List[str] = []
        for target in job.targets:
            hosts.extend(scan.expand_targets(target, guard,
                                             limit=min(guard.engagement.max_hosts, 512)))
        known = set(assets)
        candidates = [ip for ip in hosts if ip not in known]

        def alive(ip: str) -> Optional[str]:
            if job._cancel.is_set():
                return None
            try:
                return ip if scan.host_alive(ip, guard) else None
            except ScopeViolation:
                return None

        if candidates:
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                for found in pool.map(alive, candidates):
                    if found:
                        assets[found] = Asset(ip=found, sources=["active-discovery"])
        for ip in hosts:
            if ip not in assets:
                assets[ip] = Asset(ip=ip, sources=["scope"])
        LOGGER.info("Discovery: %d host nell'ambito, %d gia' noti", len(hosts), len(known))

    def _scan(self, job: AssessmentJob, guard: SafetyGuard,
              assets: Dict[str, Asset], coverage: Coverage) -> None:
        ports = scan.ports_for_profile(job.profile)
        # Scansiona prima gli asset gia' visti (passivo) e quelli vivi.
        targets = [a for a in assets.values() if a.sources != ["scope"]]
        if not targets:
            coverage.skip("port scan", "nessun host raggiungibile")
            return

        total = max(1, len(targets))
        for index, asset in enumerate(targets):
            if job._cancel.is_set():
                raise ScopeViolation("assessment annullato")
            guard.authorize_ip(asset.ip, purpose="port-scan")

            def progress(pct: int) -> None:
                job.progress = 35 + int((index + pct / 100) / total * 35)

            observations = scan.scan_host(
                asset.ip, ports, guard, timeout=0.7, workers=12, banners=True,
                progress_cb=progress,
            )
            for obs in observations:
                asset.add_port(obs)
                asset.is_ot = asset.is_ot or obs.safety_class == "control"
            if observations:
                asset.sources.append("port-scan")
                asset.confidence = "medium"

    def _fingerprint(self, job: AssessmentJob, guard: SafetyGuard,
                     assets: Dict[str, Asset]) -> None:
        candidates = [a for a in assets.values() if a.ports or (job.deep and a.is_ot)]
        for asset in candidates:
            if job._cancel.is_set():
                raise ScopeViolation("assessment annullato")
            if not asset.ports and not asset.is_ot:
                continue
            info = fingerprint.fingerprint_asset(asset, guard, deep=job.deep)
            if info.get("attempted"):
                asset.add_observation(
                    f"sonde: {info['successful']}/{info['attempted']} con risposta"
                )
            if asset.is_ot:
                asset.add_tag("ot")

    def _build_zones(self, engagement: Engagement, assets: Dict[str, Asset]) -> List[Zone]:
        zones: List[Zone] = []
        if engagement.zones:
            for raw in engagement.zones:
                zone = Zone(
                    name=str(raw.get("name", "zona")),
                    purdue_level=int(raw.get("purdue_level", 0) or 0),
                    cidrs=list(raw.get("cidrs", [])),
                    description=str(raw.get("description", "")),
                )
                zone.asset_count = sum(
                    1 for a in assets.values() if a.zone == zone.name or _in_cidrs(a.ip, zone.cidrs)
                )
                zones.append(zone)
        else:
            by_level: Dict[int, List[Asset]] = {}
            for asset in assets.values():
                by_level.setdefault(asset.purdue_level, []).append(asset)
            for level, members in sorted(by_level.items()):
                name, description = ZONE_NAMES.get(level, ("Non classificata", ""))
                zones.append(Zone(
                    name=name if level else "Non classificata",
                    purdue_level=level,
                    cidrs=sorted({_cidr24(a.ip) for a in members}),
                    description=description,
                    asset_count=len(members),
                ))
        return zones

    # ── persistenza ─────────────────────────────────────────────────────────
    def _persist(self, result: AssessmentResult) -> None:
        try:
            path = self.data_dir / f"{result.id}.json"
            path.write_text(result.to_json(), encoding="utf-8")
            LOGGER.info("Risultato salvato in %s", path)
        except OSError as exc:
            LOGGER.warning("salvataggio risultato fallito: %s", exc)

    def load_result(self, job_id: str) -> Optional[AssessmentResult]:
        job = self.get(job_id)
        if job and job.result is not None:
            return job.result
        path = self.data_dir / f"{job_id}.json"
        if not path.exists():
            return None
        return AssessmentResult.from_dict(json.loads(path.read_text(encoding="utf-8")))


def _in_cidrs(ip: str, cidrs: List[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for cidr in cidrs:
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _cidr24(ip: str) -> str:
    try:
        return str(ipaddress.ip_network(f"{ip}/24", strict=False))
    except ValueError:
        return ip
