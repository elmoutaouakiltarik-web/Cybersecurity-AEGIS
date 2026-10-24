"""Modelli dati condivisi per AEGIS Industrial Site Assessment.

Tutto e' serializzabile in JSON: un assessment deve poter essere archiviato,
confrontato con una baseline e allegato a un report di consegna.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# ── Severita' ──────────────────────────────────────────────────────────────────
SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITIES)}


def severity_rank(severity: str) -> int:
    return SEVERITY_RANK.get(str(severity).lower(), len(SEVERITIES))


def severity_weight(severity: str) -> float:
    """Peso numerico usato per lo scoring del sito (0-100)."""
    return {
        "critical": 100.0,
        "high": 72.0,
        "medium": 40.0,
        "low": 15.0,
        "info": 2.0,
    }.get(str(severity).lower(), 0.0)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ── Osservazioni elementari ────────────────────────────────────────────────────
@dataclass
class PortObservation:
    """Porta/servizio osservato su un asset.

    ``safety_class`` distingue i canali di sola lettura dai canali di controllo:
      - readonly   : telemetria o identificazione (es. Modbus FC43, ENIP ListIdentity)
      - control    : protocollo capace di comandare il processo (es. Modbus FC6)
      - management : amministrazione IT (SSH, RDP, HTTP admin)
      - unknown    : non classificato
    """

    port: int
    proto: str = "tcp"
    service: str = ""
    state: str = "open"
    banner: str = ""
    safety_class: str = "unknown"
    evidence: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Conversation:
    """Flusso L2/L3 osservato (passivo) o verificato (attivo)."""

    src_ip: str
    dst_ip: str
    protocol: str = "tcp"
    src_port: int = 0
    dst_port: int = 0
    ot_protocol: str = ""
    packets: int = 0
    bytes: int = 0
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)

    @property
    def key(self) -> str:
        return f"{self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}/{self.protocol}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """Risultato di analisi: esposizione, debolezza o deviazione.

    ``production_safe`` indica se la remediation puo' essere applicata senza
    fermare il processo produttivo. E' il campo che rende il report utilizzabile
    in una fabbrica: separa "fix subito" da "pianifica in fermata".
    """

    id: str
    title: str
    severity: str
    score: float
    asset_ip: str = ""
    asset_label: str = ""
    category: str = "exposure"
    evidence: str = ""
    why: str = ""
    remediation: str = ""
    production_safe: bool = True
    mitre_ics: str = ""
    iec62443: str = ""
    confidence: str = "medium"
    references: List[str] = field(default_factory=list)
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["production_safe_label"] = (
            "applicabile in produzione" if self.production_safe else "richiede fermata/manutenzione"
        )
        return d


@dataclass
class Asset:
    """Asset industriale o IT osservato durante l'assessment."""

    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    device_type: str = "unknown"
    model: str = ""
    firmware: str = ""
    purdue_level: int = 0
    zone: str = ""
    protocols: List[str] = field(default_factory=list)
    ports: List[PortObservation] = field(default_factory=list)
    identities: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    observations: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=utcnow_iso)
    last_seen: str = field(default_factory=utcnow_iso)
    confidence: str = "low"
    risk_score: int = 0
    is_ot: bool = False

    def add_protocol(self, protocol: str) -> None:
        if protocol and protocol not in self.protocols:
            self.protocols.append(protocol)

    def add_port(self, obs: PortObservation) -> None:
        for existing in self.ports:
            if existing.port == obs.port and existing.proto == obs.proto:
                if obs.banner and not existing.banner:
                    existing.banner = obs.banner
                if obs.service and not existing.service:
                    existing.service = obs.service
                if obs.safety_class != "unknown":
                    existing.safety_class = obs.safety_class
                if obs.evidence and obs.evidence not in existing.evidence:
                    existing.evidence = (existing.evidence + "; " + obs.evidence).strip("; ")
                return
        self.ports.append(obs)

    def add_tag(self, tag: str) -> None:
        if tag and tag not in self.tags:
            self.tags.append(tag)

    def add_observation(self, text: str) -> None:
        if text and text not in self.observations:
            self.observations.append(text)

    def open_ports(self) -> List[int]:
        return sorted({p.port for p in self.ports if p.state == "open"})

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["open_ports"] = self.open_ports()
        return d


@dataclass
class Zone:
    """Zona di rete secondo il modello Purdue / IEC 62443."""

    name: str
    purdue_level: int = 0
    cidrs: List[str] = field(default_factory=list)
    description: str = ""
    asset_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Anomaly:
    """Evento anomalo osservato (passivo) con impatto operativo."""

    id: str
    kind: str
    severity: str
    title: str
    description: str
    src_ip: str = ""
    dst_ip: str = ""
    evidence: str = ""
    mitre_ics: str = ""
    ts: str = field(default_factory=utcnow_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Coverage:
    """Cosa e' stato verificato e cosa no: evita report fuorvianti."""

    mode: str = "readonly"
    targets: List[str] = field(default_factory=list)
    interfaces: List[str] = field(default_factory=list)
    packets_analyzed: int = 0
    hosts_discovered: int = 0
    hosts_fingerprinted: int = 0
    open_ports_found: int = 0
    protocols_identified: List[str] = field(default_factory=list)
    checks_run: List[str] = field(default_factory=list)
    checks_skipped: List[Dict[str, str]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def skip(self, check: str, reason: str) -> None:
        self.checks_skipped.append({"check": check, "reason": reason})

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AssessmentResult:
    """Risultato completo di un assessment di sito."""

    id: str
    site: str = ""
    client: str = ""
    engagement_id: str = ""
    operator: str = ""
    authorization_ref: str = ""
    mode: str = "readonly"
    started_at: str = field(default_factory=utcnow_iso)
    finished_at: str = ""
    duration_s: float = 0.0
    status: str = "pending"          # pending / running / done / error / cancelled
    error: str = ""
    assets: List[Asset] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    conversations: List[Conversation] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)
    zones: List[Zone] = field(default_factory=list)
    coverage: Coverage = field(default_factory=Coverage)
    site_score: int = 100
    engine: Dict[str, Any] = field(default_factory=dict)
    baseline_diff: Dict[str, Any] = field(default_factory=dict)

    # ── derivati ────────────────────────────────────────────────────────────
    def sorted_findings(self) -> List[Finding]:
        return sorted(
            self.findings,
            key=lambda f: (severity_rank(f.severity), -float(f.score), f.asset_ip),
        )

    def severity_counts(self) -> Dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def ot_assets(self) -> List[Asset]:
        return [a for a in self.assets if a.is_ot]

    def asset_by_ip(self, ip: str) -> Optional[Asset]:
        for a in self.assets:
            if a.ip == ip:
                return a
        return None

    def compute_site_score(self) -> int:
        """0-100, piu' alto = postura migliore.

        Il punteggio e' la media dell'esposizione per asset (0-100), non una
        somma di finding: cosi' un impianto grande non viene penalizzato solo
        per la taglia e un singolo problema critico non azzera un sito sano
        senza motivo. I finding di sito (rete piatta, broadcast) aggiungono un
        piccolo aggravante, con tetto, per evitare saturazioni.
        """
        if not self.assets:
            return 0 if self.status == "done" else 100

        by_ip: Dict[str, float] = {}
        site_wide = 0
        for finding in self.findings:
            weight = severity_weight(finding.severity) * float(finding.confidence_multiplier())
            if finding.asset_ip:
                by_ip[finding.asset_ip] = max(by_ip.get(finding.asset_ip, 0.0), weight)
            else:
                site_wide += 1

        per_asset = [min(100.0, by_ip.get(a.ip, 0.0)) for a in self.assets]
        mean_risk = sum(per_asset) / len(per_asset)
        penalty = mean_risk + min(15.0, 4.0 * site_wide)
        if self.baseline_diff.get("has_drift"):
            penalty += 5.0
        return max(0, min(100, int(round(100.0 - penalty))))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "site": self.site,
            "client": self.client,
            "engagement_id": self.engagement_id,
            "operator": self.operator,
            "authorization_ref": self.authorization_ref,
            "mode": self.mode,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration_s": round(self.duration_s, 2),
            "status": self.status,
            "error": self.error,
            "site_score": self.site_score,
            "severity_counts": self.severity_counts(),
            "assets": [a.to_dict() for a in self.assets],
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "conversations": [c.to_dict() for c in self.conversations],
            "anomalies": [a.to_dict() for a in self.anomalies],
            "zones": [z.to_dict() for z in self.zones],
            "coverage": self.coverage.to_dict(),
            "engine": self.engine,
            "baseline_diff": self.baseline_diff,
            "stats": {
                "assets": len(self.assets),
                "ot_assets": len(self.ot_assets()),
                "findings": len(self.findings),
                "anomalies": len(self.anomalies),
                "conversations": len(self.conversations),
                "critical": self.severity_counts().get("critical", 0),
                "high": self.severity_counts().get("high", 0),
            },
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, raw: Dict[str, Any]) -> "AssessmentResult":
        """Ricostruisce un risultato da JSON (usato da CLI/report/baseline)."""
        assets: List[Asset] = []
        for a in raw.get("assets", []):
            ports = [PortObservation(**{k: v for k, v in p.items() if k in PortObservation.__dataclass_fields__})
                     for p in a.get("ports", [])]
            payload = {k: v for k, v in a.items()
                       if k in Asset.__dataclass_fields__ and k != "ports"}
            assets.append(Asset(ports=ports, **payload))

        findings = [Finding(**{k: v for k, v in f.items()
                               if k in Finding.__dataclass_fields__})
                    for f in raw.get("findings", [])]
        conversations = [Conversation(**{k: v for k, v in c.items()
                                         if k in Conversation.__dataclass_fields__})
                         for c in raw.get("conversations", [])]
        anomalies = [Anomaly(**{k: v for k, v in an.items()
                                if k in Anomaly.__dataclass_fields__})
                     for an in raw.get("anomalies", [])]
        zones = [Zone(**{k: v for k, v in z.items() if k in Zone.__dataclass_fields__})
                 for z in raw.get("zones", [])]
        coverage = Coverage(**{k: v for k, v in raw.get("coverage", {}).items()
                               if k in Coverage.__dataclass_fields__})
        result = cls(
            id=raw.get("id", ""),
            site=raw.get("site", ""),
            client=raw.get("client", ""),
            engagement_id=raw.get("engagement_id", ""),
            operator=raw.get("operator", ""),
            authorization_ref=raw.get("authorization_ref", ""),
            mode=raw.get("mode", "readonly"),
            started_at=raw.get("started_at", utcnow_iso()),
            finished_at=raw.get("finished_at", ""),
            duration_s=float(raw.get("duration_s", 0.0) or 0.0),
            status=raw.get("status", "done"),
            error=raw.get("error", ""),
            assets=assets,
            findings=findings,
            conversations=conversations,
            anomalies=anomalies,
            zones=zones,
            coverage=coverage,
            site_score=int(raw.get("site_score", 0) or 0),
            engine=raw.get("engine", {}) or {},
            baseline_diff=raw.get("baseline_diff", {}) or {},
        )
        return result


# ── helper di scoring ─────────────────────────────────────────────────────────
_CONFIDENCE_MULT = {"high": 1.0, "medium": 0.8, "low": 0.55, "confirmed": 1.2}


def _confidence_multiplier(self: Finding) -> float:
    return _CONFIDENCE_MULT.get(str(self.confidence).lower(), 0.7)


# Aggancio del metodo al dataclass (evita di duplicare la logica in ogni report).
Finding.confidence_multiplier = _confidence_multiplier  # type: ignore[attr-defined]


def stable_id(*parts: str) -> str:
    """ID breve e stabile per findings/anomalie (dedup e diff tra run)."""
    digest = hashlib.sha256("|".join(str(p) for p in parts).encode("utf-8")).hexdigest()
    return digest[:12]
