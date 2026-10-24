"""Motore di regole per l'assessment industriale.

Ogni regola produce un :class:`Finding` con:

* **gravita'** e punteggio 0-10;
* **evidenza** concreta (porta, identita', flusso, anomalia);
* **perche'** conta sul processo produttivo, non solo sulla teoria;
* **remediation** con indicazione se e' applicabile in produzione
  (``production_safe``) o richiede una fermata/manutenzione;
* riferimenti **MITRE ATT&CK for ICS** e **IEC 62443**.

Le regole non inventano CVE: quando serve una verifica esterna lo dichiarano
con ``confidence='low'`` e ``verified=False``.
"""
from __future__ import annotations

import ipaddress
import logging
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

from .dissect import CONTROL_PROTOCOLS, IT_RISKY_PORTS
from .models import (
    Anomaly,
    Asset,
    Conversation,
    Finding,
    Zone,
    severity_weight,
    stable_id,
)
from .safety import Engagement

LOGGER = logging.getLogger("aegis.site.risk")

PROTO_LABEL = {
    "modbus": "Modbus/TCP", "s7comm": "Siemens S7comm", "dnp3": "DNP3",
    "iec104": "IEC 60870-5-104", "enip": "EtherNet/IP (CIP)",
    "enip-io": "EtherNet/IP implicito", "bacnet": "BACnet/IP",
    "profinet-rt": "PROFINET RT", "profinet-dcp": "PROFINET DCP",
    "opcua": "OPC UA", "codesys": "CODESYS", "melsec": "Mitsubishi MELSEC",
    "omron-fins": "OMRON FINS", "iec61850-mms": "IEC 61850 MMS",
    "niagara-fox": "Niagara Fox", "hart-ip": "HART-IP", "redlion": "Red Lion",
}

REF_NIST = "NIST SP 800-82 Rev.3 — Guide to OT Security"
REF_62443 = "IEC 62443-3-3 — System security requirements"
REF_PURDUE = "ISA/IEC 62443-3-2 — Zone and conduit partitioning"


@dataclass
class RuleContext:
    assets: List[Asset] = field(default_factory=list)
    conversations: List[Conversation] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)
    engagement: Engagement = field(default_factory=Engagement)
    zones: List[Zone] = field(default_factory=list)
    baseline_diff: Dict[str, Any] = field(default_factory=dict)
    broadcast_ratio: float = 0.0
    protocols: Dict[str, int] = field(default_factory=dict)

    def by_ip(self, ip: str) -> Optional[Asset]:
        for asset in self.assets:
            if asset.ip == ip:
                return asset
        return None

    @property
    def ot_assets(self) -> List[Asset]:
        return [a for a in self.assets if a.is_ot]

    def ot_zone_assets(self) -> List[Asset]:
        """Asset in zona di controllo (Purdue 0-2) o classificati OT."""
        return [a for a in self.assets if a.is_ot or a.purdue_level in (1, 2)]


class RiskEngine:
    """Applica tutte le regole e calcola il rischio per asset e per sito."""

    RULES = [
        "ot_protocol_exposure", "ot_write_capability", "engineering_access",
        "it_services_in_ot", "cleartext_management", "snmp_default_community",
        "unauthenticated_hmi", "eol_operating_system", "firmware_unknown",
        "ot_internet_egress", "ot_write_observed", "arp_spoofing",
        "unauthorized_discovery", "zone_violation", "dns_tunneling",
        "flat_network", "baseline_drift", "broadcast_storm", "unknown_ot_assets",
        "opcua_security", "duplicate_addressing",
    ]

    def __init__(self, engagement: Optional[Engagement] = None) -> None:
        self.engagement = engagement or Engagement()

    # ── API ─────────────────────────────────────────────────────────────────
    def evaluate(self, assets: List[Asset], conversations: Optional[List[Conversation]] = None,
                 anomalies: Optional[List[Anomaly]] = None,
                 zones: Optional[List[Zone]] = None,
                 baseline_diff: Optional[Dict[str, Any]] = None,
                 broadcast_ratio: float = 0.0,
                 protocols: Optional[Dict[str, int]] = None) -> List[Finding]:
        ctx = RuleContext(
            assets=assets,
            conversations=conversations or [],
            anomalies=anomalies or [],
            engagement=self.engagement,
            zones=zones or [],
            baseline_diff=baseline_diff or {},
            broadcast_ratio=broadcast_ratio,
            protocols=protocols or {},
        )
        findings: List[Finding] = []
        for rule in (
            self._ot_protocol_exposure, self._ot_write_capability, self._engineering_access,
            self._it_services_in_ot, self._cleartext_management, self._snmp_default_community,
            self._unauthenticated_hmi, self._eol_operating_system, self._firmware_unknown,
            self._ot_internet_egress, self._ot_write_observed, self._arp_spoofing,
            self._unauthorized_discovery, self._zone_violation, self._dns_tunneling,
            self._flat_network, self._baseline_drift, self._broadcast_storm,
            self._unknown_ot_assets, self._opcua_security, self._duplicate_addressing,
        ):
            try:
                findings.extend(rule(ctx))
            except Exception as exc:  # una regola difettosa non deve fermare l'assessment
                LOGGER.error("regola %s fallita: %s", getattr(rule, "__name__", rule), exc)

        unique: Dict[str, Finding] = {}
        for finding in findings:
            unique.setdefault(finding.id, finding)
        result = sorted(unique.values(),
                        key=lambda f: (-severity_weight(f.severity), -f.score))
        self.score_assets(assets, result)
        return result

    @staticmethod
    def score_assets(assets: List[Asset], findings: Iterable[Finding]) -> None:
        by_ip: Dict[str, float] = {}
        for finding in findings:
            if not finding.asset_ip:
                continue
            by_ip[finding.asset_ip] = max(by_ip.get(finding.asset_ip, 0.0),
                                          severity_weight(finding.severity))
        for asset in assets:
            asset.risk_score = int(round(by_ip.get(asset.ip, 0.0)))

    # ── helper ──────────────────────────────────────────────────────────────
    @staticmethod
    def _finding(rule: str, title: str, severity: str, score: float, asset: Optional[Asset] = None,
                 category: str = "exposure", evidence: str = "", why: str = "",
                 remediation: str = "", production_safe: bool = False,
                 mitre: str = "", iec: str = "", confidence: str = "high",
                 references: Optional[List[str]] = None,
                 asset_label: str = "", verified: bool = False) -> Finding:
        ip = asset.ip if asset else ""
        if asset and not asset_label:
            asset_label = asset.hostname or asset.model or asset.vendor or asset.ip
        return Finding(
            id=stable_id(rule, ip, title),
            title=title,
            severity=severity,
            score=round(float(score), 1),
            asset_ip=ip,
            asset_label=asset_label,
            category=category,
            evidence=evidence,
            why=why,
            remediation=remediation,
            production_safe=production_safe,
            mitre_ics=mitre,
            iec62443=iec,
            confidence=confidence,
            references=references or [],
            verified=verified,
        )

    @staticmethod
    def _open_ports(asset: Asset) -> Dict[int, str]:
        return {p.port: p.service for p in asset.ports if p.state == "open"}

    # ── regole ──────────────────────────────────────────────────────────────
    def _ot_protocol_exposure(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for asset in ctx.ot_zone_assets():
            if not asset.is_ot:
                continue  # un client SCADA che parla Modbus non e' un device esposto
            control_protos = [p for p in asset.protocols if p in CONTROL_PROTOCOLS]
            if not control_protos:
                continue
            proto = control_protos[0]
            label = PROTO_LABEL.get(proto, proto)
            severity = "critical" if asset.purdue_level <= 1 else "high"
            ports = ", ".join(str(p.port) for p in asset.ports if p.state == "open") or "da traffico passivo"
            out.append(self._finding(
                rule="ot_protocol_exposure",
                title=f"{label} esposto senza autenticazione",
                severity=severity, score=9.1 if severity == "critical" else 7.6,
                asset=asset, category="exposure",
                evidence=f"protocol={proto}; porte/contesto={ports}; zona={asset.zone or 'non classificata'}",
                why=(
                    f"{label} non prevede autenticazione ne' cifratura: chiunque raggiunga "
                    f"l'asset puo' leggere e spesso scrivere variabili di processo. "
                    f"Un errore di configurazione o un host infetto nella stessa VLAN "
                    f"diventa un comando diretto sull'impianto."
                ),
                remediation=(
                    "1) Mappare i conduit necessari (chi deve parlare con questo asset). "
                    "2) Applicare ACL/firewall industriale con default-deny tra IT e OT. "
                    "3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. "
                    "4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di "
                    "protezione, disable PUT/GET) come da manuale del costruttore."
                ),
                production_safe=False,
                mitre="T0836 (Modify Parameter) / T0855 (Unauthorized Command Message)",
                iec="IEC 62443-3-3 SR 1.1, SR 3.1, SR 5.1",
                references=[REF_NIST, REF_62443, REF_PURDUE],
                confidence="high" if asset.identities else "medium",
            ))
        return out

    def _ot_write_capability(self, ctx: RuleContext) -> List[Finding]:
        """Un device che accetta scritture e' un attuatore raggiungibile."""
        out: List[Finding] = []
        for asset in ctx.ot_zone_assets():
            ports = self._open_ports(asset)
            writable = [p for p in (502, 102, 2404, 20000, 44818, 2222, 47808) if p in ports]
            if not writable:
                continue
            out.append(self._finding(
                rule="ot_write_capability",
                title="Canale di scrittura verso il processo raggiungibile",
                severity="high", score=8.2, asset=asset, category="exposure",
                evidence=f"porte scrivibili: {', '.join(map(str, writable))}",
                why=(
                    "Questi protocolli permettono di scrivere coil/registri, scaricare "
                    "programmi o azionare uscite. Non serve un exploit: basta un client "
                    "Modbus/S7 per fermare una linea."
                ),
                remediation=(
                    "Immediato e non invasivo: abilitare il logging dei comandi di scrittura "
                    "su mirror port e correlarli con il MES/SCADA (chi scrive, quando, su quale "
                    "indirizzo). Strutturale, in fermata: ACL di sola lettura dove il processo "
                    "lo consente, separazione delle reti di programmazione."
                ),
                production_safe=True,
                mitre="T0855 (Unauthorized Command Message)",
                iec="IEC 62443-3-3 SR 3.1, SR 6.1",
                references=[REF_NIST, REF_62443],
            ))
        return out

    def _engineering_access(self, ctx: RuleContext) -> List[Finding]:
        """Programmazione PLC raggiungibile da host fuori dalla zona engineering."""
        out: List[Finding] = []
        eng_ports = {102: "S7comm", 2455: "CODESYS", 44818: "EtherNet/IP CIP", 4840: "OPC UA"}
        for asset in ctx.assets:
            ports = self._open_ports(asset)
            hit = [p for p in eng_ports if p in ports]
            if not hit:
                continue
            if asset.purdue_level not in (3, 4) and not asset.is_ot:
                continue
            if asset.purdue_level >= 3:
                continue  # un EWS in zona 3 ha legittimamente accesso in alcuni impianti
            sources = self._sources_of(ctx, asset.ip, set(hit))
            risky_sources = [s for s in sources
                             if (ctx.by_ip(s) and (ctx.by_ip(s).purdue_level >= 3
                                                   or not ctx.by_ip(s).is_ot))]
            if not risky_sources:
                continue
            out.append(self._finding(
                rule="engineering_access",
                title="Accesso di programmazione PLC da rete non dedicata",
                severity="high", score=8.4, asset=asset, category="segmentation",
                evidence=f"porte {', '.join(map(str, hit))}; sorgenti non-engineering: "
                         f"{', '.join(risky_sources[:5])}",
                why=(
                    "Le porte di programmazione permettono download di logica e stop del "
                    "controllore. Devono essere raggiungibili solo dalla rete di engineering "
                    "(Purdue 3) e solo durante le finestre di manutenzione."
                ),
                remediation=(
                    "Creare una VLAN di engineering con accesso temporaneo (jump host + MFA) "
                    "e regole firewall che consentono la programmazione solo da quegli host. "
                    "Attivare l'audit dei download sul PLC dove disponibile."
                ),
                production_safe=False,
                mitre="T0843 (Program Download)",
                iec="IEC 62443-3-3 SR 5.1, SR 5.2",
                references=[REF_62443, REF_PURDUE],
            ))
        return out

    @staticmethod
    def _sources_of(ctx: RuleContext, dst_ip: str, ports: set) -> List[str]:
        sources: Counter = Counter()
        for conv in ctx.conversations:
            if conv.dst_ip == dst_ip and (conv.dst_port in ports or conv.ot_protocol):
                sources[conv.src_ip] += conv.packets
        return [ip for ip, _ in sources.most_common(10)]

    def _it_services_in_ot(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        labels = {21: "FTP", 23: "Telnet", 135: "MS-RPC", 139: "NetBIOS", 445: "SMB",
                  3389: "RDP", 5900: "VNC", 5985: "WinRM", 1433: "SQL Server",
                  3306: "MySQL", 27017: "MongoDB", 6379: "Redis"}
        for asset in ctx.ot_zone_assets():
            ports = self._open_ports(asset)
            exposed = [p for p in ports if p in IT_RISKY_PORTS]
            if not exposed:
                continue
            names = ", ".join(f"{labels.get(p, p)}:{p}" for p in sorted(exposed))
            out.append(self._finding(
                rule="it_services_in_ot",
                title="Servizi IT ad alto rischio in zona di processo",
                severity="critical" if any(p in (23, 445) for p in exposed) else "high",
                score=8.8 if any(p in (23, 445) for p in exposed) else 7.2,
                asset=asset, category="hardening",
                evidence=f"servizi esposti: {names}",
                why=(
                    "Telnet, FTP e SMB trasmettono credenziali in chiaro e sono i vettori "
                    "principali di ransomware che poi si propaga ai PLC. Un HMI Windows "
                    "infetto puo' fermare la linea anche se il PLC e' sano."
                ),
                remediation=(
                    "Disabilitare i servizi non necessari (prima su un asset pilota, in "
                    "finestra di manutenzione), sostituire Telnet/FTP con SSH/SFTP, "
                    "applicare SMB signing e disabilitare SMBv1, limitare RDP a un jump host."
                ),
                production_safe=False,
                mitre="T1021 (Remote Services) / T1210 (Exploitation of Remote Services)",
                iec="IEC 62443-3-3 SR 1.5, SR 4.1, SR 7.6",
                references=[REF_NIST, REF_62443],
            ))
        return out

    def _cleartext_management(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for asset in ctx.assets:
            ports = self._open_ports(asset)
            if not (80 in ports or 8080 in ports):
                continue
            identity = asset.identities.get("http-80") or asset.identities.get("http-8080") or {}
            if identity.get("product"):
                continue  # gia' coperto da _unauthenticated_hmi
            if asset.purdue_level not in (1, 2, 3) and not asset.is_ot:
                continue
            out.append(self._finding(
                rule="cleartext_management",
                title="Interfaccia web di management in chiaro",
                severity="medium", score=5.4, asset=asset, category="hardening",
                evidence=f"HTTP su porta {80 if 80 in ports else 8080}, senza TLS",
                why=(
                    "Credenziali e configurazione transitano in chiaro: chiunque faccia "
                    "port mirroring o ARP spoofing sulla VLAN le cattura."
                ),
                remediation="Abilitare HTTPS sul device (o pubblicare dietro reverse proxy TLS) "
                            "e disabilitare l'accesso HTTP in chiaro.",
                production_safe=False,
                mitre="T1040 (Network Sniffing)",
                iec="IEC 62443-3-3 SR 4.1",
                references=[REF_62443],
                confidence="medium",
            ))
        return out

    def _snmp_default_community(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for asset in ctx.assets:
            identity = asset.identities.get("snmp") or {}
            community = str(identity.get("community", ""))
            if community not in ("public", "private"):
                continue
            out.append(self._finding(
                rule="snmp_default_community",
                title=f"Community SNMP di default ({community})",
                severity="high", score=7.0, asset=asset, category="credentials",
                evidence=f"sysDescr='{identity.get('sys_descr','')[:120]}'",
                why=(
                    "Con la community di default si leggono configurazione, tabelle ARP, "
                    "interfacce e a volte si scrive la configurazione dello switch: un "
                    "attaccante puo' ridisegnare la rete senza toccare il PLC."
                ),
                remediation="Passare a SNMPv3 (auth+priv) o almeno cambiare community e "
                            "limitarla agli IP del monitoraggio. Verificare prima quale "
                            "sistema di supervisione usa la community attuale.",
                production_safe=False,
                mitre="T1602 (Data from Configuration Repository)",
                iec="IEC 62443-3-3 SR 1.1, SR 4.1",
                references=[REF_62443],
                confidence="high", verified=True,
            ))
        return out

    def _unauthenticated_hmi(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for asset in ctx.assets:
            for key, identity in asset.identities.items():
                if not key.startswith("http"):
                    continue
                if identity.get("auth_required"):
                    continue
                product = identity.get("product")
                status = str(identity.get("status_line", ""))
                if not status.startswith("HTTP/1.1 200") and not status.startswith("HTTP/1.0 200"):
                    continue
                if not product and not identity.get("login_page"):
                    continue
                out.append(self._finding(
                    rule="unauthenticated_hmi",
                    title="HMI/web server accessibile senza autenticazione",
                    severity="critical", score=9.4, asset=asset, category="access-control",
                    evidence=f"{status}; product={product or 'sconosciuto'}; title={identity.get('title','')}",
                    why=(
                        "Una pagina di supervisione aperta permette di vedere stati di "
                        "processo e, su molte HMI, di comandare pompe/valvole dal browser. "
                        "E' anche il bersaglio preferito di chi cerca accesso iniziale in OT."
                    ),
                    remediation=(
                        "Abilitare l'autenticazione nativa o pubblicare l'HMI dietro un "
                        "reverse proxy con login e ACL. Nel frattempo limitare l'accesso "
                        "alla sola rete di supervisione."
                    ),
                    production_safe=False,
                    mitre="T0812 (Default Credentials) / T0826 (Loss of Availability)",
                    iec="IEC 62443-3-3 SR 1.1, SR 1.2, SR 2.1",
                    references=[REF_NIST, REF_62443],
                ))
        return out

    def _eol_operating_system(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        eol_markers = [
            ("windows xp", "Windows XP"), ("windows 2003", "Windows Server 2003"),
            ("windows 2000", "Windows 2000"), ("windows nt 5", "Windows NT 5.x"),
            ("windows 7", "Windows 7"), ("windows server 2008", "Windows Server 2008"),
            ("windows vista", "Windows Vista"), ("windows 8.1", "Windows 8.1"),
            ("linux 2.6", "kernel Linux 2.6"),
        ]
        for asset in ctx.assets:
            haystack = " ".join([
                str(asset.identities.get("snmp", {}).get("sys_descr", "")),
                str(asset.identities.get("http-80", {}).get("server", "")),
                str(asset.identities.get("http-443", {}).get("server", "")),
                asset.model or "",
            ]).lower()
            for needle, label in eol_markers:
                if needle in haystack:
                    out.append(self._finding(
                        rule="eol_operating_system",
                        title=f"Sistema operativo fuori supporto ({label})",
                        severity="high", score=8.0, asset=asset, category="lifecycle",
                        evidence=f"fingerprint: {haystack[:160]}",
                        why=(
                            "Un sistema fuori supporto non riceve patch: ogni vulnerabilita' "
                            "pubblica resta sfruttabile. In OT questi host sono spesso HMI o "
                            "server di supervisione, quindi il compromesso arriva vicino al PLC."
                        ),
                        remediation=(
                            "Pianificare migrazione/upgrade in fermata. Nel frattempo: "
                            "isolamento di rete, nessun accesso Internet, backup immagine, "
                            "application allow-listing e monitoraggio dei processi."
                        ),
                        production_safe=False,
                        mitre="T1210 (Exploitation of Remote Services)",
                        iec="IEC 62443-3-3 SR 3.2, SR 7.6",
                        references=[REF_NIST],
                        confidence="medium",
                    ))
                    break
        return out

    def _firmware_unknown(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for asset in ctx.ot_assets:
            if asset.model and not asset.firmware:
                out.append(self._finding(
                    rule="firmware_unknown",
                    title="Firmware non determinato: verifica bollettini del costruttore",
                    severity="low", score=3.0, asset=asset, category="lifecycle",
                    evidence=f"modello rilevato: {asset.model}",
                    why=(
                        "Senza versione firmware non e' possibile correlare le vulnerabilita' "
                        "pubblicate dal costruttore. Non e' un problema in se', ma un buco "
                        "informativo che va chiuso."
                    ),
                    remediation="Leggere la versione dal web server diagnostico o dal manuale e "
                                "confrontarla con il bollettino di sicurezza del vendor.",
                    production_safe=True,
                    iec="IEC 62443-2-3 (patch management)",
                    references=["Siemens ProductCERT", "Rockwell Security Advisory index",
                                "Schneider Electric Security Notices", "ABB Cyber Security Alerts"],
                    confidence="high",
                ))
        return out

    def _ot_internet_egress(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for anomaly in ctx.anomalies:
            if anomaly.kind != "ot_internet_egress":
                continue
            asset = ctx.by_ip(anomaly.src_ip)
            out.append(self._finding(
                rule="ot_internet_egress",
                title="Asset industriale con traffico verso Internet",
                severity="critical", score=9.7, asset=asset,
                category="malware", evidence=anomaly.evidence,
                why=(
                    "Nessun PLC/HMI deve avere egress diretto. Questo pattern e' compatibile "
                    "con C2 di malware, esfiltrazione di dati di processo o un doppio NIC "
                    "che bypassa la segmentazione."
                ),
                remediation=(
                    "Bloccare subito l'egress a firewall (azione normalmente non invasiva), "
                    "identificare il processo che genera il traffico, acquisire memoria/rete "
                    "dell'host prima di spegnerlo, poi analisi DFIR."
                ),
                production_safe=True,
                mitre="T0885 (Commonly Used Port) / T1041 (Exfiltration Over C2 Channel)",
                iec="IEC 62443-3-3 SR 5.1, SR 5.2",
                references=[REF_NIST],
                confidence="medium",
                asset_label=anomaly.src_ip,
            ))
        return out

    def _ot_write_observed(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for anomaly in ctx.anomalies:
            if anomaly.kind != "ot_write_command":
                continue
            asset = ctx.by_ip(anomaly.dst_ip)
            out.append(self._finding(
                rule="ot_write_observed",
                title="Comando di scrittura OT osservato sul traffico",
                severity="critical", score=9.9, asset=asset, category="malware",
                evidence=f"{anomaly.evidence}; {anomaly.src_ip} -> {anomaly.dst_ip}",
                why=(
                    "Un comando di scrittura puo' essere legittimo (operatore, SCADA) o "
                    "malevolo (malware, insider, tool di test). Va attribuito: chi lo ha "
                    "inviato, da quale postazione, in quale finestra temporale. E' il segnale "
                    "piu' diretto di manipolazione del processo."
                ),
                remediation=(
                    "Correlare con il turno di produzione e i log del SCADA. Se non "
                    "attribuibile: isolare la sorgente, acquisire evidenze, verificare lo "
                    "stato fisico degli attuatori. Implementare allow-list degli host "
                    "autorizzati a scrivere (firewall industriale con deep packet inspection)."
                ),
                production_safe=True,
                mitre="T0855 (Unauthorized Command Message) / T0836 (Modify Parameter)",
                iec="IEC 62443-3-3 SR 3.1, SR 6.1",
                references=[REF_NIST, REF_62443],
                confidence="high",
                asset_label=anomaly.dst_ip or anomaly.src_ip,
            ))
        return out

    def _arp_spoofing(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for anomaly in ctx.anomalies:
            if anomaly.kind != "arp_conflict":
                continue
            out.append(self._finding(
                rule="arp_spoofing",
                title="Conflitto ARP / possibile man-in-the-middle",
                severity="critical", score=9.0, asset=ctx.by_ip(anomaly.src_ip),
                category="network-integrity", evidence=anomaly.evidence,
                why=(
                    "Due MAC per lo stesso IP possono essere un IP duplicato (errore di "
                    "configurazione) o un ARP spoofing: in entrambi i casi il traffico di "
                    "processo puo' finire all'host sbagliato."
                ),
                remediation="Identificare i due MAC sulle tabelle dei switch, correggere "
                            "l'IP duplicato o isolare la porta. Abilitare DHCP snooping e "
                            "Dynamic ARP Inspection dove possibile.",
                production_safe=False,
                mitre="T0830 (Adversary-in-the-Middle)",
                iec="IEC 62443-3-3 SR 3.1",
                references=[REF_62443],
                confidence="medium",
                asset_label=anomaly.src_ip,
            ))
        return out

    def _unauthorized_discovery(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for anomaly in ctx.anomalies:
            if anomaly.kind not in ("unit_id_sweep", "modbus_exception_burst"):
                continue
            out.append(self._finding(
                rule="unauthorized_discovery",
                title="Attivita' di discovery non autorizzata verso PLC",
                severity="high", score=7.8, asset=ctx.by_ip(anomaly.src_ip),
                category="reconnaissance", evidence=anomaly.evidence or anomaly.description,
                why=(
                    "Uno sweep di unit-id o una raffica di eccezioni indica un tool che "
                    "enumera i device. Se non e' il team di automazione, e' ricognizione "
                    "preparatoria a un attacco."
                ),
                remediation="Identificare il processo/host sorgente, verificare con il team OT, "
                            "e in caso di dubbio isolare la porta di rete.",
                production_safe=True,
                mitre="T0846 (Remote System Discovery)",
                iec="IEC 62443-3-3 SR 6.1",
                references=[REF_NIST],
                confidence="high",
            ))
        return out

    def _zone_violation(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for anomaly in ctx.anomalies:
            if anomaly.kind != "zone_violation":
                continue
            out.append(self._finding(
                rule="zone_violation",
                title="Flusso di controllo tra zone Purdue diverse",
                severity="high", score=7.9, asset=ctx.by_ip(anomaly.dst_ip),
                category="segmentation", evidence=anomaly.evidence,
                why=(
                    "Un flusso che attraversa il confine IT/OT senza un conduit dichiarato "
                    "annulla la segmentazione: un ransomware nella rete office puo' "
                    "raggiungere il campo."
                ),
                remediation="Documentare o rimuovere il flusso. Se serve, creare un conduit "
                            "esplicito con firewall industriale e ispezione del protocollo.",
                production_safe=False,
                mitre="T0886 (Remote Services)",
                iec="IEC 62443-3-3 SR 5.1, SR 5.2",
                references=[REF_PURDUE, REF_62443],
                confidence="high",
            ))
        return out

    def _dns_tunneling(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for anomaly in ctx.anomalies:
            if anomaly.kind != "dns_tunnel":
                continue
            out.append(self._finding(
                rule="dns_tunneling",
                title="Possibile tunneling DNS (canale di exfiltrazione)",
                severity="high", score=8.1, asset=ctx.by_ip(anomaly.src_ip),
                category="malware", evidence=anomaly.evidence,
                why="Query DNS lunghe e ad alta entropia sono un canale C2/exfiltrazione "
                    "usato quando l'HTTP verso Internet e' bloccato.",
                remediation="Loggare tutte le query DNS, bloccare i resolver non autorizzati, "
                            "confrontare i domini con threat intelligence.",
                production_safe=True,
                mitre="T1071.004 (DNS)",
                iec="IEC 62443-3-3 SR 5.1",
                references=[REF_NIST],
                confidence="medium",
            ))
        return out

    def _flat_network(self, ctx: RuleContext) -> List[Finding]:
        """Rete piatta: molti asset OT e IT nella stessa L2."""
        out: List[Finding] = []
        subnets: Dict[str, List[Asset]] = {}
        for asset in ctx.assets:
            try:
                net = str(ipaddress.ip_network(f"{asset.ip}/24", strict=False))
            except ValueError:
                continue
            subnets.setdefault(net, []).append(asset)

        for net, members in subnets.items():
            roles = {a.purdue_level for a in members if a.purdue_level}
            has_ot = any(a.is_ot for a in members)
            has_it = any(a.purdue_level >= 3 or a.device_type in ("workstation", "server") for a in members)
            if has_ot and has_it and len(roles & {1, 2}) and len(roles & {3, 4}):
                first = members[0]
                out.append(self._finding(
                    rule="flat_network",
                    title="Rete piatta: asset IT e OT nella stessa sottorete",
                    severity="high", score=8.3, asset=first, category="segmentation",
                    evidence=f"{net}: {len(members)} asset, ruoli Purdue {sorted(roles)}",
                    why=(
                        "Senza separazione, un PC office compromesso puo' parlare "
                        "direttamente con PLC e HMI. E' la condizione che trasforma un "
                        "incidente IT in un fermo di produzione."
                    ),
                    remediation=(
                        "Definire zone e conduit (IEC 62443-3-2), creare VLAN separate per "
                        "controllo, supervisione e office, applicare un firewall industriale. "
                        "Intervento da pianificare: richiede mappa aggiornata e finestra."
                    ),
                    production_safe=False,
                    mitre="T0886 (Remote Services)",
                    iec="IEC 62443-3-3 SR 5.1, SR 5.2",
                    references=[REF_PURDUE],
                    confidence="high",
                ))
        return out

    def _baseline_drift(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        diff = ctx.baseline_diff or {}
        for asset_info in diff.get("new_assets", []) or []:
            ip = str(asset_info.get("ip", ""))
            if not ip:
                continue
            out.append(self._finding(
                rule="baseline_drift",
                title="Nuovo asset rispetto alla baseline",
                severity="medium", score=5.8, asset=ctx.by_ip(ip), category="change",
                evidence=f"ip={ip} label={asset_info.get('label','')}",
                why="Un device nuovo in rete di processo puo' essere un'installazione "
                    "legittima non documentata o un dispositivo introdotto da terzi.",
                remediation="Confermare con il responsabile di impianto entro 24h; se non "
                            "riconosciuto, isolare la porta e analizzare il traffico.",
                production_safe=True,
                iec="IEC 62443-2-1 (asset inventory)",
                references=[REF_62443],
                confidence="high",
                asset_label=ip,
            ))
        for change in diff.get("new_ports", []) or []:
            ip = str(change.get("ip", ""))
            out.append(self._finding(
                rule="baseline_drift_port",
                title=f"Nuova porta aperta ({change.get('port')}/{change.get('service','')})",
                severity="medium", score=5.6, asset=ctx.by_ip(ip), category="change",
                evidence=f"ip={ip} port={change.get('port')} service={change.get('service','')}",
                why="Una porta comparsa dopo la baseline puo' essere un servizio attivato "
                    "da remoto o un malware in ascolto.",
                remediation="Verificare l'owner del servizio, confrontare con il change "
                            "management e chiudere se non necessario.",
                production_safe=True,
                iec="IEC 62443-2-1",
                references=[REF_62443],
                confidence="high",
                asset_label=ip,
            ))
        return out

    def _broadcast_storm(self, ctx: RuleContext) -> List[Finding]:
        if ctx.broadcast_ratio < 0.15:
            return []
        return [self._finding(
            rule="broadcast_storm",
            title="Percentuale elevata di broadcast/multicast",
            severity="medium", score=4.8, category="network-integrity",
            evidence=f"broadcast ratio={ctx.broadcast_ratio:.1%}",
            why="Broadcast eccessivo riduce la banda disponibile per il traffico isocrono "
                "e puo' indicare un loop L2 o un device malfunzionante.",
            remediation="Verificare STP, loop e device che generano broadcast; abilitare "
                        "storm control sulle porte di accesso.",
            production_safe=True,
            iec="IEC 62443-3-3 SR 7.1",
            references=[REF_62443],
            confidence="medium",
            asset_label="rete L2",
        )]

    def _unknown_ot_assets(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        unknown = [a for a in ctx.ot_assets if not a.vendor and not a.identities]
        if not unknown:
            return out
        out.append(self._finding(
            rule="unknown_ot_assets",
            title="Asset OT non identificati (censimento incompleto)",
            severity="low", score=3.4, category="inventory",
            evidence=f"{len(unknown)} asset su {len(ctx.ot_assets)} senza vendor/identita': "
                     f"{', '.join(a.ip for a in unknown[:8])}",
            why="Senza vendor e modello non si possono valutare firmware, vulnerabilita' "
                "note e fine supporto. Un inventario incompleto e' il primo rischio "
                "gestionale in un audit IEC 62443.",
            remediation="Completare il censimento con il registro asset di impianto, "
                        "foto targhette e documentazione di commessa; ripetere poi "
                        "l'assessment per arricchire le identita'.",
            production_safe=True,
            iec="IEC 62443-2-1, SR 7.8",
            references=[REF_62443],
            confidence="high",
            asset_label="inventario",
        ))
        return out

    def _opcua_security(self, ctx: RuleContext) -> List[Finding]:
        out: List[Finding] = []
        for asset in ctx.assets:
            identity = asset.identities.get("opcua") or {}
            if not identity:
                continue
            out.append(self._finding(
                rule="opcua_security",
                title="Verificare la security policy OPC UA",
                severity="medium", score=5.2, asset=asset, category="access-control",
                evidence=f"endpoint={identity.get('endpoint','')}",
                why="OPC UA supporta cifratura e autenticazione, ma molte installazioni "
                    "usano SecurityPolicy None con accesso anonimo: il canale diventa "
                    "equivalente a un protocollo OT legacy.",
                remediation="Interrogare gli endpoint (client OPC UA) e disabilitare None/"
                            "anonymous; distribuire certificati tramite la PKI aziendale.",
                production_safe=False,
                mitre="T0822 (External Remote Services)",
                iec="IEC 62443-3-3 SR 1.1, SR 4.1",
                references=[REF_62443],
                confidence="medium",
            ))
        return out

    def _duplicate_addressing(self, ctx: RuleContext) -> List[Finding]:
        """IP duplicati osservati su MAC diverse (oltre al caso ARP)."""
        out: List[Finding] = []
        for anomaly in ctx.anomalies:
            if anomaly.kind != "duplicate_ip":
                continue
            out.append(self._finding(
                rule="duplicate_addressing",
                title="Indirizzo IP duplicato in rete di processo",
                severity="high", score=7.4, asset=ctx.by_ip(anomaly.src_ip),
                category="network-integrity", evidence=anomaly.evidence,
                why="Due device con lo stesso IP causano comandi al device sbagliato e "
                    "perdita di telemetria: rischio diretto per il processo.",
                remediation="Correggere l'indirizzamento (DHCP reservation o IP statico), "
                            "verificare la tabella ARP degli switch.",
                production_safe=False,
                iec="IEC 62443-3-3 SR 7.1",
                references=[REF_62443],
                confidence="medium",
            ))
        return out
