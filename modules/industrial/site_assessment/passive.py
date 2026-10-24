"""Analisi passiva del traffico industriale.

La modalita' passiva e' la piu' sicura per un impianto in produzione: non invia
un solo pacchetto. Osservando il traffico si ottengono comunque le informazioni
che contano davvero per un assessment:

* inventario asset con MAC, IP, hostname, vendor, ruolo e livello Purdue;
* conversazioni est-ovest e matrice di segmentazione tra zone;
* **comandi di scrittura** verso PLC/RTU (Modbus FC5/6/15/16, S7 Write,
  DNP3 Operate, IEC104 comandi, BACnet WriteProperty, PROFINET DCP Set);
* ARP spoofing / IP duplicati, sweep di unit-id, raffiche di eccezioni;
* traffico OT verso Internet (possibile C2/esfiltrazione).
"""
from __future__ import annotations

import ipaddress
import logging
import math
import threading
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

from . import dissect
from .models import (
    Anomaly,
    Asset,
    Conversation,
    PortObservation,
    stable_id,
    utcnow_iso,
)
from .safety import Engagement, SafetyGuard

LOGGER = logging.getLogger("aegis.site.passive")

# OUI principali dell'automazione industriale. Tabella volutamente corta:
# meglio "vendor sconosciuto" che un vendor sbagliato in un report.
OUI_VENDORS: Dict[str, str] = {
    "00:0e:8c": "Siemens",
    "00:1b:1b": "Siemens",
    "00:1c:06": "Siemens",
    "00:00:bc": "Rockwell/Allen-Bradley",
    "00:1d:9c": "Rockwell/Allen-Bradley",
    "00:80:f4": "Schneider Electric/Telemecanique",
    "00:00:54": "Schneider Electric/Modicon",
    "00:80:63": "Hirschmann",
    "00:90:e8": "Moxa",
    "00:a0:45": "Phoenix Contact",
    "00:30:de": "WAGO",
    "00:01:05": "Beckhoff",
    "00:1b:54": "Cisco",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "00:1b:21": "Intel",
    "00:90:7a": "HP",
    "00:11:43": "Dell",
    "00:1c:42": "Parallels",
}

_PURDUE_BY_DEVICE = {
    "plc": 1, "rtu": 1, "io-device": 1, "sensor": 1, "drive": 1,
    "hmi": 2, "panel": 2, "switch": 2, "router": 2,
    "scada": 3, "historian": 3, "ews": 3, "opcua-server": 3,
    "server": 3, "workstation": 4, "firewall": 4, "unknown": 0,
}


def vendor_from_mac(mac: str) -> str:
    return OUI_VENDORS.get((mac or "").lower()[:8], "")


def is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _ts_iso(ts: float) -> str:
    if not ts:
        return utcnow_iso()
    try:
        return datetime.fromtimestamp(ts, timezone.utc).replace(microsecond=0).isoformat()
    except (OverflowError, OSError, ValueError):
        return utcnow_iso()


@dataclass
class PassiveSnapshot:
    assets: List[Asset] = field(default_factory=list)
    conversations: List[Conversation] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    nodes: int = 0
    packets: int = 0
    bytes: int = 0
    packet_bytes: int = 0
    lldp_neighbors: List[Dict[str, Any]] = field(default_factory=list)
    dhcp_leases: List[Dict[str, Any]] = field(default_factory=list)
    broadcast_ratio: float = 0.0
    started_at: str = field(default_factory=utcnow_iso)
    finished_at: str = ""


class PassiveAnalyzer:
    """Costruisce inventario e anomalie da frame catturati o da file pcap."""

    def __init__(self, guard: Optional[SafetyGuard] = None,
                 engagement: Optional[Engagement] = None) -> None:
        self.guard = guard
        self.engagement = engagement or (guard.engagement if guard else Engagement())
        self.assets: Dict[str, Asset] = {}
        self.conversations: Dict[str, Conversation] = {}
        self.anomalies: List[Anomaly] = []
        self._anomaly_keys: set = set()
        self.protocol_counts: Counter = Counter()
        self.ip_macs: Dict[str, Dict[str, int]] = defaultdict(Counter)
        self.unit_ids: Dict[str, set] = defaultdict(set)
        self.exception_times: Dict[str, Deque[float]] = defaultdict(lambda: deque(maxlen=200))
        self.broadcast_times: Deque[float] = deque(maxlen=5000)
        self.dns_queries: Counter = Counter()
        self.lldp_neighbors: List[Dict[str, Any]] = []
        self.dhcp_leases: List[Dict[str, Any]] = []
        self.packets = 0
        self.packet_bytes = 0
        self.broadcast_packets = 0
        self.started_at = utcnow_iso()
        self._last_ts = 0.0
        self._lock = threading.Lock()

    # ── ingestion ───────────────────────────────────────────────────────────
    def feed_file(self, path: str, max_packets: Optional[int] = None) -> int:
        from .pcap import iter_packets

        count = 0
        for ts, frame in iter_packets(path, max_packets=max_packets):
            self.feed(frame, ts)
            count += 1
            if self.guard is not None:
                self.guard.check_cancelled()
        LOGGER.info("Analizzati %d pacchetti da %s", count, path)
        return count

    def feed(self, data: bytes, ts: float = 0.0) -> None:
        frame = dissect.parse_ethernet(data, ts)
        if frame is None:
            return
        with self._lock:
            self.packets += 1
            self.packet_bytes += frame.frame_len
            if ts:
                self._last_ts = ts
            if frame.dst_mac in ("ff:ff:ff:ff:ff:ff",) or frame.dst_mac.startswith("01:"):
                self.broadcast_packets += 1
                self.broadcast_times.append(ts or self.packets)

            if frame.ethertype == 0x806:
                self._handle_arp(frame)
                return

            proto, detail = dissect.classify(frame)
            self.protocol_counts[proto] += 1

            if proto in ("lldp", "cdp"):
                self._handle_l2_discovery(frame, proto, detail)

            if not frame.is_ip():
                return

            self._learn_mac(frame.src_ip, frame.src_mac, ts)
            src = self._touch(frame.src_ip, frame.src_mac, ts)
            # Un endpoint pubblico non entra nell'inventario dell'impianto:
            # serve solo a descrivere il flusso (e l'anomalia di egress).
            dst = self._touch(frame.dst_ip, "", ts, store=not is_public_ip(frame.dst_ip))
            # Chi invia traffico OT e' un client (SCADA/EWS); chi lo riceve e'
            # il device di processo. Solo il secondo entra nell'inventario OT.
            self._apply_protocol(src, proto, source=True)
            self._apply_protocol(dst, proto)

            self._converse(frame, proto)
            self._handle_hostname_sources(frame, proto, detail, src)

            if proto in dissect.CONTROL_PROTOCOLS:
                dst.is_ot = True
                dst.add_tag("ot")
                if proto in ("modbus", "s7comm", "dnp3", "iec104", "enip", "enip-io",
                             "profinet-rt", "melsec", "omron-fins", "codesys"):
                    dst.is_ot = True

            self._detect_ot_actions(frame, proto, detail, src, dst)
            self._detect_zone_violations(frame, proto, src, dst)
            self._detect_exfiltration(frame, proto, src)
            self._detect_scanning(frame, proto, detail, src, dst)
            self._detect_dns_anomaly(frame, proto, detail)

    # ── gestione asset ──────────────────────────────────────────────────────
    def _touch(self, ip: str, mac: str, ts: float, store: bool = True) -> Asset:
        asset = self.assets.get(ip)
        if asset is None:
            asset = Asset(ip=ip, mac=mac or "", sources=["passive"])
            asset.vendor = vendor_from_mac(mac)
            zone = self.engagement.zone_for(ip)
            if zone:
                asset.zone = str(zone.get("name", ""))
                asset.purdue_level = int(zone.get("purdue_level", 0) or 0)
            asset.first_seen = _ts_iso(ts)
            if store:
                self.assets[ip] = asset
        else:
            if mac and not asset.mac:
                asset.mac = mac
                asset.vendor = asset.vendor or vendor_from_mac(mac)
        asset.last_seen = _ts_iso(ts)
        if mac and mac not in ("00:00:00:00:00:00",):
            # Il MAC sorgente piu' frequente e' quello del device.
            self._learn_mac(ip, mac, ts)
        return asset

    def _learn_mac(self, ip: str, mac: str, ts: float) -> None:
        if not mac or mac == "00:00:00:00:00:00" or mac.startswith("01:"):
            return
        if is_public_ip(ip):
            return
        counter = self.ip_macs[ip]
        counter[mac] += 1
        if len(counter) > 1 and sum(counter.values()) >= 3:
            dominant, dominant_count = counter.most_common(1)[0]
            others = [m for m in counter if m != dominant]
            if others and dominant_count >= 2:
                self._anomaly(
                    kind="arp_conflict",
                    severity="high",
                    title="Due MAC diversi per lo stesso IP (possibile ARP spoofing)",
                    description=(
                        f"L'IP {ip} e' stato visto con i MAC {', '.join(others[:3])} "
                        f"oltre a {dominant}. Puo' essere un IP duplicato o un attacco "
                        f"man-in-the-middle sulla rete di processo."
                    ),
                    src_ip=ip,
                    evidence=f"mac_dominante={dominant}; altri={','.join(others[:3])}",
                    mitre_ics="T0830 (Adversary-in-the-Middle)",
                )

    def _apply_protocol(self, asset: Asset, proto: str, source: bool = False) -> None:
        if proto in ("unknown", "arp", "dns", "dhcp", "http", "https"):
            return
        asset.add_protocol(proto)
        if not source and (proto in dissect.OT_TCP_PORTS.values()
                           or proto in dissect.OT_UDP_PORTS.values()):
            asset.is_ot = True
            asset.add_tag("ot")
        self._infer_role(asset, allow_protocol_inference=not source)

    def _infer_role(self, asset: Asset, allow_protocol_inference: bool = True) -> None:
        prots = set(asset.protocols) if allow_protocol_inference else set()
        ports = set(asset.open_ports())
        if prots & {"profinet-dcp"}:
            station = str(asset.identities.get("profinet", {}).get("station_name", ""))
            role = str(asset.identities.get("profinet", {}).get("device_role", ""))
            if role == "io-controller" or "plc" in station.lower():
                asset.device_type = "plc"
            elif role == "io-device":
                asset.device_type = asset.device_type if asset.device_type != "unknown" else "io-device"
            if asset.identities.get("profinet", {}).get("capabilities"):
                pass
        if prots & {"modbus", "s7comm", "codesys", "melsec", "omron-fins", "pcworx"}:
            asset.device_type = "plc" if asset.device_type in ("unknown", "io-device") else asset.device_type
        if "dnp3" in prots:
            asset.device_type = "rtu" if asset.device_type == "unknown" else asset.device_type
        if "enip" in prots and asset.device_type == "unknown":
            asset.device_type = "plc"
        if "opcua" in prots and asset.device_type == "unknown":
            asset.device_type = "opcua-server"
        if 3389 in ports and 445 in ports and asset.device_type == "unknown":
            asset.device_type = "workstation" if 135 in ports else "server"
        if asset.mac and asset.mac.startswith(("01:",)):
            return
        self._assign_purdue(asset)

    def _assign_purdue(self, asset: Asset) -> None:
        zone = self.engagement.zone_for(asset.ip)
        if zone:
            asset.zone = str(zone.get("name", ""))
            asset.purdue_level = int(zone.get("purdue_level", 0) or 0)
            return
        if not asset.purdue_level:
            asset.purdue_level = _PURDUE_BY_DEVICE.get(asset.device_type, 0)

    # ── ARP ─────────────────────────────────────────────────────────────────
    def _handle_arp(self, frame: dissect.Frame) -> None:
        self.protocol_counts["arp"] += 1
        self._learn_mac(frame.src_ip, frame.src_mac, frame.ts)
        src = self._touch(frame.src_ip, frame.src_mac, frame.ts)
        src.add_observation(f"ARP visto per {frame.dst_ip}")

    # ── L2 discovery ────────────────────────────────────────────────────────
    def _handle_l2_discovery(self, frame: dissect.Frame, proto: str,
                             detail: Dict[str, Any]) -> None:
        if proto == "lldp":
            ip = str(detail.get("management_ip", ""))
            name = str(detail.get("system_name", ""))
            if not ip and not name:
                return
            key = (frame.src_mac, ip, name)
            if key in {(n.get("mac"), n.get("ip"), n.get("name")) for n in self.lldp_neighbors}:
                return
            neighbor = {
                "mac": frame.src_mac,
                "ip": ip,
                "name": name,
                "description": detail.get("system_description", ""),
                "capabilities": detail.get("capabilities", []),
                "port_id": detail.get("port_id", ""),
            }
            self.lldp_neighbors.append(neighbor)
            if ip:
                asset = self._touch(ip, frame.src_mac, frame.ts)
                asset.hostname = asset.hostname or name
                asset.add_observation(f"LLDP: {name} {detail.get('system_description', '')}".strip())
                asset.confidence = "high"
                caps = detail.get("capabilities", [])
                if "bridge" in caps:
                    asset.device_type = "switch"
                elif "router" in caps:
                    asset.device_type = "router"
                self._assign_purdue(asset)
        elif proto == "cdp":
            ip = str(detail.get("management_ip", ""))
            if ip:
                asset = self._touch(ip, frame.src_mac, frame.ts)
                asset.hostname = asset.hostname or str(detail.get("device_id", ""))
                asset.device_type = asset.device_type if asset.device_type != "unknown" else "switch"
                asset.add_observation(
                    f"CDP: {detail.get('device_id','')} {detail.get('platform','')} "
                    f"{detail.get('software_version','')}".strip()
                )

    # ── conversazioni ───────────────────────────────────────────────────────
    def _converse(self, frame: dissect.Frame, proto: str) -> None:
        key = (frame.src_ip, frame.dst_ip, frame.src_port, frame.dst_port, frame.ip_proto)
        conv = self.conversations.get(str(key))
        if conv is None:
            conv = Conversation(
                src_ip=frame.src_ip, dst_ip=frame.dst_ip,
                protocol="tcp" if frame.ip_proto == 6 else "udp",
                src_port=frame.src_port, dst_port=frame.dst_port,
                ot_protocol=proto if proto in dissect.CONTROL_PROTOCOLS else "",
                first_seen=_ts_iso(frame.ts),
            )
            self.conversations[str(key)] = conv
        conv.packets += 1
        conv.bytes += frame.frame_len
        conv.last_seen = _ts_iso(frame.ts)
        if proto in dissect.CONTROL_PROTOCOLS and not conv.ot_protocol:
            conv.ot_protocol = proto

    def _handle_hostname_sources(self, frame: dissect.Frame, proto: str,
                                 detail: Dict[str, Any], src: Asset) -> None:
        if proto == "dhcp" and frame.src_port == 68 and detail.get("hostname"):
            lease = {"ip": frame.src_ip, "hostname": detail["hostname"],
                     "vendor_class": detail.get("vendor_class", ""), "ts": _ts_iso(frame.ts)}
            if lease not in self.dhcp_leases:
                self.dhcp_leases.append(lease)
            if not src.hostname:
                src.hostname = str(detail["hostname"])
                src.add_observation("hostname da DHCP")
        elif proto == "dns" and detail.get("qname"):
            qname = str(detail["qname"])
            self.dns_queries[qname] += 1
            if qname.lower().endswith(".local") or proto == "dns":
                label = qname.split(".")[0]
                if label and not src.hostname and not label.startswith("_"):
                    src.hostname = label

    # ── rilevamento azioni OT ───────────────────────────────────────────────
    def _detect_ot_actions(self, frame: dissect.Frame, proto: str,
                           detail: Dict[str, Any], src: Asset, dst: Asset) -> None:
        if not detail.get("is_write"):
            return

        label = dst.hostname or dst.vendor or dst.ip
        if proto == "modbus":
            fc = int(detail.get("function_code", 0))
            fc_names = {5: "Write Single Coil", 6: "Write Single Register",
                        15: "Write Multiple Coils", 16: "Write Multiple Registers"}
            self._anomaly(
                kind="ot_write_command",
                severity="critical",
                title=f"Comando di scrittura Modbus osservato ({fc_names.get(fc, f'FC{fc}')})",
                description=(
                    f"{src.ip} ha inviato un comando di scrittura a {label} "
                    f"(unit {detail.get('unit_id')}). Modbus non ha autenticazione: "
                    f"chiunque sulla rete puo' comandare il processo."
                ),
                src_ip=src.ip, dst_ip=dst.ip,
                evidence=(f"fc={fc} unit={detail.get('unit_id')} "
                          f"addr={detail.get('address')} qty={detail.get('quantity')}"),
                mitre_ics="T0855 (Unauthorized Command Message)",
            )
        elif proto == "s7comm":
            func = str(detail.get("function", ""))
            severity = "critical" if "Download" in func or "Stop" in func or "Control" in func else "high"
            self._anomaly(
                kind="ot_write_command",
                severity=severity,
                title=f"Comando S7 di modifica PLC osservato ({func})",
                description=(
                    f"{src.ip} ha inviato a {label} la funzione S7 '{func}'. "
                    f"Download o stop del PLC possono interrompere la produzione."
                ),
                src_ip=src.ip, dst_ip=dst.ip,
                evidence=f"function=0x{int(detail.get('function_code', 0)):02X}",
                mitre_ics="T0843 (Program Download) / T0814 (Denial of Service)",
            )
        elif proto == "dnp3":
            self._anomaly(
                kind="ot_write_command",
                severity="critical",
                title=f"Operazione di controllo DNP3 osservata ({detail.get('function')})",
                description=(
                    f"{src.ip} -> {dst.ip}: DNP3 {detail.get('function')}. "
                    f"Un operate diretto puo' azionare un interruttore o una valvola."
                ),
                src_ip=src.ip, dst_ip=dst.ip,
                evidence=f"function=0x{int(detail.get('function_code', 0)):02X}",
                mitre_ics="T0855 (Unauthorized Command Message)",
            )
        elif proto == "iec104":
            self._anomaly(
                kind="ot_write_command",
                severity="critical",
                title="Comando IEC 60870-5-104 osservato",
                description=(
                    f"{src.ip} -> {dst.ip}: ASDU type {detail.get('type_id')} "
                    f"(comando o sincronizzazione). IEC104 non autentica il mittente."
                ),
                src_ip=src.ip, dst_ip=dst.ip,
                evidence=f"type_id={detail.get('type_id')} cot={detail.get('cot')}",
                mitre_ics="T0855 (Unauthorized Command Message)",
            )
        elif proto == "bacnet":
            self._anomaly(
                kind="ot_write_command",
                severity="high",
                title="Scrittura BACnet osservata",
                description=(
                    f"{src.ip} -> {dst.ip}: WriteProperty/WritePropertyMultiple su un "
                    f"controllore di edificio/impianto."
                ),
                src_ip=src.ip, dst_ip=dst.ip,
                evidence=f"service={detail.get('service')}",
                mitre_ics="T0855 (Unauthorized Command Message)",
            )
        elif proto == "profinet-dcp":
            self._anomaly(
                kind="ot_write_command",
                severity="critical",
                title="PROFINET DCP Set osservato (rinomina/re-IP di un device)",
                description=(
                    f"{src.ip} ha inviato un DCP Set: puo' cambiare nome e indirizzo di "
                    f"un device PROFINET, scollegandolo dal controllore."
                ),
                src_ip=src.ip, dst_ip=dst.ip,
                mitre_ics="T0836 (Modify Parameter)",
            )
        elif proto == "enip":
            self._anomaly(
                kind="ot_write_command",
                severity="critical",
                title="Scrittura CIP/EtherNet-IP osservata",
                description=f"{src.ip} -> {dst.ip}: servizio CIP di scrittura tag.",
                src_ip=src.ip, dst_ip=dst.ip,
                evidence=f"cip_service=0x{int(detail.get('cip_service', 0)):02X}",
                mitre_ics="T0855 (Unauthorized Command Message)",
            )

    # ── violazioni di segmentazione ─────────────────────────────────────────
    def _detect_zone_violations(self, frame: dissect.Frame, proto: str,
                                src: Asset, dst: Asset) -> None:
        if proto not in dissect.CONTROL_PROTOCOLS:
            return
        # Traffico di controllo che parte da una zona piu' alta (IT) verso il campo.
        if src.purdue_level >= 3 and dst.purdue_level in (1, 2):
            self._anomaly(
                kind="zone_violation",
                severity="high",
                title=f"Comando {proto} dalla zona IT (Purdue {src.purdue_level}) al campo (Purdue {dst.purdue_level})",
                description=(
                    f"{src.ip} ({src.zone or 'zona IT'}) parla {proto} con {dst.ip} "
                    f"({dst.zone or 'zona campo'}). In una rete segmentata correttamente "
                    f"questo flusso dovrebbe attraversare solo un demilitarized zone/gateway."
                ),
                src_ip=src.ip, dst_ip=dst.ip,
                evidence=f"purdue {src.purdue_level}->{dst.purdue_level}",
                mitre_ics="T0886 (Remote Services)",
            )


    # ── esfiltrazione / C2 ──────────────────────────────────────────────────
    def _detect_exfiltration(self, frame: dissect.Frame, proto: str, src: Asset) -> None:
        if not is_public_ip(frame.dst_ip):
            return
        if proto in dissect.CONTROL_PROTOCOLS or src.is_ot or src.purdue_level in (0, 1, 2):
            self._anomaly(
                kind="ot_internet_egress",
                severity="critical",
                title="Traffico da asset industriale verso Internet",
                description=(
                    f"{frame.src_ip} ({src.zone or 'zona OT'}) ha comunicato con "
                    f"{frame.dst_ip}:{frame.dst_port} su Internet. Un PLC/HMI non deve "
                    f"avere egress diretto: e' il segnale tipico di C2, esfiltrazione "
                    f"o di un doppio NIC mal configurato."
                ),
                src_ip=frame.src_ip, dst_ip=frame.dst_ip,
                evidence=f"proto={proto} dport={frame.dst_port}",
                mitre_ics="T0885 (Commonly Used Port) / T1041 (Exfiltration Over C2 Channel)",
            )

    # ── scansione / probing ─────────────────────────────────────────────────
    def _detect_scanning(self, frame: dissect.Frame, proto: str,
                         detail: Dict[str, Any], src: Asset, dst: Asset) -> None:
        if proto != "modbus":
            return
        unit = detail.get("unit_id")
        if unit is not None:
            key = f"{src.ip}->{dst.ip}"
            self.unit_ids[key].add(int(unit))
            if len(self.unit_ids[key]) > 8:
                self._anomaly(
                    kind="unit_id_sweep",
                    severity="high",
                    title="Sweep di unit-id Modbus",
                    description=(
                        f"{src.ip} ha interrogato {len(self.unit_ids[key])} unit-id diversi "
                        f"su {dst.ip}. E' il comportamento tipico di un tool di discovery "
                        f"non autorizzato o di un malware che cerca PLC."
                    ),
                    src_ip=src.ip, dst_ip=dst.ip,
                    evidence=f"unit_ids={len(self.unit_ids[key])}",
                    mitre_ics="T0846 (Remote System Discovery)",
                )
                self.unit_ids[key].clear()

        if detail.get("exception"):
            key = f"{src.ip}->{dst.ip}"
            self.exception_times[key].append(frame.ts or self.packets)
            if len(self.exception_times[key]) > 40:
                self._anomaly(
                    kind="modbus_exception_burst",
                    severity="medium",
                    title="Raffica di eccezioni Modbus",
                    description=(
                        f"{src.ip} ha ricevuto oltre 40 eccezioni Modbus da {dst.ip}: "
                        f"indirizzi sbagliati, unit-id errato o scansione in corso."
                    ),
                    src_ip=src.ip, dst_ip=dst.ip,
                    mitre_ics="T0846 (Remote System Discovery)",
                )
                self.exception_times[key].clear()

    # ── DNS ─────────────────────────────────────────────────────────────────
    def _detect_dns_anomaly(self, frame: dissect.Frame, proto: str,
                            detail: Dict[str, Any]) -> None:
        if frame.dst_port != 53 or not detail.get("qname"):
            return
        qname = str(detail["qname"])
        label = qname.split(".")[0]
        if len(label) >= 32:
            entropy = _entropy(label)
            if entropy > 3.6:
                self._anomaly(
                    kind="dns_tunnel",
                    severity="high",
                    title="Possibile tunneling DNS",
                    description=(
                        f"{frame.src_ip} interroga {qname} (label ad alta entropia). "
                        f"Query cosi' lunghe e casuali sono tipiche di DNS exfiltration."
                    ),
                    src_ip=frame.src_ip, dst_ip=frame.dst_ip,
                    evidence=f"qname={qname[:80]} entropy={entropy:.2f}",
                    mitre_ics="T1071.004 (DNS)",
                )

    # ── helper ──────────────────────────────────────────────────────────────
    def _anomaly(self, kind: str, severity: str, title: str, description: str,
                 src_ip: str = "", dst_ip: str = "", evidence: str = "",
                 mitre_ics: str = "") -> None:
        key = stable_id(kind, src_ip, dst_ip, title)
        if key in self._anomaly_keys:
            return
        self._anomaly_keys.add(key)
        self.anomalies.append(Anomaly(
            id=key, kind=kind, severity=severity, title=title,
            description=description, src_ip=src_ip, dst_ip=dst_ip,
            evidence=evidence, mitre_ics=mitre_ics,
            ts=_ts_iso(self._last_ts),
        ))
        LOGGER.info("ANOMALIA %s: %s (%s -> %s)", severity, title, src_ip, dst_ip)

    def _record_observed_ports(self) -> None:
        """Trasforma i flussi TCP bidirezionali in servizi osservati.

        Non e' una scansione: se un servizio e' stato visto rispondere, la porta
        era aperta in quel momento. L'evidenza resta distinta dal port scan.
        """
        for conv in self.conversations.values():
            if conv.protocol != "tcp" or conv.packets < 2 or not conv.dst_port:
                continue
            dst = self.assets.get(conv.dst_ip)
            if dst is None:
                continue
            service = (dissect.OT_TCP_PORTS.get(conv.dst_port)
                       or dissect.IT_PORTS.get(conv.dst_port)
                       or "unknown")
            dst.add_port(PortObservation(
                port=conv.dst_port, proto="tcp", service=service, state="open",
                safety_class=_port_safety(conv.dst_port),
                evidence=f"osservato nel traffico ({conv.packets} pacchetti)",
            ))

    def finalize(self) -> PassiveSnapshot:
        self._record_observed_ports()
        for asset in self.assets.values():
            # Solo chi riceve traffico di processo viene classificato come device OT:
            # un SCADA/EWS che interroga i PLC non diventa un PLC.
            self._infer_role(asset, allow_protocol_inference=asset.is_ot)
            if asset.protocols:
                asset.confidence = "high" if asset.identities else "medium"
            zones = self.engagement.zone_for(asset.ip)
            if zones:
                asset.zone = str(zones.get("name", ""))
        total = max(1, self.packets)
        return PassiveSnapshot(
            assets=sorted(self.assets.values(), key=lambda a: a.ip),
            conversations=sorted(self.conversations.values(), key=lambda c: -c.packets),
            anomalies=self.anomalies,
            protocol_counts=dict(self.protocol_counts),
            nodes=len(self.assets),
            packets=self.packets,
            bytes=self.packet_bytes,
            packet_bytes=self.packet_bytes,
            lldp_neighbors=self.lldp_neighbors,
            dhcp_leases=self.dhcp_leases,
            broadcast_ratio=round(self.broadcast_packets / total, 4),
            started_at=self.started_at,
            finished_at=utcnow_iso(),
        )

    def flow_matrix(self) -> List[Dict[str, Any]]:
        """Matrice zone -> zone con numero di flussi (per il report)."""
        counts: Counter = Counter()
        for conv in self.conversations.values():
            src_zone = (self.assets.get(conv.src_ip).zone if self.assets.get(conv.src_ip) else "") or "non classificata"
            dst_zone = (self.assets.get(conv.dst_ip).zone if self.assets.get(conv.dst_ip) else "") or "non classificata"
            counts[(src_zone, dst_zone)] += 1
        out = []
        for (src_zone, dst_zone), count in counts.most_common():
            out.append({"src_zone": src_zone, "dst_zone": dst_zone, "flows": count,
                        "cross_zone": src_zone != dst_zone})
        return out


def _port_safety(port: int) -> str:
    if port in dissect.OT_TCP_PORTS:
        if port in (502, 102, 2404, 20000, 44818, 2222, 47808, 4840, 2455, 9600,
                    5006, 5007, 1911, 789, 5094):
            return "control"
        return "readonly"
    if port in dissect.IT_PORTS:
        return "management"
    return "unknown"


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())
