#!/usr/bin/env python3
"""Cybersecurity-AEGIS passive OT/ICS monitor.

The MVP is intentionally passive and simulation-first. It can inspect observed
traffic when Scapy is available, but it never sends industrial protocol commands.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import struct
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set

try:
    import requests  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    requests = None  # type: ignore

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore

try:
    from scapy.all import IP, TCP, UDP, Ether, sniff  # type: ignore
except ImportError:  # pragma: no cover - optional dependency
    IP = TCP = UDP = Ether = None  # type: ignore
    sniff = None  # type: ignore


LOGGER = logging.getLogger("aegis.ot")

OT_PROTOCOL_PORTS = {
    "modbus": 502,
    "dnp3": 20000,
    "iec61850_mms": 102,
    "opc_ua": 4840,
    "iec104": 2404,
    "bacnet": 47808,
    "profinet": 34964,
}

MODBUS_FUNCTION_CODES = {
    0x01: ("Read Coils", "read"),
    0x02: ("Read Discrete Inputs", "read"),
    0x03: ("Read Holding Registers", "read"),
    0x04: ("Read Input Registers", "read"),
    0x05: ("Write Single Coil", "write"),
    0x06: ("Write Single Register", "write"),
    0x0F: ("Write Multiple Coils", "write"),
    0x10: ("Write Multiple Registers", "write"),
    0x17: ("Read/Write Multiple Registers", "write"),
    0x2B: ("Encapsulated Interface Transport", "diagnostic"),
}


@dataclass
class OTAsset:
    ip: str
    mac: str = ""
    hostname: str = ""
    vendor: str = "unknown"
    device_type: str = "unknown"
    purdue_level: int = -1
    protocols: List[str] = field(default_factory=list)
    first_seen: str = field(default_factory=lambda: now_iso())
    last_seen: str = field(default_factory=lambda: now_iso())
    authorized: bool = False
    risk_score: float = 0.0


@dataclass
class OTAlert:
    id: str
    timestamp: str
    severity: str
    protocol: str
    title: str
    description: str
    source_ip: str
    destination_ip: str
    purdue_level: int
    mitre_technique_id: str
    mitre_technique_name: str
    device_type: str = "ot_device"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class OTAssetInventory:
    """Tracks assets observed in passive traffic."""

    def __init__(self, authorized_assets: Iterable[Dict[str, Any]] | None = None) -> None:
        self.assets: Dict[str, OTAsset] = {}
        self.authorized_ips: Set[str] = set()
        if authorized_assets:
            for item in authorized_assets:
                ip = str(item.get("ip", "")).strip()
                if ip:
                    self.authorized_ips.add(ip)

    def discover(self, ip: str, protocol: str, mac: str = "") -> OTAsset:
        asset = self.assets.get(ip)
        if asset is None:
            asset = OTAsset(
                ip=ip,
                mac=mac,
                vendor=lookup_vendor(mac),
                device_type=classify_device(protocol),
                purdue_level=estimate_purdue_level(protocol),
                authorized=ip in self.authorized_ips,
            )
            self.assets[ip] = asset
            LOGGER.info("discovered OT asset ip=%s protocol=%s authorized=%s", ip, protocol, asset.authorized)

        asset.last_seen = now_iso()
        if protocol and protocol not in asset.protocols:
            asset.protocols.append(protocol)
        return asset

    def all_assets(self) -> List[Dict[str, Any]]:
        return [asdict(asset) for asset in self.assets.values()]


class ModbusAnalyzer:
    """Detects simple passive Modbus anomalies."""

    def __init__(self) -> None:
        self.write_history: Dict[str, List[float]] = defaultdict(list)
        self.unit_probe_history: Dict[str, Set[int]] = defaultdict(set)

    def parse(self, payload: bytes) -> Optional[Dict[str, Any]]:
        if len(payload) < 8:
            return None
        try:
            transaction_id, protocol_id, length = struct.unpack(">HHH", payload[:6])
            unit_id = payload[6]
            function_code = payload[7]
        except struct.error:
            return None
        if protocol_id != 0 or length <= 0:
            return None
        function_name, operation = MODBUS_FUNCTION_CODES.get(function_code, ("Unknown", "unknown"))
        return {
            "transaction_id": transaction_id,
            "unit_id": unit_id,
            "function_code": function_code,
            "function_name": function_name,
            "operation": operation,
        }

    def analyze(self, src_ip: str, dst_ip: str, payload: bytes) -> List[OTAlert]:
        parsed = self.parse(payload)
        if parsed is None:
            return []

        alerts: List[OTAlert] = []
        key = f"{src_ip}->{dst_ip}"
        now = time.time()

        self.unit_probe_history[key].add(int(parsed["unit_id"]))
        if len(self.unit_probe_history[key]) > 10:
            alerts.append(
                make_alert(
                    severity="high",
                    protocol="modbus",
                    title="Modbus unit-id probing detected",
                    description=f"{src_ip} queried more than 10 Modbus unit IDs on {dst_ip}",
                    src=src_ip,
                    dst=dst_ip,
                    purdue_level=1,
                    technique_id="T0846",
                    technique_name="Remote System Discovery",
                )
            )
            self.unit_probe_history[key].clear()

        if parsed["operation"] == "write":
            recent = [ts for ts in self.write_history[key] if now - ts < 60]
            recent.append(now)
            self.write_history[key] = recent
            if len(recent) > 10:
                alerts.append(
                    make_alert(
                        severity="high",
                        protocol="modbus",
                        title="High-frequency Modbus writes",
                        description=(
                            f"{len(recent)} Modbus write operations observed in 60 seconds "
                            f"from {src_ip} to {dst_ip}; function={parsed['function_name']}"
                        ),
                        src=src_ip,
                        dst=dst_ip,
                        purdue_level=1,
                        technique_id="T0855",
                        technique_name="Unauthorized Command Message",
                    )
                )

        return alerts


class OTMonitor:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.interface = str(config.get("interface") or os.getenv("OT_MONITOR_INTERFACE") or "eth0")
        self.orchestrator_url = str(
            config.get("orchestrator_url")
            or os.getenv("OT_ORCHESTRATOR_URL")
            or "http://localhost:8080"
        )
        self.inventory = OTAssetInventory(config.get("authorized_assets") or [])
        self.modbus = ModbusAnalyzer()
        self.alerts: List[OTAlert] = []
        self.stats = {
            "packets_analyzed": 0,
            "alerts_generated": 0,
            "assets_discovered": 0,
            "started_at": now_iso(),
        }

    def on_alert(self, alert: OTAlert) -> None:
        self.alerts.append(alert)
        self.stats["alerts_generated"] += 1
        LOGGER.warning("%s %s %s -> %s", alert.severity.upper(), alert.title, alert.source_ip, alert.destination_ip)
        self.send_alert(alert)

    def send_alert(self, alert: OTAlert) -> None:
        if requests is None:
            return
        try:
            requests.post(
                f"{self.orchestrator_url}/api/v1/ingest/ot",
                json=alert.to_dict(),
                timeout=3,
            )
        except Exception as exc:  # pragma: no cover - network dependent
            LOGGER.debug("orchestrator ingest failed: %s", exc)

    def run_simulation(self, cycles: Optional[int]) -> None:
        LOGGER.info("running OT simulation cycles=%s", "infinite" if cycles is None else cycles)
        assets = [
            ("192.168.10.10", "modbus", "00:00:bc:10:00:01"),
            ("192.168.10.20", "opc_ua", "00:80:91:10:00:02"),
            ("192.168.10.30", "dnp3", "00:00:54:10:00:03"),
        ]
        for ip, protocol, mac in assets:
            self.inventory.discover(ip, protocol, mac)

        count = 0
        while cycles is None or count < cycles:
            count += 1
            self.stats["packets_analyzed"] += 1
            src_ip = "192.168.10.20"
            dst_ip = "192.168.10.10"
            payload = build_modbus_packet(function_code=random.choice([0x03, 0x04, 0x10]))
            alerts = self.modbus.analyze(src_ip, dst_ip, payload)
            for alert in alerts:
                self.on_alert(alert)

            if count == cycles or (cycles is None and count % 30 == 0):
                rogue = self.inventory.discover("192.168.10.250", "modbus", "aa:bb:cc:dd:ee:ff")
                if not rogue.authorized:
                    self.on_alert(
                        make_alert(
                            severity="critical",
                            protocol="modbus",
                            title="Unauthorized OT asset observed",
                            description=(
                                f"Asset {rogue.ip} is not present in the authorized OT asset list. "
                                "Review before any operational action."
                            ),
                            src=rogue.ip,
                            dst="",
                            purdue_level=rogue.purdue_level,
                            technique_id="T0824",
                            technique_name="Device Discovery",
                        )
                    )

            time.sleep(0.1)

        LOGGER.info("simulation complete status=%s", json.dumps(self.status(), sort_keys=True))

    def run_passive_capture(self) -> None:
        if sniff is None or IP is None:
            LOGGER.warning("Scapy is not available; use --simulate or install requirements")
            return
        LOGGER.info("starting passive capture interface=%s", self.interface)
        sniff(iface=self.interface, filter="tcp or udp", prn=self.analyze_packet, store=False)

    def analyze_packet(self, packet: Any) -> None:
        if IP is None or not packet.haslayer(IP):
            return
        self.stats["packets_analyzed"] += 1
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        mac = packet[Ether].src if Ether is not None and packet.haslayer(Ether) else ""

        if TCP is not None and packet.haslayer(TCP):
            sport = int(packet[TCP].sport)
            dport = int(packet[TCP].dport)
            payload = bytes(packet[TCP].payload)
            if 502 in (sport, dport):
                asset_ip = dst_ip if dport == 502 else src_ip
                self.inventory.discover(asset_ip, "modbus", mac)
                for alert in self.modbus.analyze(src_ip, dst_ip, payload):
                    self.on_alert(alert)
            elif 20000 in (sport, dport):
                self.inventory.discover(dst_ip if dport == 20000 else src_ip, "dnp3", mac)
            elif 102 in (sport, dport):
                self.inventory.discover(dst_ip if dport == 102 else src_ip, "iec61850_mms", mac)
            elif 4840 in (sport, dport):
                self.inventory.discover(dst_ip if dport == 4840 else src_ip, "opc_ua", mac)

        if UDP is not None and packet.haslayer(UDP):
            dport = int(packet[UDP].dport)
            if dport == 47808:
                self.inventory.discover(dst_ip, "bacnet", mac)
            elif dport == 34964:
                self.inventory.discover(dst_ip, "profinet", mac)

    def status(self) -> Dict[str, Any]:
        return {
            **self.stats,
            "assets": self.inventory.all_assets(),
            "alerts": [alert.to_dict() for alert in self.alerts[-10:]],
        }


def make_alert(
    severity: str,
    protocol: str,
    title: str,
    description: str,
    src: str,
    dst: str,
    purdue_level: int,
    technique_id: str,
    technique_name: str,
) -> OTAlert:
    return OTAlert(
        id=f"ot-{int(time.time() * 1000)}-{random.randint(1000, 9999)}",
        timestamp=now_iso(),
        severity=severity,
        protocol=protocol,
        title=title,
        description=description,
        source_ip=src,
        destination_ip=dst,
        purdue_level=purdue_level,
        mitre_technique_id=technique_id,
        mitre_technique_name=technique_name,
    )


def build_modbus_packet(function_code: int, unit_id: int = 1) -> bytes:
    transaction_id = random.randint(1, 65535)
    protocol_id = 0
    length = 6
    body = struct.pack(">BBHH", unit_id, function_code, 0, 1)
    return struct.pack(">HHH", transaction_id, protocol_id, length) + body


def lookup_vendor(mac: str) -> str:
    prefixes = {
        "00:00:bc": "Rockwell Automation",
        "00:0d:9d": "Siemens",
        "00:00:54": "Schneider Electric",
        "00:80:91": "Phoenix Contact",
        "fc:c2:3d": "Beckhoff",
    }
    return prefixes.get(mac[:8].lower(), "unknown")


def classify_device(protocol: str) -> str:
    return {
        "modbus": "plc",
        "dnp3": "rtu",
        "iec61850_mms": "ied",
        "opc_ua": "historian",
        "bacnet": "building_controller",
        "profinet": "plc",
    }.get(protocol, "unknown")


def estimate_purdue_level(protocol: str) -> int:
    return {
        "modbus": 1,
        "dnp3": 1,
        "iec61850_mms": 1,
        "profinet": 1,
        "bacnet": 1,
        "opc_ua": 2,
    }.get(protocol, -1)


def load_config(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as handle:
        if yaml is not None:
            data = yaml.safe_load(handle) or {}
            return data if isinstance(data, dict) else {}
        try:
            return json.load(handle)
        except json.JSONDecodeError:
            LOGGER.warning("config file is not JSON and PyYAML is unavailable: %s", path)
            return {}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Cybersecurity-AEGIS passive OT/ICS monitor")
    parser.add_argument("--config", default="config.yaml")
    parser.add_argument("--interface")
    parser.add_argument("--orchestrator-url")
    parser.add_argument("--simulate", action="store_true")
    parser.add_argument("--cycles", type=int, default=None)
    return parser


def main() -> int:
    log_level = os.getenv("AEGIS_LOG_LEVEL", os.getenv("CYBERFORGE_LOG_LEVEL", "INFO")).upper()
    logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(message)s")
    args = build_parser().parse_args()
    config = load_config(args.config)
    if args.interface:
        config["interface"] = args.interface
    if args.orchestrator_url:
        config["orchestrator_url"] = args.orchestrator_url

    simulate_env = os.getenv("OT_MONITOR_SIMULATE", "").lower() in {"1", "true", "yes"}
    simulate = args.simulate or bool(config.get("simulate")) or simulate_env

    monitor = OTMonitor(config)
    if simulate:
        monitor.run_simulation(args.cycles)
    else:
        monitor.run_passive_capture()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
