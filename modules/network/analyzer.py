#!/usr/bin/env python3
"""Cybersecurity-AEGIS Network Traffic Analyzer.

Passive network traffic analysis with multi-protocol support.
Detects: port scans, DoS signatures, protocol anomalies, data exfiltration indicators.
Forwards structured alerts to the AEGIS orchestrator.

Safe by design: read-only passive capture, no packet injection.
"""
from __future__ import annotations

import argparse
import collections
import json
import logging
import os
import random
import socket
import struct
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import requests  # type: ignore
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

try:
    from scapy.all import IP, TCP, UDP, ICMP, DNS, DNSQR, Ether, Raw, sniff  # type: ignore
    _SCAPY = True
except ImportError:
    IP = TCP = UDP = ICMP = DNS = DNSQR = Ether = Raw = None  # type: ignore
    sniff = None  # type: ignore

# Shared secret for orchestrator ingest endpoints (must match AEGIS_INGEST_KEY).
_INGEST_HEADERS = {"X-AEGIS-INGEST-KEY": os.environ.get("AEGIS_INGEST_KEY", "")}

LOGGER = logging.getLogger('aegis.network')

# ── WELL-KNOWN SUSPICIOUS PORT CATEGORIES ─────────────────────────────────────
C2_PORTS: Set[int] = {4444, 4445, 1337, 31337, 8888, 9001, 9030}
RAT_PORTS: Set[int] = {5900, 5901, 3389, 1090, 8080}
EXFIL_PORTS: Set[int] = {53, 443, 80}

SUSPICIOUS_PORT_BANDS = {
    'c2_common': C2_PORTS,
    'remote_access': RAT_PORTS,
}

MITRE_PORT_MAP: Dict[int, Tuple[str, str]] = {
    4444: ('T1571', 'Non-Standard Port'),
    1337: ('T1571', 'Non-Standard Port'),
    31337: ('T1571', 'Non-Standard Port'),
    5900: ('T1021.005', 'Remote Services: VNC'),
    3389: ('T1021.001', 'Remote Services: RDP'),
    53: ('T1071.004', 'Application Layer Protocol: DNS'),
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class NetworkAlert:
    id: str
    timestamp: str
    severity: str
    category: str
    title: str
    description: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    mitre_technique_id: str
    mitre_technique_name: str
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def make_alert(
    severity: str,
    category: str,
    title: str,
    description: str,
    src_ip: str = '',
    dst_ip: str = '',
    src_port: int = 0,
    dst_port: int = 0,
    protocol: str = 'unknown',
    technique_id: str = '',
    technique_name: str = '',
    tags: List[str] | None = None,
    extra: Dict[str, Any] | None = None,
) -> NetworkAlert:
    return NetworkAlert(
        id=f'net-{int(time.time() * 1000)}-{random.randint(1000, 9999)}',
        timestamp=now_iso(),
        severity=severity,
        category=category,
        title=title,
        description=description,
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=src_port,
        destination_port=dst_port,
        protocol=protocol,
        mitre_technique_id=technique_id,
        mitre_technique_name=technique_name,
        tags=tags or [],
        extra=extra or {},
    )


# ── PORT SCAN DETECTOR ─────────────────────────────────────────────────────────
class PortScanDetector:
    """Detects horizontal and vertical port scans."""

    def __init__(self, window_sec: int = 60, port_threshold: int = 15, host_threshold: int = 10) -> None:
        self.window_sec = window_sec
        self.port_threshold = port_threshold
        self.host_threshold = host_threshold
        # src_ip -> {(dst_ip, dst_port): [timestamps]}
        self._syn_map: Dict[str, Dict[Tuple[str, int], List[float]]] = collections.defaultdict(
            lambda: collections.defaultdict(list)
        )
        self._alerted: Set[str] = set()

    def record_syn(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[NetworkAlert]:
        now = time.time()
        key = (dst_ip, dst_port)
        bucket = self._syn_map[src_ip]
        bucket[key] = [ts for ts in bucket[key] if now - ts < self.window_sec]
        bucket[key].append(now)

        unique_ports = len({p for (_, p) in bucket if now - min(bucket[(_, p)], default=now) < self.window_sec})
        unique_hosts = len({h for (h, _) in bucket if any(now - ts < self.window_sec for ts in bucket[(h, _)])})

        alert_key = f'{src_ip}-scan'
        if unique_ports >= self.port_threshold and alert_key not in self._alerted:
            self._alerted.add(alert_key)
            return make_alert(
                severity='high',
                category='network',
                title='Vertical port scan detected',
                description=f'{src_ip} sent SYNs to {unique_ports}+ unique ports in {self.window_sec}s',
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=0,
                dst_port=dst_port,
                protocol='tcp',
                technique_id='T1046',
                technique_name='Network Service Discovery',
                tags=['port_scan', 'vertical_scan', 'reconnaissance'],
            )
        if unique_hosts >= self.host_threshold and f'{src_ip}-hscan' not in self._alerted:
            self._alerted.add(f'{src_ip}-hscan')
            return make_alert(
                severity='medium',
                category='network',
                title='Horizontal port scan detected',
                description=f'{src_ip} probed {unique_hosts}+ unique hosts in {self.window_sec}s',
                src_ip=src_ip,
                dst_ip='multiple',
                src_port=0,
                dst_port=dst_port,
                protocol='tcp',
                technique_id='T1018',
                technique_name='Remote System Discovery',
                tags=['port_scan', 'horizontal_scan', 'reconnaissance'],
            )
        return None


# ── DOS / FLOOD DETECTOR ───────────────────────────────────────────────────────
class FloodDetector:
    """Detects high-volume packet floods (SYN flood, UDP flood, ICMP flood)."""

    def __init__(self, window_sec: int = 10, threshold: int = 500) -> None:
        self.window_sec = window_sec
        self.threshold = threshold
        self._counts: Dict[str, List[float]] = collections.defaultdict(list)
        self._alerted: Set[str] = set()

    def record(self, proto: str, src_ip: str, dst_ip: str) -> Optional[NetworkAlert]:
        now = time.time()
        key = f'{proto}:{src_ip}->{dst_ip}'
        bucket = self._counts[key]
        self._counts[key] = [ts for ts in bucket if now - ts < self.window_sec]
        self._counts[key].append(now)
        count = len(self._counts[key])

        if count >= self.threshold and key not in self._alerted:
            self._alerted.add(key)
            return make_alert(
                severity='critical',
                category='network',
                title=f'{proto.upper()} flood attack detected',
                description=f'{count} {proto.upper()} packets from {src_ip} to {dst_ip} in {self.window_sec}s',
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=proto.lower(),
                technique_id='T1498',
                technique_name='Network Denial of Service',
                tags=['dos', 'flood', proto.lower()],
            )
        return None


# ── DNS EXFILTRATION DETECTOR ──────────────────────────────────────────────────
class DNSExfilDetector:
    """Detects potential DNS tunnelling / data exfiltration via DNS queries."""

    def __init__(self, window_sec: int = 60, query_threshold: int = 50, entropy_threshold: float = 3.5) -> None:
        self.window_sec = window_sec
        self.query_threshold = query_threshold
        self.entropy_threshold = entropy_threshold
        self._queries: Dict[str, List[Tuple[float, str]]] = collections.defaultdict(list)
        self._alerted: Set[str] = set()

    def record(self, src_ip: str, query_name: str) -> Optional[NetworkAlert]:
        now = time.time()
        bucket = self._queries[src_ip]
        self._queries[src_ip] = [(ts, q) for ts, q in bucket if now - ts < self.window_sec]
        self._queries[src_ip].append((now, query_name))
        count = len(self._queries[src_ip])

        if count >= self.query_threshold and src_ip not in self._alerted:
            entropy = self._avg_entropy([q for _, q in self._queries[src_ip]])
            if entropy >= self.entropy_threshold:
                self._alerted.add(src_ip)
                return make_alert(
                    severity='high',
                    category='network',
                    title='Potential DNS exfiltration / tunnelling',
                    description=(
                        f'{src_ip} generated {count} DNS queries in {self.window_sec}s '
                        f'with avg label entropy {entropy:.2f} (threshold {self.entropy_threshold})'
                    ),
                    src_ip=src_ip,
                    dst_ip='dns-server',
                    dst_port=53,
                    protocol='udp/dns',
                    technique_id='T1071.004',
                    technique_name='Application Layer Protocol: DNS',
                    tags=['dns', 'exfiltration', 'tunnelling'],
                )
        return None

    def _avg_entropy(self, names: List[str]) -> float:
        entropies = []
        for name in names[:20]:
            label = name.split('.')[0]
            if not label:
                continue
            freq: Dict[str, float] = {}
            for ch in label:
                freq[ch] = freq.get(ch, 0) + 1
            total = len(label)
            ent = -sum((c / total) * (c / total).bit_length() for c in freq.values() if c)
            entropies.append(abs(ent))
        return sum(entropies) / len(entropies) if entropies else 0.0


# ── BEACONING DETECTOR ─────────────────────────────────────────────────────────
class BeaconingDetector:
    """Detects periodic outbound connections indicative of C2 beaconing."""

    def __init__(self, window_sec: int = 600, min_connections: int = 5,
                 jitter_tolerance: float = 0.35) -> None:
        self.window_sec = window_sec
        self.min_connections = min_connections
        self.jitter_tolerance = jitter_tolerance
        # src_ip -> {dst_ip: [timestamps]}
        self._conns: Dict[str, Dict[str, List[float]]] = collections.defaultdict(
            lambda: collections.defaultdict(list)
        )
        self._alerted: Set[str] = set()

    def record(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[NetworkAlert]:
        now = time.time()
        key = dst_ip
        bucket = self._conns[src_ip][key]
        self._conns[src_ip][key] = [ts for ts in bucket if now - ts < self.window_sec]
        self._conns[src_ip][key].append(now)
        timestamps = self._conns[src_ip][key]

        if len(timestamps) < self.min_connections:
            return None

        alert_key = f'{src_ip}->{dst_ip}:{dst_port}-beacon'
        if alert_key in self._alerted:
            return None

        # Compute intervals and coefficient of variation (CV = std/mean)
        intervals = [timestamps[i + 1] - timestamps[i] for i in range(len(timestamps) - 1)]
        mean_iv = sum(intervals) / len(intervals) if intervals else 0
        if mean_iv < 5:
            return None
        variance = sum((x - mean_iv) ** 2 for x in intervals) / len(intervals)
        cv = (variance ** 0.5) / mean_iv if mean_iv else 1.0

        if cv <= self.jitter_tolerance:
            self._alerted.add(alert_key)
            return make_alert(
                severity='high',
                category='network',
                title=f'C2 beaconing pattern detected: {src_ip} → {dst_ip}',
                description=(
                    f'{src_ip} made {len(timestamps)} connections to {dst_ip}:{dst_port} '
                    f'in {self.window_sec}s with avg interval {mean_iv:.1f}s '
                    f'(jitter CV={cv:.2f} ≤ threshold {self.jitter_tolerance})'
                ),
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol='tcp',
                technique_id='T1071',
                technique_name='Application Layer Protocol',
                tags=['beaconing', 'c2', 'periodic_connection'],
                extra={'beacon_interval_avg': mean_iv, 'connection_count': len(timestamps), 'cv': cv},
            )
        return None


# ── SUSPICIOUS PORT DETECTOR ───────────────────────────────────────────────────
class SuspiciousPortDetector:
    """Alerts on connections to known C2 / RAT ports."""

    def __init__(self) -> None:
        self._seen: Set[str] = set()

    def check(self, src_ip: str, dst_ip: str, dst_port: int, proto: str) -> Optional[NetworkAlert]:
        for band_name, ports in SUSPICIOUS_PORT_BANDS.items():
            if dst_port in ports:
                key = f'{src_ip}->{dst_ip}:{dst_port}'
                if key not in self._seen:
                    self._seen.add(key)
                    technique_id, technique_name = MITRE_PORT_MAP.get(dst_port, ('T1571', 'Non-Standard Port'))
                    return make_alert(
                        severity='high',
                        category='network',
                        title=f'Connection to suspicious port {dst_port} ({band_name})',
                        description=f'{src_ip} connected to {dst_ip}:{dst_port} — matches {band_name} category',
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        dst_port=dst_port,
                        protocol=proto,
                        technique_id=technique_id,
                        technique_name=technique_name,
                        tags=['suspicious_port', band_name, proto],
                    )
        return None


# ── MAIN NETWORK MONITOR ───────────────────────────────────────────────────────
class NetworkMonitor:
    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.interface = str(config.get('interface') or os.getenv('NETWORK_INTERFACE', 'eth0'))
        self.orchestrator_url = str(
            config.get('orchestrator_url')
            or os.getenv('ORCHESTRATOR_URL', 'http://localhost:8080')
        )
        self.port_scan = PortScanDetector()
        self.flood = FloodDetector()
        self.dns_exfil = DNSExfilDetector()
        self.suspicious_port = SuspiciousPortDetector()
        self.beaconing = BeaconingDetector()
        self.alerts: List[NetworkAlert] = []
        self.stats = {
            'packets': 0,
            'alerts': 0,
            'tcp': 0,
            'udp': 0,
            'icmp': 0,
            'dns': 0,
            'started_at': now_iso(),
        }

    def on_alert(self, alert: NetworkAlert) -> None:
        self.alerts.append(alert)
        self.stats['alerts'] += 1
        LOGGER.warning('[%s] %s | %s -> %s', alert.severity.upper(), alert.title,
                       alert.source_ip, alert.destination_ip)
        self._send(alert)

    def _send(self, alert: NetworkAlert) -> None:
        if not _REQUESTS:
            return
        payload = {
            'source': 'network_monitor',
            'category': 'network',
            'severity': alert.severity,
            'title': alert.title,
            'description': alert.description,
            'tags': alert.tags,
            'mitre': {
                'technique_id': alert.mitre_technique_id,
                'technique_name': alert.mitre_technique_name,
            },
            'raw_data': alert.to_dict(),
        }
        try:
            requests.post(f'{self.orchestrator_url}/api/v1/ingest/generic', json=payload, timeout=3, headers=_INGEST_HEADERS)
        except Exception as exc:
            LOGGER.debug('orchestrator send failed: %s', exc)

    def analyze_packet(self, packet: Any) -> None:
        if IP is None or not packet.haslayer(IP):
            return
        self.stats['packets'] += 1
        src_ip: str = packet[IP].src
        dst_ip: str = packet[IP].dst

        if TCP is not None and packet.haslayer(TCP):
            self.stats['tcp'] += 1
            flags = int(packet[TCP].flags)
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            is_syn = (flags & 0x02) and not (flags & 0x10)
            if is_syn:
                alert = self.port_scan.record_syn(src_ip, dst_ip, dst_port)
                if alert:
                    self.on_alert(alert)
                alert = self.flood.record('syn', src_ip, dst_ip)
                if alert:
                    self.on_alert(alert)
            alert = self.suspicious_port.check(src_ip, dst_ip, dst_port, 'tcp')
            if alert:
                self.on_alert(alert)
            alert = self.beaconing.record(src_ip, dst_ip, dst_port)
            if alert:
                self.on_alert(alert)

        if UDP is not None and packet.haslayer(UDP):
            self.stats['udp'] += 1
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
            alert = self.flood.record('udp', src_ip, dst_ip)
            if alert:
                self.on_alert(alert)
            if DNS is not None and packet.haslayer(DNS) and DNSQR is not None and packet.haslayer(DNSQR):
                self.stats['dns'] += 1
                query_name = str(packet[DNSQR].qname)
                alert = self.dns_exfil.record(src_ip, query_name)
                if alert:
                    self.on_alert(alert)

        if ICMP is not None and packet.haslayer(ICMP):
            self.stats['icmp'] += 1
            alert = self.flood.record('icmp', src_ip, dst_ip)
            if alert:
                self.on_alert(alert)

    def run_passive(self) -> None:
        if sniff is None or not _SCAPY:
            LOGGER.warning('Scapy unavailable; use --simulate or install requirements')
            return
        LOGGER.info('Starting passive capture on %s', self.interface)
        sniff(
            iface=self.interface,
            filter='ip',
            prn=self.analyze_packet,
            store=False,
        )

    def run_simulation(self, cycles: int = 100) -> None:
        LOGGER.info('Running network simulation cycles=%d', cycles)
        ips = [f'10.0.{i}.{j}' for i in range(1, 4) for j in range(1, 6)]
        attacker = '10.99.1.1'

        for i in range(cycles):
            # Simulate SYN scan from attacker
            for port in range(80, 80 + (i % 20)):
                dst = random.choice(ips)
                alert = self.port_scan.record_syn(attacker, dst, port)
                if alert:
                    self.on_alert(alert)

            # Simulate normal traffic
            self.stats['packets'] += 1
            self.stats['tcp'] += 1

            # Simulate suspicious port
            if i == 40:
                alert = self.suspicious_port.check(attacker, '10.0.1.2', 4444, 'tcp')
                if alert:
                    self.on_alert(alert)

            # Simulate DNS exfil
            for _ in range(3):
                label = ''.join(random.choices("abcdef0123456789", k=24))
                qname = label + '.evil.com.'
                alert = self.dns_exfil.record(attacker, qname)
                if alert:
                    self.on_alert(alert)

            time.sleep(0.05)

        LOGGER.info('Simulation complete. Stats: %s', json.dumps(self.stats))

    def status(self) -> Dict[str, Any]:
        return {
            **self.stats,
            'recent_alerts': [a.to_dict() for a in self.alerts[-10:]],
        }


def load_config(path: str) -> Dict[str, Any]:
    if not path or not os.path.exists(path):
        return {}
    try:
        with open(path, encoding='utf-8') as fh:
            import yaml  # type: ignore
            return yaml.safe_load(fh) or {}
    except Exception:
        try:
            with open(path, encoding='utf-8') as fh:
                return json.load(fh)
        except Exception:
            return {}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Cybersecurity-AEGIS Network Traffic Analyzer')
    p.add_argument('--config', default='config.yaml')
    p.add_argument('--interface', default=None)
    p.add_argument('--orchestrator-url', default=None)
    p.add_argument('--simulate', action='store_true')
    p.add_argument('--cycles', type=int, default=200)
    return p


def main() -> int:
    log_level = os.getenv('AEGIS_LOG_LEVEL', 'INFO').upper()
    logging.basicConfig(level=log_level, format='%(asctime)s %(levelname)s %(name)s %(message)s')
    args = build_parser().parse_args()
    config = load_config(args.config)
    if args.interface:
        config['interface'] = args.interface
    if args.orchestrator_url:
        config['orchestrator_url'] = args.orchestrator_url
    simulate = args.simulate or os.getenv('NETWORK_SIMULATE', '').lower() in {'1', 'true'}
    monitor = NetworkMonitor(config)
    if simulate:
        monitor.run_simulation(args.cycles)
    else:
        monitor.run_passive()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
