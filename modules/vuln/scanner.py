#!/usr/bin/env python3
"""Cybersecurity-AEGIS Vulnerability Scanner Module.

Provides:
- Port/service fingerprinting (passive from existing alerts + active TCP probe)
- NVD/CVE feed integration (offline JSON or live API)
- Service-to-CVE correlation
- Risk scoring with CVSS integration
- Forwarding findings to the AEGIS orchestrator

Active scanning is opt-in (VULN_ACTIVE_SCAN=1 env var).
By default, the module operates in passive mode using data from other modules.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import socket
import ssl
import subprocess
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import requests  # type: ignore
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

# Shared secret for orchestrator ingest endpoints (must match AEGIS_INGEST_KEY).
_INGEST_HEADERS = {"X-AEGIS-INGEST-KEY": os.environ.get("AEGIS_INGEST_KEY", "")}

LOGGER = logging.getLogger('aegis.vuln')

NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
NVD_API_KEY = os.getenv('NVD_API_KEY', '')


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── SERVICE FINGERPRINT DATABASE ───────────────────────────────────────────────
SERVICE_FINGERPRINTS: Dict[int, str] = {
    21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
    80: 'http', 110: 'pop3', 143: 'imap', 389: 'ldap', 443: 'https',
    445: 'smb', 502: 'modbus', 1433: 'mssql', 1521: 'oracle',
    2404: 'iec104', 3306: 'mysql', 3389: 'rdp', 4840: 'opcua',
    5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 8080: 'http-alt',
    8443: 'https-alt', 9200: 'elasticsearch', 27017: 'mongodb',
    47808: 'bacnet',
}

# Known CVEs by service (static data for offline mode — augment with live NVD)
STATIC_CVE_DB: Dict[str, List[Dict[str, Any]]] = {
    'telnet': [
        {'cve_id': 'CVE-1999-0619', 'description': 'Telnet transmits credentials in cleartext.',
         'cvss_score': 9.8, 'severity': 'critical', 'mitre': 'T1040'},
    ],
    'ftp': [
        {'cve_id': 'CVE-1999-0497', 'description': 'Anonymous FTP access may expose sensitive data.',
         'cvss_score': 7.5, 'severity': 'high', 'mitre': 'T1190'},
    ],
    'smb': [
        {'cve_id': 'CVE-2017-0144', 'description': 'EternalBlue MS17-010 SMB RCE.',
         'cvss_score': 9.8, 'severity': 'critical', 'mitre': 'T1210'},
        {'cve_id': 'CVE-2020-0796', 'description': 'SMBGhost Windows SMB RCE (SMBv3).',
         'cvss_score': 10.0, 'severity': 'critical', 'mitre': 'T1210'},
    ],
    'rdp': [
        {'cve_id': 'CVE-2019-0708', 'description': 'BlueKeep RDP pre-auth RCE.',
         'cvss_score': 9.8, 'severity': 'critical', 'mitre': 'T1210'},
        {'cve_id': 'CVE-2019-1182', 'description': 'DejaBlue RDP RCE.',
         'cvss_score': 9.8, 'severity': 'critical', 'mitre': 'T1210'},
    ],
    'redis': [
        {'cve_id': 'CVE-2022-0543', 'description': 'Redis Lua sandbox escape RCE.',
         'cvss_score': 10.0, 'severity': 'critical', 'mitre': 'T1190'},
    ],
    'elasticsearch': [
        {'cve_id': 'CVE-2014-3120', 'description': 'Elasticsearch dynamic script RCE.',
         'cvss_score': 9.8, 'severity': 'critical', 'mitre': 'T1190'},
    ],
    'modbus': [
        {'cve_id': 'ICS-ADVISORY-CVE', 'description': 'Modbus lacks authentication; write commands may alter industrial process.',
         'cvss_score': 8.6, 'severity': 'high', 'mitre': 'T0855'},
    ],
    'opcua': [
        {'cve_id': 'ICS-OPC-UA-ADVISORY', 'description': 'OPC UA may expose process data without proper security mode.',
         'cvss_score': 6.5, 'severity': 'medium', 'mitre': 'T0882'},
    ],
    'vnc': [
        {'cve_id': 'CVE-2019-15681', 'description': 'LibVNCServer memory disclosure.',
         'cvss_score': 7.5, 'severity': 'high', 'mitre': 'T1021.005'},
    ],
    'mongodb': [
        {'cve_id': 'CVE-2013-2132', 'description': 'MongoDB no-auth access may expose all databases.',
         'cvss_score': 7.5, 'severity': 'high', 'mitre': 'T1190'},
    ],
    'bacnet': [
        {'cve_id': 'ICS-BACNET-ADVISORY', 'description': 'BACnet has no authentication; may allow unauthorized building control.',
         'cvss_score': 8.1, 'severity': 'high', 'mitre': 'T0855'},
    ],
    'ssh': [
        {'cve_id': 'CVE-2023-38408', 'description': 'libssh remote code execution via ssh-agent forwarding.',
         'cvss_score': 9.8, 'severity': 'critical', 'mitre': 'T1021.004'},
        {'cve_id': 'CVE-2023-48795', 'description': 'Terrapin SSH attack — prefix truncation weakens MAC algorithms.',
         'cvss_score': 5.9, 'severity': 'medium', 'mitre': 'T1557'},
        {'cve_id': 'CVE-2024-6387', 'description': 'regreSSHion: OpenSSH signal handler race condition RCE (unauthenticated, Linux).',
         'cvss_score': 8.1, 'severity': 'high', 'mitre': 'T1190'},
    ],
    'http': [
        {'cve_id': 'CVE-2023-44487', 'description': 'HTTP/2 Rapid Reset DoS — used in record DDoS attacks (CVSS 7.5).',
         'cvss_score': 7.5, 'severity': 'high', 'mitre': 'T1498'},
        {'cve_id': 'CVE-2024-27316', 'description': 'Apache httpd HTTP/2 CONTINUATION flood DoS.',
         'cvss_score': 7.5, 'severity': 'high', 'mitre': 'T1499'},
    ],
    'https': [
        {'cve_id': 'CVE-2024-3400', 'description': 'PAN-OS GlobalProtect OS command injection (CVSS 10.0). Exploited in the wild.',
         'cvss_score': 10.0, 'severity': 'critical', 'mitre': 'T1190'},
        {'cve_id': 'CVE-2024-21762', 'description': 'Fortinet FortiOS SSL-VPN out-of-bounds write RCE (CVSS 9.6). KEV listed.',
         'cvss_score': 9.6, 'severity': 'critical', 'mitre': 'T1190'},
        {'cve_id': 'CVE-2023-27997', 'description': 'FortiOS/FortiProxy SSL-VPN heap buffer overflow RCE (CVSS 9.2).',
         'cvss_score': 9.2, 'severity': 'critical', 'mitre': 'T1190'},
        {'cve_id': 'CVE-2023-46805', 'description': 'Ivanti Connect Secure auth bypass — chained for RCE (CISA KEV).',
         'cvss_score': 8.2, 'severity': 'high', 'mitre': 'T1078'},
        {'cve_id': 'CVE-2024-21887', 'description': 'Ivanti Connect Secure command injection — chained with CVE-2023-46805.',
         'cvss_score': 9.1, 'severity': 'critical', 'mitre': 'T1190'},
    ],
    'https-alt': [
        {'cve_id': 'CVE-2024-3400', 'description': 'PAN-OS command injection if management interface exposed on alt port.',
         'cvss_score': 10.0, 'severity': 'critical', 'mitre': 'T1190'},
    ],
    'dns': [
        {'cve_id': 'CVE-2023-50387', 'description': 'KeyTrap DNSSEC validation DoS — single malicious DNS packet.',
         'cvss_score': 7.5, 'severity': 'high', 'mitre': 'T1499'},
        {'cve_id': 'CVE-2020-1350', 'description': 'SIGRed Windows DNS Server RCE — CVSS 10.0, wormable.',
         'cvss_score': 10.0, 'severity': 'critical', 'mitre': 'T1210'},
    ],
    'smtp': [
        {'cve_id': 'CVE-2024-1709', 'description': 'ScreenConnect auth bypass via SMTP interface (chained RCE).',
         'cvss_score': 10.0, 'severity': 'critical', 'mitre': 'T1190'},
    ],
    'mssql': [
        {'cve_id': 'CVE-2024-37335', 'description': 'Microsoft SQL Server native scoring memory corruption RCE.',
         'cvss_score': 8.8, 'severity': 'high', 'mitre': 'T1190'},
    ],
    'oracle': [
        {'cve_id': 'CVE-2022-21500', 'description': 'Oracle E-Business Suite auth bypass allows unauthenticated read access.',
         'cvss_score': 8.6, 'severity': 'high', 'mitre': 'T1078'},
    ],
    'ldap': [
        {'cve_id': 'CVE-2021-44228', 'description': 'Log4Shell: Java JNDI LDAP injection RCE (CVSS 10.0). Still exploited in 2024.',
         'cvss_score': 10.0, 'severity': 'critical', 'mitre': 'T1190'},
        {'cve_id': 'CVE-2024-49113', 'description': 'Windows LDAP Denial of Service vulnerability (CVSS 7.5).',
         'cvss_score': 7.5, 'severity': 'high', 'mitre': 'T1499'},
    ],
    'postgresql': [
        {'cve_id': 'CVE-2024-7348', 'description': 'PostgreSQL pg_dump race condition allows privilege escalation.',
         'cvss_score': 7.5, 'severity': 'high', 'mitre': 'T1068'},
    ],
    'mysql': [
        {'cve_id': 'CVE-2024-20963', 'description': 'MySQL Server unauthorized data modification via network.',
         'cvss_score': 6.8, 'severity': 'medium', 'mitre': 'T1190'},
    ],
    'iec104': [
        {'cve_id': 'ICS-IEC104-ADVISORY', 'description': 'IEC 60870-5-104 lacks authentication; allows unauthorized SCADA command injection.',
         'cvss_score': 9.1, 'severity': 'critical', 'mitre': 'T0855'},
    ],
}


@dataclass
class VulnFinding:
    id: str
    target_ip: str
    target_port: int
    service: str
    cve_id: str
    description: str
    cvss_score: float
    severity: str
    mitre_technique: str
    source: str
    timestamp: str = field(default_factory=now_iso)
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TargetProfile:
    ip: str
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, str] = field(default_factory=dict)
    os_guess: str = 'unknown'
    last_scanned: str = field(default_factory=now_iso)


# ── PORT PROBER ────────────────────────────────────────────────────────────────
class PortProber:
    """Lightweight active TCP port prober (opt-in only)."""

    def __init__(self, timeout: float = 1.0, max_ports: int = 50) -> None:
        self.timeout = timeout
        self.max_ports = max_ports

    def probe(self, ip: str, ports: List[int] | None = None) -> List[int]:
        if ports is None:
            ports = sorted(SERVICE_FINGERPRINTS.keys())[:self.max_ports]
        open_ports: List[int] = []
        for port in ports[:self.max_ports]:
            if self._check_port(ip, port):
                open_ports.append(port)
        return open_ports

    def _check_port(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except (ConnectionRefusedError, OSError, TimeoutError):
            return False


# ── NVD FEED CLIENT ────────────────────────────────────────────────────────────
class NVDClient:
    """NVD CVE API client."""

    def search_by_keyword(self, keyword: str, max_results: int = 10) -> List[Dict[str, Any]]:
        if not _REQUESTS:
            return []
        headers = {}
        if NVD_API_KEY:
            headers['apiKey'] = NVD_API_KEY
        try:
            resp = requests.get(
                NVD_API_BASE,
                params={'keywordSearch': keyword, 'resultsPerPage': min(max_results, 20)},
                headers=headers,
                timeout=10,
            )
            if resp.status_code != 200:
                return []
            vulns = []
            for item in resp.json().get('vulnerabilities', []):
                cve = item.get('cve', {})
                metrics = cve.get('metrics', {})
                cvss_score = 0.0
                for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                    if key in metrics and metrics[key]:
                        cvss_score = float(
                            metrics[key][0].get('cvssData', {}).get('baseScore', 0.0)
                        )
                        break
                descs = cve.get('descriptions', [])
                desc_text = next((d['value'] for d in descs if d.get('lang') == 'en'), 'N/A')
                vulns.append({
                    'cve_id': cve.get('id', 'UNKNOWN'),
                    'description': desc_text[:300],
                    'cvss_score': cvss_score,
                    'severity': _cvss_to_severity(cvss_score),
                })
            return vulns
        except Exception as exc:
            LOGGER.debug('NVD lookup failed: %s', exc)
            return []


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0:
        return 'critical'
    if score >= 7.0:
        return 'high'
    if score >= 4.0:
        return 'medium'
    return 'low'


# ── VULNERABILITY SCANNER ──────────────────────────────────────────────────────
class VulnerabilityScanner:
    """Main vulnerability scanner — passive-first, active opt-in."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.orchestrator_url = str(
            config.get('orchestrator_url')
            or os.getenv('ORCHESTRATOR_URL', 'http://localhost:8080')
        )
        self.active_scan = config.get('active_scan', False) or os.getenv('VULN_ACTIVE_SCAN', '') in {'1', 'true'}
        self.prober = PortProber()
        self.nvd = NVDClient()
        self.findings: List[VulnFinding] = []
        self.profiles: Dict[str, TargetProfile] = {}
        self.stats = {'targets_scanned': 0, 'findings': 0, 'started_at': now_iso()}

    def scan_ip(self, ip: str, hints: List[int] | None = None) -> List[VulnFinding]:
        LOGGER.info('Scanning %s (active=%s)', ip, self.active_scan)

        if ip not in self.profiles:
            self.profiles[ip] = TargetProfile(ip=ip)

        profile = self.profiles[ip]
        self.stats['targets_scanned'] += 1

        if self.active_scan:
            open_ports = self.prober.probe(ip, hints)
        elif hints:
            open_ports = hints
        else:
            open_ports = list(profile.open_ports)

        profile.open_ports = list(set(profile.open_ports) | set(open_ports))
        for port in open_ports:
            profile.services[port] = SERVICE_FINGERPRINTS.get(port, 'unknown')

        findings = self._correlate_cves(ip, profile)
        self.findings.extend(findings)
        self.stats['findings'] += len(findings)

        for finding in findings:
            self._forward_finding(finding)

        return findings

    def enrich_from_event(self, event: Dict[str, Any]) -> List[VulnFinding]:
        """Extract service info from a security event and scan if actionable."""
        dst_ip = event.get('destination_ip') or event.get('dst_ip')
        dst_port = event.get('destination_port') or event.get('dst_port')
        service = event.get('service')

        if not dst_ip:
            return []
        hints = [int(dst_port)] if dst_port else None

        # If service is given, add to profile directly
        if dst_ip and dst_port and service:
            if dst_ip not in self.profiles:
                self.profiles[dst_ip] = TargetProfile(ip=dst_ip)
            self.profiles[dst_ip].services[int(dst_port)] = service

        return self.scan_ip(dst_ip, hints)

    def _correlate_cves(self, ip: str, profile: TargetProfile) -> List[VulnFinding]:
        findings: List[VulnFinding] = []
        seen_cves: set[str] = set()

        for port, service in profile.services.items():
            cves = STATIC_CVE_DB.get(service, [])
            for cve in cves:
                key = f'{ip}:{port}:{cve["cve_id"]}'
                if key in seen_cves:
                    continue
                seen_cves.add(key)
                findings.append(VulnFinding(
                    id=f'VULN-{int(time.time()*1000)}-{len(findings)}',
                    target_ip=ip,
                    target_port=port,
                    service=service,
                    cve_id=cve['cve_id'],
                    description=cve['description'],
                    cvss_score=cve['cvss_score'],
                    severity=cve['severity'],
                    mitre_technique=cve.get('mitre', ''),
                    source='static_db',
                ))
                LOGGER.warning('[VULN] %s %s:%d %s CVSS=%.1f',
                               cve['severity'].upper(), ip, port, cve['cve_id'], cve['cvss_score'])
        return findings

    def _forward_finding(self, finding: VulnFinding) -> None:
        if not _REQUESTS:
            return
        payload = {
            'source': 'vuln_scanner',
            'category': 'vulnerability',
            'severity': finding.severity,
            'title': f'Vuln: {finding.cve_id} on {finding.target_ip}:{finding.target_port} ({finding.service})',
            'description': finding.description,
            'tags': ['vuln', finding.service, finding.cve_id],
            'raw_data': finding.to_dict(),
        }
        try:
            requests.post(f'{self.orchestrator_url}/api/v1/ingest/generic', json=payload, timeout=3, headers=_INGEST_HEADERS)
        except Exception as exc:
            LOGGER.debug('Orchestrator forward failed: %s', exc)

    def status(self) -> Dict[str, Any]:
        return {
            **self.stats,
            'profiles': len(self.profiles),
            'active_scan_enabled': self.active_scan,
            'recent_findings': [f.to_dict() for f in self.findings[-5:]],
        }

    def demo_scan(self) -> None:
        """Demo scan against simulated targets."""
        LOGGER.info('Running vulnerability scanner demo...')
        demo_targets = [
            ('192.168.1.10', [22, 80, 443, 3389, 445]),
            ('192.168.1.20', [502, 4840, 23]),
            ('192.168.1.30', [6379, 27017, 9200]),
        ]
        for ip, ports in demo_targets:
            findings = self.scan_ip(ip, hints=ports)
            LOGGER.info('Found %d findings for %s', len(findings), ip)
        print(json.dumps(self.status(), indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Cybersecurity-AEGIS Vulnerability Scanner')
    p.add_argument('--orchestrator-url', default=None)
    p.add_argument('--target', default=None, help='IP address to scan')
    p.add_argument('--ports', default=None, help='Comma-separated port list')
    p.add_argument('--active', action='store_true', help='Enable active port probing')
    p.add_argument('--demo', action='store_true')
    return p


def main() -> int:
    logging.basicConfig(level='INFO', format='%(asctime)s %(levelname)s %(name)s %(message)s')
    args = build_parser().parse_args()
    config: Dict[str, Any] = {'active_scan': args.active}
    if args.orchestrator_url:
        config['orchestrator_url'] = args.orchestrator_url
    scanner = VulnerabilityScanner(config)
    if args.demo:
        scanner.demo_scan()
        return 0
    if args.target:
        ports = [int(p.strip()) for p in args.ports.split(',')] if args.ports else None
        findings = scanner.scan_ip(args.target, hints=ports)
        print(json.dumps([f.to_dict() for f in findings], indent=2))
        return 0
    LOGGER.info('Vulnerability scanner ready. Status: %s', json.dumps(scanner.status()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
