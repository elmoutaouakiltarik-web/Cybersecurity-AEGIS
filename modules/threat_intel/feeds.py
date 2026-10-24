#!/usr/bin/env python3
"""Cybersecurity-AEGIS Threat Intelligence Module.

Provides:
- IOC (Indicator of Compromise) registry: IP, domain, hash, URL
- Threat feed ingestion (AbuseIPDB, OTX, MISP-compatible, CSV flat files)
- IOC matching against live events
- Threat actor / campaign context enrichment
- Forwarding enriched alerts to the AEGIS orchestrator

Safe by design: read-only lookups, no active scanning.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import logging
import os
import re
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

try:
    import requests  # type: ignore
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

LOGGER = logging.getLogger('aegis.threat_intel')

ABUSE_IPDB_API = 'https://api.abuseipdb.com/api/v2/check'
OTX_API_BASE = 'https://otx.alienvault.com/api/v1'


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── IOC DATA MODEL ─────────────────────────────────────────────────────────────
@dataclass
class IOC:
    value: str
    ioc_type: str          # ip, domain, hash_md5, hash_sha256, url, cidr
    severity: str          # critical, high, medium, low
    confidence: int        # 0–100
    source: str
    tags: List[str] = field(default_factory=list)
    description: str = ''
    first_seen: str = field(default_factory=now_iso)
    last_seen: str = field(default_factory=now_iso)
    mitre_technique: str = ''
    threat_actor: str = ''
    campaign: str = ''
    expiry_epoch: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def is_expired(self) -> bool:
        if self.expiry_epoch <= 0:
            return False
        return time.time() > self.expiry_epoch


@dataclass
class MatchResult:
    ioc: IOC
    matched_value: str
    match_type: str
    event_context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'ioc': self.ioc.to_dict(),
            'matched_value': self.matched_value,
            'match_type': self.match_type,
            'event_context': self.event_context,
        }


# ── IOC REGISTRY ──────────────────────────────────────────────────────────────
class IOCRegistry:
    """In-memory IOC registry with fast lookups."""

    def __init__(self) -> None:
        self._exact: Dict[str, IOC] = {}
        self._cidrs: List[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, IOC]] = []
        self._domains: Dict[str, IOC] = {}
        self._domain_suffixes: List[tuple[str, IOC]] = []

    def add(self, ioc: IOC) -> None:
        if ioc.is_expired():
            return
        if ioc.ioc_type == 'cidr':
            try:
                net = ipaddress.ip_network(ioc.value, strict=False)
                self._cidrs.append((net, ioc))
            except ValueError:
                LOGGER.debug('Invalid CIDR: %s', ioc.value)
        elif ioc.ioc_type == 'domain':
            if ioc.value.startswith('*.'):
                self._domain_suffixes.append((ioc.value[2:], ioc))
            else:
                self._domains[ioc.value.lower()] = ioc
        else:
            self._exact[ioc.value.lower()] = ioc

    def lookup_ip(self, ip_str: str) -> Optional[IOC]:
        match = self._exact.get(ip_str.lower())
        if match:
            return match
        try:
            addr = ipaddress.ip_address(ip_str)
            for net, ioc in self._cidrs:
                if addr in net:
                    return ioc
        except ValueError:
            pass
        return None

    def lookup_domain(self, domain: str) -> Optional[IOC]:
        domain_lower = domain.lower().rstrip('.')
        if domain_lower in self._domains:
            return self._domains[domain_lower]
        for suffix, ioc in self._domain_suffixes:
            if domain_lower.endswith('.' + suffix) or domain_lower == suffix:
                return ioc
        return None

    def lookup_hash(self, hash_value: str) -> Optional[IOC]:
        return self._exact.get(hash_value.lower())

    def lookup_url(self, url: str) -> Optional[IOC]:
        return self._exact.get(url.lower())

    def stats(self) -> Dict[str, int]:
        return {
            'exact_iocs': len(self._exact),
            'cidr_ranges': len(self._cidrs),
            'domains': len(self._domains),
            'domain_wildcards': len(self._domain_suffixes),
            'total': len(self._exact) + len(self._cidrs) + len(self._domains) + len(self._domain_suffixes),
        }


# ── IOC MATCHER ───────────────────────────────────────────────────────────────
class IOCMatcher:
    """Matches events against the IOC registry."""

    def __init__(self, registry: IOCRegistry) -> None:
        self.registry = registry

    def match_event(self, event: Dict[str, Any]) -> List[MatchResult]:
        results: List[MatchResult] = []

        for field_name in ('source_ip', 'src_ip', 'ip', 'remote_ip', 'client_ip'):
            ip = event.get(field_name)
            if ip and isinstance(ip, str):
                ioc = self.registry.lookup_ip(ip)
                if ioc:
                    results.append(MatchResult(ioc, ip, f'ip:{field_name}', event))

        for field_name in ('destination_ip', 'dst_ip', 'server_ip'):
            ip = event.get(field_name)
            if ip and isinstance(ip, str):
                ioc = self.registry.lookup_ip(ip)
                if ioc:
                    results.append(MatchResult(ioc, ip, f'ip:{field_name}', event))

        for field_name in ('domain', 'hostname', 'dns_query', 'fqdn'):
            domain = event.get(field_name)
            if domain and isinstance(domain, str):
                ioc = self.registry.lookup_domain(domain)
                if ioc:
                    results.append(MatchResult(ioc, domain, f'domain:{field_name}', event))

        for field_name in ('md5', 'sha256', 'hash', 'file_hash'):
            h = event.get(field_name)
            if h and isinstance(h, str):
                ioc = self.registry.lookup_hash(h)
                if ioc:
                    results.append(MatchResult(ioc, h, f'hash:{field_name}', event))

        return results


# ── FEED INGESTION ─────────────────────────────────────────────────────────────
class FeedIngester:
    """Ingests IOCs from various feed formats."""

    def ingest_csv_flat(self, path: str, ioc_type: str, source: str,
                        severity: str = 'medium', value_col: str = 'ioc',
                        skip_header: bool = True) -> List[IOC]:
        iocs: List[IOC] = []
        try:
            with open(path, 'r', encoding='utf-8', errors='replace') as fh:
                reader = csv.reader(fh)
                if skip_header:
                    next(reader, None)
                for row in reader:
                    if not row:
                        continue
                    value = row[0].strip()
                    if value and not value.startswith('#'):
                        iocs.append(IOC(
                            value=value.lower(),
                            ioc_type=ioc_type,
                            severity=severity,
                            confidence=70,
                            source=source,
                        ))
        except OSError as exc:
            LOGGER.warning('Failed to read feed %s: %s', path, exc)
        return iocs

    def ingest_misp_json(self, path: str) -> List[IOC]:
        iocs: List[IOC] = []
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            events = data.get('response', data) if isinstance(data, dict) else data
            if not isinstance(events, list):
                events = [events]
            for event in events:
                attrs = event.get('Attribute', []) or event.get('attributes', [])
                for attr in attrs:
                    ioc_type = _misp_type_map(attr.get('type', ''))
                    if not ioc_type:
                        continue
                    iocs.append(IOC(
                        value=str(attr.get('value', '')).lower().strip(),
                        ioc_type=ioc_type,
                        severity='high',
                        confidence=80,
                        source=f"misp:{event.get('id', 'unknown')}",
                        description=attr.get('comment', ''),
                    ))
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            LOGGER.warning('Failed to parse MISP feed %s: %s', path, exc)
        return iocs

    def ingest_otx_json(self, path: str) -> List[IOC]:
        iocs: List[IOC] = []
        try:
            with open(path, 'r', encoding='utf-8') as fh:
                data = json.load(fh)
            pulses = data.get('results', data) if isinstance(data, dict) else data
            if not isinstance(pulses, list):
                pulses = [pulses]
            for pulse in pulses:
                indicators = pulse.get('indicators', [])
                for ind in indicators:
                    ioc_type = _otx_type_map(ind.get('type', ''))
                    if not ioc_type:
                        continue
                    iocs.append(IOC(
                        value=str(ind.get('indicator', '')).lower().strip(),
                        ioc_type=ioc_type,
                        severity='high',
                        confidence=75,
                        source=f"otx:{pulse.get('id', 'unknown')}",
                        description=ind.get('description', ''),
                        tags=pulse.get('tags', []),
                    ))
        except (OSError, json.JSONDecodeError, KeyError) as exc:
            LOGGER.warning('Failed to parse OTX feed %s: %s', path, exc)
        return iocs

    def fetch_abuseipdb(self, ip: str, api_key: str) -> Optional[IOC]:
        if not _REQUESTS or not api_key:
            return None
        try:
            resp = requests.get(
                ABUSE_IPDB_API,
                params={'ipAddress': ip, 'maxAgeInDays': 90},
                headers={'Key': api_key, 'Accept': 'application/json'},
                timeout=5,
            )
            if resp.status_code == 200:
                d = resp.json().get('data', {})
                score = int(d.get('abuseConfidenceScore', 0))
                if score >= 25:
                    return IOC(
                        value=ip,
                        ioc_type='ip',
                        severity='critical' if score >= 80 else 'high' if score >= 50 else 'medium',
                        confidence=score,
                        source='abuseipdb',
                        description=f'AbuseIPDB score {score}/100. Country: {d.get("countryCode","?")}. Reports: {d.get("totalReports",0)}',
                        tags=d.get('reports', [{}])[0].get('categories', [])[:5] if d.get('reports') else [],
                    )
        except Exception as exc:
            LOGGER.debug('AbuseIPDB lookup failed for %s: %s', ip, exc)
        return None


def _misp_type_map(misp_type: str) -> str:
    return {
        'ip-src': 'ip', 'ip-dst': 'ip', 'ip-src|port': 'ip',
        'domain': 'domain', 'hostname': 'domain', 'domain|ip': 'domain',
        'md5': 'hash_md5', 'sha256': 'hash_sha256', 'sha1': 'hash_sha1',
        'url': 'url', 'uri': 'url',
    }.get(misp_type, '')


def _otx_type_map(otx_type: str) -> str:
    return {
        'IPv4': 'ip', 'IPv6': 'ip', 'domain': 'domain', 'hostname': 'domain',
        'FileHash-MD5': 'hash_md5', 'FileHash-SHA256': 'hash_sha256',
        'URL': 'url', 'CIDR': 'cidr',
    }.get(otx_type, '')


# ── THREAT INTEL SERVICE ───────────────────────────────────────────────────────
class ThreatIntelService:
    """Main service: loads feeds, provides matching, forwards results."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.orchestrator_url = str(
            config.get('orchestrator_url')
            or os.getenv('ORCHESTRATOR_URL', 'http://localhost:8080')
        )
        self.registry = IOCRegistry()
        self.matcher = IOCMatcher(self.registry)
        self.ingester = FeedIngester()
        self._load_feeds()

    def _load_feeds(self) -> None:
        feeds_dir = Path(self.config.get('feeds_dir', 'feeds'))
        if feeds_dir.exists():
            for csv_file in feeds_dir.glob('*.csv'):
                iocs = self.ingester.ingest_csv_flat(str(csv_file), ioc_type='ip', source=csv_file.stem)
                for ioc in iocs:
                    self.registry.add(ioc)
                LOGGER.info('Loaded %d IOCs from %s', len(iocs), csv_file.name)
            for json_file in feeds_dir.glob('misp_*.json'):
                iocs = self.ingester.ingest_misp_json(str(json_file))
                for ioc in iocs:
                    self.registry.add(ioc)
                LOGGER.info('Loaded %d IOCs from MISP feed %s', len(iocs), json_file.name)
            for json_file in feeds_dir.glob('otx_*.json'):
                iocs = self.ingester.ingest_otx_json(str(json_file))
                for ioc in iocs:
                    self.registry.add(ioc)
                LOGGER.info('Loaded %d IOCs from OTX feed %s', len(iocs), json_file.name)

        # Built-in minimal threat list (demo)
        demo_iocs = self._demo_iocs()
        for ioc in demo_iocs:
            self.registry.add(ioc)

        LOGGER.info('IOC registry loaded: %s', json.dumps(self.registry.stats()))

    def _demo_iocs(self) -> List[IOC]:
        """A small built-in threat list for demo/testing purposes."""
        return [
            IOC('198.51.100.99', 'ip', 'high', 90, 'demo_list', tags=['c2', 'botnet'],
                description='Demo C2 IP — replace with real feed data', mitre_technique='T1583'),
            IOC('203.0.113.42', 'ip', 'critical', 95, 'demo_list', tags=['ransomware', 'c2'],
                description='Demo ransomware C2 — replace with real feed data'),
            IOC('*.evil-domain-demo.com', 'domain', 'high', 80, 'demo_list', tags=['phishing'],
                description='Demo wildcard phishing domain — replace with real feed data'),
            IOC('44d88612fea8a8f36de82e1278abb02f', 'hash_md5', 'critical', 99, 'demo_list',
                tags=['malware', 'dropper'], description='Demo known-bad MD5 (EICAR test signature hash)'),
        ]

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        matches = self.matcher.match_event(event)
        if not matches:
            return {'matched': False, 'matches': []}
        enriched = {
            'matched': True,
            'match_count': len(matches),
            'highest_severity': max((m.ioc.severity for m in matches), key=lambda s: ['low','medium','high','critical'].index(s)),
            'matches': [m.to_dict() for m in matches],
        }
        if _REQUESTS:
            for match in matches:
                self._forward_match(event, match)
        return enriched

    def _forward_match(self, event: Dict[str, Any], match: MatchResult) -> None:
        payload = {
            'source': 'threat_intel',
            'category': 'intelligence',
            'severity': match.ioc.severity,
            'title': f'IOC Match: {match.ioc.ioc_type.upper()} {match.matched_value}',
            'description': match.ioc.description or f'IOC matched from feed: {match.ioc.source}',
            'tags': ['threat_intel', 'ioc_match'] + match.ioc.tags,
            'raw_data': match.to_dict(),
        }
        try:
            requests.post(f'{self.orchestrator_url}/api/v1/ingest/generic', json=payload, timeout=3)
        except Exception as exc:
            LOGGER.debug('Orchestrator forward failed: %s', exc)

    def stats(self) -> Dict[str, Any]:
        return {'registry': self.registry.stats(), 'orchestrator_url': self.orchestrator_url}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Cybersecurity-AEGIS Threat Intelligence Module')
    p.add_argument('--feeds-dir', default='feeds')
    p.add_argument('--orchestrator-url', default=None)
    p.add_argument('--check-ip', default=None, help='Look up a single IP')
    p.add_argument('--abuseipdb-key', default=os.getenv('ABUSEIPDB_API_KEY', ''))
    return p


def main() -> int:
    logging.basicConfig(level='INFO', format='%(asctime)s %(levelname)s %(name)s %(message)s')
    args = build_parser().parse_args()
    config: Dict[str, Any] = {'feeds_dir': args.feeds_dir}
    if args.orchestrator_url:
        config['orchestrator_url'] = args.orchestrator_url

    service = ThreatIntelService(config)

    if args.check_ip:
        ioc = service.registry.lookup_ip(args.check_ip)
        if ioc:
            print(json.dumps({'match': True, 'ioc': ioc.to_dict()}, indent=2))
        else:
            if args.abuseipdb_key:
                ioc = service.ingester.fetch_abuseipdb(args.check_ip, args.abuseipdb_key)
                if ioc:
                    print(json.dumps({'match': True, 'source': 'abuseipdb', 'ioc': ioc.to_dict()}, indent=2))
                    return 0
            print(json.dumps({'match': False, 'ip': args.check_ip}))
        return 0

    LOGGER.info('Threat intel service ready. Stats: %s', json.dumps(service.stats()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
