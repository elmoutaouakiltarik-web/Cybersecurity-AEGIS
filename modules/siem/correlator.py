#!/usr/bin/env python3
"""Cybersecurity-AEGIS SIEM Correlation Engine.

Provides:
- Rule-based event correlation (Sigma-inspired YAML rules)
- Temporal correlation (events within time windows)
- Alert deduplication and grouping
- Incident creation from correlated events
- Automated escalation to orchestrator

Safe by design: analysis only, no active response.
"""
from __future__ import annotations

import argparse
import collections
import json
import logging
import os
import re
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import yaml  # type: ignore
    _YAML = True
except ImportError:
    _YAML = False

try:
    import requests  # type: ignore
    _REQUESTS = True
except ImportError:
    _REQUESTS = False

# Shared secret for orchestrator ingest endpoints (must match AEGIS_INGEST_KEY).
_INGEST_HEADERS = {"X-AEGIS-INGEST-KEY": os.environ.get("AEGIS_INGEST_KEY", "")}

LOGGER = logging.getLogger('aegis.siem')


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── DATA MODELS ───────────────────────────────────────────────────────────────
@dataclass
class CorrelationRule:
    id: str
    name: str
    description: str
    severity: str
    category: str
    window_sec: int
    threshold: int
    match_fields: Dict[str, Any]
    group_by: List[str]
    mitre_technique_id: str = ''
    mitre_technique_name: str = ''
    tags: List[str] = field(default_factory=list)
    enabled: bool = True


@dataclass
class Incident:
    id: str
    rule_id: str
    rule_name: str
    severity: str
    category: str
    title: str
    description: str
    first_seen: str
    last_seen: str
    event_count: int
    source_ips: List[str]
    destination_ips: List[str]
    resolved: bool = False
    mitre_technique_id: str = ''
    mitre_technique_name: str = ''
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EventRecord:
    id: str
    timestamp: float
    source: str
    category: str
    severity: str
    title: str
    raw: Dict[str, Any]


# ── EVENT STORE ────────────────────────────────────────────────────────────────
class EventStore:
    """Sliding window in-memory event store."""

    def __init__(self, max_events: int = 50_000, max_age_sec: int = 3600) -> None:
        self.max_events = max_events
        self.max_age_sec = max_age_sec
        self._events: collections.deque[EventRecord] = collections.deque(maxlen=max_events)

    def add(self, event: EventRecord) -> None:
        self._events.append(event)

    def query_window(self, window_sec: int, category: str = '') -> List[EventRecord]:
        cutoff = time.time() - window_sec
        return [
            e for e in self._events
            if e.timestamp >= cutoff and (not category or e.category == category)
        ]

    def purge_old(self) -> int:
        cutoff = time.time() - self.max_age_sec
        old_len = len(self._events)
        self._events = collections.deque(
            (e for e in self._events if e.timestamp >= cutoff),
            maxlen=self.max_events,
        )
        return old_len - len(self._events)


# ── CORRELATION RULES ──────────────────────────────────────────────────────────
BUILTIN_RULES: List[CorrelationRule] = [
    CorrelationRule(
        id='AEGIS-COR-001',
        name='Brute Force Login Detection',
        description='Multiple failed authentication events from same source in short window',
        severity='high',
        category='identity',
        window_sec=120,
        threshold=5,
        match_fields={'title_contains': ['failed login', 'authentication failure', 'invalid password', 'wrong password']},
        group_by=['source_ip'],
        mitre_technique_id='T1110',
        mitre_technique_name='Brute Force',
        tags=['brute_force', 'credential_access'],
    ),
    CorrelationRule(
        id='AEGIS-COR-002',
        name='Lateral Movement Detection',
        description='Same source IP generating alerts in multiple categories within a window',
        severity='critical',
        category='network',
        window_sec=300,
        threshold=3,
        match_fields={'multi_category': True},
        group_by=['source_ip'],
        mitre_technique_id='T1021',
        mitre_technique_name='Remote Services',
        tags=['lateral_movement', 'multi_vector'],
    ),
    CorrelationRule(
        id='AEGIS-COR-003',
        name='ML IDS + Network Alert Correlation',
        description='CyberShield AI ATTACK prediction correlated with concurrent network alert',
        severity='critical',
        category='ml',
        window_sec=60,
        threshold=2,
        match_fields={'source_any': ['cybershield_ai', 'suricata', 'network_monitor']},
        group_by=['source_ip'],
        mitre_technique_id='T1041',
        mitre_technique_name='Exfiltration Over C2 Channel',
        tags=['ml_correlation', 'multi_source'],
    ),
    CorrelationRule(
        id='AEGIS-COR-004',
        name='OT + IT Attack Chain',
        description='Industrial alert followed by IT network alert — potential cross-domain attack',
        severity='critical',
        category='industrial',
        window_sec=600,
        threshold=2,
        match_fields={'multi_source_category': ['industrial', 'network']},
        group_by=['all'],
        mitre_technique_id='T0866',
        mitre_technique_name='Exploitation of Remote Services',
        tags=['ot_it_correlation', 'attack_chain'],
    ),
    CorrelationRule(
        id='AEGIS-COR-005',
        name='Reconnaissance Sweep',
        description='Port scan + DNS queries + ML probe detection in same window',
        severity='high',
        category='network',
        window_sec=180,
        threshold=3,
        match_fields={'title_contains': ['port scan', 'dns', 'probe', 'discovery', 'scan']},
        group_by=['source_ip'],
        mitre_technique_id='T1046',
        mitre_technique_name='Network Service Discovery',
        tags=['reconnaissance', 'discovery'],
    ),
    CorrelationRule(
        id='AEGIS-COR-006',
        name='File Integrity + Privilege Alert',
        description='File integrity change correlated with privilege escalation alert',
        severity='critical',
        category='endpoint',
        window_sec=300,
        threshold=2,
        match_fields={'title_contains': ['file integrity', 'privilege', 'root', 'admin', 'sudo', 'escalation']},
        group_by=['hostname'],
        mitre_technique_id='T1548',
        mitre_technique_name='Abuse Elevation Control Mechanism',
        tags=['privilege_escalation', 'fim'],
    ),
]


def load_rules_from_yaml(path: str) -> List[CorrelationRule]:
    if not _YAML or not os.path.exists(path):
        return []
    rules = []
    try:
        with open(path, encoding='utf-8') as fh:
            data = yaml.safe_load(fh) or {}
        for r in data.get('rules', []):
            rules.append(CorrelationRule(
                id=r.get('id', str(uuid.uuid4())),
                name=r['name'],
                description=r.get('description', ''),
                severity=r.get('severity', 'medium'),
                category=r.get('category', 'generic'),
                window_sec=int(r.get('window_sec', 300)),
                threshold=int(r.get('threshold', 3)),
                match_fields=r.get('match_fields', {}),
                group_by=r.get('group_by', []),
                mitre_technique_id=r.get('mitre_technique_id', ''),
                mitre_technique_name=r.get('mitre_technique_name', ''),
                tags=r.get('tags', []),
                enabled=r.get('enabled', True),
            ))
    except Exception as exc:
        LOGGER.warning('Failed to load YAML rules from %s: %s', path, exc)
    return rules


# ── RULE EVALUATOR ─────────────────────────────────────────────────────────────
class RuleEvaluator:
    """Evaluates a single correlation rule against recent events."""

    def evaluate(self, rule: CorrelationRule, events: List[EventRecord]) -> Optional[Incident]:
        if not rule.enabled:
            return None

        matching = self._filter_events(rule, events)
        if not matching:
            return None

        groups = self._group_events(rule, matching)
        for group_key, group_events in groups.items():
            if len(group_events) >= rule.threshold:
                return self._create_incident(rule, group_key, group_events)

        return None

    def _filter_events(self, rule: CorrelationRule, events: List[EventRecord]) -> List[EventRecord]:
        mf = rule.match_fields

        if 'title_contains' in mf:
            keywords = [k.lower() for k in mf['title_contains']]
            events = [e for e in events if any(kw in e.title.lower() for kw in keywords)]

        if 'source_any' in mf:
            sources = {s.lower() for s in mf['source_any']}
            events = [e for e in events if e.source.lower() in sources]

        if mf.get('multi_category'):
            src_ips = collections.Counter(e.raw.get('source_ip', '') for e in events if e.raw.get('source_ip'))
            repeat_ips = {ip for ip, count in src_ips.items() if count >= rule.threshold}
            events = [e for e in events if e.raw.get('source_ip') in repeat_ips]

        if 'multi_source_category' in mf:
            required_cats = set(mf['multi_source_category'])
            available_cats = {e.category for e in events}
            if not required_cats.issubset(available_cats):
                return []

        return events

    def _group_events(self, rule: CorrelationRule, events: List[EventRecord]) -> Dict[str, List[EventRecord]]:
        groups: Dict[str, List[EventRecord]] = collections.defaultdict(list)
        for event in events:
            if 'all' in rule.group_by:
                groups['global'].append(event)
            else:
                key_parts = []
                for field in rule.group_by:
                    if field == 'source_ip':
                        val = event.raw.get('source_ip', event.raw.get('src_ip', 'unknown'))
                    elif field == 'hostname':
                        val = event.raw.get('hostname', event.source)
                    else:
                        val = event.raw.get(field, 'unknown')
                    key_parts.append(str(val))
                groups[':'.join(key_parts)].append(event)
        return groups

    def _create_incident(self, rule: CorrelationRule, group_key: str, events: List[EventRecord]) -> Incident:
        src_ips = list({e.raw.get('source_ip', e.raw.get('src_ip', '')) for e in events if e.raw.get('source_ip', e.raw.get('src_ip'))})
        dst_ips = list({e.raw.get('destination_ip', e.raw.get('dst_ip', '')) for e in events if e.raw.get('destination_ip', e.raw.get('dst_ip'))})
        timestamps = sorted(e.timestamp for e in events)

        return Incident(
            id=f'INC-{int(time.time())}-{uuid.uuid4().hex[:6].upper()}',
            rule_id=rule.id,
            rule_name=rule.name,
            severity=rule.severity,
            category=rule.category,
            title=f'[{rule.severity.upper()}] {rule.name} — group: {group_key}',
            description=(
                f'{rule.description}. '
                f'{len(events)} events matched in {rule.window_sec}s window. '
                f'Group: {group_key}.'
            ),
            first_seen=datetime.fromtimestamp(timestamps[0], tz=timezone.utc).isoformat() if timestamps else now_iso(),
            last_seen=datetime.fromtimestamp(timestamps[-1], tz=timezone.utc).isoformat() if timestamps else now_iso(),
            event_count=len(events),
            source_ips=src_ips[:10],
            destination_ips=dst_ips[:10],
            mitre_technique_id=rule.mitre_technique_id,
            mitre_technique_name=rule.mitre_technique_name,
            tags=rule.tags,
        )


# ── DEDUPLICATION ──────────────────────────────────────────────────────────────
class IncidentDeduplicator:
    """Prevents duplicate incident creation for the same rule/group within a cooldown period."""

    def __init__(self, cooldown_sec: int = 300) -> None:
        self.cooldown_sec = cooldown_sec
        self._seen: Dict[str, float] = {}

    def is_duplicate(self, rule_id: str, group_key: str) -> bool:
        key = f'{rule_id}:{group_key}'
        last = self._seen.get(key, 0.0)
        return time.time() - last < self.cooldown_sec

    def record(self, rule_id: str, group_key: str) -> None:
        self._seen[f'{rule_id}:{group_key}'] = time.time()


# ── SIEM CORRELATOR ────────────────────────────────────────────────────────────
class SIEMCorrelator:
    """Main SIEM correlation engine."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.config = config
        self.orchestrator_url = str(
            config.get('orchestrator_url')
            or os.getenv('ORCHESTRATOR_URL', 'http://localhost:8080')
        )
        self.event_store = EventStore()
        self.evaluator = RuleEvaluator()
        self.dedup = IncidentDeduplicator(cooldown_sec=int(config.get('dedup_cooldown_sec', 300)))
        self.incidents: List[Incident] = []
        self.stats = {'events_ingested': 0, 'incidents_created': 0, 'rules_loaded': 0}

        # Load rules
        self.rules: List[CorrelationRule] = list(BUILTIN_RULES)
        rules_file = config.get('rules_file', 'siem_rules.yaml')
        custom_rules = load_rules_from_yaml(rules_file)
        self.rules.extend(custom_rules)
        self.stats['rules_loaded'] = len(self.rules)
        LOGGER.info('SIEM correlator initialized with %d rules', len(self.rules))

    def ingest(self, event_data: Dict[str, Any]) -> List[Incident]:
        record = EventRecord(
            id=str(uuid.uuid4()),
            timestamp=time.time(),
            source=str(event_data.get('source', 'unknown')),
            category=str(event_data.get('category', 'generic')),
            severity=str(event_data.get('severity', 'info')),
            title=str(event_data.get('title', '')),
            raw=event_data,
        )
        self.event_store.add(record)
        self.stats['events_ingested'] += 1
        return self._run_correlation()

    def _run_correlation(self) -> List[Incident]:
        new_incidents: List[Incident] = []
        for rule in self.rules:
            recent = self.event_store.query_window(rule.window_sec)
            incident = self.evaluator.evaluate(rule, recent)
            if incident is None:
                continue
            group_key = incident.title.split('group: ')[-1] if 'group: ' in incident.title else 'global'
            if self.dedup.is_duplicate(rule.id, group_key):
                continue
            self.dedup.record(rule.id, group_key)
            self.incidents.append(incident)
            self.stats['incidents_created'] += 1
            new_incidents.append(incident)
            LOGGER.warning('[INCIDENT] %s | %s', incident.severity.upper(), incident.title)
            self._forward_incident(incident)

        return new_incidents

    def _forward_incident(self, incident: Incident) -> None:
        if not _REQUESTS:
            return
        payload = {
            'source': 'siem_correlator',
            'category': incident.category,
            'severity': incident.severity,
            'title': incident.title,
            'description': incident.description,
            'tags': ['siem', 'correlation', 'incident'] + incident.tags,
            'raw_data': incident.to_dict(),
        }
        try:
            requests.post(f'{self.orchestrator_url}/api/v1/ingest/generic', json=payload, timeout=3, headers=_INGEST_HEADERS)
        except Exception as exc:
            LOGGER.debug('Orchestrator forward failed: %s', exc)

    def status(self) -> Dict[str, Any]:
        return {
            **self.stats,
            'active_rules': len([r for r in self.rules if r.enabled]),
            'stored_events': len(self.event_store._events),
            'recent_incidents': [i.to_dict() for i in self.incidents[-5:]],
        }

    def run_demo(self) -> None:
        """Inject demo events to demonstrate correlation."""
        LOGGER.info('Running SIEM correlation demo...')
        demo_events = [
            {'source': 'wazuh', 'category': 'identity', 'severity': 'medium',
             'title': 'Failed login attempt', 'source_ip': '10.0.1.50',
             'description': 'Authentication failure for user admin'},
            {'source': 'wazuh', 'category': 'identity', 'severity': 'medium',
             'title': 'Failed login attempt', 'source_ip': '10.0.1.50'},
            {'source': 'wazuh', 'category': 'identity', 'severity': 'medium',
             'title': 'Authentication failure invalid password', 'source_ip': '10.0.1.50'},
            {'source': 'wazuh', 'category': 'identity', 'severity': 'medium',
             'title': 'Failed login attempt', 'source_ip': '10.0.1.50'},
            {'source': 'wazuh', 'category': 'identity', 'severity': 'high',
             'title': 'Authentication failure invalid password', 'source_ip': '10.0.1.50'},
            {'source': 'network_monitor', 'category': 'network', 'severity': 'high',
             'title': 'Vertical port scan detected', 'source_ip': '10.0.1.50'},
            {'source': 'cybershield_ai', 'category': 'ml', 'severity': 'high',
             'title': 'CyberShield AI: ATTACK / Probe', 'source_ip': '10.0.1.50'},
            {'source': 'suricata', 'category': 'network', 'severity': 'critical',
             'title': 'ET SCAN nmap TCP SYN scan', 'source_ip': '10.0.1.50'},
        ]
        for evt in demo_events:
            incidents = self.ingest(evt)
            for inc in incidents:
                print(json.dumps(inc.to_dict(), indent=2))
            time.sleep(0.1)
        print('\n=== SIEM Status ===')
        print(json.dumps(self.status(), indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Cybersecurity-AEGIS SIEM Correlation Engine')
    p.add_argument('--orchestrator-url', default=None)
    p.add_argument('--rules-file', default='siem_rules.yaml')
    p.add_argument('--demo', action='store_true', help='Run correlation demo')
    p.add_argument('--dedup-cooldown', type=int, default=300)
    return p


def main() -> int:
    logging.basicConfig(level='INFO', format='%(asctime)s %(levelname)s %(name)s %(message)s')
    args = build_parser().parse_args()
    config: Dict[str, Any] = {
        'rules_file': args.rules_file,
        'dedup_cooldown_sec': args.dedup_cooldown,
    }
    if args.orchestrator_url:
        config['orchestrator_url'] = args.orchestrator_url
    correlator = SIEMCorrelator(config)
    if args.demo:
        correlator.run_demo()
        return 0
    LOGGER.info('SIEM correlator ready. Status: %s', json.dumps(correlator.status()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
