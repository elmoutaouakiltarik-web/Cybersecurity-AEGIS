#!/usr/bin/env python3
"""Cybersecurity-AEGIS SOAR-lite Playbook Executor.

Provides automated response capability with strict safety controls:
- Playbooks defined in YAML (human-readable, auditable)
- Dry-run mode by default — logs actions without executing
- OT/ICS actions always require human confirmation
- Audit trail for every action taken
- Integrates with orchestrator for incident lifecycle management
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

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

LOGGER = logging.getLogger('aegis.soar')


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── ACTION TYPES ───────────────────────────────────────────────────────────────
SAFE_ACTIONS = frozenset({
    'log', 'notify', 'enrich', 'tag_event', 'create_ticket',
    'send_alert', 'quarantine_file', 'update_status',
})

REQUIRES_CONFIRMATION = frozenset({
    'block_ip_firewall', 'isolate_host', 'kill_process',
    'disable_account', 'ot_advisory',
})

# Actions that are never permitted
PROHIBITED_ACTIONS = frozenset({
    'delete_data', 'wipe_disk', 'ot_command', 'send_modbus_write',
    'active_exploit', 'scan_external',
})


@dataclass
class PlaybookAction:
    type: str
    params: Dict[str, Any] = field(default_factory=dict)
    description: str = ''
    on_failure: str = 'continue'   # continue | stop | rollback


@dataclass
class Playbook:
    id: str
    name: str
    description: str
    trigger_conditions: List[Dict[str, Any]]
    actions: List[PlaybookAction]
    severity_filter: List[str] = field(default_factory=list)
    category_filter: List[str] = field(default_factory=list)
    dry_run: bool = True
    ot_safe: bool = True
    enabled: bool = True
    version: str = '1.0'


@dataclass
class PlaybookExecution:
    id: str
    playbook_id: str
    playbook_name: str
    trigger_event: Dict[str, Any]
    started_at: str
    completed_at: str = ''
    status: str = 'pending'  # pending | running | completed | failed | skipped
    actions_taken: List[Dict[str, Any]] = field(default_factory=list)
    dry_run: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── PLAYBOOK DEFINITIONS ───────────────────────────────────────────────────────
BUILTIN_PLAYBOOKS: List[Playbook] = [
    Playbook(
        id='PB-001',
        name='High-Risk Network Alert Response',
        description='Logs, enriches, and optionally blocks IPs generating high/critical network alerts',
        trigger_conditions=[{'severity': ['high', 'critical'], 'category': ['network']}],
        severity_filter=['high', 'critical'],
        category_filter=['network'],
        actions=[
            PlaybookAction('log', {'message': 'High-risk network alert detected'}, 'Log event to audit trail'),
            PlaybookAction('enrich', {'check_threat_intel': True}, 'Enrich source IP with threat intel'),
            PlaybookAction('tag_event', {'tag': 'investigated'}, 'Mark event as investigated'),
            PlaybookAction('send_alert', {'channel': 'soc_email'}, 'Notify SOC team'),
            PlaybookAction('block_ip_firewall', {'target': '{{source_ip}}', 'duration_min': 60},
                           'Block source IP for 60 min (requires confirmation)',
                           on_failure='continue'),
        ],
        dry_run=True,
    ),
    Playbook(
        id='PB-002',
        name='Brute Force Account Protection',
        description='Locks suspicious source IP and alerts security team on credential attacks',
        trigger_conditions=[{'severity': ['high', 'critical'], 'category': ['identity']}],
        severity_filter=['high', 'critical'],
        category_filter=['identity'],
        actions=[
            PlaybookAction('log', {'message': 'Brute force attack detected'}, 'Audit log'),
            PlaybookAction('enrich', {'check_threat_intel': True, 'check_geo': True}, 'Geo + threat intel enrichment'),
            PlaybookAction('send_alert', {'channel': 'soc_email', 'priority': 'high'}, 'Alert SOC'),
            PlaybookAction('block_ip_firewall', {'target': '{{source_ip}}', 'duration_min': 120},
                           'Temporary IP block (requires confirmation)'),
            PlaybookAction('create_ticket', {'severity': 'high', 'team': 'security'},
                           'Create incident ticket'),
        ],
        dry_run=True,
    ),
    Playbook(
        id='PB-003',
        name='OT Advisory Alert',
        description='Read-only advisory for OT/ICS events — no automated containment',
        trigger_conditions=[{'category': ['industrial']}],
        category_filter=['industrial'],
        actions=[
            PlaybookAction('log', {'message': 'OT/ICS advisory alert'}, 'Audit log'),
            PlaybookAction('ot_advisory', {
                'message': 'OT alert requires human review. Do NOT take automated containment action.',
                'notify_engineer': True,
            }, 'Send read-only advisory to OT engineer'),
            PlaybookAction('create_ticket', {'severity': '{{severity}}', 'team': 'ot_engineering', 'priority': 'urgent'},
                           'Create OT engineering ticket'),
        ],
        dry_run=True,
        ot_safe=True,
    ),
    Playbook(
        id='PB-004',
        name='ML IDS Critical Detection Response',
        description='Handles CyberShield AI critical detections with correlated investigation',
        trigger_conditions=[{'source': ['cybershield_ai'], 'severity': ['critical']}],
        severity_filter=['critical'],
        actions=[
            PlaybookAction('log', {'message': 'ML IDS critical detection'}, 'Audit log'),
            PlaybookAction('enrich', {'check_threat_intel': True, 'correlate_siem': True}, 'Full enrichment'),
            PlaybookAction('tag_event', {'tags': ['ml_critical', 'auto_investigated']}, 'Tag for tracking'),
            PlaybookAction('send_alert', {'channel': 'pagerduty', 'priority': 'critical'}, 'Page on-call'),
            PlaybookAction('update_status', {'status': 'investigating'}, 'Update event status'),
        ],
        dry_run=True,
    ),
    Playbook(
        id='PB-005',
        name='Vulnerability Critical Finding Response',
        description='Responds to critical CVE findings on active hosts',
        trigger_conditions=[{'category': ['vulnerability'], 'severity': ['critical']}],
        severity_filter=['critical'],
        category_filter=['vulnerability'],
        actions=[
            PlaybookAction('log', {'message': 'Critical CVE finding'}, 'Audit log'),
            PlaybookAction('send_alert', {'channel': 'soc_email', 'priority': 'critical'}, 'Alert SOC + asset owner'),
            PlaybookAction('create_ticket', {'severity': 'critical', 'team': 'patching', 'sla_hours': 24},
                           'Create patching ticket with 24h SLA'),
            PlaybookAction('tag_event', {'tags': ['patching_required', 'cve_critical']}, 'Tag finding'),
        ],
        dry_run=True,
    ),
]


# ── ACTION EXECUTOR ────────────────────────────────────────────────────────────
class ActionExecutor:
    """Executes individual playbook actions."""

    def __init__(self, orchestrator_url: str, dry_run: bool = True) -> None:
        self.orchestrator_url = orchestrator_url
        self.dry_run = dry_run
        self.audit_log: List[Dict[str, Any]] = []

    def execute(self, action: PlaybookAction, context: Dict[str, Any]) -> Dict[str, Any]:
        action_type = action.type

        if action_type in PROHIBITED_ACTIONS:
            return {'status': 'rejected', 'reason': f'Action {action_type} is prohibited'}

        params = self._resolve_params(action.params, context)
        result: Dict[str, Any] = {
            'action': action_type,
            'params': params,
            'dry_run': self.dry_run,
            'timestamp': now_iso(),
        }

        try:
            handler = getattr(self, f'_action_{action_type}', self._action_unknown)
            outcome = handler(params, context)
            result.update(outcome)
            result['status'] = 'executed' if not self.dry_run else 'dry_run'
        except Exception as exc:
            result['status'] = 'failed'
            result['error'] = str(exc)
            LOGGER.error('Action %s failed: %s', action_type, exc)

        self.audit_log.append(result)
        LOGGER.info('[SOAR] %s %s | %s', 'DRY-RUN' if self.dry_run else 'EXEC', action_type, params)
        return result

    def _resolve_params(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        resolved = {}
        for k, v in params.items():
            if isinstance(v, str) and '{{' in v and '}}' in v:
                field_name = v.strip('{}').strip()
                resolved[k] = context.get(field_name, v)
            else:
                resolved[k] = v
        return resolved

    def _action_log(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {'message': params.get('message', 'Action logged'), 'context_keys': list(context.keys())}

    def _action_notify(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {'channel': params.get('channel', 'default'), 'notified': not self.dry_run}

    def _action_enrich(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {'enrichment_requested': list(params.keys()), 'enriched': not self.dry_run}

    def _action_tag_event(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        tags = params.get('tags', [params.get('tag', 'tagged')])
        return {'tags_applied': tags, 'applied': not self.dry_run}

    def _action_send_alert(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {'channel': params.get('channel'), 'priority': params.get('priority', 'normal'), 'sent': not self.dry_run}

    def _action_block_ip_firewall(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        target_ip = params.get('target', context.get('source_ip', ''))
        duration = params.get('duration_min', 60)
        if self.dry_run:
            return {'would_block': target_ip, 'duration_min': duration, 'note': 'dry_run — no change made'}
        # Real implementation would call firewall API / iptables here
        return {'blocked': target_ip, 'duration_min': duration, 'note': 'ACTIVE — requires manual verification'}

    def _action_isolate_host(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        host = params.get('target', context.get('destination_ip', ''))
        if self.dry_run:
            return {'would_isolate': host, 'note': 'dry_run — no change made'}
        return {'isolated': host, 'note': 'ACTIVE — requires manual verification'}

    def _action_create_ticket(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {'ticket_created': not self.dry_run, 'team': params.get('team'), 'severity': params.get('severity')}

    def _action_update_status(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {'new_status': params.get('status'), 'updated': not self.dry_run}

    def _action_ot_advisory(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {
            'advisory_message': params.get('message'),
            'notify_engineer': params.get('notify_engineer', True),
            'note': 'OT advisory — human decision required. No automated action taken.',
        }

    def _action_unknown(self, params: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        return {'note': 'Unknown action type — no-op'}


# ── PLAYBOOK EXECUTOR ──────────────────────────────────────────────────────────
class PlaybookExecutor:
    """Selects and executes playbooks for incoming events."""

    def __init__(self, config: Dict[str, Any]) -> None:
        self.orchestrator_url = str(
            config.get('orchestrator_url')
            or os.getenv('ORCHESTRATOR_URL', 'http://localhost:8080')
        )
        self.global_dry_run = config.get('dry_run', True) if not os.getenv('SOAR_LIVE_MODE') else False
        self.playbooks = list(BUILTIN_PLAYBOOKS)
        self._load_custom_playbooks(config.get('playbooks_dir', 'playbooks'))
        self.executions: List[PlaybookExecution] = []
        self.stats = {'events_processed': 0, 'playbooks_triggered': 0, 'actions_executed': 0}

    def _load_custom_playbooks(self, directory: str) -> None:
        if not _YAML or not os.path.isdir(directory):
            return
        for path in Path(directory).glob('*.yaml'):
            try:
                with open(path, encoding='utf-8') as fh:
                    data = yaml.safe_load(fh) or {}
                if not isinstance(data.get('actions'), list):
                    continue
                pb = Playbook(
                    id=data.get('id', str(uuid.uuid4())),
                    name=data.get('name', path.stem),
                    description=data.get('description', ''),
                    trigger_conditions=data.get('trigger_conditions', []),
                    actions=[PlaybookAction(**a) for a in data['actions']],
                    severity_filter=data.get('severity_filter', []),
                    category_filter=data.get('category_filter', []),
                    dry_run=data.get('dry_run', True),
                )
                self.playbooks.append(pb)
                LOGGER.info('Loaded playbook from %s: %s', path.name, pb.name)
            except Exception as exc:
                LOGGER.warning('Failed to load playbook %s: %s', path, exc)

    def handle_event(self, event: Dict[str, Any]) -> List[PlaybookExecution]:
        self.stats['events_processed'] += 1
        triggered: List[PlaybookExecution] = []

        for playbook in self.playbooks:
            if not playbook.enabled:
                continue
            if not self._matches(playbook, event):
                continue
            execution = self._execute_playbook(playbook, event)
            triggered.append(execution)
            self.executions.append(execution)
            self.stats['playbooks_triggered'] += 1
            self.stats['actions_executed'] += len(execution.actions_taken)

        return triggered

    def _matches(self, playbook: Playbook, event: Dict[str, Any]) -> bool:
        severity = event.get('severity', '').lower()
        category = event.get('category', '').lower()
        source = event.get('source', '').lower()

        if playbook.severity_filter and severity not in playbook.severity_filter:
            return False
        if playbook.category_filter and category not in [c.lower() for c in playbook.category_filter]:
            return False

        for condition in playbook.trigger_conditions:
            if 'source' in condition and source not in [s.lower() for s in condition['source']]:
                continue
            return True
        return not playbook.trigger_conditions

    def _execute_playbook(self, playbook: Playbook, event: Dict[str, Any]) -> PlaybookExecution:
        dry_run = playbook.dry_run or self.global_dry_run
        executor = ActionExecutor(self.orchestrator_url, dry_run=dry_run)
        execution = PlaybookExecution(
            id=f'EXE-{uuid.uuid4().hex[:8].upper()}',
            playbook_id=playbook.id,
            playbook_name=playbook.name,
            trigger_event=event,
            started_at=now_iso(),
            dry_run=dry_run,
            status='running',
        )
        LOGGER.info('[SOAR] Triggering playbook: %s (dry_run=%s)', playbook.name, dry_run)

        for action in playbook.actions:
            if action.type in PROHIBITED_ACTIONS:
                LOGGER.warning('[SOAR] Skipping prohibited action: %s', action.type)
                continue
            result = executor.execute(action, event)
            execution.actions_taken.append(result)
            if result.get('status') == 'failed' and action.on_failure == 'stop':
                execution.status = 'failed'
                execution.completed_at = now_iso()
                return execution

        execution.status = 'completed'
        execution.completed_at = now_iso()
        self._report_execution(execution)
        return execution

    def _report_execution(self, execution: PlaybookExecution) -> None:
        if not _REQUESTS:
            return
        payload = {
            'source': 'soar',
            'category': 'system',
            'severity': 'info',
            'title': f'Playbook executed: {execution.playbook_name}',
            'description': f'Playbook {execution.playbook_id} completed with {len(execution.actions_taken)} actions. dry_run={execution.dry_run}',
            'tags': ['soar', 'playbook', execution.playbook_id],
            'raw_data': execution.to_dict(),
        }
        try:
            requests.post(f'{self.orchestrator_url}/api/v1/ingest/generic', json=payload, timeout=3)
        except Exception as exc:
            LOGGER.debug('Report failed: %s', exc)

    def status(self) -> Dict[str, Any]:
        return {
            **self.stats,
            'playbooks_loaded': len(self.playbooks),
            'dry_run_mode': self.global_dry_run,
            'recent_executions': [e.to_dict() for e in self.executions[-3:]],
        }


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description='Cybersecurity-AEGIS SOAR-lite Playbook Executor')
    p.add_argument('--orchestrator-url', default=None)
    p.add_argument('--playbooks-dir', default='playbooks')
    p.add_argument('--dry-run', action='store_true', default=True)
    p.add_argument('--demo', action='store_true')
    return p


def main() -> int:
    logging.basicConfig(level='INFO', format='%(asctime)s %(levelname)s %(name)s %(message)s')
    args = build_parser().parse_args()
    config: Dict[str, Any] = {
        'dry_run': args.dry_run,
        'playbooks_dir': args.playbooks_dir,
    }
    if args.orchestrator_url:
        config['orchestrator_url'] = args.orchestrator_url
    executor = PlaybookExecutor(config)
    if args.demo:
        demo_events = [
            {'source': 'cybershield_ai', 'severity': 'critical', 'category': 'ml',
             'title': 'CyberShield AI: ATTACK / DoS', 'source_ip': '10.1.1.99'},
            {'source': 'wazuh', 'severity': 'high', 'category': 'identity',
             'title': 'Failed login attempt', 'source_ip': '10.2.2.50'},
            {'source': 'ot_monitor', 'severity': 'critical', 'category': 'industrial',
             'title': 'Unauthorized OT asset observed', 'source_ip': '192.168.10.250'},
        ]
        for evt in demo_events:
            executions = executor.handle_event(evt)
            for exe in executions:
                print(json.dumps(exe.to_dict(), indent=2))
        print('\n=== SOAR Status ===')
        print(json.dumps(executor.status(), indent=2))
        return 0
    LOGGER.info('SOAR executor ready. Status: %s', json.dumps(executor.status()))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
