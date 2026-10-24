#!/usr/bin/env python3
"""Cybersecurity-AEGIS SOAR Service — polling orchestrator events."""
from __future__ import annotations

import logging
import os
import sys
import time
from typing import Any, Dict, List

try:
    import requests  # type: ignore
except ImportError:
    requests = None  # type: ignore

sys.path.insert(0, os.path.dirname(__file__))
from executor import PlaybookExecutor

LOGGER = logging.getLogger('aegis.soar_service')
ORCH_URL = os.getenv('ORCHESTRATOR_URL', 'http://localhost:8080')
POLL_SEC = int(os.getenv('POLL_INTERVAL', '10'))
DRY_RUN = os.getenv('SOAR_LIVE_MODE', '').lower() not in {'1', 'true'}


def fetch_recent_events() -> List[Dict[str, Any]]:
    if requests is None:
        return []
    try:
        resp = requests.get(f'{ORCH_URL}/api/v1/events?limit=50', timeout=5)
        if resp.status_code == 200:
            return resp.json()
    except Exception as exc:
        LOGGER.debug('Event fetch failed: %s', exc)
    return []


def main() -> int:
    logging.basicConfig(level='INFO', format='%(asctime)s %(levelname)s %(name)s %(message)s')
    LOGGER.info('SOAR service starting. Polling %s every %ds (dry_run=%s)', ORCH_URL, POLL_SEC, DRY_RUN)

    executor = PlaybookExecutor({'orchestrator_url': ORCH_URL, 'dry_run': DRY_RUN})
    seen_ids: set[str] = set()

    while True:
        events = fetch_recent_events()
        for ev in events:
            eid = ev.get('id')
            if not eid or eid in seen_ids:
                continue
            seen_ids.add(eid)

            sev = str(ev.get('severity', '')).lower()
            if sev not in ('high', 'critical'):
                continue

            executions = executor.handle_event(ev)
            if executions:
                LOGGER.warning('[SOAR] Triggered %d playbook(s) for event %s', len(executions), eid)

        if len(seen_ids) > 10000:
            seen_ids = set(list(seen_ids)[-5000:])

        time.sleep(POLL_SEC)


if __name__ == '__main__':
    raise SystemExit(main())
