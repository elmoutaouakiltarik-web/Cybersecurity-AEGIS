#!/usr/bin/env python3
"""Cybersecurity-AEGIS Threat Intel Service — polling orchestrator events."""
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
from feeds import ThreatIntelService

LOGGER = logging.getLogger('aegis.ti_service')
ORCH_URL = os.getenv('ORCHESTRATOR_URL', 'http://localhost:8080')
POLL_SEC = int(os.getenv('POLL_INTERVAL', '10'))


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
    LOGGER.info('Threat Intel service starting. Polling %s every %ds', ORCH_URL, POLL_SEC)

    service = ThreatIntelService({'orchestrator_url': ORCH_URL})
    seen_ids: set[str] = set()

    while True:
        events = fetch_recent_events()
        for ev in events:
            eid = ev.get('id')
            if not eid or eid in seen_ids:
                continue
            seen_ids.add(eid)
            result = service.enrich_event(ev)
            if result.get('matched'):
                LOGGER.warning('[TI] IOC match on event %s: severity=%s', eid, result.get('highest_severity'))

        if len(seen_ids) > 10000:
            seen_ids = set(list(seen_ids)[-5000:])

        time.sleep(POLL_SEC)


if __name__ == '__main__':
    raise SystemExit(main())
