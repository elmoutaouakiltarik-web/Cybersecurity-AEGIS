#!/usr/bin/env python3
"""Cybersecurity-AEGIS SIEM Service — polling orchestrator events."""
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
from correlator import SIEMCorrelator

LOGGER = logging.getLogger('aegis.siem_service')
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
    LOGGER.info('SIEM service starting. Polling %s every %ds', ORCH_URL, POLL_SEC)

    correlator = SIEMCorrelator({'orchestrator_url': ORCH_URL})
    seen_ids: set[str] = set()

    while True:
        events = fetch_recent_events()
        for ev in events:
            eid = ev.get('id')
            if not eid or eid in seen_ids:
                continue
            seen_ids.add(eid)

            payload = {
                'source': ev.get('source', 'unknown'),
                'category': ev.get('category', 'generic'),
                'severity': ev.get('severity', 'info'),
                'title': ev.get('title', ''),
                'description': ev.get('description', ''),
                'source_ip': ev.get('raw_data', {}).get('source_ip', ''),
            }
            incidents = correlator.ingest(payload)
            if incidents:
                LOGGER.warning('[SIEM] Created %d incident(s)', len(incidents))

        if len(seen_ids) > 10000:
            seen_ids = set(list(seen_ids)[-5000:])

        time.sleep(POLL_SEC)


if __name__ == '__main__':
    raise SystemExit(main())
