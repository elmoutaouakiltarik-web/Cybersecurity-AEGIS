#!/usr/bin/env python3
"""Cybersecurity-AEGIS Vulnerability Scanner Service."""
from __future__ import annotations

import logging
import os
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from scanner import VulnerabilityScanner

LOGGER = logging.getLogger('aegis.vuln_service')
ORCH_URL = os.getenv('ORCHESTRATOR_URL', 'http://localhost:8080')
SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', '300'))


def main() -> int:
    logging.basicConfig(level='INFO', format='%(asctime)s %(levelname)s %(name)s %(message)s')
    LOGGER.info('Vulnerability scanner service starting. Scan interval=%ds', SCAN_INTERVAL)

    scanner = VulnerabilityScanner({'orchestrator_url': ORCH_URL, 'active_scan': False})

    # No demo scan: keep service idle unless real events/trigger drive scanning.
    while True:
        # keep alive; real actions are driven by API /trigger and scanner.enrich_from_event
        time.sleep(SCAN_INTERVAL)
        LOGGER.info('Vulnerability scanner service heartbeat (no demo)')




if __name__ == '__main__':
    raise SystemExit(main())
