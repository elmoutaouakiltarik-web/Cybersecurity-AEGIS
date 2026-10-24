#!/bin/sh
set -e
while true; do
    echo "[ot_monitor] Running simulation cycle..."
    python main.py --simulate --cycles 100 --orchestrator-url "$ORCHESTRATOR_URL" || true
    echo "[ot_monitor] Sleeping 60s..."
    sleep 60
done
