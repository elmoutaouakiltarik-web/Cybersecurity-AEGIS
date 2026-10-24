#!/bin/sh
set -e
while true; do
    echo "[network] Running simulation cycle..."
    python analyzer.py --simulate --cycles 200 --orchestrator-url "$ORCHESTRATOR_URL" || true
    echo "[network] Sleeping 60s..."
    sleep 60
done
