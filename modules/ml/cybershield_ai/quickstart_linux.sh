#!/usr/bin/env bash
set -euo pipefail
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH="$PWD/src"
python -m cybershield_pro.predict --input examples/real_nsl_kdd_input_example_v0_3.csv --output reports/local_predictions_v0_3.csv --ot-ics
python scripts/verify_package.py
echo "OK: CyberShield AI Real Pro v0.3 pronto. Predizioni in reports/local_predictions_v0_3.csv"
