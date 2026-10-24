$ErrorActionPreference = "Stop"
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PYTHONPATH = "$PWD\src"
python -m cybershield_pro.predict --input examples/real_nsl_kdd_input_example_v0_3.csv --output reports/local_predictions_v0_3.csv --ot-ics
python scriptserify_package.py
Write-Host "OK: CyberShield AI Real Pro v0.3 pronto. Predizioni in reports/local_predictions_v0_3.csv"
