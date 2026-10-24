$ErrorActionPreference = "Stop"
if (!(Test-Path "dataeal\KDDTrain+.txt")) {
  Write-Host "Metti il file reale KDDTrain+.txt in dataeal\KDDTrain+.txt prima di eseguire questo script."
  exit 1
}
$env:PYTHONPATH = "$PWD\src"
python scripts	rain_on_full_nsl_kdd.py --input dataeal\KDDTrain+.txt --output-dir retrained_full_nsl_kdd
Write-Host "Retraining completato in retrained_full_nsl_kdd"
