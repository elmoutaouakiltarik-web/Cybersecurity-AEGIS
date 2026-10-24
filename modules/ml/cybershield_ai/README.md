# CyberShield AI Real Pro v0.3 FINAL

Pacchetto reale e scaricabile con modelli AI difensivi già addestrati sui dati reali NSL-KDD disponibili nel pacchetto base.

## Verità tecnica

- **Dati sintetici usati per training:** NO.
- **Dataset incorporato:** NSL-KDD, subset reale incluso in `data/real/nsl_kdd_real_training_subset_v0_3.csv`.
- **Righe reali incorporate:** 122.
- **Feature NSL-KDD:** 41.
- **SHA256 dataset incorporato:** `371aafb74a9174a98b0081d56d0570b3e081848d2259d44679297a6aa3b8786d`.
- **Uso:** difensivo IDS/NDR/SIEM; non offensivo.

> Nota onesta: questo pacchetto contiene modelli veri `.joblib` già addestrati, ma sui 122 record reali disponibili nel pacchetto base. Per una versione da produzione bisogna aggiungere il dataset completo `KDDTrain+.txt`/`KDDTest+.txt` e riaddestrare con `scripts/train_on_full_nsl_kdd.py`.

## Cosa c'è dentro

```text
models/
  cybershield_realpro_binary_ensemble_v0_3.joblib
  cybershield_realpro_attack_family_v0_3.joblib
  cybershield_realpro_anomaly_baseline_v0_3.joblib
src/cybershield_pro/
  predict.py, train.py, risk.py, schema.py, io.py
api/app.py
dashboard/streamlit_app.py
reports/training_report_v0_3.json
reports/model_manifest_v0_3.json
integrations/wazuh, zeek, suricata, stackstorm, ot_ics
scripts/verify_package.py
scripts/train_on_full_nsl_kdd.py
```

## Modelli

| Modello | File | Funzione |
|---|---|---|
| Binary ensemble | `models/cybershield_realpro_binary_ensemble_v0_3.joblib` | BENIGN vs ATTACK |
| Attack family | `models/cybershield_realpro_attack_family_v0_3.joblib` | BENIGN, DoS, Probe, R2L |
| Anomaly baseline | `models/cybershield_realpro_anomaly_baseline_v0_3.joblib` | comportamento diverso dal benign baseline |

## Metriche sul subset reale incorporato

Vedi `reports/training_report_v0_3.json` per metriche complete, confusion matrix e cross-validation.

## Avvio rapido Windows

```powershell
.\quickstart_windows.ps1
```

## Avvio API

```powershell
$env:PYTHONPATH="$PWD\src"
uvicorn api.app:app --host 0.0.0.0 --port 8919
```

## Predizione CLI

```powershell
$env:PYTHONPATH="$PWD\src"
python -m cybershield_pro.predict --input examples/real_nsl_kdd_input_example_v0_3.csv --output reports/predictions.csv --ot-ics
```

## Dashboard

```powershell
$env:PYTHONPATH="$PWD\src"
streamlit run dashboard/streamlit_app.py
```

## Retraining su full NSL-KDD

Metti il file reale `KDDTrain+.txt` in `data/real/KDDTrain+.txt`, poi:

```powershell
.\scriptsetrain_on_full_nsl_kdd.ps1
```

## Regola importante OT/ICS

In industria il modello deve fare **alert e risk scoring**, non bloccare automaticamente PLC/SCADA. Le azioni di contenimento devono passare da approvazione umana e finestra operativa.
