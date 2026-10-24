from __future__ import annotations
import json, hashlib, sys
from pathlib import Path
import joblib, pandas as pd
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from cybershield_pro.predict import predict_dataframe

manifest = json.loads((ROOT/'reports/model_manifest_v0_3.json').read_text(encoding='utf-8'))
data_path = ROOT / manifest['training_data']['local_file']
sha = hashlib.sha256(data_path.read_bytes()).hexdigest()
assert sha == manifest['training_data']['sha256'], 'DATA HASH MISMATCH'
for m in ['cybershield_realpro_binary_ensemble_v0_3.joblib','cybershield_realpro_attack_family_v0_3.joblib','cybershield_realpro_anomaly_baseline_v0_3.joblib']:
    payload = joblib.load(ROOT/'models'/m)
    assert 'model' in payload and 'metadata' in payload and 'feature_columns' in payload, f'Bad model payload {m}'
ex = pd.read_csv(ROOT/'examples/real_nsl_kdd_input_example_v0_3.csv')
out = predict_dataframe(ex, ot_ics=True)
assert len(out) == len(ex)
print(json.dumps({'ok': True, 'data_sha256': sha, 'models_checked': 3, 'prediction_rows': len(out)}, indent=2))
