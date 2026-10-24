from pathlib import Path
import joblib

ROOT = Path(__file__).resolve().parents[1]

def test_models_exist_and_load():
    for name in ['cybershield_realpro_binary_ensemble_v0_3.joblib','cybershield_realpro_attack_family_v0_3.joblib','cybershield_realpro_anomaly_baseline_v0_3.joblib']:
        payload = joblib.load(ROOT/'models'/name)
        assert 'model' in payload
        assert 'feature_columns' in payload
        assert payload['metadata']['training_data']['synthetic_data_used'] is False
