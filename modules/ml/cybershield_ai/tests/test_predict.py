from pathlib import Path
import pandas as pd
from cybershield_pro.predict import predict_dataframe
ROOT = Path(__file__).resolve().parents[1]

def test_predict_example():
    df = pd.read_csv(ROOT/'examples/real_nsl_kdd_input_example_v0_3.csv')
    out = predict_dataframe(df, ot_ics=True)
    assert len(out) == len(df)
    assert 'risk_score' in out.columns
    assert 'recommended_action' in out.columns
