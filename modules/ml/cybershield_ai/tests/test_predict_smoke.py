import joblib
import pandas as pd
from cybershield_pro.io import align_features

def test_align_features():
    df = pd.DataFrame([{'protocol_type':'tcp','service':'http','flag':'SF'}])
    X = align_features(df)
    assert X.shape[1] == 41
