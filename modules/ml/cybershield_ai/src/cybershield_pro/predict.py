from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from .io import align_features
from .risk import level_from_score, recommended_action

DEFAULT_BINARY_MODEL = 'models/cybershield_realpro_binary_ensemble_v0_3.joblib'
DEFAULT_FAMILY_MODEL = 'models/cybershield_realpro_attack_family_v0_3.joblib'
DEFAULT_ANOMALY_MODEL = 'models/cybershield_realpro_anomaly_baseline_v0_3.joblib'


def ensure_sklearn_compat() -> None:
    """Alias top-level ``_loss`` to sklearn's private loss modules.

    I modelli v0_3 sono stati serializzati con una versione di scikit-learn
    in cui le classi di loss/link erano referenziate dal pickle come modulo
    ``_loss``. Con sklearn moderne l'unpickling fallisce con
    ``ModuleNotFoundError: No module named '_loss'``. Registrare l'alias in
    ``sys.modules`` prima del ``joblib.load`` ripristina la compatibilità
    senza dover ripicchettare i modelli.
    """
    import sys
    import types

    if "_loss" in sys.modules:
        return
    try:
        import sklearn._loss.link as _link  # noqa: F401
        import sklearn._loss.loss as _loss_mod
    except ImportError:  # layout futuro senza sklearn._loss
        return
    shim = types.ModuleType("_loss")
    shim.__dict__.update(_loss_mod.__dict__)
    shim.__dict__.update(_link.__dict__)
    sys.modules["_loss"] = shim


# Compatibilità attiva all'import: qualsiasi joblib.load nel processo
# (test, API, CLI) trova l'alias già registrato.
ensure_sklearn_compat()


# Radice del pacchetto (modules/ml/cybershield_ai): i path dei modelli
# relativi ('models/...') vengono ancorati qui, così l'inference funziona
# qualunque sia la CWD del processo (test, API uvicorn, CLI).
_PKG_ROOT = Path(__file__).resolve().parents[2]


def resolve_model_path(path: str | Path) -> Path:
    """Risolvi un path modello: assoluto invariato, relativo ancorato al pacchetto."""
    p = Path(path)
    if p.is_absolute():
        return p
    return _PKG_ROOT / p


def load_payload(path: str | Path):
    return joblib.load(resolve_model_path(path))


def predict_dataframe(df: pd.DataFrame, binary_model_path=DEFAULT_BINARY_MODEL, family_model_path=DEFAULT_FAMILY_MODEL, anomaly_model_path=DEFAULT_ANOMALY_MODEL, ot_ics: bool = False) -> pd.DataFrame:
    X = align_features(df)
    binary_payload = load_payload(binary_model_path)
    family_payload = load_payload(family_model_path)
    anomaly_payload = load_payload(anomaly_model_path)

    binary_model = binary_payload['model']
    family_model = family_payload['model']
    anomaly_model = anomaly_payload['model']

    pred = binary_model.predict(X)
    proba = binary_model.predict_proba(X)
    classes = list(binary_model.named_steps['clf'].classes_)
    attack_idx = classes.index('ATTACK') if 'ATTACK' in classes else int(np.argmax(classes))
    attack_probability = proba[:, attack_idx]
    confidence = proba.max(axis=1)
    risk_score = np.clip(np.round(attack_probability * 100, 1), 0, 100)
    family = family_model.predict(X)
    raw_anomaly = anomaly_model.predict(X)
    anomaly_flag = np.where(raw_anomaly == 1, 'BENIGN_LIKE', 'ANOMALOUS')
    if hasattr(anomaly_model, 'decision_function'):
        anomaly_score = anomaly_model.decision_function(X)
    else:
        anomaly_score = np.zeros(len(X))

    out = df.copy()
    out['cybershield_prediction'] = pred
    out['attack_probability'] = np.round(attack_probability, 4)
    out['confidence'] = np.round(confidence, 4)
    out['risk_score'] = risk_score
    out['risk_level'] = [level_from_score(float(s)) for s in risk_score]
    out['attack_family_prediction'] = family
    out['anomaly_flag'] = anomaly_flag
    out['anomaly_score'] = np.round(anomaly_score, 6)
    out['recommended_action'] = [
        recommended_action(level, fam, ot_ics=ot_ics)
        for level, fam in zip(out['risk_level'], family, strict=True)
    ]
    return out


def main():
    parser = argparse.ArgumentParser(description='CyberShield Real Pro v0.3 inference CLI')
    parser.add_argument('--input', required=True)
    parser.add_argument('--output', required=True)
    parser.add_argument('--binary-model', default=DEFAULT_BINARY_MODEL)
    parser.add_argument('--family-model', default=DEFAULT_FAMILY_MODEL)
    parser.add_argument('--anomaly-model', default=DEFAULT_ANOMALY_MODEL)
    parser.add_argument('--ot-ics', action='store_true', help='Use OT/ICS-safe recommendations; no automatic containment advice.')
    args = parser.parse_args()
    df = pd.read_csv(args.input)
    out = predict_dataframe(df, args.binary_model, args.family_model, args.anomaly_model, ot_ics=args.ot_ics)
    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(args.output, index=False)
    print(json.dumps({'output': args.output, 'rows': len(out), 'high_or_critical': int(out['risk_level'].isin(['high','critical']).sum())}, indent=2))

if __name__ == '__main__':
    main()
