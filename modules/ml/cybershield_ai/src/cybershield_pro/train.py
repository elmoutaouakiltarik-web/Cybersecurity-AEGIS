from __future__ import annotations

import argparse
import json
from pathlib import Path
from datetime import datetime, timezone
import hashlib
import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier, GradientBoostingClassifier, VotingClassifier, IsolationForest
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from .schema import NSL_KDD_FEATURES, CATEGORICAL_COLUMNS, normalize_attack_family


def build_models():
    num_cols = [c for c in NSL_KDD_FEATURES if c not in CATEGORICAL_COLUMNS]
    def make_prep():
        return ColumnTransformer([
            ('cat', OneHotEncoder(handle_unknown='ignore', sparse_output=False), CATEGORICAL_COLUMNS),
            ('num', StandardScaler(), num_cols),
        ])
    bin_model = Pipeline([('prep', make_prep()), ('clf', VotingClassifier([
        ('rf', RandomForestClassifier(n_estimators=120, class_weight='balanced_subsample', n_jobs=1, random_state=42)),
        ('et', ExtraTreesClassifier(n_estimators=120, class_weight='balanced', n_jobs=1, random_state=43)),
        ('gb', GradientBoostingClassifier(random_state=44)),
        ('lr', LogisticRegression(max_iter=2000, class_weight='balanced', random_state=45)),
    ], voting='soft', weights=[3,3,2,1], n_jobs=1))])
    fam_model = Pipeline([('prep', make_prep()), ('clf', VotingClassifier([
        ('rf', RandomForestClassifier(n_estimators=100, class_weight='balanced_subsample', n_jobs=1, random_state=52)),
        ('et', ExtraTreesClassifier(n_estimators=100, class_weight='balanced', n_jobs=1, random_state=53)),
        ('gb', GradientBoostingClassifier(random_state=54)),
        ('lr', LogisticRegression(max_iter=2000, class_weight='balanced', random_state=55)),
    ], voting='soft', weights=[3,3,2,1], n_jobs=1))])
    anom = Pipeline([('prep', make_prep()), ('iso', IsolationForest(n_estimators=150, contamination='auto', n_jobs=1, random_state=62))])
    return bin_model, fam_model, anom


def train(input_csv: str, output_dir: str):
    df = pd.read_csv(input_csv)
    missing = [c for c in NSL_KDD_FEATURES + ['label'] if c not in df.columns]
    if missing:
        raise ValueError(f'Missing columns: {missing}')
    df['binary_label'] = df['label'].apply(lambda x: 'BENIGN' if str(x).strip().lower() == 'normal' else 'ATTACK')
    df['attack_family'] = df['label'].apply(normalize_attack_family)
    X = df[NSL_KDD_FEATURES]
    yb = df['binary_label']
    yf = df['attack_family']
    bin_model, fam_model, anom = build_models()

    X_train, X_test, y_train, y_test = train_test_split(X, yb, test_size=0.25, random_state=10, stratify=yb)
    bin_model.fit(X_train, y_train)
    pred = bin_model.predict(X_test)
    report = {
        'created_utc': datetime.now(timezone.utc).isoformat(),
        'input_csv': input_csv,
        'sha256': hashlib.sha256(Path(input_csv).read_bytes()).hexdigest(),
        'rows': int(len(df)),
        'binary_accuracy': float(accuracy_score(y_test, pred)),
        'binary_macro_f1': float(f1_score(y_test, pred, average='macro')),
        'binary_report': classification_report(y_test, pred, output_dict=True, zero_division=0),
        'binary_confusion_matrix': confusion_matrix(y_test, pred, labels=['BENIGN','ATTACK']).tolist(),
        'label_counts': df['label'].value_counts().to_dict(),
        'family_counts': df['attack_family'].value_counts().to_dict(),
    }

    bin_model.fit(X, yb)
    fam_model.fit(X, yf)
    anom.fit(X[yb == 'BENIGN'])
    out = Path(output_dir); (out/'models').mkdir(parents=True, exist_ok=True); (out/'reports').mkdir(parents=True, exist_ok=True)
    meta = {'version': 'retrained', 'feature_columns': NSL_KDD_FEATURES, 'source_sha256': report['sha256'], 'synthetic_data_used': False}
    joblib.dump({'kind':'binary_classifier','model':bin_model,'metadata':meta,'feature_columns':NSL_KDD_FEATURES}, out/'models/cybershield_retrained_binary.joblib', compress=3)
    joblib.dump({'kind':'attack_family_classifier','model':fam_model,'metadata':meta,'feature_columns':NSL_KDD_FEATURES}, out/'models/cybershield_retrained_family.joblib', compress=3)
    joblib.dump({'kind':'anomaly_detector','model':anom,'metadata':meta,'feature_columns':NSL_KDD_FEATURES}, out/'models/cybershield_retrained_anomaly.joblib', compress=3)
    (out/'reports/retraining_report.json').write_text(json.dumps(report, indent=2), encoding='utf-8')
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description='Retrain CyberShield models on a real NSL-KDD CSV with header.')
    parser.add_argument('--input-csv', required=True)
    parser.add_argument('--output-dir', default='retrained_output')
    args = parser.parse_args()
    train(args.input_csv, args.output_dir)

if __name__ == '__main__':
    main()
