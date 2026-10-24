from __future__ import annotations

from pathlib import Path

import pandas as pd

from .schema import CATEGORICAL_COLUMNS, NSL_KDD_FEATURES


def load_nsl_kdd_csv(path: str | Path, has_labels: bool = False) -> pd.DataFrame:
    """Load a CSV with NSL-KDD column names already present.

    If you have the original TXT files without a header, use scripts/train_on_full_nsl_kdd.py,
    which applies the official 41 feature columns plus label and difficulty.
    """
    df = pd.read_csv(path)
    missing = [c for c in NSL_KDD_FEATURES if c not in df.columns]
    if missing:
        raise ValueError(f'Missing required NSL-KDD feature columns: {missing[:10]}')
    return df


def align_features(df: pd.DataFrame, fill_missing: bool = True) -> pd.DataFrame:
    """Allineare il frame alle 41 feature NSL-KDD nell'ordine del training.

    Con ``fill_missing=True`` (default) le colonne assenti vengono create con
    default sicuri: 0 per le numeriche e ``'other'`` per le categoriche
    (protocol_type/service/flag). Questo permette all'API di accettare
    telemetria parziale senza fallire; l'allineamento all'ordine esatto delle
    feature resta garantito in entrambi i modi.

    Con ``fill_missing=False`` si ottiene il comportamento strict: colonne
    mancanti → ValueError, utile per validare batch di training/ETL.
    """
    missing = [c for c in NSL_KDD_FEATURES if c not in df.columns]
    if missing:
        if not fill_missing:
            raise ValueError(f'Missing required NSL-KDD feature columns: {missing[:10]}')

        out = df.copy()
        for col in missing:
            out[col] = 'other' if col in CATEGORICAL_COLUMNS else 0
    else:
        out = df
    return out[NSL_KDD_FEATURES].copy()
