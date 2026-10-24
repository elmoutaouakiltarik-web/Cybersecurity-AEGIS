from __future__ import annotations

import os, sys
from pathlib import Path
from typing import Any, Dict, List
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from cybershield_pro.predict import predict_dataframe, DEFAULT_BINARY_MODEL, DEFAULT_FAMILY_MODEL, DEFAULT_ANOMALY_MODEL
from cybershield_pro.schema import NSL_KDD_FEATURES

app = FastAPI(title='CyberShield AI Real Pro API', version='0.3.0-final')

BINARY_MODEL = os.getenv('CYBERSHIELD_BINARY_MODEL', str(ROOT / DEFAULT_BINARY_MODEL))
FAMILY_MODEL = os.getenv('CYBERSHIELD_FAMILY_MODEL', str(ROOT / DEFAULT_FAMILY_MODEL))
ANOMALY_MODEL = os.getenv('CYBERSHIELD_ANOMALY_MODEL', str(ROOT / DEFAULT_ANOMALY_MODEL))

class FlowEvent(BaseModel):
    features: Dict[str, Any] = Field(..., description='One NSL-KDD-compatible network flow feature dictionary.')
    ot_ics: bool = Field(False, description='When true, recommendations are OT/ICS-safe and read-only.')

class BatchRequest(BaseModel):
    events: List[FlowEvent]

@app.get('/health')
def health():
    return {
        'ok': True,
        'version': '0.3.0-final',
        'models': {
            'binary_exists': Path(BINARY_MODEL).exists(),
            'family_exists': Path(FAMILY_MODEL).exists(),
            'anomaly_exists': Path(ANOMALY_MODEL).exists(),
        },
        'required_features': NSL_KDD_FEATURES,
    }

@app.post('/predict')
def predict_one(event: FlowEvent):
    missing = [c for c in NSL_KDD_FEATURES if c not in event.features]
    if missing:
        raise HTTPException(status_code=400, detail={'missing_features': missing})
    df = pd.DataFrame([event.features])
    out = predict_dataframe(df, BINARY_MODEL, FAMILY_MODEL, ANOMALY_MODEL, ot_ics=event.ot_ics)
    return out.iloc[0].to_dict()

@app.post('/predict_batch')
def predict_batch(req: BatchRequest):
    if not req.events:
        return {'results': []}
    rows = []
    ot_flags = []
    for event in req.events:
        missing = [c for c in NSL_KDD_FEATURES if c not in event.features]
        if missing:
            raise HTTPException(status_code=400, detail={'missing_features': missing})
        rows.append(event.features); ot_flags.append(event.ot_ics)
    # If mixed OT flags, use individual prediction for safe recommendation.
    if len(set(ot_flags)) > 1:
        return {'results': [predict_one(e) for e in req.events]}
    df = pd.DataFrame(rows)
    out = predict_dataframe(df, BINARY_MODEL, FAMILY_MODEL, ANOMALY_MODEL, ot_ics=ot_flags[0])
    return {'results': out.to_dict(orient='records')}
