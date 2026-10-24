# CyberShield AI Integration

CyberShield AI v0.2 is imported from the user-provided research ZIP as the
Cybersecurity-AEGIS ML/IDS module. It adds real model artifacts and a concrete
prediction API to the control plane.

## Included Assets

- NSL-KDD real subset manifest: 122 rows, 41 features, no synthetic training data.
- Binary ensemble model: attack versus benign.
- Family classifier: DoS, Probe, R2L, U2R, normal.
- Anomaly baseline model.
- FastAPI prediction service.
- Streamlit analysis dashboard from the source package.
- Wazuh, Zeek, Suricata, StackStorm, NIS2/GDPR, and OT/ICS safety notes.

## AEGIS Runtime Contract

- Service profile: `ml`
- Local API port: `8919`
- Health: `GET /health`
- Prediction: `POST /predict`
- Normalized event ingest into AEGIS: `POST /api/v1/ingest/cybershield-ai`

## Safety Rules

- The module is defensive-only and performs classification, enrichment, and risk
  scoring.
- OT/ICS outputs stay alert-only unless a human operator approves action through
  a separate safety gate.
- The current models are useful for MVP proof and pipeline validation, but
  production requires full dataset retraining, drift tests, signed artifacts,
  rollback, and audit logging.
