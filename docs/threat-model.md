# Threat model

A short, honest model of what AEGIS trusts, what it does not, and what an
attacker gains at each step. It describes the **current** code, not an
aspiration.

## Assets

| Asset | Why it matters |
|---|---|
| Event store (memory + `data/events.jsonl` + optional PostgreSQL) | Everything downstream — correlation, dashboards, incident records — is built from it |
| SOAR playbooks and their credentials | A playbook can block, isolate or notify; a forged trigger is a real action |
| Detection rules (Sigma / built-in packs) | Silently disabling a rule hides an attack |
| Model artifacts (`*.joblib`) | Unpickling a tampered model executes code |
| Dashboard session and admin password | Full control of the control plane |
| Evidence store (`data/evidence`) | Chain of custody; modification destroys its value |
| PKI material (`data/pki`) | Host and SSH certificates |

## Trust boundaries

```
┌──────────────────────────── trusted: operator workstation ────────────────────────────┐
│  browser ──HTTP──▶ orchestrator :8070  (session cookie, loopback bind by default)      │
└───────────────────────────────────────┬───────────────────────────────────────────────┘
                                        │ X-AEGIS-INGEST-KEY
┌───────────────────────────────────────▼───────────────────────────────────────────────┐
│  collectors: python modules, local agent, endpoint service                             │
│  each authenticates to the orchestrator with the shared ingest key                     │
└───────────────────────────────────────┬───────────────────────────────────────────────┘
                                        │ reads only
┌───────────────────────────────────────▼───────────────────────────────────────────────┐
│  external world: Wazuh, Suricata, CrowdSec, MISP/OTX feeds, plant networks             │
│  untrusted input; everything from here is parsed as data, never executed               │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### 1. Browser ↔ orchestrator

- Default bind is `127.0.0.1:8070`; the compose stack publishes the port on the
  host loopback only.
- Dashboard authentication is a session cookie (`HttpOnly`, `SameSite=Lax`)
  issued by `/api/v1/auth/login`, with a per-process Argon2id password hash and
  a lockout after repeated failures.
- `AEGIS_AUTH_REQUIRED` turns enforcement on for every non-public route. It is
  **off by default** in native mode so a single-operator install works without
  configuration; see the checklist in [SECURITY.md](../SECURITY.md).
- CORS reflects an `Origin` only when its hostname is exactly `localhost`,
  `127.0.0.1` or `::1`. No wildcard, no `null`, no prefix matching.

### 2. Collectors ↔ orchestrator

- `/api/v1/ingest/*` requires `X-AEGIS-INGEST-KEY` (or a dashboard session or
  API key). The key comes from `AEGIS_INGEST_KEY`; the launcher generates one
  per run, compose requires it in `.env`.
- Without a key the orchestrator logs a warning at startup and accepts
  unauthenticated ingest, which is only acceptable on a loopback bind.

### 3. Orchestrator ↔ modules

- Module APIs are reachable on loopback or the internal compose network. They
  are **not** individually hardened: treat the module network as semi-trusted.
- The ML prediction API requires the same ingest key; its models are verified
  against `models/SHA256SUMS` before `joblib.load`.

### 4. Orchestrator ↔ OT networks

- OT collectors are read-only and simulation-first. Live capture needs an
  explicit interface and an engagement reference.
- No write primitive to a PLC exists in the codebase; OT write commands are
  only ever *detected* in captured traffic.

## What an attacker gets at each step

| Compromise | Impact | Mitigation |
|---|---|---|
| Network access to the orchestrator port | Can read the dashboard if auth is off | Loopback bind, `AEGIS_AUTH_REQUIRED=true`, reverse proxy with TLS |
| The ingest key | Can inject arbitrary events: false positives, poisoned correlation, masked real alerts | Rotate the key, scope it per deployment, never reuse the admin password |
| A collector process | Same as the ingest key, plus whatever that module can read locally | Run modules as unprivileged users; keep `X-AEGIS-INGEST-KEY` scoped to ingest |
| The model file | Arbitrary code execution as the ML service | SHA-256 manifest verified before load; mount models read-only |
| The evidence directory | Loss of integrity for investigations | WORM storage, SHA-256 verification, off-host backup |
| The admin password | Full control of the control plane | Argon2id at rest, random generation when unset, login lockout |

## Explicit non-goals

- AEGIS does **not** protect its own host from a local administrator.
- AEGIS does **not** sandbox playbooks: a playbook with live mode enabled runs
  the commands it names.
- AEGIS does **not** validate the accuracy of external threat feeds.
- AEGIS is **not** a substitute for network segmentation on OT networks.

## Known gaps

| Gap | Status |
|---|---|
| Rate limiting applies to unauthenticated API calls only | By design: authenticated dashboards poll and stream |
| Module APIs have no per-module authentication | Accepted; keep them on loopback / internal network |
| Session store is in memory | Sessions end on restart; multi-instance deployments need shared state |
| No TLS termination included | Put a reverse proxy in front for anything beyond loopback |
| ML models are pickles | Verified by checksum, but a checksum cannot distinguish a malicious model that was registered deliberately |
