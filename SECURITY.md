# Security Policy

Cybersecurity-AEGIS is a defensive security control plane. Please treat any
weakness in it as a security issue rather than an ordinary bug.

## Reporting a vulnerability

Open a private security advisory on the GitHub repository
("Security" → "Advisories" → "Report a vulnerability"). Please do not open a
public issue for anything that could be exploited against a running instance.

Include the affected component, a reproduction, and the impact you observed.
We aim to acknowledge reports within a few days.

## Credentials and secrets

This repository ships **no working credentials**. In particular:

- The dashboard has no default admin password. Set `AEGIS_ADMIN_PASSWORD`
  before starting the orchestrator; if you leave it unset, a random one-time
  password is generated and printed to stderr on startup. The password is
  hashed with Argon2id at startup and never written to disk.
- The shared ingest secret comes from `AEGIS_INGEST_KEY`; the Windows launcher
  generates one per run, and `docker compose` refuses to start without it.
- Grafana and PostgreSQL have no shipped default passwords: compose requires
  `POSTGRES_PASSWORD`, and the Grafana entry in `config.yaml` is empty.
- `.env` is git-ignored. Copy `.env.example` and fill in your own values.
- API keys for external feeds (AbuseIPDB, NVD, OTX, MISP) are read from the
  environment only and are never committed.
- Downloaded feed caches (`data/iocs/`, `data/kev/`) are git-ignored; they are
  refreshed at runtime.

If you believe you have found a leaked credential in this repository or its
history, report it through the advisory channel above.

## Deployment hardening

The default configuration favours local, single-operator use:

- The orchestrator binds to `127.0.0.1:8070` unless you set `AEGIS_BIND` (or
  `AEGIS_BIND_ADDR`) or change `orchestrator.bind` in `config.yaml`. Containers
  set `0.0.0.0` internally while the published port stays on loopback.
- Authentication is not enforced by default so the dashboard works out of the
  box on a trust-local machine. Set `AEGIS_AUTH_REQUIRED=true` (and an admin
  password) before exposing the service beyond localhost.
- **Ingest is authenticated.** `/api/v1/ingest/*` requires the shared key in
  `X-AEGIS-INGEST-KEY` (`AEGIS_INGEST_KEY`). If the variable is unset the
  orchestrator logs a warning and accepts unauthenticated ingest — acceptable
  only on a loopback bind.
- **CORS** reflects only exact `localhost` / `127.0.0.1` / `::1` origins. No
  wildcard, no `null` origin.
- **Rate limiting** is applied to unauthenticated API traffic (default 120
  requests/minute, burst 20).
- **Model artifacts** are verified against `models/SHA256SUMS` before
  `joblib.load`; a mismatch aborts the load.
- **API keys are header-only.** A key in the query string is ignored, because
  URLs end up in access logs and browser history.
- OT/ICS collectors are read-only and simulation-first. Live capture requires
  explicit opt-in and must only be used on networks where you have written
  authorization.

Trust boundaries, per-interface authentication and the impact of a compromised
component are documented in [docs/threat-model.md](docs/threat-model.md).

## Supported versions

The project is pre-1.0 and moves quickly; security fixes land on `master`.
Run the latest commit before reporting an issue.

## Automated checks

Every push runs `go vet`, `go test`, `ruff` (syntax errors and undefined
names), the Python test suites and a `gitleaks` secret scan — see
`.github/workflows/ci.yml`.
