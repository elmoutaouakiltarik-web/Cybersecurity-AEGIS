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

This repository ships **no credentials**. In particular:

- The dashboard has no default admin password. Set `AEGIS_ADMIN_PASSWORD`
  before starting the orchestrator; if you leave it unset, a random one-time
  password is generated and printed to stderr on startup.
- `.env` is git-ignored. Copy `.env.example` and fill in your own values.
- API keys for external feeds (AbuseIPDB, NVD, OTX, MISP) are read from the
  environment only and are never committed.

If you believe you have found a leaked credential in this repository or its
history, report it through the advisory channel above.

## Deployment hardening

The default configuration favours local, single-operator use:

- The orchestrator binds to `127.0.0.1` unless you change `bind` in
  `config.yaml` or set `AEGIS_BIND`.
- Authentication is not enforced by default so the dashboard works out of the
  box on a trust-local machine. Set `auth.required: true` (and an admin
  password) before exposing the service beyond localhost.
- OT/ICS collectors are read-only and simulation-first. Live capture requires
  explicit opt-in and must only be used on networks where you have written
  authorization.

## Supported versions

The project is pre-1.0 and moves quickly; security fixes land on `master`.
Run the latest commit before reporting an issue.
