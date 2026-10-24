# Implementation Plan: Cybersecurity-AEGIS MVP Control Plane

**Branch**: `001-cyberforge-mvp` | **Date**: 2026-05-21 | **Spec**: [spec.md](spec.md)

**Input**: Feature specification from `specs/001-cyberforge-mvp/spec.md`

## Summary

Build the first Cybersecurity-AEGIS scaffold as a defensive, self-hosted
cybersecurity control plane. The MVP provides a Go orchestrator with normalized
event ingest, module health APIs, an embedded dashboard, passive/simulation OT
posture, deployment templates, and defensive repository intelligence. Research
drafts that propose wider AEGIS/150+ repository scope are treated as future
vision, not MVP baseline.

## Technical Context

**Language/Version**: Go 1.22+ for the orchestrator; Python 3.12+ for agents and OT monitor.

**Primary Dependencies**: Go standard library for MVP API server; optional Python
dependencies `requests`, `pyyaml`, `scapy`, and `psutil` for runtime enrichment.

**Storage**: In-memory event ring buffer for MVP; PostgreSQL reserved in compose
for future durable storage.

**Testing**: `go test ./...`; Python `py_compile` for scaffold; future `pytest`
for agents and protocol analyzers.

**Target Platform**: Linux runtime for services and packet capture; Windows
development workspace supported for authoring and static checks.

**Project Type**: Multi-service cybersecurity platform scaffold.

**Performance Goals**: MVP handles at least 1,000 in-memory recent events and
sample ingestion bursts without blocking the API.

**Constraints**: Defensive-only; self-hosted; no production default secrets; OT
read-only; lab/offensive tools excluded from default stack; GPL/AGPL components
kept as external services.

**Scale/Scope**: Initial lab and personal SOC deployments: 1 operator, 1 local
control plane, simulated or passive OT monitor, sample integrations for Wazuh,
Suricata, CrowdSec, generic events, and OT alerts.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

- Defensive-Only Scope: PASS. The MVP excludes offensive tools and active attack automation.
- Composable Control Plane: PASS. Upstream security engines remain independent services.
- OT Safety First: PASS. OT monitor is passive/simulation and advisory-only.
- Testable Security Contracts: PASS. OpenAPI contract, schema-like data model, and build checks are included.
- Local-First Privacy and Observability: PASS. Services are local by default; secrets are placeholders only.

## Project Structure

### Documentation (this feature)

```text
specs/001-cyberforge-mvp/
├── spec.md
├── plan.md
├── research.md
├── data-model.md
├── quickstart.md
├── contracts/
│   └── openapi.yaml
├── checklists/
│   └── requirements.md
└── tasks.md
```

### Source Code (repository root)

```text
core/
└── orchestrator/
    ├── Dockerfile
    ├── dashboard/
    │   └── index.html
    ├── go.mod
    ├── main.go
    └── main_test.go

agents/
└── local/
    ├── agent.py
    └── requirements.txt

modules/
├── industrial/
│   └── ot_monitor/
│       ├── Dockerfile
│       ├── main.py
│       └── requirements.txt
└── intelligence/
    └── yara/
        └── rules/
            ├── ot_threats.yar
            └── ransomware.yar

config/
├── ot-config.example.yaml
└── prometheus.yml

docs/
├── architecture.md
├── github-research.md
└── source-decisions.md

docker-compose.yml
docker-compose.industrial.yml
.env.example
README.md
```

**Structure Decision**: The project uses a multi-service layout. First-party
control-plane code is under `core/`; host-side collectors are under `agents/`;
domain modules are under `modules/`; deployment configuration remains at the
root and under `config/`; design rationale lives in `docs/` and Spec Kit files.

## Complexity Tracking

No constitution violations. The multi-service structure is required because Go
API services, Python host agents, and passive OT monitors have different runtime
constraints and dependency profiles.
