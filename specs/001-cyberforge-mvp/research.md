# Research: Cybersecurity-AEGIS MVP Control Plane

## Decision: Rename product to Cybersecurity-AEGIS

**Rationale**: The user renamed the product to Cybersecurity-AEGIS on
2026-05-21. The implementation now uses Cybersecurity-AEGIS for user-facing
documentation, dashboard, compose resources, and health metadata. The older
CyberForge name remains only as feature-track history and temporary environment
aliases during migration.

**Alternatives considered**: Keep CyberForge. Rejected because the project owner
explicitly changed the product name.

## Decision: Build a composable control plane, not a monolith

**Rationale**: Prior research recommends orchestration of mature tools instead of
reimplementing SIEM, NDR, EDR, PKI, NAC, CTI, and DFIR engines. This reduces
licensing risk and keeps upstream update paths intact.

**Alternatives considered**: Embed all tools into one binary or container.
Rejected due to licensing, operational complexity, and high blast radius.

## Decision: Go standard library for MVP orchestrator

**Rationale**: The provided Go snippet used external routers/websocket packages.
For the MVP, the standard library is sufficient for health, metrics, ingest, and
event retrieval. This keeps the first scaffold buildable in constrained
environments.

**Alternatives considered**: Gin/Gorilla stack. Deferred until route complexity
or websocket requirements justify it.

## Decision: Python for local agent and OT monitor

**Rationale**: Python is practical for wrappers around osquery, ClamAV, file
integrity checks, optional packet parsing, and simulation. Optional imports allow
the code to compile even when host tools are not installed.

**Alternatives considered**: Go for all agents. Rejected for MVP because packet
experimentation and security-tool wrappers are faster to prototype in Python.

## Decision: OT monitor is passive/simulation-first

**Rationale**: NIST OT guidance emphasizes performance, reliability, and safety.
The MVP should never write to PLCs or enforce network changes automatically.

**Alternatives considered**: Modbus proxy gateway and Purdue enforcer that can
change traffic path. Deferred to lab-only future work.

## Decision: Docker Compose profiles for optional surfaces

**Rationale**: The baseline should start with the orchestrator and supporting
services, while industrial and lab modules stay opt-in.

**Alternatives considered**: One large compose stack. Rejected because it would
enable too much too early and require many heavy upstream services.

## Decision: Detection content is shipped as examples

**Rationale**: YARA and future Sigma content are useful, but unvalidated rules can
create false positives. MVP marks rules as defensive examples requiring local
validation.

**Alternatives considered**: Treat rules as production-grade. Rejected until
test corpora and rule QA exist.
