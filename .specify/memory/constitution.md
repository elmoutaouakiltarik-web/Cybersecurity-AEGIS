<!--
Sync Impact Report
Version change: template -> 1.0.0
Modified principles:
- [PRINCIPLE_1_NAME] -> Defensive-Only Scope
- [PRINCIPLE_2_NAME] -> Composable Control Plane
- [PRINCIPLE_3_NAME] -> OT Safety First
- [PRINCIPLE_4_NAME] -> Testable Security Contracts
- [PRINCIPLE_5_NAME] -> Local-First Privacy and Observability
Added sections:
- Security and Compliance Constraints
- Development Workflow and Quality Gates
Removed sections:
- Placeholder sections only
Templates requiring updates:
- .specify/templates/plan-template.md: reviewed, no structural change required
- .specify/templates/spec-template.md: reviewed, no structural change required
- .specify/templates/tasks-template.md: reviewed, no structural change required
Deferred items:
- None
-->

# CyberForge Constitution

## Core Principles

### I. Defensive-Only Scope
CyberForge MUST be designed and documented exclusively for defensive monitoring,
hardening, incident response, forensics, and authorized lab validation. The core
product MUST NOT include C2 frameworks, exploit automation, brute-force tooling,
credential attack workflows, or active offensive playbooks. Dual-use tools MAY be
referenced only in isolated lab documentation when they are clearly separated from
the production baseline.

### II. Composable Control Plane
CyberForge MUST orchestrate mature upstream security tools as independent
subsystems instead of embedding or reimplementing their engines. The control
plane owns normalized events, module health, policy state, evidence metadata, and
operator workflow. Upstream engines such as Wazuh, Suricata, Zeek, Velociraptor,
Greenbone, MISP, OpenCTI, Keycloak, PacketFence, step-ca, and Fleet remain
separate services with explicit boundaries.

### III. OT Safety First
Operational technology integrations MUST be passive or read-only by default. Any
workflow that can affect PLC, RTU, IED, HMI, SCADA, safety systems, production
networking, or industrial process availability MUST require an explicit human
safety gate, maintenance window, and rollback path. Automated containment is
allowed in IT zones; OT containment starts as advisory-only until approved by an
authorized operator.

### IV. Testable Security Contracts
Every feature MUST define testable contracts for event schemas, integration
inputs, severity mapping, module health, and deployment configuration. Security
logic MUST be covered by unit or integration tests before being treated as
production-ready. Generated detections, YARA rules, Sigma rules, and playbooks
MUST include sample benign and malicious test fixtures where practical.

### V. Local-First Privacy and Observability
CyberForge MUST run self-hosted by default and avoid sending sensitive telemetry
to external services unless explicitly configured by the operator. Logs,
evidence, asset identifiers, secrets, packet metadata, and endpoint telemetry MUST
use retention, redaction, access control, and audit trails appropriate for GDPR,
NIS2, and OT governance. All services MUST emit structured logs and health
signals sufficient for troubleshooting without exposing secrets.

## Security and Compliance Constraints

- Secrets MUST be provided via environment variables, secret files, or a secrets
  manager; no default production secret may be committed.
- GPL and AGPL components MUST be isolated as services unless a legal review
  approves tighter integration.
- OT scans and vulnerability checks MUST be safe-profile by default and disabled
  for production controllers unless explicitly approved.
- Documentation MUST distinguish production baseline, optional module, lab-only
  module, and excluded module.
- Any AI/ML feature MUST be local-first, explainable enough for operator review,
  and non-authoritative for OT actuation decisions.

## Development Workflow and Quality Gates

- Spec Kit artifacts are mandatory for new features: specification, plan, tasks,
  and implementation notes.
- The MVP MUST remain independently runnable without the full 150+ repository
  universe proposed in research documents.
- Code changes MUST pass local syntax/build checks for touched languages.
- Architecture changes MUST update `docs/architecture.md` and the relevant Spec
  Kit plan or tasks.
- Memory of durable decisions MUST be saved to the external vault at session end.

## Governance

This constitution supersedes ad-hoc snippets and research drafts. Amendments
require a documented reason, semantic version bump, affected-template review, and
migration notes when existing code or deployment behavior changes.

Versioning policy:
- MAJOR for principle removals or incompatible governance changes.
- MINOR for new principles, new mandatory gates, or expanded compliance scope.
- PATCH for clarifications and typo-level changes.

Compliance with this constitution is checked during planning, code review, and
release readiness.

**Version**: 1.0.0 | **Ratified**: 2026-05-21 | **Last Amended**: 2026-05-21
