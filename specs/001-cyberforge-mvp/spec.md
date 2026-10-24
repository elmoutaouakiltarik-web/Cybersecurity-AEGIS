# Feature Specification: Cybersecurity-AEGIS MVP Control Plane

**Feature Branch**: `001-cyberforge-mvp`

**Created**: 2026-05-21

**Status**: Draft

**Input**: User description: "Use Spec Kit to start CyberForge, prepare the architecture, improve the provided code snippets, and put them in the right places." Updated 2026-05-21: project name is now Cybersecurity-AEGIS and research/GitHub repository decisions must be unified in the dashboard.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Review Unified Security Posture (Priority: P1)

As a personal SOC operator, I want one local dashboard/API to show security event
counts, module health, and critical alerts across IT and OT sources so that I can
understand current risk without opening every upstream tool separately.

**Why this priority**: This is the minimum useful control-plane value. Without a
normalized view, the project is only a loose bundle of tools.

**Independent Test**: Start the orchestrator, submit sample events from at least
two source categories, and confirm metrics and recent events are visible through
the local API.

**Acceptance Scenarios**:

1. **Given** the orchestrator is running, **When** a user opens the health and metrics endpoints, **Then** the system reports uptime, module status, and alert totals.
2. **Given** normalized events exist, **When** a user filters recent events by category, **Then** only matching endpoint, network, identity, or industrial events are returned.

---

### User Story 2 - Normalize Security Events (Priority: P1)

As an integrator, I want Cybersecurity-AEGIS to receive Wazuh, Suricata, CrowdSec, generic,
and OT events and convert them into one common event schema so that downstream
dashboards, alerts, and playbooks use consistent data.

**Why this priority**: Event normalization is the core contract that allows every
future module to plug into Cybersecurity-AEGIS.

**Independent Test**: POST sample Wazuh, Suricata, CrowdSec, and OT payloads to
their ingest endpoints and verify severity, source, category, title, tags, and
raw data are preserved or mapped predictably.

**Acceptance Scenarios**:

1. **Given** a Suricata EVE alert with severity 1, **When** it is ingested, **Then** Cybersecurity-AEGIS stores a critical network event.
2. **Given** an OT payload with protocol and Purdue level, **When** it is ingested, **Then** Cybersecurity-AEGIS attaches OT context and marks the event as industrial.

---

### User Story 3 - Monitor OT Passively (Priority: P2)

As an OT engineer, I want a passive OT monitor that detects risky Modbus and
industrial traffic patterns without sending commands to controllers so that I can
evaluate OT visibility safely.

**Why this priority**: OT support is a differentiator, but it must not endanger
process availability or safety.

**Independent Test**: Run OT monitor simulation mode and confirm it produces
read-only alerts for high-frequency Modbus write attempts and unauthorized asset
detection without transmitting industrial control commands.

**Acceptance Scenarios**:

1. **Given** simulated Modbus write traffic exceeds the configured threshold, **When** the monitor evaluates it, **Then** it emits a high-severity industrial alert.
2. **Given** a new OT asset appears outside the allowlist, **When** the monitor observes the device, **Then** it records the asset and raises an advisory rogue-device alert.

---

### User Story 4 - Configure a Safe Deployment Baseline (Priority: P2)

As a maintainer, I want environment templates, compose profiles, and clear module
classification so that I can deploy the MVP locally without accidentally enabling
unsafe or lab-only components.

**Why this priority**: Security software with weak defaults becomes a risk by
itself.

**Independent Test**: Copy the environment example, run configuration validation,
and confirm production baseline services are separated from optional OT and lab
profiles.

**Acceptance Scenarios**:

1. **Given** no production secrets are set, **When** deployment starts, **Then** the documentation and configuration identify required secret changes before production use.
2. **Given** an OT profile is disabled, **When** the base compose stack is inspected, **Then** no OT packet capture or active OT scanner is enabled.

### Edge Cases

- Ingested events can be malformed, missing severity, or contain unexpected
  nested fields.
- Upstream services can be unavailable while the Cybersecurity-AEGIS orchestrator remains
  healthy.
- OT monitor may run without packet-capture dependencies installed and must fall
  back to simulation or exit clearly.
- Duplicate alerts may arrive in bursts and must not block ingestion.
- Secrets scanners must not dump discovered secrets into logs or API responses.

## Requirements *(mandatory)*

### Functional Requirements

- **FR-001**: System MUST expose a local health endpoint and local metrics endpoint.
- **FR-002**: System MUST maintain a normalized security event schema covering source, category, severity, title, description, tags, MITRE context, OT context, and raw source payload.
- **FR-003**: System MUST ingest Wazuh-style endpoint alerts, Suricata-style network alerts, CrowdSec-style perimeter alerts, generic events, and OT monitor alerts.
- **FR-004**: System MUST classify events into endpoint, network, perimeter, identity, intelligence, industrial, or system categories.
- **FR-005**: System MUST provide recent-event retrieval with category filtering.
- **FR-006**: System MUST maintain module status for core integrations.
- **FR-007**: System MUST include a passive OT monitor capable of simulation mode and read-only packet analysis.
- **FR-008**: System MUST detect Modbus write activity above a configurable threshold.
- **FR-009**: System MUST record OT asset observations with IP, MAC, protocol, device type estimate, Purdue level estimate, first seen, and last seen.
- **FR-010**: System MUST mark OT actions that could affect process control as advisory-only in the MVP.
- **FR-011**: System MUST include defensive YARA rules as examples and identify them as detection content requiring validation before production enforcement.
- **FR-012**: System MUST provide environment and compose templates with production secrets represented only as placeholders.
- **FR-013**: System MUST document production baseline, optional modules, lab-only modules, and excluded/offensive modules separately.
- **FR-014**: System MUST avoid enabling offensive tooling or active OT enforcement in the default stack.
- **FR-015**: System MUST include local build or syntax checks for the initial Go and Python components.

### Key Entities

- **SecurityEvent**: A normalized alert or observation from any IT/OT source.
- **ModuleStatus**: Health and status metadata for an upstream integration or Cybersecurity-AEGIS component.
- **OTAsset**: A passively observed industrial asset with protocol and Purdue metadata.
- **OTAlert**: A security-relevant OT observation derived from passive monitoring or simulation.
- **IntegrationSource**: A configured source such as Wazuh, Suricata, CrowdSec, OT Monitor, or generic API clients.
- **DeploymentProfile**: A named deployment mode such as baseline, industrial, lab, or observability.
- **DetectionRule**: A YARA or future Sigma detection artifact with metadata, scope, and validation status.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: A user can start the orchestrator and receive a healthy response in under 30 seconds on a development machine.
- **SC-002**: At least four sample event types can be ingested and retrieved using the common event schema.
- **SC-003**: The OT monitor simulation produces at least one advisory industrial alert without requiring real OT hardware.
- **SC-004**: A maintainer can identify baseline, optional, lab-only, and excluded modules in under 5 minutes from the documentation.
- **SC-005**: Local syntax/build checks pass for all first-party Go and Python files in the scaffold.

## Assumptions

- The initial implementation targets local development and small self-hosted labs,
  not a managed MSSP platform.
- Linux is the primary runtime for packet capture and security tooling; Windows
  remains a development host for Codex and documentation.
- The MVP stores events in memory first; durable storage is planned but not
  required for the first architecture scaffold.
- Wazuh, Suricata, CrowdSec, Greenbone, MISP, OpenCTI, Keycloak, PacketFence,
  step-ca, Fleet, and Velociraptor are upstream services, not embedded engines.
- AEGIS-OMNI documents are treated as research input; the shipped project name is
  Cybersecurity-AEGIS.
