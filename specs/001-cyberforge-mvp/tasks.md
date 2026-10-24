# Tasks: Cybersecurity-AEGIS MVP Control Plane

**Input**: Design documents from `specs/001-cyberforge-mvp/`

**Prerequisites**: plan.md, spec.md, research.md, data-model.md, contracts/openapi.yaml

**Tests**: Include build/syntax checks for all first-party scaffold code.

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Create the project skeleton and baseline documentation.

- [x] T001 Create Spec Kit constitution in `.specify/memory/constitution.md`
- [x] T002 Create feature spec in `specs/001-cyberforge-mvp/spec.md`
- [x] T003 Create implementation plan in `specs/001-cyberforge-mvp/plan.md`
- [x] T004 [P] Create design research in `specs/001-cyberforge-mvp/research.md`
- [x] T005 [P] Create data model in `specs/001-cyberforge-mvp/data-model.md`
- [x] T006 [P] Create API contract in `specs/001-cyberforge-mvp/contracts/openapi.yaml`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: Core files and safe defaults required by all stories.

- [x] T007 Create root project README in `README.md`
- [x] T008 Create safe environment template in `.env.example`
- [x] T009 Create baseline compose scaffold in `docker-compose.yml`
- [x] T010 Create industrial opt-in compose overlay in `docker-compose.industrial.yml`
- [x] T011 [P] Create architecture documentation in `docs/architecture.md`
- [x] T012 [P] Create source decision documentation in `docs/source-decisions.md`

**Checkpoint**: Foundation ready - user story implementation can now begin.

---

## Phase 3: User Story 1 - Review Unified Security Posture (Priority: P1) MVP

**Goal**: Run a local orchestrator with health, metrics, modules, and events.

**Independent Test**: `go test ./...` in `core/orchestrator`, then run the service
and call `/health`, `/api/v1/metrics`, and `/api/v1/events`.

- [x] T013 [US1] Create Go module in `core/orchestrator/go.mod`
- [x] T014 [US1] Implement orchestrator API in `core/orchestrator/main.go`
- [x] T015 [P] [US1] Add orchestrator tests in `core/orchestrator/main_test.go`
- [x] T016 [P] [US1] Add orchestrator Dockerfile in `core/orchestrator/Dockerfile`

**Checkpoint**: User Story 1 functional and testable.

---

## Phase 4: User Story 2 - Normalize Security Events (Priority: P1)

**Goal**: Accept source-specific sample events and normalize them.

**Independent Test**: POST sample Wazuh, Suricata, CrowdSec, generic, and OT
payloads to the API and retrieve normalized events.

- [x] T017 [US2] Implement Wazuh, Suricata, CrowdSec, generic, and OT normalizers in `core/orchestrator/main.go`
- [x] T018 [P] [US2] Add normalizer tests in `core/orchestrator/main_test.go`
- [x] T019 [US2] Document sample ingest commands in `specs/001-cyberforge-mvp/quickstart.md`

**Checkpoint**: User Story 2 functional and testable.

---

## Phase 5: User Story 3 - Monitor OT Passively (Priority: P2)

**Goal**: Provide a safe OT monitor with simulation and passive analysis.

**Independent Test**: Run `python modules/industrial/ot_monitor/main.py --simulate --cycles 3`.

- [x] T020 [US3] Implement OT monitor in `modules/industrial/ot_monitor/main.py`
- [x] T021 [P] [US3] Add OT monitor requirements in `modules/industrial/ot_monitor/requirements.txt`
- [x] T022 [P] [US3] Add OT monitor Dockerfile in `modules/industrial/ot_monitor/Dockerfile`
- [x] T023 [P] [US3] Create OT config example in `config/ot-config.example.yaml`

**Checkpoint**: User Story 3 functional and testable.

---

## Phase 6: User Story 4 - Configure a Safe Deployment Baseline (Priority: P2)

**Goal**: Provide host agent, defensive rules, and clear safe deployment surfaces.

**Independent Test**: Compile Python files and inspect compose config without
enabling industrial profiles.

- [x] T024 [US4] Implement local endpoint agent in `agents/local/agent.py`
- [x] T025 [P] [US4] Add local agent requirements in `agents/local/requirements.txt`
- [x] T026 [P] [US4] Add defensive YARA ransomware examples in `modules/intelligence/yara/rules/ransomware.yar`
- [x] T027 [P] [US4] Add defensive YARA OT examples in `modules/intelligence/yara/rules/ot_threats.yar`

**Checkpoint**: User Story 4 functional and testable.

---

## Final Phase: Polish & Cross-Cutting Concerns

- [x] T028 Run `go test ./...` in `core/orchestrator`
- [x] T029 Run Python compile checks for `agents/local/agent.py` and `modules/industrial/ot_monitor/main.py`
- [x] T030 Run `docker compose --profile core config`
- [x] T031 Update external memory vault with architecture and implementation decisions
- [x] T032 Add embedded Cybersecurity-AEGIS dashboard that merges local research and GitHub repository decisions
- [x] T033 Import CyberShield AI v0.2 ZIP as `modules/ml/cybershield_ai`
- [x] T034 Add CyberShield AI Docker profile and environment variables
- [x] T035 Add `/api/v1/ingest/cybershield-ai` normalizer and tests
- [x] T036 Surface CyberShield AI models, metrics, safety policy, and integrations in the dashboard
- [x] T037 Update architecture/source-decision docs with ML boundary and production gates

## Dependencies & Execution Order

- Setup (Phase 1) is complete.
- Foundational tasks block all implementation stories.
- US1 and US2 are the MVP and should be completed before broader OT work.
- US3 and US4 can proceed after the foundation and may be worked independently.

## Implementation Strategy

1. Deliver Go orchestrator and API first.
2. Add event normalizers and test samples.
3. Add passive/simulation OT monitor.
4. Add endpoint agent and detection examples.
5. Validate build/syntax and compose configuration.
