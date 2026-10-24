# Source Decisions

This file records how the supplied research, pasted prototype notes, AEGIS-OMNI
blueprint, and GitHub repository checks were translated into the current
Cybersecurity-AEGIS implementation.

## Accepted Into MVP

- Cybersecurity-AEGIS product name and defense-in-depth direction.
- Embedded dashboard served by the Go orchestrator at `/dashboard/`.
- Local Go orchestrator for event ingest, module state, and metrics.
- Normalized event model for Wazuh, Suricata, CrowdSec, generic, and OT events.
- CyberShield AI v0.2 package from the supplied ZIP as `modules/ml/cybershield_ai`.
- ML event ingest endpoint `/api/v1/ingest/cybershield-ai`.
- Repository intelligence catalog with baseline/optional/lab/excluded decisions.
- Passive/simulation-first OT posture.
- Defensive YARA/Sigma direction as detection-as-code examples.
- Docker Compose profiles for local development.

## Accepted Into Roadmap

- Wazuh, Zeek, Suricata, Velociraptor, Greenbone, MISP, OpenCTI, Sigma,
  StackStorm, Keycloak, PacketFence, step-ca, Fleet.
- OSQuery, ClamAV, CrowdSec, OpenBao, Gitleaks, TruffleHog, Lynis, YARA.
- open62541 and pymodbus for read-only OT protocol adapters.
- Malcolm, Ghidra, and Volatility 3 for DFIR and OT/PCAP investigation.

## Deferred

- Durable PostgreSQL/OpenSearch persistence and migrations.
- Full external service deployment for the repository catalog.
- Threat intelligence feed ingestion.
- MITRE ATT&CK enrichment beyond basic normalized fields.
- Production AI anomaly engines beyond the imported CyberShield AI proof module.
- Tauri/Electron desktop packaging.

## Optional Or Lab-Only

- Vaultwarden and WG-Easy are useful for personal operations but not required in
  the baseline.
- Nmap, RustScan, and Nikto are authorized-audit only; never default on OT.
- libiec61850 is useful for power/substation work but has a GPL-3.0 boundary.
- Conpot is lab/deception only.
- OpenPLC Runtime v4 is a lab/digital-twin candidate; public GitHub runtime v4
  was not confirmed during this pass.

## Excluded From Default Stack

The larger AEGIS notes mention powerful tools that can be dual-use or unsuitable
as default dependencies. They are not included in the default stack:

- exploit frameworks and C2 tooling
- brute-force automation
- active OT scanners
- autonomous blocking or OT network enforcement
- honeypots that expose services by default
- TheHive OSS public repository, because it is archived and the maintained
  distribution is now commercial
- OpenPLC v3, because it is archived/EOL and replaced by Runtime v4

## Key Corrections

- The project name is now Cybersecurity-AEGIS.
- The old CyberForge naming is retained only as early Spec Kit track history or
  backward-compatible environment aliases.
- The OT module is passive by default, not an automatic enforcer.
- Industrial host networking is separated into `industrial-host`, not enabled by
  the normal industrial simulation profile.
- Secrets are placeholders in `.env.example`; no generated credentials are committed.
- The orchestrator MVP uses the Go standard library to reduce dependency and
  build risk.
- The CyberShield v0.2 ZIP supersedes the older v0.1 model package for runtime
  placement; v0.1 remains useful only as provenance/history.
- The supplied CyberShield models are real MVP artifacts, but production needs
  full NSL-KDD/CIC/UNSW/TON_IoT retraining, drift tests, signed artifacts, and
  model cards before any safety-critical reliance.
