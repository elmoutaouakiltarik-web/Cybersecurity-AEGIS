# GitHub Research: Cybersecurity-AEGIS

Verified on 2026-05-21 from GitHub primary repository pages/search plus the
local research files in the parent workspace. A repeat GitHub API pull during
the CyberShield merge hit anonymous rate limiting, so volatile counts should be
refreshed with an authenticated token before procurement or release decisions.

## Decision Model

| Decision | Meaning |
| --- | --- |
| Baseline | Candidate for the defensive Cybersecurity-AEGIS core or first production roadmap. |
| Optional | Useful, but only after explicit configuration, scope control, or operational need. |
| Lab | Research, simulation, DFIR, deception, or OT test-bench only. |
| Excluded | Not suitable for default baseline because of archive/EOL status, commercial-only shift, or dual-use risk. |

## Baseline Repository Set

| Repository | Role | Decision Notes |
| --- | --- | --- |
| [wazuh/wazuh](https://github.com/wazuh/wazuh) | SIEM/XDR/HIDS backbone | Primary alert and endpoint security backbone. |
| [zeek/zeek](https://github.com/zeek/zeek) | Network security monitoring | High-fidelity network metadata and protocol analysis. |
| [OISF/suricata](https://github.com/OISF/suricata) | IDS/IPS/NDR | EVE JSON alert source for normalized ingest. |
| [Velocidex/velociraptor](https://github.com/Velocidex/velociraptor) | DFIR/live response | Service boundary recommended because licensing is strong copyleft/unclear via API. |
| [greenbone/openvas-scanner](https://github.com/greenbone/openvas-scanner) | Vulnerability scanner | IT baseline; OT scanning requires allowlists and maintenance windows. |
| [MISP/MISP](https://github.com/MISP/MISP) | Threat intelligence sharing | Run as a separate service because AGPL boundary matters. |
| [OpenCTI-Platform/opencti](https://github.com/OpenCTI-Platform/opencti) | CTI graph | Strong fit for STIX2 knowledge graph and connector ecosystem. |
| [scikit-learn/scikit-learn](https://github.com/scikit-learn/scikit-learn) | ML runtime | Required by the imported CyberShield AI model artifacts and retraining path. |
| [joblib/joblib](https://github.com/joblib/joblib) | Model artifact loading | Used by the supplied CyberShield AI `.joblib` models. |
| [fastapi/fastapi](https://github.com/fastapi/fastapi) | Prediction API | Runtime API framework for the CyberShield AI service profile. |
| [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | Detection-as-code | Portable detection rules; backend conversion/testing required. |
| [StackStorm/st2](https://github.com/StackStorm/st2) | SOAR automation | IT remediation and enrichment workflows; OT actions need approval gates. |
| [keycloak/keycloak](https://github.com/keycloak/keycloak) | IAM/SSO | Central identity provider for dashboard and APIs. |
| [inverse-inc/packetfence](https://github.com/inverse-inc/packetfence) | NAC | Gradual rollout only; policy errors can affect availability. |
| [smallstep/certificates](https://github.com/smallstep/certificates) | PKI/mTLS | Private CA and certificate lifecycle for AEGIS services. |
| [fleetdm/fleet](https://github.com/fleetdm/fleet) | Device management | Inventory, osquery orchestration, patch visibility. |
| [osquery/osquery](https://github.com/osquery/osquery) | Endpoint telemetry | SQL-based endpoint instrumentation. |
| [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav) | Antivirus scanning | On-demand and daemon scanning workflows. |
| [crowdsecurity/crowdsec](https://github.com/crowdsecurity/crowdsec) | Perimeter reputation | Bouncers and decisions limited to IT/perimeter by default. |
| [openbao/openbao](https://github.com/openbao/openbao) | Secrets management | Strong local secrets service for automation. |
| [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | Secret scanning | Repository and filesystem scanning. |
| [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | Secret verification | Useful for verified credential findings; AGPL boundary applies. |
| [CISOfy/lynis](https://github.com/CISOfy/lynis) | Hardening audit | Agentless Linux/macOS/Unix audit. |
| [VirusTotal/yara](https://github.com/VirusTotal/yara) | Malware rules | Classic YARA is maintenance mode; track YARA-X for future migration. |
| [open62541/open62541](https://github.com/open62541/open62541) | OPC UA | Good OT protocol candidate because MPL-2.0 is integration-friendly. |
| [pymodbus-dev/pymodbus](https://github.com/pymodbus-dev/pymodbus) | Modbus | Fit for read-only collectors, simulator mode, and lab adapters. |
| [cisagov/Malcolm](https://github.com/cisagov/Malcolm) | PCAP/traffic IR | Use as IR/OT analytics appliance, not always-on duplicate of core SIEM. |
| [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | Reverse engineering | Malware, firmware, and binary analysis. |
| [volatilityfoundation/volatility3](https://github.com/volatilityfoundation/volatility3) | Memory forensics | Custom VSL license; procurement/redistribution review required. |

## Optional Or Lab Repository Set

| Repository | Classification | Reason |
| --- | --- | --- |
| [dani-garcia/vaultwarden](https://github.com/dani-garcia/vaultwarden) | Optional | Excellent personal vault, but not mandatory for the AEGIS security control plane. |
| [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go) | Optional | GitHub mirror; kernel WireGuard is preferred on Linux. |
| [wg-easy/wg-easy](https://github.com/wg-easy/wg-easy) | Optional | Convenient VPN UI, AGPL boundary and hardening required. |
| [nmap/nmap](https://github.com/nmap/nmap) | Optional | Authorized audit only; never default on OT. |
| [RustScan/RustScan](https://github.com/RustScan/RustScan) | Optional | Fast discovery helper, same authorized-scope constraint as Nmap. |
| [sullo/nikto](https://github.com/sullo/nikto) | Optional | Web server scanner for owned assets. |
| [mz-automation/libiec61850](https://github.com/mz-automation/libiec61850) | Optional | Useful for power/substation monitoring; GPL-3.0 boundary. |
| [mushorg/conpot](https://github.com/mushorg/conpot) | Lab | ICS honeypot; latest public release is old, so keep isolated. |
| [OpenPLC Runtime v4](https://autonomylogic.com/runtime) | Lab | Useful digital twin/test bench, but public GitHub runtime v4 was not confirmed in this pass. |

## Excluded From Baseline

| Repository | Reason |
| --- | --- |
| [TheHive-Project/TheHive](https://github.com/TheHive-Project/TheHive) | Public repository is archived; current maintained version is commercial. |
| [thiagoralves/OpenPLC_v3](https://github.com/thiagoralves/OpenPLC_v3) | Archived/EOL and replaced by OpenPLC Runtime v4. |
| C2/exploit/brute-force frameworks | Dual-use or offensive by default; outside the defensive scope of Cybersecurity-AEGIS. |

## Dashboard Integration

The embedded dashboard in `core/orchestrator/dashboard/index.html` surfaces this
catalog as filterable repository intelligence and links every repository back to
its primary source.

## CyberShield AI ZIP Merge

The local `CyberShield_AI_Real_NSLCIC_Pro_v0_2.zip` is not a GitHub repository,
but it is now treated as a first-party research asset inside
`modules/ml/cybershield_ai`. It contributes real NSL-KDD model artifacts,
training reports, Wazuh/Zeek/Suricata/StackStorm examples, and OT/ICS safety
notes. The older v0.1 ZIP is retained conceptually as provenance; v0.2 is the
runtime source.
