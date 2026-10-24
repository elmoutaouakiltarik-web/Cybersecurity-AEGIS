# Cybersecurity-AEGIS 🔱

**Personal and industrial cybersecurity control plane** — defensive monitoring,
event normalization, AI-driven anomaly detection, repository-driven architecture,
and safe OT/ICS visibility.

> *"The best defense is a unified defense."*

## Screenshots

| SOC Overview | Shield Engine |
|---|---|
| ![SOC Overview](docs/screenshots/soc-overview.png) | ![Shield Engine](docs/screenshots/shield-engine.png) |

| OT Control | Threat Intelligence |
|---|---|
| ![OT Control](docs/screenshots/ot-control.png) | ![Threat Intelligence](docs/screenshots/threat-intel.png) |

| SIEM Correlation | Plant Assessment |
|---|---|
| ![SIEM Correlation](docs/screenshots/siem-correlation.png) | ![Plant Assessment](docs/screenshots/plant-assessment.png) |

> Captured from a local instance populated with synthetic sample events. No
> customer, production or personal data appears in these images.

## What is Cybersecurity-AEGIS?

Cybersecurity-AEGIS is not a monolithic security product. It is a **composable,
vendor-neutral suite** that turns trusted open-source defensive tools and
first-party collectors into one coherent local workflow:

- **Embedded dashboard** at `/dashboard/` with real-time events, module posture,
  GitHub repository catalog, safety gates, and roadmap.
- **Go orchestrator** with health checks, module status, metrics, event ingest,
  optional PostgreSQL persistence, and SSE live streaming.
- **Normalized event model** for Wazuh, Suricata, CrowdSec, OT monitor, ML IDS,
  threat intel, vulnerabilities, and generic sources.
- **CyberShield AI** ML/IDS module with real NSL-KDD model artifacts, FastAPI
  prediction API, reports, and SOC integrations.
- **Passive OT/ICS monitor** for Modbus, DNP3, OPC UA, IEC 61850, BACnet, and
  Profinet — simulation-first, read-only by default.
- **SIEM correlation engine** with Sigma-inspired rules, temporal correlation,
  and incident deduplication.
- **SOAR-lite playbook executor** with YAML playbooks, dry-run default, OT safety
  gates, and audit trails.
- **Threat intelligence module** with IOC registry, MISP/OTX/AbuseIPDB feeds,
  and automatic event enrichment.
- **Vulnerability scanner** with passive-first operation, NVD CVE lookup, and
  service-to-CVE correlation.

## Safety Position

Cybersecurity-AEGIS is **defensive-only**. The default stack does not include
exploit frameworks, C2 systems, brute-force tooling, or active OT manipulation.

OT/ICS support is **passive and simulation-first**. Industrial traffic monitoring
is opt-in through `docker-compose.industrial.yml` and must only be used on
networks where you have explicit authorization.

## Quick Start

### Option A — Windows Standalone (no Docker required)

The simplest way to run AEGIS on Windows with a fully functional Control Room:

```powershell
# From the project root:
.\start-aegis.ps1
```

**What it does automatically:**
1. Builds the Go orchestrator with `go build`
2. Installs Python dependencies (Flask, FastAPI, scikit-learn, etc.)
3. Starts all core module services (Network, SIEM, SOAR, Threat Intel, Vuln, Reports, OT, CyberShield AI)
4. Starts the host-native Endpoint Protection module on Windows (`:8088`) unless disabled with `-NoEndpoint`
5. Starts the Go orchestrator on port 8070
6. Runs in real-data mode (no synthetic demo seed)
7. Opens the browser to `http://localhost:8070/dashboard/` (disable with `-NoBrowser`)

To stop everything: `.\stop-aegis.ps1` or press Ctrl+C in the launcher window.

Optional launcher flags:
- `.\start-aegis.ps1 -NoEndpoint` to skip host endpoint checks
- `.\start-aegis.ps1 -EndpointPort 9088` to change endpoint port
- `.\start-aegis.ps1 -NoBrowser` to keep it headless

**Requirements:**
- Python 3.10+ (`python --version`)
- Go 1.22+ (`go version`) — required, the launcher builds the orchestrator locally

### Option B — Docker (Linux / macOS / Windows with Docker Desktop)

```bash
# Linux / macOS:
bash install.sh

# Windows (PowerShell as Administrator):
.\install.ps1
```

**Manual Docker:**
```bash
cp .env.example .env
docker compose --profile full up --build -d
```

### Verify

```powershell
# Health
Invoke-RestMethod http://localhost:8070/health

# Dashboard
Start-Process http://localhost:8070/dashboard/
```

### Send a test event

There is no demo-data generator: the platform runs on real ingested data. Use
any `/api/v1/ingest/*` endpoint to push events.

```powershell
Invoke-RestMethod -Uri http://localhost:8070/api/v1/ingest/generic `
  -Method POST -ContentType "application/json" `
  -Body '{"source":"manual","category":"system","severity":"high","title":"AEGIS test alert"}'
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Cybersecurity-AEGIS                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │  Dashboard  │  │  Go API     │  │  Event Bus          │  │
│  │  (HTML/JS)  │  │  (REST/SSE) │  │  Memory + Postgres  │  │
│  └──────┬──────┘  └──────┬──────┘  └─────────────────────┘  │
└─────────┼────────────────┼───────────────────────────────────┘
          │                │
    ┌─────┴─────┐    ┌─────┴─────┐
    │  Sources  │    │ Consumers │
    │  ───────  │    │ ────────  │
    │ Wazuh     │    │ SIEM      │
    │ Suricata  │    │ SOAR      │
    │ CrowdSec  │    │ Threat    │
    │ CyberShield│   │ Intel     │
    │ OT Monitor│    │ Vuln      │
    │ Network   │    │ Scanner   │
    └───────────┘    └───────────┘
```

For the full architecture document, see [docs/architecture.md](docs/architecture.md).

## Profiles

Deploy only what you need:

| Profile | Purpose |
|---------|---------|
| `core` | Orchestrator + dashboard |
| `ml` | CyberShield AI prediction API |
| `siem` | Wazuh + SIEM correlator |
| `network` | Suricata + network analyzer |
| `soar` | Playbook executor |
| `threat-intel` | IOC enrichment service |
| `vuln` | Vulnerability scanner |
| `industrial` | OT/ICS passive monitor |
| `storage` | PostgreSQL persistence |
| `observability` | Prometheus |
| `full` | Everything |

## CyberShield AI Integration

CyberShield AI v0.3 is embedded as the ML/IDS neural core:

- **Binary ensemble**: BENIGN vs ATTACK classification
- **Family classifier**: DoS, Probe, R2L, U2R, normal
- **Anomaly baseline**: Deviation scoring with confidence
- **FastAPI service**: Port 8919 with `/predict` and `/predict_batch`
- **Safety**: OT/ICS outputs are alert-only unless a human approves action

Ingest a prediction into AEGIS:
```bash
curl -X POST http://localhost:8070/api/v1/ingest/cybershield-ai \
  -H "Content-Type: application/json" \
  -d '{"binary_prediction":"ATTACK","family_prediction":"DoS","risk_score":95,"confidence":0.98}'
```

## OT/ICS Safety

- **Read-only default**: Collectors parse traffic; they never write to PLCs.
- **Simulation mode**: Default in containers for safe development.
- **Live capture**: Requires explicit `--interface` and host networking.
- **Approval gates**: SOAR playbooks for OT are advisory-only; no automated
  containment.

## Plant Assessment (rete industriale)

Modulo dedicato al lavoro sul campo: collegarsi alla rete di un impianto,
capire cosa c'e', quali porte e protocolli sono esposti e cosa puo' essere
comandato da chi, **senza fermare la produzione**.

- **Passivo prima di tutto**: analizza un pcap/pcapng o cattura da mirror port
  senza inviare un solo pacchetto.
- **Read-only sui protocolli di processo**: Modbus FC43, S7 Read SZL,
  EtherNet/IP ListIdentity, BACnet Who-Is/ReadProperty, SNMP GET, OPC UA Hello.
  Ogni funzione di scrittura e' bloccata a livello di codice.
- **Rileva comandi di scrittura** osservati nel traffico (Modbus, S7, DNP3,
  IEC 104, BACnet, PROFINET DCP Set): il segnale piu' diretto di manipolazione
  o malware.
- **Report in italiano** diviso tra interventi applicabili in produzione e
  interventi da pianificare in fermata, con MITRE ATT&CK for ICS e IEC 62443.
- **Baseline**: confronto nel tempo per scoprire device nuovi e porte comparse.

```powershell
cd modules\industrial
python -m site_assessment preflight
python -m site_assessment assess --site "Linea 2" --auth-ref "WO-2026-014" `
    --target 192.168.10.0/24 --pcap cattura.pcapng --out reports\linea2
python -m site_assessment selftest   # verifica installazione, nessuna rete
```

Dalla dashboard: **Plant Assessment** (porta 8097, proxata dall'orchestratore).
Guida completa: [docs/industrial-site-assessment.md](docs/industrial-site-assessment.md).

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Orchestrator health |
| `/api/v1/metrics` | GET | System metrics & module status |
| `/api/v1/events` | GET/POST | Query or publish events |
| `/api/v1/events/live` | GET | SSE live event stream |
| `/api/v1/config` | GET | Current configuration |
| `/api/v1/modules` | GET/PUT | Module status & updates |
| `/api/v1/ingest/wazuh` | POST | Ingest Wazuh alert |
| `/api/v1/ingest/suricata` | POST | Ingest Suricata EVE JSON |
| `/api/v1/ingest/crowdsec` | POST | Ingest CrowdSec decision |
| `/api/v1/ingest/cybershield-ai` | POST | Ingest ML prediction |
| `/api/v1/ingest/ot` | POST | Ingest OT/ICS event |
| `/api/v1/ingest/network` | POST | Ingest network alert |
| `/api/v1/ingest/threat-intel` | POST | Ingest TI match |
| `/api/v1/ingest/vuln` | POST | Ingest vulnerability finding |
| `/api/v1/ingest/generic` | POST | Ingest any event |
| `/api/v1/soar/trigger` | POST | Trigger SOAR on event |
| `/api/endpoint/health` | GET | Endpoint module health via orchestrator proxy |
| `/api/endpoint/audit` | GET/POST | Host hardening audit via endpoint module |
| `/dashboard/` | GET | Embedded web dashboard |

## Repository Layout

```
.
├── README.md
├── INSTALL.md
├── COMMERCIAL.md
├── LICENSE
├── install.sh / install.ps1
├── .env.example
├── docker-compose.yml
├── docker-compose.industrial.yml
├── core/orchestrator/         # Go API + dashboard
├── modules/
│   ├── ml/cybershield_ai/     # ML/IDS FastAPI service
│   ├── network/               # Passive traffic analyzer
│   ├── siem/                  # Correlation engine
│   ├── soar/                  # Playbook executor
│   ├── threat_intel/          # IOC & feeds
│   ├── vuln/                  # CVE scanner
│   ├── industrial/ot_monitor/ # OT/ICS parser
│   └── industrial/site_assessment/ # Assessment rete industriale (passivo + read-only)
├── playbooks/                 # YAML SOAR playbooks
├── config/                    # Prometheus, OT config
└── docs/                      # Architecture, decisions
```

## License

Cybersecurity-AEGIS is released under **AGPL-3.0 + Commons Clause**.

- Free for personal, research, and internal defensive use.
- Commercial redistribution, OEM embedding, and MSP multi-tenant use require a
  commercial license. See [COMMERCIAL.md](COMMERCIAL.md).

## Acknowledgments

AEGIS is possible thanks to the global open-source security community:
Wazuh, Suricata, Zeek, CrowdSec, MISP, OpenCTI, Sigma, StackStorm, Keycloak,
PacketFence, step-ca, Fleet, Greenbone, Velociraptor, Ghidra, Volatility,
open62541, pymodbus, and many more.
