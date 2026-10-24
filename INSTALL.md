# Cybersecurity-AEGIS — Installation Guide

## System Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores x86_64 | 8 cores / Apple Silicon |
| RAM | 8 GB | 16–32 GB |
| Disk | 50 GB SSD | 128–256 GB NVMe |
| Network | 1 Gbps | 1 Gbps + promiscuous interface |
| OS | Linux (Debian/Ubuntu/Fedora) | Ubuntu 24.04 LTS |
| Docker | Engine 24.0+ with Compose | Docker Desktop / Docker CE latest |

## Quick Start (Docker Compose)

### 1. Clone or extract the project

```bash
cd Cybersecurity-AEGIS
cp .env.example .env
# Edit .env if you want to change ports or enable PostgreSQL persistence
```

### 2. Run the full stack

```bash
# Build and start all modules
docker compose --profile full up --build -d
```

### 3. Verify health

```bash
# Orchestrator
curl http://localhost:8070/health

# CyberShield AI ML
curl http://localhost:8919/health

# Dashboard (open in browser)
http://localhost:8070/dashboard/
```

### 4. Send a test event

```bash
curl -X POST http://localhost:8070/api/v1/ingest/generic \
  -H "Content-Type: application/json" \
  -d '{"source":"manual","category":"system","severity":"high","title":"Test alert"}'
```

## Profile-Based Deployment

Instead of `full`, you can start only the profiles you need:

| Profile | Services |
|---------|----------|
| `core` | Orchestrator + dashboard |
| `ml` | CyberShield AI prediction API |
| `siem` | Wazuh manager + SIEM correlator |
| `network` | Suricata IDS + network analyzer |
| `soar` | Playbook executor |
| `threat-intel` | IOC registry + enrichment |
| `vuln` | Vulnerability scanner |
| `industrial` | OT/ICS passive monitor + industrial site assessment API (:8097) |
| `storage` | PostgreSQL |
| `observability` | Prometheus |

Example:

```bash
# Core + ML + OT only
docker compose --profile core --profile ml --profile industrial up --build -d
```

## Data Persistence

By default, events are stored in-memory with a ring buffer (10,000 events).
To enable PostgreSQL persistence:

1. In `.env`, set:
   ```
   AEGIS_DB_CONN=postgres://aegis:CHANGE_ME_LOCAL_ONLY@postgres:5432/aegis?sslmode=disable
   ```
2. Start with the `storage` profile:
   ```bash
   docker compose --profile core --profile storage up --build -d
   ```

## Updating

```bash
docker compose --profile full pull
docker compose --profile full up --build -d
```

## Uninstall

```bash
docker compose --profile full down -v
```

## Troubleshooting

- **Port conflicts**: Change `DASHBOARD_API_PORT` or `CYBERSHIELD_AI_PORT` in `.env`.
- **Scapy not available on Windows host**: Network and OT monitors run inside Linux containers; this is normal.
- **OT monitor simulation**: The industrial profile runs in simulation mode by default. For live capture, use host networking and set `OT_MONITOR_INTERFACE`.
- **SOAR dry-run**: All playbooks run in dry-run mode by default. Set `SOAR_LIVE_MODE=true` only after safety review.

## Support

For architecture details, see `docs/architecture.md`.  
For commercial inquiries, see `COMMERCIAL.md`.
