# Quickstart: Cybersecurity-AEGIS MVP

## 1. Prepare environment

```powershell
cd "<percorso-progetto>"
Copy-Item .env.example .env
```

Edit `.env` and replace all `CHANGE_ME` values before production use.

## 2. Build and test the orchestrator

```powershell
cd core\orchestrator
go test ./...
go run .
```

Health check:

```powershell
Invoke-RestMethod http://localhost:8080/health
```

Dashboard:

```text
http://localhost:8080/dashboard/
```

## 3. Send sample events

```powershell
Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/ingest/generic `
  -ContentType "application/json" `
  -Body '{"source":"manual","category":"system","severity":"high","title":"Cybersecurity-AEGIS sample alert","description":"Manual test","tags":["sample"]}'

Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/ingest/wazuh `
  -ContentType "application/json" `
  -Body '{"rule":{"level":12,"description":"Privilege escalation attempt","mitre":{"id":"T1068","technique":"Exploitation for Privilege Escalation"}}}'

Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/ingest/suricata `
  -ContentType "application/json" `
  -Body '{"alert":{"signature":"ET TEST Critical alert","severity":1}}'

Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/ingest/crowdsec `
  -ContentType "application/json" `
  -Body '{"scenario":"ssh-bf","source_ip":"203.0.113.10","remediation":"ban"}'

Invoke-RestMethod -Method Post -Uri http://localhost:8080/api/v1/ingest/ot `
  -ContentType "application/json" `
  -Body '{"severity":"critical","protocol":"modbus","title":"Unauthorized OT asset observed","description":"Simulation event","source_ip":"192.168.10.250","purdue_level":1,"mitre_technique_id":"T0824","mitre_technique_name":"Device Discovery"}'

Invoke-RestMethod http://localhost:8080/api/v1/events
Invoke-RestMethod http://localhost:8080/api/v1/metrics
```

## 4. Run OT monitor in simulation mode

```powershell
python modules\industrial\ot_monitor\main.py --simulate --cycles 3
```

Note: the OT monitor scaffold is tracked in `tasks.md`; run this command after
that module exists in the local checkout.

## 5. Compile Python files

```powershell
python -m py_compile agents\local\agent.py modules\industrial\ot_monitor\main.py
```

Note: the Python agent and OT monitor are roadmap scaffolds in this workspace.

## 6. Compose baseline

The baseline compose file is a scaffold. Start with the orchestrator profile only
until secrets and upstream service configuration are completed.

```powershell
docker compose --profile core config
```
