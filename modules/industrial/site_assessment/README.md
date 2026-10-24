# Industrial Site Assessment

Assessment di sicurezza per reti di impianto (fabbrica, linea, cabina, depuratore)
con approccio **passivo-first** e **read-only** sui protocolli di processo.

Guida completa: [docs/industrial-site-assessment.md](../../../docs/industrial-site-assessment.md).

## Quick start

```bash
cd modules/industrial

python -m site_assessment preflight          # capacita' della macchina
python -m site_assessment selftest           # verifica installazione, nessuna rete

# Analisi passiva di una cattura Wireshark (nessun pacchetto inviato)
python -m site_assessment assess \
  --site "Linea 2" --auth-ref "WO-2026-014" --mode passive \
  --target 192.168.10.0/24 --pcap cattura.pcapng \
  --zones site_assessment/examples/zones.example.json --out ../../reports/linea2

# Scansione read-only, con baseline per i confronti futuri
python -m site_assessment assess \
  --site "Linea 2" --auth-ref "WO-2026-014" --mode readonly --profile ot \
  --target 192.168.10.0/24 --pcap cattura.pcapng \
  --save-baseline ../../data/site_assessment/linea2-baseline.json \
  --out ../../reports/linea2
```

## API e dashboard

```bash
python -m site_assessment.app       # http://127.0.0.1:8097
```

Dashboard → **Plant Assessment** (proxy orchestratore `/api/v1/proxy/site-assessment/`).
Endpoint: `/preflight`, `/analyze-pcap`, `/assess`, `/assess/<id>`,
`/assess/<id>/result`, `/assess/<id>/report?format=html|md|json`.

## Garanzie di sicurezza

| Controllo | Dove |
|---|---|
| Autorizzazione scritta obbligatoria (`authorization_ref`) | `safety.Engagement.validate` |
| Scope chiuso IP/CIDR, esclusioni, no target pubblici | `safety.Engagement.check_ip/check_target` |
| Blacklist funzioni di scrittura (Modbus, S7, DNP3, IEC104, BACnet, ENIP, PROFINET) | `safety.DANGEROUS_OPERATIONS` |
| Rate limit globale e per host | `safety.RateLimiter` |
| Audit log JSONL di ogni azione | `safety.AuditLog` |
| Nessun probe su DNP3/IEC104/PROFINET I/O | `fingerprint.NO_PROBE_PROTOCOLS` |
| Test che verificano il blocco delle scritture | `tests/test_industrial_assessment.py` |

## Struttura

| File | Ruolo |
|---|---|
| `models.py` | Asset, Finding, Anomaly, Coverage, AssessmentResult |
| `safety.py` | Engagement, scope, rate limit, audit, preflight |
| `dissect.py` | Dissector Ethernet/ARP/IP + 15 protocolli industriali |
| `pcap.py` | Lettore/scrittore pcap e pcapng (senza dipendenze) |
| `passive.py` | Inventario e anomalie da traffico |
| `scan.py` | Port scan TCP con classificazione OT |
| `fingerprint.py` | Sonde read-only di identificazione |
| `risk.py` | Regole IEC 62443 / Purdue / MITRE ICS |
| `report.py` | Report Markdown, HTML, JSON |
| `baseline.py` | Snapshot e diff nel tempo |
| `assessor.py` | Orchestrazione job |
| `cli.py` / `app.py` | CLI e API REST |
| `demo.py` | Traffico sintetico per self-test |
