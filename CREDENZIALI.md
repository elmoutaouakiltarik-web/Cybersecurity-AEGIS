# AEGIS-OMNI Control Room — Credenziali & Quick Start

## Credenziali di default

| Campo | Valore |
|---|---|
| Username | `admin` |
| Password | impostata con `AEGIS_ADMIN_PASSWORD` (se assente, generata e stampata al primo avvio) |
| URL Dashboard | http://127.0.0.1:8070/dashboard/ |

> La password è **hashata in memoria** all'avvio. Non viene mai scritta su disco.
> Cambiala con la env var `AEGIS_ADMIN_PASSWORD` prima di avviare, oppure passa `-AdminPassword` allo script:
> ```powershell
> .\aegis-docker.ps1 -AdminPassword "MiaPasswordSicura#2026"
> ```

## Avvio rapido (un solo comando)

```powershell
# Dal root del progetto Cybersecurity-AEGIS/
.\aegis-docker.ps1
```

Lo script:
1. Verifica che Docker Desktop sia attivo.
2. Builda i container del profilo full (orchestrator + moduli + postgres) — ~2-4 min la prima volta.
3. Avvia lo stack.
4. Attende healthy.
5. Esegue smoke test su tutti gli endpoint.
6. Apre il browser sulla dashboard.
7. Stampa le credenziali.

### Con il modulo OT/ICS (industrial)

```powershell
.\aegis-docker.ps1 -Industrial
```

### Rebuild completo (no cache)

```powershell
.\aegis-docker.ps1 -Rebuild
```

### Arresto

```powershell
.\aegis-docker.ps1 -Stop
```

(I dati Postgres/eventi/report rimangono nei volumi.)

## Test end-to-end

Dopo che `aegis-docker.ps1` ha finito:

```powershell
.\aegis-smoke-test.ps1
```

Verifica login, /auth/me, metriche, remediation (CVE/servizio/IOC/TLS), SIEM rules,
CVE search, ingest reale, network discover, threat-intel lookup, logout.

## Endpoint host-native (consigliato su Windows)

Per collegare AEGIS ai controlli reali del tuo PC (Defender, Firewall, BitLocker,
processi, scansioni file/secrets), avvia anche:

```powershell
.\aegis-endpoint.ps1 -Admin
```

Questo espone il modulo su `http://127.0.0.1:8088` e la dashboard usa i path
`/api/endpoint/*` tramite orchestrator proxy.

## Modalità login

| Metodo | Quando |
|---|---|
| **admin/password** | Default. Sessione 4h via cookie HttpOnly `aegis_sid`. |
| **API key Bearer** | Imposta `AEGIS_API_KEY=<token>` nell'env. Click "Hai una API key?" sulla login box. |
| **Modalità locale** | Click "Entra in modalità locale". Crea una sessione locale reale solo da `127.0.0.1` / `::1`. |

In Docker l'env `AEGIS_AUTH_REQUIRED=true` protegge comunque le API. Il pulsante locale
non disattiva la sicurezza: crea una sessione localhost-only e viene rifiutato da IP non locali.

## Tool funzionanti dalla dashboard

Ogni risultato include un bottone **🔧 Fix** che mostra rimedio concreto, riferimenti e
playbook SOAR consigliato.

| Pagina | Tool reale | Endpoint | Remediation |
|---|---|---|---|
| Network | LAN discovery, scan TCP, banner grabbing | `/api/scan/*` | per servizio + porta |
| Vulnerabilities | CVE matching da banner + NVD live | `/api/vuln/*`, `/api/v1/vuln/cve-search` | per CVE (KEV-aware) |
| Threat Intel | IOC lookup IP/dominio | `/api/ti/lookup` | per categoria IOC |
| TLS Inspector | Cipher, cert, OCSP, HSTS | `/api/tls/inspect` | per issue TLS |
| Topology | Grafo + attack paths | `/api/topology*` | segmentation gaps |
| Threat Fusion | Correlazione multi-modulo | `/api/fusion/*` | kill-chain awareness |
| SIEM | Regole correlazione | `/api/v1/siem/rules` | livello regola |
| SOAR | Playbook (dry-run) | `/api/v1/playbooks`, `/api/v1/soar/trigger` | esecuzione su match |
| OT/ICS | Asset Modbus/DNP3/OPC UA | `/api/v1/ot/assets` | OT-safe (read-only) |
| Reports | Export HTML/JSON | `/api/report` | – |
| ML | CyberShield AI (NSL-KDD) | proxy `/api/v1/proxy/ml/*` | – |

## Endpoint API principali

| Verbo | Path | Descrizione |
|---|---|---|
| POST | `/api/v1/auth/login` | `{username,password}` → cookie sessione |
| POST | `/api/v1/auth/logout` | Invalida sessione corrente |
| GET  | `/api/v1/auth/me` | Stato autenticazione |
| GET  | `/api/v1/remediation?cve=...&service=...&port=...&ioc=...&tls=...` | Knowledge base rimedi |
| GET  | `/api/v1/metrics` | KPI dashboard |
| GET  | `/api/v1/events?limit=N&category=X&severity=Y` | Event store |
| GET  | `/api/v1/events/live` | Server-Sent Events stream |
| POST | `/api/v1/demo/seed` | Inietta eventi demo |
| GET  | `/api/v1/siem/rules` | Regole correlazione SIEM |
| GET  | `/api/v1/playbooks` | Playbook SOAR |

## Porte locali

| Servizio | Porta | URL health |
|---|---|---|
| Orchestrator | 8070 | http://127.0.0.1:8070/health |
| Network | 8081 | http://127.0.0.1:8081/health |
| SIEM | 8082 | http://127.0.0.1:8082/health |
| SOAR | 8083 | http://127.0.0.1:8083/health |
| Threat Intel | 8084 | http://127.0.0.1:8084/health |
| Vuln | 8085 | http://127.0.0.1:8085/health |
| Reports | 8086 | http://127.0.0.1:8086/health |
| OT (industrial) | 8087 | http://127.0.0.1:8087/health |
| Endpoint (host-native) | 8088 | http://127.0.0.1:8088/health |
| Postgres | 5432 | – |

## Troubleshooting

- **"Docker engine non risponde"** → Avvia Docker Desktop e riprova.
- **Login dice "Credenziali non valide"** ma le credenziali sono giuste → controlla il
  log dell'orchestrator: `docker compose -f docker-compose.full.yml logs orchestrator | grep "Auth:"`.
- **Tool restituiscono "module offline: X"** → un container è giù. `docker compose -f docker-compose.full.yml ps` e
  `docker compose -f docker-compose.full.yml logs <nome>`.
- **Voglio cambiare password** → arresta lo stack, imposta `$env:AEGIS_ADMIN_PASSWORD = "nuova"`,
  poi `.\aegis-docker.ps1 -Rebuild`.
- **Reset completo (incluso DB)** → `docker compose -f docker-compose.full.yml down -v`.

## Sicurezza

- L'orchestrator espone le porte solo su `127.0.0.1` (loopback host).
- Le password admin non vengono mai persistite (hash SHA-256 + salt random in RAM, valido per la sessione del processo).
- Le sessioni sono in-memory, scadono dopo 4h, ruotate alla scadenza, invalidate al logout.
- `/api/v1/ingest/*` è esposto in chiaro **solo** sulla rete interna Docker — non esporre l'orchestrator su Internet senza reverse-proxy con TLS + auth aggiuntiva.

## Architettura aderente al brief

| Layer del brief | Implementazione AEGIS |
|---|---|
| Perimetro | CrowdSec/Fail2Ban via ingest endpoint + playbook `block_ip` |
| Endpoint | Local agent + Wazuh ingest |
| Rete | Modulo `network` (LAN scan, TLS, topology, fusion) — sostituisce Nmap/Suricata locale |
| Identità | Login admin/password con sessione cookie + opzione API key |
| Dati | Postgres + event store JSONL persistente |
| Intelligence | Modulo `vuln` (NVD + KEV static), `threat_intel` (feeds OTX/MISP), YARA rules incluse |
