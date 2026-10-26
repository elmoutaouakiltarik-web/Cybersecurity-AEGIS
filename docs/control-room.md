# Control Room — accesso e operatività

Guida operativa della dashboard AEGIS: come entrarci, come avviarla su Docker o
su Windows nativo, quali endpoint espone e cosa fare quando qualcosa non
risponde.

## Accesso

| Campo | Valore |
|---|---|
| URL dashboard | http://127.0.0.1:8070/dashboard/ |
| Username | `admin` |
| Password | da `AEGIS_ADMIN_PASSWORD` (se assente, generata e stampata su stderr al primo avvio) |

> La password non viene mai scritta su disco: l'hash resta in memoria per la
> durata del processo. Impostala prima dell'avvio, oppure passala allo script:
>
> ```powershell
> .\aegis-docker.ps1 -AdminPassword "<scegli-una-password-lunga>"
> ```

### Metodi di autenticazione

| Metodo | Quando usarlo |
|---|---|
| **admin + password** | Default. Sessione di 4h via cookie HttpOnly `aegis_sid`. |
| **API key Bearer** | Imposta `AEGIS_API_KEY` nell'ambiente, poi usa "Hai una API key?" nel login. |
| **Modalità locale** | Solo da `127.0.0.1` / `::1`. Crea una sessione reale limitata a localhost, non disattiva la sicurezza. |

In Docker, `AEGIS_AUTH_REQUIRED=true` protegge comunque le API indipendentemente
dal metodo scelto.

## Avvio con Docker

```powershell
# Dal root del progetto
.\aegis-docker.ps1
```

Lo script:

1. verifica che Docker Desktop sia attivo;
2. builda i container del profilo `full` (orchestrator, moduli, Postgres) — 2-4
   minuti la prima volta;
3. avvia lo stack e attende lo stato healthy;
4. esegue lo smoke test su tutti gli endpoint;
5. apre il browser sulla dashboard;
6. stampa le credenziali di sessione.

| Comando | Effetto |
|---|---|
| `.\aegis-docker.ps1 -Industrial` | Aggiunge il modulo OT/ICS |
| `.\aegis-docker.ps1 -Rebuild` | Rebuild completo senza cache |
| `.\aegis-docker.ps1 -Stop` | Arresta lo stack (i volumi restano) |

## Endpoint host-native (consigliato su Windows)

Per collegare AEGIS ai controlli reali del PC — Defender, firewall, BitLocker,
processi, scansione file e secrets:

```powershell
.\aegis-endpoint.ps1 -Admin
```

Il modulo si espone su `http://127.0.0.1:8088`; la dashboard lo raggiunge tramite
il proxy dell'orchestratore (`/api/endpoint/*`), così il browser non parla mai
direttamente con il servizio privilegiato.

## Test end-to-end

```powershell
.\aegis-smoke-test.ps1
```

Verifica login, `/auth/me`, metriche, remediation (CVE / servizio / IOC / TLS),
regole SIEM, ricerca CVE, ingest reale, network discovery, threat-intel lookup e
logout.

## Porte locali

| Servizio | Porta | Health |
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
| Plant Assessment | 8097 | — |
| CyberShield AI | 8919 | http://127.0.0.1:8919/health |
| Postgres | 5432 | — |

## Endpoint API principali

| Verbo | Path | Descrizione |
|---|---|---|
| POST | `/api/v1/auth/login` | `{username,password}` → cookie di sessione |
| POST | `/api/v1/auth/logout` | Invalida la sessione corrente |
| GET | `/api/v1/auth/me` | Stato dell'autenticazione |
| GET | `/api/v1/remediation` | Knowledge base rimedi (`cve`, `service`, `port`, `ioc`, `tls`) |
| GET | `/api/v1/metrics` | KPI della dashboard |
| GET | `/api/v1/events` | Event store (`limit`, `category`, `severity`) |
| GET | `/api/v1/events/live` | Stream SSE |
| POST | `/api/v1/ingest/generic` | Ingest di un evento |
| GET | `/api/v1/siem/rules` | Regole di correlazione SIEM |
| GET | `/api/v1/playbooks` | Playbook SOAR disponibili |

> Non esiste un endpoint di seed demo: la piattaforma lavora solo su dati
> realmente ingeriti tramite `/api/v1/ingest/*`.

## Tool della dashboard

Ogni risultato include un pulsante **Fix** con il rimedio concreto, i
riferimenti e il playbook SOAR consigliato.

| Pagina | Cosa fa | Endpoint | Remediation |
|---|---|---|---|
| Network | LAN discovery, scan TCP, banner grabbing | `/api/scan/*` | per servizio e porta |
| Vulnerabilities | CVE matching da banner + NVD live | `/api/vuln/*`, `/api/v1/vuln/cve-search` | per CVE (KEV-aware) |
| Threat Intel | Lookup IOC IP/dominio | `/api/ti/lookup` | per categoria IOC |
| TLS Inspector | Cipher, certificato, OCSP, HSTS | `/api/tls/inspect` | per issue TLS |
| Topology | Grafo e attack path | `/api/topology*` | gap di segmentazione |
| Threat Fusion | Correlazione multi-modulo | `/api/fusion/*` | kill-chain awareness |
| SIEM | Regole di correlazione | `/api/v1/siem/rules` | livello regola |
| SOAR | Playbook in dry-run | `/api/v1/playbooks`, `/api/v1/soar/trigger` | esecuzione su match |
| OT/ICS | Asset Modbus / DNP3 / OPC UA | `/api/v1/ot/assets` | OT-safe, read-only |
| Reports | Export HTML/JSON | `/api/report` | — |
| ML | CyberShield AI (NSL-KDD) | proxy `/api/v1/proxy/ml/*` | — |

## Troubleshooting

| Sintomo | Rimedio |
|---|---|
| "Docker engine non risponde" | Avvia Docker Desktop e riprova |
| Login rifiutato con password corretta | Controlla il log: `docker compose -f docker-compose.full.yml logs orchestrator \| grep "Auth:"` |
| I tool rispondono "module offline: X" | Un container è giù: `docker compose -f docker-compose.full.yml ps`, poi `logs <nome>` |
| Serve cambiare password | Arresta lo stack, imposta `$env:AEGIS_ADMIN_PASSWORD`, poi `.\aegis-docker.ps1 -Rebuild` |
| Reset completo, database incluso | `docker compose -f docker-compose.full.yml down -v` |

## Sicurezza

- L'orchestrator espone le porte solo su `127.0.0.1` (loopback host).
- Le password admin non vengono persistite: hash SHA-256 con salt casuale in RAM,
  valido per la sessione del processo.
- Le sessioni sono in memoria, scadono dopo 4 ore e vengono invalidate al logout.
- `/api/v1/ingest/*` è raggiungibile in chiaro **solo** sulla rete interna
  Docker. Non esporre l'orchestratore su Internet senza un reverse proxy con TLS
  e autenticazione aggiuntiva.

Per il processo di segnalazione vulnerabilità vedi [SECURITY.md](../SECURITY.md).

## Mappatura funzionale

| Ambito | Implementazione AEGIS |
|---|---|
| Perimetro | Ingest CrowdSec / Fail2Ban + playbook `block_ip` |
| Endpoint | Modulo endpoint host-native + ingest Wazuh |
| Rete | Modulo `network`: LAN scan, TLS, topology, fusion |
| Identità | Login admin con sessione cookie, oppure API key Bearer |
| Dati | PostgreSQL + event store JSONL persistente |
| Intelligence | Moduli `vuln` (NVD + KEV), `threat_intel` (OTX/MISP), regole YARA incluse |
| Conformità | Modulo `compliance`: GDPR, NIS2, prontezza OT |
