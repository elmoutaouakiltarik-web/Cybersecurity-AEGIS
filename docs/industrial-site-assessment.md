# Assessment di sicurezza di un impianto industriale

Guida operativa per usare AEGIS su una rete di fabbrica senza fermare la
produzione. Copre il flusso completo: autorizzazione, cattura passiva,
scansione read-only, fingerprint dei protocolli industriali, valutazione del
rischio, report e baseline.

> **In una frase:** prima si ascolta (passivo), poi si identifica (read-only),
> mai si scrive sul processo. Il report separa cio' che si puo' correggere
> subito da cio' che richiede una fermata.

---

## 1. Cosa fa e cosa non fa

| Fa | Non fa |
|---|---|
| Inventario asset con MAC, IP, hostname, vendor, modello, firmware quando disponibile | Non sfrutta vulnerabilita' (nessun exploit, nessuna password brute force) |
| Riconosce 15+ protocolli industriali anche su porte non standard | Non invia comandi di scrittura (blocco a livello di codice) |
| Rileva comandi di scrittura osservati (Modbus FC5/6/15/16, S7 Write, DNP3 Operate, IEC104, BACnet, PROFINET DCP Set) | Non modifica configurazioni, non installa agenti |
| Mappa le zone Purdue e i flussi est-ovest | Non sostituisce un vulnerability assessment contrattuale completo |
| Verifica servizi IT rischiosi in zona OT (Telnet, SMBv1, RDP, VNC) | Non testa applicazioni SCADA/MES a livello di codice |
| Produce report HTML/Markdown/JSON con piano di remediation in 3 fasi | Non e' un IDS continuo: e' un assessment puntuale (o periodico) |

L'assenza di finding **non** dimostra l'assenza di vulnerabilita'. Il report
dichiara sempre copertura e limiti.

---

## 2. Perche' e' sicuro su un impianto in produzione

Cinque livelli di protezione, tutti verificabili nel codice
(`modules/industrial/site_assessment/safety.py`):

1. **Autorizzazione obbligatoria.** Senza `--auth-ref` e una finestra valida
   nulla parte. Il riferimento deve essere scritto (ordine di lavoro, email
   del responsabile di stabilimento, contratto).
2. **Scope chiuso.** Solo gli IP/CIDR dichiarati. Indirizzi pubblici rifiutati
   per default. Esclusioni supportate (es. il PLC della linea critica).
3. **Passivo prima di attivo.** In `--mode passive` non viene inviato un solo
   pacchetto: si analizza un pcap o si ascolta un'interfaccia in mirror.
4. **Read-only sui protocolli di processo.** Ogni funzione di scrittura e'
   in blacklist (`DANGEROUS_OPERATIONS`) e viene bloccata prima dell'invio,
   con registrazione nel log di audit. Le sonde usate sono solo:
   Modbus FC43/MEI 14 (Read Device ID), S7 Read SZL, EtherNet/IP ListIdentity,
   BACnet Who-Is/ReadProperty, SNMP GET, OPC UA Hello.
   DNP3, IEC 104, PROFINET I/O, EtherCAT e CIP implicito **non** vengono
   interrogati: solo osservati.
5. **Ritmo controllato.** Rate limiter globale e per host (`--max-pps`,
   intervallo minimo per device): un PLC degli anni 2000 non viene saturato.

Ogni azione finisce in `data/site_assessment/audit.jsonl` con timestamp,
scope e riferimento di autorizzazione.

---

## 3. Prima di collegarsi

- [ ] Autorizzazione scritta e referente tecnico dell'impianto presenti.
- [ ] Finestra concordata (anche per il solo passivo: un mirror port va
      configurato da chi gestisce gli switch).
- [ ] Etichette delle linee e degli interblocchi note: sapere cosa non va
      toccato.
- [ ] Backup delle configurazioni di switch/firewall prima di qualunque
      modifica successiva al report.
- [ ] Contatto del fornitore OEM se il PLC e' ancora in garanzia.

**Non serve** essere root per analizzare un pcap. Serve per la cattura live su
Linux (o Npcap + privilegi su Windows).

---

## 4. Procedura passo-passo

### 4.1 Preflight

```powershell
cd modules\industrial
python -m site_assessment preflight
```

Verifica scapy, privilegi, interfacce IPv4, profili porte e data dir.
Da Windows si puo' usare anche lo wrapper:

```powershell
.\aegis-assess.ps1 preflight
```

### 4.2 Cattura passiva (la modalita' piu' sicura)

**Opzione A — Wireshark su porta in mirror (consigliata).**
Chiedere al network manager uno SPAN/mirror della VLAN di controllo, catturare
5–15 minuti di traffico rappresentativo (incluso un cambio turno), salvare in
`pcapng`.

Filtro di cattura utile:

```
ip or arp or (ether proto 0x88cc) or (ether proto 0x8892)
```

**Opzione B — cattura diretta** (interfaccia dedicata collegata al mirror):

```powershell
python -m site_assessment assess `
  --site "Linea 2" --client "ACME S.p.A." --operator "M. Rossi" `
  --auth-ref "WO-2026-014" --mode passive `
  --target 192.168.10.0/24 --iface "Ethernet 2" --duration 300 `
  --out reports\linea2
```

**Opzione C — analisi di un pcap gia' catturato:**

```powershell
python -m site_assessment assess `
  --site "Linea 2" --auth-ref "WO-2026-014" --mode passive `
  --target 192.168.10.0/24 --pcap C:\capture\linea2.pcapng `
  --out reports\linea2
```

### 4.3 Scansione read-only (quando serve confermare i servizi)

```powershell
python -m site_assessment assess `
  --site "Linea 2" --auth-ref "WO-2026-014" --mode readonly `
  --target 192.168.10.0/24 --profile ot `
  --pcap C:\capture\linea2.pcapng `
  --baseline data\site_assessment\linea2-baseline.json `
  --save-baseline data\site_assessment\linea2-baseline.json `
  --out reports\linea2
```

- `--profile ot` scansiona 502, 102, 2404, 20000, 44818, 47808, 4840, 2222,
  9600, 5006/5007, 2455, 1911, 789, 5094 + servizi di management.
- `--profile common` aggiunge le porte IT piu' diffuse.
- `--exclude 192.168.10.5` esclude il PLC critico dalla scansione.
- Se un device e' fragile, usare `--mode passive` o alzare
  `--max-hosts`/abbassare `--max-pps` (default 200 pps).

### 4.4 Baseline e monitoraggio nel tempo

```powershell
# salva lo stato "noto buono"
python -m site_assessment baseline save --result reports\linea2\assessment-*.json --out baseline-linea2.json

# dopo un mese: confronto
python -m site_assessment assess ... --baseline baseline-linea2.json --out reports\linea2-mese2
```

Il report evidenzia device nuovi, porte comparse, firmware cambiati. E' il modo
piu' economico per accorgersi di un device intruso o di un servizio attivato
da remoto.

### 4.5 API e dashboard

Con lo stack avviato (`start-aegis.ps1` o `docker compose`), il modulo risponde
su `:8097` ed e' proxato dalla dashboard:

- Dashboard → **Plant Assessment**
- Analisi rapida di un pcap dal browser (upload, nessun pacchetto inviato)
- API diretta: `http://127.0.0.1:8097/health`

Endpoint principali: `/preflight`, `/analyze-pcap`, `/assess`,
`/assess/<id>`, `/assess/<id>/result`, `/assess/<id>/report?format=html`.

### 4.6 Verifica dell'installazione

```powershell
python -m site_assessment selftest --out reports\site-assessment-demo
```

Genera traffico sintetico (PLC Siemens, RTU DNP3, HMI, BACnet, PROFINET,
scritture sospette, ARP spoofing, egress Internet) e verifica che dissector,
regole e report funzionino. Non tocca la rete.

---

## 5. Come leggere il report

### Punteggio 0-100

Pesa gravita' e confidenza dei finding sul numero di asset.
`>=85` buono, `70-84` discreto, `50-69` critico, `<50` grave.
Il punteggio serve a confrontare lo stesso sito nel tempo, non siti diversi.

### `production_safe`

- **true** → l'azione si puo' fare durante l'esercizio (es. bloccare l'egress
  a firewall, abilitare il logging, completare il censimento).
- **false** → richiede finestra di manutenzione (segmentazione, patch,
  disabilitazione di servizi, modifica configurazioni PLC/switch).

Questa distinzione e' il motivo per cui il report e' utilizzabile in fabbrica:
un direttore di stabilimento non accetta "chiudiamo tutto".

### Severita'

| Livello | Significato pratico |
|---|---|
| Critico | percorso diretto verso il processo o evidenza di comando anomalo: agire subito |
| Alto | esposizione strutturale (protocollo OT senza autenticazione, rete piatta, servizi IT in OT) |
| Medio | debolezza di configurazione o igiene (HTTP in chiaro, SNMP default, firmware ignoto) |
| Basso | incompletezza informativa (asset non identificati) |

### Riferimenti normativi

Ogni finding riporta la tecnica **MITRE ATT&CK for ICS** e il requisito
**IEC 62443-3-3** (SR) applicabile. Utile per audit NIS2 e per giustificare il
budget di remediation.

---

## 6. Se il report mostra comandi di scrittura anomali

Un `ot_write_command` osservato sul traffico e' il segnale piu' diretto di
manipolazione. Procedura consigliata:

1. **Non spegnere nulla.** Un PLC spento puo' lasciare attuatori in posizione
   non sicura.
2. Identificare sorgente (IP/MAC) e correlare con i log SCADA e il turno.
3. Verificare lo stato fisico del processo con l'operatore di linea.
4. Se la sorgente non e' autorizzata: isolare la **porta di rete**, non il
   device; acquisire una copia del traffico con `tcpdump`/Wireshark.
5. Conservare evidenze (pcap, log, screenshot) con hash: usare il modulo
   Evidence.
6. Solo dopo: contenimento dell'host, analisi DFIR, ripristino.

Un `ot_internet_egress` da un asset di processo va trattato come possibile
compromissione: bloccare l'uscita a firewall e' di norma non invasivo.

---

## 7. Piano di remediation tipo

**Fase 0 — 0-7 giorni (nessuna fermata)**
- Bloccare egress Internet dagli asset OT.
- Abilitare mirror/SPAN + IDS OT passivo sulle VLAN di controllo.
- Abilitare il logging dei comandi di scrittura e degli accessi alle HMI.
- Cambiare le password di default di HMI/switch esposti.
- Completare l'inventario (targhette, commesse, vendor).

**Fase 1 — 30 giorni (finestre brevi)**
- ACL di sola lettura dove il processo lo consente.
- Disabilitare Telnet/FTP/SMBv1 su HMI e server di supervisione.
- SNMPv3 o community dedicate con ACL.
- Autenticazione sulle HMI web; TLS dove supportato.
- Baseline e primo confronto.

**Fase 2 — 90 giorni (fermata programmata)**
- Segmentazione VLAN + firewall industriale con ispezione dei protocolli OT.
- Zona di engineering con jump host e accesso temporaneo.
- Patch firmware/OS con piano di rollback e test in banco.
- Procedura di change management OT e test di ripristino.

---

## 8. Limiti e responsabilita'

- Un assessment non e' una certificazione. Per IEC 62443 serve un audit
  formale con evidenze documentali.
- Il traffico catturato contiene dati di processo: trattarlo come riservato,
  conservarlo cifrato e cancellarlo secondo la policy del cliente.
- Scansionare reti senza autorizzazione e' reato (art. 615-ter c.p. in Italia;
  NIS2 e contratti di fornitura aggiungono obblighi di notifica). Il modulo
  rifiuta di partire senza riferimento scritto, ma la responsabilita' resta
  dell'operatore.
- I protocolli OT non hanno autenticazione: la sicurezza si ottiene con
  segmentazione, monitoraggio e procedure, non con una patch.

---

## 9. Riferimenti

- NIST SP 800-82 Rev.3 — Guide to Operational Technology Security
- IEC 62443-3-3 — System security requirements and security levels
- ISA/IEC 62443-3-2 — Security risk assessment and zone/conduit design
- MITRE ATT&CK for ICS
- CISA — Recommended Practice: Improving Industrial Control System Cybersecurity
