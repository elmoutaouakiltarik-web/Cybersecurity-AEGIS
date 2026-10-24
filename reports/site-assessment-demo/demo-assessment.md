# Assessment di sicurezza industriale — Stabilimento demo — Linea 2

| Campo | Valore |
|---|---|
| Cliente | Demo Industria S.p.A. |
| Sito / impianto | Stabilimento demo — Linea 2 |
| Operatore | self-test |
| Riferimento autorizzazione | SELFTEST-LOCAL-ONLY |
| Modalita' | Passivo — nessun pacchetto inviato alla rete dell'impianto |
| Inizio | 2026-10-21T21:43:29+00:00 |
| Fine | 2026-10-21T21:43:29+00:00 |
| Durata | 0 s |
| Punteggio postura | **0/100** (grave) |
| ID assessment | `selftest` |

## Sintesi esecutiva

- 11 asset osservati (6 classificati OT), 13 critici, 5 alti, 1 medi, 1 bassi.
- **[Critico] Comando di scrittura OT osservato sul traffico** su 10.10.0.30 (rtu) — Un comando di scrittura puo' essere legittimo (operatore, SCADA) o malevolo (malware, insider, tool di test). Va attribuito: chi lo ha inviato, da quale postazione, in quale finestra temporale. E' il segnale piu' diretto di manipolazione del processo.
- **[Critico] Comando di scrittura OT osservato sul traffico** su 10.10.0.40 — Un comando di scrittura puo' essere legittimo (operatore, SCADA) o malevolo (malware, insider, tool di test). Va attribuito: chi lo ha inviato, da quale postazione, in quale finestra temporale. E' il segnale piu' diretto di manipolazione del processo.
- **[Critico] Comando di scrittura OT osservato sul traffico** su 10.10.0.5 (Siemens) — Un comando di scrittura puo' essere legittimo (operatore, SCADA) o malevolo (malware, insider, tool di test). Va attribuito: chi lo ha inviato, da quale postazione, in quale finestra temporale. E' il segnale piu' diretto di manipolazione del processo.
- **5 comandi di scrittura OT osservati nel traffico**: e' l'indicatore piu' diretto di un comando malevolo o di un HMI/configurazione errata. Verificare immediatamente chi li ha generati.
- Punteggio di postura **0/100**: grave. Il punteggio pesa gravita' e confidenza delle findings sul numero di asset.

## Cosa fare subito (senza fermare la produzione)

Azioni a basso impatto, applicabili durante l'esercizio. Verificare comunque con il responsabile di produzione prima di modificare configurazioni su apparati attivi.

- **[Critico] Comando di scrittura OT osservato sul traffico** (10.10.0.30 (rtu), score 9.9) — Correlare con il turno di produzione e i log del SCADA. Se non attribuibile: isolare la sorgente, acquisire evidenze, verificare lo stato fisico degli attuatori. Implementare allow-list degli host autorizzati a scrivere (firewall industriale con deep packet inspection). — rif. IEC 62443-3-3 SR 3.1, SR 6.1
- **[Critico] Comando di scrittura OT osservato sul traffico** (10.10.0.40, score 9.9) — Correlare con il turno di produzione e i log del SCADA. Se non attribuibile: isolare la sorgente, acquisire evidenze, verificare lo stato fisico degli attuatori. Implementare allow-list degli host autorizzati a scrivere (firewall industriale con deep packet inspection). — rif. IEC 62443-3-3 SR 3.1, SR 6.1
- **[Critico] Comando di scrittura OT osservato sul traffico** (10.10.0.5 (Siemens), score 9.9) — Correlare con il turno di produzione e i log del SCADA. Se non attribuibile: isolare la sorgente, acquisire evidenze, verificare lo stato fisico degli attuatori. Implementare allow-list degli host autorizzati a scrivere (firewall industriale con deep packet inspection). — rif. IEC 62443-3-3 SR 3.1, SR 6.1
- **[Critico] Comando di scrittura OT osservato sul traffico** (10.10.0.60, score 9.9) — Correlare con il turno di produzione e i log del SCADA. Se non attribuibile: isolare la sorgente, acquisire evidenze, verificare lo stato fisico degli attuatori. Implementare allow-list degli host autorizzati a scrivere (firewall industriale con deep packet inspection). — rif. IEC 62443-3-3 SR 3.1, SR 6.1
- **[Critico] Asset industriale con traffico verso Internet** (10.10.0.5 (Siemens), score 9.7) — Bloccare subito l'egress a firewall (azione normalmente non invasiva), identificare il processo che genera il traffico, acquisire memoria/rete dell'host prima di spegnerlo, poi analisi DFIR. — rif. IEC 62443-3-3 SR 5.1, SR 5.2
- **[Medio] Percentuale elevata di broadcast/multicast** (—, score 4.8) — Verificare STP, loop e device che generano broadcast; abilitare storm control sulle porte di accesso. — rif. IEC 62443-3-3 SR 7.1
- **[Basso] Asset OT non identificati (censimento incompleto)** (—, score 3.4) — Completare il censimento con il registro asset di impianto, foto targhette e documentazione di commessa; ripetere poi l'assessment per arricchire le identita'. — rif. IEC 62443-2-1, SR 7.8

## Cosa pianificare in fermata

Interventi che possono interrompere la comunicazione o richiedere il riavvio di un apparato: vanno pianificati in una finestra di manutenzione concordata.

- **[Critico] Modbus/TCP esposto senza autenticazione** (10.10.0.10 (Dell), score 9.1) — 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **[Critico] DNP3 esposto senza autenticazione** (10.10.0.30 (rtu), score 9.1) — 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **[Critico] BACnet/IP esposto senza autenticazione** (10.10.0.40, score 9.1) — 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **[Critico] Modbus/TCP esposto senza autenticazione** (10.10.0.5 (Siemens), score 9.1) — 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **[Critico] IEC 60870-5-104 esposto senza autenticazione** (10.10.0.60, score 9.1) — 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **[Critico] EtherNet/IP (CIP) esposto senza autenticazione** (10.10.0.80 (plc), score 9.1) — 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **[Critico] Conflitto ARP / possibile man-in-the-middle** (10.10.0.1, score 9.0) — Identificare i due MAC sulle tabelle dei switch, correggere l'IP duplicato o isolare la porta. Abilitare DHCP snooping e Dynamic ARP Inspection dove possibile.
- **[Critico] Servizi IT ad alto rischio in zona di processo** (10.10.0.20 (Dell), score 8.8) — Disabilitare i servizi non necessari (prima su un asset pilota, in finestra di manutenzione), sostituire Telnet/FTP con SSH/SFTP, applicare SMB signing e disabilitare SMBv1, limitare RDP a un jump host.
- **[Alto] Rete piatta: asset IT e OT nella stessa sottorete** (10.10.0.1, score 8.3) — Definire zone e conduit (IEC 62443-3-2), creare VLAN separate per controllo, supervisione e office, applicare un firewall industriale. Intervento da pianificare: richiede mappa aggiornata e finestra.
- **[Alto] Flusso di controllo tra zone Purdue diverse** (10.10.0.30 (rtu), score 7.9) — Documentare o rimuovere il flusso. Se serve, creare un conduit esplicito con firewall industriale e ispezione del protocollo.
- **[Alto] Flusso di controllo tra zone Purdue diverse** (10.10.0.40, score 7.9) — Documentare o rimuovere il flusso. Se serve, creare un conduit esplicito con firewall industriale e ispezione del protocollo.
- **[Alto] Flusso di controllo tra zone Purdue diverse** (10.10.0.5 (Siemens), score 7.9) — Documentare o rimuovere il flusso. Se serve, creare un conduit esplicito con firewall industriale e ispezione del protocollo.
- **[Alto] Flusso di controllo tra zone Purdue diverse** (10.10.0.60, score 7.9) — Documentare o rimuovere il flusso. Se serve, creare un conduit esplicito con firewall industriale e ispezione del protocollo.

## Inventario asset

| IP | MAC | Nome | Vendor | Tipo | Zona | Purdue | Protocolli | Porte | Rischio |
|---|---|---|---|---|---|---|---|---|---|
| 10.10.0.1 | 02:00:00:00:00:66 | — | — | unknown | Controllo Linea 2 | 1 | — | — | 100 |
| 10.10.0.10 | 00:11:43:00:00:01 | — | Dell | plc | Controllo Linea 2 | 1 | modbus, enip | — | 100 |
| 10.10.0.2 | 00:80:63:aa:bb:cc | SW-LINEA-2 | Hirschmann | switch | Controllo Linea 2 | 1 | — | — | 0 |
| 10.10.0.20 | 00:11:43:00:00:50 | — | Dell | opcua-server | Controllo Linea 2 | 1 | opcua, smb | 445/smb | 100 |
| 10.10.0.30 | — | — | — | rtu | Controllo Linea 2 | 1 | dnp3 | — | 100 |
| 10.10.0.40 | — | — | — | unknown | Controllo Linea 2 | 1 | bacnet | — | 100 |
| 10.10.0.5 | 00:0e:8c:11:22:33 | — | Siemens | plc | Controllo Linea 2 | 1 | modbus, s7comm | — | 100 |
| 10.10.0.60 | — | — | — | unknown | Controllo Linea 2 | 1 | iec104 | — | 100 |
| 10.10.0.70 | — | — | — | opcua-server | Controllo Linea 2 | 1 | opcua | — | 0 |
| 10.10.0.80 | — | — | — | plc | Controllo Linea 2 | 1 | enip | — | 100 |
| 10.10.0.130 | 00:11:43:00:00:50 | — | Dell | plc | Office | 3 | modbus, s7comm, dnp3, bacnet, iec104, smb | — | 0 |

## Risultati dettagliati

### [Critico] Comando di scrittura OT osservato sul traffico

- **Score:** 9.9/10 · **Categoria:** malware · **Confidenza:** high
- **Asset:** 10.10.0.30 (rtu)
- **Etichetta asset:** 10.10.0.30
- **Evidenza:** function=0x05; 10.10.0.130 -> 10.10.0.30
- **Perche' conta:** Un comando di scrittura puo' essere legittimo (operatore, SCADA) o malevolo (malware, insider, tool di test). Va attribuito: chi lo ha inviato, da quale postazione, in quale finestra temporale. E' il segnale piu' diretto di manipolazione del processo.
- **Remediation:** Correlare con il turno di produzione e i log del SCADA. Se non attribuibile: isolare la sorgente, acquisire evidenze, verificare lo stato fisico degli attuatori. Implementare allow-list degli host autorizzati a scrivere (firewall industriale con deep packet inspection).
- **Applicabile in produzione:** si
- **MITRE ATT&CK for ICS:** T0855 (Unauthorized Command Message) / T0836 (Modify Parameter)
- **IEC 62443:** IEC 62443-3-3 SR 3.1, SR 6.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements

### [Critico] Comando di scrittura OT osservato sul traffico

- **Score:** 9.9/10 · **Categoria:** malware · **Confidenza:** high
- **Asset:** 10.10.0.40
- **Etichetta asset:** 10.10.0.40
- **Evidenza:** service=15; 10.10.0.130 -> 10.10.0.40
- **Perche' conta:** Un comando di scrittura puo' essere legittimo (operatore, SCADA) o malevolo (malware, insider, tool di test). Va attribuito: chi lo ha inviato, da quale postazione, in quale finestra temporale. E' il segnale piu' diretto di manipolazione del processo.
- **Remediation:** Correlare con il turno di produzione e i log del SCADA. Se non attribuibile: isolare la sorgente, acquisire evidenze, verificare lo stato fisico degli attuatori. Implementare allow-list degli host autorizzati a scrivere (firewall industriale con deep packet inspection).
- **Applicabile in produzione:** si
- **MITRE ATT&CK for ICS:** T0855 (Unauthorized Command Message) / T0836 (Modify Parameter)
- **IEC 62443:** IEC 62443-3-3 SR 3.1, SR 6.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements

### [Critico] Comando di scrittura OT osservato sul traffico

- **Score:** 9.9/10 · **Categoria:** malware · **Confidenza:** high
- **Asset:** 10.10.0.5 (Siemens)
- **Etichetta asset:** 10.10.0.5
- **Evidenza:** fc=6 unit=1 addr=10 qty=None; 10.10.0.130 -> 10.10.0.5
- **Perche' conta:** Un comando di scrittura puo' essere legittimo (operatore, SCADA) o malevolo (malware, insider, tool di test). Va attribuito: chi lo ha inviato, da quale postazione, in quale finestra temporale. E' il segnale piu' diretto di manipolazione del processo.
- **Remediation:** Correlare con il turno di produzione e i log del SCADA. Se non attribuibile: isolare la sorgente, acquisire evidenze, verificare lo stato fisico degli attuatori. Implementare allow-list degli host autorizzati a scrivere (firewall industriale con deep packet inspection).
- **Applicabile in produzione:** si
- **MITRE ATT&CK for ICS:** T0855 (Unauthorized Command Message) / T0836 (Modify Parameter)
- **IEC 62443:** IEC 62443-3-3 SR 3.1, SR 6.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements

### [Critico] Comando di scrittura OT osservato sul traffico

- **Score:** 9.9/10 · **Categoria:** malware · **Confidenza:** high
- **Asset:** 10.10.0.60
- **Etichetta asset:** 10.10.0.60
- **Evidenza:** type_id=45 cot=3; 10.10.0.130 -> 10.10.0.60
- **Perche' conta:** Un comando di scrittura puo' essere legittimo (operatore, SCADA) o malevolo (malware, insider, tool di test). Va attribuito: chi lo ha inviato, da quale postazione, in quale finestra temporale. E' il segnale piu' diretto di manipolazione del processo.
- **Remediation:** Correlare con il turno di produzione e i log del SCADA. Se non attribuibile: isolare la sorgente, acquisire evidenze, verificare lo stato fisico degli attuatori. Implementare allow-list degli host autorizzati a scrivere (firewall industriale con deep packet inspection).
- **Applicabile in produzione:** si
- **MITRE ATT&CK for ICS:** T0855 (Unauthorized Command Message) / T0836 (Modify Parameter)
- **IEC 62443:** IEC 62443-3-3 SR 3.1, SR 6.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements

### [Critico] Asset industriale con traffico verso Internet

- **Score:** 9.7/10 · **Categoria:** malware · **Confidenza:** medium
- **Asset:** 10.10.0.5 (Siemens)
- **Etichetta asset:** 10.10.0.5
- **Evidenza:** proto=https dport=443
- **Perche' conta:** Nessun PLC/HMI deve avere egress diretto. Questo pattern e' compatibile con C2 di malware, esfiltrazione di dati di processo o un doppio NIC che bypassa la segmentazione.
- **Remediation:** Bloccare subito l'egress a firewall (azione normalmente non invasiva), identificare il processo che genera il traffico, acquisire memoria/rete dell'host prima di spegnerlo, poi analisi DFIR.
- **Applicabile in produzione:** si
- **MITRE ATT&CK for ICS:** T0885 (Commonly Used Port) / T1041 (Exfiltration Over C2 Channel)
- **IEC 62443:** IEC 62443-3-3 SR 5.1, SR 5.2
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security

### [Critico] Modbus/TCP esposto senza autenticazione

- **Score:** 9.1/10 · **Categoria:** exposure · **Confidenza:** medium
- **Asset:** 10.10.0.10 (Dell)
- **Etichetta asset:** Dell
- **Evidenza:** protocol=modbus; porte/contesto=da traffico passivo; zona=Controllo Linea 2
- **Perche' conta:** Modbus/TCP non prevede autenticazione ne' cifratura: chiunque raggiunga l'asset puo' leggere e spesso scrivere variabili di processo. Un errore di configurazione o un host infetto nella stessa VLAN diventa un comando diretto sull'impianto.
- **Remediation:** 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0836 (Modify Parameter) / T0855 (Unauthorized Command Message)
- **IEC 62443:** IEC 62443-3-3 SR 1.1, SR 3.1, SR 5.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements, ISA/IEC 62443-3-2 — Zone and conduit partitioning

### [Critico] DNP3 esposto senza autenticazione

- **Score:** 9.1/10 · **Categoria:** exposure · **Confidenza:** medium
- **Asset:** 10.10.0.30 (rtu)
- **Etichetta asset:** 10.10.0.30
- **Evidenza:** protocol=dnp3; porte/contesto=da traffico passivo; zona=Controllo Linea 2
- **Perche' conta:** DNP3 non prevede autenticazione ne' cifratura: chiunque raggiunga l'asset puo' leggere e spesso scrivere variabili di processo. Un errore di configurazione o un host infetto nella stessa VLAN diventa un comando diretto sull'impianto.
- **Remediation:** 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0836 (Modify Parameter) / T0855 (Unauthorized Command Message)
- **IEC 62443:** IEC 62443-3-3 SR 1.1, SR 3.1, SR 5.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements, ISA/IEC 62443-3-2 — Zone and conduit partitioning

### [Critico] BACnet/IP esposto senza autenticazione

- **Score:** 9.1/10 · **Categoria:** exposure · **Confidenza:** medium
- **Asset:** 10.10.0.40
- **Etichetta asset:** 10.10.0.40
- **Evidenza:** protocol=bacnet; porte/contesto=da traffico passivo; zona=Controllo Linea 2
- **Perche' conta:** BACnet/IP non prevede autenticazione ne' cifratura: chiunque raggiunga l'asset puo' leggere e spesso scrivere variabili di processo. Un errore di configurazione o un host infetto nella stessa VLAN diventa un comando diretto sull'impianto.
- **Remediation:** 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0836 (Modify Parameter) / T0855 (Unauthorized Command Message)
- **IEC 62443:** IEC 62443-3-3 SR 1.1, SR 3.1, SR 5.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements, ISA/IEC 62443-3-2 — Zone and conduit partitioning

### [Critico] Modbus/TCP esposto senza autenticazione

- **Score:** 9.1/10 · **Categoria:** exposure · **Confidenza:** medium
- **Asset:** 10.10.0.5 (Siemens)
- **Etichetta asset:** Siemens
- **Evidenza:** protocol=modbus; porte/contesto=da traffico passivo; zona=Controllo Linea 2
- **Perche' conta:** Modbus/TCP non prevede autenticazione ne' cifratura: chiunque raggiunga l'asset puo' leggere e spesso scrivere variabili di processo. Un errore di configurazione o un host infetto nella stessa VLAN diventa un comando diretto sull'impianto.
- **Remediation:** 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0836 (Modify Parameter) / T0855 (Unauthorized Command Message)
- **IEC 62443:** IEC 62443-3-3 SR 1.1, SR 3.1, SR 5.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements, ISA/IEC 62443-3-2 — Zone and conduit partitioning

### [Critico] IEC 60870-5-104 esposto senza autenticazione

- **Score:** 9.1/10 · **Categoria:** exposure · **Confidenza:** medium
- **Asset:** 10.10.0.60
- **Etichetta asset:** 10.10.0.60
- **Evidenza:** protocol=iec104; porte/contesto=da traffico passivo; zona=Controllo Linea 2
- **Perche' conta:** IEC 60870-5-104 non prevede autenticazione ne' cifratura: chiunque raggiunga l'asset puo' leggere e spesso scrivere variabili di processo. Un errore di configurazione o un host infetto nella stessa VLAN diventa un comando diretto sull'impianto.
- **Remediation:** 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0836 (Modify Parameter) / T0855 (Unauthorized Command Message)
- **IEC 62443:** IEC 62443-3-3 SR 1.1, SR 3.1, SR 5.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements, ISA/IEC 62443-3-2 — Zone and conduit partitioning

### [Critico] EtherNet/IP (CIP) esposto senza autenticazione

- **Score:** 9.1/10 · **Categoria:** exposure · **Confidenza:** medium
- **Asset:** 10.10.0.80 (plc)
- **Etichetta asset:** 10.10.0.80
- **Evidenza:** protocol=enip; porte/contesto=da traffico passivo; zona=Controllo Linea 2
- **Perche' conta:** EtherNet/IP (CIP) non prevede autenticazione ne' cifratura: chiunque raggiunga l'asset puo' leggere e spesso scrivere variabili di processo. Un errore di configurazione o un host infetto nella stessa VLAN diventa un comando diretto sull'impianto.
- **Remediation:** 1) Mappare i conduit necessari (chi deve parlare con questo asset). 2) Applicare ACL/firewall industriale con default-deny tra IT e OT. 3) Mettere un IDS OT passivo su SPAN/mirror per rilevare comandi anomali. 4) Se il PLC lo supporta, abilitare le protezioni di accesso (password di protezione, disable PUT/GET) come da manuale del costruttore.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0836 (Modify Parameter) / T0855 (Unauthorized Command Message)
- **IEC 62443:** IEC 62443-3-3 SR 1.1, SR 3.1, SR 5.1
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements, ISA/IEC 62443-3-2 — Zone and conduit partitioning

### [Critico] Conflitto ARP / possibile man-in-the-middle

- **Score:** 9.0/10 · **Categoria:** network-integrity · **Confidenza:** medium
- **Asset:** 10.10.0.1
- **Etichetta asset:** 10.10.0.1
- **Evidenza:** mac_dominante=02:00:00:00:00:66; altri=00:80:63:aa:bb:cc
- **Perche' conta:** Due MAC per lo stesso IP possono essere un IP duplicato (errore di configurazione) o un ARP spoofing: in entrambi i casi il traffico di processo puo' finire all'host sbagliato.
- **Remediation:** Identificare i due MAC sulle tabelle dei switch, correggere l'IP duplicato o isolare la porta. Abilitare DHCP snooping e Dynamic ARP Inspection dove possibile.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0830 (Adversary-in-the-Middle)
- **IEC 62443:** IEC 62443-3-3 SR 3.1
- **Riferimenti:** IEC 62443-3-3 — System security requirements

### [Critico] Servizi IT ad alto rischio in zona di processo

- **Score:** 8.8/10 · **Categoria:** hardening · **Confidenza:** high
- **Asset:** 10.10.0.20 (Dell)
- **Etichetta asset:** Dell
- **Evidenza:** servizi esposti: SMB:445
- **Perche' conta:** Telnet, FTP e SMB trasmettono credenziali in chiaro e sono i vettori principali di ransomware che poi si propaga ai PLC. Un HMI Windows infetto puo' fermare la linea anche se il PLC e' sano.
- **Remediation:** Disabilitare i servizi non necessari (prima su un asset pilota, in finestra di manutenzione), sostituire Telnet/FTP con SSH/SFTP, applicare SMB signing e disabilitare SMBv1, limitare RDP a un jump host.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T1021 (Remote Services) / T1210 (Exploitation of Remote Services)
- **IEC 62443:** IEC 62443-3-3 SR 1.5, SR 4.1, SR 7.6
- **Riferimenti:** NIST SP 800-82 Rev.3 — Guide to OT Security, IEC 62443-3-3 — System security requirements

### [Alto] Rete piatta: asset IT e OT nella stessa sottorete

- **Score:** 8.3/10 · **Categoria:** segmentation · **Confidenza:** high
- **Asset:** 10.10.0.1
- **Etichetta asset:** 10.10.0.1
- **Evidenza:** 10.10.0.0/24: 11 asset, ruoli Purdue [1, 3]
- **Perche' conta:** Senza separazione, un PC office compromesso puo' parlare direttamente con PLC e HMI. E' la condizione che trasforma un incidente IT in un fermo di produzione.
- **Remediation:** Definire zone e conduit (IEC 62443-3-2), creare VLAN separate per controllo, supervisione e office, applicare un firewall industriale. Intervento da pianificare: richiede mappa aggiornata e finestra.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0886 (Remote Services)
- **IEC 62443:** IEC 62443-3-3 SR 5.1, SR 5.2
- **Riferimenti:** ISA/IEC 62443-3-2 — Zone and conduit partitioning

### [Alto] Flusso di controllo tra zone Purdue diverse

- **Score:** 7.9/10 · **Categoria:** segmentation · **Confidenza:** high
- **Asset:** 10.10.0.30 (rtu)
- **Etichetta asset:** 10.10.0.30
- **Evidenza:** purdue 3->1
- **Perche' conta:** Un flusso che attraversa il confine IT/OT senza un conduit dichiarato annulla la segmentazione: un ransomware nella rete office puo' raggiungere il campo.
- **Remediation:** Documentare o rimuovere il flusso. Se serve, creare un conduit esplicito con firewall industriale e ispezione del protocollo.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0886 (Remote Services)
- **IEC 62443:** IEC 62443-3-3 SR 5.1, SR 5.2
- **Riferimenti:** ISA/IEC 62443-3-2 — Zone and conduit partitioning, IEC 62443-3-3 — System security requirements

### [Alto] Flusso di controllo tra zone Purdue diverse

- **Score:** 7.9/10 · **Categoria:** segmentation · **Confidenza:** high
- **Asset:** 10.10.0.40
- **Etichetta asset:** 10.10.0.40
- **Evidenza:** purdue 3->1
- **Perche' conta:** Un flusso che attraversa il confine IT/OT senza un conduit dichiarato annulla la segmentazione: un ransomware nella rete office puo' raggiungere il campo.
- **Remediation:** Documentare o rimuovere il flusso. Se serve, creare un conduit esplicito con firewall industriale e ispezione del protocollo.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0886 (Remote Services)
- **IEC 62443:** IEC 62443-3-3 SR 5.1, SR 5.2
- **Riferimenti:** ISA/IEC 62443-3-2 — Zone and conduit partitioning, IEC 62443-3-3 — System security requirements

### [Alto] Flusso di controllo tra zone Purdue diverse

- **Score:** 7.9/10 · **Categoria:** segmentation · **Confidenza:** high
- **Asset:** 10.10.0.5 (Siemens)
- **Etichetta asset:** Siemens
- **Evidenza:** purdue 3->1
- **Perche' conta:** Un flusso che attraversa il confine IT/OT senza un conduit dichiarato annulla la segmentazione: un ransomware nella rete office puo' raggiungere il campo.
- **Remediation:** Documentare o rimuovere il flusso. Se serve, creare un conduit esplicito con firewall industriale e ispezione del protocollo.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0886 (Remote Services)
- **IEC 62443:** IEC 62443-3-3 SR 5.1, SR 5.2
- **Riferimenti:** ISA/IEC 62443-3-2 — Zone and conduit partitioning, IEC 62443-3-3 — System security requirements

### [Alto] Flusso di controllo tra zone Purdue diverse

- **Score:** 7.9/10 · **Categoria:** segmentation · **Confidenza:** high
- **Asset:** 10.10.0.60
- **Etichetta asset:** 10.10.0.60
- **Evidenza:** purdue 3->1
- **Perche' conta:** Un flusso che attraversa il confine IT/OT senza un conduit dichiarato annulla la segmentazione: un ransomware nella rete office puo' raggiungere il campo.
- **Remediation:** Documentare o rimuovere il flusso. Se serve, creare un conduit esplicito con firewall industriale e ispezione del protocollo.
- **Applicabile in produzione:** no — richiede fermata/manutenzione
- **MITRE ATT&CK for ICS:** T0886 (Remote Services)
- **IEC 62443:** IEC 62443-3-3 SR 5.1, SR 5.2
- **Riferimenti:** ISA/IEC 62443-3-2 — Zone and conduit partitioning, IEC 62443-3-3 — System security requirements

### [Medio] Percentuale elevata di broadcast/multicast

- **Score:** 4.8/10 · **Categoria:** network-integrity · **Confidenza:** medium
- **Asset:** —
- **Etichetta asset:** rete L2
- **Evidenza:** broadcast ratio=44.4%
- **Perche' conta:** Broadcast eccessivo riduce la banda disponibile per il traffico isocrono e puo' indicare un loop L2 o un device malfunzionante.
- **Remediation:** Verificare STP, loop e device che generano broadcast; abilitare storm control sulle porte di accesso.
- **Applicabile in produzione:** si
- **IEC 62443:** IEC 62443-3-3 SR 7.1
- **Riferimenti:** IEC 62443-3-3 — System security requirements

### [Basso] Asset OT non identificati (censimento incompleto)

- **Score:** 3.4/10 · **Categoria:** inventory · **Confidenza:** high
- **Asset:** —
- **Etichetta asset:** inventario
- **Evidenza:** 5 asset su 6 senza vendor/identita': 10.10.0.30, 10.10.0.40, 10.10.0.60, 10.10.0.70, 10.10.0.80
- **Perche' conta:** Senza vendor e modello non si possono valutare firmware, vulnerabilita' note e fine supporto. Un inventario incompleto e' il primo rischio gestionale in un audit IEC 62443.
- **Remediation:** Completare il censimento con il registro asset di impianto, foto targhette e documentazione di commessa; ripetere poi l'assessment per arricchire le identita'.
- **Applicabile in produzione:** si
- **IEC 62443:** IEC 62443-2-1, SR 7.8
- **Riferimenti:** IEC 62443-3-3 — System security requirements

## Anomalie di traffico

| Severita' | Tipo | Titolo | Sorgente | Destinazione | Evidenza |
|---|---|---|---|---|---|
| Critico | ot_write_command | Comando IEC 60870-5-104 osservato | 10.10.0.130 | 10.10.0.60 | type_id=45 cot=3 |
| Critico | ot_write_command | Comando di scrittura Modbus osservato (Write Single Register) | 10.10.0.130 | 10.10.0.5 | fc=6 unit=1 addr=10 qty=None |
| Critico | ot_write_command | Operazione di controllo DNP3 osservata (Direct Operate) | 10.10.0.130 | 10.10.0.30 | function=0x05 |
| Critico | ot_internet_egress | Traffico da asset industriale verso Internet | 10.10.0.5 | 8.8.8.8 | proto=https dport=443 |
| Alto | ot_write_command | Comando S7 di modifica PLC osservato (Write Var) | 10.10.0.130 | 10.10.0.5 | function=0x05 |
| Alto | zone_violation | Comando bacnet dalla zona IT (Purdue 3) al campo (Purdue 1) | 10.10.0.130 | 10.10.0.40 | purdue 3->1 |
| Alto | zone_violation | Comando dnp3 dalla zona IT (Purdue 3) al campo (Purdue 1) | 10.10.0.130 | 10.10.0.30 | purdue 3->1 |
| Alto | zone_violation | Comando iec104 dalla zona IT (Purdue 3) al campo (Purdue 1) | 10.10.0.130 | 10.10.0.60 | purdue 3->1 |
| Alto | zone_violation | Comando modbus dalla zona IT (Purdue 3) al campo (Purdue 1) | 10.10.0.130 | 10.10.0.5 | purdue 3->1 |
| Alto | zone_violation | Comando s7comm dalla zona IT (Purdue 3) al campo (Purdue 1) | 10.10.0.130 | 10.10.0.5 | purdue 3->1 |
| Alto | arp_conflict | Due MAC diversi per lo stesso IP (possibile ARP spoofing) | 10.10.0.1 | — | mac_dominante=02:00:00:00:00:66; altri=00:80:63:aa:bb:cc |
| Alto | ot_write_command | Scrittura BACnet osservata | 10.10.0.130 | 10.10.0.40 | service=15 |

> **Comandi di scrittura verso il processo.** Le anomalie di tipo `ot_write_command` non sono vulnerabilita' teoriche: qualcuno o qualcosa ha inviato un comando capace di muovere un attuatore. Correlare con i log del SCADA e con le finestre di manutenzione.

## Segmentazione tra zone

| Zona sorgente | Zona destinazione | Flussi | Attraversa zone |
|---|---|---|---|
| Office | Controllo Linea 2 | 6 | si |
| Controllo Linea 2 | Controllo Linea 2 | 3 | no |
| Controllo Linea 2 | non classificata | 1 | si |

Totale flussi tra zone diverse: **7**. Ogni flusso tra Purdue 3/4 e Purdue 1/2 dovrebbe passare da un firewall industriale o da un data diode, non da uno switch condiviso.

## Copertura e limiti

- Modalita': **Passivo — nessun pacchetto inviato alla rete dell'impianto**
- Target dichiarati: —
- Interfacce: —
- Pacchetti analizzati: 18
- Host scoperti: 11 · fingerprintati: 0
- Porte aperte rilevate: 1
- Protocolli identificati: —

Verifiche eseguite:
- ot_protocol_exposure
- ot_write_capability
- engineering_access
- it_services_in_ot
- cleartext_management
- snmp_default_community
- unauthenticated_hmi
- eol_operating_system
- firmware_unknown
- ot_internet_egress
- ot_write_observed
- arp_spoofing
- unauthorized_discovery
- zone_violation
- dns_tunneling
- flat_network
- baseline_drift
- broadcast_storm
- unknown_ot_assets
- opcua_security
- duplicate_addressing

> L'assenza di findings non dimostra l'assenza di vulnerabilita': un assessment e' una fotografia di una finestra temporale, non una garanzia. Le verifiche non eseguite sono elencate sopra e vanno coperte in un ciclo successivo.

## Appendice: metodologia e note legali

- Riferimenti metodologici: NIST SP 800-82 Rev. 3, IEC 62443-3-3, ISA/IEC 62443-2-4.
- Politica di sicurezza applicata: nessuna funzione di scrittura sui protocolli di processo (Modbus FC5/6/15/16, S7 Write/Download, DNP3 Operate, IEC104 comandi, BACnet WriteProperty, PROFINET DCP Set, CIP Write) viene mai generata dal tool.
- Ogni azione di rete e' tracciata in un audit log con riferimento all'autorizzazione.
- Autorizzazione dichiarata: SELFTEST-LOCAL-ONLY. L'assessment e' valido solo entro la finestra e lo scope autorizzati.
- I dati contenuti in questo report sono informazioni riservate del cliente e vanno conservati secondo la policy aziendale.
