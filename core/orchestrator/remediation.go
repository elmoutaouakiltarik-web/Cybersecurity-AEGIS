package main

import (
	"net/http"
	"strconv"
	"strings"
)

// Remediation is the canonical structure shown to operators next to a finding.
// It is intentionally compact so the dashboard can render it inline.
type Remediation struct {
	Severity   string   `json:"severity"`         // info|low|medium|high|critical
	Summary    string   `json:"summary"`          // one-line explanation
	Impact     string   `json:"impact,omitempty"` // what an attacker gains
	Actions    []string `json:"actions"`          // ordered, actionable steps
	References []string `json:"references,omitempty"`
	Effort     string   `json:"effort,omitempty"`     // quick|moderate|hard
	Automated  bool     `json:"automated,omitempty"`  // true if SOAR can handle
	Playbook   string   `json:"playbook_id,omitempty"`
}

// ── Knowledge base: service / port → remediation ─────────────────────────────
// Keys are service identifiers (lowercase) emitted by the network and vuln
// modules; the port fallback map is used when only the port number is known.

var serviceRemediations = map[string]Remediation{
	"telnet": {
		Severity: "critical",
		Summary:  "Telnet expone le credenziali in chiaro sulla rete.",
		Impact:   "Sniffing della LAN restituisce username e password in chiaro.",
		Actions: []string{
			"Disabilita immediatamente il servizio Telnet sul target.",
			"Sostituiscilo con SSH (OpenSSH) usando chiavi asimmetriche.",
			"Se è un device OT che non supporta SSH: isolalo in VLAN dedicata + ACL sorgente.",
			"Blocca la porta 23/TCP in firewall verso il segmento utenti.",
		},
		References: []string{"CWE-319", "NIST SP 800-53 SC-8", "CIS Benchmark"},
		Effort:     "quick",
		Automated:  true,
		Playbook:   "block_ip",
	},
	"ftp": {
		Severity: "high",
		Summary:  "FTP trasmette credenziali e dati in chiaro; spesso accetta anonymous.",
		Actions: []string{
			"Migra a SFTP (SSH File Transfer Protocol) o FTPS con TLS.",
			"Disabilita login anonymous (config: anonymous_enable=NO).",
			"Forza autenticazione e chroot per ogni utente.",
			"Logga ogni upload/download con timestamp e hash file.",
		},
		References: []string{"CIS 2.2.10", "RFC 4217"},
		Effort:     "moderate",
	},
	"smb": {
		Severity: "critical",
		Summary:  "SMB esposto in rete è il vettore #1 per ransomware (EternalBlue, SMBGhost).",
		Impact:   "RCE non autenticato → lateral movement → ransomware in pochi minuti.",
		Actions: []string{
			"Disabilita SMBv1 (Set-SmbServerConfiguration -EnableSMB1Protocol $false).",
			"Applica MS17-010 e KB4551762 (SMBGhost) immediatamente.",
			"Abilita SMB signing obbligatorio (RequireSecuritySignature).",
			"Blocca 445/TCP da Internet (firewall perimetrale).",
			"Segmenta i file server in VLAN separata, accessibile solo da host autorizzati.",
		},
		References: []string{"CVE-2017-0144", "CVE-2020-0796", "CISA AA20-049A"},
		Effort:     "moderate",
		Automated:  true,
		Playbook:   "isolate_host",
	},
	"rdp": {
		Severity: "critical",
		Summary:  "RDP esposto è il vettore #2 di compromissione (BlueKeep, brute-force).",
		Actions: []string{
			"Non esporre 3389/TCP su Internet. Usa un VPN (WireGuard) o Bastion host.",
			"Abilita NLA (Network Level Authentication).",
			"Applica MFA su tutti gli account amministratori (Duo/Azure MFA).",
			"Limita logon RDP solo a gruppo dedicato (Remote Desktop Users).",
			"Patcha CVE-2019-0708 (BlueKeep) e ruota le password.",
		},
		References: []string{"CVE-2019-0708", "CISA AA22-040A"},
		Effort:     "quick",
		Automated:  true,
		Playbook:   "block_ip",
	},
	"redis": {
		Severity: "critical",
		Summary:  "Redis spesso esposto senza autenticazione → RCE via CONFIG SET o Lua sandbox escape.",
		Actions: []string{
			"Imposta requirepass con password robusta (>32 char) in redis.conf.",
			"Bind solo su 127.0.0.1 o socket Unix se non serve in rete.",
			"Disabilita comandi pericolosi: rename-command CONFIG \"\", FLUSHALL \"\".",
			"Aggiorna Redis a versione >= 7.2.4 (patch CVE-2022-0543).",
			"Aggiungi firewall rule: solo app server può raggiungere 6379.",
		},
		References: []string{"CVE-2022-0543", "Redis Security Docs"},
		Effort:     "quick",
	},
	"mongodb": {
		Severity: "high",
		Summary:  "MongoDB senza auth permette lettura/scrittura di tutti i database.",
		Actions: []string{
			"Abilita authorization: enabled in mongod.conf.",
			"Crea utente admin e utenti per database con principio del minimo privilegio.",
			"Bind solo su interfaccia interna (bindIp: 127.0.0.1 + IP cluster).",
			"Aggiorna a MongoDB >= 7.0 con TLS obbligatorio (tls.mode: requireTLS).",
			"Aggiungi audit log: auditLog.destination: file.",
		},
		References: []string{"MongoDB Security Checklist"},
		Effort:     "moderate",
	},
	"elasticsearch": {
		Severity: "critical",
		Summary:  "Elasticsearch storicamente esposto senza auth (decine di milioni di leak).",
		Actions: []string{
			"Abilita X-Pack security (xpack.security.enabled: true).",
			"Configura HTTPS con certificato valido (xpack.security.http.ssl).",
			"Crea ruoli granulari per ogni applicazione che legge.",
			"Bind interno solo (network.host: _site_).",
			"Aggiorna a >= 8.x per security by default.",
		},
		References: []string{"Elastic Security Hardening"},
		Effort:     "moderate",
	},
	"ssh": {
		Severity: "high",
		Summary:  "SSH è solido ma vulnerabile a brute-force, regreSSHion (CVE-2024-6387) e Terrapin.",
		Actions: []string{
			"Disabilita PasswordAuthentication: usa solo chiavi pubbliche (PubkeyAuthentication yes).",
			"Aggiorna OpenSSH a >= 9.8p1 per patch CVE-2024-6387 (regreSSHion).",
			"Disabilita root login (PermitRootLogin no).",
			"Installa fail2ban o CrowdSec per ban automatico dopo N tentativi falliti.",
			"Per Terrapin: disabilita chacha20-poly1305@openssh.com se possibile.",
		},
		References: []string{"CVE-2024-6387", "CVE-2023-48795"},
		Effort:     "quick",
		Automated:  true,
		Playbook:   "block_ip",
	},
	"http": {
		Severity: "medium",
		Summary:  "HTTP in chiaro è soggetto a sniffing, downgrade e injection.",
		Actions: []string{
			"Forza redirect a HTTPS (HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload).",
			"Aggiungi WAF davanti (CrowdSec WAF, ModSecurity).",
			"Patch HTTP/2 Rapid Reset (CVE-2023-44487): aggiorna nginx >= 1.25.3.",
			"Imposta security headers: CSP, X-Frame-Options DENY, X-Content-Type-Options nosniff.",
		},
		References: []string{"OWASP Secure Headers Project"},
		Effort:     "quick",
	},
	"https": {
		Severity: "medium",
		Summary:  "HTTPS richiede config TLS solida: cipher deboli e cert scaduti = MITM facile.",
		Actions: []string{
			"Usa TLS 1.2+/1.3, disabilita SSLv3/TLS 1.0/1.1.",
			"Cipher suite: ECDHE+AES-GCM o CHACHA20-POLY1305 (mozilla intermediate).",
			"Certificato valido (Let's Encrypt automation con certbot).",
			"OCSP Stapling abilitato per fault tolerance.",
			"Monitora con SSL Labs / testssl.sh ogni mese.",
		},
		References: []string{"Mozilla SSL Config Generator", "SSL Labs A+"},
		Effort:     "moderate",
	},
	"dns": {
		Severity: "high",
		Summary:  "DNS server esposto è vettore di amplification e exfiltration.",
		Actions: []string{
			"Disabilita recursion per client non autorizzati (allow-recursion).",
			"Implementa DNSSEC per zone autoritative.",
			"Limita query rate (response-rate-limiting).",
			"Patch CVE-2023-50387 (KeyTrap) e CVE-2020-1350 (SIGRed).",
			"Logga query sospette (NXDOMAIN spike, long TXT records → DNS tunneling).",
		},
		References: []string{"CVE-2020-1350", "CVE-2023-50387", "NIST SP 800-81"},
		Effort:     "moderate",
	},
	"mssql": {
		Severity: "high",
		Summary:  "SQL Server esposto = vettore di SQLi e privilege escalation.",
		Actions: []string{
			"Non esporre 1433/TCP su Internet. Bind interno solo.",
			"Forza Windows Authentication, disabilita SA o cambia password.",
			"Abilita TDE (Transparent Data Encryption) per dati at-rest.",
			"Applica Cumulative Update mensile (CU).",
			"Audit di login falliti tramite SQL Server Audit.",
		},
		References: []string{"Microsoft SQL Hardening"},
		Effort:     "moderate",
	},
	"mysql": {
		Severity: "medium",
		Summary:  "MySQL/MariaDB esposto può essere brute-forzato e leak via UDF.",
		Actions: []string{
			"bind-address = 127.0.0.1 in my.cnf se non serve in rete.",
			"Esegui mysql_secure_installation: rimuovi anonymous user e test DB.",
			"Forza TLS richiesto (require_secure_transport=ON).",
			"Aggiorna a MySQL 8.0.34+ / MariaDB 11.x.",
		},
		Effort: "quick",
	},
	"postgresql": {
		Severity: "medium",
		Summary:  "PostgreSQL esposto è bersaglio comune; default trust auth è disastro.",
		Actions: []string{
			"pg_hba.conf: usa scram-sha-256, mai trust o md5 per connessioni remote.",
			"listen_addresses = 'localhost' se non serve esterno.",
			"Forza ssl = on con certificato valido.",
			"Applica patch CVE-2024-7348 (pg_dump race condition).",
		},
		Effort: "quick",
	},
	"vnc": {
		Severity: "high",
		Summary:  "VNC ha autenticazione debole (max 8 char) e spesso senza crittografia.",
		Actions: []string{
			"Sostituisci con RDP+NLA o usa VNC over SSH tunnel.",
			"Mai esporre 5900/TCP su Internet.",
			"Aggiungi password robusta + abilita TLS plugin se disponibile.",
		},
		Effort: "moderate",
	},
	"ldap": {
		Severity: "high",
		Summary:  "LDAP in chiaro espone bind credentials; vulnerabile a Log4Shell se serve Java.",
		Actions: []string{
			"Forza LDAPS (636/TCP) o StartTLS sulla 389.",
			"Patch CVE-2021-44228 (Log4Shell) e CVE-2024-49113 (Windows LDAP DoS).",
			"Disabilita anonymous bind.",
			"Limita query rate da client non autorizzati.",
		},
		Effort: "moderate",
	},

	// ── OT / ICS protocols ───────────────────────────────────────────────────
	"modbus": {
		Severity: "critical",
		Summary:  "Modbus/TCP non ha autenticazione: chiunque sulla rete può scrivere PLC.",
		Impact:   "Comando non autorizzato verso PLC → impatto fisico (pompe, valvole, motori).",
		Actions: []string{
			"Segmenta la rete OT con DMZ industriale (Purdue Model L3.5).",
			"Inserisci data diode o firewall industriale (Tofino, Hirschmann) tra IT e OT.",
			"Abilita Modbus Security (RFC) dove i PLC lo supportano.",
			"Whitelist host autorizzati a scrivere (FC05/FC06/FC15/FC16) tramite ACL.",
			"Monitora con Suricata + regole OT (Quickdraw, ET-OT).",
		},
		References: []string{"NIST SP 800-82r3", "IEC 62443", "T0855"},
		Effort:     "hard",
		Automated:  false,
		Playbook:   "ot_advisory",
	},
	"opcua": {
		Severity: "high",
		Summary:  "OPC UA può funzionare in modalità 'None' (no security) se mal configurato.",
		Actions: []string{
			"Imposta SecurityMode = Sign+Encrypt sui server OPC UA.",
			"Usa certificati X.509 validi per ogni endpoint client/server.",
			"Disabilita endpoint 'None' (UA-TCP senza sicurezza).",
			"Audit tag access tramite Server-Side Audit Log.",
		},
		Effort: "moderate",
	},
	"dnp3": {
		Severity: "high",
		Summary:  "DNP3 senza Secure Authentication v5 è esposto a spoofing e injection.",
		Actions: []string{
			"Abilita DNP3 Secure Authentication v5 sui device che lo supportano.",
			"Whitelist degli RTU indirizzi autorizzati.",
			"Monitora unsolicited responses da indirizzi non noti.",
		},
		Effort: "hard",
	},
	"iec104": {
		Severity: "critical",
		Summary:  "IEC 60870-5-104 non ha autenticazione: comando SCADA spoofing è banale.",
		Actions: []string{
			"Inserisci gateway IEC 62351 per autenticazione e cifratura.",
			"Segmenta in rete L1/L2 isolata; usa data diode verso IT.",
			"Logga tutti i comandi C_SC_NA_1 e C_DC_NA_1.",
		},
		Effort: "hard",
	},
	"bacnet": {
		Severity: "high",
		Summary:  "BACnet (building automation) non ha auth: controllo HVAC, luci, accessi compromessi.",
		Actions: []string{
			"Segmenta la rete BAS in VLAN dedicata.",
			"Abilita BACnet/SC (Secure Connect) dove disponibile.",
			"Disabilita Foreign Device Registration non autorizzate.",
		},
		Effort: "moderate",
	},
}

// portFallback gives sane default remediation when only the port number is
// available (no service banner was returned).
var portFallback = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
	53: "dns", 80: "http", 110: "pop3", 143: "imap",
	389: "ldap", 443: "https", 445: "smb", 502: "modbus",
	1433: "mssql", 1521: "oracle", 2404: "iec104",
	3306: "mysql", 3389: "rdp", 4840: "opcua",
	5432: "postgresql", 5900: "vnc", 6379: "redis",
	8080: "http", 8443: "https", 9200: "elasticsearch",
	27017: "mongodb", 47808: "bacnet",
}

// ── CVE → remediation ────────────────────────────────────────────────────────
// Authoritative remediation tied to specific CVEs that hit news in 2024–2025.

var cveRemediations = map[string]Remediation{
	"CVE-2024-3400": {
		Severity: "critical",
		Summary:  "PAN-OS GlobalProtect: command injection non autenticato, exploit attivo.",
		Actions: []string{
			"Aggiorna a PAN-OS 11.1.2-h3 / 11.0.4-h1 / 10.2.9-h1 IMMEDIATAMENTE.",
			"Disabilita Telemetry temporaneamente fino al patch (workaround Palo Alto).",
			"Audit dei log GlobalProtect per pattern /api/?type=oauth-callback.",
			"Ruota tutte le credenziali e i cert dei firewall esposti.",
		},
		References: []string{"PAN-SA-2024-0008", "CISA KEV"},
		Effort:     "quick",
	},
	"CVE-2024-21762": {
		Severity: "critical",
		Summary:  "FortiOS SSL-VPN out-of-bounds write → RCE pre-auth.",
		Actions: []string{
			"Upgrade FortiOS a 7.4.3 / 7.2.7 / 7.0.14 / 6.4.15 / 6.2.16.",
			"Workaround: disabilita SSL-VPN se non puoi patchare subito.",
			"Verifica IoC FG-IR-24-015.",
		},
		References: []string{"FG-IR-24-015", "CISA KEV"},
		Effort:     "quick",
	},
	"CVE-2017-0144": {
		Severity: "critical",
		Summary:  "EternalBlue: SMB v1 RCE non autenticato (NotPetya, WannaCry).",
		Actions: []string{
			"Applica MS17-010 su tutti i Windows (anche client).",
			"Disabilita SMBv1 ovunque (Get-WindowsOptionalFeature -FeatureName SMB1Protocol).",
			"Segmenta la rete: blocca 445/TCP tra workstation e tra VLAN.",
		},
		References: []string{"MS17-010", "US-CERT TA17-132A"},
		Effort:     "quick",
	},
	"CVE-2019-0708": {
		Severity: "critical",
		Summary:  "BlueKeep: RDP pre-auth RCE, wormable.",
		Actions: []string{
			"Patch KB4499175/KB4499180 su tutti i Windows 7/2008/2008R2.",
			"Abilita NLA (Network Level Authentication).",
			"Blocca 3389/TCP da Internet.",
		},
		References: []string{"CVE-2019-0708"},
		Effort:     "quick",
	},
	"CVE-2021-44228": {
		Severity: "critical",
		Summary:  "Log4Shell: JNDI injection in log4j → RCE banale.",
		Actions: []string{
			"Upgrade log4j a 2.17.1+ ovunque.",
			"Set system property: log4j2.formatMsgNoLookups=true.",
			"Scansiona container e jar con scanner dedicato (log4j-detector).",
			"Audit logs per pattern jndi:ldap, jndi:rmi.",
		},
		References: []string{"CVE-2021-44228", "Apache Log4j Security"},
		Effort:     "moderate",
	},
	"CVE-2024-6387": {
		Severity: "high",
		Summary:  "regreSSHion: OpenSSH signal handler race → RCE remoto su Linux glibc.",
		Actions: []string{
			"Upgrade OpenSSH a 9.8p1.",
			"Workaround: LoginGraceTime 0 (rate-limit DoS, ma blocca exploit).",
			"Limita esposizione 22/TCP a IP autorizzati.",
		},
		References: []string{"Qualys regreSSHion advisory"},
		Effort:     "quick",
	},
	"CVE-2023-44487": {
		Severity: "high",
		Summary:  "HTTP/2 Rapid Reset DDoS — record DDoS 398M rps su Google.",
		Actions: []string{
			"Patch web server (nginx 1.25.3+, Apache httpd 2.4.58+, h2o 2.2.6+).",
			"Abilita rate-limit per stream HTTP/2.",
			"Considera CDN con DDoS mitigation davanti.",
		},
		References: []string{"CVE-2023-44487"},
		Effort:     "quick",
	},
	"CVE-2020-0796": {
		Severity: "critical",
		Summary:  "SMBGhost: SMBv3 compression RCE wormable.",
		Actions: []string{
			"Patch KB4551762 su Windows 10 1903/1909.",
			"Workaround: disable SMBv3 compression (Set-ItemProperty HKLM:\\...\\LanmanServer\\Parameters DisableCompression 1).",
		},
		References: []string{"CVE-2020-0796", "MSRC 2020-0796"},
		Effort:     "quick",
	},
}

// ── IOC category → remediation ───────────────────────────────────────────────
// Used when threat-intel matches a known-bad IP / domain / hash.

var iocRemediations = map[string]Remediation{
	"malicious_ip": {
		Severity: "high",
		Summary:  "IP corrisponde a IOC noto (C2, scanner abusivo, exit Tor malicious).",
		Actions: []string{
			"Blocca l'IP su firewall perimetrale (iptables/nftables/CrowdSec).",
			"Cerca connessioni storiche verso quell'IP in netflow/Suricata.",
			"Isola gli host che hanno comunicato con esso per IR.",
			"Forwarda al SOAR per ban automatico (playbook block_ip).",
		},
		Effort:    "quick",
		Automated: true,
		Playbook:  "block_ip",
	},
	"phishing_domain": {
		Severity: "high",
		Summary:  "Dominio corrisponde a campagna di phishing nota.",
		Actions: []string{
			"Aggiungi a blocklist DNS (Pi-hole / AdGuard / Umbrella).",
			"Cerca query DNS storiche da host interni.",
			"Forma utenti che hanno cliccato con micro-training.",
			"Reset credenziali degli utenti che hanno visitato la pagina.",
		},
		Effort: "quick",
	},
	"malware_hash": {
		Severity: "critical",
		Summary:  "Hash file corrisponde a malware noto.",
		Actions: []string{
			"Quarantena immediata del file (antivirus + EDR isolation).",
			"Cerca lo stesso hash su altri endpoint (osquery, Velociraptor).",
			"Isola l'host dalla rete fino a triage.",
			"Memory dump e disk image per analisi forense.",
		},
		Effort:    "moderate",
		Automated: true,
		Playbook:  "isolate_host",
	},
	"c2_domain": {
		Severity: "critical",
		Summary:  "Comunicazione verso infrastruttura C2 attiva.",
		Actions: []string{
			"Sinkhole del dominio (risolvi a 127.0.0.1 sul resolver interno).",
			"Isola l'host che ha tentato la query.",
			"Hunt per altri host con stesso pattern beacon.",
			"Esegui playbook c2_detected.",
		},
		Effort:    "quick",
		Automated: true,
		Playbook:  "c2_detected",
	},
}

// ── TLS issue → remediation ──────────────────────────────────────────────────

var tlsRemediations = map[string]Remediation{
	"expired_cert": {
		Severity: "high",
		Summary:  "Certificato scaduto: browser e API client falliscono la connessione.",
		Actions: []string{
			"Rinnova il certificato (Let's Encrypt: certbot renew).",
			"Configura cron/systemd timer per renewal automatico.",
			"Imposta alerting 30 giorni prima della scadenza.",
		},
		Effort: "quick",
	},
	"self_signed": {
		Severity: "medium",
		Summary:  "Certificato self-signed: i client non possono verificare l'identità del server.",
		Actions: []string{
			"Sostituisci con certificato di CA pubblica (Let's Encrypt, ZeroSSL).",
			"O distribuisci la tua CA interna sui client autorizzati.",
		},
		Effort: "moderate",
	},
	"weak_cipher": {
		Severity: "high",
		Summary:  "Cipher suite deboli abilitate (RC4, 3DES, CBC senza AEAD).",
		Actions: []string{
			"Riconfigura il server con Mozilla intermediate profile (ECDHE + AES-GCM/CHACHA20).",
			"Disabilita SSLv3, TLS 1.0, TLS 1.1.",
			"Testa con SSL Labs (target: A+).",
		},
		Effort: "quick",
	},
	"no_ocsp_stapling": {
		Severity: "low",
		Summary:  "OCSP stapling non abilitato: rischio privacy e disponibilità revoca.",
		Actions: []string{
			"Abilita ssl_stapling on; ssl_stapling_verify on; in nginx.",
			"Per Apache: SSLUseStapling On + SSLStaplingCache.",
		},
		Effort: "quick",
	},
}

// ── Public API: HTTP handler /api/v1/remediation ─────────────────────────────
// Query params: ?service=ssh | ?port=22 | ?cve=CVE-2024-3400 | ?ioc=c2_domain | ?tls=expired_cert

func (o *Orchestrator) handleRemediation(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	results := map[string]Remediation{}

	if svc := strings.ToLower(strings.TrimSpace(q.Get("service"))); svc != "" {
		if rem, ok := serviceRemediations[svc]; ok {
			results["service:"+svc] = rem
		}
	}
	if portStr := strings.TrimSpace(q.Get("port")); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			if svc, ok := portFallback[p]; ok {
				if rem, ok2 := serviceRemediations[svc]; ok2 {
					results["port:"+portStr] = rem
				}
			}
		}
	}
	if cve := strings.ToUpper(strings.TrimSpace(q.Get("cve"))); cve != "" {
		if rem, ok := cveRemediations[cve]; ok {
			results["cve:"+cve] = rem
		}
	}
	if ioc := strings.ToLower(strings.TrimSpace(q.Get("ioc"))); ioc != "" {
		if rem, ok := iocRemediations[ioc]; ok {
			results["ioc:"+ioc] = rem
		}
	}
	if tls := strings.ToLower(strings.TrimSpace(q.Get("tls"))); tls != "" {
		if rem, ok := tlsRemediations[tls]; ok {
			results["tls:"+tls] = rem
		}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"count":   len(results),
		"results": results,
	})
}

// RemediationLookup is a server-side helper to enrich responses with
// remediation when the orchestrator forwards data to the dashboard.
func RemediationLookup(service string, port int, cve string) *Remediation {
	if cve != "" {
		if r, ok := cveRemediations[strings.ToUpper(cve)]; ok {
			return &r
		}
	}
	if service != "" {
		if r, ok := serviceRemediations[strings.ToLower(service)]; ok {
			return &r
		}
	}
	if port > 0 {
		if svc, ok := portFallback[port]; ok {
			if r, ok2 := serviceRemediations[svc]; ok2 {
				return &r
			}
		}
	}
	return nil
}
