package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ShieldAnalysis struct {
	GeneratedAt      time.Time       `json:"generated_at"`
	WindowHours      int             `json:"window_hours"`
	EventsAnalyzed   int             `json:"events_analyzed"`
	RiskScore        int             `json:"risk_score"`
	Posture          string          `json:"posture"`
	ExecutiveSummary string          `json:"executive_summary"`
	Findings         []ShieldFinding `json:"findings"`
	Entities         []ShieldEntity  `json:"entities"`
	Hunts            []ShieldHunt    `json:"hunts"`
	Actions          []ShieldAction  `json:"actions"`
	Rules            []ShieldRule    `json:"rules"`
}

type ShieldFinding struct {
	ID                 string   `json:"id"`
	Title              string   `json:"title"`
	Severity           string   `json:"severity"`
	Confidence         int      `json:"confidence"`
	Category           string   `json:"category"`
	TacticID           string   `json:"tactic_id,omitempty"`
	TacticName         string   `json:"tactic_name,omitempty"`
	TechniqueID        string   `json:"technique_id,omitempty"`
	TechniqueName      string   `json:"technique_name,omitempty"`
	Evidence           []string `json:"evidence"`
	Entities           []string `json:"entities"`
	RecommendedActions []string `json:"recommended_actions"`
	HuntQuery          string   `json:"hunt_query"`
}

type ShieldEntity struct {
	Value    string    `json:"value"`
	Type     string    `json:"type"`
	Score    int       `json:"score"`
	Hits     int       `json:"hits"`
	LastSeen time.Time `json:"last_seen"`
	Reasons  []string  `json:"reasons"`
}

type ShieldHunt struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Query     string `json:"query"`
	Severity  string `json:"severity"`
	Rationale string `json:"rationale"`
}

type ShieldAction struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Priority    string   `json:"priority"`
	SafeMode    bool     `json:"safe_mode"`
	Steps       []string `json:"steps"`
	PowerShell  []string `json:"powershell,omitempty"`
	LinuxShell  []string `json:"linux_shell,omitempty"`
	EvidenceRef []string `json:"evidence_ref,omitempty"`
}

type ShieldRule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Coverage string `json:"coverage"`
	Content  string `json:"content"`
}

type shieldDetector struct {
	id        string
	title     string
	category  string
	severity  string
	tacticID  string
	tactic    string
	techID    string
	technique string
	keywords  []string
	actions   []string
	hunt      string
}

var shieldDetectors = []shieldDetector{
	{
		id: "ransomware-defense", title: "Ransomware behavior or staging indicators", category: "malware", severity: "critical",
		tacticID: "TA0040", tactic: "Impact", techID: "T1486", technique: "Data Encrypted for Impact",
		keywords: []string{"ransom", "encrypt", "shadow copy", "vssadmin", "lockbit", "blackcat", "mass file rename"},
		actions: []string{
			"Isolate only confirmed affected hosts from business networks; keep power on for volatile evidence.",
			"Verify immutable/offline backups and stop backup rotation until scope is known.",
			"Collect process tree, autoruns, recent file writes, and EDR timeline before cleanup.",
		},
		hunt: "ransom OR encrypt OR shadow copy OR vssadmin OR mass file rename",
	},
	{
		id: "credential-theft", title: "Credential theft or brute-force pressure", category: "identity", severity: "high",
		tacticID: "TA0006", tactic: "Credential Access", techID: "T1003", technique: "OS Credential Dumping",
		keywords: []string{"lsass", "mimikatz", "credential", "password spraying", "brute", "failed sudo", "login failed", "unauthorized sudo"},
		actions: []string{
			"Reset and rotate credentials for affected accounts after containment.",
			"Enable MFA or step-up authentication on exposed services and privileged access.",
			"Review recent logons, sudo attempts, token use, and impossible-travel indicators.",
		},
		hunt: "lsass OR mimikatz OR credential OR brute OR failed sudo OR login failed",
	},
	{
		id: "c2-beaconing", title: "Command-and-control or beaconing pattern", category: "network", severity: "high",
		tacticID: "TA0011", tactic: "Command and Control", techID: "T1071", technique: "Application Layer Protocol",
		keywords: []string{"c2", "beacon", "beaconing", "dns tunnel", "tor exit", "callback", "command and control"},
		actions: []string{
			"Block confirmed destinations at DNS, proxy, firewall, and EDR network layers.",
			"Preserve DNS/proxy logs and identify the first host that contacted the indicator.",
			"Create a temporary high-signal watchlist for related domains, JA3, and user agents.",
		},
		hunt: "c2 OR beaconing OR dns tunnel OR tor exit OR callback",
	},
	{
		id: "lateral-movement", title: "Lateral movement or remote service abuse", category: "movement", severity: "high",
		tacticID: "TA0008", tactic: "Lateral Movement", techID: "T1021", technique: "Remote Services",
		keywords: []string{"lateral", "psexec", "pass the hash", "remote service", "ssh scan", "rdp", "smb", "winrm"},
		actions: []string{
			"Disable or restrict lateral protocols between workstation and server segments.",
			"Inspect admin shares, service creation events, SSH keys, RDP logons, and jump hosts.",
			"Rotate local admin passwords and validate LAPS/privileged access boundaries.",
		},
		hunt: "lateral movement OR psexec OR pass the hash OR remote service OR ssh scan OR rdp OR smb",
	},
	{
		id: "ot-unsafe-command", title: "OT/ICS unsafe or unauthorized control activity", category: "industrial", severity: "critical",
		tacticID: "TA0105", tactic: "Inhibit Response Function", techID: "T0855", technique: "Unauthorized Command Message",
		keywords: []string{"modbus write", "unauthorized modbus", "dnp3 unsolicited", "opc ua", "plc", "rtu", "coil", "unsafe command"},
		actions: []string{
			"Do not issue automated OT changes; notify the control-room operator and safety owner.",
			"Verify engineering workstation, HMI, and PLC allowlists for the observed source.",
			"Capture passive packet evidence around the command window and compare with approved work orders.",
		},
		hunt: "modbus OR dnp3 OR opc ua OR plc OR rtu OR unauthorized",
	},
	{
		id: "exfiltration", title: "Possible data exfiltration or data-loss path", category: "data", severity: "high",
		tacticID: "TA0010", tactic: "Exfiltration", techID: "T1041", technique: "Exfiltration Over C2 Channel",
		keywords: []string{"exfil", "exfiltration", "data loss", "large upload", "archive staged", "mega.nz", "pastebin"},
		actions: []string{
			"Identify owner, data classification, and destination for the transfer before blocking business flows.",
			"Review proxy, DNS, DLP, and cloud audit logs for related uploads or archive creation.",
			"Start legal/privacy breach assessment if sensitive data is confirmed.",
		},
		hunt: "exfil OR exfiltration OR data loss OR large upload OR archive staged",
	},
	{
		id: "critical-cve", title: "Critical vulnerability exposure or exploitation path", category: "vulnerability", severity: "critical",
		tacticID: "TA0001", tactic: "Initial Access", techID: "T1190", technique: "Exploit Public-Facing Application",
		keywords: []string{"cve-2024", "rce", "auth bypass", "ssl-vpn", "globalprotect", "screenconnect", "kev"},
		actions: []string{
			"Patch or mitigate internet-facing critical CVEs first; document exception owner and deadline.",
			"Temporarily restrict exposed management interfaces behind VPN, allowlists, or access broker.",
			"Run focused hunt for exploitation indicators listed in vendor and CISA advisories.",
		},
		hunt: "CVE-2024 OR RCE OR auth bypass OR SSL-VPN OR GlobalProtect OR ScreenConnect",
	},
	{
		id: "deception-trigger", title: "Deception trap or honeytoken interaction", category: "deception", severity: "high",
		tacticID: "TA0007", tactic: "Discovery", techID: "T1087", technique: "Account Discovery",
		keywords: []string{"canary", "honeypot", "honeytoken", "trap triggered", "decoy"},
		actions: []string{
			"Treat the source as suspicious until proven otherwise; normal users should not touch canaries.",
			"Pivot from the source IP/user to recent authentication, process, DNS, and file access events.",
			"Add temporary monitoring around the decoy path and nearby high-value assets.",
		},
		hunt: "canary OR honeypot OR honeytoken OR trap triggered OR decoy",
	},
}

var (
	shieldIPRegex  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	shieldCVERegex = regexp.MustCompile(`(?i)\bCVE-\d{4}-\d{4,7}\b`)
)

func (o *Orchestrator) handleShieldAnalysis(w http.ResponseWriter, r *http.Request) {
	windowHours := queryInt(r, "window", 24)
	if windowHours < 1 {
		windowHours = 1
	}
	if windowHours > 168 {
		windowHours = 168
	}
	analysis := o.buildShieldAnalysis(windowHours)
	if o.auditLog != nil {
		o.auditLog.Append("shield_analysis", "api", fmt.Sprintf("window=%dh score=%d findings=%d", windowHours, analysis.RiskScore, len(analysis.Findings)), r.RemoteAddr, "info")
	}
	respondJSON(w, http.StatusOK, analysis)
}

func (o *Orchestrator) handleShieldHunts(w http.ResponseWriter, r *http.Request) {
	analysis := o.buildShieldAnalysis(queryInt(r, "window", 24))
	respondJSON(w, http.StatusOK, map[string]any{"count": len(analysis.Hunts), "hunts": analysis.Hunts})
}

func (o *Orchestrator) handleShieldRules(w http.ResponseWriter, r *http.Request) {
	analysis := o.buildShieldAnalysis(queryInt(r, "window", 24))
	if strings.EqualFold(r.URL.Query().Get("format"), "text") || strings.EqualFold(r.URL.Query().Get("format"), "yaml") {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		for i, rule := range analysis.Rules {
			if i > 0 {
				fmt.Fprintln(w, "\n---")
			}
			fmt.Fprintf(w, "# %s (%s)\n%s\n", rule.Name, rule.Type, rule.Content)
		}
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"count": len(analysis.Rules), "rules": analysis.Rules})
}

func (o *Orchestrator) buildShieldAnalysis(windowHours int) ShieldAnalysis {
	if windowHours <= 0 {
		windowHours = 24
	}
	now := time.Now().UTC()
	cutoff := now.Add(-time.Duration(windowHours) * time.Hour)
	all := o.eventBus.Recent(5000, "")
	events := make([]SecurityEvent, 0, len(all))
	for _, ev := range all {
		if ev.Timestamp.IsZero() || ev.Timestamp.After(cutoff) {
			events = append(events, ev)
		}
	}

	findings := detectShieldFindings(events)
	entities := detectShieldEntities(events)
	hunts := buildShieldHunts(findings, entities)
	actions := buildShieldActions(findings, entities)
	rules := buildShieldRules(findings)
	score := shieldRiskScore(events, findings, entities)
	posture := shieldPosture(score)
	summary := shieldSummary(score, findings, entities, events)

	return ShieldAnalysis{
		GeneratedAt:      now,
		WindowHours:      windowHours,
		EventsAnalyzed:   len(events),
		RiskScore:        score,
		Posture:          posture,
		ExecutiveSummary: summary,
		Findings:         findings,
		Entities:         entities,
		Hunts:            hunts,
		Actions:          actions,
		Rules:            rules,
	}
}

func detectShieldFindings(events []SecurityEvent) []ShieldFinding {
	type bucket struct {
		det      shieldDetector
		score    int
		evidence []string
		entities map[string]bool
	}
	buckets := map[string]*bucket{}
	for _, ev := range events {
		if ev.Resolved {
			continue
		}
		hay := shieldEventHaystack(ev)
		for _, det := range shieldDetectors {
			matches := keywordHits(hay, det.keywords)
			if ev.MITRE != nil && det.techID != "" && strings.EqualFold(ev.MITRE.TechniqueID, det.techID) {
				matches += 2
			}
			if ev.Category == det.category {
				matches++
			}
			if matches == 0 {
				continue
			}
			b := buckets[det.id]
			if b == nil {
				b = &bucket{det: det, entities: map[string]bool{}}
				buckets[det.id] = b
			}
			b.score += matches*12 + severityWeight(ev.Severity)
			if len(b.evidence) < 6 {
				b.evidence = append(b.evidence, fmt.Sprintf("%s | %s | %s", ev.Timestamp.Format(time.RFC3339), ev.Severity, firstNonEmpty(ev.Title, ev.ID)))
			}
			for _, ent := range eventEntities(ev) {
				b.entities[ent] = true
			}
		}
	}
	findings := make([]ShieldFinding, 0, len(buckets))
	for _, b := range buckets {
		conf := b.score
		if conf > 99 {
			conf = 99
		}
		ents := sortedKeys(b.entities)
		findings = append(findings, ShieldFinding{
			ID:                 b.det.id,
			Title:              b.det.title,
			Severity:           b.det.severity,
			Confidence:         conf,
			Category:           b.det.category,
			TacticID:           b.det.tacticID,
			TacticName:         b.det.tactic,
			TechniqueID:        b.det.techID,
			TechniqueName:      b.det.technique,
			Evidence:           b.evidence,
			Entities:           truncateStrings(ents, 12),
			RecommendedActions: b.det.actions,
			HuntQuery:          b.det.hunt,
		})
	}
	sort.Slice(findings, func(i, j int) bool {
		if severityRank(findings[i].Severity) == severityRank(findings[j].Severity) {
			return findings[i].Confidence > findings[j].Confidence
		}
		return severityRank(findings[i].Severity) > severityRank(findings[j].Severity)
	})
	return findings
}

func detectShieldEntities(events []SecurityEvent) []ShieldEntity {
	type entAgg struct {
		value    string
		typ      string
		score    int
		hits     int
		lastSeen time.Time
		reasons  map[string]bool
	}
	entities := map[string]*entAgg{}
	add := func(value, typ, reason string, ev SecurityEvent, score int) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		key := typ + ":" + strings.ToLower(value)
		e := entities[key]
		if e == nil {
			e = &entAgg{value: value, typ: typ, reasons: map[string]bool{}}
			entities[key] = e
		}
		e.hits++
		e.score += score + severityWeight(ev.Severity)/2
		if ev.Timestamp.After(e.lastSeen) {
			e.lastSeen = ev.Timestamp
		}
		e.reasons[reason] = true
	}
	for _, ev := range events {
		if ev.Resolved {
			continue
		}
		hay := shieldEventHaystack(ev)
		for _, ip := range shieldIPRegex.FindAllString(hay, -1) {
			add(ip, "ip", firstNonEmpty(ev.Category, "event"), ev, 6)
		}
		for _, cve := range shieldCVERegex.FindAllString(hay, -1) {
			add(strings.ToUpper(cve), "cve", "vulnerability", ev, 16)
		}
		if ev.OTContext != nil && ev.OTContext.AssetID != "" {
			add(ev.OTContext.AssetID, "asset", "ot-context", ev, 12)
		}
		if ev.RawData != nil {
			for _, key := range []string{"source_ip", "src_ip", "destination_ip", "dst_ip", "target_ip", "host", "hostname", "user", "account"} {
				if v := asString(ev.RawData[key]); v != "" {
					typ := "identity"
					if strings.Contains(key, "ip") {
						typ = "ip"
					}
					if strings.Contains(key, "host") {
						typ = "asset"
					}
					add(v, typ, key, ev, 8)
				}
			}
		}
	}
	out := make([]ShieldEntity, 0, len(entities))
	for _, e := range entities {
		score := e.score
		if score > 100 {
			score = 100
		}
		out = append(out, ShieldEntity{Value: e.value, Type: e.typ, Score: score, Hits: e.hits, LastSeen: e.lastSeen, Reasons: sortedKeys(e.reasons)})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].Hits > out[j].Hits
		}
		return out[i].Score > out[j].Score
	})
	if len(out) > 25 {
		out = out[:25]
	}
	return out
}

func buildShieldHunts(findings []ShieldFinding, entities []ShieldEntity) []ShieldHunt {
	hunts := []ShieldHunt{
		{ID: "hunt-identity-pivot", Name: "Privileged identity pivot", Query: "credential OR sudo OR admin OR token OR login failed", Severity: "high", Rationale: "Finds early credential pressure before lateral movement."},
		{ID: "hunt-living-off-the-land", Name: "Living-off-the-land execution", Query: "powershell OR wmic OR rundll32 OR regsvr32 OR certutil OR bash -c", Severity: "high", Rationale: "Common attacker tradecraft using native tools."},
		{ID: "hunt-ot-safety", Name: "OT safety boundary violation", Query: "modbus OR dnp3 OR opc ua OR unauthorized OR write coil", Severity: "critical", Rationale: "OT commands must be passive-reviewed before response."},
	}
	seen := map[string]bool{}
	for _, h := range hunts {
		seen[h.Query] = true
	}
	for _, f := range findings {
		if f.HuntQuery == "" || seen[f.HuntQuery] {
			continue
		}
		hunts = append(hunts, ShieldHunt{ID: "hunt-" + f.ID, Name: f.Title, Query: f.HuntQuery, Severity: f.Severity, Rationale: "Auto-generated from active Shield finding " + f.ID + "."})
		seen[f.HuntQuery] = true
	}
	for _, e := range entities {
		if e.Score < 50 || len(hunts) >= 12 {
			continue
		}
		q := e.Value
		if e.Type == "cve" {
			q = strings.ToUpper(e.Value)
		}
		if !seen[q] {
			hunts = append(hunts, ShieldHunt{ID: "hunt-entity-" + strings.ToLower(strings.ReplaceAll(e.Type+"-"+e.Value, ".", "-")), Name: "Pivot on " + e.Value, Query: q, Severity: severityFromScore(e.Score), Rationale: fmt.Sprintf("%s appeared %d times across high-signal events.", e.Type, e.Hits)})
			seen[q] = true
		}
	}
	return hunts
}

func buildShieldActions(findings []ShieldFinding, entities []ShieldEntity) []ShieldAction {
	actions := []ShieldAction{
		{
			ID: "act-triage-host", Title: "Endpoint triage snapshot", Priority: "high", SafeMode: true,
			Steps: []string{
				"Capture running processes, network connections, autoruns, scheduled tasks, Defender status, and recent security log events.",
				"Preserve outputs with timestamp and SHA256 in DFIR evidence registry before cleanup.",
			},
			PowerShell: []string{
				"Get-MpComputerStatus | Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,AntispywareEnabled",
				"Get-NetTCPConnection | Where-Object {$_.State -eq 'Established'} | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess",
				"Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\\Microsoft*'} | Select-Object TaskName,TaskPath,State",
			},
		},
		{
			ID: "act-network-containment", Title: "Network containment decision", Priority: "critical", SafeMode: true,
			Steps: []string{
				"Block only confirmed malicious indicators; keep an exception record and rollback plan.",
				"Mirror the block to DNS, proxy, firewall, EDR, and CrowdSec/Wazuh rules where available.",
			},
			PowerShell: []string{
				"New-NetFirewallRule -DisplayName 'AEGIS Confirmed Block <IP>' -Direction Outbound -RemoteAddress <IP> -Action Block",
			},
		},
		{
			ID: "act-ot-advisory", Title: "OT safety-gated escalation", Priority: "critical", SafeMode: true,
			Steps: []string{
				"Notify OT owner and control-room operator before any containment action.",
				"Compare source, protocol, function code, and target asset against approved change windows.",
				"Use passive capture and switch/span data; avoid active scans on safety-critical segments.",
			},
		},
	}
	if len(findings) > 0 {
		refs := make([]string, 0, len(findings))
		for _, f := range findings {
			refs = append(refs, f.ID)
		}
		for i := range actions {
			actions[i].EvidenceRef = truncateStrings(refs, 8)
		}
	}
	if len(entities) > 0 && entities[0].Score >= 70 {
		actions = append(actions, ShieldAction{
			ID: "act-pivot-top-entity", Title: "Pivot top risky entity: " + entities[0].Value, Priority: severityFromScore(entities[0].Score), SafeMode: true,
			Steps: []string{
				"Search the top entity across event, proxy, DNS, endpoint, and authentication telemetry.",
				"Mark related events as one incident if the entity appears across multiple categories.",
			},
			EvidenceRef: []string{entities[0].Value},
		})
	}
	return actions
}

func buildShieldRules(findings []ShieldFinding) []ShieldRule {
	rules := make([]ShieldRule, 0, len(findings)+2)
	for _, f := range findings {
		rules = append(rules, ShieldRule{
			ID:       "sigma-" + f.ID,
			Name:     "AEGIS " + f.Title,
			Type:     "sigma-like",
			Severity: f.Severity,
			Coverage: firstNonEmpty(f.TechniqueID, f.Category),
			Content:  sigmaRuleForFinding(f),
		})
	}
	rules = append(rules, ShieldRule{
		ID:       "yara-ransomware-ops",
		Name:     "AEGIS Ransomware Operations Strings",
		Type:     "yara",
		Severity: "high",
		Coverage: "T1486",
		Content: `rule AEGIS_Ransomware_Operations_Strings {
  meta:
    description = "Defensive string triage for ransomware operations and staging notes"
    author = "Cybersecurity-AEGIS"
  strings:
    $s1 = "shadow copy" nocase
    $s2 = "vssadmin" nocase
    $s3 = "decrypt" nocase
    $s4 = "ransom" nocase
    $s5 = "mass file rename" nocase
  condition:
    2 of them
}`,
	})
	rules = append(rules, ShieldRule{
		ID:       "wazuh-ot-unsafe-command",
		Name:     "AEGIS OT Unauthorized Command Alert",
		Type:     "wazuh-rule",
		Severity: "critical",
		Coverage: "T0855",
		Content: `<group name="aegis,ot,ics,">
  <rule id="110855" level="14">
    <field name="protocol">Modbus|DNP3|OPC UA</field>
    <match>unauthorized|write coil|unsolicited</match>
    <description>AEGIS OT unsafe or unauthorized command message</description>
    <mitre><id>T0855</id></mitre>
  </rule>
</group>`,
	})
	return rules
}

func sigmaRuleForFinding(f ShieldFinding) string {
	keywords := strings.Split(f.HuntQuery, " OR ")
	if len(keywords) == 1 {
		keywords = strings.FieldsFunc(f.HuntQuery, func(r rune) bool { return r == '|' || r == ',' })
	}
	var b strings.Builder
	fmt.Fprintf(&b, "title: %s\nid: %s\nstatus: experimental\nlogsource:\n  product: aegis\n  category: security_event\ndetection:\n  keywords:\n", f.Title, f.ID)
	for _, kw := range keywords {
		kw = strings.TrimSpace(strings.Trim(kw, "\"'"))
		if kw != "" && strings.ToUpper(kw) != "OR" {
			fmt.Fprintf(&b, "    - '%s'\n", strings.ReplaceAll(kw, "'", "''"))
		}
	}
	fmt.Fprintln(&b, "  condition: keywords")
	if f.TechniqueID != "" {
		fmt.Fprintf(&b, "tags:\n  - attack.%s\n", strings.ToLower(f.TechniqueID))
	}
	fmt.Fprintf(&b, "level: %s\n", f.Severity)
	return b.String()
}

func shieldRiskScore(events []SecurityEvent, findings []ShieldFinding, entities []ShieldEntity) int {
	score := 0
	for _, f := range findings {
		score += severityRank(f.Severity)*8 + f.Confidence/8
	}
	for _, e := range entities {
		if e.Score >= 70 {
			score += 7
		}
	}
	for _, ev := range events {
		if ev.Resolved {
			continue
		}
		switch ev.Severity {
		case SeverityCritical:
			score += 5
		case SeverityHigh:
			score += 2
		}
	}
	if score > 100 {
		score = 100
	}
	return score
}

func shieldPosture(score int) string {
	switch {
	case score >= 85:
		return "RED - active defense"
	case score >= 65:
		return "ORANGE - high alert"
	case score >= 35:
		return "YELLOW - guarded"
	default:
		return "GREEN - stable"
	}
}

func shieldSummary(score int, findings []ShieldFinding, entities []ShieldEntity, events []SecurityEvent) string {
	lead := "Shield Engine analyzed live AEGIS telemetry"
	if len(events) == 0 {
		return lead + ": no events in the selected window."
	}
	if len(findings) == 0 {
		return fmt.Sprintf("%s: %d events, no active high-confidence campaign pattern. Risk score %d.", lead, len(events), score)
	}
	top := findings[0]
	entity := "no dominant entity"
	if len(entities) > 0 {
		entity = entities[0].Type + " " + entities[0].Value
	}
	return fmt.Sprintf("%s: %d events, top finding %q (%s, %d%% confidence), dominant pivot %s. Risk score %d.", lead, len(events), top.Title, top.Severity, top.Confidence, entity, score)
}

func shieldEventHaystack(ev SecurityEvent) string {
	parts := []string{ev.ID, ev.Source, ev.Category, string(ev.Severity), ev.Title, ev.Description, strings.Join(ev.Tags, " ")}
	if ev.MITRE != nil {
		parts = append(parts, ev.MITRE.TacticID, ev.MITRE.TacticName, ev.MITRE.TechniqueID, ev.MITRE.TechniqueName)
	}
	if ev.OTContext != nil {
		parts = append(parts, ev.OTContext.Protocol, ev.OTContext.AssetID, ev.OTContext.DeviceType, ev.OTContext.ProcessArea)
	}
	if ev.RawData != nil {
		if raw, err := json.Marshal(ev.RawData); err == nil {
			parts = append(parts, string(raw))
		}
	}
	return strings.ToLower(strings.Join(parts, " "))
}

func eventEntities(ev SecurityEvent) []string {
	set := map[string]bool{}
	hay := shieldEventHaystack(ev)
	for _, ip := range shieldIPRegex.FindAllString(hay, -1) {
		set[ip] = true
	}
	for _, cve := range shieldCVERegex.FindAllString(hay, -1) {
		set[strings.ToUpper(cve)] = true
	}
	if ev.OTContext != nil && ev.OTContext.AssetID != "" {
		set[ev.OTContext.AssetID] = true
	}
	if ev.RawData != nil {
		for _, key := range []string{"source_ip", "src_ip", "destination_ip", "dst_ip", "target_ip", "host", "hostname", "user", "account"} {
			if v := asString(ev.RawData[key]); v != "" {
				set[v] = true
			}
		}
	}
	return sortedKeys(set)
}

func queryInt(r *http.Request, key string, def int) int {
	raw := strings.TrimSpace(r.URL.Query().Get(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

func keywordHits(hay string, keywords []string) int {
	n := 0
	for _, kw := range keywords {
		if strings.Contains(hay, strings.ToLower(kw)) {
			n++
		}
	}
	return n
}

func severityWeight(sev Severity) int {
	switch sev {
	case SeverityCritical:
		return 30
	case SeverityHigh:
		return 18
	case SeverityMedium:
		return 8
	case SeverityLow:
		return 3
	default:
		return 1
	}
}

func severityRank(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	default:
		return 1
	}
}

func severityFromScore(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 65:
		return "high"
	case score >= 35:
		return "medium"
	default:
		return "low"
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func truncateStrings(values []string, max int) []string {
	if max <= 0 || len(values) <= max {
		return values
	}
	return values[:max]
}
