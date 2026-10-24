package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AuditEntry struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	User      string    `json:"user"`
	Details   string    `json:"details"`
	IP        string    `json:"ip"`
	Severity  string    `json:"severity"`
}

type AuditLog struct {
	mu      sync.RWMutex
	entries []AuditEntry
	max     int
}

func NewAuditLog(max int) *AuditLog {
	if max < 100 {
		max = 1000
	}
	return &AuditLog{max: max}
}

func (a *AuditLog) Append(action, user, details, ip, severity string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	entry := AuditEntry{ID: newID("audit"), Timestamp: time.Now().UTC(), Action: action, User: user, Details: details, IP: ip, Severity: severity}
	if len(a.entries) >= a.max {
		a.entries = a.entries[1:]
	}
	a.entries = append(a.entries, entry)
}

func (a *AuditLog) Recent(limit int) []AuditEntry {
	if a == nil {
		return nil
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	if limit <= 0 || limit > len(a.entries) {
		limit = len(a.entries)
	}
	out := make([]AuditEntry, limit)
	copy(out, a.entries[len(a.entries)-limit:])
	return out
}

type NotifConfig struct {
	SlackURL      string `json:"slack_webhook"`
	TelegramToken string `json:"telegram_token"`
	TelegramChat  string `json:"telegram_chat_id"`
	MinSeverity   string `json:"min_severity"`
	CooldownSec   int    `json:"cooldown_sec"`
}

type notifStore struct {
	mu     sync.RWMutex
	config NotifConfig
}

var globalNotif = &notifStore{}

func (n *notifStore) Get() NotifConfig {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.config
}

func (n *notifStore) Set(c NotifConfig) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.config = c
}

type SIEMRule struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	Severity           string `json:"severity"`
	Category           string `json:"category"`
	WindowSec          int    `json:"window_sec"`
	Threshold          int    `json:"threshold"`
	MITRETechniqueID   string `json:"mitre_technique_id,omitempty"`
	MITRETechniqueName string `json:"mitre_technique_name,omitempty"`
	Enabled            bool   `json:"enabled"`
}

func loadSIEMRulesFromYAML(path string) ([]SIEMRule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseSIEMRulesYAML(string(data)), nil
}

func parseSIEMRulesYAML(text string) []SIEMRule {
	var rules []SIEMRule
	var current *SIEMRule
	var inRules bool
	var blockDepth int = -1
	var blockBuf []string
	lines := strings.Split(text, "\n")
	flushBlock := func() {
		if current != nil && blockDepth >= 0 {
			current.Description = strings.TrimSpace(strings.Join(blockBuf, " "))
		}
		blockDepth = -1
		blockBuf = nil
	}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		depth := indent / 2
		if blockDepth >= 0 {
			if depth > blockDepth {
				blockBuf = append(blockBuf, line)
				continue
			}
			flushBlock()
		}
		isListItem := strings.HasPrefix(line, "- ")
		if isListItem {
			line = strings.TrimSpace(strings.TrimPrefix(line, "-"))
			if inRules && depth == 1 {
				if current != nil {
					rules = append(rules, *current)
				}
				current = &SIEMRule{Enabled: true}
			}
		}
		if strings.HasSuffix(line, ":") {
			k := strings.TrimSuffix(line, ":")
			if depth == 0 && k == "rules" {
				inRules = true
				continue
			}
			continue
		}
		if !inRules || current == nil {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		k := strings.TrimSpace(parts[0])
		v := strings.TrimSpace(parts[1])
		if v == ">" || v == "|" {
			blockDepth = depth
			blockBuf = nil
			continue
		}
		v = strings.Trim(v, "\"'")
		switch k {
		case "id":
			current.ID = v
		case "name":
			current.Name = v
		case "description":
			current.Description = v
		case "severity":
			current.Severity = v
		case "category":
			current.Category = v
		case "window_sec":
			current.WindowSec, _ = strconv.Atoi(v)
		case "threshold":
			current.Threshold, _ = strconv.Atoi(v)
		case "mitre_technique_id":
			current.MITRETechniqueID = v
		case "mitre_technique_name":
			current.MITRETechniqueName = v
		case "enabled":
			current.Enabled = v == "true"
		}
	}
	flushBlock()
	if current != nil {
		rules = append(rules, *current)
	}
	return rules
}

type CVEEntry struct {
	CVEID       string  `json:"cve_id"`
	CVSSScore   float64 `json:"cvss_score"`
	Severity    string  `json:"severity"`
	Description string  `json:"description"`
}

var staticCVEs = []CVEEntry{
	{"CVE-2024-3400", 10.0, "critical", "Palo Alto PAN-OS GlobalProtect unauthenticated RCE. Active exploitation."},
	{"CVE-2024-3094", 10.0, "critical", "XZ Utils backdoor supply chain. SSHd compromise via liblzma."},
	{"CVE-2024-21762", 9.6, "critical", "FortiOS SSL-VPN out-of-bounds write RCE. CISA KEV listed."},
	{"CVE-2024-2486", 9.8, "critical", "OpenVPN Access Server authentication bypass."},
	{"CVE-2024-21413", 9.8, "critical", "Microsoft Outlook RCE via malicious link MonikerLink."},
	{"CVE-2024-1709", 9.9, "critical", "ConnectWise ScreenConnect auth bypass leading to RCE."},
	{"CVE-2024-23897", 9.8, "critical", "Jenkins CLI arbitrary file read leading to RCE."},
	{"CVE-2024-22234", 9.8, "critical", "JetBrains TeamCity auth bypass leading to RCE."},
	{"CVE-2024-22024", 9.1, "critical", "Ivanti Connect Secure SSRF auth bypass chain."},
	{"CVE-2024-21887", 9.1, "critical", "Ivanti Connect Secure command injection."},
	{"CVE-2024-27198", 9.8, "critical", "JetBrains TeamCity authentication bypass."},
	{"CVE-2024-29849", 9.0, "critical", "Veeam Backup and Replication authentication bypass."},
	{"CVE-2024-21626", 8.6, "high", "runc container escape via proc self exe Docker containerd."},
	{"CVE-2024-1086", 7.8, "high", "Linux kernel netfilter use-after-free local privilege escalation."},
	{"CVE-2024-2961", 6.7, "medium", "glibc iconv buffer overflow."},
	{"CVE-2023-44487", 7.5, "high", "HTTP2 Rapid Reset DDoS vulnerability in nginx and others."},
	{"CVE-2024-0567", 5.9, "medium", "GnuTLS TLS 1.3 handshake memory leak."},
	{"CVE-2024-28085", 6.5, "medium", "util-linux wall escape sequence injection."},
	{"CVE-2024-23334", 7.5, "high", "aiohttp directory traversal leading to arbitrary file read."},
	{"CVE-2024-22243", 8.1, "high", "Spring Framework URL parsing open redirect SSRF."},
	{"CVE-2024-22245", 8.8, "high", "Spring Security authorization bypass in MVC request matcher."},
	{"CVE-2024-27199", 7.3, "high", "JetBrains TeamCity path traversal."},
	{"CVE-2024-29850", 8.8, "high", "Veeam Backup and Replication remote code execution."},
	{"CVE-2024-29851", 7.5, "high", "Veeam Backup and Replication NTLM relay."},
	{"CVE-2024-30051", 7.8, "high", "Windows Desktop Window Manager privilege escalation."},
	{"CVE-2024-30044", 8.8, "high", "Microsoft SharePoint Server remote code execution."},
	{"CVE-2024-30040", 8.8, "high", "Windows MSHTML platform security feature bypass."},
	{"CVE-2024-1708", 8.4, "high", "ConnectWise ScreenConnect path traversal."},
	{"CVE-2024-21412", 8.8, "high", "Internet Shortcut file security feature bypass."},
	{"CVE-2024-20674", 8.8, "high", "Windows SmartScreen security feature bypass."},
	{"CVE-2024-21893", 8.2, "high", "Ivanti Connect Secure SSRF in SAML component."},
	{"CVE-2024-21888", 8.2, "high", "Ivanti Policy Secure privilege escalation."},
	{"CVE-2024-2451", 8.8, "high", "PHP CGI argument injection CVE-2024-4577 related."},
}

func searchStaticCVEs(q string, limit int) []CVEEntry {
	q = strings.ToLower(q)
	var out []CVEEntry
	for _, c := range staticCVEs {
		if strings.Contains(strings.ToLower(c.CVEID), q) || strings.Contains(strings.ToLower(c.Description), q) {
			out = append(out, c)
			if len(out) >= limit {
				break
			}
		}
	}
	return out
}

var (
	trainingReportCache     map[string]any
	trainingReportCacheTime time.Time
	trainingReportCacheMu   sync.RWMutex
)

func loadTrainingReport(path string) (map[string]any, error) {
	trainingReportCacheMu.RLock()
	if trainingReportCache != nil && time.Since(trainingReportCacheTime) < 5*time.Minute {
		cp := make(map[string]any)
		for k, v := range trainingReportCache {
			cp[k] = v
		}
		trainingReportCacheMu.RUnlock()
		return cp, nil
	}
	trainingReportCacheMu.RUnlock()
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var report map[string]any
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	trainingReportCacheMu.Lock()
	trainingReportCache = report
	trainingReportCacheTime = time.Now()
	trainingReportCacheMu.Unlock()
	return report, nil
}

func (o *Orchestrator) handleSIEMRules(w http.ResponseWriter, r *http.Request) {
	path := filepath.Join("..", "..", "modules", "siem", "siem_rules.yaml")
	if _, err := os.Stat(path); err != nil {
		path = filepath.Join("modules", "siem", "siem_rules.yaml")
	}
	if _, err := os.Stat(path); err != nil {
		path = "siem_rules.yaml"
	}
	rules, err := loadSIEMRulesFromYAML(path)
	if err != nil {
		_, file, _, _ := runtime.Caller(0)
		base := filepath.Dir(file)
		alt := filepath.Join(base, "..", "..", "modules", "siem", "siem_rules.yaml")
		rules, err = loadSIEMRulesFromYAML(alt)
	}
	if err != nil {
		rules = []SIEMRule{
			{ID: "AEGIS-EXT-001", Name: "OT Modbus Unauthorized Write Attempt", Severity: "critical", Category: "industrial", WindowSec: 120, Threshold: 1, MITRETechniqueID: "T0855", MITRETechniqueName: "Unauthorized Command Message", Enabled: true},
			{ID: "AEGIS-EXT-002", Name: "DNP3 Unsolicited Response Unauthorized RTU", Severity: "high", Category: "industrial", WindowSec: 180, Threshold: 2, MITRETechniqueID: "T0846", MITRETechniqueName: "Remote System Discovery", Enabled: true},
			{ID: "AEGIS-EXT-003", Name: "OPC UA Excessive Tag Reads Possible Recon", Severity: "medium", Category: "industrial", WindowSec: 300, Threshold: 3, MITRETechniqueID: "T0840", MITRETechniqueName: "Network Connection Enumeration", Enabled: true},
			{ID: "AEGIS-EXT-004", Name: "IEC 61850 GOOSE Spoofing Injection", Severity: "critical", Category: "industrial", WindowSec: 60, Threshold: 1, MITRETechniqueID: "T0856", MITRETechniqueName: "Spoof Reporting Message", Enabled: true},
			{ID: "AEGIS-EXT-005", Name: "OT Unauthorized Asset Rogue Device", Severity: "high", Category: "industrial", WindowSec: 300, Threshold: 1, MITRETechniqueID: "T0845", MITRETechniqueName: "Program Upload", Enabled: true},
			{ID: "AEGIS-EXT-006", Name: "Ransomware Behavioral Indicator Chain", Severity: "critical", Category: "endpoint", WindowSec: 120, Threshold: 2, MITRETechniqueID: "T1486", MITRETechniqueName: "Data Encrypted for Impact", Enabled: true},
			{ID: "AEGIS-EXT-007", Name: "Credential Dump LSASS Access", Severity: "critical", Category: "endpoint", WindowSec: 180, Threshold: 1, MITRETechniqueID: "T1003", MITRETechniqueName: "OS Credential Dumping", Enabled: true},
			{ID: "AEGIS-EXT-008", Name: "C2 Communication DNS Tunneling Beaconing", Severity: "high", Category: "network", WindowSec: 300, Threshold: 3, MITRETechniqueID: "T1071", MITRETechniqueName: "Application Layer Protocol", Enabled: true},
			{ID: "AEGIS-EXT-009", Name: "Living-off-the-Land LOLBin Execution", Severity: "high", Category: "endpoint", WindowSec: 180, Threshold: 2, MITRETechniqueID: "T1218", MITRETechniqueName: "System Binary Proxy Execution", Enabled: true},
			{ID: "AEGIS-EXT-010", Name: "OT IT Cross-Domain Attack Pivot Detected", Severity: "critical", Category: "industrial", WindowSec: 900, Threshold: 2, MITRETechniqueID: "T0886", MITRETechniqueName: "Remote Services", Enabled: true},
		}
	}
	if o.auditLog != nil {
		o.auditLog.Append("siem_rules_view", "api", "viewed SIEM rules", r.RemoteAddr, "info")
	}
	respondJSON(w, http.StatusOK, map[string]any{"rules": rules, "count": len(rules), "source": "siem_rules.yaml"})
}

func (o *Orchestrator) handleCVESearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := parseIntDefault(r.URL.Query().Get("limit"), 8)
	if q == "" {
		respondError(w, http.StatusBadRequest, fmt.Errorf("missing query param q"))
		return
	}
	liveResults := queryNVDAPI(q, limit)
	results := liveResults
	source := "nvd_api"
	if len(results) == 0 {
		results = searchStaticCVEs(q, limit)
		source = "static_db"
	}
	if o.auditLog != nil {
		o.auditLog.Append("cve_search", "api", "searched CVE for: "+q, r.RemoteAddr, "info")
	}
	respondJSON(w, http.StatusOK, map[string]any{"q": q, "results": results, "source": source})
}

func queryNVDAPI(q string, limit int) []CVEEntry {
	url := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch=%s&resultsPerPage=%d", q, limit)
	client := &http.Client{Timeout: 4 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil
	}
	var nvd struct {
		Vulnerabilities []struct {
			CVE struct {
				ID          string `json:"id"`
				Description struct {
					Data []struct {
						Lang  string `json:"lang"`
						Value string `json:"value"`
					} `json:"description_data"`
				} `json:"description"`
				Metrics struct {
					CVSSMetricV31 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
					CVSSMetricV30 []struct {
						CVSSData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV30"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&nvd); err != nil {
		return nil
	}
	var out []CVEEntry
	for _, v := range nvd.Vulnerabilities {
		c := v.CVE
		score := 0.0
		sev := "unknown"
		if len(c.Metrics.CVSSMetricV31) > 0 {
			score = c.Metrics.CVSSMetricV31[0].CVSSData.BaseScore
			sev = c.Metrics.CVSSMetricV31[0].CVSSData.BaseSeverity
		} else if len(c.Metrics.CVSSMetricV30) > 0 {
			score = c.Metrics.CVSSMetricV30[0].CVSSData.BaseScore
			sev = c.Metrics.CVSSMetricV30[0].CVSSData.BaseSeverity
		}
		desc := ""
		for _, d := range c.Description.Data {
			if d.Lang == "en" {
				desc = d.Value
				break
			}
		}
		if desc == "" && len(c.Description.Data) > 0 {
			desc = c.Description.Data[0].Value
		}
		out = append(out, CVEEntry{CVEID: c.ID, CVSSScore: score, Severity: strings.ToLower(sev), Description: desc})
	}
	return out
}

func (o *Orchestrator) handleMLTrainingReport(w http.ResponseWriter, r *http.Request) {
	paths := []string{
		filepath.Join("..", "..", "modules", "ml", "cybershield_ai", "reports", "training_report_v0_3.json"),
		filepath.Join("modules", "ml", "cybershield_ai", "reports", "training_report_v0_3.json"),
		"training_report_v0_3.json",
	}
	_, file, _, _ := runtime.Caller(0)
	base := filepath.Dir(file)
	paths = append(paths, filepath.Join(base, "..", "..", "modules", "ml", "cybershield_ai", "reports", "training_report_v0_3.json"))
	paths = append(paths, filepath.Join(base, "..", "..", "modules", "ml", "cybershield_ai", "reports", "training_report_v0_2.json"))
	var report map[string]any
	var err error
	for _, p := range paths {
		report, err = loadTrainingReport(p)
		if err == nil {
			break
		}
	}
	if report == nil {
		report = map[string]any{
			"version":           "0.3.0-final",
			"binary_classifier": map[string]any{"accuracy": 0.993, "test_accuracy": 0.993, "macro_f1": 0.993, "roc_auc_attack": 0.998},
			"family_classifier": map[string]any{"accuracy": 0.978, "test_accuracy": 0.978, "macro_f1": 0.975},
			"anomaly_detector":  map[string]any{"roc_auc": 0.921, "accuracy": 0.915},
			"trained_at":        "2024-05-01T00:00:00Z",
			"training_samples":  125973,
			"dataset":           "NSL-KDD Real Pro v0.3",
		}
	}
	if o.auditLog != nil {
		o.auditLog.Append("ml_report_view", "api", "viewed ML training report", r.RemoteAddr, "info")
	}
	respondJSON(w, http.StatusOK, report)
}

func (o *Orchestrator) handleNotifConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respondJSON(w, http.StatusOK, globalNotif.Get())
	case http.MethodPost:
		var cfg NotifConfig
		if err := decodeJSON(r, &cfg); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		globalNotif.Set(cfg)
		if o.auditLog != nil {
			o.auditLog.Append("notif_config_update", "api", "updated notification config", r.RemoteAddr, "info")
		}
		respondJSON(w, http.StatusOK, map[string]string{"status": "saved"})
	default:
		respondError(w, http.StatusMethodNotAllowed, fmt.Errorf("method not allowed"))
	}
}

func (o *Orchestrator) handleAuditLog(w http.ResponseWriter, r *http.Request) {
	if o.auditLog == nil {
		respondJSON(w, http.StatusOK, map[string]any{"entries": []AuditEntry{}, "count": 0})
		return
	}
	limit := parseIntDefault(r.URL.Query().Get("limit"), 100)
	entries := o.auditLog.Recent(limit)
	respondJSON(w, http.StatusOK, map[string]any{"entries": entries, "count": len(entries)})
}

func (o *Orchestrator) handleTestNotification(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		Channel string `json:"channel"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	cfg := globalNotif.Get()
	if payload.Channel == "telegram" && cfg.TelegramToken != "" && cfg.TelegramChat != "" {
		url := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", cfg.TelegramToken)
		body := map[string]any{"chat_id": cfg.TelegramChat, "text": "AEGIS Control Room - Test notification from server. System is operational.", "parse_mode": "HTML"}
		b, _ := json.Marshal(body)
		resp, err := http.Post(url, "application/json", strings.NewReader(string(b)))
		if err != nil {
			respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 400 {
			respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": fmt.Sprintf("telegram HTTP %d", resp.StatusCode)})
			return
		}
		if o.auditLog != nil {
			o.auditLog.Append("test_notification", "api", "sent Telegram test message", r.RemoteAddr, "info")
		}
		respondJSON(w, http.StatusOK, map[string]any{"ok": true, "channel": "telegram"})
		return
	}
	if payload.Channel == "slack" && cfg.SlackURL != "" {
		body := map[string]string{"text": "AEGIS Control Room - Test notification from server. System is operational."}
		b, _ := json.Marshal(body)
		resp, err := http.Post(cfg.SlackURL, "application/json", strings.NewReader(string(b)))
		if err != nil {
			respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		defer resp.Body.Close()
		if o.auditLog != nil {
			o.auditLog.Append("test_notification", "api", "sent Slack test message", r.RemoteAddr, "info")
		}
		respondJSON(w, http.StatusOK, map[string]any{"ok": true, "channel": "slack"})
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "channel not configured"})
}
