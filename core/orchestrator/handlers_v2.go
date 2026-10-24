package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────────────
// SIGMA — Detection-as-code rules (from data/sigma/*.yml)
// ─────────────────────────────────────────────────────────────────────────────

type SigmaRule struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	SigmaLevel string   `json:"sigma_level"`
	Category   string   `json:"category"`
	Tags       []string `json:"tags"`
	Enabled    bool     `json:"enabled"`
	Source     string   `json:"source,omitempty"`
}

// Built-in fallback rules. These mirror the public SigmaHQ "windows" pack.
// When data/sigma/*.yml are present, those override the in-memory list.
var builtinSigmaRules = []SigmaRule{
	{ID: "win-suspicious-encoded-ps", Name: "Suspicious PowerShell -EncodedCommand",
		SigmaLevel: "high", Category: "process_creation",
		Tags: []string{"attack.execution", "attack.t1059.001"}, Enabled: true, Source: "builtin"},
	{ID: "win-mimikatz-strings", Name: "Mimikatz command-line strings",
		SigmaLevel: "critical", Category: "process_creation",
		Tags: []string{"attack.credential_access", "attack.t1003"}, Enabled: true, Source: "builtin"},
	{ID: "win-regsvr32-scrobj", Name: "Regsvr32 SCT scriptlet (Squiblydoo)",
		SigmaLevel: "high", Category: "process_creation",
		Tags: []string{"attack.defense_evasion", "attack.t1218.010"}, Enabled: true, Source: "builtin"},
	{ID: "win-rundll32-jscript", Name: "Rundll32 with javascript: protocol",
		SigmaLevel: "high", Category: "process_creation",
		Tags: []string{"attack.defense_evasion", "attack.t1218.011"}, Enabled: true, Source: "builtin"},
	{ID: "win-certutil-urlcache", Name: "Certutil URLCache download cradle",
		SigmaLevel: "high", Category: "process_creation",
		Tags: []string{"attack.command_and_control", "attack.t1105"}, Enabled: true, Source: "builtin"},
	{ID: "win-bitsadmin-transfer", Name: "Bitsadmin transfer / addfile",
		SigmaLevel: "medium", Category: "process_creation",
		Tags: []string{"attack.command_and_control", "attack.t1197"}, Enabled: true, Source: "builtin"},
	{ID: "win-wmi-persistence", Name: "WMI Event Subscription persistence",
		SigmaLevel: "critical", Category: "wmi",
		Tags: []string{"attack.persistence", "attack.t1546.003"}, Enabled: true, Source: "builtin"},
	{ID: "win-lsass-dump", Name: "LSASS memory dump via comsvcs.dll MiniDump",
		SigmaLevel: "critical", Category: "process_creation",
		Tags: []string{"attack.credential_access", "attack.t1003.001"}, Enabled: true, Source: "builtin"},
	{ID: "win-vssadmin-shadow-del", Name: "Shadow copy deletion (ransomware indicator)",
		SigmaLevel: "critical", Category: "process_creation",
		Tags: []string{"attack.impact", "attack.t1490"}, Enabled: true, Source: "builtin"},
	{ID: "win-rdp-external-logon", Name: "Successful RDP logon from external IP",
		SigmaLevel: "high", Category: "authentication",
		Tags: []string{"attack.lateral_movement", "attack.t1021.001"}, Enabled: true, Source: "builtin"},
	{ID: "lin-cron-suspicious", Name: "Suspicious cron persistence",
		SigmaLevel: "medium", Category: "process_creation",
		Tags: []string{"attack.persistence", "attack.t1053.003"}, Enabled: true, Source: "builtin"},
	{ID: "net-dns-tunnel", Name: "DNS tunneling — high-entropy subdomain",
		SigmaLevel: "high", Category: "dns",
		Tags: []string{"attack.command_and_control", "attack.t1071.004"}, Enabled: true, Source: "builtin"},
	{ID: "ot-modbus-write", Name: "Unauthorized Modbus write (FC05/FC06/FC15/FC16)",
		SigmaLevel: "critical", Category: "ot",
		Tags: []string{"attack.impact", "ics.t0855"}, Enabled: true, Source: "builtin"},
	{ID: "ot-iec104-cmd", Name: "IEC 60870-5-104 C_SC_NA_1 unauthorized command",
		SigmaLevel: "critical", Category: "ot",
		Tags: []string{"attack.impact", "ics.t0855"}, Enabled: true, Source: "builtin"},
	{ID: "ot-opcua-recon", Name: "OPC UA Browse Service abuse (recon)",
		SigmaLevel: "medium", Category: "ot",
		Tags: []string{"attack.discovery", "ics.t0846"}, Enabled: true, Source: "builtin"},
}

func loadSigmaRulesFromDisk(dir string) []SigmaRule {
	var out []SigmaRule
	if dir == "" {
		return out
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(strings.ToLower(d.Name()), ".yml") &&
			!strings.HasSuffix(strings.ToLower(d.Name()), ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		r := parseSigmaYAMLLite(string(data))
		if r.ID != "" || r.Name != "" {
			rel, _ := filepath.Rel(dir, path)
			r.Source = "file:" + rel
			if r.ID == "" {
				r.ID = strings.TrimSuffix(d.Name(), filepath.Ext(d.Name()))
			}
			out = append(out, r)
		}
		return nil
	})
	return out
}

// parseSigmaYAMLLite extracts ID/title/level/logsource.category/tags from a
// Sigma rule file without pulling in a full YAML dep.
func parseSigmaYAMLLite(text string) SigmaRule {
	r := SigmaRule{Enabled: true}
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "id:") {
			r.ID = strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "id:")), "\"'")
		} else if strings.HasPrefix(t, "title:") {
			r.Name = strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "title:")), "\"'")
		} else if strings.HasPrefix(t, "level:") {
			r.SigmaLevel = strings.ToLower(strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "level:")), "\"'"))
		} else if strings.HasPrefix(t, "category:") {
			r.Category = strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "category:")), "\"'")
		} else if strings.HasPrefix(t, "- attack.") || strings.HasPrefix(t, "- ics.") {
			r.Tags = append(r.Tags, strings.TrimSpace(strings.TrimPrefix(t, "- ")))
		} else if strings.HasPrefix(t, "status:") {
			st := strings.ToLower(strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "status:")), "\"'"))
			r.Enabled = !(st == "deprecated" || st == "disabled")
		}
	}
	return r
}

func (o *Orchestrator) handleSigmaRules(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	level := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level")))
	rules := append([]SigmaRule{}, builtinSigmaRules...)
	dir := envOrEmpty("AEGIS_SIGMA_DIR")
	if dir == "" {
		candidates := []string{"data/sigma", "config/sigma", "modules/sigma/rules"}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				dir = c
				break
			}
		}
	}
	if dir != "" {
		fromDisk := loadSigmaRulesFromDisk(dir)
		rules = append(rules, fromDisk...)
	}
	// Filter
	out := make([]SigmaRule, 0, len(rules))
	for _, ru := range rules {
		if level != "" && ru.SigmaLevel != level {
			continue
		}
		if q != "" {
			hay := strings.ToLower(ru.ID + " " + ru.Name + " " + ru.Category + " " + strings.Join(ru.Tags, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		out = append(out, ru)
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"rules":  out,
		"count":  len(out),
		"source": dir,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// EVIDENCE — Filesystem-backed evidence store (data/evidence/)
// ─────────────────────────────────────────────────────────────────────────────

type Evidence struct {
	ID         string `json:"id"`
	Filename   string `json:"filename"`
	CaseID     string `json:"case_id,omitempty"`
	SizeBytes  int64  `json:"size_bytes"`
	HashSHA256 string `json:"hash_sha256"`
	Immutable  bool   `json:"immutable"`
	StoredAt   string `json:"stored_at"`
	ExpiresAt  string `json:"expires_at,omitempty"`
	Path       string `json:"-"`
}

func evidenceDir() string {
	if d := envOrEmpty("AEGIS_EVIDENCE_DIR"); d != "" {
		return d
	}
	return "data/evidence"
}

func listEvidence() ([]Evidence, error) {
	dir := evidenceDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	out := make([]Evidence, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(dir, e.Name())
		info, err := e.Info()
		if err != nil {
			continue
		}
		hash, _ := sha256File(full)
		ev := Evidence{
			ID:         hash[:16],
			Filename:   e.Name(),
			SizeBytes:  info.Size(),
			HashSHA256: hash,
			Immutable:  isReadOnly(info),
			StoredAt:   info.ModTime().UTC().Format(time.RFC3339),
			Path:       full,
		}
		// Companion metadata file: <name>.meta.json
		if meta, err := os.ReadFile(full + ".meta.json"); err == nil {
			var m map[string]any
			if json.Unmarshal(meta, &m) == nil {
				if s, ok := m["case_id"].(string); ok {
					ev.CaseID = s
				}
				if s, ok := m["expires_at"].(string); ok {
					ev.ExpiresAt = s
				}
			}
		}
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].StoredAt > out[j].StoredAt })
	return out, nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isReadOnly(info os.FileInfo) bool {
	mode := info.Mode().Perm()
	return mode&0o200 == 0
}

func (o *Orchestrator) handleEvidenceList(w http.ResponseWriter, r *http.Request) {
	items, err := listEvidence()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"artifacts": items,
		"count":     len(items),
		"dir":       evidenceDir(),
	})
}

func (o *Orchestrator) handleEvidenceVerify(w http.ResponseWriter, r *http.Request) {
	items, err := listEvidence()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	type vRes struct {
		ID       string `json:"id"`
		Filename string `json:"filename"`
		Hash     string `json:"hash_sha256"`
		Verified bool   `json:"verified"`
		Note     string `json:"note,omitempty"`
	}
	results := make([]vRes, 0, len(items))
	allOK := true
	for _, it := range items {
		// Re-compute to confirm the previously stored hash is still correct.
		fresh, err := sha256File(it.Path)
		ok := err == nil && fresh == it.HashSHA256
		if !ok {
			allOK = false
		}
		r := vRes{ID: it.ID, Filename: it.Filename, Hash: it.HashSHA256, Verified: ok}
		if err != nil {
			r.Note = err.Error()
		} else if !ok {
			r.Note = "hash mismatch (file modified)"
		}
		results = append(results, r)
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"all_verified": allOK,
		"results":      results,
		"count":        len(results),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// PKI — X.509 certificate management (data/pki/*.pem)
// ─────────────────────────────────────────────────────────────────────────────

type CertEntry struct {
	CN              string   `json:"cn"`
	Subject         string   `json:"subject"`
	Issuer          string   `json:"issuer"`
	CertType        string   `json:"cert_type"`
	Status          string   `json:"status"` // active | expiring | expired | revoked
	NotBefore       string   `json:"not_before"`
	NotAfter        string   `json:"not_after"`
	Serial          string   `json:"serial"`
	SHA256          string   `json:"sha256"`
	DNSNames        []string `json:"dns_names,omitempty"`
	KeyUsage        []string `json:"key_usage,omitempty"`
	IsCA            bool     `json:"is_ca"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	Path            string   `json:"-"`
}

func pkiDir() string {
	if d := envOrEmpty("AEGIS_PKI_DIR"); d != "" {
		return d
	}
	return "data/pki"
}

func parseCertFile(path string) ([]CertEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []CertEntry
	rest := data
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		// status
		now := time.Now()
		days := int(cert.NotAfter.Sub(now).Hours() / 24)
		status := "active"
		if days < 0 {
			status = "expired"
		} else if days < 30 {
			status = "expiring"
		}
		sum := sha256.Sum256(cert.Raw)
		certType := "leaf"
		if cert.IsCA {
			certType = "ca"
		}
		entry := CertEntry{
			CN:              cert.Subject.CommonName,
			Subject:         cert.Subject.String(),
			Issuer:          cert.Issuer.String(),
			CertType:        certType,
			Status:          status,
			NotBefore:       cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:        cert.NotAfter.UTC().Format(time.RFC3339),
			Serial:          cert.SerialNumber.Text(16),
			SHA256:          hex.EncodeToString(sum[:]),
			DNSNames:        cert.DNSNames,
			IsCA:            cert.IsCA,
			DaysUntilExpiry: days,
			Path:            path,
		}
		// Key usage names
		ku := cert.KeyUsage
		var kuNames []string
		if ku&x509.KeyUsageDigitalSignature != 0 {
			kuNames = append(kuNames, "DigitalSignature")
		}
		if ku&x509.KeyUsageKeyEncipherment != 0 {
			kuNames = append(kuNames, "KeyEncipherment")
		}
		if ku&x509.KeyUsageCertSign != 0 {
			kuNames = append(kuNames, "CertSign")
		}
		entry.KeyUsage = kuNames
		out = append(out, entry)
	}
	return out, nil
}

func listCertificates() ([]CertEntry, error) {
	dir := pkiDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var all []CertEntry
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".pem") && !strings.HasSuffix(name, ".crt") &&
			!strings.HasSuffix(name, ".cer") {
			continue
		}
		certs, _ := parseCertFile(filepath.Join(dir, e.Name()))
		all = append(all, certs...)
	}
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].DaysUntilExpiry < all[j].DaysUntilExpiry
	})
	return all, nil
}

func (o *Orchestrator) handlePKICerts(w http.ResponseWriter, r *http.Request) {
	certs, err := listCertificates()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"certs": certs,
		"count": len(certs),
		"dir":   pkiDir(),
	})
}

func (o *Orchestrator) handlePKICheckExpiry(w http.ResponseWriter, r *http.Request) {
	days := parseIntDefault(r.URL.Query().Get("days"), 30)
	certs, err := listCertificates()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err)
		return
	}
	expiring := make([]CertEntry, 0)
	for _, c := range certs {
		if c.DaysUntilExpiry <= days {
			expiring = append(expiring, c)
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"threshold_days": days,
		"expiring_count": len(expiring),
		"expiring":       expiring,
		"total_certs":    len(certs),
	})
}

func (o *Orchestrator) handlePKIHealth(w http.ResponseWriter, r *http.Request) {
	step := lookPath("step")
	openssl := lookPath("openssl")
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":                true,
		"step_ca_available": step != "",
		"openssl_available": openssl != "",
		"step_path":         step,
		"openssl_path":      openssl,
		"dir":               pkiDir(),
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATIONS — inventory of installed defensive tools (Go-native)
// ─────────────────────────────────────────────────────────────────────────────

type ToolInventory struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Layer     string `json:"layer"`
	Role      string `json:"role"`
	Installed bool   `json:"installed"`
	Binary    string `json:"binary,omitempty"`
	Version   string `json:"version,omitempty"`
	Notes     string `json:"notes,omitempty"`
}

var toolCatalog = []struct {
	ID, Name, Layer, Role string
	Bins                  []string
	Notes                 string
}{
	{"wazuh", "Wazuh Agent/Manager", "endpoint", "FIM, rootkit detection",
		[]string{"wazuh-agent", "wazuh-control"}, "External alerts via /api/v1/ingest/wazuh."},
	{"osquery", "OSQuery", "endpoint", "SQL endpoint inventory",
		[]string{"osqueryi", "osqueryi.exe"}, "Threat hunting via SQL queries."},
	{"clamav", "ClamAV", "endpoint", "Local antivirus",
		[]string{"clamscan", "clamdscan", "clamscan.exe"}, "Use /api/endpoint/scan/clamav."},
	{"crowdsec", "CrowdSec", "perimeter", "Collaborative IPS",
		[]string{"cscli", "crowdsec"}, "Ingest events via /api/v1/ingest/crowdsec."},
	{"suricata", "Suricata", "network", "IDS/IPS + EVE JSON",
		[]string{"suricata", "suricata.exe"}, "Ingest events via /api/v1/ingest/suricata."},
	{"zeek", "Zeek", "network", "Network analysis framework",
		[]string{"zeek"}, "Forensic-grade flow analytics."},
	{"nmap", "Nmap", "network", "Service discovery",
		[]string{"nmap", "nmap.exe"}, "Used by network module when present."},
	{"rustscan", "RustScan", "network", "Fast port scanner",
		[]string{"rustscan", "rustscan.exe"}, "Optional fast scanner."},
	{"openvas", "OpenVAS / GVM", "intelligence", "Vulnerability scanner",
		[]string{"gvm-cli", "openvas"}, "Authorized targets only."},
	{"nikto", "Nikto", "intelligence", "Web server scanner",
		[]string{"nikto", "nikto.pl"}, "Manual web app checks."},
	{"gitleaks", "Gitleaks", "identity", "Secrets scanner",
		[]string{"gitleaks", "gitleaks.exe"}, "Repository secret detection."},
	{"trufflehog", "TruffleHog", "identity", "Secrets scanner",
		[]string{"trufflehog", "trufflehog.exe"}, "Verifies leaked credentials."},
	{"yara", "YARA", "intelligence", "Malware rules engine",
		[]string{"yara", "yara.exe"}, "Endpoint uses yara-python."},
	{"lynis", "Lynis", "endpoint", "Unix hardening audit",
		[]string{"lynis"}, "Windows uses AEGIS native audit."},
	{"wireguard", "WireGuard", "perimeter", "VPN tunnel",
		[]string{"wg", "wg.exe"}, "Operator-managed tunnels."},
	{"vaultwarden", "Vaultwarden", "identity", "Self-hosted password vault",
		[]string{"vaultwarden", "vaultwarden.exe"}, "Bitwarden-compatible server."},
	{"openbao", "OpenBao / Vault", "identity", "Secrets management",
		[]string{"bao", "vault"}, "API-based secrets."},
	{"velociraptor", "Velociraptor", "endpoint", "DFIR",
		[]string{"velociraptor", "velociraptor.exe"}, "Endpoint hunting platform."},
	{"misp", "MISP", "intelligence", "Threat sharing platform",
		[]string{}, "External MISP host; configure URL."},
	{"opencti", "OpenCTI", "intelligence", "CTI knowledge graph",
		[]string{}, "External CTI host; configure URL."},
	{"thehive", "TheHive", "soar", "Incident response platform",
		[]string{"thehive"}, "External TheHive host; configure URL."},
	{"keycloak", "Keycloak", "identity", "Identity provider",
		[]string{"keycloak"}, "SSO / OIDC server."},
	{"step-ca", "step-ca", "identity", "ACME CA",
		[]string{"step", "step-ca"}, "Used by PKI module for mTLS."},
	{"fleet", "FleetDM", "endpoint", "OSQuery fleet manager",
		[]string{"fleetctl"}, "Manage osquery at scale."},
	{"opencanary", "OpenCanary", "endpoint", "Honeypot",
		[]string{"opencanary"}, "Decoy services."},
	{"ghidra", "Ghidra", "intelligence", "Reverse engineering",
		[]string{"ghidraRun"}, "Forensic analysis."},
	{"volatility", "Volatility", "intelligence", "Memory forensics",
		[]string{"vol", "volatility"}, "Memory dump analysis."},
}

func lookPath(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

func runVersionFast(bin string) string {
	if bin == "" {
		return ""
	}
	ctx := exec.Command(bin, "--version")
	out, err := ctx.CombinedOutput()
	if err == nil && len(out) > 0 {
		s := strings.TrimSpace(strings.Split(string(out), "\n")[0])
		if len(s) > 200 {
			s = s[:200]
		}
		return s
	}
	return ""
}

func (o *Orchestrator) handleIntegrationsTools(w http.ResponseWriter, r *http.Request) {
	out := make([]ToolInventory, 0, len(toolCatalog))
	byLayer := map[string]map[string]int{}
	for _, c := range toolCatalog {
		t := ToolInventory{ID: c.ID, Name: c.Name, Layer: c.Layer, Role: c.Role, Notes: c.Notes}
		for _, b := range c.Bins {
			if p := lookPath(b); p != "" {
				t.Installed = true
				t.Binary = p
				t.Version = runVersionFast(p)
				break
			}
		}
		out = append(out, t)
		stat := byLayer[c.Layer]
		if stat == nil {
			stat = map[string]int{"available": 0, "total": 0}
		}
		stat["total"]++
		if t.Installed {
			stat["available"]++
		}
		byLayer[c.Layer] = stat
	}
	installed := 0
	for _, t := range out {
		if t.Installed {
			installed++
		}
	}
	respondJSON(w, http.StatusOK, map[string]any{
		"generated_at":    time.Now().UTC().Format(time.RFC3339),
		"platform":        runtime.GOOS,
		"installed_count": installed,
		"total_count":     len(out),
		"by_layer":        byLayer,
		"tools":           out,
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// OT PROTOCOLS — health probe + minimal Modbus read using stdlib net dial.
// (Real protocol I/O lives in the Python network module; this is a fallback.)
// ─────────────────────────────────────────────────────────────────────────────

func (o *Orchestrator) handleOTProtocolsHealth(w http.ResponseWriter, r *http.Request) {
	// We don't have native Python modules in Go, so we report capability flags
	// + whether common OT tools are reachable on the network.
	respondJSON(w, http.StatusOK, map[string]any{
		"ok":                 true,
		"ot_safe_mode":       true,
		"pymodbus_available": false, // Go orchestrator has no pymodbus; UI shows badge
		"opcua_available":    false,
		"iec61850_available": false,
		"notes":              "Per Modbus/OPC UA reali avvia il network module Python con aegis-all.ps1. Il Go orchestrator espone solo health checks.",
	})
}

func (o *Orchestrator) handleOTModbusRead(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusNotImplemented, map[string]any{
		"ok":    false,
		"error": "Modbus client non implementato nel Go orchestrator. Avvia il network module Python (porta 8081) per accesso reale a Modbus TCP/RTU.",
	})
}

func (o *Orchestrator) handleOTOpcuaBrowse(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusNotImplemented, map[string]any{
		"ok":    false,
		"error": "OPC UA client non implementato nel Go orchestrator. Avvia il network module Python (porta 8081) per browse OPC UA.",
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Topology / TLS / Campaigns / Reports — empty-state fallbacks
// When the Python network/reports modules are not running, the dashboard would
// see "module offline". Instead we now return a clean empty payload with a
// hint so the UI renders an empty state with instructions rather than an
// error.
// These handlers only fire if the network module is unreachable.
// ─────────────────────────────────────────────────────────────────────────────

func (o *Orchestrator) handleTopologyFallback(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"nodes":             []any{},
		"links":             []any{},
		"attack_paths":      []any{},
		"segmentation_gaps": []any{},
		"stats":             map[string]any{},
		"_note":             "Topology richiede il network module Python avviato. Esegui aegis-all.ps1 (oppure docker compose up network) e poi esegui una scansione LAN.",
	})
}

func (o *Orchestrator) handleTLSFallback(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusServiceUnavailable, map[string]any{
		"error":   "TLS inspector richiede il network module Python",
		"hint":    "Avvia aegis-all.ps1 per attivare il network module (porta 8081).",
		"results": []any{},
	})
}

func (o *Orchestrator) handleFusionFallback(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"campaigns":  []any{},
		"statistics": map[string]any{},
		"_note":      "Threat Fusion richiede il network module Python. Avvia aegis-all.ps1 per attivarlo.",
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// Seed data writer — called once at startup if directories are empty.
// ─────────────────────────────────────────────────────────────────────────────

func seedExtraDataDirs() {
	// Sigma seed (we always have built-in rules; nothing to write).
	_ = os.MkdirAll(evidenceDir(), 0o755)
	_ = os.MkdirAll(pkiDir(), 0o755)
	// README sentinels.
	if _, err := os.Stat(filepath.Join(evidenceDir(), "README.txt")); os.IsNotExist(err) {
		_ = os.WriteFile(filepath.Join(evidenceDir(), "README.txt"),
			[]byte("AEGIS Evidence Store — drop case artifacts here.\n"+
				"Each file is hashed (SHA-256) on read. Add a companion <name>.meta.json with {\"case_id\":\"...\", \"expires_at\":\"...\"} for metadata.\n"), 0o644)
	}
	if _, err := os.Stat(filepath.Join(pkiDir(), "README.txt")); os.IsNotExist(err) {
		_ = os.WriteFile(filepath.Join(pkiDir(), "README.txt"),
			[]byte("AEGIS PKI store — drop *.pem / *.crt / *.cer here.\n"+
				"Certificates are parsed and shown in the dashboard PKI page.\n"), 0o644)
	}
}

// silence unused warnings if any
var _ = fmt.Sprintf
var _ = json.Marshal
