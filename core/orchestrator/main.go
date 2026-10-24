package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

//go:embed dashboard/*
var dashboardFiles embed.FS

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type MITREAttack struct {
	TacticID      string `json:"tactic_id,omitempty"`
	TacticName    string `json:"tactic_name,omitempty"`
	TechniqueID   string `json:"technique_id,omitempty"`
	TechniqueName string `json:"technique_name,omitempty"`
	IsICS         bool   `json:"is_ics"`
}

type OTContext struct {
	Protocol    string `json:"protocol,omitempty"`
	PurdueLevel int    `json:"purdue_level,omitempty"`
	DeviceType  string `json:"device_type,omitempty"`
	AssetID     string `json:"asset_id,omitempty"`
	ProcessArea string `json:"process_area,omitempty"`
}

type SecurityEvent struct {
	ID          string         `json:"id"`
	Timestamp   time.Time      `json:"timestamp"`
	Source      string         `json:"source"`
	Category    string         `json:"category"`
	Severity    Severity       `json:"severity"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	MITRE       *MITREAttack   `json:"mitre,omitempty"`
	OTContext   *OTContext     `json:"ot_context,omitempty"`
	RawData     map[string]any `json:"raw_data,omitempty"`
	Resolved    bool           `json:"resolved"`
	Tags        []string       `json:"tags"`
}

type ModuleStatus struct {
	Name          string    `json:"name"`
	Status        string    `json:"status"`
	Version       string    `json:"version"`
	LastSeen      time.Time `json:"last_seen"`
	UptimeSeconds int64     `json:"uptime_seconds"`
	Events24h     int64     `json:"events_24h"`
	Alerts24h     int64     `json:"alerts_24h"`
	Error         string    `json:"error,omitempty"`
}

type SystemMetrics struct {
	TotalEvents24h int64          `json:"total_events_24h"`
	CriticalAlerts int64          `json:"critical_alerts"`
	HighAlerts     int64          `json:"high_alerts"`
	ActiveModules  int            `json:"active_modules"`
	TotalModules   int            `json:"total_modules"`
	ThreatScore    float64        `json:"threat_score"`
	Modules        []ModuleStatus `json:"modules"`
}

type EventBus struct {
	mu        sync.RWMutex
	events    []SecurityEvent
	maxEvents int
	store     *EventStore
	notifier  *WebhookNotifier
	db        *DBStore
	hub       *LiveHub
}

func NewEventBus(maxEvents int, db *DBStore, hub *LiveHub) *EventBus {
	if maxEvents < 100 {
		maxEvents = 100
	}
	return &EventBus{
		events:    make([]SecurityEvent, 0, maxEvents),
		maxEvents: maxEvents,
		db:        db,
		hub:       hub,
	}
}

// BulkLoad pre-fills the event buffer from persisted events (call once at startup).
func (eb *EventBus) BulkLoad(events []SecurityEvent) {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	for _, ev := range events {
		if len(eb.events) >= eb.maxEvents {
			copy(eb.events, eb.events[1:])
			eb.events[len(eb.events)-1] = ev
		} else {
			eb.events = append(eb.events, ev)
		}
	}
}

// Resolve marks an event as resolved by ID. Returns false if not found.
func (eb *EventBus) Resolve(id string) bool {
	eb.mu.Lock()
	defer eb.mu.Unlock()
	for i := range eb.events {
		if eb.events[i].ID == id {
			eb.events[i].Resolved = true
			return true
		}
	}
	return false
}

func (eb *EventBus) Publish(event SecurityEvent) SecurityEvent {
	event = finalizeEvent(event)

	eb.mu.Lock()
	if len(eb.events) >= eb.maxEvents {
		copy(eb.events, eb.events[1:])
		eb.events[len(eb.events)-1] = event
	} else {
		eb.events = append(eb.events, event)
	}
	eb.mu.Unlock()

	eb.store.Append(event)
	if eb.notifier != nil {
		eb.notifier.NotifyIfNeeded(event)
	}
	if eb.db != nil {
		go eb.db.Insert(event)
	}
	if eb.hub != nil {
		go eb.hub.Broadcast(event)
	}
	return event
}

func (eb *EventBus) Recent(limit int, category string) []SecurityEvent {
	if eb.db != nil {
		if events, err := eb.db.Recent(limit, category); err == nil {
			return events
		}
	}

	eb.mu.RLock()
	defer eb.mu.RUnlock()

	if limit <= 0 || limit > 1000 {
		limit = 100
	}

	out := make([]SecurityEvent, 0, limit)
	for i := len(eb.events) - 1; i >= 0 && len(out) < limit; i-- {
		ev := eb.events[i]
		if category == "" || ev.Category == category {
			out = append(out, ev)
		}
	}
	return out
}

func (eb *EventBus) Count24h() (total int64, critical int64, high int64) {
	if eb.db != nil {
		if t, c, h, err := eb.db.Count24h(); err == nil {
			return t, c, h
		}
	}

	eb.mu.RLock()
	defer eb.mu.RUnlock()

	cutoff := time.Now().Add(-24 * time.Hour)
	for _, ev := range eb.events {
		if ev.Timestamp.Before(cutoff) {
			continue
		}
		total++
		switch ev.Severity {
		case SeverityCritical:
			critical++
		case SeverityHigh:
			high++
		}
	}
	return total, critical, high
}

type Orchestrator struct {
	eventBus *EventBus
	modules  map[string]*ModuleStatus
	mu       sync.RWMutex
	started  time.Time
	hub      *LiveHub
	config   *Config
	auditLog *AuditLog
}

func NewOrchestrator(db *DBStore, hub *LiveHub, config *Config) *Orchestrator {
	if config == nil {
		config = LoadConfig()
	}
	maxEvents := config.MaxEvents
	if maxEvents < 100 {
		maxEvents = 100
	}
	o := &Orchestrator{
		eventBus: NewEventBus(maxEvents, db, hub),
		modules:  map[string]*ModuleStatus{},
		started:  time.Now(),
		hub:      hub,
		config:   config,
		auditLog: NewAuditLog(5000),
	}
	o.RegisterModule("orchestrator", "1.0.0")
	return o
}

func (o *Orchestrator) RegisterModule(name, version string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.modules[name] = &ModuleStatus{
		Name:     name,
		Status:   "running",
		Version:  version,
		LastSeen: time.Now(),
	}
}

func (o *Orchestrator) UpdateModule(name, status, version, errText string) ModuleStatus {
	o.mu.Lock()
	defer o.mu.Unlock()

	module, ok := o.modules[name]
	if !ok {
		module = &ModuleStatus{Name: name}
		o.modules[name] = module
	}
	module.Status = firstNonEmpty(status, "unknown")
	module.Version = firstNonEmpty(version, module.Version)
	module.LastSeen = time.Now()
	module.Error = errText
	module.UptimeSeconds = int64(time.Since(o.started).Seconds())
	return *module
}

func (o *Orchestrator) Metrics() SystemMetrics {
	total, critical, high := o.eventBus.Count24h()

	o.mu.RLock()
	modules := make([]ModuleStatus, 0, len(o.modules))
	active := 0
	for _, module := range o.modules {
		copyModule := *module
		copyModule.UptimeSeconds = int64(time.Since(o.started).Seconds())
		modules = append(modules, copyModule)
		if copyModule.Status == "running" || copyModule.Status == "healthy" {
			active++
		}
	}
	o.mu.RUnlock()

	score := float64(critical)*20 + float64(high)*5
	if score > 100 {
		score = 100
	}

	return SystemMetrics{
		TotalEvents24h: total,
		CriticalAlerts: critical,
		HighAlerts:     high,
		ActiveModules:  active,
		TotalModules:   len(modules),
		ThreatScore:    score,
		Modules:        modules,
	}
}

func (o *Orchestrator) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", o.handleHealth)
	mux.HandleFunc("/api/v1/metrics", method(http.MethodGet, o.handleMetrics))
	mux.HandleFunc("/api/v1/modules", o.handleModules)
	mux.HandleFunc("/api/v1/modules/", o.handleModuleStatus)
	mux.HandleFunc("/api/v1/events", o.handleEvents)
	mux.HandleFunc("/api/v1/events/live", method(http.MethodGet, o.handleEventsLive))
	mux.HandleFunc("/api/v1/events/export", method(http.MethodGet, o.handleEventsExport))
	mux.HandleFunc("/api/v1/events/stats/timeline", method(http.MethodGet, o.handleEventsTimeline))
	mux.HandleFunc("/api/v1/events/{id}/resolve", method(http.MethodPatch, o.handleEventResolve))
	mux.HandleFunc("/api/v1/ingest/wazuh", method(http.MethodPost, o.handleIngestWazuh))
	mux.HandleFunc("/api/v1/ingest/suricata", method(http.MethodPost, o.handleIngestSuricata))
	mux.HandleFunc("/api/v1/ingest/crowdsec", method(http.MethodPost, o.handleIngestCrowdSec))
	mux.HandleFunc("/api/v1/ingest/cybershield-ai", method(http.MethodPost, o.handleIngestCyberShieldAI))
	mux.HandleFunc("/api/v1/ingest/ot", method(http.MethodPost, o.handleIngestOT))
	mux.HandleFunc("/api/v1/ingest/network", method(http.MethodPost, o.handleIngestNetwork))
	mux.HandleFunc("/api/v1/ingest/threat-intel", method(http.MethodPost, o.handleIngestThreatIntel))
	mux.HandleFunc("/api/v1/ingest/vuln", method(http.MethodPost, o.handleIngestVuln))
	mux.HandleFunc("/api/v1/ingest/generic", method(http.MethodPost, o.handleIngestGeneric))
	mux.HandleFunc("/api/v1/soar/trigger", method(http.MethodPost, o.handleSOARTrigger))
	mux.HandleFunc("/api/v1/config", method(http.MethodGet, o.handleConfig))
	mux.HandleFunc("/api/v1/status", method(http.MethodGet, o.handleSystemStatus))
	mux.HandleFunc("/api/v1/ot/assets", method(http.MethodGet, o.handleOTAssets))
	mux.HandleFunc("/api/v1/events/search", method(http.MethodGet, o.handleEventsSearch))
	mux.HandleFunc("/api/v1/playbooks", method(http.MethodGet, o.handlePlaybooks))
	mux.HandleFunc("/api/v1/events/bulk-resolve", method(http.MethodPatch, o.handleEventsBulkResolve))
	mux.HandleFunc("/api/v1/events/export/csv", method(http.MethodGet, o.handleEventsExportCSV))
	mux.HandleFunc("/api/v1/honeypot/status", method(http.MethodGet, o.handleHoneypotStatus))
	mux.HandleFunc("/api/v1/honeypot/trigger", method(http.MethodPost, o.handleHoneypotTrigger))
	mux.HandleFunc("/api/v1/assets", method(http.MethodGet, o.handleAssets))
	mux.HandleFunc("/api/v1/shield/analysis", method(http.MethodGet, o.handleShieldAnalysis))
	mux.HandleFunc("/api/v1/shield/hunts", method(http.MethodGet, o.handleShieldHunts))
	mux.HandleFunc("/api/v1/shield/rules", method(http.MethodGet, o.handleShieldRules))
	mux.HandleFunc("/api/v1/proxy/", o.handleProxy)

	// ── Shortcut endpoints (scan, reports, TI lookup) ──────────────────────
	mux.HandleFunc("/api/scan/discover", o.makeModuleProxy("network", "discover"))
	mux.HandleFunc("/api/scan/launch", o.makeModuleProxy("network", "scan"))
	mux.HandleFunc("/api/scan/status", o.makeModuleProxy("network", "scan/status"))
	mux.HandleFunc("/api/scan/results", o.makeModuleProxy("network", "scan/results"))
	mux.HandleFunc("/api/scan/jobs", o.makeModuleProxy("network", "scan/jobs"))
	mux.HandleFunc("/api/scan/cancel", o.makeModuleProxy("network", "scan/cancel"))
	mux.HandleFunc("/api/scan/export", o.makeModuleProxy("network", "scan/export"))
	mux.HandleFunc("/api/vuln/batch", o.makeModuleProxy("vuln", "scan/batch"))
	mux.HandleFunc("/api/vuln/findings", o.makeModuleProxy("vuln", "findings"))
	mux.HandleFunc("/api/report", o.makeModuleProxy("reports", "report"))
	mux.HandleFunc("/api/report/list", o.makeModuleProxy("reports", "report/list"))
	mux.HandleFunc("/api/ti/lookup", o.makeModuleProxy("threat-intel", "lookup"))

	// ── Network Topology + Attack Paths (fallback empty when network module offline)
	mux.HandleFunc("/api/topology", o.makeModuleProxyWithFallback("network", "topology", o.handleTopologyFallback))
	mux.HandleFunc("/api/topology/attack-paths", o.makeModuleProxyWithFallback("network", "topology/attack-paths", o.handleTopologyFallback))

	// ── TLS / SSL Deep Inspector (fallback 503+hint when offline) ──────────
	mux.HandleFunc("/api/tls/inspect", o.makeModuleProxyWithFallback("network", "tls/inspect", o.handleTLSFallback))
	mux.HandleFunc("/api/tls/batch", o.makeModuleProxyWithFallback("network", "tls/batch", o.handleTLSFallback))
	mux.HandleFunc("/api/tls/scan-from-results", o.makeModuleProxyWithFallback("network", "tls/scan-from-results", o.handleTLSFallback))

	// ── Threat Fusion Engine (fallback empty campaigns when offline) ───────
	mux.HandleFunc("/api/fusion/analyze", o.makeModuleProxyWithFallback("network", "fusion/analyze", o.handleFusionFallback))
	mux.HandleFunc("/api/fusion/live", o.makeModuleProxyWithFallback("network", "fusion/live", o.handleFusionFallback))
	mux.HandleFunc("/api/fusion/stats", o.makeModuleProxyWithFallback("network", "fusion/stats", o.handleFusionFallback))

	// ── New direct endpoints for dashboard real functionality ──────────────
	mux.HandleFunc("/api/v1/siem/rules", method(http.MethodGet, o.handleSIEMRules))
	mux.HandleFunc("/api/v1/vuln/cve-search", method(http.MethodGet, o.handleCVESearch))
	mux.HandleFunc("/api/v1/ml/training-report", method(http.MethodGet, o.handleMLTrainingReport))
	mux.HandleFunc("/api/v1/notifications/config", o.handleNotifConfig)
	mux.HandleFunc("/api/v1/audit-log", method(http.MethodGet, o.handleAuditLog))
	mux.HandleFunc("/api/v1/notifications/test", method(http.MethodPost, o.handleTestNotification))

	// ── Session-based authentication (admin/password + cookie) ─────────────
	mux.HandleFunc("/api/v1/auth/login", o.handleAuthLogin)
	mux.HandleFunc("/api/v1/auth/local", o.handleAuthLocal)
	mux.HandleFunc("/api/v1/auth/logout", o.handleAuthLogout)
	mux.HandleFunc("/api/v1/auth/me", o.handleAuthMe)

	// ── Remediation knowledge base (service/port/CVE/IOC/TLS) ──────────────
	mux.HandleFunc("/api/v1/remediation", method(http.MethodGet, o.handleRemediation))

	// ── Endpoint Protection (native Windows module on host) ─────────────────
	mux.HandleFunc("/api/endpoint/health", o.makeModuleProxy("endpoint", "health"))
	mux.HandleFunc("/api/endpoint/info", o.makeModuleProxy("endpoint", "info"))
	mux.HandleFunc("/api/endpoint/defender", o.makeModuleProxy("endpoint", "defender"))
	mux.HandleFunc("/api/endpoint/firewall", o.makeModuleProxy("endpoint", "firewall"))
	mux.HandleFunc("/api/endpoint/bitlocker", o.makeModuleProxy("endpoint", "bitlocker"))
	mux.HandleFunc("/api/endpoint/accounts", o.makeModuleProxy("endpoint", "accounts"))
	mux.HandleFunc("/api/endpoint/smb-v1", o.makeModuleProxy("endpoint", "smb-v1"))
	mux.HandleFunc("/api/endpoint/rdp", o.makeModuleProxy("endpoint", "rdp"))
	mux.HandleFunc("/api/endpoint/uac", o.makeModuleProxy("endpoint", "uac"))
	mux.HandleFunc("/api/endpoint/autoruns", o.makeModuleProxy("endpoint", "autoruns"))
	mux.HandleFunc("/api/endpoint/ports", o.makeModuleProxy("endpoint", "listening-ports"))
	mux.HandleFunc("/api/endpoint/shares", o.makeModuleProxy("endpoint", "shares"))
	mux.HandleFunc("/api/endpoint/telemetry", o.makeModuleProxy("endpoint", "telemetry"))
	mux.HandleFunc("/api/endpoint/pslogging", o.makeModuleProxy("endpoint", "pslogging"))
	mux.HandleFunc("/api/endpoint/updates", o.makeModuleProxy("endpoint", "updates"))
	mux.HandleFunc("/api/endpoint/audit", o.makeModuleProxy("endpoint", "audit"))
	mux.HandleFunc("/api/endpoint/integrations", o.makeModuleProxy("endpoint", "integrations"))
	mux.HandleFunc("/api/endpoint/processes", o.makeModuleProxy("endpoint", "processes"))
	mux.HandleFunc("/api/endpoint/connections", o.makeModuleProxy("endpoint", "connections"))
	mux.HandleFunc("/api/endpoint/scan/file", o.makeModuleProxy("endpoint", "scan/file"))
	mux.HandleFunc("/api/endpoint/scan/directory", o.makeModuleProxy("endpoint", "scan/directory"))
	mux.HandleFunc("/api/endpoint/scan/secrets", o.makeModuleProxy("endpoint", "scan/secrets"))
	mux.HandleFunc("/api/endpoint/scan/clamav", o.makeModuleProxy("endpoint", "scan/clamav"))

	// ── Enhanced Windows audit (TPM/SecureBoot/VBS/Sysmon/USB/WiFi/Browser/LAPS) ─
	mux.HandleFunc("/api/endpoint/enhanced/audit", o.makeModuleProxy("endpoint", "enhanced/audit"))
	mux.HandleFunc("/api/endpoint/enhanced/", o.makeModuleProxy("endpoint", "enhanced/"))

	// ── CISA KEV (Known Exploited Vulnerabilities) ─────────────────────────
	mux.HandleFunc("/api/endpoint/kev/stats", o.makeModuleProxy("endpoint", "kev/stats"))
	mux.HandleFunc("/api/endpoint/kev/refresh", o.makeModuleProxy("endpoint", "kev/refresh"))
	mux.HandleFunc("/api/endpoint/kev/lookup", o.makeModuleProxy("endpoint", "kev/lookup"))
	mux.HandleFunc("/api/endpoint/kev/search", o.makeModuleProxy("endpoint", "kev/search"))

	// ── HIBP Pwned Passwords (k-anonymity) ─────────────────────────────────
	mux.HandleFunc("/api/endpoint/hibp/password", o.makeModuleProxy("endpoint", "hibp/password"))

	// ── MITRE ATT&CK Navigator + APT lookup ─────────────────────────────────
	mux.HandleFunc("/api/endpoint/mitre/navigator-layer", o.makeModuleProxy("endpoint", "mitre/navigator-layer"))
	mux.HandleFunc("/api/endpoint/mitre/apt-for-technique", o.makeModuleProxy("endpoint", "mitre/apt-for-technique"))

	// ── Certificate Transparency lookup (crt.sh) ────────────────────────────
	mux.HandleFunc("/api/endpoint/crt/lookup", o.makeModuleProxy("endpoint", "crt/lookup"))

	// ── Pro SOC capabilities ────────────────────────────────────────────────
	mux.HandleFunc("/api/endpoint/process-tree", o.makeModuleProxy("endpoint", "process-tree"))
	mux.HandleFunc("/api/endpoint/ransomware/status", o.makeModuleProxy("endpoint", "ransomware/status"))
	mux.HandleFunc("/api/endpoint/ransomware/start", o.makeModuleProxy("endpoint", "ransomware/start"))
	mux.HandleFunc("/api/endpoint/ransomware/stop", o.makeModuleProxy("endpoint", "ransomware/stop"))
	mux.HandleFunc("/api/endpoint/amsi", o.makeModuleProxy("endpoint", "amsi"))
	mux.HandleFunc("/api/endpoint/wdac-applocker", o.makeModuleProxy("endpoint", "wdac-applocker"))
	mux.HandleFunc("/api/endpoint/ps-log/analyze", o.makeModuleProxy("endpoint", "ps-log/analyze"))
	mux.HandleFunc("/api/endpoint/deep-inspect", o.makeModuleProxy("endpoint", "deep-inspect"))
	mux.HandleFunc("/api/endpoint/email-auth", o.makeModuleProxy("endpoint", "email-auth"))
	mux.HandleFunc("/api/endpoint/doh/check", o.makeModuleProxy("endpoint", "doh/check"))
	mux.HandleFunc("/api/endpoint/backup/health", o.makeModuleProxy("endpoint", "backup/health"))
	mux.HandleFunc("/api/endpoint/csf/maturity", o.makeModuleProxy("endpoint", "csf/maturity"))
	mux.HandleFunc("/api/endpoint/office/macros", o.makeModuleProxy("endpoint", "office/macros"))
	mux.HandleFunc("/api/endpoint/smart-app-control", o.makeModuleProxy("endpoint", "smart-app-control"))
	mux.HandleFunc("/api/endpoint/hello", o.makeModuleProxy("endpoint", "hello"))

	// ── Honeypot real listeners ─────────────────────────────────────────────
	mux.HandleFunc("/api/endpoint/honeypot/status", o.makeModuleProxy("endpoint", "honeypot/status"))
	mux.HandleFunc("/api/endpoint/honeypot/start", o.makeModuleProxy("endpoint", "honeypot/start"))
	mux.HandleFunc("/api/endpoint/honeypot/stop", o.makeModuleProxy("endpoint", "honeypot/stop"))

	// ── Sigma Live Engine ───────────────────────────────────────────────────
	mux.HandleFunc("/api/endpoint/sigma-live/rules", o.makeModuleProxy("endpoint", "sigma-live/rules"))
	mux.HandleFunc("/api/endpoint/sigma-live/status", o.makeModuleProxy("endpoint", "sigma-live/status"))
	mux.HandleFunc("/api/endpoint/sigma-live/start", o.makeModuleProxy("endpoint", "sigma-live/start"))
	mux.HandleFunc("/api/endpoint/sigma-live/stop", o.makeModuleProxy("endpoint", "sigma-live/stop"))

	// ── Atomic Red Team ─────────────────────────────────────────────────────
	mux.HandleFunc("/api/endpoint/atomic/tests", o.makeModuleProxy("endpoint", "atomic/tests"))
	mux.HandleFunc("/api/endpoint/atomic/run/", o.makeModuleProxy("endpoint", "atomic/run/"))

	// ── D3FEND mapping ──────────────────────────────────────────────────────
	mux.HandleFunc("/api/endpoint/d3fend/for-technique", o.makeModuleProxy("endpoint", "d3fend/for-technique"))
	mux.HandleFunc("/api/endpoint/d3fend/coverage", o.makeModuleProxy("endpoint", "d3fend/coverage"))

	// ── VirusTotal lookup ───────────────────────────────────────────────────
	mux.HandleFunc("/api/endpoint/vt/", o.makeModuleProxy("endpoint", "vt/"))

	// ── Executive HTML report ───────────────────────────────────────────────
	mux.HandleFunc("/api/endpoint/exec-report", o.makeModuleProxy("endpoint", "exec-report"))

	// ── Threat Hunting (osquery-style queries on Windows) ──────────────────
	mux.HandleFunc("/api/endpoint/hunt", o.makeModuleProxy("endpoint", "hunt"))
	mux.HandleFunc("/api/endpoint/hunt/run", o.makeModuleProxy("endpoint", "hunt/run"))
	mux.HandleFunc("/api/endpoint/hunt/", o.makeModuleProxy("endpoint", "hunt/"))

	// ── Live IOC feeds (Abuse.ch / Tor / Spamhaus) ─────────────────────────
	mux.HandleFunc("/api/endpoint/ioc/feeds", o.makeModuleProxy("endpoint", "ioc/feeds"))
	mux.HandleFunc("/api/endpoint/ioc/refresh", o.makeModuleProxy("endpoint", "ioc/refresh"))
	mux.HandleFunc("/api/endpoint/ioc/lookup", o.makeModuleProxy("endpoint", "ioc/lookup"))

	// ── Realtime monitor ────────────────────────────────────────────────────
	mux.HandleFunc("/api/endpoint/realtime/status", o.makeModuleProxy("endpoint", "realtime/status"))
	mux.HandleFunc("/api/endpoint/realtime/start", o.makeModuleProxy("endpoint", "realtime/start"))
	mux.HandleFunc("/api/endpoint/realtime/stop", o.makeModuleProxy("endpoint", "realtime/stop"))

	// ── Security Posture (holistic 0-100 score) ─────────────────────────────
	mux.HandleFunc("/api/endpoint/posture", o.makeModuleProxy("endpoint", "posture"))

	// ── Containment actions (dry-run by default; X-AEGIS-Confirm: yes) ─────
	mux.HandleFunc("/api/endpoint/contain/log", o.makeModuleProxy("endpoint", "contain/log"))
	mux.HandleFunc("/api/endpoint/contain/block-ip", o.makeModuleProxy("endpoint", "contain/block-ip"))
	mux.HandleFunc("/api/endpoint/contain/unblock-ip", o.makeModuleProxy("endpoint", "contain/unblock-ip"))
	mux.HandleFunc("/api/endpoint/contain/kill-pid", o.makeModuleProxy("endpoint", "contain/kill-pid"))
	mux.HandleFunc("/api/endpoint/contain/quarantine", o.makeModuleProxy("endpoint", "contain/quarantine"))
	mux.HandleFunc("/api/endpoint/contain/disable-account", o.makeModuleProxy("endpoint", "contain/disable-account"))
	mux.HandleFunc("/api/endpoint/contain/enable-account", o.makeModuleProxy("endpoint", "contain/enable-account"))
	mux.HandleFunc("/api/endpoint/contain/isolate", o.makeModuleProxy("endpoint", "contain/isolate"))
	mux.HandleFunc("/api/endpoint/contain/unisolate", o.makeModuleProxy("endpoint", "contain/unisolate"))

	// ── External Tool Integrations (Go-native inventory) ────────────────────
	mux.HandleFunc("/api/v1/integrations/tools", method(http.MethodGet, o.handleIntegrationsTools))

	// ── Sigma Detection-as-Code (Go-native; reads data/sigma + builtin pack)
	mux.HandleFunc("/api/v1/sigma/rules", method(http.MethodGet, o.handleSigmaRules))

	// ── OT Protocol Collectors (Go health stubs; real I/O via Python network module)
	mux.HandleFunc("/api/v1/proxy/ot-protocols/health", method(http.MethodGet, o.handleOTProtocolsHealth))
	mux.HandleFunc("/api/v1/proxy/ot-protocols/modbus/read", method(http.MethodPost, o.handleOTModbusRead))
	mux.HandleFunc("/api/v1/proxy/ot-protocols/opcua/browse", method(http.MethodPost, o.handleOTOpcuaBrowse))

	// ── DFIR Case Management
	mux.HandleFunc("/api/v1/dfir/cases", o.makeModuleProxy("dfir", "cases"))
	mux.HandleFunc("/api/v1/dfir/cases/", o.makeModuleProxy("dfir", "cases/"))
	mux.HandleFunc("/api/v1/dfir/timeline", o.makeModuleProxy("dfir", "timeline"))
	mux.HandleFunc("/api/v1/dfir/stats", o.makeModuleProxy("dfir", "stats"))

	// ── Compliance (GDPR, NIS2, OT/NIST)
	mux.HandleFunc("/api/v1/compliance/assess", o.makeModuleProxy("compliance", "assess"))
	mux.HandleFunc("/api/v1/compliance/assessments", o.makeModuleProxy("compliance", "assessments"))
	mux.HandleFunc("/api/v1/compliance/frameworks", o.makeModuleProxy("compliance", "frameworks"))

	// ── Evidence Store (Go-native: data/evidence/) ───────────────────────────
	mux.HandleFunc("/api/v1/evidence/artifacts", method(http.MethodGet, o.handleEvidenceList))
	mux.HandleFunc("/api/v1/evidence/verify", method(http.MethodGet, o.handleEvidenceVerify))

	// ── PKI / Certificate Management (Go-native: data/pki/) ─────────────────
	mux.HandleFunc("/api/v1/pki/certs", method(http.MethodGet, o.handlePKICerts))
	mux.HandleFunc("/api/v1/pki/check-expiry", method(http.MethodGet, o.handlePKICheckExpiry))
	mux.HandleFunc("/api/v1/proxy/pki/health", method(http.MethodGet, o.handlePKIHealth))

	// ── OT Safety Gate (advisory endpoint; real enforcement is human-in-the-loop)
	mux.HandleFunc("/api/v1/ot/safety-gate", method(http.MethodGet, o.handleOTSafetyGate))

	registerDashboardRoutes(mux)
	return withCORS(withCommonHeaders(mux))
}

func registerDashboardRoutes(mux *http.ServeMux) {
	dashboardRoot, err := fs.Sub(dashboardFiles, "dashboard")
	if err != nil {
		mux.HandleFunc("/dashboard/", func(w http.ResponseWriter, r *http.Request) {
			respondError(w, http.StatusInternalServerError, err)
		})
		return
	}

	dashboardServer := http.StripPrefix("/dashboard/", http.FileServer(http.FS(dashboardRoot)))
	mux.Handle("/dashboard/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
		w.Header().Set("Pragma", "no-cache")
		dashboardServer.ServeHTTP(w, r)
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, "/dashboard/", http.StatusFound)
	})
}

func (o *Orchestrator) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"status":         "healthy",
		"product":        "Cybersecurity-AEGIS",
		"version":        "1.0.0",
		"uptime_seconds": int64(time.Since(o.started).Seconds()),
	})
}

func (o *Orchestrator) handleMetrics(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, o.Metrics())
}

func (o *Orchestrator) handleModules(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		respondJSON(w, http.StatusOK, o.Metrics().Modules)
	case http.MethodPut:
		var payload struct {
			Name    string `json:"name"`
			Status  string `json:"status"`
			Version string `json:"version"`
			Error   string `json:"error"`
		}
		if err := decodeJSON(r, &payload); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		if payload.Name == "" {
			respondError(w, http.StatusBadRequest, errors.New("name is required"))
			return
		}
		respondJSON(w, http.StatusOK, o.UpdateModule(payload.Name, payload.Status, payload.Version, payload.Error))
	default:
		respondError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

func (o *Orchestrator) handleModuleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPut {
		respondError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
		return
	}

	name := strings.TrimPrefix(r.URL.Path, "/api/v1/modules/")
	name = strings.TrimSuffix(name, "/status")
	name = strings.Trim(name, "/")
	if name == "" {
		respondError(w, http.StatusBadRequest, errors.New("module name is required"))
		return
	}

	var payload struct {
		Status  string `json:"status"`
		Version string `json:"version"`
		Error   string `json:"error"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusOK, o.UpdateModule(name, payload.Status, payload.Version, payload.Error))
}

func (o *Orchestrator) handleEvents(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit := parseIntDefault(r.URL.Query().Get("limit"), 100)
		category := r.URL.Query().Get("category")
		respondJSON(w, http.StatusOK, o.eventBus.Recent(limit, category))
	case http.MethodPost:
		var event SecurityEvent
		if err := decodeJSON(r, &event); err != nil {
			respondError(w, http.StatusBadRequest, err)
			return
		}
		respondJSON(w, http.StatusCreated, o.eventBus.Publish(event))
	default:
		respondError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
	}
}

// handleEventsTimeline returns per-hour event counts for the past 24 hours,
// broken down by severity bucket, for dashboard bar-chart rendering.
func (o *Orchestrator) handleEventsTimeline(w http.ResponseWriter, r *http.Request) {
	type HourBucket struct {
		Hour     string `json:"hour"`
		Critical int    `json:"critical"`
		High     int    `json:"high"`
		Medium   int    `json:"medium"`
		Low      int    `json:"low"`
		Info     int    `json:"info"`
		Total    int    `json:"total"`
	}

	now := time.Now().UTC()
	buckets := make([]HourBucket, 24)
	for i := range buckets {
		t := now.Add(time.Duration(i-23) * time.Hour).Truncate(time.Hour)
		buckets[i].Hour = t.Format("15:04")
	}

	cutoff := now.Add(-24 * time.Hour)
	o.eventBus.mu.RLock()
	for _, ev := range o.eventBus.events {
		if ev.Timestamp.Before(cutoff) {
			continue
		}
		idx := int(ev.Timestamp.UTC().Sub(cutoff.Truncate(time.Hour)).Hours())
		if idx < 0 || idx >= 24 {
			continue
		}
		buckets[idx].Total++
		switch ev.Severity {
		case SeverityCritical:
			buckets[idx].Critical++
		case SeverityHigh:
			buckets[idx].High++
		case SeverityMedium:
			buckets[idx].Medium++
		case SeverityLow:
			buckets[idx].Low++
		default:
			buckets[idx].Info++
		}
	}
	o.eventBus.mu.RUnlock()

	respondJSON(w, http.StatusOK, map[string]any{"buckets": buckets})
}

// handleEventResolve marks a single event as resolved.
// PATCH /api/v1/events/{id}/resolve
func (o *Orchestrator) handleEventResolve(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		respondError(w, http.StatusBadRequest, errors.New("missing event id"))
		return
	}
	if !o.eventBus.Resolve(id) {
		respondError(w, http.StatusNotFound, fmt.Errorf("event %s not found", id))
		return
	}
	if o.auditLog != nil {
		o.auditLog.Append("event_resolve", "api", fmt.Sprintf("resolved event %s", id), r.RemoteAddr, "info")
	}
	respondJSON(w, http.StatusOK, map[string]string{"id": id, "status": "resolved"})
}

// handleEventsExport streams all in-memory events as JSON (array).
// Clients may pass ?limit=N; 0 means all events.
func (o *Orchestrator) handleEventsExport(w http.ResponseWriter, r *http.Request) {
	limit := parseIntDefault(r.URL.Query().Get("limit"), 0)
	events := o.eventBus.Recent(func() int {
		if limit <= 0 {
			return 100000
		}
		return limit
	}(), "")

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis_events.json"`)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(events)
}

func (o *Orchestrator) handleIngestWazuh(w http.ResponseWriter, r *http.Request) {
	raw, err := decodeMap(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusCreated, o.eventBus.Publish(normalizeWazuh(raw)))
}

func (o *Orchestrator) handleIngestSuricata(w http.ResponseWriter, r *http.Request) {
	raw, err := decodeMap(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusCreated, o.eventBus.Publish(normalizeSuricata(raw)))
}

func (o *Orchestrator) handleIngestCrowdSec(w http.ResponseWriter, r *http.Request) {
	raw, err := decodeMap(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusCreated, o.eventBus.Publish(normalizeCrowdSec(raw)))
}

func (o *Orchestrator) handleIngestCyberShieldAI(w http.ResponseWriter, r *http.Request) {
	raw, err := decodeMap(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusCreated, o.eventBus.Publish(normalizeCyberShieldAI(raw)))
}

func (o *Orchestrator) handleIngestOT(w http.ResponseWriter, r *http.Request) {
	raw, err := decodeMap(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusCreated, o.eventBus.Publish(normalizeOT(raw)))
}

func (o *Orchestrator) handleIngestNetwork(w http.ResponseWriter, r *http.Request) {
	raw, err := decodeMap(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusCreated, o.eventBus.Publish(normalizeNetwork(raw)))
}

func (o *Orchestrator) handleIngestThreatIntel(w http.ResponseWriter, r *http.Request) {
	raw, err := decodeMap(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusCreated, o.eventBus.Publish(normalizeThreatIntel(raw)))
}

func (o *Orchestrator) handleIngestVuln(w http.ResponseWriter, r *http.Request) {
	raw, err := decodeMap(r)
	if err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusCreated, o.eventBus.Publish(normalizeVuln(raw)))
}

func (o *Orchestrator) handleIngestGeneric(w http.ResponseWriter, r *http.Request) {
	var event SecurityEvent
	if err := decodeJSON(r, &event); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	respondJSON(w, http.StatusCreated, o.eventBus.Publish(event))
}

// fetchModuleJSON performs a GET to a module endpoint and returns parsed JSON.
func fetchModuleJSON(module, subpath string) (any, error) {
	base := moduleProxyBase(module)
	if base == "" {
		return nil, fmt.Errorf("unknown module: %s", module)
	}
	url := base + "/" + subpath
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var data any
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, err
	}
	return data, nil
}

// handleOTAssets returns OT asset list derived from live OT module or recent events.
func (o *Orchestrator) handleOTAssets(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	assets := []map[string]any{}
	seen := map[string]bool{}

	// 1. Try live OT module
	if raw, err := fetchModuleJSON("ot", "status"); err == nil {
		if m, ok := raw.(map[string]any); ok {
			if arr, ok := m["assets"].([]any); ok {
				for _, item := range arr {
					if a, ok := item.(map[string]any); ok {
						ip, _ := a["ip"].(string)
						if ip != "" {
							seen[ip] = true
						}
						assets = append(assets, a)
					}
				}
			}
		}
	}

	// 2. Fall back to OT events from event bus
	o.eventBus.mu.RLock()
	cutoff := now.Add(-7 * 24 * time.Hour)
	for _, ev := range o.eventBus.events {
		if !ev.Timestamp.After(cutoff) {
			continue
		}
		if ev.OTContext == nil {
			continue
		}
		ip := ""
		if ev.RawData != nil {
			if v, ok := ev.RawData["source_ip"].(string); ok {
				ip = v
			}
		}
		if ip == "" {
			continue
		}
		if seen[ip] {
			continue
		}
		seen[ip] = true
		assets = append(assets, map[string]any{
			"ip":           ip,
			"hostname":     ev.OTContext.AssetID,
			"type":         ev.OTContext.DeviceType,
			"os":           ev.OTContext.DeviceType,
			"vendor":       "",
			"criticality":  "high",
			"purdue_level": ev.OTContext.PurdueLevel,
			"authorized":   true,
			"open_ports":   []int{},
			"cves":         []string{},
			"risk_score":   50,
			"last_seen":    ev.Timestamp.Format(time.RFC3339),
			"process_area": ev.OTContext.ProcessArea,
		})
	}
	o.eventBus.mu.RUnlock()

	respondJSON(w, http.StatusOK, map[string]any{
		"assets":       assets,
		"total":        len(assets),
		"last_updated": now.Format(time.RFC3339),
		"note":         "OT assets sourced from live OT module + recent OT events.",
	})
}

// handleOTSafetyGate returns the current OT safety gate policy and pending approvals.
// This is advisory-only: real enforcement requires human-in-the-loop per NIST 800-82.
func (o *Orchestrator) handleOTSafetyGate(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]any{
		"safety_gate_enabled":            true,
		"ot_safe_mode":                   true,
		"default_policy":                 "read-only",
		"containment_requires_approval":  true,
		"auto_containment_zones":         []string{}, // none by default
		"maintenance_window_required":    true,
		"human_approval_timeout_minutes": 30,
		"pending_approvals":              []map[string]any{},
		"note":                           "OT actions are read-only by default. Containment requires explicit human approval and maintenance window.",
		"compliance":                     []string{"NIST SP 800-82 Rev. 3", "NIS2 Art. 21"},
	})
}

// handleHoneypotStatus returns canary trap status and recent trigger events.
// Trigger events are sourced from the in-memory event store (category=honeypot).
func (o *Orchestrator) handleHoneypotStatus(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()

	// Pull honeypot-tagged events from the store (last 200)
	o.eventBus.mu.RLock()
	var triggers []map[string]any
	count := 0
	for i := len(o.eventBus.events) - 1; i >= 0 && count < 200; i-- {
		ev := o.eventBus.events[i]
		if ev.Category == "honeypot" || ev.Category == "deception" {
			tid, tname := "", ""
			if ev.MITRE != nil {
				tid = ev.MITRE.TechniqueID
				tname = ev.MITRE.TechniqueName
			}
			var trapType, trapName, srcIP interface{}
			if ev.RawData != nil {
				trapType = ev.RawData["trap_type"]
				trapName = ev.RawData["trap_name"]
				srcIP = ev.RawData["source_ip"]
			}
			triggers = append(triggers, map[string]any{
				"id":             ev.ID,
				"timestamp":      ev.Timestamp,
				"trap_type":      trapType,
				"trap_name":      trapName,
				"attacker_ip":    srcIP,
				"technique_id":   tid,
				"technique_name": tname,
				"severity":       string(ev.Severity),
				"title":          ev.Title,
			})
			count++
		}
	}
	o.eventBus.mu.RUnlock()

	traps := []map[string]any{}
	trapIndex := map[string]int{}
	addTrap := func(id, name, trapType string, port int, protocol, status string) {
		id = firstNonEmpty(id, name, trapType, "unknown")
		key := strings.ToLower(id)
		if _, exists := trapIndex[key]; exists {
			return
		}
		trapIndex[key] = len(traps)
		traps = append(traps, map[string]any{
			"id":             id,
			"name":           firstNonEmpty(name, id),
			"type":           firstNonEmpty(trapType, "unknown"),
			"port":           port,
			"status":         firstNonEmpty(status, "configured"),
			"protocol":       firstNonEmpty(protocol, strings.ToUpper(trapType)),
			"triggers_today": 0,
			"last_trigger":   "",
		})
	}

	// Optional real sensor inventory. Example:
	// AEGIS_HONEYPOT_TRAPS='[{"id":"opencanary-ssh","name":"OpenCanary SSH","type":"ssh","port":2222,"protocol":"TCP","status":"active"}]'
	if cfg := strings.TrimSpace(os.Getenv("AEGIS_HONEYPOT_TRAPS")); cfg != "" {
		var configured []map[string]any
		if err := json.Unmarshal([]byte(cfg), &configured); err == nil {
			for _, t := range configured {
				addTrap(
					asString(t["id"]),
					asString(t["name"]),
					asString(t["type"]),
					int(asFloat(t["port"])),
					asString(t["protocol"]),
					asString(t["status"]),
				)
			}
		} else {
			for _, item := range strings.Split(cfg, ",") {
				parts := strings.Split(strings.TrimSpace(item), ":")
				if len(parts) == 0 || strings.TrimSpace(parts[0]) == "" {
					continue
				}
				trapType := strings.TrimSpace(parts[0])
				if len(parts) > 1 {
					trapType = firstNonEmpty(strings.TrimSpace(parts[1]), trapType)
				}
				port := 0
				if len(parts) > 2 {
					port = parseIntDefault(parts[2], 0)
				}
				addTrap(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[0]), trapType, port, "", "configured")
			}
		}
	}

	// Derive observed traps from real trigger events.
	for _, trig := range triggers {
		trapName := asString(trig["trap_name"])
		trapType := asString(trig["trap_type"])
		addTrap(firstNonEmpty(trapName, trapType), firstNonEmpty(trapName, trapType), trapType, 0, "", "observed")
	}

	// Count today's triggers per configured/observed trap from events.
	today := now.Format("2006-01-02")
	for _, trig := range triggers {
		ts, _ := trig["timestamp"].(time.Time)
		if ts.Format("2006-01-02") == today {
			trapID := firstNonEmpty(asString(trig["trap_name"]), asString(trig["trap_type"]))
			if idx, ok := trapIndex[strings.ToLower(trapID)]; ok {
				traps[idx]["triggers_today"] = traps[idx]["triggers_today"].(int) + 1
				traps[idx]["last_trigger"] = ts.Format(time.RFC3339)
			}
		}
	}

	if triggers == nil {
		triggers = []map[string]any{}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"status":         "active",
		"traps":          traps,
		"total_traps":    len(traps),
		"triggers":       triggers,
		"triggers_today": len(triggers),
		"unique_attackers": func() int {
			seen := map[string]bool{}
			for _, t := range triggers {
				if ip, ok := t["attacker_ip"].(string); ok && ip != "" {
					seen[ip] = true
				}
			}
			return len(seen)
		}(),
		"last_updated": now.Format(time.RFC3339),
	})
}

// handleHoneypotTrigger receives an inbound honeypot trigger from an external trap sensor.
func (o *Orchestrator) handleHoneypotTrigger(w http.ResponseWriter, r *http.Request) {
	var payload map[string]any
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}

	sourceIP, _ := payload["source_ip"].(string)
	trapName, _ := payload["trap_name"].(string)
	trapType, _ := payload["trap_type"].(string)
	sevStr, _ := payload["severity"].(string)
	if sevStr == "" {
		sevStr = "medium"
	}
	if o.auditLog != nil {
		o.auditLog.Append("honeypot_trigger", "api", fmt.Sprintf("trap %s triggered by %s", trapName, sourceIP), r.RemoteAddr, sevStr)
	}

	mitreMap := map[string]MITREAttack{
		"ssh":    {TacticID: "TA0006", TacticName: "Credential Access", TechniqueID: "T1110.001", TechniqueName: "Password Guessing"},
		"rdp":    {TacticID: "TA0001", TacticName: "Initial Access", TechniqueID: "T1133", TechniqueName: "External Remote Services"},
		"smb":    {TacticID: "TA0008", TacticName: "Lateral Movement", TechniqueID: "T1021.002", TechniqueName: "SMB/Windows Admin Shares"},
		"modbus": {TacticID: "TA0040", TacticName: "Impact", TechniqueID: "T0855", TechniqueName: "Unauthorized Command Message", IsICS: true},
		"redis":  {TacticID: "TA0003", TacticName: "Persistence", TechniqueID: "T1505", TechniqueName: "Server Software Component"},
		"http":   {TacticID: "TA0009", TacticName: "Collection", TechniqueID: "T1056", TechniqueName: "Input Capture"},
		"ftp":    {TacticID: "TA0006", TacticName: "Credential Access", TechniqueID: "T1110", TechniqueName: "Brute Force"},
		"api":    {TacticID: "TA0001", TacticName: "Initial Access", TechniqueID: "T1190", TechniqueName: "Exploit Public-Facing Application"},
	}

	mitre := mitreMap[trapType]

	ev := SecurityEvent{
		Source:      "honeypot",
		Category:    "honeypot",
		Severity:    Severity(sevStr),
		Title:       "Canary Trap Triggered: " + trapName,
		Description: "Honeypot trap '" + trapName + "' triggered by " + sourceIP,
		MITRE:       &mitre,
		RawData: map[string]any{
			"source_ip": sourceIP,
			"trap_name": trapName,
			"trap_type": trapType,
		},
		Tags: []string{"honeypot", "deception", trapType},
	}

	stored := o.eventBus.Publish(ev)
	respondJSON(w, http.StatusOK, map[string]any{"ok": true, "event_id": stored.ID})
}

// handleAssets returns the merged IT+OT asset inventory with risk scoring.
// Assets are derived from live module data (network scan, endpoint, OT) plus recent events.
func (o *Orchestrator) handleAssets(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	assets := []map[string]any{}
	assetMap := map[string]map[string]any{}

	// Helper to merge / add asset
	addAsset := func(ip string, a map[string]any) {
		if ip == "" {
			return
		}
		if existing, ok := assetMap[ip]; ok {
			// Merge fields: prefer non-empty values
			for k, v := range a {
				if v != nil && v != "" {
					existing[k] = v
				}
			}
		} else {
			assetMap[ip] = a
		}
	}

	// 1. Pull from Network module scan results
	if raw, err := fetchModuleJSON("network", "scan/results"); err == nil {
		if m, ok := raw.(map[string]any); ok {
			if results, ok := m["results"].([]any); ok {
				for _, item := range results {
					if h, ok := item.(map[string]any); ok {
						ip, _ := h["ip"].(string)
						if ip == "" {
							continue
						}
						ports := []int{}
						if pArr, ok := h["ports"].([]any); ok {
							for _, p := range pArr {
								if pm, ok := p.(map[string]any); ok {
									if portNum, ok := pm["port"].(float64); ok {
										ports = append(ports, int(portNum))
									}
								}
							}
						}
						cves := []string{}
						if fArr, ok := h["findings"].([]any); ok {
							for _, f := range fArr {
								if fm, ok := f.(map[string]any); ok {
									if eid, ok := fm["exposure_id"].(string); ok && strings.HasPrefix(eid, "CVE-") {
										cves = append(cves, eid)
									}
								}
							}
						}
						osGuess, _ := h["os_guess"].(string)
						typ := "server"
						if strings.Contains(osGuess, "Windows") {
							typ = "workstation"
						}
						if strings.Contains(osGuess, "OT") || strings.Contains(osGuess, "ICS") {
							typ = "ot"
						}
						addAsset(ip, map[string]any{
							"ip":         ip,
							"hostname":   h["hostname"],
							"type":       typ,
							"os":         osGuess,
							"vendor":     h["vendor"],
							"open_ports": ports,
							"cves":       cves,
							"risk_score": int(h["risk_score"].(float64)),
							"last_seen":  h["scan_time"],
							"authorized": true,
						})
					}
				}
			}
		}
	}

	// 2. Pull local endpoint info
	if raw, err := fetchModuleJSON("endpoint", "info"); err == nil {
		if info, ok := raw.(map[string]any); ok {
			hostname, _ := info["hostname"].(string)
			platform, _ := info["platform"].(string)
			var win map[string]any
			if w, ok := info["windows"].(map[string]any); ok {
				win = w
			}
			ip := "127.0.0.1"
			if h, ok := info["hostname"].(string); ok && h != "" {
				// Try to resolve local IP from events
				o.eventBus.mu.RLock()
				for _, ev := range o.eventBus.events {
					if ev.RawData != nil {
						if sip, ok := ev.RawData["source_ip"].(string); ok && sip != "" && sip != "127.0.0.1" {
							ip = sip
							break
						}
					}
				}
				o.eventBus.mu.RUnlock()
			}
			osName := platform
			if win != nil {
				if c, ok := win["OSCaption"].(string); ok && c != "" {
					osName = c
				}
			}
			addAsset(ip, map[string]any{
				"ip":         ip,
				"hostname":   hostname,
				"type":       "workstation",
				"os":         osName,
				"vendor":     "",
				"open_ports": []int{},
				"cves":       []string{},
				"last_seen":  now.Format(time.RFC3339),
				"authorized": true,
			})
		}
	}

	// 3. Derive risk from recent high/critical events per asset IP
	o.eventBus.mu.RLock()
	assetRisk := map[string]int{}
	cutoff := now.Add(-24 * time.Hour)
	for _, ev := range o.eventBus.events {
		if !ev.Timestamp.After(cutoff) || ev.Resolved {
			continue
		}
		ip := ""
		if ev.RawData != nil {
			if v, ok := ev.RawData["source_ip"].(string); ok {
				ip = v
			}
		}
		if ip == "" {
			continue
		}
		switch ev.Severity {
		case SeverityCritical:
			assetRisk[ip] += 40
		case SeverityHigh:
			assetRisk[ip] += 20
		case SeverityMedium:
			assetRisk[ip] += 8
		}
	}
	o.eventBus.mu.RUnlock()

	// 4. Build final list
	for ip, a := range assetMap {
		_ = ip
		score := 0
		if s, ok := a["risk_score"].(int); ok {
			score = s
		}
		if r, ok := assetRisk[ip]; ok {
			score += r
		}
		if score > 100 {
			score = 100
		}
		a["risk_score"] = score
		if a["risk_score"].(int) >= 75 {
			a["risk_level"] = "critical"
		} else if a["risk_score"].(int) >= 50 {
			a["risk_level"] = "high"
		} else if a["risk_score"].(int) >= 25 {
			a["risk_level"] = "medium"
		} else {
			a["risk_level"] = "low"
		}
		assets = append(assets, a)
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"assets":       assets,
		"total":        len(assets),
		"last_updated": now.Format(time.RFC3339),
		"note":         "Assets sourced from live network scans, endpoint module, and recent events. No synthetic baseline.",
	})
}

func (o *Orchestrator) handleEventsLive(w http.ResponseWriter, r *http.Request) {
	if o.hub == nil {
		respondError(w, http.StatusServiceUnavailable, errors.New("live events hub not available"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	flusher, ok := w.(http.Flusher)
	if !ok {
		respondError(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}
	ch := o.hub.Subscribe()
	defer o.hub.Unsubscribe(ch)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	for {
		select {
		case event, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(event)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "data: %s\n\n", data)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

func (o *Orchestrator) handleConfig(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, o.config)
}

// handleSystemStatus returns consolidated health for orchestrator + all modules.
func (o *Orchestrator) handleSystemStatus(w http.ResponseWriter, r *http.Request) {
	now := time.Now().UTC()
	modules := []string{"network", "siem", "soar", "threat-intel", "vuln", "reports", "ot", "endpoint", "ml", "integrations", "sigma", "ot-protocols", "dfir", "compliance", "evidence", "pki"}
	statuses := map[string]any{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, name := range modules {
		wg.Add(1)
		go func(mod string) {
			defer wg.Done()
			base := moduleProxyBase(mod)
			url := base + "/health"
			client := &http.Client{Timeout: 2 * time.Second}
			start := time.Now()
			resp, err := client.Get(url)
			latency := time.Since(start).Milliseconds()
			if err != nil {
				mu.Lock()
				statuses[mod] = map[string]any{"status": "offline", "latency_ms": latency, "error": err.Error()}
				mu.Unlock()
				return
			}
			defer resp.Body.Close()
			var body map[string]any
			json.NewDecoder(resp.Body).Decode(&body)
			mu.Lock()
			statuses[mod] = map[string]any{"status": "online", "latency_ms": latency, "detail": body}
			mu.Unlock()
		}(name)
	}
	wg.Wait()

	o.eventBus.mu.RLock()
	eventCount := len(o.eventBus.events)
	o.eventBus.mu.RUnlock()

	respondJSON(w, http.StatusOK, map[string]any{
		"orchestrator": map[string]any{"status": "healthy", "events_in_memory": eventCount, "timestamp": now.Format(time.RFC3339)},
		"modules":      statuses,
	})
}

func (o *Orchestrator) handleSOARTrigger(w http.ResponseWriter, r *http.Request) {
	var event SecurityEvent
	if err := decodeJSON(r, &event); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	stored := o.eventBus.Publish(event)
	if o.auditLog != nil {
		o.auditLog.Append("soar_trigger", "api", fmt.Sprintf("SOAR trigger: %s", event.Title), r.RemoteAddr, string(event.Severity))
	}
	respondJSON(w, http.StatusCreated, stored)
}

func normalizeNetwork(raw map[string]any) SecurityEvent {
	detector := firstNonEmpty(asString(raw["detector"]), "network_analyzer")
	title := firstNonEmpty(asString(raw["title"]), fmt.Sprintf("Network alert: %s", detector))
	severity := normalizeSeverity(asString(raw["severity"]))
	techniqueID := asString(raw["mitre_technique_id"])
	techniqueName := firstNonEmpty(asString(raw["mitre_technique_name"]), asString(raw["mitre_technique"]))
	event := SecurityEvent{
		Source:      "network_analyzer",
		Category:    "network",
		Severity:    severity,
		Title:       title,
		Description: firstNonEmpty(asString(raw["description"]), title),
		RawData:     raw,
		Tags:        []string{"network", "passive", "aegis"},
	}
	if techniqueID != "" || techniqueName != "" {
		event.MITRE = &MITREAttack{TechniqueID: techniqueID, TechniqueName: techniqueName}
	}
	return event
}

func normalizeThreatIntel(raw map[string]any) SecurityEvent {
	ioc := firstNonEmpty(asString(raw["ioc"]), asString(raw["indicator"]))
	iocType := firstNonEmpty(asString(raw["ioc_type"]), asString(raw["type"]))
	title := firstNonEmpty(asString(raw["title"]), fmt.Sprintf("Threat Intel IOC: %s %s", iocType, ioc))
	severity := normalizeSeverity(asString(raw["severity"]))
	return SecurityEvent{
		Source:      "threat_intel",
		Category:    "threat_intelligence",
		Severity:    severity,
		Title:       title,
		Description: firstNonEmpty(asString(raw["description"]), title),
		RawData:     raw,
		Tags:        []string{"threat_intel", "ioc", iocType},
	}
}

func normalizeVuln(raw map[string]any) SecurityEvent {
	cveID := asString(raw["cve_id"])
	host := firstNonEmpty(asString(raw["host"]), asString(raw["target"]))
	title := firstNonEmpty(asString(raw["title"]), fmt.Sprintf("Vulnerability: %s on %s", cveID, host))
	severity := normalizeSeverity(asString(raw["severity"]))
	event := SecurityEvent{
		Source:      "vuln_scanner",
		Category:    "vulnerability",
		Severity:    severity,
		Title:       title,
		Description: firstNonEmpty(asString(raw["description"]), title),
		RawData:     raw,
		Tags:        []string{"vulnerability", "scanner"},
	}
	if cveID != "" {
		event.Tags = append(event.Tags, cveID)
	}
	return event
}

func normalizeWazuh(raw map[string]any) SecurityEvent {
	rule := asMap(raw["rule"])
	level := asFloat(rule["level"])
	description := firstNonEmpty(asString(rule["description"]), "Wazuh alert")
	event := SecurityEvent{
		Source:      "wazuh",
		Category:    "endpoint",
		Severity:    wazuhSeverity(level),
		Title:       description,
		Description: description,
		RawData:     raw,
		Tags:        []string{"wazuh", "endpoint", "siem"},
	}

	mitre := asMap(rule["mitre"])
	if len(mitre) > 0 {
		event.MITRE = &MITREAttack{
			TacticName:    asString(mitre["tactic"]),
			TechniqueID:   asString(mitre["id"]),
			TechniqueName: asString(mitre["technique"]),
		}
	}
	return event
}

func normalizeSuricata(raw map[string]any) SecurityEvent {
	alert := asMap(raw["alert"])
	title := firstNonEmpty(asString(alert["signature"]), "Suricata alert")
	severity := SeverityMedium
	if sev := int(asFloat(alert["severity"])); sev > 0 {
		switch sev {
		case 1:
			severity = SeverityCritical
		case 2:
			severity = SeverityHigh
		case 3:
			severity = SeverityMedium
		default:
			severity = SeverityLow
		}
	}

	return SecurityEvent{
		Source:      "suricata",
		Category:    "network",
		Severity:    severity,
		Title:       title,
		Description: fmt.Sprintf("Suricata IDS alert: %s", title),
		RawData:     raw,
		Tags:        []string{"suricata", "network", "ids"},
	}
}

func normalizeCrowdSec(raw map[string]any) SecurityEvent {
	scenario := firstNonEmpty(asString(raw["scenario"]), asString(raw["type"]), "CrowdSec decision")
	sourceIP := firstNonEmpty(asString(raw["source_ip"]), asString(raw["ip"]), "unknown")
	severity := SeverityMedium
	remediation := strings.ToLower(asString(raw["remediation"]))
	if strings.Contains(remediation, "ban") || strings.Contains(remediation, "block") {
		severity = SeverityHigh
	}

	return SecurityEvent{
		Source:      "crowdsec",
		Category:    "perimeter",
		Severity:    severity,
		Title:       fmt.Sprintf("CrowdSec: %s", scenario),
		Description: fmt.Sprintf("CrowdSec decision for %s using scenario %s", sourceIP, scenario),
		RawData:     raw,
		Tags:        []string{"crowdsec", "perimeter", "reputation"},
	}
}

func normalizeCyberShieldAI(raw map[string]any) SecurityEvent {
	riskScore := firstNonZero(
		asFloat(raw["risk_score"]),
		asFloat(raw["risk"]),
		asFloat(raw["score"]),
	)
	severity := riskSeverity(riskScore)
	if riskLevel := asString(raw["risk_level"]); riskLevel != "" {
		severity = normalizeSeverity(riskLevel)
	}

	// v0.3: cybershield_prediction / attack_family_prediction; v0.2 fallbacks preserved
	binary := firstNonEmpty(
		asString(raw["cybershield_prediction"]),
		asString(raw["binary_prediction"]),
		asString(raw["prediction"]),
		asString(raw["label"]),
		"unknown",
	)
	family := firstNonEmpty(
		asString(raw["attack_family_prediction"]),
		asString(raw["family_prediction"]),
		asString(raw["attack_family"]),
		asString(raw["family"]),
		"unknown",
	)
	confidence := firstNonZero(asFloat(raw["attack_probability"]), asFloat(raw["confidence"]))

	title := fmt.Sprintf("CyberShield AI: %s", strings.ToUpper(binary))
	if family != "" && family != "unknown" {
		title = fmt.Sprintf("%s / %s", title, family)
	}

	event := SecurityEvent{
		Source:      "cybershield_ai",
		Category:    "ml",
		Severity:    severity,
		Title:       title,
		Description: firstNonEmpty(asString(raw["description"]), fmt.Sprintf("ML IDS classification risk %.0f confidence %.2f", riskScore, confidence)),
		RawData:     raw,
		Tags:        []string{"cybershield_ai", "ml", "ids", "nsl_kdd"},
	}

	if strings.EqualFold(family, "DoS") {
		event.MITRE = &MITREAttack{TechniqueID: "T1499", TechniqueName: "Endpoint Denial of Service"}
	} else if strings.EqualFold(family, "Probe") {
		event.MITRE = &MITREAttack{TechniqueID: "T1046", TechniqueName: "Network Service Discovery"}
	}
	return event
}

func normalizeOT(raw map[string]any) SecurityEvent {
	title := firstNonEmpty(asString(raw["title"]), "OT security event")
	severity := normalizeSeverity(asString(raw["severity"]))
	protocol := firstNonEmpty(asString(raw["protocol"]), "unknown")

	event := SecurityEvent{
		Source:      "ot_monitor",
		Category:    "industrial",
		Severity:    severity,
		Title:       title,
		Description: firstNonEmpty(asString(raw["description"]), title),
		RawData:     raw,
		Tags:        []string{"ot", "ics", "passive"},
		OTContext: &OTContext{
			Protocol:    protocol,
			PurdueLevel: int(asFloat(raw["purdue_level"])),
			DeviceType:  asString(raw["device_type"]),
			AssetID:     asString(raw["asset_id"]),
			ProcessArea: asString(raw["process_area"]),
		},
	}

	techniqueID := asString(raw["mitre_technique_id"])
	techniqueName := asString(raw["mitre_technique_name"])
	if techniqueID != "" || techniqueName != "" {
		event.MITRE = &MITREAttack{
			TechniqueID:   techniqueID,
			TechniqueName: techniqueName,
			IsICS:         true,
		}
	}
	return event
}

func finalizeEvent(event SecurityEvent) SecurityEvent {
	if event.ID == "" {
		event.ID = newID(event.Source)
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event.Severity = normalizeSeverity(string(event.Severity))
	event.Source = firstNonEmpty(event.Source, "generic")
	event.Category = firstNonEmpty(event.Category, "general")
	event.Title = firstNonEmpty(event.Title, "Security event")
	event.Description = firstNonEmpty(event.Description, event.Title)
	if event.Tags == nil {
		event.Tags = []string{}
	}
	if event.RawData == nil {
		event.RawData = map[string]any{}
	}
	return event
}

func wazuhSeverity(level float64) Severity {
	switch {
	case level >= 15:
		return SeverityCritical
	case level >= 12:
		return SeverityHigh
	case level >= 8:
		return SeverityMedium
	case level > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func normalizeSeverity(value string) Severity {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "crit":
		return SeverityCritical
	case "high":
		return SeverityHigh
	case "medium", "warn", "warning":
		return SeverityMedium
	case "low":
		return SeverityLow
	case "info", "informational", "":
		return SeverityInfo
	default:
		return SeverityMedium
	}
}

func method(expected string, handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != expected {
			respondError(w, http.StatusMethodNotAllowed, errors.New("method not allowed"))
			return
		}
		handler(w, r)
	}
}

func withCommonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "null" || strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1") || strings.HasPrefix(origin, "http://[::1]") {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
		} else {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-AEGIS-SESSION")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func respondJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func respondError(w http.ResponseWriter, status int, err error) {
	respondJSON(w, status, map[string]any{"error": err.Error()})
}

func decodeJSON(r *http.Request, dst any) error {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	return nil
}

func decodeMap(r *http.Request) (map[string]any, error) {
	var raw map[string]any
	if err := decodeJSON(r, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		raw = map[string]any{}
	}
	return raw, nil
}

func asMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if m, ok := value.(map[string]any); ok {
		return m
	}
	return map[string]any{}
}

func asString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

func asFloat(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int64:
		return float64(v)
	case json.Number:
		f, _ := v.Float64()
		return f
	case string:
		f, _ := strconv.ParseFloat(v, 64)
		return f
	default:
		return 0
	}
}

func firstNonZero(values ...float64) float64 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}

func riskSeverity(score float64) Severity {
	switch {
	case score >= 85:
		return SeverityCritical
	case score >= 65:
		return SeverityHigh
	case score >= 35:
		return SeverityMedium
	case score > 0:
		return SeverityLow
	default:
		return SeverityInfo
	}
}

func parseIntDefault(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func newID(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		prefix = "event"
	}
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	}
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(buf))
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func runHealthcheck() int {
	client := http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://127.0.0.1:8070/health")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintf(os.Stderr, "healthcheck status %d\n", resp.StatusCode)
		return 1
	}
	return 0
}

// ── Security headers middleware ──────────────────────────────────────
// Applied to every response. CSP is calibrated for the embedded dashboard
// (inline scripts/handlers + jsdelivr/unpkg CDNs) while still locking down
// framing, sniffing, MIME confusion and referrer leakage.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "+
				"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "+
				"img-src 'self' data: blob: https:; "+
				"font-src 'self' data: https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; "+
				"connect-src 'self' ws: wss:; "+
				"object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}

func main() {
	healthcheck := flag.Bool("healthcheck", false, "check local HTTP health endpoint")
	flag.Parse()
	if *healthcheck {
		os.Exit(runHealthcheck())
	}

	// Load configuration via ConfigManager (Viper-based, hot-reloadable)
	configManager := GetConfigManager()
	configManager.StartWatching()
	config := configManager.Get()

	bind := config.Bind
	if bind == "" {
		bind = "0.0.0.0:8070"
	}

	hub := NewLiveHub()

	var db *DBStore
	if config.PostgresDSN != "" {
		db = NewDBStore(config.PostgresDSN)
	}

	orchestrator := NewOrchestrator(db, hub, config)
	orchestrator.RegisterModule("local_agent", "0.1.0")
	orchestrator.RegisterModule("ot_monitor", "0.1.0")
	orchestrator.RegisterModule("wazuh", "external")
	orchestrator.RegisterModule("suricata", "external")
	orchestrator.RegisterModule("crowdsec", "external")
	orchestrator.RegisterModule("cybershield_ai", "0.3.0")
	orchestrator.RegisterModule("network_analyzer", "0.1.0")
	orchestrator.RegisterModule("threat_intel", "0.1.0")
	orchestrator.RegisterModule("vuln_scanner", "0.1.0")
	orchestrator.RegisterModule("siem_correlator", "0.1.0")
	orchestrator.RegisterModule("soar", "0.1.0")

	// ── Event persistence ────────────────────────────────────────────────────────
	storePath := config.ResolvePath("data/events.jsonl")
	eventStore, err := OpenEventStore(storePath)
	if err != nil {
		log.Printf("WARNING: could not open event store at %s: %v (running without persistence)", storePath, err)
	}
	orchestrator.eventBus.store = eventStore
	if eventStore != nil {
		recent := eventStore.LoadRecent(config.MaxEvents)
		if len(recent) > 0 {
			orchestrator.eventBus.BulkLoad(recent)
			log.Printf("Loaded %d events from persistent store", len(recent))
		}
	}

	// ── Webhook notifications ─────────────────────────────────────────────────────
	notifier := NewWebhookNotifier(
		os.Getenv("ALERT_SLACK_WEBHOOK"),
		os.Getenv("ALERT_TELEGRAM_BOT_TOKEN"),
		os.Getenv("ALERT_TELEGRAM_CHAT_ID"),
	)
	orchestrator.eventBus.notifier = notifier

	// ── Authentication: session cookies + optional API key ─────────────────────
	ensureAuthGlobals()

	// Override session TTL from config if set
	if config.SessionTTLHours > 0 {
		globalSessions.ttl = config.GetSessionTTL()
	}

	// ── Seed extra data directories (Evidence/PKI READMEs) ─────────────────
	seedExtraDataDirs()
	adminUser := config.AdminUser
	if adminUser == "" {
		adminUser = "admin"
	}
	pwSource := "default"
	if config.AdminPassword != "" {
		pwSource = "config"
	}
	authRequired := config.APIKey != "" || config.AuthRequired
	auth := NewAuthMiddleware(config.APIKey)
	log.Printf("Auth: admin user=%q (password source: %s), required=%v", adminUser, pwSource, authRequired)
	if !authRequired {
		log.Printf("WARNING: No API key and auth not required — dashboard runs in OPEN mode (local trust)")
	}
	if config.APIKey != "" {
		log.Printf("API key authentication path enabled (Bearer token)")
	}

	server := &http.Server{
		Addr:              bind,
		Handler:           securityHeaders(auth.Wrap(orchestrator.Routes())),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		// Generous write timeout: proxied audit/scan calls to the endpoint or
		// vuln modules can legitimately take minutes (parallel PowerShell
		// checks, NVD lookups, ClamAV scans). The browser still has its own
		// fetch timeout, but the server must not cut the response itself.
		WriteTimeout: 10 * time.Minute,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Printf("Cybersecurity-AEGIS orchestrator listening on %s", bind)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	<-signals

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("shutdown error: %v", err)
	}
	eventStore.Close()
}

// ── Event search ──────────────────────────────────────────────────────────────

func (o *Orchestrator) handleEventsSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(r.URL.Query().Get("q"))
	cat := r.URL.Query().Get("category")
	sev := r.URL.Query().Get("severity")
	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if n, err := strconv.Atoi(limitStr); err == nil && n > 0 && n <= 1000 {
			limit = n
		}
	}
	all := o.eventBus.Recent(1000, cat)
	var filtered []SecurityEvent
	for _, ev := range all {
		if sev != "" && !strings.EqualFold(string(ev.Severity), sev) {
			continue
		}
		if q != "" {
			hay := strings.ToLower(ev.Title + " " + ev.Description + " " + ev.Source + " " + strings.Join(ev.Tags, " "))
			if !strings.Contains(hay, q) {
				continue
			}
		}
		filtered = append(filtered, ev)
		if len(filtered) >= limit {
			break
		}
	}
	if filtered == nil {
		filtered = []SecurityEvent{}
	}
	respondJSON(w, http.StatusOK, filtered)
}

// ── Playbooks ─────────────────────────────────────────────────────────────────

// handlePlaybooks returns playbooks read from the real YAML files in
// playbooks/. Execution counts are pulled from the in-memory event bus
// (category=soar) so the dashboard shows REAL invocations, not placeholders.
func (o *Orchestrator) handlePlaybooks(w http.ResponseWriter, r *http.Request) {
	// Resolve playbooks dir: env > ./playbooks > ../../playbooks
	dir := envOrEmpty("AEGIS_PLAYBOOKS_DIR")
	if dir == "" {
		for _, c := range []string{"playbooks", "../../playbooks"} {
			if st, err := os.Stat(c); err == nil && st.IsDir() {
				dir = c
				break
			}
		}
	}

	// Build execution counts from real SOAR events
	execCounts := map[string]int{}
	o.eventBus.mu.RLock()
	for _, ev := range o.eventBus.events {
		if ev.Category != "soar" && !strings.Contains(strings.ToLower(ev.Source), "soar") {
			continue
		}
		// Look for a "playbook_id" tag or raw_data field
		if ev.RawData != nil {
			if pid, ok := ev.RawData["playbook_id"].(string); ok && pid != "" {
				execCounts[pid]++
			}
		}
		for _, tag := range ev.Tags {
			if strings.HasPrefix(tag, "PB-") {
				execCounts[tag]++
			}
		}
	}
	o.eventBus.mu.RUnlock()

	playbooks := []map[string]any{}
	if dir != "" {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				if e.IsDir() {
					continue
				}
				name := strings.ToLower(e.Name())
				if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
					continue
				}
				path := filepath.Join(dir, e.Name())
				data, err := os.ReadFile(path)
				if err != nil {
					continue
				}
				pb := parsePlaybookYAMLLite(string(data))
				if pb["id"] == nil || pb["id"] == "" {
					pb["id"] = strings.TrimSuffix(e.Name(), filepath.Ext(e.Name()))
				}
				pb["file"] = e.Name()
				if pid, ok := pb["id"].(string); ok {
					pb["executions"] = execCounts[pid]
				} else {
					pb["executions"] = 0
				}
				playbooks = append(playbooks, pb)
			}
		}
	}

	respondJSON(w, http.StatusOK, playbooks)
}

// parsePlaybookYAMLLite extracts id/name/description/enabled/dry_run/severity_filter/category_filter/actions
// from a SOAR playbook YAML without pulling in a full YAML lib.
func parsePlaybookYAMLLite(text string) map[string]any {
	out := map[string]any{
		"id": "", "name": "", "description": "",
		"enabled": true, "dry_run": true,
		"severity_filter": []string{},
		"category_filter": []string{},
		"actions":         []string{},
		"trigger":         "",
	}
	lines := strings.Split(text, "\n")
	var currentList string
	for _, raw := range lines {
		t := strings.TrimRight(raw, " \r\n")
		if t == "" || strings.HasPrefix(strings.TrimSpace(t), "#") {
			continue
		}
		indent := len(t) - len(strings.TrimLeft(t, " "))
		trim := strings.TrimSpace(t)
		// Top-level scalar key:value
		if indent == 0 && strings.Contains(trim, ":") && !strings.HasSuffix(trim, ":") {
			parts := strings.SplitN(trim, ":", 2)
			k := strings.TrimSpace(parts[0])
			v := strings.TrimSpace(parts[1])
			v = strings.Trim(v, "\"'")
			switch k {
			case "id", "name", "description", "version", "trigger":
				out[k] = v
			case "enabled":
				out["enabled"] = (v == "true" || v == "yes")
			case "dry_run":
				out["dry_run"] = (v == "true" || v == "yes")
			case "ot_safe":
				out["ot_safe"] = (v == "true" || v == "yes")
			}
			currentList = ""
			continue
		}
		// Top-level list-header
		if indent == 0 && strings.HasSuffix(trim, ":") {
			currentList = strings.TrimSuffix(trim, ":")
			continue
		}
		// List item under a known section
		if currentList != "" && strings.HasPrefix(trim, "- ") {
			item := strings.TrimSpace(strings.TrimPrefix(trim, "- "))
			item = strings.Trim(item, "\"'")
			switch currentList {
			case "severity_filter":
				out["severity_filter"] = append(out["severity_filter"].([]string), item)
			case "category_filter":
				out["category_filter"] = append(out["category_filter"].([]string), item)
			case "actions":
				if strings.HasPrefix(item, "action:") {
					a := strings.TrimSpace(strings.TrimPrefix(item, "action:"))
					a = strings.Trim(a, "\"'")
					out["actions"] = append(out["actions"].([]string), a)
				} else {
					out["actions"] = append(out["actions"].([]string), item)
				}
			}
		}
		// Nested "action:" lines deeper than 2 spaces (action lists)
		if indent >= 2 && strings.HasPrefix(trim, "action:") {
			a := strings.TrimSpace(strings.TrimPrefix(trim, "action:"))
			a = strings.Trim(a, "\"'")
			cur := out["actions"].([]string)
			// Avoid duplicates
			found := false
			for _, x := range cur {
				if x == a {
					found = true
					break
				}
			}
			if !found && a != "" {
				out["actions"] = append(cur, a)
			}
		}
	}
	return out
}

// handleEventsBulkResolve resolves multiple events by ID.
// PATCH /api/v1/events/bulk-resolve
func (o *Orchestrator) handleEventsBulkResolve(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		IDs []string `json:"ids"`
	}
	if err := decodeJSON(r, &payload); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}
	resolved := 0
	for _, id := range payload.IDs {
		if o.eventBus.Resolve(id) {
			resolved++
		}
	}
	if o.auditLog != nil {
		o.auditLog.Append("bulk_resolve", "api", fmt.Sprintf("resolved %d events", resolved), r.RemoteAddr, "info")
	}
	respondJSON(w, http.StatusOK, map[string]any{"resolved": resolved, "requested": len(payload.IDs)})
}

// handleEventsExportCSV streams all in-memory events as CSV.
func (o *Orchestrator) handleEventsExportCSV(w http.ResponseWriter, r *http.Request) {
	events := o.eventBus.Recent(100000, "")
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="aegis_events.csv"`)
	fmt.Fprintln(w, "id,timestamp,source,category,severity,title,description,resolved,tags")
	for _, ev := range events {
		fmt.Fprintf(w, "%s,%s,%s,%s,%s,%q,%q,%v,%q\n",
			ev.ID,
			ev.Timestamp.Format(time.RFC3339),
			ev.Source,
			ev.Category,
			ev.Severity,
			ev.Title,
			ev.Description,
			ev.Resolved,
			strings.Join(ev.Tags, " "),
		)
	}
}
