package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// Config holds all configuration for the Cybersecurity-AEGIS orchestrator and modules
type Config struct {
	// Orchestrator settings
	Bind             string   `mapstructure:"orchestrator.bind"`
	AuthRequired     bool     `mapstructure:"orchestrator.auth_required"`
	APIKey           string   `mapstructure:"orchestrator.api_key"`
	SessionTTLHours  int      `mapstructure:"orchestrator.session_ttl_hours"`
	AdminUser        string   `mapstructure:"orchestrator.admin_user"`
	AdminPassword    string   `mapstructure:"orchestrator.admin_password"`
	PostgresDSN      string   `mapstructure:"orchestrator.postgres_dsn"`
	RedisAddr        string   `mapstructure:"orchestrator.redis_addr"`
	SigmaDir         string   `mapstructure:"orchestrator.sigma_dir"`
	EvidenceDir      string   `mapstructure:"orchestrator.evidence_dir"`
	PKIDir           string   `mapstructure:"orchestrator.pki_dir"`
	IOCCacheDir      string   `mapstructure:"orchestrator.ioc_cache_dir"`
	KEVCacheDir      string   `mapstructure:"orchestrator.kev_cache_dir"`
	LogLevel         string   `mapstructure:"orchestrator.log_level"`
	CORSOrigins      []string `mapstructure:"orchestrator.cors_origins"`
	MaxEvents        int      `mapstructure:"orchestrator.max_events"`
	RateLimitEnabled bool     `mapstructure:"orchestrator.rate_limit.enabled"`
	RateLimitRPM     int      `mapstructure:"orchestrator.rate_limit.requests_per_minute"`
	RateLimitBurst   int      `mapstructure:"orchestrator.rate_limit.burst"`

	// ML Module settings
	MLPort           int     `mapstructure:"ml.api_port"`
	MLBindHost       string  `mapstructure:"ml.bind_host"`
	MLBinaryModel    string  `mapstructure:"ml.binary_model"`
	MLFamilyModel    string  `mapstructure:"ml.family_model"`
	MLAnomalyModel   string  `mapstructure:"ml.anomaly_model"`
	MLOTSafeMode     bool    `mapstructure:"ml.ot_safe_mode"`
	MLModelConfig    string  `mapstructure:"ml.model_config"`
	MLTrainingReport string  `mapstructure:"ml.training_report"`
	MLDriftEnabled   bool    `mapstructure:"ml.drift_detection.enabled"`
	MLDriftThreshold float64 `mapstructure:"ml.drift_detection.threshold"`
	MLDriftInterval  int     `mapstructure:"ml.drift_detection.check_interval_hours"`

	// Endpoint Module settings
	EndpointBindHost         string `mapstructure:"endpoint.bind_host"`
	EndpointAPIPort          int    `mapstructure:"endpoint.api_port"`
	EndpointYARARules        string `mapstructure:"endpoint.yara_rules_dir"`
	EndpointHashDB           string `mapstructure:"endpoint.hash_db"`
	EndpointUseDefender      bool   `mapstructure:"endpoint.use_defender"`
	EndpointIngestEnabled    bool   `mapstructure:"endpoint.ingest_enabled"`
	EndpointOrchestratorURL  string `mapstructure:"endpoint.orchestrator_url"`
	EndpointRealtimeInterval int    `mapstructure:"endpoint.realtime_interval_sec"`
	EndpointSigmaInterval    int    `mapstructure:"endpoint.sigma_live_interval_sec"`
	EndpointIOCFreshness     int    `mapstructure:"endpoint.ioc_freshness_hours"`
	EndpointHoneypotBind     string `mapstructure:"endpoint.honeypot_bind"`

	// Network Module settings
	NetworkBindHost         string                     `mapstructure:"network.bind_host"`
	NetworkAPIPort          int                        `mapstructure:"network.api_port"`
	NetworkInterface        string                     `mapstructure:"network.interface"`
	NetworkSimulate         bool                       `mapstructure:"network.simulate"`
	NetworkBaselineDays     int                        `mapstructure:"network.baseline_days"`
	NetworkAlertThreshold   float64                    `mapstructure:"network.alert_threshold"`
	NetworkOrchestratorURL  string                     `mapstructure:"network.orchestrator_url"`
	NetworkAuthorizedAssets []AuthorizedAsset          `mapstructure:"network.authorized_assets"`
	NetworkPassiveProtocols map[string]PassiveProtocol `mapstructure:"network.passive_protocols"`

	// Agent settings
	AgentOrchestratorURL string `mapstructure:"agent.orchestrator_url"`
	AgentIntervalSec     int    `mapstructure:"agent.interval_sec"`
	AgentBatchSize       int    `mapstructure:"agent.batch_size"`
	AgentUseYARA         bool   `mapstructure:"agent.use_yara"`
	AgentUseClamAV       bool   `mapstructure:"agent.use_clamav"`
	AgentIncludeHashes   bool   `mapstructure:"agent.include_hashes"`

	// Notifications
	NotificationSlackWebhook  string `mapstructure:"notifications.slack_webhook"`
	NotificationTelegramToken string `mapstructure:"notifications.telegram_token"`
	NotificationTelegramChat  string `mapstructure:"notifications.telegram_chat_id"`
	NotificationMinSeverity   string `mapstructure:"notifications.min_severity"`
	NotificationCooldownSec   int    `mapstructure:"notifications.cooldown_sec"`

	// Dashboard
	DashboardTheme            string `mapstructure:"dashboard.theme"`
	DashboardAutoRefreshSec   int    `mapstructure:"dashboard.auto_refresh_sec"`
	DashboardChartRetention   int    `mapstructure:"dashboard.chart_retention_points"`
	DashboardWebSocketEnabled bool   `mapstructure:"dashboard.websocket_enabled"`

	// TLS/mTLS
	TLSEnabled   bool   `mapstructure:"tls.enabled"`
	TLSCertFile  string `mapstructure:"tls.cert_file"`
	TLSKeyFile   string `mapstructure:"tls.key_file"`
	TLSCAFile    string `mapstructure:"tls.ca_file"`
	MTLSEnabled  bool   `mapstructure:"tls.mtls.enabled"`
	MTLSClientCA string `mapstructure:"tls.mtls.client_ca_file"`

	// Observability
	PrometheusEnabled bool   `mapstructure:"observability.prometheus.enabled"`
	PrometheusPort    int    `mapstructure:"observability.prometheus.port"`
	PrometheusPath    string `mapstructure:"observability.prometheus.path"`
	GrafanaEnabled    bool   `mapstructure:"observability.grafana.enabled"`
	GrafanaPort       int    `mapstructure:"observability.grafana.port"`
	GrafanaAdminUser  string `mapstructure:"observability.grafana.admin_user"`
	GrafanaAdminPass  string `mapstructure:"observability.grafana.admin_password"`
	LokiEnabled       bool   `mapstructure:"observability.loki.enabled"`
	LokiPort          int    `mapstructure:"observability.loki.port"`
	TempoEnabled      bool   `mapstructure:"observability.tempo.enabled"`
	TempoPort         int    `mapstructure:"observability.tempo.port"`
	OTELEnabled       bool   `mapstructure:"observability.otel.enabled"`
	OTELCollectorPort int    `mapstructure:"observability.otel.collector_port"`
	OTELExporter      string `mapstructure:"observability.otel.exporter"`
}

// AuthorizedAsset represents an authorized OT/ICS asset
type AuthorizedAsset struct {
	IP          string   `mapstructure:"ip"`
	Name        string   `mapstructure:"name"`
	PurdueLevel int      `mapstructure:"purdue_level"`
	Protocols   []string `mapstructure:"protocols"`
}

// PassiveProtocol represents a passive protocol configuration
type PassiveProtocol struct {
	Enabled bool `mapstructure:"enabled"`
	Port    int  `mapstructure:"port"`
}

// ConfigManager handles configuration loading, watching, and hot-reload
type ConfigManager struct {
	mu        sync.RWMutex
	config    *Config
	viper     *viper.Viper
	callbacks []func(*Config)
	watchStop chan struct{}
}

var (
	configManager *ConfigManager
	configOnce    sync.Once
)

// GetConfigManager returns the singleton ConfigManager instance
func GetConfigManager() *ConfigManager {
	configOnce.Do(func() {
		configManager = NewConfigManager()
	})
	return configManager
}

// NewConfigManager creates a new ConfigManager with Viper
func NewConfigManager() *ConfigManager {
	v := viper.New()
	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")
	v.AddConfigPath("/etc/cybersecurity-aegis")
	v.AddConfigPath("$HOME/.config/cybersecurity-aegis")

	// Environment variable binding (prefix: AEGIS_)
	v.SetEnvPrefix("AEGIS")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// Set defaults
	setDefaults(v)

	cm := &ConfigManager{
		viper:     v,
		callbacks: make([]func(*Config), 0),
		watchStop: make(chan struct{}),
	}

	// Load initial config
	if err := cm.load(); err != nil {
		fmt.Printf("WARNING: Failed to load config: %v (using defaults)\n", err)
		cm.config = &Config{}
		cm.applyDefaults()
	}

	return cm
}

// setDefaults sets all default configuration values
func setDefaults(v *viper.Viper) {
	// Orchestrator defaults
	v.SetDefault("orchestrator.bind", "0.0.0.0:8070")
	v.SetDefault("orchestrator.auth_required", true)
	v.SetDefault("orchestrator.api_key", "")
	v.SetDefault("orchestrator.session_ttl_hours", 24)
	v.SetDefault("orchestrator.admin_user", "admin")
	v.SetDefault("orchestrator.admin_password", "")
	v.SetDefault("orchestrator.postgres_dsn", "") // set via AEGIS_DB_CONN or config file; empty = run without DB
	v.SetDefault("orchestrator.redis_addr", "redis:6379")
	v.SetDefault("orchestrator.sigma_dir", "data/sigma")
	v.SetDefault("orchestrator.evidence_dir", "data/evidence")
	v.SetDefault("orchestrator.pki_dir", "data/pki")
	v.SetDefault("orchestrator.ioc_cache_dir", "data/iocs")
	v.SetDefault("orchestrator.kev_cache_dir", "data/kev")
	v.SetDefault("orchestrator.log_level", "info")
	v.SetDefault("orchestrator.cors_origins", []string{
		"http://localhost:8070",
		"http://127.0.0.1:8070",
		"http://localhost:8080",
		"http://127.0.0.1:8080",
		"http://localhost:3000",
	})
	v.SetDefault("orchestrator.max_events", 10000)
	v.SetDefault("orchestrator.rate_limit.enabled", true)
	v.SetDefault("orchestrator.rate_limit.requests_per_minute", 120)
	v.SetDefault("orchestrator.rate_limit.burst", 20)

	// ML defaults
	v.SetDefault("ml.api_port", 8919)
	v.SetDefault("ml.bind_host", "0.0.0.0")
	v.SetDefault("ml.binary_model", "models/cybershield_realpro_binary_ensemble_v0_3.joblib")
	v.SetDefault("ml.family_model", "models/cybershield_realpro_attack_family_v0_3.joblib")
	v.SetDefault("ml.anomaly_model", "models/cybershield_realpro_anomaly_baseline_v0_3.joblib")
	v.SetDefault("ml.ot_safe_mode", true)
	v.SetDefault("ml.model_config", "configs/model_config.yaml")
	v.SetDefault("ml.training_report", "reports/training_report_v0_3.json")
	v.SetDefault("ml.drift_detection.enabled", true)
	v.SetDefault("ml.drift_detection.threshold", 0.1)
	v.SetDefault("ml.drift_detection.check_interval_hours", 24)

	// Endpoint defaults
	v.SetDefault("endpoint.bind_host", "127.0.0.1")
	v.SetDefault("endpoint.api_port", 8088)
	v.SetDefault("endpoint.yara_rules_dir", "modules/intelligence/yara/rules")
	v.SetDefault("endpoint.hash_db", "")
	v.SetDefault("endpoint.use_defender", true)
	v.SetDefault("endpoint.ingest_enabled", true)
	v.SetDefault("endpoint.orchestrator_url", "http://orchestrator:8080")
	v.SetDefault("endpoint.realtime_interval_sec", 15)
	v.SetDefault("endpoint.sigma_live_interval_sec", 60)
	v.SetDefault("endpoint.ioc_freshness_hours", 12)
	v.SetDefault("endpoint.honeypot_bind", "127.0.0.1")

	// Network defaults
	v.SetDefault("network.bind_host", "0.0.0.0")
	v.SetDefault("network.api_port", 8081)
	v.SetDefault("network.interface", "eth0")
	v.SetDefault("network.simulate", true)
	v.SetDefault("network.baseline_days", 7)
	v.SetDefault("network.alert_threshold", 3.0)
	v.SetDefault("network.orchestrator_url", "http://orchestrator:8080")
	v.SetDefault("network.authorized_assets", []AuthorizedAsset{
		{IP: "192.168.10.10", Name: "demo-plc-1", PurdueLevel: 1, Protocols: []string{"modbus"}},
		{IP: "192.168.10.20", Name: "demo-hmi-1", PurdueLevel: 2, Protocols: []string{"opc_ua"}},
	})
	v.SetDefault("network.passive_protocols", map[string]PassiveProtocol{
		"modbus":       {Enabled: true, Port: 502},
		"dnp3":         {Enabled: true, Port: 20000},
		"iec61850_mms": {Enabled: false, Port: 102},
		"opc_ua":       {Enabled: true, Port: 4840},
	})

	// Agent defaults
	v.SetDefault("agent.orchestrator_url", "http://orchestrator:8080")
	v.SetDefault("agent.interval_sec", 30)
	v.SetDefault("agent.batch_size", 100)
	v.SetDefault("agent.use_yara", true)
	v.SetDefault("agent.use_clamav", false)
	v.SetDefault("agent.include_hashes", true)

	// Notifications defaults
	v.SetDefault("notifications.slack_webhook", "")
	v.SetDefault("notifications.telegram_token", "")
	v.SetDefault("notifications.telegram_chat_id", "")
	v.SetDefault("notifications.min_severity", "high")
	v.SetDefault("notifications.cooldown_sec", 300)

	// Dashboard defaults
	v.SetDefault("dashboard.theme", "dark")
	v.SetDefault("dashboard.auto_refresh_sec", 30)
	v.SetDefault("dashboard.chart_retention_points", 100)
	v.SetDefault("dashboard.websocket_enabled", true)

	// TLS defaults
	v.SetDefault("tls.enabled", false)
	v.SetDefault("tls.cert_file", "certs/server.pem")
	v.SetDefault("tls.key_file", "certs/server.key")
	v.SetDefault("tls.ca_file", "certs/ca.pem")
	v.SetDefault("tls.mtls.enabled", false)
	v.SetDefault("tls.mtls.client_ca_file", "certs/client-ca.pem")

	// Observability defaults
	v.SetDefault("observability.prometheus.enabled", true)
	v.SetDefault("observability.prometheus.port", 9090)
	v.SetDefault("observability.prometheus.path", "/metrics")
	v.SetDefault("observability.grafana.enabled", true)
	v.SetDefault("observability.grafana.port", 3000)
	v.SetDefault("observability.grafana.admin_user", "admin")
	v.SetDefault("observability.grafana.admin_password", "admin")
	v.SetDefault("observability.loki.enabled", true)
	v.SetDefault("observability.loki.port", 3100)
	v.SetDefault("observability.tempo.enabled", true)
	v.SetDefault("observability.tempo.port", 3200)
	v.SetDefault("observability.otel.enabled", true)
	v.SetDefault("observability.otel.collector_port", 4317)
	v.SetDefault("observability.otel.exporter", "otlp")
}

// load loads configuration from file and environment
func (cm *ConfigManager) load() error {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if err := cm.viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		// Config file not found - use defaults + env vars
	}

	var cfg Config
	if err := cm.viper.Unmarshal(&cfg); err != nil {
		return err
	}

	cm.config = &cfg
	cm.applyEnvOverrides()
	return nil
}

// applyEnvOverrides applies environment variable overrides for critical settings
func (cm *ConfigManager) applyEnvOverrides() {
	if cm.config == nil {
		return
	}

	// Bind address override
	if bind := os.Getenv("AEGIS_BIND"); bind != "" {
		cm.config.Bind = bind
	}
	if bind := os.Getenv("CYBERFORGE_BIND"); bind != "" && cm.config.Bind == "" {
		cm.config.Bind = bind
	}

	// Database override
	if dsn := os.Getenv("AEGIS_DB_CONN"); dsn != "" {
		cm.config.PostgresDSN = dsn
	}

	// Redis override
	if redis := os.Getenv("AEGIS_REDIS_ADDR"); redis != "" {
		cm.config.RedisAddr = redis
	}

	// Auth overrides
	if apiKey := os.Getenv("AEGIS_API_KEY"); apiKey != "" {
		cm.config.APIKey = apiKey
	}
	if authReq := os.Getenv("AEGIS_AUTH_REQUIRED"); authReq != "" {
		cm.config.AuthRequired = strings.EqualFold(authReq, "true") || authReq == "1"
	}
	if adminUser := os.Getenv("AEGIS_ADMIN_USER"); adminUser != "" {
		cm.config.AdminUser = adminUser
	}
	if adminPass := os.Getenv("AEGIS_ADMIN_PASSWORD"); adminPass != "" {
		cm.config.AdminPassword = adminPass
	}
	if sessionTTL := os.Getenv("AEGIS_SESSION_TTL_HOURS"); sessionTTL != "" {
		if n, err := strconv.Atoi(sessionTTL); err == nil && n > 0 && n <= 24*30 {
			cm.config.SessionTTLHours = n
		}
	}

	// Path overrides
	if dir := os.Getenv("AEGIS_SIGMA_DIR"); dir != "" {
		cm.config.SigmaDir = dir
	}
	if dir := os.Getenv("AEGIS_EVIDENCE_DIR"); dir != "" {
		cm.config.EvidenceDir = dir
	}
	if dir := os.Getenv("AEGIS_PKI_DIR"); dir != "" {
		cm.config.PKIDir = dir
	}
	if dir := os.Getenv("AEGIS_IOC_CACHE_DIR"); dir != "" {
		cm.config.IOCCacheDir = dir
	}
	if dir := os.Getenv("AEGIS_KEV_CACHE_DIR"); dir != "" {
		cm.config.KEVCacheDir = dir
	}
	if dir := os.Getenv("AEGIS_PLAYBOOKS_DIR"); dir != "" {
		// Handled in handlers
	}

	// Notification overrides
	if webhook := os.Getenv("ALERT_SLACK_WEBHOOK"); webhook != "" {
		cm.config.NotificationSlackWebhook = webhook
	}
	if token := os.Getenv("ALERT_TELEGRAM_BOT_TOKEN"); token != "" {
		cm.config.NotificationTelegramToken = token
	}
	if chat := os.Getenv("ALERT_TELEGRAM_CHAT_ID"); chat != "" {
		cm.config.NotificationTelegramChat = chat
	}
}

// applyDefaults applies defaults to the config struct
func (cm *ConfigManager) applyDefaults() {
	if cm.config.MaxEvents < 100 {
		cm.config.MaxEvents = 10000
	}
	if cm.config.SessionTTLHours == 0 {
		cm.config.SessionTTLHours = 24
	}
	if cm.config.Bind == "" {
		cm.config.Bind = "0.0.0.0:8080"
	}
	if cm.config.LogLevel == "" {
		cm.config.LogLevel = "info"
	}
}

// Get returns the current configuration (thread-safe)
func (cm *ConfigManager) Get() *Config {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	// Return a copy to prevent external mutation
	cfg := *cm.config
	return &cfg
}

// GetViper returns the underlying Viper instance for advanced usage
func (cm *ConfigManager) GetViper() *viper.Viper {
	return cm.viper
}

// OnChange registers a callback to be called when configuration changes
func (cm *ConfigManager) OnChange(callback func(*Config)) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.callbacks = append(cm.callbacks, callback)
}

// StartWatching starts watching the config file for changes (hot-reload)
func (cm *ConfigManager) StartWatching() {
	cm.viper.WatchConfig()
	cm.viper.OnConfigChange(func(e fsnotify.Event) {
		fmt.Printf("Config file changed: %s\n", e.Name)
		if err := cm.load(); err != nil {
			fmt.Printf("ERROR reloading config: %v\n", err)
			return
		}
		cm.notifyCallbacks()
	})
}

// StopWatching stops the config file watcher
func (cm *ConfigManager) StopWatching() {
	close(cm.watchStop)
}

// notifyCallbacks calls all registered change callbacks
func (cm *ConfigManager) notifyCallbacks() {
	cm.mu.RLock()
	callbacks := make([]func(*Config), len(cm.callbacks))
	copy(callbacks, cm.callbacks)
	cfg := cm.config
	cm.mu.RUnlock()

	for _, cb := range callbacks {
		go cb(cfg)
	}
}

// LoadConfig is a convenience function that returns the current config
// This replaces the old LoadConfig() function for backward compatibility
func LoadConfig() *Config {
	return GetConfigManager().Get()
}

// Helper to resolve relative paths relative to the config file location
func (c *Config) ResolvePath(relPath string) string {
	if filepath.IsAbs(relPath) {
		return relPath
	}
	configFile := GetConfigManager().GetViper().ConfigFileUsed()
	if configFile == "" {
		return relPath
	}
	baseDir := filepath.Dir(configFile)
	return filepath.Join(baseDir, relPath)
}

// GetSessionTTL returns the session TTL as a time.Duration
func (c *Config) GetSessionTTL() time.Duration {
	return time.Duration(c.SessionTTLHours) * time.Hour
}

// GetRateLimitConfig returns rate limiter configuration
func (c *Config) GetRateLimitConfig() (enabled bool, rpm int, burst int) {
	return c.RateLimitEnabled, c.RateLimitRPM, c.RateLimitBurst
}

// GetCORSOrigins returns the CORS allowed origins
func (c *Config) GetCORSOrigins() []string {
	if len(c.CORSOrigins) == 0 {
		return []string{"http://localhost:8080", "http://127.0.0.1:8080"}
	}
	return c.CORSOrigins
}

// Validate validates the configuration and returns any errors
func (c *Config) Validate() error {
	if c.SessionTTLHours <= 0 || c.SessionTTLHours > 24*30 {
		return fmt.Errorf("invalid session_ttl_hours: %d (must be 1-720)", c.SessionTTLHours)
	}
	if c.MaxEvents < 100 {
		return fmt.Errorf("max_events too low: %d (minimum 100)", c.MaxEvents)
	}
	if c.AdminUser == "" {
		return fmt.Errorf("admin_user cannot be empty")
	}
	if c.PostgresDSN != "" && !strings.HasPrefix(c.PostgresDSN, "postgres://") {
		return fmt.Errorf("invalid postgres_dsn format")
	}
	return nil
}
