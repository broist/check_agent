package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Agent struct {
	AgentID         string        `yaml:"agent_id"`
	ServerURL       string        `yaml:"server_url"`
	Token           string        `yaml:"token"`
	Interval        time.Duration `yaml:"interval"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
	QueueSize       int           `yaml:"queue_size"`
	StateFile       string        `yaml:"state_file"`
	IncludeFSTypes  []string      `yaml:"include_fs_types"`
	InsecureDevHTTP bool          `yaml:"insecure_dev_http"`
}

type Server struct {
	Listen                string        `yaml:"listen"`
	DatabasePath          string        `yaml:"database_path"`
	PublicURL             string        `yaml:"public_url"`
	AgentTokens           []AgentToken  `yaml:"agent_tokens"`
	AdminPasswordHash     string        `yaml:"admin_password_hash"`
	SessionSecret         string        `yaml:"session_secret"`
	SessionIdleTimeout    time.Duration `yaml:"session_idle_timeout"`
	SessionMaxLifetime    time.Duration `yaml:"session_max_lifetime"`
	SecureCookies         bool          `yaml:"secure_cookies"`
	MaxClockSkew          time.Duration `yaml:"max_clock_skew"`
	CPUAlertThreshold     float64       `yaml:"cpu_alert_threshold"`
	MemoryAlertThreshold  float64       `yaml:"memory_alert_threshold"`
	HighUsageDuration     time.Duration `yaml:"high_usage_duration"`
	DiskWarningThreshold  float64       `yaml:"disk_warning_threshold"`
	DiskCriticalThreshold float64       `yaml:"disk_critical_threshold"`
	AgentOfflineAfter     time.Duration `yaml:"agent_offline_after"`
	AlertCooldown         time.Duration `yaml:"alert_cooldown"`
	TrustedProxy          string        `yaml:"trusted_proxy"`
	RawRetention          time.Duration `yaml:"raw_retention"`
	AggregateRetention    time.Duration `yaml:"aggregate_retention"`
	MaintenanceInterval   time.Duration `yaml:"maintenance_interval"`
	SMTP                  SMTP          `yaml:"smtp"`
}

type AgentToken struct {
	AgentID string `yaml:"agent_id"`
	Hash    string `yaml:"hash"`
}

type SMTP struct {
	Enabled  bool   `yaml:"enabled"`
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	To       string `yaml:"to"`
}

func LoadAgent(path string) (Agent, error) {
	cfg := Agent{
		Interval:       10 * time.Second,
		RequestTimeout: 5 * time.Second,
		QueueSize:      60,
		StateFile:      "/var/lib/monitorozo-agent/sequence",
	}
	if err := loadYAML(path, &cfg); err != nil {
		return cfg, err
	}
	setString("MONITOROZO_AGENT_ID", &cfg.AgentID)
	setString("MONITOROZO_SERVER_URL", &cfg.ServerURL)
	setString("MONITOROZO_AGENT_TOKEN", &cfg.Token)
	if err := setDuration("MONITOROZO_INTERVAL", &cfg.Interval); err != nil {
		return cfg, err
	}
	if cfg.Interval < 5*time.Second {
		return cfg, errors.New("interval must be at least 5s")
	}
	if cfg.AgentID == "" || cfg.ServerURL == "" || cfg.Token == "" {
		return cfg, errors.New("agent_id, server_url and token are required")
	}
	if !strings.HasPrefix(cfg.ServerURL, "https://") && !cfg.InsecureDevHTTP {
		return cfg, errors.New("server_url must use HTTPS unless insecure_dev_http is explicitly enabled")
	}
	if cfg.QueueSize < 1 || cfg.QueueSize > 10000 {
		return cfg, errors.New("queue_size must be between 1 and 10000")
	}
	return cfg, nil
}

func LoadServer(path string) (Server, error) {
	cfg := Server{
		Listen:                "127.0.0.1:8080",
		DatabasePath:          "/var/lib/monitorozo-server/monitorozo.db",
		SessionIdleTimeout:    30 * time.Minute,
		SessionMaxLifetime:    12 * time.Hour,
		SecureCookies:         true,
		MaxClockSkew:          2 * time.Minute,
		CPUAlertThreshold:     90,
		MemoryAlertThreshold:  90,
		HighUsageDuration:     5 * time.Minute,
		DiskWarningThreshold:  85,
		DiskCriticalThreshold: 95,
		AgentOfflineAfter:     120 * time.Second,
		AlertCooldown:         30 * time.Minute,
		RawRetention:          7 * 24 * time.Hour,
		AggregateRetention:    90 * 24 * time.Hour,
		MaintenanceInterval:   time.Hour,
	}
	if err := loadYAML(path, &cfg); err != nil {
		return cfg, err
	}
	setString("MONITOROZO_LISTEN", &cfg.Listen)
	setString("MONITOROZO_DATABASE_PATH", &cfg.DatabasePath)
	setString("MONITOROZO_PUBLIC_URL", &cfg.PublicURL)
	setString("MONITOROZO_ADMIN_PASSWORD_HASH", &cfg.AdminPasswordHash)
	setString("MONITOROZO_SESSION_SECRET", &cfg.SessionSecret)
	setString("MONITOROZO_SMTP_PASSWORD", &cfg.SMTP.Password)
	if raw := os.Getenv("MONITOROZO_SECURE_COOKIES"); raw != "" {
		value, err := strconv.ParseBool(raw)
		if err != nil {
			return cfg, fmt.Errorf("MONITOROZO_SECURE_COOKIES: %w", err)
		}
		cfg.SecureCookies = value
	}
	if cfg.AdminPasswordHash == "" || len(cfg.SessionSecret) < 32 || len(cfg.AgentTokens) == 0 {
		return cfg, errors.New("admin password hash, 32+ byte session secret and at least one agent token are required")
	}
	if cfg.CPUAlertThreshold <= 0 || cfg.CPUAlertThreshold > 100 {
		return cfg, errors.New("cpu_alert_threshold must be between 0 and 100")
	}
	if cfg.MemoryAlertThreshold <= 0 || cfg.MemoryAlertThreshold > 100 {
		return cfg, errors.New("memory_alert_threshold must be between 0 and 100")
	}
	if cfg.HighUsageDuration < 0 {
		return cfg, errors.New("high_usage_duration must not be negative")
	}
	if cfg.DiskWarningThreshold <= 0 || cfg.DiskWarningThreshold >= cfg.DiskCriticalThreshold ||
		cfg.DiskCriticalThreshold > 100 {
		return cfg, errors.New("disk thresholds must be ordered between 0 and 100")
	}
	if cfg.AgentOfflineAfter < 30*time.Second {
		return cfg, errors.New("agent_offline_after must be at least 30s")
	}
	if cfg.AlertCooldown < 0 {
		return cfg, errors.New("alert_cooldown must not be negative")
	}
	if cfg.RawRetention < 24*time.Hour {
		return cfg, errors.New("raw_retention must be at least 24h")
	}
	if cfg.AggregateRetention < cfg.RawRetention {
		return cfg, errors.New("aggregate_retention must not be shorter than raw_retention")
	}
	if cfg.MaintenanceInterval < 5*time.Minute {
		return cfg, errors.New("maintenance_interval must be at least 5m")
	}
	return cfg, nil
}

func loadYAML(path string, target any) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config: %w", err)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse config: %w", err)
	}
	return nil
}

func setString(name string, target *string) {
	if value := os.Getenv(name); value != "" {
		*target = value
	}
}

func setDuration(name string, target *time.Duration) error {
	if value := os.Getenv(name); value != "" {
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		*target = parsed
	}
	return nil
}
