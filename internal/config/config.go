package config

import (
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	pathpkg "path"
	"strconv"
	"strings"
	"time"

	"github.com/broist/check_agent/internal/auth"
	"golang.org/x/crypto/bcrypt"
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
	SpoolDirectory  string        `yaml:"spool_directory"`
	ProcRoot        string        `yaml:"proc_root"`
	SysRoot         string        `yaml:"sys_root"`
	HostRoot        string        `yaml:"host_root"`
	MountInfoPath   string        `yaml:"mountinfo_path"`
	IncludeFSTypes  []string      `yaml:"include_fs_types"`
	InsecureDevHTTP bool          `yaml:"insecure_dev_http"`
	SystemdServices []string      `yaml:"systemd_services"`
	Docker          DockerChecks  `yaml:"docker"`
	HTTPChecks      []HTTPCheck   `yaml:"http_checks"`
	TCPChecks       []TCPCheck    `yaml:"tcp_checks"`
}

type DockerChecks struct {
	Enabled bool          `yaml:"enabled"`
	Socket  string        `yaml:"socket"`
	Timeout time.Duration `yaml:"timeout"`
}

type HTTPCheck struct {
	Name    string        `yaml:"name"`
	URL     string        `yaml:"url"`
	Timeout time.Duration `yaml:"timeout"`
}

type TCPCheck struct {
	Name    string        `yaml:"name"`
	Address string        `yaml:"address"`
	Timeout time.Duration `yaml:"timeout"`
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
	MaxReportAge          time.Duration `yaml:"max_report_age"`
	CPUAlertThreshold     float64       `yaml:"cpu_alert_threshold"`
	MemoryAlertThreshold  float64       `yaml:"memory_alert_threshold"`
	HighUsageDuration     time.Duration `yaml:"high_usage_duration"`
	DiskWarningThreshold  float64       `yaml:"disk_warning_threshold"`
	DiskCriticalThreshold float64       `yaml:"disk_critical_threshold"`
	AgentOfflineAfter     time.Duration `yaml:"agent_offline_after"`
	AlertCooldown         time.Duration `yaml:"alert_cooldown"`
	HTTPFailureCount      int           `yaml:"http_failure_count"`
	TLSWarningDays        float64       `yaml:"tls_warning_days"`
	TLSCriticalDays       float64       `yaml:"tls_critical_days"`
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
		SpoolDirectory: "/var/lib/monitorozo-agent/spool",
		ProcRoot:       "/proc",
		SysRoot:        "/sys",
		HostRoot:       "/",
		MountInfoPath:  "/proc/self/mountinfo",
		Docker: DockerChecks{
			Socket:  "/var/run/docker.sock",
			Timeout: 3 * time.Second,
		},
	}
	if err := loadYAML(path, &cfg); err != nil {
		return cfg, err
	}
	setString("MONITOROZO_AGENT_ID", &cfg.AgentID)
	setString("MONITOROZO_SERVER_URL", &cfg.ServerURL)
	setString("MONITOROZO_AGENT_TOKEN", &cfg.Token)
	setString("MONITOROZO_PROC_ROOT", &cfg.ProcRoot)
	setString("MONITOROZO_SYS_ROOT", &cfg.SysRoot)
	setString("MONITOROZO_HOST_ROOT", &cfg.HostRoot)
	setString("MONITOROZO_MOUNTINFO_PATH", &cfg.MountInfoPath)
	if err := setDuration("MONITOROZO_INTERVAL", &cfg.Interval); err != nil {
		return cfg, err
	}
	if cfg.Interval < 5*time.Second {
		return cfg, errors.New("interval must be at least 5s")
	}
	if cfg.AgentID == "" || cfg.ServerURL == "" || cfg.Token == "" {
		return cfg, errors.New("agent_id, server_url and token are required")
	}
	if !validAgentID(cfg.AgentID) {
		return cfg, errors.New("agent_id contains unsupported characters")
	}
	serverURL, err := url.ParseRequestURI(cfg.ServerURL)
	if err != nil || serverURL.Host == "" || serverURL.User != nil ||
		serverURL.RawQuery != "" || serverURL.Fragment != "" ||
		(serverURL.Path != "" && serverURL.Path != "/") {
		return cfg, errors.New("server_url must be an origin URL without credentials, query, fragment or path")
	}
	if serverURL.Scheme != "https" && !(cfg.InsecureDevHTTP && serverURL.Scheme == "http") {
		return cfg, errors.New("server_url must use HTTPS unless insecure_dev_http is explicitly enabled")
	}
	cfg.ServerURL = strings.TrimSuffix(cfg.ServerURL, "/")
	if len(cfg.Token) < 32 {
		return cfg, errors.New("agent token must contain at least 32 characters")
	}
	if cfg.QueueSize < 1 || cfg.QueueSize > 10000 {
		return cfg, errors.New("queue_size must be between 1 and 10000")
	}
	if !pathpkg.IsAbs(cfg.StateFile) || !pathpkg.IsAbs(cfg.SpoolDirectory) ||
		!pathpkg.IsAbs(cfg.ProcRoot) || !pathpkg.IsAbs(cfg.SysRoot) ||
		!pathpkg.IsAbs(cfg.HostRoot) || !pathpkg.IsAbs(cfg.MountInfoPath) {
		return cfg, errors.New("agent state and collector paths must be absolute")
	}
	if cfg.RequestTimeout <= 0 || cfg.RequestTimeout > time.Minute {
		return cfg, errors.New("request_timeout must be between 1ns and 1m")
	}
	if len(cfg.SystemdServices) > 32 || len(cfg.HTTPChecks) > 32 || len(cfg.TCPChecks) > 32 {
		return cfg, errors.New("at most 32 checks of each type are allowed")
	}
	if cfg.Docker.Timeout == 0 {
		cfg.Docker.Timeout = 3 * time.Second
	}
	for index := range cfg.HTTPChecks {
		if cfg.HTTPChecks[index].Timeout == 0 {
			cfg.HTTPChecks[index].Timeout = 3 * time.Second
		}
	}
	for index := range cfg.TCPChecks {
		if cfg.TCPChecks[index].Timeout == 0 {
			cfg.TCPChecks[index].Timeout = 3 * time.Second
		}
	}
	seen := make(map[string]bool)
	for _, service := range cfg.SystemdServices {
		if !validCheckName(service) || !strings.HasSuffix(service, ".service") {
			return cfg, fmt.Errorf("invalid systemd service name %q", service)
		}
		if seen["systemd:"+service] {
			return cfg, fmt.Errorf("duplicate systemd service %q", service)
		}
		seen["systemd:"+service] = true
	}
	if cfg.Docker.Enabled {
		if !pathpkg.IsAbs(cfg.Docker.Socket) {
			return cfg, errors.New("docker.socket must be an absolute path")
		}
		if err := validCheckTimeout("docker.timeout", cfg.Docker.Timeout); err != nil {
			return cfg, err
		}
	}
	for _, check := range cfg.HTTPChecks {
		if !validCheckName(check.Name) {
			return cfg, fmt.Errorf("invalid HTTP check name %q", check.Name)
		}
		if seen["http:"+check.Name] {
			return cfg, fmt.Errorf("duplicate HTTP check name %q", check.Name)
		}
		seen["http:"+check.Name] = true
		parsed, err := url.ParseRequestURI(check.URL)
		if err != nil || parsed.Host == "" ||
			(parsed.Scheme != "http" && parsed.Scheme != "https") ||
			parsed.User != nil {
			return cfg, fmt.Errorf("HTTP check %q requires an http(s) URL without credentials", check.Name)
		}
		if err := validCheckTimeout("http_checks.timeout", check.Timeout); err != nil {
			return cfg, err
		}
	}
	for _, check := range cfg.TCPChecks {
		if !validCheckName(check.Name) {
			return cfg, fmt.Errorf("invalid TCP check name %q", check.Name)
		}
		if seen["tcp:"+check.Name] {
			return cfg, fmt.Errorf("duplicate TCP check name %q", check.Name)
		}
		seen["tcp:"+check.Name] = true
		if _, _, err := net.SplitHostPort(check.Address); err != nil {
			return cfg, fmt.Errorf("invalid TCP check address for %q: %w", check.Name, err)
		}
		if err := validCheckTimeout("tcp_checks.timeout", check.Timeout); err != nil {
			return cfg, err
		}
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
		MaxReportAge:          24 * time.Hour,
		CPUAlertThreshold:     90,
		MemoryAlertThreshold:  90,
		HighUsageDuration:     5 * time.Minute,
		DiskWarningThreshold:  85,
		DiskCriticalThreshold: 95,
		AgentOfflineAfter:     120 * time.Second,
		AlertCooldown:         30 * time.Minute,
		HTTPFailureCount:      3,
		TLSWarningDays:        14,
		TLSCriticalDays:       3,
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
	if _, err := bcrypt.Cost([]byte(cfg.AdminPasswordHash)); err != nil {
		return cfg, errors.New("admin_password_hash is not a valid bcrypt hash")
	}
	if err := validateServerEndpoints(&cfg); err != nil {
		return cfg, err
	}
	seenTokens := make(map[string]bool)
	for _, item := range cfg.AgentTokens {
		if !validAgentID(item.AgentID) || !auth.ValidTokenHash(item.Hash) {
			return cfg, fmt.Errorf("invalid agent token entry for %q", item.AgentID)
		}
		key := item.AgentID + "\x00" + item.Hash
		if seenTokens[key] {
			return cfg, fmt.Errorf("duplicate agent token entry for %q", item.AgentID)
		}
		seenTokens[key] = true
	}
	if cfg.SessionIdleTimeout < time.Minute ||
		cfg.SessionMaxLifetime < cfg.SessionIdleTimeout ||
		cfg.SessionMaxLifetime > 30*24*time.Hour {
		return cfg, errors.New("session timeouts must be ordered between 1m and 720h")
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
	if cfg.HTTPFailureCount < 1 || cfg.HTTPFailureCount > 100 {
		return cfg, errors.New("http_failure_count must be between 1 and 100")
	}
	if cfg.TLSCriticalDays <= 0 || cfg.TLSCriticalDays >= cfg.TLSWarningDays {
		return cfg, errors.New("TLS day thresholds must be positive and ordered")
	}
	if cfg.MaxClockSkew <= 0 || cfg.MaxClockSkew > time.Hour {
		return cfg, errors.New("max_clock_skew must be between 1ns and 1h")
	}
	if cfg.MaxReportAge < cfg.MaxClockSkew || cfg.MaxReportAge > 7*24*time.Hour {
		return cfg, errors.New("max_report_age must be between max_clock_skew and 168h")
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
	if err := validateSMTP(cfg.SMTP); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func validateServerEndpoints(cfg *Server) error {
	host, port, err := net.SplitHostPort(cfg.Listen)
	portNumber, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("listen must be a host:port address")
	}
	if host != "" && net.ParseIP(host) == nil && host != "localhost" {
		return errors.New("listen host must be an IP address or localhost")
	}
	if !pathpkg.IsAbs(cfg.DatabasePath) {
		return errors.New("database_path must be absolute")
	}
	publicURL, err := url.ParseRequestURI(cfg.PublicURL)
	if err != nil || publicURL.Host == "" || publicURL.User != nil ||
		publicURL.RawQuery != "" || publicURL.Fragment != "" ||
		(publicURL.Path != "" && publicURL.Path != "/") ||
		(publicURL.Scheme != "http" && publicURL.Scheme != "https") {
		return errors.New("public_url must be an http(s) origin URL without credentials, query or fragment")
	}
	if cfg.SecureCookies && publicURL.Scheme != "https" {
		return errors.New("secure_cookies requires an HTTPS public_url")
	}
	cfg.PublicURL = strings.TrimSuffix(cfg.PublicURL, "/") + "/"
	if cfg.TrustedProxy != "" {
		if _, _, err := net.ParseCIDR(cfg.TrustedProxy); err != nil {
			return errors.New("trusted_proxy must use CIDR notation")
		}
	}
	return nil
}

func validateSMTP(cfg SMTP) error {
	if !cfg.Enabled {
		return nil
	}
	host, _, err := net.SplitHostPort(cfg.Address)
	if err != nil || host == "" {
		return errors.New("smtp.address must be a host:port address")
	}
	for field, value := range map[string]string{"smtp.from": cfg.From, "smtp.to": cfg.To} {
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s contains a line break", field)
		}
		address, err := mail.ParseAddress(value)
		if err != nil || address.Address != value {
			return fmt.Errorf("%s must be one bare email address", field)
		}
	}
	if cfg.Username != "" && cfg.Password == "" {
		return errors.New("smtp.password is required when smtp.username is set")
	}
	return nil
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

func validCheckName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' || r == '@' ||
			r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) == -1
}

func validAgentID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		return !(r == '-' || r == '_' || r == '.' ||
			r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) == -1
}

func validCheckTimeout(field string, value time.Duration) error {
	if value <= 0 || value > time.Minute {
		return fmt.Errorf("%s must be between 1ns and 1m", field)
	}
	return nil
}
