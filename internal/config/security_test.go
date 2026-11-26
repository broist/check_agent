package config

import (
	"strings"
	"testing"
	"time"
)

const agentBase = `
agent_id: node-01
server_url: https://monitor.example.test
token: 01234567890123456789012345678901
`

func TestLoadAgentSecurityDefaults(t *testing.T) {
	cfg, err := LoadAgent(writeAgentConfig(t, agentBase))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Packages.Enabled || cfg.Packages.Interval != time.Hour ||
		cfg.Packages.Command != "/usr/lib/update-notifier/apt-check" ||
		cfg.VulnerabilityReport.Path != "" {
		t.Fatalf("unexpected security defaults: %+v %+v", cfg.Packages, cfg.VulnerabilityReport)
	}
	cfg, err = LoadAgent(writeAgentConfig(t, agentBase+`
packages:
  enabled: true
  interval: 30m
vulnerability_report:
  path: /var/lib/monitorozo-cvescan/summary.json
`))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Packages.Enabled || cfg.Packages.Interval != 30*time.Minute ||
		cfg.Packages.Command != DefaultPackageCommand ||
		cfg.VulnerabilityReport.Path != "/var/lib/monitorozo-cvescan/summary.json" {
		t.Fatalf("unexpected security config: %+v %+v", cfg.Packages, cfg.VulnerabilityReport)
	}
}

func TestLoadAgentRejectsInvalidSecurityConfig(t *testing.T) {
	for name, extra := range map[string]string{
		"short interval":   "packages:\n  enabled: true\n  interval: 1m\n",
		"relative command": "packages:\n  enabled: true\n  command: apt-check\n",
		"relative report":  "vulnerability_report:\n  path: summary.json\n",
	} {
		if _, err := LoadAgent(writeAgentConfig(t, agentBase+extra)); err == nil {
			t.Errorf("%s: invalid configuration accepted", name)
		}
	}
}

func TestLoadServerSecurityDefaultsAndValidation(t *testing.T) {
	cfg, err := LoadServer(writeServerConfig(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.SecurityUpdateGrace != 72*time.Hour || cfg.RebootRequiredGrace != 168*time.Hour ||
		cfg.VulnerabilityScanMaxAge != 48*time.Hour {
		t.Fatalf("unexpected security alert defaults: %+v", cfg)
	}
	for name, overrides := range map[string]string{
		"negative grace":   "security_update_grace: -1h\n",
		"short scan age":   "vulnerability_scan_max_age: 10m\n",
		"huge reboot wait": "reboot_required_grace: 9000h\n",
	} {
		if _, err := LoadServer(writeServerConfig(t, overrides)); err == nil ||
			!strings.Contains(err.Error(), "_") {
			t.Errorf("%s: error=%v", name, err)
		}
	}
}
