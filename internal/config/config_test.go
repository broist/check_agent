package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/auth"
	"golang.org/x/crypto/bcrypt"
)

func TestLoadAgentOptionalChecksAndDefaults(t *testing.T) {
	path := writeAgentConfig(t, `
agent_id: node-01
server_url: https://monitor.example.test
token: 01234567890123456789012345678901
systemd_services: [nginx.service]
docker:
  enabled: true
  socket: /var/run/docker.sock
http_checks:
  - name: health
    url: https://example.test/health?source=agent
tcp_checks:
  - name: postgres
    address: 127.0.0.1:5432
`)
	cfg, err := LoadAgent(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Docker.Timeout != 3*time.Second ||
		cfg.HTTPChecks[0].Timeout != 3*time.Second ||
		cfg.TCPChecks[0].Timeout != 3*time.Second {
		t.Fatalf("optional check timeout defaults not applied: %+v", cfg)
	}
}

func TestLoadAgentRejectsURLCredentialsAndInvalidService(t *testing.T) {
	tests := []struct {
		name, extra, want string
	}{
		{
			name:  "URL credentials",
			extra: "http_checks:\n  - name: bad\n    url: https://user:secret@example.test/\n",
			want:  "without credentials",
		},
		{
			name:  "invalid service",
			extra: "systemd_services: ['../../bad.service']\n",
			want:  "invalid systemd service",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeAgentConfig(t, `
agent_id: node-01
server_url: https://monitor.example.test
token: 01234567890123456789012345678901
`+test.extra)
			_, err := LoadAgent(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func writeAgentConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadServerValidatesOriginsCredentialsAndAlertDefaults(t *testing.T) {
	path := writeServerConfig(t, "")
	cfg, err := LoadServer(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://monitor.example.test/" ||
		cfg.HTTPFailureCount != 3 || cfg.TLSWarningDays != 14 ||
		cfg.TLSCriticalDays != 3 {
		t.Fatalf("unexpected server defaults: %+v", cfg)
	}
}

func TestLoadServerRejectsUnsafePublicURLAndSMTPHeader(t *testing.T) {
	tests := []struct {
		name, overrides, want string
	}{
		{
			name:      "insecure cookie origin",
			overrides: "public_url: http://monitor.example.test/\n",
			want:      "secure_cookies requires",
		},
		{
			name: "SMTP header injection",
			overrides: "smtp:\n  enabled: true\n  address: smtp.example.test:587\n" +
				"  from: \"ops@example.test\\nBcc: attacker@example.test\"\n" +
				"  to: admin@example.test\n",
			want: "line break",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			path := writeServerConfig(t, test.overrides)
			_, err := LoadServer(path)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func writeServerConfig(t *testing.T, overrides string) string {
	t.Helper()
	tokenHash, err := auth.HashToken("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("a-long-test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	content := `
listen: 127.0.0.1:8080
database_path: /var/lib/monitorozo-server/test.db
public_url: https://monitor.example.test/
secure_cookies: true
admin_password_hash: "` + string(passwordHash) + `"
session_secret: 0123456789abcdef0123456789abcdef
agent_tokens:
  - agent_id: node-01
    hash: "` + tokenHash + `"
`
	if strings.HasPrefix(overrides, "public_url:") {
		content = strings.Replace(content,
			"public_url: https://monitor.example.test/\n", overrides, 1)
	} else {
		content += overrides
	}
	path := filepath.Join(t.TempDir(), "server.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
