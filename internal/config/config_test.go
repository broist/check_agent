package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
