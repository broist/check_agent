package checks

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/config"
)

func TestHTTPCheckAndURLRedaction(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	definition := config.HTTPCheck{
		Name: "health", URL: server.URL + "/ready?token=secret", Timeout: time.Second,
	}
	result := checkHTTP(context.Background(), definition)
	if !result.OK || result.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected HTTP check result: %+v", result)
	}
	if strings.Contains(result.URL, "secret") || result.URL != server.URL+"/ready" {
		t.Fatalf("URL query was not redacted: %q", result.URL)
	}
}

func TestTCPCheck(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
		}
	}()
	checker := New(config.Agent{TCPChecks: []config.TCPCheck{
		{Name: "local", Address: listener.Addr().String(), Timeout: time.Second},
	}})
	_, docker, _, results := checker.Collect(context.Background())
	if len(results) != 1 || !results[0].Reachable {
		t.Fatalf("unexpected TCP check result: %+v", results)
	}
	if docker.Enabled || docker.Available {
		t.Fatalf("disabled Docker integration reported available: %+v", docker)
	}
}

func TestDockerHealthParsing(t *testing.T) {
	tests := map[string]string{
		"Up 2 hours (healthy)":            "healthy",
		"Up 1 minute (unhealthy)":         "unhealthy",
		"Up 3 seconds (health: starting)": "starting",
		"Exited (0) 2 minutes ago":        "",
	}
	for input, expected := range tests {
		if actual := dockerHealth(input); actual != expected {
			t.Errorf("dockerHealth(%q)=%q, want %q", input, actual, expected)
		}
	}
}
