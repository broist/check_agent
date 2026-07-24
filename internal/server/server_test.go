package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/monitorozo/internal/auth"
	"github.com/example/monitorozo/internal/config"
	"github.com/example/monitorozo/internal/model"
	"github.com/example/monitorozo/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

type recordingMailer struct {
	alerts []storage.Alert
}

func (m *recordingMailer) Send(alert storage.Alert, _ string) error {
	m.alerts = append(m.alerts, alert)
	return nil
}

func TestIngestEndToEndAndReplayProtection(t *testing.T) {
	token := "0123456789abcdef0123456789abcdef"
	tokenHash, err := auth.HashToken(token)
	if err != nil {
		t.Fatal(err)
	}
	rotatedToken := "abcdef0123456789abcdef0123456789"
	rotatedHash, err := auth.HashToken(rotatedToken)
	if err != nil {
		t.Fatal(err)
	}
	passwordHash, err := bcrypt.GenerateFromPassword([]byte("a-long-test-password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Server{
		AgentTokens: []config.AgentToken{
			{AgentID: "test-01", Hash: tokenHash},
			{AgentID: "test-01", Hash: rotatedHash},
		},
		AdminPasswordHash: string(passwordHash), SessionSecret: "0123456789abcdef0123456789abcdef",
		SessionIdleTimeout: time.Minute, SessionMaxLifetime: time.Hour,
		MaxClockSkew: 2 * time.Minute, CPUAlertThreshold: 80,
	}
	store, err := storage.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SyncAgents(context.Background(), cfg.AgentTokens); err != nil {
		t.Fatal(err)
	}
	mailer := &recordingMailer{}
	app, err := New(cfg, store, mailer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	report := model.Report{
		AgentID: "test-01", Timestamp: time.Now().UTC(), Sequence: 1,
		Version: "test", Hostname: "test", CPUPercent: 91,
		Memory: model.Memory{UsedPercent: 50}, Uptime: 100,
	}
	body, _ := json.Marshal(report)
	send := func(requestToken string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/reports", bytes.NewReader(body))
		request.Header.Set("Authorization", "Bearer "+requestToken)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		app.Handler().ServeHTTP(response, request)
		return response
	}
	if response := send(token); response.Code != http.StatusAccepted {
		t.Fatalf("ingest returned %d: %s", response.Code, response.Body.String())
	}
	if len(mailer.alerts) != 1 || mailer.alerts[0].State != "firing" {
		t.Fatalf("expected firing alert notification, got %+v", mailer.alerts)
	}
	reports, err := store.LatestReports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Sequence != 1 {
		t.Fatalf("stored reports: %+v, err=%v", reports, err)
	}
	if response := send(rotatedToken); response.Code != http.StatusConflict {
		t.Fatalf("replay returned %d, want 409", response.Code)
	}
}
