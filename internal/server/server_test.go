package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/auth"
	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
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
		MemoryAlertThreshold: 90, DiskWarningThreshold: 85,
		DiskCriticalThreshold: 95, AgentOfflineAfter: 2 * time.Minute,
		RawRetention: 7 * 24 * time.Hour,
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
		DiskIO: []model.DiskIO{{
			Device: "xvda", ReadBytesPerSecond: 1024, WriteBytesPerSecond: 2048,
		}},
		Networks: []model.NetworkIO{{
			Interface: "eth0", ReceiveBytesRate: 4096, TransmitBytesRate: 8192,
		}},
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
	app.processNotifications(context.Background())
	if len(mailer.alerts) != 1 || mailer.alerts[0].State != "firing" {
		t.Fatalf("expected firing alert notification, got %+v", mailer.alerts)
	}
	reports, err := store.LatestReports(context.Background())
	if err != nil || len(reports) != 1 || reports[0].Sequence != 1 ||
		len(reports[0].DiskIO) != 1 || reports[0].DiskIO[0].WriteBytesPerSecond != 2048 ||
		len(reports[0].Networks) != 1 || reports[0].Networks[0].TransmitBytesRate != 8192 {
		t.Fatalf("stored reports: %+v, err=%v", reports, err)
	}
	if response := send(rotatedToken); response.Code != http.StatusConflict {
		t.Fatalf("replay returned %d, want 409", response.Code)
	}
	form := url.Values{"password": {"a-long-test-password"}}
	loginRequest := httptest.NewRequest(http.MethodPost, "/login", bytes.NewBufferString(form.Encode()))
	loginRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(loginResponse, loginRequest)
	if loginResponse.Code != http.StatusSeeOther {
		t.Fatalf("login returned %d", loginResponse.Code)
	}
	historyRequest := httptest.NewRequest(http.MethodGet, "/api/v1/history?agent_id=test-01&range=24h", nil)
	for _, cookie := range loginResponse.Result().Cookies() {
		historyRequest.AddCookie(cookie)
	}
	historyResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(historyResponse, historyRequest)
	if historyResponse.Code != http.StatusOK {
		t.Fatalf("history returned %d: %s", historyResponse.Code, historyResponse.Body.String())
	}
	session, ok := app.sessions.Get(historyRequest)
	if !ok {
		t.Fatal("authenticated session not found")
	}
	alerts, err := store.ActiveAlerts(context.Background())
	if err != nil || len(alerts) != 1 {
		t.Fatalf("active alerts: %+v, err=%v", alerts, err)
	}
	ackForm := url.Values{"csrf_token": {session.CSRF}}
	ackRequest := httptest.NewRequest(http.MethodPost,
		fmt.Sprintf("/api/v1/alerts/%d/ack", alerts[0].ID),
		bytes.NewBufferString(ackForm.Encode()))
	ackRequest.SetPathValue("id", fmt.Sprintf("%d", alerts[0].ID))
	ackRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range loginResponse.Result().Cookies() {
		ackRequest.AddCookie(cookie)
	}
	ackResponse := httptest.NewRecorder()
	app.Handler().ServeHTTP(ackResponse, ackRequest)
	if ackResponse.Code != http.StatusSeeOther {
		t.Fatalf("acknowledgement returned %d: %s", ackResponse.Code, ackResponse.Body.String())
	}
	alerts, err = store.ActiveAlerts(context.Background())
	if err != nil || alerts[0].AcknowledgedAt == nil || alerts[0].AcknowledgedBy != "admin" {
		t.Fatalf("alert was not acknowledged: %+v, err=%v", alerts, err)
	}
}
