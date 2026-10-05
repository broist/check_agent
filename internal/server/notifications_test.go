package server

import (
	"context"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
)

type recipientMailer struct {
	recipient string
	calls     int
	fail      bool
}

func (m *recipientMailer) SendTo(_ storage.Alert, _, recipient string) error {
	m.recipient = recipient
	m.calls++
	if m.fail {
		return errors.New("SMTP authentication: rejected")
	}
	return nil
}

func notificationServer(t *testing.T) (*Server, *recipientMailer, *http.Cookie, string) {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "preferences.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	mailer := &recipientMailer{}
	app, err := New(config.Server{
		SMTP: config.SMTP{Enabled: true, To: "original@example.com"}, PublicURL: "http://example.test",
		SessionSecret: strings.Repeat("s", 32), SessionIdleTimeout: time.Hour, SessionMaxLifetime: time.Hour,
		AgentOfflineAfter: 2 * time.Minute, DiskWarningThreshold: 85, DiskCriticalThreshold: 95,
		AgentTokens: []config.AgentToken{{AgentID: "node@01", Hash: "test"}, {AgentID: "waiting", Hash: "test"}},
	}, store, mailer, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SyncAgents(context.Background(), app.cfg.AgentTokens); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	session, err := app.sessions.Create(response)
	if err != nil {
		t.Fatal(err)
	}
	return app, mailer, response.Result().Cookies()[0], session.CSRF
}

func postPreferences(app *Server, cookie *http.Cookie, csrf, path, recipient, origin string) *httptest.ResponseRecorder {
	values := url.Values{"csrf_token": {csrf}, "recipient": {recipient}, "enabled": {"on"}, "recovery": {"on"}}
	request := httptest.NewRequest("POST", path, strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	return response
}

func TestNotificationSettingsSecurityAndPersistence(t *testing.T) {
	app, _, cookie, csrf := notificationServer(t)
	path := "/api/v1/notifications"
	for _, test := range []struct {
		name, token, address, origin string
		cookie                       *http.Cookie
		status                       int
	}{
		{"login required", csrf, "ops@example.com", "http://example.test", nil, 303},
		{"csrf", "bad", "ops@example.com", "http://example.test", cookie, 403},
		{"origin", csrf, "ops@example.com", "http://evil.test", cookie, 403},
		{"header injection", csrf, "ops@example.com\r\nBcc: leak@example.com", "http://example.test", cookie, 422},
		{"multiple addresses", csrf, "a@example.com,b@example.com", "http://example.test", cookie, 422},
		{"valid", csrf, "ops@example.com", "http://example.test", cookie, 200},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := postPreferences(app, test.cookie, test.token, path, test.address, test.origin)
			if response.Code != test.status {
				t.Fatalf("status %d: %s", response.Code, response.Body.String())
			}
		})
	}
	// Recreate the application to verify preferences are read from SQLite, not process memory.
	restarted, err := New(app.cfg, app.store, app.mailer, app.logger)
	if err != nil {
		t.Fatal(err)
	}
	p, err := restarted.notificationPreferences(context.Background())
	if err != nil || p.Recipient != "ops@example.com" || !p.Enabled || p.Warnings || !p.Recovery {
		t.Fatalf("preferences: %+v, %v", p, err)
	}
}

func TestTestEmailUsesUnsavedRecipientAndReportsFailures(t *testing.T) {
	app, mailer, cookie, csrf := notificationServer(t)
	send := func() *httptest.ResponseRecorder {
		return postPreferences(app, cookie, csrf, "/api/v1/notifications/test", "test@example.com", "http://example.test")
	}
	if response := send(); response.Code != 200 || mailer.recipient != "test@example.com" {
		t.Fatalf("test send: %d %s", response.Code, response.Body.String())
	}
	p, _ := app.notificationPreferences(context.Background())
	if p.Recipient != "original@example.com" {
		t.Fatal("test email changed saved settings")
	}
	mailer.fail = true
	if response := send(); response.Code != 502 || !strings.Contains(response.Body.String(), "hitelesítés") {
		t.Fatalf("failure: %d %s", response.Code, response.Body.String())
	}
	app.cfg.SMTP.Enabled = false
	if response := send(); response.Code != 409 {
		t.Fatalf("disabled SMTP returned %d", response.Code)
	}
	app.cfg.SMTP.Enabled = true
	send()
	if response := send(); response.Code != 429 {
		t.Fatalf("rate limit returned %d", response.Code)
	}
}

func TestNotificationDeliveryFiltersAndRetries(t *testing.T) {
	for _, tc := range []struct {
		name, severity, state                   string
		enabled, warnings, recovery, smtp, fail bool
		calls                                   int
		wantState                               string
	}{
		{"critical", "critical", "firing", true, false, true, true, false, 1, "sent"},
		{"warning filtered", "warning", "firing", true, false, true, true, false, 0, "suppressed"},
		{"warning enabled", "warning", "firing", true, true, true, true, false, 1, "sent"},
		{"off", "critical", "firing", false, false, true, true, false, 0, "suppressed"},
		{"smtp off", "critical", "firing", true, false, true, false, false, 0, "suppressed"},
		{"retry", "critical", "firing", true, false, true, true, true, 1, "pending"},
		{"recovery off", "critical", "resolved", true, false, false, true, false, 0, "suppressed"},
		{"recovery", "critical", "resolved", true, false, true, true, false, 1, "sent"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, mailer, _, _ := notificationServer(t)
			ctx := context.Background()
			app.cfg.SMTP.Enabled = tc.smtp
			mailer.fail = tc.fail
			if err := app.store.SaveNotificationPreferences(ctx, storage.NotificationPreferences{Enabled: tc.enabled, Recipient: "chosen@example.com", Warnings: tc.warnings, Recovery: tc.recovery}); err != nil {
				t.Fatal(err)
			}
			rule := storage.RuleEvaluation{AgentID: "node@01", RuleKey: "disk_critical", Resource: "/var/lib/data", Severity: tc.severity, Value: 97, Threshold: 95, Violated: true}
			if _, err := app.store.ApplyRule(ctx, rule, time.Now()); err != nil {
				t.Fatal(err)
			}
			if tc.state == "resolved" {
				rule.Violated = false
				if _, err := app.store.ApplyRule(ctx, rule, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
			app.processNotifications(ctx)
			history, err := app.store.AlertHistory(ctx, 10)
			if tc.state == "firing" {
				history, err = app.store.ActiveAlerts(ctx)
			}
			if err != nil || len(history) != 1 || history[0].NotificationState != tc.wantState {
				t.Fatalf("history: %+v %v", history, err)
			}
			if mailer.calls != tc.calls || (mailer.calls > 0 && mailer.recipient != "chosen@example.com") {
				t.Fatalf("mailer %+v", mailer)
			}
			if tc.fail {
				mailer.fail = false
				app.processNotifications(ctx)
				if mailer.calls != 2 {
					t.Fatal("failed delivery was not retried")
				}
			}
		})
	}
}

func TestDashboardPathsGrowthStaleDataAndMissingAgents(t *testing.T) {
	app, _, cookie, _ := notificationServer(t)
	report := model.Report{AgentID: "node@01", Hostname: "production", Sequence: 1, Timestamp: time.Now().Add(-10 * time.Minute), Filesystems: []model.Filesystem{{Mountpoint: "/var/lib/data", Device: "/dev/nvme1n1", TotalBytes: 100000, UsedBytes: 96000, UsedPercent: 96, AvailBytes: 4000}}}
	if err := app.store.SaveReport(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	report.Sequence = 2
	report.Timestamp = report.Timestamp.Add(time.Minute)
	report.Filesystems[0].UsedBytes = 97024
	if err := app.store.SaveReport(context.Background(), report); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/", "/api/v1/dashboard"} {
		request := httptest.NewRequest("GET", path, nil)
		request.AddCookie(cookie)
		response := httptest.NewRecorder()
		app.Handler().ServeHTTP(response, request)
		if response.Header().Get("Referrer-Policy") != "same-origin" {
			t.Fatal("same-origin forms must retain their Origin header")
		}
		for _, want := range []string{"/var/lib/data", "/dev/nvme1n1", "+1.0 KiB", "régi mérés", "Nincs jelentés", "waiting"} {
			if response.Code != 200 || !strings.Contains(html.UnescapeString(response.Body.String()), want) {
				t.Fatalf("%s missing %q: %d %s", path, want, response.Code, response.Body.String())
			}
		}
	}
	request := httptest.NewRequest("GET", "/api/v1/history?agent_id=node%4001&range=24h", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("valid agent ID rejected: %d", response.Code)
	}
}
