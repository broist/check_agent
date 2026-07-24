package alerts

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
)

func TestHighUsagePendingFiringAndRecovery(t *testing.T) {
	store := newTestStore(t)
	cfg := config.Server{
		CPUAlertThreshold: 90, MemoryAlertThreshold: 90,
		HighUsageDuration: 5 * time.Minute, DiskWarningThreshold: 85,
		DiskCriticalThreshold: 95, AgentOfflineAfter: 2 * time.Minute,
	}
	engine := New(store, cfg)
	ctx := context.Background()
	start := time.Now().UTC()
	report := model.Report{
		AgentID: "node-01", CPUPercent: 95,
		Memory: model.Memory{UsedPercent: 20},
	}
	if err := engine.EvaluateReport(ctx, report, start); err != nil {
		t.Fatal(err)
	}
	active, err := store.ActiveAlerts(ctx)
	if err != nil || len(active) != 1 || active[0].State != "pending" {
		t.Fatalf("expected pending alert, got %+v, err=%v", active, err)
	}
	if err := engine.EvaluateReport(ctx, report, start.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	active, err = store.ActiveAlerts(ctx)
	if err != nil || len(active) != 1 || active[0].State != "firing" {
		t.Fatalf("expected firing alert, got %+v, err=%v", active, err)
	}
	notifications, err := store.PendingNotifications(ctx, 10)
	if err != nil || len(notifications) != 1 || notifications[0].State != "firing" {
		t.Fatalf("expected firing notification, got %+v, err=%v", notifications, err)
	}
	if err := store.MarkAlertNotification(ctx, notifications[0].ID, "sent", start.Add(5*time.Minute)); err != nil {
		t.Fatal(err)
	}
	report.CPUPercent = 20
	if err := engine.EvaluateReport(ctx, report, start.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	history, err := store.AlertHistory(ctx, 10)
	if err != nil || len(history) != 1 || history[0].State != "resolved" {
		t.Fatalf("expected resolved history, got %+v, err=%v", history, err)
	}
	notifications, err = store.PendingNotifications(ctx, 10)
	if err != nil || len(notifications) != 1 || notifications[0].State != "resolved" {
		t.Fatalf("expected recovery notification, got %+v, err=%v", notifications, err)
	}
	if err := store.MarkAlertNotification(ctx, notifications[0].ID, "sent", start.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	report.CPUPercent = 95
	if err := engine.EvaluateReport(ctx, report, start.Add(7*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := engine.EvaluateReport(ctx, report, start.Add(12*time.Minute)); err != nil {
		t.Fatal(err)
	}
	notifications, err = store.PendingNotifications(ctx, 10)
	if err != nil || len(notifications) != 1 {
		t.Fatalf("expected second firing notification, got %+v, err=%v", notifications, err)
	}
	inCooldown, err := store.NotificationInCooldown(ctx, notifications[0], 30*time.Minute, start.Add(12*time.Minute))
	if err != nil || !inCooldown {
		t.Fatalf("expected cooldown suppression, got %v, err=%v", inCooldown, err)
	}
}

func TestDiskSeverityAndOfflineRule(t *testing.T) {
	store := newTestStore(t)
	cfg := config.Server{
		CPUAlertThreshold: 90, MemoryAlertThreshold: 90,
		HighUsageDuration: 5 * time.Minute, DiskWarningThreshold: 85,
		DiskCriticalThreshold: 95, AgentOfflineAfter: 2 * time.Minute,
	}
	engine := New(store, cfg)
	ctx := context.Background()
	now := time.Now().UTC()
	report := model.Report{
		AgentID: "node-01", Timestamp: now, Sequence: 1,
		Memory:      model.Memory{UsedPercent: 20},
		Filesystems: []model.Filesystem{{Mountpoint: "/", UsedPercent: 97}},
	}
	if err := store.SaveReport(ctx, report); err != nil {
		t.Fatal(err)
	}
	if err := engine.EvaluateReport(ctx, report, now); err != nil {
		t.Fatal(err)
	}
	active, err := store.ActiveAlerts(ctx)
	if err != nil || len(active) != 1 || active[0].RuleKey != "disk_critical" ||
		active[0].State != "firing" {
		t.Fatalf("expected critical disk alert, got %+v, err=%v", active, err)
	}
	if err := engine.EvaluateOffline(ctx, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	active, err = store.ActiveAlerts(ctx)
	if err != nil || len(active) != 2 {
		t.Fatalf("expected disk and offline alerts, got %+v, err=%v", active, err)
	}
}

func TestIntegrationRulesAndThreeConsecutiveHTTPFailures(t *testing.T) {
	store := newTestStore(t)
	cfg := config.Server{
		CPUAlertThreshold: 90, MemoryAlertThreshold: 90,
		HighUsageDuration: 5 * time.Minute, DiskWarningThreshold: 85,
		DiskCriticalThreshold: 95, AgentOfflineAfter: 2 * time.Minute,
	}
	engine := New(store, cfg)
	ctx := context.Background()
	now := time.Now().UTC()
	tlsDays := 10.0
	report := model.Report{
		AgentID: "node-01", Memory: model.Memory{UsedPercent: 20},
		Services: []model.ServiceStatus{
			{Name: "nginx.service", ActiveState: "failed", SubState: "failed"},
		},
		Docker: model.DockerStatus{
			Enabled: true, Available: true,
			Containers: []model.ContainerStatus{
				{Name: "api", State: "exited"},
				{Name: "worker", State: "running", Health: "unhealthy"},
			},
		},
		HTTPChecks: []model.HTTPStatus{
			{Name: "site", URL: "https://example.test/health", OK: false, TLSDaysLeft: &tlsDays},
		},
	}
	for index := 0; index < 2; index++ {
		if err := engine.EvaluateReport(ctx, report, now.Add(time.Duration(index)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	active, err := store.ActiveAlerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertAlertState(t, active, "http_failed", "pending")
	assertAlertState(t, active, "systemd_unavailable", "firing")
	assertAlertState(t, active, "docker_stopped", "firing")
	assertAlertState(t, active, "docker_unhealthy", "firing")
	assertAlertState(t, active, "tls_expiring", "firing")

	if err := engine.EvaluateReport(ctx, report, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	active, err = store.ActiveAlerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertAlertState(t, active, "http_failed", "firing")

	report.Services[0].ActiveState = "unknown"
	report.Services[0].Error = "systemctl timeout"
	if err := engine.EvaluateReport(ctx, report, now.Add(2500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	active, err = store.ActiveAlerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	assertAlertState(t, active, "systemd_unavailable", "firing")

	report.Services[0].ActiveState = "active"
	report.Services[0].Error = ""
	report.Docker.Containers = nil
	report.HTTPChecks[0].OK = true
	report.HTTPChecks[0].StatusCode = 204
	tlsDays = 30
	if err := engine.EvaluateReport(ctx, report, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	active, err = store.ActiveAlerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != 0 {
		t.Fatalf("expected all integration alerts resolved, got %+v", active)
	}
}

func assertAlertState(t *testing.T, alerts []storage.Alert, rule, state string) {
	t.Helper()
	for _, alert := range alerts {
		if alert.RuleKey == rule {
			if alert.State != state {
				t.Fatalf("%s state=%s, want %s", rule, alert.State, state)
			}
			return
		}
	}
	t.Fatalf("missing alert %s in %+v", rule, alerts)
}

func newTestStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.Open(filepath.Join(t.TempDir(), "alerts.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.SyncAgents(context.Background(), []config.AgentToken{
		{AgentID: "node-01", Hash: "test-hash"},
	}); err != nil {
		t.Fatal(err)
	}
	return store
}
