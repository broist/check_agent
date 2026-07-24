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
