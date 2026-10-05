package storage

import (
	"context"
	"github.com/broist/check_agent/internal/config"
	"path/filepath"
	"testing"
	"time"
)

func TestEscalationAndInFlightRecoveryDelivery(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "notifications.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.SyncAgents(ctx, []config.AgentToken{{AgentID: "prod", Hash: "test"}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	rule := RuleEvaluation{AgentID: "prod", RuleKey: "tls_expiring", Resource: "website", Severity: "warning", Violated: true, Value: 12, Threshold: 14}
	if _, err := store.ApplyRule(ctx, rule, now); err != nil {
		t.Fatal(err)
	}
	pending, err := store.PendingNotifications(ctx, 10)
	if err != nil || len(pending) != 1 {
		t.Fatalf("pending: %+v %v", pending, err)
	}
	warning := pending[0]
	if err := store.MarkAlertDelivery(ctx, warning, "suppressed", now); err != nil {
		t.Fatal(err)
	}
	if err := store.AcknowledgeAlert(ctx, warning.ID, "admin", now); err != nil {
		t.Fatal(err)
	}
	rule.Severity = "critical"
	rule.Value = 2
	changed, err := store.ApplyRule(ctx, rule, now.Add(time.Minute))
	if err != nil || !changed {
		t.Fatalf("escalation: %v %v", changed, err)
	}
	pending, err = store.PendingNotifications(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].Severity != "critical" || pending[0].AcknowledgedAt != nil {
		t.Fatalf("critical notification missing: %+v %v", pending, err)
	}
	critical := pending[0]
	if err := store.MarkAlertDelivery(ctx, warning, "sent", now); err != nil {
		t.Fatal(err)
	}
	pending, _ = store.PendingNotifications(ctx, 10)
	if len(pending) != 1 {
		t.Fatal("stale warning delivery consumed critical notification")
	}
	rule.Violated = false
	if _, err := store.ApplyRule(ctx, rule, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkAlertDelivery(ctx, critical, "sent", now); err != nil {
		t.Fatal(err)
	}
	pending, err = store.PendingNotifications(ctx, 10)
	if err != nil || len(pending) != 1 || pending[0].State != "resolved" {
		t.Fatalf("in-flight send consumed recovery: %+v %v", pending, err)
	}
}
