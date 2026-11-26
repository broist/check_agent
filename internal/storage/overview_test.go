package storage

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
)

func openOverviewStore(t *testing.T, agents ...string) *Store {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "overview.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var tokens []config.AgentToken
	for _, agent := range agents {
		tokens = append(tokens, config.AgentToken{AgentID: agent, Hash: "test-hash"})
	}
	if err := store.SyncAgents(context.Background(), tokens); err != nil {
		t.Fatal(err)
	}
	return store
}

func TestMigrationsCreateOverviewTables(t *testing.T) {
	store := openOverviewStore(t)
	for _, table := range []string{"agent_labels", "http_check_buckets"} {
		var count int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&count); err != nil || count != 1 {
			t.Fatalf("table %s missing: %d %v", table, count, err)
		}
	}
	var index int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='idx_http_check_buckets_time'").Scan(&index); err != nil || index != 1 {
		t.Fatalf("bucket time index missing: %v", err)
	}
	var versions int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM schema_migrations WHERE version IN (6, 7)").Scan(&versions); err != nil || versions != 2 {
		t.Fatalf("migrations 6 and 7 not recorded: %d %v", versions, err)
	}
}

func TestCleanLabelText(t *testing.T) {
	for _, test := range []struct {
		value string
		max   int
		want  string
		ok    bool
	}{
		{"  AcuWall éles  ", 64, "AcuWall éles", true},
		{strings.Repeat("é", 64), 64, strings.Repeat("é", 64), true},
		{strings.Repeat("é", 65), 64, "", false},
		{"sor\ntörés", 64, "", false},
		{"tab\there", 64, "", false},
		{"bad\x7f", 64, "", false},
		{"\xff\xfe", 64, "", false},
		{"", 64, "", true},
	} {
		got, ok := CleanLabelText(test.value, test.max)
		if ok != test.ok || (ok && got != test.want) {
			t.Errorf("CleanLabelText(%q) = %q, %v; want %q, %v", test.value, got, ok, test.want, test.ok)
		}
	}
}

func TestAgentLabels(t *testing.T) {
	store := openOverviewStore(t, "prod-01")
	ctx := context.Background()
	now := time.Now()
	if err := store.SetAgentLabel(ctx, AgentLabel{AgentID: "ghost", DisplayName: "x"}, "admin", now); !errors.Is(err, ErrUnknownAgent) {
		t.Fatalf("unknown agent accepted: %v", err)
	}
	if err := store.SetAgentLabel(ctx, AgentLabel{AgentID: "prod-01", DisplayName: strings.Repeat("x", 65)}, "admin", now); err == nil {
		t.Fatal("too long name accepted")
	}
	if err := store.SetAgentLabel(ctx, AgentLabel{AgentID: "prod-01", DisplayName: "AcuWall éles", Description: "cloud · licenc"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	if err := store.SetAgentLabel(ctx, AgentLabel{AgentID: "prod-01", DisplayName: "AcuWall éles 2", Description: "cloud"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	labels, err := store.AgentLabels(ctx)
	if err != nil || labels["prod-01"].DisplayName != "AcuWall éles 2" || labels["prod-01"].Description != "cloud" {
		t.Fatalf("labels %+v, %v", labels, err)
	}
	var audits int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='agent.label' AND target='prod-01'").Scan(&audits); err != nil || audits != 2 {
		t.Fatalf("label changes not audited: %d %v", audits, err)
	}
	if err := store.SetAgentLabel(ctx, AgentLabel{AgentID: "prod-01"}, "admin", now); err != nil {
		t.Fatal(err)
	}
	if labels, err = store.AgentLabels(ctx); err != nil || len(labels) != 0 {
		t.Fatalf("empty label must restore the default: %+v %v", labels, err)
	}
}

func TestHTTPCheckBucketsAndRetention(t *testing.T) {
	store := openOverviewStore(t, "web-01")
	ctx := context.Background()
	now := time.Now().UTC()
	bucket := now.Truncate(HTTPBucketSize)
	check := func(ok bool) []model.HTTPStatus {
		return []model.HTTPStatus{{Name: "home", URL: "https://example.test/", StatusCode: 200, OK: ok}, {Name: "api", URL: "https://example.test/api", OK: true}}
	}
	reports := []model.Report{
		{AgentID: "web-01", Timestamp: bucket.Add(-HTTPBucketSize + time.Minute), Sequence: 1, HTTPChecks: check(true)},
		{AgentID: "web-01", Timestamp: bucket.Add(time.Second), Sequence: 2, HTTPChecks: check(true)},
		{AgentID: "web-01", Timestamp: bucket.Add(2 * time.Second), Sequence: 3, HTTPChecks: check(false)},
		{AgentID: "web-01", Timestamp: now.Add(-100 * 24 * time.Hour), Sequence: 4, HTTPChecks: check(false)},
	}
	for _, report := range reports {
		if err := store.SaveReport(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	// A replayed report must not be counted twice.
	if err := store.SaveReport(ctx, reports[2]); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
	availability, err := store.HTTPAvailability(ctx, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	home := availability["web-01"]["home"]
	if len(home) != 2 || home[0].OK != 1 || home[0].Fail != 0 || home[1].OK != 1 || home[1].Fail != 1 ||
		!home[1].Start.Equal(bucket) || len(availability["web-01"]["api"]) != 2 {
		t.Fatalf("unexpected buckets %+v", availability)
	}
	var total int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM http_check_buckets").Scan(&total); err != nil || total != 6 {
		t.Fatalf("expected 6 stored buckets, got %d %v", total, err)
	}
	if err := store.Maintain(ctx, now, 7*24*time.Hour, 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow("SELECT COUNT(*) FROM http_check_buckets").Scan(&total); err != nil || total != 4 {
		t.Fatalf("retention must drop buckets older than the aggregate retention: %d %v", total, err)
	}
}

func TestMetricBuckets(t *testing.T) {
	store := openOverviewStore(t, "node-01")
	ctx := context.Background()
	start := time.Now().UTC().Truncate(10 * time.Minute).Add(-30 * time.Minute)
	values := []struct {
		offset   time.Duration
		cpu, mem float64
	}{{time.Minute, 10, 40}, {2 * time.Minute, 70, 60}, {11 * time.Minute, 5, 20}, {-time.Hour, 99, 99}}
	for i, value := range values {
		if err := store.SaveReport(ctx, model.Report{AgentID: "node-01", Timestamp: start.Add(value.offset), Sequence: uint64(i + 1),
			CPUPercent: value.cpu, Memory: model.Memory{UsedPercent: value.mem}}); err != nil {
			t.Fatal(err)
		}
	}
	points, err := store.MetricBuckets(ctx, "node-01", start, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 2 || !points[0].Timestamp.Equal(start) || points[0].CPUPercent != 70 || points[0].MemoryPercent != 50 ||
		points[0].Samples != 2 || points[1].CPUPercent != 5 || !points[1].Timestamp.Equal(start.Add(10*time.Minute)) {
		t.Fatalf("unexpected buckets %+v", points)
	}
	if _, err := store.MetricBuckets(ctx, "node-01", start, 0); err == nil {
		t.Fatal("zero step accepted")
	}
}

func TestTimelineAlerts(t *testing.T) {
	store := openOverviewStore(t, "node-01")
	ctx := context.Background()
	now := time.Now().UTC()
	apply := func(rule string, at time.Time, violated bool, consecutive int) {
		t.Helper()
		if _, err := store.ApplyRule(ctx, RuleEvaluation{AgentID: "node-01", RuleKey: rule, Severity: "critical",
			Violated: violated, Consecutive: consecutive}, at); err != nil {
			t.Fatal(err)
		}
	}
	apply("old", now.Add(-10*24*time.Hour), true, 0)
	apply("old", now.Add(-9*24*time.Hour), false, 0)
	apply("long", now.Add(-10*24*time.Hour), true, 0) // still firing
	apply("recent", now.Add(-time.Hour), true, 0)
	apply("recent", now.Add(-50*time.Minute), false, 0)
	apply("never_fired", now.Add(-time.Hour), true, 3) // pending only
	apply("never_fired", now.Add(-50*time.Minute), false, 3)
	alerts, err := store.TimelineAlerts(ctx, now.Add(-7*24*time.Hour), 100)
	if err != nil {
		t.Fatal(err)
	}
	var rules []string
	for _, alert := range alerts {
		rules = append(rules, alert.RuleKey)
	}
	if strings.Join(rules, ",") != "recent,long" {
		t.Fatalf("unexpected timeline %v", rules)
	}
}
