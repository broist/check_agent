package storage

import (
	"context"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
)

func TestMaintainAggregatesAndRetainsMetrics(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "metrics.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.SyncAgents(ctx, []config.AgentToken{{AgentID: "node-01", Hash: "test-hash"}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Hour).Add(30 * time.Minute)
	oldHour := now.Add(-8 * 24 * time.Hour).Truncate(time.Hour)
	reports := []model.Report{
		{AgentID: "node-01", Timestamp: oldHour.Add(10 * time.Minute), Sequence: 1, CPUPercent: 20, Memory: model.Memory{UsedPercent: 40}},
		{AgentID: "node-01", Timestamp: oldHour.Add(20 * time.Minute), Sequence: 2, CPUPercent: 40, Memory: model.Memory{UsedPercent: 60}},
		{AgentID: "node-01", Timestamp: now.Add(-30 * time.Minute), Sequence: 3, CPUPercent: 10, Memory: model.Memory{UsedPercent: 25}},
	}
	for _, report := range reports {
		if err := store.SaveReport(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Maintain(ctx, now, 7*24*time.Hour, 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	points, err := store.History(ctx, "node-01", now.Add(-30*24*time.Hour), 7*24*time.Hour, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(points) != 2 {
		t.Fatalf("got %d history points, want hourly aggregate plus recent raw point: %+v", len(points), points)
	}
	if math.Abs(points[0].CPUPercent-30) > 0.001 ||
		math.Abs(points[0].MemoryPercent-50) > 0.001 || points[0].Samples != 2 {
		t.Fatalf("unexpected hourly aggregate: %+v", points[0])
	}
	if points[1].CPUPercent != 10 || points[1].Samples != 1 {
		t.Fatalf("unexpected recent raw point: %+v", points[1])
	}
	latest, err := store.LatestReports(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(latest) != 1 || latest[0].Sequence != 3 {
		t.Fatalf("raw retention did not remove old reports: %+v", latest)
	}
}

func TestDownsampleUsesSampleWeights(t *testing.T) {
	points := []HistoryPoint{
		{Timestamp: time.Unix(1, 0), CPUPercent: 10, MemoryPercent: 20, Samples: 1},
		{Timestamp: time.Unix(2, 0), CPUPercent: 30, MemoryPercent: 40, Samples: 3},
	}
	got := downsample(points, 1)
	if len(got) != 1 || math.Abs(got[0].CPUPercent-25) > 0.001 ||
		math.Abs(got[0].MemoryPercent-35) > 0.001 || got[0].Samples != 4 {
		t.Fatalf("unexpected weighted downsample: %+v", got)
	}
}
