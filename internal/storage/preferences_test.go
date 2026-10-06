package storage

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
)

func TestPreviousReportUsesAgentTimeIndex(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "previous.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.SyncAgents(ctx, []config.AgentToken{{AgentID: "prod", Hash: "test"}}); err != nil {
		t.Fatal(err)
	}
	measuredAt := time.Now().UTC().Truncate(time.Second)
	for sequence, age := range []time.Duration{2 * time.Minute, time.Minute} {
		report := model.Report{
			AgentID: "prod", Sequence: uint64(sequence + 1),
			Timestamp: measuredAt.Add(-age), CPUPercent: float64(sequence + 1),
		}
		if err := store.SaveReport(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	previous, err := store.PreviousReport(ctx, "prod", measuredAt)
	if err != nil || previous.Sequence != 2 {
		t.Fatalf("previous report: %+v, err=%v", previous, err)
	}

	rows, err := store.db.QueryContext(ctx, "EXPLAIN QUERY PLAN "+previousReportQuery,
		"prod", measuredAt.Format(time.RFC3339Nano))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plan.String(), "idx_reports_agent_time") {
		t.Fatalf("previous report query does not use the time index: %s", plan.String())
	}
}
