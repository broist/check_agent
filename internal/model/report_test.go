package model

import (
	"testing"
	"time"
)

func TestReportValidate(t *testing.T) {
	now := time.Now().UTC()
	report := Report{
		AgentID: "web-01", Timestamp: now, Sequence: 1, CPUPercent: 50,
		Memory: Memory{UsedPercent: 25, SwapPercent: 0},
	}
	if err := report.Validate(now, 2*time.Minute); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	report.AgentID = "../bad"
	if err := report.Validate(now, 2*time.Minute); err == nil {
		t.Fatal("unsafe agent ID accepted")
	}
}
