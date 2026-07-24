package model

import (
	"math"
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
	report.AgentID = "web-01"
	report.Networks = []NetworkIO{{Interface: "eth0", ReceiveBytesRate: math.NaN()}}
	if err := report.Validate(now, 2*time.Minute); err == nil {
		t.Fatal("non-finite network rate accepted")
	}
	report.Networks = nil
	report.HTTPChecks = []HTTPStatus{{Name: "health", URL: "https://example.test", ResponseMS: math.Inf(1)}}
	if err := report.Validate(now, 2*time.Minute); err == nil {
		t.Fatal("non-finite HTTP latency accepted")
	}
}

func TestHTTPStatusTLSDays(t *testing.T) {
	days := 12.5
	if got := (HTTPStatus{TLSDaysLeft: &days}).TLSDays(); got != days {
		t.Fatalf("TLSDays()=%v, want %v", got, days)
	}
	if got := (HTTPStatus{}).TLSDays(); got != 0 {
		t.Fatalf("nil TLSDays()=%v, want 0", got)
	}
}
