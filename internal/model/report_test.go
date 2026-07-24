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
	if err := report.Validate(now, 2*time.Minute, 24*time.Hour); err != nil {
		t.Fatalf("valid report rejected: %v", err)
	}
	report.AgentID = "../bad"
	if err := report.Validate(now, 2*time.Minute, 24*time.Hour); err == nil {
		t.Fatal("unsafe agent ID accepted")
	}
	report.AgentID = "web-01"
	report.Networks = []NetworkIO{{Interface: "eth0", ReceiveBytesRate: math.NaN()}}
	if err := report.Validate(now, 2*time.Minute, 24*time.Hour); err == nil {
		t.Fatal("non-finite network rate accepted")
	}
	report.Networks = nil
	report.HTTPChecks = []HTTPStatus{{Name: "health", URL: "https://example.test", ResponseMS: math.Inf(1)}}
	if err := report.Validate(now, 2*time.Minute, 24*time.Hour); err == nil {
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

func TestReportValidateAllowsBoundedBufferedAge(t *testing.T) {
	now := time.Now().UTC()
	report := Report{
		AgentID: "node-01", Timestamp: now.Add(-10 * time.Minute), Sequence: 1,
		Memory: Memory{},
	}
	if err := report.Validate(now, 2*time.Minute, 24*time.Hour); err != nil {
		t.Fatalf("bounded buffered report rejected: %v", err)
	}
	report.Timestamp = now.Add(-25 * time.Hour)
	if err := report.Validate(now, 2*time.Minute, 24*time.Hour); err == nil {
		t.Fatal("expired buffered report accepted")
	}
	report.Timestamp = now.Add(3 * time.Minute)
	if err := report.Validate(now, 2*time.Minute, 24*time.Hour); err == nil {
		t.Fatal("future-skewed report accepted")
	}
}
