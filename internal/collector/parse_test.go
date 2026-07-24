package collector

import (
	"math"
	"strings"
	"testing"
)

func TestCPUPercent(t *testing.T) {
	previous, err := parseCPU(strings.NewReader("cpu  100 0 100 800 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := parseCPU(strings.NewReader("cpu  150 0 150 900 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cpuPercent(previous, current); math.Abs(got-50) > 0.001 {
		t.Fatalf("got %.2f, want 50", got)
	}
}

func TestParseMemory(t *testing.T) {
	input := "MemTotal: 1000 kB\nMemAvailable: 250 kB\nSwapTotal: 100 kB\nSwapFree: 40 kB\n"
	got, err := parseMemory(strings.NewReader(input))
	if err != nil {
		t.Fatal(err)
	}
	if got.UsedPercent != 75 || got.SwapPercent != 60 {
		t.Fatalf("unexpected percentages: %+v", got)
	}
}
