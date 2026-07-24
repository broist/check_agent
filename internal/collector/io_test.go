package collector

import (
	"math"
	"strings"
	"testing"
)

func TestParseDiskStatsAndRates(t *testing.T) {
	previous, err := parseDiskStats(strings.NewReader("8 0 xvda 100 0 200 0 50 0 300 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := parseDiskStats(strings.NewReader("8 0 xvda 110 0 240 0 56 0 360 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	rates := calculateDiskIO(previous, current, 10)
	if len(rates) != 1 {
		t.Fatalf("got %d devices", len(rates))
	}
	if rates[0].ReadBytesPerSecond != 2048 ||
		rates[0].WriteBytesPerSecond != 3072 ||
		rates[0].ReadOpsPerSecond != 1 ||
		math.Abs(rates[0].WriteOpsPerSecond-0.6) > 0.001 {
		t.Fatalf("unexpected disk rates: %+v", rates[0])
	}
}

func TestParseNetworkStatsAndRates(t *testing.T) {
	header := "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
	previous, err := parseNetworkStats(strings.NewReader(header + " eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	current, err := parseNetworkStats(strings.NewReader(header + " eth0: 3000 30 0 0 0 0 0 0 5000 50 0 0 0 0 0 0\n"))
	if err != nil {
		t.Fatal(err)
	}
	rates := calculateNetworkIO(previous, current, 10)
	if len(rates) != 1 ||
		rates[0].ReceiveBytesRate != 200 ||
		rates[0].TransmitBytesRate != 300 ||
		rates[0].ReceivePacketRate != 2 ||
		rates[0].TransmitPacketRate != 3 {
		t.Fatalf("unexpected network rates: %+v", rates)
	}
}

func TestCounterResetDoesNotUnderflow(t *testing.T) {
	if got := counterDelta(1, 100); got != 0 {
		t.Fatalf("counter reset produced delta %d", got)
	}
}
