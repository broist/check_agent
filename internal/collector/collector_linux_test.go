//go:build linux

package collector

import "testing"

func TestStatTargetUsesConfiguredHostRoot(t *testing.T) {
	collector := &Collector{paths: Paths{HostRoot: "/host/root"}}
	target, ok := collector.statTarget("/var/lib")
	if !ok || target != "/host/root/var/lib" {
		t.Fatalf("target=%q ok=%v", target, ok)
	}
}
