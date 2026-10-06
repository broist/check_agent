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

func TestIncludeFilesystemExcludesReadOnlyPackageImages(t *testing.T) {
	collector := &Collector{fsTypes: map[string]bool{"squashfs": true, "ext4": true}}
	if collector.includeFilesystem("squashfs") {
		t.Fatal("squashfs must stay excluded even when explicitly listed")
	}
	if !collector.includeFilesystem("ext4") {
		t.Fatal("configured writable filesystem excluded")
	}
}
