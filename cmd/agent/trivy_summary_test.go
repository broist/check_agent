package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/broist/check_agent/internal/checks"
)

func TestRunTrivySummary(t *testing.T) {
	dir := t.TempDir()
	report := filepath.Join(dir, "image-1.json")
	if err := os.WriteFile(report, []byte(`{"ArtifactName":"nginx:1.27","Results":[{"Target":"nginx","Vulnerabilities":[
		{"VulnerabilityID":"CVE-1","PkgName":"a","InstalledVersion":"1","FixedVersion":"2","Severity":"CRITICAL"},
		{"VulnerabilityID":"CVE-2","PkgName":"b","InstalledVersion":"1","Severity":"HIGH"}]}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "summary.json")
	var stderr bytes.Buffer
	code := runTrivySummary([]string{"-out", out, "-scanner", "trivy 0.65.0",
		"nginx:1.27=" + report, "redis:7=" + filepath.Join(dir, "image-2.json")}, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	// The agent reader must accept what the subcommand writes.
	status, err := checks.ReadVulnerabilitySummary(out)
	if err != nil {
		t.Fatal(err)
	}
	if status.Scanner != "trivy 0.65.0" || len(status.Images) != 2 ||
		status.Images[0].Image != "nginx:1.27" || status.Images[0].FixableCritical != 1 ||
		status.Images[0].High != 1 || status.Images[1].Error == "" {
		t.Fatalf("unexpected summary %+v", status)
	}

	for _, args := range [][]string{
		{"nginx=" + report},               // missing -out
		{"-out", out, "nginx.json"},       // not IMAGE=FILE
		{"-out", out, "-unknown", "flag"}, // unknown flag
	} {
		stderr.Reset()
		if code := runTrivySummary(args, &stderr); code != 2 || !strings.Contains(stderr.String(), "trivy-summary") {
			t.Errorf("args %v: exit %d, stderr %q", args, code, stderr.String())
		}
	}
	if code := runTrivySummary([]string{"-out", filepath.Join(dir, "missing-dir", "s.json")}, &stderr); code != 1 {
		t.Errorf("unwritable output: exit %d", code)
	}
}
