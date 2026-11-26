package trivy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/model"
)

// sampleReport mirrors "trivy image --format json" (schema v2) output,
// including an OS result, a language result, a duplicate finding and an
// unfixed finding.
const sampleReport = `{
  "SchemaVersion": 2,
  "CreatedAt": "2026-11-26T04:41:12.123456789Z",
  "ArtifactName": "nginx:1.27.0",
  "ArtifactType": "container_image",
  "Metadata": {
    "OS": {"Family": "debian", "Name": "12.6"},
    "ImageID": "sha256:fffffc3a1b2c",
    "RepoTags": ["nginx:1.27.0"]
  },
  "Results": [
    {
      "Target": "nginx:1.27.0 (debian 12.6)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-45491", "PkgID": "libexpat1@2.5.0-1", "PkgName": "libexpat1",
         "InstalledVersion": "2.5.0-1", "FixedVersion": "2.5.0-1+deb12u1", "Status": "fixed",
         "SeveritySource": "nvd", "Severity": "CRITICAL", "Title": "libexpat: integer overflow"},
        {"VulnerabilityID": "CVE-2024-45491", "PkgID": "libexpat1@2.5.0-1", "PkgName": "libexpat1",
         "InstalledVersion": "2.5.0-1", "FixedVersion": "2.5.0-1+deb12u1", "Status": "fixed",
         "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-2023-45853", "PkgName": "zlib1g", "InstalledVersion": "1:1.2.13.dfsg-1",
         "Status": "will_not_fix", "Severity": "CRITICAL"},
        {"VulnerabilityID": "CVE-2024-6119", "PkgName": "libssl3", "InstalledVersion": "3.0.13-1~deb12u1",
         "FixedVersion": "3.0.14-1~deb12u2", "Status": "fixed", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-2024-2511", "PkgName": "libssl3", "InstalledVersion": "3.0.13-1~deb12u1",
         "Status": "affected", "Severity": "MEDIUM"},
        {"VulnerabilityID": "CVE-2011-3374", "PkgName": "apt", "InstalledVersion": "2.6.1",
         "Status": "affected", "Severity": "LOW"}
      ]
    },
    {
      "Target": "usr/local/lib/node_modules/npm/package.json",
      "Class": "lang-pkgs",
      "Type": "node-pkg",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2024-21538", "PkgName": "cross-spawn", "PkgPath": "usr/local/lib/node_modules/npm/node_modules/cross-spawn/package.json",
         "InstalledVersion": "7.0.3", "FixedVersion": "7.0.5, 6.0.6", "Status": "fixed", "Severity": "HIGH"},
        {"VulnerabilityID": "CVE-2024-4067", "PkgName": "micromatch", "InstalledVersion": "4.0.5",
         "FixedVersion": "4.0.8", "Status": "fixed", "Severity": "MEDIUM"}
      ]
    },
    {"Target": "app/requirements.txt", "Class": "lang-pkgs", "Type": "pip"}
  ]
}`

func TestSummarizeFileRealisticTrivyReport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nginx.json")
	writeFile(t, path, sampleReport)
	got, err := SummarizeFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := model.ImageVulnerabilities{Critical: 2, High: 2, Medium: 2,
		FixableCritical: 1, FixableHigh: 2, FixableMedium: 1}
	if got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestSummarizeFileWithoutFindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clean.json")
	writeFile(t, path, `{"SchemaVersion":2,"ArtifactName":"alpine:3.20","Results":[{"Target":"alpine:3.20 (alpine 3.20.3)","Class":"os-pkgs","Type":"alpine"}]}`)
	got, err := SummarizeFile(path)
	if err != nil || got != (model.ImageVulnerabilities{}) {
		t.Fatalf("got %+v err=%v", got, err)
	}
}

func TestSummarizeMarksBrokenInputsPerImage(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	empty := filepath.Join(dir, "empty.json")
	invalid := filepath.Join(dir, "invalid.json")
	writeFile(t, good, sampleReport)
	writeFile(t, empty, "")
	writeFile(t, invalid, "{not json")
	now := time.Date(2026, 11, 26, 4, 45, 0, 0, time.FixedZone("CET", 3600))
	status, warnings := Summarize([]Input{
		{Image: "postgres:16", Path: empty},
		{Image: "nginx:1.27.0", Path: good},
		{Image: "redis:7", Path: invalid},
		{Image: "app:missing", Path: filepath.Join(dir, "missing.json")},
		{Image: "bad image", Path: good},
		{Image: "nginx:1.27.0", Path: good},
	}, "trivy 0.65.0", "", now)
	if len(warnings) != 2 {
		t.Fatalf("expected invalid and duplicate warnings, got %v", warnings)
	}
	if !status.ScannedAt.Equal(now) || status.ScannedAt.Location() != time.UTC ||
		status.Scanner != "trivy 0.65.0" || status.Error != "" {
		t.Fatalf("unexpected metadata %+v", status)
	}
	names := make([]string, 0, len(status.Images))
	for _, image := range status.Images {
		names = append(names, image.Image)
	}
	if strings.Join(names, ",") != "app:missing,nginx:1.27.0,postgres:16,redis:7" {
		t.Fatalf("images are not sorted/deduplicated: %v", names)
	}
	for _, image := range status.Images {
		if image.Image == "nginx:1.27.0" {
			if image.Error != "" || image.FixableCritical != 1 {
				t.Fatalf("good image: %+v", image)
			}
			continue
		}
		if image.Error == "" || image.Critical != 0 {
			t.Fatalf("broken input must only carry an error: %+v", image)
		}
	}
	if err := status.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSummarizeLimitsImagesAndKeepsScanError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clean.json")
	writeFile(t, path, `{"Results":[]}`)
	var inputs []Input
	for i := 0; i < model.MaxScannedImages+3; i++ {
		inputs = append(inputs, Input{Image: fmt.Sprintf("app%03d:1", i), Path: path})
	}
	status, _ := Summarize(inputs, "trivy", "A Trivy-adatbázis frissítése sikertelen volt.", time.Now())
	if len(status.Images) != model.MaxScannedImages || !strings.Contains(status.Error, "adatbázis") ||
		!strings.Contains(status.Error, "Csak az első 64 kép") {
		t.Fatalf("unexpected limit handling: %d images, error %q", len(status.Images), status.Error)
	}
	if err := status.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseInputs(t *testing.T) {
	inputs, err := ParseInputs([]string{"nginx:1.27=/tmp/a.json", "registry:5000/app@sha256:ab=/tmp/b=c.json"})
	if err != nil || len(inputs) != 2 || inputs[1].Image != "registry:5000/app@sha256:ab" ||
		inputs[1].Path != "/tmp/b=c.json" {
		t.Fatalf("got %+v err=%v", inputs, err)
	}
	for _, bad := range []string{"nginx.json", "=x.json", "nginx="} {
		if _, err := ParseInputs([]string{bad}); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestWriteAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "summary.json")
	writeFile(t, path, "old")
	status := model.VulnerabilityStatus{ScannedAt: time.Now().UTC(), Scanner: "trivy 0.65.0",
		Images: []model.ImageVulnerabilities{{Image: "nginx:1.27", Critical: 1, FixableCritical: 1}}}
	if err := WriteAtomic(path, status); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var decoded model.VulnerabilityStatus
	if err := json.Unmarshal(data, &decoded); err != nil || decoded.Images[0].FixableCritical != 1 {
		t.Fatalf("decoded %+v err=%v", decoded, err)
	}
	if runtime.GOOS != "windows" {
		info, _ := os.Stat(path)
		if info.Mode().Perm() != 0o644 {
			t.Fatalf("mode %v, want 0644", info.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("temporary files left behind: %v", entries)
	}
	status.Images[0].Image = "bad image"
	if err := WriteAtomic(path, status); err == nil {
		t.Fatal("invalid summary written")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
