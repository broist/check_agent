package checks

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
)

func TestParseAptCheck(t *testing.T) {
	cases := []struct {
		name           string
		stderr, stdout string
		upgradable     int
		security       int
		wantErr        bool
	}{
		{name: "stderr", stderr: "12;3", upgradable: 12, security: 3},
		{name: "stderr newline", stderr: "0;0\n", upgradable: 0, security: 0},
		{name: "stdout", stdout: "7;1\n", upgradable: 7, security: 1},
		{name: "warning first", stderr: "W: some warning\n4;2\n", upgradable: 4, security: 2},
		{name: "garbage", stderr: "Traceback (most recent call last):", wantErr: true},
		{name: "empty", wantErr: true},
		{name: "security over total", stderr: "1;5", wantErr: true},
	}
	for _, tc := range cases {
		upgradable, security, err := ParseAptCheck([]byte(tc.stderr), []byte(tc.stdout))
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: expected error", tc.name)
			}
			continue
		}
		if err != nil || upgradable != tc.upgradable || security != tc.security {
			t.Errorf("%s: got %d;%d err=%v", tc.name, upgradable, security, err)
		}
	}
}

func TestReadRebootRequired(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "run", "reboot-required")
	fallback := filepath.Join(dir, "var-run", "reboot-required")
	if required, packages := ReadRebootRequired([]string{missing, fallback}); required || packages != nil {
		t.Fatalf("no marker: got %v %v", required, packages)
	}
	if err := os.MkdirAll(filepath.Dir(fallback), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, fallback, "*** System restart required ***\n")
	required, packages := ReadRebootRequired([]string{missing, fallback})
	if !required || packages != nil {
		t.Fatalf("fallback marker without pkgs: got %v %v", required, packages)
	}
	lines := []string{"linux-image-6.8.0-45-generic", "libc6", "libc6", "  dbus  ", "", "bad name;x"}
	for i := 0; i < 40; i++ {
		lines = append(lines, fmt.Sprintf("zz-pkg-%02d", i))
	}
	writeFile(t, fallback+".pkgs", strings.Join(lines, "\n"))
	required, packages = ReadRebootRequired([]string{missing, fallback})
	if !required || len(packages) != model.MaxRebootPackages {
		t.Fatalf("expected %d packages, got %v", model.MaxRebootPackages, packages)
	}
	if !reflect.DeepEqual(packages[:3], []string{"dbus", "libc6", "linux-image-6.8.0-45-generic"}) {
		t.Fatalf("packages are not unique and sorted: %v", packages[:3])
	}
}

func TestSecurityPackagesBackgroundRefresh(t *testing.T) {
	cfg := config.Agent{Packages: config.PackageChecks{Enabled: true, Interval: time.Hour,
		Command: "/usr/lib/update-notifier/apt-check"}}
	security := NewSecurity(cfg)
	marker := filepath.Join(t.TempDir(), "reboot-required")
	security.SetRebootPaths([]string{marker})
	fixed := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	security.now = func() time.Time { return fixed }

	initial := security.Packages()
	if initial == nil || initial.Error == "" || !initial.CheckedAt.IsZero() {
		t.Fatalf("expected pending first check, got %+v", initial)
	}
	var gotArgv []string
	security.SetRunner(func(_ context.Context, argv []string) ([]byte, []byte, error) {
		gotArgv = argv
		return nil, []byte("15;4"), nil
	})
	security.RefreshPackages(context.Background())
	status := security.Packages()
	if gotArgv[0] != "/usr/lib/update-notifier/apt-check" || status.Upgradable != 15 ||
		status.Security != 4 || status.Error != "" || !status.CheckedAt.Equal(fixed) || status.RebootRequired {
		t.Fatalf("unexpected status %+v (argv %v)", status, gotArgv)
	}
	if err := status.Validate(); err != nil {
		t.Fatal(err)
	}
	writeFile(t, marker, "")
	writeFile(t, marker+".pkgs", "linux-image-generic\n")
	if status := security.Packages(); !status.RebootRequired ||
		!reflect.DeepEqual(status.RebootPackages, []string{"linux-image-generic"}) {
		t.Fatalf("reboot state not refreshed: %+v", status)
	}

	security.SetRunner(func(context.Context, []string) ([]byte, []byte, error) {
		return nil, nil, &fs.PathError{Op: "stat", Path: "/usr/lib/update-notifier/apt-check", Err: fs.ErrNotExist}
	})
	security.RefreshPackages(context.Background())
	status = security.Packages()
	if !strings.Contains(status.Error, "Az apt-check nem található") || status.Upgradable != 15 ||
		status.Security != 4 {
		t.Fatalf("missing helper should keep the last counts and explain: %+v", status)
	}
	security.SetRunner(func(context.Context, []string) ([]byte, []byte, error) {
		return nil, []byte("E: " + strings.Repeat("hosszú hiba ", 100)), errors.New("exit status 1")
	})
	security.RefreshPackages(context.Background())
	status = security.Packages()
	if !strings.HasPrefix(status.Error, "Az apt-check hibával állt le") || !utf8.ValidString(status.Error) ||
		len(status.Error) > model.MaxSecurityError {
		t.Fatalf("unexpected command error %q", status.Error)
	}
	if err := status.Validate(); err != nil {
		t.Fatalf("error status must stay valid: %v", err)
	}

	disabled := NewSecurity(config.Agent{})
	if disabled.Packages() != nil || disabled.Vulnerabilities() != nil {
		t.Fatal("disabled sections must be omitted from reports")
	}
	disabled.Run(context.Background()) // returns immediately when disabled
}

func TestSecurityRunUsesExecForMissingCommand(t *testing.T) {
	_, _, err := execCommand(context.Background(), []string{filepath.Join(t.TempDir(), "apt-check")})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected not-exist error, got %v", err)
	}
}

func TestSecurityVulnerabilitySummaryCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "summary.json")
	security := NewSecurity(config.Agent{VulnerabilityReport: config.VulnerabilityReport{Path: path}})
	if status := security.Vulnerabilities(); status == nil || status.Error != MsgNoVulnerabilityScan {
		t.Fatalf("missing summary: got %+v", status)
	}
	writeFile(t, path, `{"scanned_at":"2026-11-26T04:41:00Z","scanner":"trivy 0.65.0","images":[
		{"image":"nginx:1.27","critical":1,"high":2,"medium":3,"fixable_critical":1,"fixable_high":2,"fixable_medium":0}]}`)
	status := security.Vulnerabilities()
	if status.Error != "" || len(status.Images) != 1 || status.Images[0].FixableCritical != 1 ||
		status.Scanner != "trivy 0.65.0" {
		t.Fatalf("unexpected summary %+v", status)
	}
	status.Images[0].Image = "mutated"
	if again := security.Vulnerabilities(); again.Images[0].Image != "nginx:1.27" {
		t.Fatal("cached summary was mutated through a returned copy")
	}
	// Unchanged mtime and size: the cache is used even if content differs.
	info, _ := os.Stat(path)
	writeFile(t, path, strings.Replace(mustRead(t, path), `"critical":1`, `"critical":7`, 1))
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if cached := security.Vulnerabilities(); cached.Images[0].Critical != 1 {
		t.Fatalf("expected cached result, got %+v", cached.Images[0])
	}
	// A broken update keeps the last good images and reports the problem.
	writeFile(t, path, `{"images":[{"image":"bad name"}]}`)
	if err := os.Chtimes(path, info.ModTime().Add(time.Minute), info.ModTime().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	broken := security.Vulnerabilities()
	if !strings.HasPrefix(broken.Error, "A CVE-összesítő érvénytelen") || len(broken.Images) != 1 ||
		broken.Images[0].Image != "nginx:1.27" {
		t.Fatalf("broken summary: got %+v", broken)
	}
	if err := broken.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if status := security.Vulnerabilities(); status.Error != MsgNoVulnerabilityScan || len(status.Images) != 0 {
		t.Fatalf("removed summary: got %+v", status)
	}
}

func TestTruncateUTF8(t *testing.T) {
	value := truncateUTF8(strings.Repeat("é", 300)+"\nx", 511)
	if !utf8.ValidString(value) || len(value) > 511 || strings.Contains(value, "\n") {
		t.Fatalf("invalid truncation: len=%d", len(value))
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
