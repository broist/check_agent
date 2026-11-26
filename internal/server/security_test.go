package server

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
)

func renderOverview(t *testing.T, reports ...model.Report) (string, dashboardData) {
	t.Helper()
	cfg := config.Server{
		AgentTokens: []config.AgentToken{
			{AgentID: "web-01", Hash: "test-hash"}, {AgentID: "db-01", Hash: "test-hash"},
		},
		SessionSecret: "0123456789abcdef0123456789abcdef", SessionIdleTimeout: time.Minute,
		SessionMaxLifetime: time.Hour, AgentOfflineAfter: 2 * time.Minute,
		DiskWarningThreshold: 85, DiskCriticalThreshold: 95,
	}
	store, err := storage.Open(filepath.Join(t.TempDir(), "dashboard.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	if err := store.SyncAgents(ctx, cfg.AgentTokens); err != nil {
		t.Fatal(err)
	}
	for _, report := range reports {
		if err := store.SaveReport(ctx, report); err != nil {
			t.Fatal(err)
		}
	}
	app, err := New(cfg, store, &recordingMailer{}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	latest, err := store.LatestReports(ctx)
	if err != nil {
		t.Fatal(err)
	}
	data, err := app.dashboardView(ctx, latest, nil)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := app.templates.ExecuteTemplate(&output, "overview", data); err != nil {
		t.Fatal(err)
	}
	return output.String(), data
}

func TestDashboardRendersSecuritySection(t *testing.T) {
	now := time.Now().UTC()
	longImage := "registry.example.com:5000/team/" + strings.Repeat("very-long-image-name-", 8) + ":1.0"
	secured := model.Report{
		AgentID: "web-01", Hostname: "web-production", Timestamp: now, Sequence: 1,
		Packages: &model.PackageStatus{CheckedAt: now, Upgradable: 12, Security: 3,
			RebootRequired: true, RebootPackages: []string{"libc6", "linux-image-generic"}},
		Vulnerabilities: &model.VulnerabilityStatus{ScannedAt: now, Scanner: "trivy 0.65.0",
			Images: []model.ImageVulnerabilities{
				{Image: "nginx:1.27", Critical: 3, High: 1, Medium: 2, FixableCritical: 2, FixableHigh: 1},
				{Image: "redis:7", High: 2, FixableHigh: 1},
				{Image: longImage},
				{Image: "postgres:16", Error: "A vizsgálat üres eredményt adott."},
			}},
	}
	legacy := model.Report{AgentID: "db-01", Hostname: "db-legacy", Timestamp: now, Sequence: 1}
	html, data := renderOverview(t, secured, legacy)

	for _, fragment := range []string{
		"Biztonság", "<b>12 (ebből bizt.: 3)</b>", "<b>12 vár · 3 bizt.</b>",
		"<b>szükséges</b>", "Újraindítás kell", "libc6, linux-image-generic",
		"4 kép · vizsgálva ", "trivy 0.65.0", `<div class="cv critical">`, `<div class="cv warning">`, `<div class="cv ok">`,
		`title="javítható: 2/1/0"`, "A vizsgálat üres eredményt adott.", longImage, "nginx:1.27", "2 krit.",
		"Csomagállapot nem érkezik (packages kikapcsolva)", "Ezen a gépen nincs CVE-vizsgálat",
	} {
		if !strings.Contains(html, fragment) {
			t.Errorf("rendered overview misses %q", fragment)
		}
	}
	var web serverView
	for _, view := range data.Reports {
		if view.AgentID == "web-01" {
			web = view
		}
	}
	if web.PackageLevel != "warning" || len(web.Images) != 4 {
		t.Fatalf("unexpected view %+v", web)
	}
	issues := strings.Join(web.Issues, "\n")
	if !strings.Contains(issues, "Javítható kritikus CVE: nginx:1.27 (2 db)") ||
		!strings.Contains(issues, "Újraindítás szükséges") || strings.Contains(issues, "redis:7") {
		t.Fatalf("unexpected issues %q", issues)
	}
}

func TestDashboardSecurityEmptyStates(t *testing.T) {
	now := time.Now().UTC()
	report := model.Report{
		AgentID: "web-01", Hostname: "web", Timestamp: now, Sequence: 1,
		Packages:        &model.PackageStatus{Error: "Az első csomagellenőrzés folyamatban."},
		Vulnerabilities: &model.VulnerabilityStatus{Error: "Még nem készült CVE-vizsgálat."},
	}
	html, _ := renderOverview(t, report)
	for _, fragment := range []string{
		"Csomagellenőrzés: még nem futott", "Az első csomagellenőrzés folyamatban.",
		"Még nem készült CVE-vizsgálat.", "<b>nem kell</b>", "Nincs biztonsági adat",
	} {
		if !strings.Contains(html, fragment) {
			t.Errorf("rendered overview misses %q", fragment)
		}
	}
	if strings.Contains(html, `class="cves"`) {
		t.Error("empty scan must not render a table")
	}
}

func TestLabelSecurityRules(t *testing.T) {
	for _, rule := range []string{"security_updates_pending", "reboot_required",
		"vulnerability_critical", "vulnerability_scan_stale"} {
		if label := labelRule(rule); label == rule {
			t.Errorf("rule %s has no Hungarian label", rule)
		}
	}
}
