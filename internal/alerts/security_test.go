package alerts

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
)

func securityConfig() config.Server {
	return config.Server{
		CPUAlertThreshold: 90, MemoryAlertThreshold: 90,
		HighUsageDuration: 5 * time.Minute, DiskWarningThreshold: 85,
		DiskCriticalThreshold: 95, AgentOfflineAfter: 2 * time.Minute,
		SecurityUpdateGrace: 72 * time.Hour, RebootRequiredGrace: 168 * time.Hour,
		VulnerabilityScanMaxAge: 48 * time.Hour,
	}
}

func findAlert(alerts []storage.Alert, rule, resource string) *storage.Alert {
	for index := range alerts {
		if alerts[index].RuleKey == rule && alerts[index].Resource == resource {
			return &alerts[index]
		}
	}
	return nil
}

func TestPackageRulesUseGracePeriods(t *testing.T) {
	store := newTestStore(t)
	engine := New(store, securityConfig())
	ctx := context.Background()
	start := time.Now().UTC()
	report := model.Report{AgentID: "node-01", Memory: model.Memory{UsedPercent: 20},
		Packages: &model.PackageStatus{CheckedAt: start, Upgradable: 10, Security: 4, RebootRequired: true}}
	evaluate := func(at time.Time) []storage.Alert {
		t.Helper()
		if err := engine.EvaluateReport(ctx, report, at); err != nil {
			t.Fatal(err)
		}
		active, err := store.ActiveAlerts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return active
	}
	active := evaluate(start)
	if a := findAlert(active, "security_updates_pending", ""); a == nil || a.State != "pending" ||
		a.Severity != "warning" || a.Value != 4 {
		t.Fatalf("security updates: %+v", a)
	}
	if a := findAlert(active, "reboot_required", ""); a == nil || a.State != "pending" {
		t.Fatalf("reboot: %+v", a)
	}
	// A failing apt-check neither resolves nor restarts the grace period.
	report.Packages.Error = "Az apt-check 60 másodperc alatt nem futott le."
	active = evaluate(start.Add(73 * time.Hour))
	if a := findAlert(active, "security_updates_pending", ""); a == nil || a.State != "pending" {
		t.Fatalf("errored check must keep the alert unchanged: %+v", a)
	}
	report.Packages.Error = ""
	active = evaluate(start.Add(74 * time.Hour))
	if a := findAlert(active, "security_updates_pending", ""); a == nil || a.State != "firing" {
		t.Fatalf("expected firing after grace: %+v", a)
	}
	if a := findAlert(active, "reboot_required", ""); a == nil || a.State != "pending" {
		t.Fatalf("reboot must still wait for its longer grace: %+v", a)
	}
	active = evaluate(start.Add(169 * time.Hour))
	if a := findAlert(active, "reboot_required", ""); a == nil || a.State != "firing" {
		t.Fatalf("expected firing reboot alert: %+v", a)
	}
	report.Packages.Security = 0
	active = evaluate(start.Add(170 * time.Hour))
	if findAlert(active, "security_updates_pending", "") != nil {
		t.Fatal("security alert must resolve when no update is pending")
	}
	// Disabling package reporting resolves the remaining package alert.
	report.Packages = nil
	if active = evaluate(start.Add(171 * time.Hour)); len(active) != 0 {
		t.Fatalf("expected all package alerts resolved, got %+v", active)
	}
}

func TestVulnerabilityRulesAndResolution(t *testing.T) {
	store := newTestStore(t)
	engine := New(store, securityConfig())
	ctx := context.Background()
	now := time.Now().UTC()
	report := model.Report{AgentID: "node-01", Memory: model.Memory{UsedPercent: 20},
		Vulnerabilities: &model.VulnerabilityStatus{ScannedAt: now.Add(-2 * time.Hour), Scanner: "trivy 0.65.0",
			Images: []model.ImageVulnerabilities{
				{Image: "nginx:1.27", Critical: 3, FixableCritical: 2},
				{Image: "redis:7", Critical: 1, High: 4, FixableHigh: 4},
				{Image: "postgres:16", Critical: 1, FixableCritical: 1},
			}}}
	evaluate := func(at time.Time) []storage.Alert {
		t.Helper()
		if err := engine.EvaluateReport(ctx, report, at); err != nil {
			t.Fatal(err)
		}
		active, err := store.ActiveAlerts(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return active
	}
	active := evaluate(now)
	if a := findAlert(active, "vulnerability_critical", "nginx:1.27"); a == nil || a.State != "firing" ||
		a.Severity != "critical" || a.Value != 2 {
		t.Fatalf("nginx: %+v", a)
	}
	if findAlert(active, "vulnerability_critical", "redis:7") != nil {
		t.Fatal("unfixable critical finding must not alert")
	}
	if findAlert(active, "vulnerability_scan_stale", "") != nil {
		t.Fatal("fresh scan reported as stale")
	}
	// A failed rescan of postgres keeps its alert; nginx is no longer running.
	report.Vulnerabilities.Images = []model.ImageVulnerabilities{
		{Image: "redis:7"}, {Image: "postgres:16", Error: "A vizsgálat üres eredményt adott."},
	}
	active = evaluate(now.Add(time.Hour))
	if findAlert(active, "vulnerability_critical", "nginx:1.27") != nil {
		t.Fatal("alert of a removed image must resolve")
	}
	if a := findAlert(active, "vulnerability_critical", "postgres:16"); a == nil || a.State != "firing" {
		t.Fatalf("errored image must keep its alert: %+v", a)
	}
	// Stale scan: older than the configured maximum age.
	active = evaluate(now.Add(51 * time.Hour))
	if a := findAlert(active, "vulnerability_scan_stale", ""); a == nil || a.State != "firing" ||
		a.Value < 50 || a.Threshold != 48 {
		t.Fatalf("stale scan: %+v", a)
	}
	// The section disappears (vulnerability_report disabled): everything resolves.
	report.Vulnerabilities = nil
	if active = evaluate(now.Add(52 * time.Hour)); len(active) != 0 {
		t.Fatalf("expected vulnerability alerts resolved, got %+v", active)
	}
}

func TestVulnerabilityScanNeverRan(t *testing.T) {
	store := newTestStore(t)
	cfg := securityConfig()
	cfg.VulnerabilityScanMaxAge = 0 // engine default (48h) applies
	engine := New(store, cfg)
	ctx := context.Background()
	report := model.Report{AgentID: "node-01",
		Vulnerabilities: &model.VulnerabilityStatus{Error: "Még nem készült CVE-vizsgálat."}}
	if err := engine.EvaluateReport(ctx, report, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	active, err := store.ActiveAlerts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a := findAlert(active, "vulnerability_scan_stale", "")
	if a == nil || a.Value != -1 || a.Threshold != 48 {
		t.Fatalf("missing scan: %+v", a)
	}
	if !strings.Contains(Describe(*a).Measurement, "Még nem készült CVE-vizsgálat") {
		t.Fatalf("unexpected measurement %q", Describe(*a).Measurement)
	}
}

func TestSecurityDescriptions(t *testing.T) {
	cases := map[string][]string{
		"security_updates_pending": {"Biztonsági frissítések", "sudo apt-get upgrade"},
		"reboot_required":          {"Újraindítás szükséges", "sudo reboot", "karbantartási ablakban"},
		"vulnerability_critical":   {"kritikus sérülékenység", "nginx:1.27", "telepítsd újra"},
		"vulnerability_scan_stale": {"CVE-vizsgálat", "systemctl status monitorozo-cvescan.timer", "journalctl -u monitorozo-cvescan"},
	}
	for rule, fragments := range cases {
		description := Describe(storage.Alert{RuleKey: rule, Resource: "nginx:1.27", Value: 2, Threshold: 48})
		text := strings.ToLower(description.Title + " " + description.Measurement + " " + description.Action)
		for _, fragment := range fragments {
			if !strings.Contains(text, strings.ToLower(fragment)) {
				t.Errorf("%s: %q missing from %+v", rule, fragment, description)
			}
		}
	}
}
