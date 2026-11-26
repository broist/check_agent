package alerts

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
)

type Engine struct {
	store *storage.Store
	cfg   config.Server
}

func New(store *storage.Store, cfg config.Server) *Engine {
	if cfg.HTTPFailureCount == 0 {
		cfg.HTTPFailureCount = 3
	}
	if cfg.TLSWarningDays == 0 {
		cfg.TLSWarningDays = 14
	}
	if cfg.TLSCriticalDays == 0 {
		cfg.TLSCriticalDays = 3
	}
	if cfg.VulnerabilityScanMaxAge == 0 {
		cfg.VulnerabilityScanMaxAge = 48 * time.Hour
	}
	return &Engine{store: store, cfg: cfg}
}

func (e *Engine) EvaluateReport(ctx context.Context, report model.Report, now time.Time) error {
	rules := []storage.RuleEvaluation{
		{
			AgentID: report.AgentID, RuleKey: "cpu_high", Severity: "critical",
			Value: report.CPUPercent, Threshold: e.cfg.CPUAlertThreshold,
			Violated: report.CPUPercent > e.cfg.CPUAlertThreshold,
			For:      e.cfg.HighUsageDuration,
		},
		{
			AgentID: report.AgentID, RuleKey: "memory_high", Severity: "critical",
			Value: report.Memory.UsedPercent, Threshold: e.cfg.MemoryAlertThreshold,
			Violated: report.Memory.UsedPercent > e.cfg.MemoryAlertThreshold,
			For:      e.cfg.HighUsageDuration,
		},
		{
			AgentID: report.AgentID, RuleKey: "agent_offline", Severity: "critical",
			Value: 0, Threshold: e.cfg.AgentOfflineAfter.Seconds(), Violated: false,
		},
	}
	seen := make(map[string]bool)
	httpResources := make(map[string]model.HTTPStatus)
	serviceResources := make(map[string]model.ServiceStatus)
	for _, filesystem := range report.Filesystems {
		if !filesystem.Monitorable() {
			continue
		}
		rules = append(rules,
			storage.RuleEvaluation{
				AgentID: report.AgentID, RuleKey: "disk_warning",
				Resource: filesystem.Mountpoint, Severity: "warning",
				Value: filesystem.UsedPercent, Threshold: e.cfg.DiskWarningThreshold,
				Violated: filesystem.UsedPercent > e.cfg.DiskWarningThreshold &&
					filesystem.UsedPercent <= e.cfg.DiskCriticalThreshold,
			},
			storage.RuleEvaluation{
				AgentID: report.AgentID, RuleKey: "disk_critical",
				Resource: filesystem.Mountpoint, Severity: "critical",
				Value: filesystem.UsedPercent, Threshold: e.cfg.DiskCriticalThreshold,
				Violated: filesystem.UsedPercent > e.cfg.DiskCriticalThreshold,
			},
		)
	}
	for _, service := range report.Services {
		serviceResources[service.Name] = service
		if service.Error != "" || service.ActiveState == "" || service.ActiveState == "unknown" {
			continue
		}
		rules = append(rules, storage.RuleEvaluation{
			AgentID: report.AgentID, RuleKey: "systemd_unavailable",
			Resource: service.Name, Severity: "critical", Value: boolValue(
				service.ActiveState == "failed" || service.ActiveState == "inactive"),
			Threshold: 1, Violated: service.ActiveState == "failed" ||
				service.ActiveState == "inactive",
		})
	}
	for _, container := range report.Docker.Containers {
		rules = append(rules,
			storage.RuleEvaluation{
				AgentID: report.AgentID, RuleKey: "docker_stopped",
				Resource: container.Name, Severity: "critical",
				Value: boolValue(container.State != "running"), Threshold: 1,
				Violated: container.State != "running",
			},
			storage.RuleEvaluation{
				AgentID: report.AgentID, RuleKey: "docker_unhealthy",
				Resource: container.Name, Severity: "critical",
				Value: boolValue(container.Health == "unhealthy"), Threshold: 1,
				Violated: container.Health == "unhealthy",
			},
		)
	}
	for _, check := range report.HTTPChecks {
		httpResources[check.Name] = check
		rules = append(rules, storage.RuleEvaluation{
			AgentID: report.AgentID, RuleKey: "http_failed",
			Resource: check.Name, Severity: "critical",
			Value: float64(check.StatusCode), Threshold: 399,
			Violated: !check.OK, Consecutive: e.cfg.HTTPFailureCount,
		})
		if check.TLSDaysLeft != nil {
			severity := "warning"
			if *check.TLSDaysLeft <= e.cfg.TLSCriticalDays {
				severity = "critical"
			}
			rules = append(rules, storage.RuleEvaluation{
				AgentID: report.AgentID, RuleKey: "tls_expiring",
				Resource: check.Name, Severity: severity,
				Value: *check.TLSDaysLeft, Threshold: e.cfg.TLSWarningDays,
				Violated: *check.TLSDaysLeft <= e.cfg.TLSWarningDays,
			})
		}
	}
	rules = append(rules, e.securityRules(report, now)...)
	for _, rule := range rules {
		seen[ruleKey(rule.RuleKey, rule.Resource)] = true
		if _, err := e.store.ApplyRule(ctx, rule, now); err != nil {
			return fmt.Errorf("apply rule %s/%s: %w", rule.RuleKey, rule.Resource, err)
		}
	}
	return e.resolveMissing(ctx, report, seen, httpResources, serviceResources, now)
}

func (e *Engine) resolveMissing(
	ctx context.Context,
	report model.Report,
	seen map[string]bool,
	httpResources map[string]model.HTTPStatus,
	serviceResources map[string]model.ServiceStatus,
	now time.Time,
) error {
	active, err := e.store.ActiveAlerts(ctx)
	if err != nil {
		return err
	}
	for _, alert := range active {
		if alert.AgentID != report.AgentID || seen[ruleKey(alert.RuleKey, alert.Resource)] {
			continue
		}
		resolve := false
		switch alert.RuleKey {
		case "disk_warning", "disk_critical", "http_failed":
			resolve = true
		case "systemd_unavailable":
			service, exists := serviceResources[alert.Resource]
			resolve = !exists || (service.Error == "" &&
				service.ActiveState != "" && service.ActiveState != "unknown")
		case "docker_stopped", "docker_unhealthy":
			resolve = !report.Docker.Enabled || report.Docker.Available
		case "tls_expiring":
			check, exists := httpResources[alert.Resource]
			resolve = !exists || strings.HasPrefix(check.URL, "http://")
		case "security_updates_pending", "reboot_required":
			// A failed apt-check keeps the alert (and its grace timer) as is;
			// it resolves only when package reporting is switched off.
			resolve = report.Packages == nil
		case "vulnerability_scan_stale":
			resolve = report.Vulnerabilities == nil
		case "vulnerability_critical":
			// An image whose scan failed keeps its last state; an image that
			// is no longer running (or a disabled report) resolves.
			resolve = report.Vulnerabilities == nil ||
				!scannedImage(report.Vulnerabilities, alert.Resource)
		}
		if !resolve {
			continue
		}
		evaluation := storage.RuleEvaluation{
			AgentID: alert.AgentID, RuleKey: alert.RuleKey, Resource: alert.Resource,
			Severity: alert.Severity, Value: 0, Threshold: alert.Threshold,
		}
		if _, err := e.store.ApplyRule(ctx, evaluation, now); err != nil {
			return fmt.Errorf("resolve missing rule %s/%s: %w",
				alert.RuleKey, alert.Resource, err)
		}
	}
	return nil
}

func (e *Engine) EvaluateOffline(ctx context.Context, now time.Time) error {
	agents, err := e.store.AgentLastSeen(ctx)
	if err != nil {
		return err
	}
	for _, agent := range agents {
		seconds := now.Sub(agent.LastSeen).Seconds()
		if seconds < 0 {
			seconds = 0
		}
		rule := storage.RuleEvaluation{
			AgentID: agent.AgentID, RuleKey: "agent_offline", Severity: "critical",
			Value: seconds, Threshold: e.cfg.AgentOfflineAfter.Seconds(),
			Violated: seconds > e.cfg.AgentOfflineAfter.Seconds(),
		}
		if _, err := e.store.ApplyRule(ctx, rule, now); err != nil {
			return fmt.Errorf("apply offline rule for %s: %w", agent.AgentID, err)
		}
	}
	return nil
}

func (e *Engine) ResolveOnline(ctx context.Context, agentID string, now time.Time) error {
	_, err := e.store.ApplyRule(ctx, storage.RuleEvaluation{
		AgentID: agentID, RuleKey: "agent_offline", Severity: "critical",
		Value: 0, Threshold: e.cfg.AgentOfflineAfter.Seconds(), Violated: false,
	}, now)
	return err
}

// securityRules evaluates the package-update and container CVE sections.
// Sections missing from the report produce no rules (see resolveMissing).
func (e *Engine) securityRules(report model.Report, now time.Time) []storage.RuleEvaluation {
	var rules []storage.RuleEvaluation
	if packages := report.Packages; packages != nil {
		if packages.Error == "" {
			rules = append(rules, storage.RuleEvaluation{
				AgentID: report.AgentID, RuleKey: "security_updates_pending", Severity: "warning",
				Value: float64(packages.Security), Threshold: 0,
				Violated: packages.Security > 0, For: e.cfg.SecurityUpdateGrace,
			})
		}
		rules = append(rules, storage.RuleEvaluation{
			AgentID: report.AgentID, RuleKey: "reboot_required", Severity: "warning",
			Value: boolValue(packages.RebootRequired), Threshold: 1,
			Violated: packages.RebootRequired, For: e.cfg.RebootRequiredGrace,
		})
	}
	vulnerabilities := report.Vulnerabilities
	if vulnerabilities == nil {
		return rules
	}
	for _, image := range vulnerabilities.Images {
		if image.Error != "" {
			continue
		}
		rules = append(rules, storage.RuleEvaluation{
			AgentID: report.AgentID, RuleKey: "vulnerability_critical",
			Resource: image.Image, Severity: "critical",
			Value: float64(image.FixableCritical), Threshold: 0,
			Violated: image.FixableCritical > 0,
		})
	}
	maxAge := e.cfg.VulnerabilityScanMaxAge
	age := -1.0 // never scanned
	if !vulnerabilities.ScannedAt.IsZero() {
		age = now.Sub(vulnerabilities.ScannedAt).Hours()
		if age < 0 {
			age = 0
		}
	}
	rules = append(rules, storage.RuleEvaluation{
		AgentID: report.AgentID, RuleKey: "vulnerability_scan_stale", Severity: "warning",
		Value: age, Threshold: maxAge.Hours(),
		Violated: age < 0 || age > maxAge.Hours(),
	})
	return rules
}

func scannedImage(status *model.VulnerabilityStatus, image string) bool {
	for _, item := range status.Images {
		if item.Image == image {
			return true
		}
	}
	return false
}

func boolValue(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func ruleKey(rule, resource string) string {
	return rule + "\x00" + resource
}
