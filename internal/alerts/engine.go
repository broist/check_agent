package alerts

import (
	"context"
	"fmt"
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
	for _, filesystem := range report.Filesystems {
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
	for _, rule := range rules {
		if _, err := e.store.ApplyRule(ctx, rule, now); err != nil {
			return fmt.Errorf("apply rule %s/%s: %w", rule.RuleKey, rule.Resource, err)
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
