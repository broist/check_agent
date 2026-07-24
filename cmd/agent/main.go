package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/broist/check_agent/internal/agent"
	"github.com/broist/check_agent/internal/checks"
	"github.com/broist/check_agent/internal/collector"
	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
)

func main() {
	configPath := flag.String("config", "/etc/monitorozo/agent.yaml", "configuration file")
	flag.Parse()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadAgent(*configPath)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	metrics, err := collector.New(cfg.IncludeFSTypes)
	if err != nil {
		logger.Error("collector initialization failed", "error", err)
		os.Exit(1)
	}
	sequence, err := agent.NewSequence(cfg.StateFile)
	if err != nil {
		logger.Error("sequence initialization failed", "error", err)
		os.Exit(1)
	}
	runtimeChecks := checks.New(cfg)
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	queue := make(chan model.Report, cfg.QueueSize)
	sender := agent.NewSender(cfg.ServerURL, cfg.Token, cfg.RequestTimeout)
	go sender.Run(ctx, queue, func(err error) { logger.Error("delivery failed", "error", err) })

	ticker := time.NewTicker(cfg.Interval)
	defer ticker.Stop()
	logger.Info("agent started", "agent_id", cfg.AgentID, "interval", cfg.Interval)
	collect := func() {
		report, err := metrics.Collect()
		if err != nil {
			logger.Error("collection failed", "error", err)
			return
		}
		report.AgentID = cfg.AgentID
		report.Services, report.Docker, report.HTTPChecks, report.TCPChecks =
			runtimeChecks.Collect(ctx)
		report.Sequence, err = sequence.Next()
		if err != nil {
			logger.Error("sequence update failed", "error", err)
			return
		}
		select {
		case queue <- report:
		default:
			select {
			case <-queue:
			default:
			}
			queue <- report
			logger.Warn("report queue full; oldest report dropped")
		}
	}
	collect()
	for {
		select {
		case <-ctx.Done():
			logger.Info("agent stopped")
			return
		case <-ticker.C:
			collect()
		}
	}
}
