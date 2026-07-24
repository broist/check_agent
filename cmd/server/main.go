package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/broist/check_agent/internal/auth"
	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/email"
	appserver "github.com/broist/check_agent/internal/server"
	"github.com/broist/check_agent/internal/storage"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	configPath := flag.String("config", "/etc/monitorozo/server.yaml", "configuration file")
	flag.Parse()
	if flag.NArg() > 0 {
		runUtility(flag.Args())
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o750); err != nil {
		logger.Error("database directory creation failed", "error", err)
		os.Exit(1)
	}
	store, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		logger.Error("database initialization failed", "error", err)
		os.Exit(1)
	}
	defer store.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := store.SyncAgents(ctx, cfg.AgentTokens); err != nil {
		cancel()
		logger.Error("agent token synchronization failed", "error", err)
		os.Exit(1)
	}
	cancel()
	app, err := appserver.New(cfg, store, email.New(cfg.SMTP), logger)
	if err != nil {
		logger.Error("server initialization failed", "error", err)
		os.Exit(1)
	}
	httpServer := &http.Server{
		Addr: cfg.Listen, Handler: app.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10,
	}
	stopCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go runMaintenance(stopCtx, store, cfg, logger)
	go func() {
		<-stopCtx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}()
	logger.Info("server started", "listen", cfg.Listen)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server failed", "error", err)
		os.Exit(1)
	}
}

func runMaintenance(ctx context.Context, store *storage.Store, cfg config.Server, logger *slog.Logger) {
	run := func() {
		maintenanceCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		if err := store.Maintain(maintenanceCtx, time.Now(), cfg.RawRetention, cfg.AggregateRetention); err != nil &&
			ctx.Err() == nil {
			logger.Error("metric maintenance failed", "error", err)
		}
	}
	run()
	ticker := time.NewTicker(cfg.MaintenanceInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}

func runUtility(args []string) {
	switch args[0] {
	case "hash-token":
		if len(args) != 2 {
			fatalUsage("usage: monitorozo-server hash-token TOKEN")
		}
		value, err := auth.HashToken(args[1])
		if err != nil {
			fatalUsage(err.Error())
		}
		fmt.Println(value)
	case "hash-password":
		if len(args) != 2 || len(args[1]) < 12 {
			fatalUsage("password must contain at least 12 characters")
		}
		value, err := bcrypt.GenerateFromPassword([]byte(args[1]), 12)
		if err != nil {
			fatalUsage(err.Error())
		}
		fmt.Println(string(value))
	case "generate-secret":
		value := make([]byte, 32)
		if _, err := rand.Read(value); err != nil {
			fatalUsage(err.Error())
		}
		fmt.Println(base64.RawURLEncoding.EncodeToString(value))
	default:
		fatalUsage("unknown command")
	}
}

func fatalUsage(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
