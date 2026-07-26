package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/broist/check_agent/internal/auth"
	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/email"
	appserver "github.com/broist/check_agent/internal/server"
	"github.com/broist/check_agent/internal/storage"
	"github.com/broist/check_agent/internal/version"
	"golang.org/x/crypto/bcrypt"
)

func main() {
	os.Exit(run())
}

func run() int {
	configPath := flag.String("config", "/etc/monitorozo/server.yaml", "configuration file")
	showVersion := flag.Bool("version", false, "print version information")
	flag.Parse()
	if *showVersion {
		fmt.Printf("monitorozo-server %s commit=%s built=%s\n",
			version.Version, version.Commit, version.BuildTime)
		return 0
	}
	if flag.NArg() > 0 {
		runUtility(flag.Args())
		return 0
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	cfg, err := config.LoadServer(*configPath)
	if err != nil {
		logger.Error("configuration failed", "error", err)
		return 1
	}
	if err := os.MkdirAll(filepath.Dir(cfg.DatabasePath), 0o750); err != nil {
		logger.Error("database directory creation failed", "error", err)
		return 1
	}
	store, err := storage.Open(cfg.DatabasePath)
	if err != nil {
		logger.Error("database initialization failed", "error", err)
		return 1
	}
	defer func() {
		if err := store.Close(); err != nil {
			logger.Error("database close failed", "error", err)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	if err := store.SyncAgents(ctx, cfg.AgentTokens); err != nil {
		cancel()
		logger.Error("agent token synchronization failed", "error", err)
		return 1
	}
	cancel()
	app, err := appserver.New(cfg, store, email.New(cfg.SMTP), logger)
	if err != nil {
		logger.Error("server initialization failed", "error", err)
		return 1
	}
	stopCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	httpServer := &http.Server{
		Addr: cfg.Listen, Handler: app.Handler(),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 32 << 10,
		BaseContext:    func(net.Listener) context.Context { return stopCtx },
	}
	var background sync.WaitGroup
	background.Add(3)
	go func() {
		defer background.Done()
		runMaintenance(stopCtx, store, cfg, logger)
	}()
	go func() {
		defer background.Done()
		app.Run(stopCtx)
	}()
	go func() {
		defer background.Done()
		<-stopCtx.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := httpServer.Shutdown(ctx); err != nil {
			logger.Error("graceful shutdown failed", "error", err)
		}
	}()
	logger.Info("server started", "listen", cfg.Listen)
	serveErr := httpServer.ListenAndServe()
	stop()
	background.Wait()
	if serveErr != nil && serveErr != http.ErrServerClosed {
		logger.Error("server failed", "error", serveErr)
		return 1
	}
	logger.Info("server stopped")
	return 0
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
	case "version":
		fmt.Printf("monitorozo-server %s commit=%s built=%s\n",
			version.Version, version.Commit, version.BuildTime)
	case "healthcheck":
		if len(args) != 2 {
			fatalUsage("usage: monitorozo-server healthcheck URL")
		}
		client := &http.Client{Timeout: 3 * time.Second}
		response, err := client.Get(args[1])
		if err != nil {
			fatalUsage("healthcheck failed")
		}
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		if response.StatusCode != http.StatusOK {
			fatalUsage(fmt.Sprintf("healthcheck returned status %d", response.StatusCode))
		}
	default:
		fatalUsage("unknown command")
	}
}

func fatalUsage(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(2)
}
