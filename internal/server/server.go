package server

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/broist/check_agent/internal/alerts"
	"github.com/broist/check_agent/internal/auth"
	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/model"
	"github.com/broist/check_agent/internal/storage"
	"github.com/broist/check_agent/web"
	"golang.org/x/crypto/bcrypt"
)

const (
	maxReportBody = 256 << 10
	maxFormBody   = 16 << 10
)

type AlertSender interface {
	Send(storage.Alert, string) error
}

type Server struct {
	cfg          config.Server
	store        *storage.Store
	mailer       AlertSender
	logger       *slog.Logger
	sessions     *auth.Sessions
	loginLimiter *auth.Limiter
	apiLimiter   *auth.Limiter
	templates    *template.Template
	trustedProxy *net.IPNet
	events       *broker
	alerts       *alerts.Engine
	notifyWake   chan struct{}
}

type dashboardData struct {
	CSRF         string
	Reports      []model.Report
	Alerts       []storage.Alert
	AlertHistory []storage.Alert
}

func New(cfg config.Server, store *storage.Store, mailer AlertSender, logger *slog.Logger) (*Server, error) {
	funcs := template.FuncMap{
		"time": func(value time.Time) string { return value.Local().Format("2006-01-02 15:04:05") },
		"duration": func(seconds uint64) string {
			return formatHungarianDuration(time.Duration(seconds) * time.Second)
		},
		"rate": func(value float64) string {
			units := []string{"B/s", "KiB/s", "MiB/s", "GiB/s"}
			unit := 0
			for value >= 1024 && unit < len(units)-1 {
				value /= 1024
				unit++
			}
			return fmt.Sprintf("%.1f %s", value, units[unit])
		},
		"online": func(value time.Time) string {
			if time.Since(value) <= cfg.AgentOfflineAfter {
				return "elérhető"
			}
			return "nem elérhető"
		},
		"status": func(value time.Time) string {
			if time.Since(value) <= cfg.AgentOfflineAfter {
				return "ok"
			}
			return "offline"
		},
		"alertState":     labelAlertState,
		"severity":       labelSeverity,
		"rule":           labelRule,
		"serviceState":   labelServiceState,
		"containerState": labelContainerState,
	}
	templates, err := template.New("pages").Funcs(funcs).ParseFS(web.Files, "*.html")
	if err != nil {
		return nil, err
	}
	result := &Server{
		cfg: cfg, store: store, mailer: mailer, logger: logger,
		sessions: auth.NewSessions(cfg.SessionSecret, cfg.SessionIdleTimeout,
			cfg.SessionMaxLifetime, cfg.SecureCookies),
		loginLimiter: auth.NewLimiter(5, 15*time.Minute),
		apiLimiter:   auth.NewLimiter(120, time.Minute),
		templates:    templates,
		events:       newBroker(),
		alerts:       alerts.New(store, cfg),
		notifyWake:   make(chan struct{}, 1),
	}
	if cfg.TrustedProxy != "" {
		_, network, err := net.ParseCIDR(cfg.TrustedProxy)
		if err != nil {
			return nil, fmt.Errorf("trusted_proxy must be CIDR notation: %w", err)
		}
		result.trustedProxy = network
	}
	return result, nil
}

func formatHungarianDuration(value time.Duration) string {
	value = value.Round(time.Minute)
	if value < time.Minute {
		return "< 1 perc"
	}
	days := value / (24 * time.Hour)
	value -= days * 24 * time.Hour
	hours := value / time.Hour
	value -= hours * time.Hour
	minutes := value / time.Minute
	parts := make([]string, 0, 3)
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d nap", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d óra", hours))
	}
	if minutes > 0 && days == 0 {
		parts = append(parts, fmt.Sprintf("%d perc", minutes))
	}
	if len(parts) == 0 {
		return "0 perc"
	}
	return strings.Join(parts, " ")
}

func labelAlertState(value string) string {
	switch value {
	case "pending":
		return "várakozik"
	case "firing":
		return "aktív"
	case "resolved":
		return "megoldva"
	default:
		return value
	}
}

func labelSeverity(value string) string {
	switch value {
	case "critical":
		return "kritikus"
	case "warning":
		return "figyelmeztetés"
	default:
		return value
	}
}

func labelRule(value string) string {
	switch value {
	case "cpu_high":
		return "magas CPU használat"
	case "memory_high":
		return "magas memóriahasználat"
	case "agent_offline":
		return "agent nem elérhető"
	case "disk_warning":
		return "magas lemezhasználat"
	case "disk_critical":
		return "kritikus lemezhasználat"
	case "systemd_unavailable":
		return "systemd szolgáltatás nem elérhető"
	case "docker_stopped":
		return "Docker konténer leállt"
	case "docker_unhealthy":
		return "Docker konténer hibás"
	case "http_failed":
		return "HTTP ellenőrzés sikertelen"
	case "tls_expiring":
		return "TLS tanúsítvány lejár"
	default:
		return value
	}
}

func labelServiceState(value string) string {
	switch value {
	case "active":
		return "aktív"
	case "inactive":
		return "inaktív"
	case "failed":
		return "hibás"
	case "unknown":
		return "ismeretlen"
	default:
		return value
	}
}

func labelContainerState(value string) string {
	switch value {
	case "running":
		return "fut"
	case "exited":
		return "kilépett"
	case "created":
		return "létrehozva"
	case "paused":
		return "szüneteltetve"
	case "restarting":
		return "újraindul"
	case "dead":
		return "halott"
	case "healthy":
		return "egészséges"
	case "unhealthy":
		return "hibás"
	default:
		return value
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /readyz", s.ready)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.requireAuth(s.logout))
	mux.HandleFunc("POST /api/v1/reports", s.ingest)
	mux.HandleFunc("GET /api/v1/history", s.requireAuth(s.history))
	mux.HandleFunc("GET /api/v1/events", s.requireAuth(s.eventStream))
	mux.HandleFunc("POST /api/v1/alerts/{id}/ack", s.requireAuth(s.acknowledgeAlert))
	mux.Handle("GET /static/", http.FileServer(http.FS(web.Files)))
	mux.HandleFunc("GET /", s.requireAuth(s.dashboard))
	return s.securityHeaders(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
}

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := contextWithTimeout(r, 2*time.Second)
	defer cancel()
	w.Header().Set("Content-Type", "application/json")
	if err := s.store.Ping(ctx); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"status":"unavailable"}`)
		return
	}
	_, _ = io.WriteString(w, `{"status":"ready"}`)
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.sessions.Get(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login", struct{ Error string }{})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.loginLimiter.Allow(ip) {
		http.Error(w, "túl sok bejelentkezési próbálkozás", http.StatusTooManyRequests)
		return
	}
	if !s.validOrigin(r) {
		http.Error(w, "érvénytelen eredet", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(s.cfg.AdminPasswordHash), []byte(r.FormValue("password")))
	if err != nil {
		time.Sleep(250 * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "login", struct{ Error string }{Error: "Hibás jelszó"})
		return
	}
	if _, err := s.sessions.Create(w); err != nil {
		s.logger.Error("session creation failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.loginLimiter.Reset(ip)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	session, ok := s.sessions.Get(r)
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if !ok || !s.validOrigin(r) || r.ParseForm() != nil ||
		subtle.ConstantTimeCompare([]byte(session.CSRF), []byte(r.FormValue("csrf_token"))) != 1 {
		http.Error(w, "érvénytelen CSRF token", http.StatusForbidden)
		return
	}
	s.sessions.Delete(w, r)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	session, _ := s.sessions.Get(r)
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	reports, err := s.store.LatestReports(ctx)
	if err != nil {
		s.logger.Error("load reports failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	alerts, err := s.store.UnacknowledgedActiveAlerts(ctx)
	if err != nil {
		s.logger.Error("load alerts failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	history, err := s.store.AlertHistory(ctx, 50)
	if err != nil {
		s.logger.Error("load alert history failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "dashboard", dashboardData{
		CSRF: session.CSRF, Reports: reports, Alerts: alerts, AlertHistory: history,
	})
}

func (s *Server) acknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	session, ok := s.sessions.Get(r)
	if !ok || !s.validOrigin(r) {
		http.Error(w, "invalid session or origin", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if err := r.ParseForm(); err != nil ||
		subtle.ConstantTimeCompare([]byte(session.CSRF), []byte(r.FormValue("csrf_token"))) != 1 {
		http.Error(w, "érvénytelen CSRF token", http.StatusForbidden)
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id < 1 {
		http.Error(w, "invalid alert id", http.StatusBadRequest)
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	if err := s.store.AcknowledgeAlert(ctx, id, "admin", time.Now()); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			http.Error(w, "alert not found or already acknowledged", http.StatusNotFound)
			return
		}
		s.logger.Error("acknowledge alert failed", "error", err, "alert_id", id)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) history(w http.ResponseWriter, r *http.Request) {
	agentID := r.URL.Query().Get("agent_id")
	if !validAgentID(agentID) {
		http.Error(w, "invalid agent_id", http.StatusBadRequest)
		return
	}
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "24h"
	}
	historyRange, ok := historyRanges[rangeName]
	if !ok {
		http.Error(w, "invalid range", http.StatusBadRequest)
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	points, err := s.store.History(ctx, agentID, time.Now().UTC().Add(-historyRange), s.cfg.RawRetention, 720)
	if err != nil {
		s.logger.Error("load history failed", "error", err, "agent_id", agentID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(struct {
		AgentID string                 `json:"agent_id"`
		Range   string                 `json:"range"`
		Points  []storage.HistoryPoint `json:"points"`
	}{AgentID: agentID, Range: rangeName, Points: points}); err != nil {
		s.logger.Error("encode history failed", "error", err)
	}
}

func (s *Server) eventStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})
	channel, unsubscribe := s.events.subscribe()
	defer unsubscribe()
	_, _ = io.WriteString(w, ": connected\n\n")
	flusher.Flush()
	keepAlive := time.NewTicker(15 * time.Second)
	defer keepAlive.Stop()
	revalidate := time.NewTimer(5 * time.Minute)
	defer revalidate.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-revalidate.C:
			return
		case message := <-channel:
			_, _ = fmt.Fprintf(w, "event: report\ndata: %s\n\n", message)
			flusher.Flush()
		case <-keepAlive.C:
			_, _ = io.WriteString(w, ": keepalive\n\n")
			flusher.Flush()
		}
	}
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	if !s.apiLimiter.Allow(s.clientIP(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxReportBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var report model.Report
	if err := decoder.Decode(&report); err != nil {
		http.Error(w, "invalid report", http.StatusBadRequest)
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		http.Error(w, "invalid report", http.StatusBadRequest)
		return
	}
	receivedAt := time.Now().UTC()
	if err := report.Validate(receivedAt, s.cfg.MaxClockSkew, s.cfg.MaxReportAge); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}
	token := bearerToken(r.Header.Get("Authorization"))
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	hashes, err := s.store.TokenHashes(ctx, report.AgentID)
	if err != nil || token == "" || !verifyAnyToken(token, hashes) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if err := s.store.SaveReport(ctx, report); err != nil {
		if errors.Is(err, storage.ErrReplay) {
			http.Error(w, "sequence replay rejected", http.StatusConflict)
			return
		}
		s.logger.Error("store report failed", "error", err, "agent_id", report.AgentID)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !report.Timestamp.Before(receivedAt.Add(-s.cfg.AgentOfflineAfter)) {
		if err := s.alerts.EvaluateReport(ctx, report, receivedAt); err != nil {
			s.logger.Error("alert evaluation failed", "error", err, "agent_id", report.AgentID)
		}
	} else if err := s.alerts.ResolveOnline(ctx, report.AgentID, receivedAt); err != nil {
		s.logger.Error("online recovery evaluation failed", "error", err, "agent_id", report.AgentID)
	}
	select {
	case s.notifyWake <- struct{}{}:
	default:
	}
	event, _ := json.Marshal(struct {
		AgentID   string    `json:"agent_id"`
		Timestamp time.Time `json:"timestamp"`
	}{AgentID: report.AgentID, Timestamp: report.Timestamp})
	s.events.publish(string(event))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, `{"status":"accepted"}`)
}

func (s *Server) Run(ctx context.Context) {
	offlineTicker := time.NewTicker(15 * time.Second)
	retryTicker := time.NewTicker(time.Minute)
	defer offlineTicker.Stop()
	defer retryTicker.Stop()
	s.processNotifications(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.notifyWake:
			s.processNotifications(ctx)
		case <-retryTicker.C:
			s.processNotifications(ctx)
		case now := <-offlineTicker.C:
			operationCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			if err := s.alerts.EvaluateOffline(operationCtx, now); err != nil && ctx.Err() == nil {
				s.logger.Error("offline alert evaluation failed", "error", err)
			}
			cancel()
			s.processNotifications(ctx)
		}
	}
}

func (s *Server) processNotifications(ctx context.Context) {
	operationCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pending, err := s.store.PendingNotifications(operationCtx, 50)
	if err != nil {
		if ctx.Err() == nil {
			s.logger.Error("load pending notifications failed", "error", err)
		}
		return
	}
	for _, alert := range pending {
		inCooldown, err := s.store.NotificationInCooldown(
			operationCtx, alert, s.cfg.AlertCooldown, time.Now())
		if err != nil {
			s.logger.Error("notification cooldown check failed", "error", err, "alert_id", alert.ID)
			continue
		}
		if inCooldown {
			if err := s.store.MarkAlertNotification(operationCtx, alert.ID, "suppressed", time.Now()); err != nil {
				s.logger.Error("suppress alert notification failed", "error", err, "alert_id", alert.ID)
			}
			continue
		}
		if err := s.mailer.Send(alert, s.cfg.PublicURL); err != nil {
			s.logger.Error("alert email failed", "error", err, "agent_id", alert.AgentID)
			continue
		}
		if err := s.store.MarkAlertNotification(operationCtx, alert.ID, "sent", time.Now()); err != nil {
			s.logger.Error("mark alert notification failed", "error", err, "alert_id", alert.ID)
		}
	}
}

func (s *Server) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.sessions.Get(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := s.templates.ExecuteTemplate(w, name, data); err != nil {
		s.logger.Error("template render failed", "error", err)
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if s.cfg.SecureCookies {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	if s.trustedProxy != nil && remote != nil && s.trustedProxy.Contains(remote) {
		if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); net.ParseIP(forwarded) != nil {
			return forwarded
		}
	}
	return host
}

func (s *Server) validOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" ||
		(parsed.Path != "" && parsed.Path != "/") {
		return false
	}
	expected, expectedErr := url.Parse(s.cfg.PublicURL)
	if expectedErr == nil && expected.Host != "" {
		return parsed.Scheme == expected.Scheme && strings.EqualFold(parsed.Host, expected.Host)
	}
	return strings.EqualFold(parsed.Host, r.Host)
}

func bearerToken(header string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func verifyAnyToken(token string, hashes []string) bool {
	valid := false
	for _, hash := range hashes {
		if auth.VerifyToken(token, hash) {
			valid = true
		}
	}
	return valid
}

var historyRanges = map[string]time.Duration{
	"1h":  time.Hour,
	"24h": 24 * time.Hour,
	"7d":  7 * 24 * time.Hour,
	"30d": 30 * 24 * time.Hour,
	"90d": 90 * 24 * time.Hour,
}

func validAgentID(value string) bool {
	if value == "" || len(value) > model.MaxAgentIDLen {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character == '.' ||
			character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func contextWithTimeout(r *http.Request, duration time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), duration)
}
