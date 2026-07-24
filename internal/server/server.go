package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/example/monitorozo/internal/auth"
	"github.com/example/monitorozo/internal/config"
	"github.com/example/monitorozo/internal/model"
	"github.com/example/monitorozo/internal/storage"
	"github.com/example/monitorozo/web"
	"golang.org/x/crypto/bcrypt"
)

const maxReportBody = 256 << 10

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
}

type dashboardData struct {
	CSRF    string
	Reports []model.Report
	Alerts  []storage.Alert
}

func New(cfg config.Server, store *storage.Store, mailer AlertSender, logger *slog.Logger) (*Server, error) {
	funcs := template.FuncMap{
		"time": func(value time.Time) string { return value.Local().Format("2006-01-02 15:04:05") },
		"duration": func(seconds uint64) string {
			return (time.Duration(seconds) * time.Second).Round(time.Minute).String()
		},
		"online": func(value time.Time) string {
			if time.Since(value) <= 120*time.Second {
				return "online"
			}
			return "offline"
		},
		"status": func(value time.Time) string {
			if time.Since(value) <= 120*time.Second {
				return "ok"
			}
			return "offline"
		},
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

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.requireAuth(s.logout))
	mux.HandleFunc("POST /api/v1/reports", s.ingest)
	mux.Handle("GET /static/", http.FileServer(http.FS(web.Files)))
	mux.HandleFunc("GET /", s.requireAuth(s.dashboard))
	return s.securityHeaders(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = io.WriteString(w, `{"status":"ok"}`)
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
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}
	if !s.validOrigin(r) {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "invalid form", http.StatusBadRequest)
		return
	}
	err := bcrypt.CompareHashAndPassword([]byte(s.cfg.AdminPasswordHash), []byte(r.FormValue("password")))
	if err != nil {
		time.Sleep(250 * time.Millisecond)
		w.WriteHeader(http.StatusUnauthorized)
		s.render(w, "login", struct{ Error string }{Error: "Invalid credentials"})
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
	if !ok || !s.validOrigin(r) ||
		subtle.ConstantTimeCompare([]byte(session.CSRF), []byte(r.FormValue("csrf_token"))) != 1 {
		http.Error(w, "invalid CSRF token", http.StatusForbidden)
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
	alerts, err := s.store.ActiveAlerts(ctx)
	if err != nil {
		s.logger.Error("load alerts failed", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.render(w, "dashboard", dashboardData{CSRF: session.CSRF, Reports: reports, Alerts: alerts})
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
	if err := report.Validate(time.Now().UTC(), s.cfg.MaxClockSkew); err != nil {
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
	alert, err := s.store.EvaluateCPU(ctx, report, s.cfg.CPUAlertThreshold)
	if err != nil {
		s.logger.Error("alert evaluation failed", "error", err, "agent_id", report.AgentID)
	} else if alert != nil {
		if err := s.mailer.Send(*alert, s.cfg.PublicURL); err != nil {
			s.logger.Error("alert email failed", "error", err, "agent_id", report.AgentID)
		} else if err := s.store.MarkAlertNotified(ctx, alert.ID); err != nil {
			s.logger.Error("mark alert notification failed", "error", err, "alert_id", alert.ID)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_, _ = io.WriteString(w, `{"status":"accepted"}`)
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
	return err == nil && parsed.Host == r.Host
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

func contextWithTimeout(r *http.Request, duration time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), duration)
}
