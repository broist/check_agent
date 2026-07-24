package email

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/storage"
)

type Sender struct {
	cfg config.SMTP
}

func New(cfg config.SMTP) *Sender { return &Sender{cfg: cfg} }

func (s *Sender) Send(alert storage.Alert, dashboardURL string) error {
	if !s.cfg.Enabled {
		return nil
	}
	host, _, err := net.SplitHostPort(s.cfg.Address)
	if err != nil {
		return fmt.Errorf("invalid SMTP address: %w", err)
	}
	subject := fmt.Sprintf("[Monitorozo] %s %s on %s", alert.Severity, alert.State, alert.AgentID)
	duration := ""
	if alert.ResolvedAt != nil {
		duration = fmt.Sprintf("\nDuration: %s", alert.ResolvedAt.Sub(alert.StartedAt).Round(time.Second))
	}
	body := fmt.Sprintf("Server: %s\nSeverity: %s\nRule: %s\nResource: %s\nState: %s\nValue: %.2f\nThreshold: %.2f\nStarted: %s%s\nDashboard: %s\n",
		alert.AgentID, alert.Severity, alert.RuleKey, alert.Resource, alert.State, alert.Value,
		alert.Threshold, alert.StartedAt.Format(time.RFC3339), duration, dashboardURL)
	message := []byte("From: " + s.cfg.From + "\r\nTo: " + s.cfg.To +
		"\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" + body)
	var auth smtp.Auth
	if s.cfg.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, host)
	}
	conn, err := net.DialTimeout("tcp", s.cfg.Address, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect SMTP: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("start SMTP: %w", err)
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); ok {
		if err := client.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("SMTP STARTTLS: %w", err)
		}
	} else {
		return fmt.Errorf("SMTP server does not offer STARTTLS")
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP authentication: %w", err)
		}
	}
	if err := client.Mail(s.cfg.From); err != nil {
		return err
	}
	if err := client.Rcpt(s.cfg.To); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	if err := client.Quit(); err != nil && !strings.Contains(err.Error(), "connection") {
		return err
	}
	return nil
}
