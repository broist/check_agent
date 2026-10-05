package email

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/broist/check_agent/internal/alerts"
	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/storage"
)

type Sender struct {
	cfg       config.SMTP
	tlsConfig *tls.Config
}

func New(cfg config.SMTP) *Sender {
	return &Sender{cfg: cfg, tlsConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
}

func (s *Sender) Send(alert storage.Alert, dashboardURL string) error {
	return s.SendTo(alert, dashboardURL, s.cfg.To)
}

func (s *Sender) SendTo(alert storage.Alert, dashboardURL, recipient string) error {
	if !s.cfg.Enabled {
		return fmt.Errorf("SMTP nincs engedélyezve a szerver konfigurációjában")
	}
	address, addressErr := mail.ParseAddress(recipient)
	if addressErr != nil || address.Address != recipient || strings.ContainsAny(recipient, "\r\n") {
		return fmt.Errorf("érvénytelen címzett")
	}
	host, _, err := net.SplitHostPort(s.cfg.Address)
	if err != nil {
		return fmt.Errorf("invalid SMTP address: %w", err)
	}
	description := alerts.Describe(alert)
	if alert.Target == "" {
		alert.Target = alert.Resource
	}
	if alert.Hostname == "" {
		alert.Hostname = alert.AgentID
	}
	state := "KRITIKUS"
	if alert.Severity == "warning" {
		state = "FIGYELMEZTETÉS"
	}
	if alert.State == "resolved" {
		state = "HELYREÁLLT"
	}
	if alert.RuleKey == "test_email" {
		state = "TESZT"
	}
	subject := mime.QEncoding.Encode("UTF-8", fmt.Sprintf("[Monitorozo] %s: %s · %s · %s", state, alert.Hostname, description.Title, alert.Target))
	subject = strings.ReplaceAll(subject, "?= =?", "?=\r\n =?")
	duration := ""
	if alert.ResolvedAt != nil {
		duration = fmt.Sprintf("\nHiba időtartama: %s", alert.ResolvedAt.Sub(alert.StartedAt).Round(time.Second))
	}
	if alert.State == "resolved" {
		description.Action = "Az állapot helyreállt. Ellenőrizd, hogy a javulás tartós-e. " + description.Action
	}
	body := fmt.Sprintf("%s: %s\nSzerver: %s\nAgent azonosító: %s\nÉrintett erőforrás / útvonal: %s\n%s\nKezdete: %s%s\n\nTeendő\n%s\n\nÁllapot és részletek: %s\n",
		state, description.Title, alert.Hostname, alert.AgentID, alert.Target, description.Measurement,
		alert.StartedAt.Format(time.RFC3339), duration, description.Action, dashboardURL)
	var encoded bytes.Buffer
	encoder := quotedprintable.NewWriter(&encoded)
	if _, err := encoder.Write([]byte(body)); err != nil {
		return err
	}
	if err := encoder.Close(); err != nil {
		return err
	}
	message := []byte("From: " + s.cfg.From + "\r\nTo: " + recipient +
		"\r\nSubject: " + subject + "\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" + encoded.String())
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
		tlsConfig := s.tlsConfig.Clone()
		tlsConfig.ServerName = host
		if err := client.StartTLS(tlsConfig); err != nil {
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
		return fmt.Errorf("SMTP sender rejected: %w", err)
	}
	if err := client.Rcpt(recipient); err != nil {
		return fmt.Errorf("SMTP recipient rejected: %w", err)
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
