package email

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/broist/check_agent/internal/config"
	"github.com/broist/check_agent/internal/storage"
)

func TestSenderSTARTTLS(t *testing.T) {
	certificate, roots := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	message := make(chan string, 1)
	serverError := make(chan error, 1)
	go func() {
		serverError <- serveSMTP(listener, certificate, true, message)
	}()

	sender := New(config.SMTP{
		Enabled: true,
		Address: listener.Addr().String(),
		From:    "alerts@example.com",
		To:      "operator@example.com",
	})
	sender.tlsConfig.RootCAs = roots
	started := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	resolved := started.Add(3*time.Minute + 12*time.Second)
	err = sender.Send(storage.Alert{
		AgentID: "prod-1", RuleKey: "disk", Resource: "/",
		Severity: "critical", State: "resolved", Value: 97, Threshold: 95,
		StartedAt: started, ResolvedAt: &resolved,
	}, "https://monitor.example.com/")
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
	body := <-message
	for _, expected := range []string{
		"Subject: [Monitorozo] critical resolved on prod-1",
		"Server: prod-1", "Severity: critical", "Rule: disk",
		"Resource: /", "Value: 97.00", "Threshold: 95.00",
		"Duration: 3m12s", "Dashboard: https://monitor.example.com/",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("message does not contain %q:\n%s", expected, body)
		}
	}
}

func TestSenderRejectsPlainSMTP(t *testing.T) {
	certificate, _ := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverError := make(chan error, 1)
	go func() {
		serverError <- serveSMTP(listener, certificate, false, nil)
	}()
	sender := New(config.SMTP{
		Enabled: true, Address: listener.Addr().String(),
		From: "alerts@example.com", To: "operator@example.com",
	})
	err = sender.Send(storage.Alert{}, "https://monitor.example.com/")
	if err == nil || !strings.Contains(err.Error(), "does not offer STARTTLS") {
		t.Fatalf("expected STARTTLS error, got %v", err)
	}
	if err := <-serverError; err != nil {
		t.Fatal(err)
	}
}

func TestDisabledSenderDoesNotConnect(t *testing.T) {
	if err := New(config.SMTP{}).Send(storage.Alert{}, ""); err != nil {
		t.Fatal(err)
	}
}

func serveSMTP(listener net.Listener, certificate tlsCertificate, startTLS bool, message chan<- string) error {
	connection, err := listener.Accept()
	if err != nil {
		return err
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReader(connection)
	if _, err := fmt.Fprint(connection, "220 localhost ESMTP\r\n"); err != nil {
		return err
	}
	if err := expectCommand(reader, "EHLO "); err != nil {
		return err
	}
	if !startTLS {
		_, err = fmt.Fprint(connection, "250 localhost\r\n")
		return err
	}
	if _, err := fmt.Fprint(connection, "250-localhost\r\n250 STARTTLS\r\n"); err != nil {
		return err
	}
	if err := expectCommand(reader, "STARTTLS"); err != nil {
		return err
	}
	if _, err := fmt.Fprint(connection, "220 Ready to start TLS\r\n"); err != nil {
		return err
	}
	tlsConnection := tls.Server(connection, &tls.Config{
		Certificates: []tls.Certificate{certificate.certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConnection.Handshake(); err != nil {
		return err
	}
	reader = bufio.NewReader(tlsConnection)
	if err := expectCommand(reader, "EHLO "); err != nil {
		return err
	}
	if _, err := fmt.Fprint(tlsConnection, "250 localhost\r\n"); err != nil {
		return err
	}
	for _, command := range []string{"MAIL FROM:", "RCPT TO:", "DATA"} {
		if err := expectCommand(reader, command); err != nil {
			return err
		}
		response := "250 OK\r\n"
		if command == "DATA" {
			response = "354 End data with <CR><LF>.<CR><LF>\r\n"
		}
		if _, err := fmt.Fprint(tlsConnection, response); err != nil {
			return err
		}
	}
	var data strings.Builder
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == ".\r\n" {
			break
		}
		data.WriteString(line)
	}
	if message != nil {
		message <- data.String()
	}
	if _, err := fmt.Fprint(tlsConnection, "250 Queued\r\n"); err != nil {
		return err
	}
	if err := expectCommand(reader, "QUIT"); err != nil {
		return err
	}
	_, err = fmt.Fprint(tlsConnection, "221 Bye\r\n")
	return err
}

func expectCommand(reader *bufio.Reader, prefix string) error {
	line, err := reader.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, prefix) {
		return fmt.Errorf("expected %q, got %q", prefix, line)
	}
	return nil
}

type tlsCertificate struct {
	certificate tls.Certificate
}

func testCertificate(t *testing.T) (tlsCertificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	return tlsCertificate{certificate: certificate}, roots
}
