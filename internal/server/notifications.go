package server

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/broist/check_agent/internal/storage"
)

func (s *Server) notificationPreferences(ctx context.Context) (storage.NotificationPreferences, error) {
	return s.store.NotificationPreferences(ctx, storage.NotificationPreferences{
		Enabled: s.cfg.SMTP.Enabled, Recipient: s.cfg.SMTP.To, Recovery: true,
	})
}

func (s *Server) notificationForm(w http.ResponseWriter, r *http.Request) (storage.NotificationPreferences, bool) {
	session, ok := s.sessions.Get(r)
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if !ok || !s.validOrigin(r) || r.ParseForm() != nil || subtle.ConstantTimeCompare([]byte(session.CSRF), []byte(r.FormValue("csrf_token"))) != 1 {
		http.Error(w, "A munkamenet vagy a biztonsági token érvénytelen. Jelentkezz be újra.", http.StatusForbidden)
		return storage.NotificationPreferences{}, false
	}
	p := storage.NotificationPreferences{Enabled: r.FormValue("enabled") == "on", Recipient: strings.TrimSpace(r.FormValue("recipient")), Warnings: r.FormValue("warnings") == "on", Recovery: r.FormValue("recovery") == "on"}
	address, err := mail.ParseAddress(p.Recipient)
	if len(p.Recipient) > 254 || strings.ContainsAny(p.Recipient, "\r\n") || err != nil || address.Address != p.Recipient {
		http.Error(w, "Adj meg egy érvényes email-címet, név és vessző nélkül.", http.StatusUnprocessableEntity)
		return p, false
	}
	return p, true
}

func (s *Server) saveNotifications(w http.ResponseWriter, r *http.Request) {
	p, ok := s.notificationForm(w, r)
	if !ok {
		return
	}
	if p.Enabled && !s.cfg.SMTP.Enabled {
		http.Error(w, "Az SMTP-küldés nincs engedélyezve. A server.yaml smtp beállításait kell megadni és a szervert újraindítani.", http.StatusConflict)
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	if err := s.store.SaveNotificationPreferences(ctx, p); err != nil {
		s.logger.Error("save notification preferences failed", "error", err)
		http.Error(w, "Nem sikerült menteni a beállításokat. Próbáld újra.", http.StatusInternalServerError)
		return
	}
	writeMessage(w, "Az értesítési beállításokat elmentettük.")
}

func (s *Server) testNotification(w http.ResponseWriter, r *http.Request) {
	p, ok := s.notificationForm(w, r)
	if !ok {
		return
	}
	if !s.cfg.SMTP.Enabled {
		http.Error(w, "Az SMTP nincs engedélyezve. Állítsd be a server.yaml smtp mezőit (enabled, address, from, username), és a MONITOROZO_SMTP_PASSWORD környezeti változót, majd indítsd újra a szervert.", http.StatusConflict)
		return
	}
	if !s.emailLimiter.Allow("test-email") {
		http.Error(w, "Legfeljebb három teszt küldhető percenként. Várj egy percet.", http.StatusTooManyRequests)
		return
	}
	// SMTP has a bounded dial and protocol deadline longer than the normal HTTP deadline.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(35 * time.Second))
	err := s.mailer.SendTo(storage.Alert{AgentID: "Monitorozo", RuleKey: "test_email", State: "test", StartedAt: time.Now().UTC()}, s.cfg.PublicURL, p.Recipient)
	if err != nil {
		s.logger.Error("test email failed", "error", err)
		message := "Az SMTP-küldés sikertelen. Ellenőrizd a kiszolgáló címét, portját és a tűzfalat."
		if strings.Contains(err.Error(), "sender rejected") {
			message = "Az SMTP-kiszolgáló elutasította a feladót. Ellenőrizd a server.yaml smtp.from címét és a szolgáltatónál engedélyezett feladót."
		}
		if strings.Contains(err.Error(), "recipient rejected") {
			message = "Az SMTP-kiszolgáló elutasította a címzettet. Ellenőrizd az email-címet és a szolgáltató küldési korlátozásait."
		}
		if strings.Contains(err.Error(), "authentication") {
			message = "Az SMTP-hitelesítés sikertelen. Ellenőrizd az SMTP-felhasználónevet és a MONITOROZO_SMTP_PASSWORD értékét."
		}
		if strings.Contains(err.Error(), "TLS") || strings.Contains(err.Error(), "x509") {
			message = "Az SMTP TLS-kapcsolat sikertelen. Ellenőrizd a tanúsítványt és a STARTTLS-t támogató portot (általában 587)."
		}
		http.Error(w, message+" A pontos hiba a monitorozo-server naplójában található.", http.StatusBadGateway)
		return
	}
	writeMessage(w, "Az SMTP-kiszolgáló elfogadta a tesztlevelet erre a címre: "+p.Recipient+". Ellenőrizd a beérkező és a spam mappát. A teszt nem menti a beállításokat.")
}

func writeMessage(w http.ResponseWriter, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(map[string]string{"message": message})
}
