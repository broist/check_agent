package server

import (
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/broist/check_agent/internal/storage"
)

// saveAgentLabel stores the display name and description of a machine. A
// plain form POST is redirected back to the dashboard; a fetch request that
// accepts JSON receives a JSON message.
func (s *Server) saveAgentLabel(w http.ResponseWriter, r *http.Request) {
	session, ok := s.sessions.Get(r)
	r.Body = http.MaxBytesReader(w, r.Body, maxFormBody)
	if !ok || !s.validOrigin(r) || r.ParseForm() != nil ||
		subtle.ConstantTimeCompare([]byte(session.CSRF), []byte(r.FormValue("csrf_token"))) != 1 {
		http.Error(w, "A munkamenet vagy a biztonsági token érvénytelen. Jelentkezz be újra.", http.StatusForbidden)
		return
	}
	agentID := r.PathValue("id")
	if !validAgentID(agentID) {
		http.Error(w, "Érvénytelen gépazonosító.", http.StatusBadRequest)
		return
	}
	name, nameOK := storage.CleanLabelText(r.FormValue("display_name"), storage.MaxDisplayNameLen)
	description, descriptionOK := storage.CleanLabelText(r.FormValue("description"), storage.MaxDescriptionLen)
	if !nameOK || !descriptionOK {
		http.Error(w, "A név legfeljebb 64, a leírás legfeljebb 160 karakter lehet, sortörés és vezérlőkarakter nélkül.", http.StatusUnprocessableEntity)
		return
	}
	ctx, cancel := contextWithTimeout(r, 5*time.Second)
	defer cancel()
	err := s.store.SetAgentLabel(ctx, storage.AgentLabel{AgentID: agentID, DisplayName: name, Description: description}, "admin", time.Now())
	if errors.Is(err, storage.ErrUnknownAgent) {
		http.Error(w, "Nincs ilyen gép.", http.StatusNotFound)
		return
	}
	if err != nil {
		s.logger.Error("save agent label failed", "error", err, "agent_id", agentID)
		http.Error(w, "Nem sikerült menteni a nevet. Próbáld újra.", http.StatusInternalServerError)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		writeMessage(w, "A gép nevét elmentettük.")
		return
	}
	http.Redirect(w, r, viewState{}.url(agentID, "", "", false), http.StatusSeeOther)
}
