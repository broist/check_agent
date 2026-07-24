package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const CookieName = "monitorozo_session"

type Session struct {
	CSRF       string
	CreatedAt  time.Time
	LastActive time.Time
}

type Sessions struct {
	mu       sync.Mutex
	items    map[[32]byte]Session
	secret   []byte
	idle     time.Duration
	lifetime time.Duration
	secure   bool
}

func NewSessions(secret string, idle, lifetime time.Duration, secure bool) *Sessions {
	return &Sessions{items: make(map[[32]byte]Session), secret: []byte(secret),
		idle: idle, lifetime: lifetime, secure: secure}
}

func (s *Sessions) Create(w http.ResponseWriter) (Session, error) {
	token, err := randomString(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := randomString(32)
	if err != nil {
		return Session{}, err
	}
	now := time.Now()
	session := Session{CSRF: csrf, CreatedAt: now, LastActive: now}
	s.mu.Lock()
	s.cleanupLocked(now)
	if len(s.items) >= 10000 {
		s.mu.Unlock()
		return Session{}, fmt.Errorf("session capacity reached")
	}
	s.items[s.key(token)] = session
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/", Secure: s.secure,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
		MaxAge: int(s.lifetime.Seconds()),
	})
	return session, nil
}

func (s *Sessions) Get(r *http.Request) (Session, bool) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		return Session{}, false
	}
	now := time.Now()
	key := s.key(cookie.Value)
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.items[key]
	if !ok || now.Sub(session.LastActive) > s.idle || now.Sub(session.CreatedAt) > s.lifetime {
		delete(s.items, key)
		return Session{}, false
	}
	session.LastActive = now
	s.items[key] = session
	return session, true
}

func (s *Sessions) Delete(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(CookieName); err == nil {
		s.mu.Lock()
		delete(s.items, s.key(cookie.Value))
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Path: "/", MaxAge: -1, Secure: s.secure,
		HttpOnly: true, SameSite: http.SameSiteStrictMode,
	})
}

func (s *Sessions) key(token string) [32]byte {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(token))
	var result [32]byte
	copy(result[:], mac.Sum(nil))
	return result
}

func (s *Sessions) cleanupLocked(now time.Time) {
	for key, session := range s.items {
		if now.Sub(session.LastActive) > s.idle || now.Sub(session.CreatedAt) > s.lifetime {
			delete(s.items, key)
		}
	}
}

func randomString(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}
