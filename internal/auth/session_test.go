package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionCookieLifecycleAndExpiry(t *testing.T) {
	sessions := NewSessions("0123456789abcdef0123456789abcdef", time.Minute, time.Hour, true)
	recorder := httptest.NewRecorder()
	created, err := sessions.Create(recorder)
	if err != nil {
		t.Fatal(err)
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("got %d cookies", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != CookieName || !cookie.Secure || !cookie.HttpOnly ||
		cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" {
		t.Fatalf("unsafe session cookie: %#v", cookie)
	}
	request := httptest.NewRequest(http.MethodGet, "https://monitor.example.com/", nil)
	request.AddCookie(cookie)
	got, ok := sessions.Get(request)
	if !ok || got.CSRF != created.CSRF {
		t.Fatal("created session was not returned")
	}

	key := sessions.key(cookie.Value)
	sessions.mu.Lock()
	expired := sessions.items[key]
	expired.LastActive = time.Now().Add(-2 * time.Minute)
	sessions.items[key] = expired
	sessions.mu.Unlock()
	if _, ok := sessions.Get(request); ok {
		t.Fatal("idle session was accepted")
	}

	deleteRecorder := httptest.NewRecorder()
	sessions.Delete(deleteRecorder, request)
	deleted := deleteRecorder.Result().Cookies()[0]
	if deleted.MaxAge >= 0 || !deleted.Secure || !deleted.HttpOnly {
		t.Fatalf("unsafe deletion cookie: %#v", deleted)
	}
}

func TestSessionCapacity(t *testing.T) {
	sessions := NewSessions("0123456789abcdef0123456789abcdef", time.Hour, time.Hour, false)
	sessions.items = make(map[[32]byte]Session, 10000)
	now := time.Now()
	for index := 0; index < 10000; index++ {
		sessions.items[sessions.key(string(rune(index))+time.Now().String())] = Session{
			CreatedAt: now, LastActive: now,
		}
	}
	if _, err := sessions.Create(httptest.NewRecorder()); err == nil {
		t.Fatal("expected capacity error")
	}
}
