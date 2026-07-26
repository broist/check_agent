package auth

import (
	"testing"
	"time"
)

func TestLimiterLimitResetAndWindow(t *testing.T) {
	limiter := NewLimiter(2, time.Minute)
	if !limiter.Allow("client") || !limiter.Allow("client") {
		t.Fatal("allowed attempts were rejected")
	}
	if limiter.Allow("client") {
		t.Fatal("attempt above limit was accepted")
	}
	limiter.Reset("client")
	if !limiter.Allow("client") {
		t.Fatal("reset client was rejected")
	}
	limiter.mu.Lock()
	item := limiter.items["client"]
	item.since = time.Now().Add(-2 * time.Minute)
	limiter.items["client"] = item
	limiter.mu.Unlock()
	if !limiter.Allow("client") {
		t.Fatal("client was not allowed after window")
	}
}

func TestLimiterBoundsUniqueKeys(t *testing.T) {
	limiter := NewLimiter(1, time.Hour)
	limiter.maxKeys = 1
	if !limiter.Allow("first") {
		t.Fatal("first key rejected")
	}
	if limiter.Allow("second") {
		t.Fatal("key above capacity accepted")
	}
}
