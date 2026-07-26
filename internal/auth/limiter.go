package auth

import (
	"sync"
	"time"
)

type attempt struct {
	count int
	since time.Time
}

type Limiter struct {
	mu          sync.Mutex
	items       map[string]attempt
	limit       int
	window      time.Duration
	maxKeys     int
	lastCleanup time.Time
}

func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{
		items: make(map[string]attempt), limit: limit, window: window,
		maxKeys: 10000, lastCleanup: time.Now(),
	}
}

func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.lastCleanup) >= l.window {
		for existingKey, existing := range l.items {
			if now.Sub(existing.since) >= l.window {
				delete(l.items, existingKey)
			}
		}
		l.lastCleanup = now
	}
	item := l.items[key]
	if item.since.IsZero() && len(l.items) >= l.maxKeys {
		return false
	}
	if now.Sub(item.since) >= l.window {
		item = attempt{since: now}
	}
	item.count++
	l.items[key] = item
	return item.count <= l.limit
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.items, key)
	l.mu.Unlock()
}
