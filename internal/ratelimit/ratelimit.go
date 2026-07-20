package ratelimit

import (
	"sync"
	"time"
)

type Limiter struct {
	limit  int
	window time.Duration
	mu     sync.Mutex
	items  map[string]bucket
}

type bucket struct {
	count   int
	resetAt time.Time
}

func New(limit int, window time.Duration) *Limiter {
	return &Limiter{
		limit:  limit,
		window: window,
		items:  map[string]bucket{},
	}
}

func (l *Limiter) Allow(key string) bool {
	if key == "" {
		key = "unknown"
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	item := l.items[key]
	if item.resetAt.IsZero() || now.After(item.resetAt) {
		l.items[key] = bucket{count: 1, resetAt: now.Add(l.window)}
		return true
	}
	if item.count >= l.limit {
		return false
	}
	item.count++
	l.items[key] = item
	return true
}

func (l *Limiter) Cleanup() {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, item := range l.items {
		if now.After(item.resetAt) {
			delete(l.items, key)
		}
	}
}

type Registry struct {
	Login      *Limiter
	Create     *Limiter
	Prepare    *Limiter
	Consume    *Limiter
	EmailSend  *Limiter
	EmailRetry *Limiter
	EmailTest  *Limiter
}

func NewRegistry() *Registry {
	return &Registry{
		Login:      New(10, 15*time.Minute),
		Create:     New(30, time.Minute),
		Prepare:    New(20, time.Minute),
		Consume:    New(10, time.Minute),
		EmailSend:  New(20, time.Minute),
		EmailRetry: New(5, time.Minute),
		EmailTest:  New(5, 15*time.Minute),
	}
}

func (r *Registry) Cleanup() {
	r.Login.Cleanup()
	r.Create.Cleanup()
	r.Prepare.Cleanup()
	r.Consume.Cleanup()
	r.EmailSend.Cleanup()
	r.EmailRetry.Cleanup()
	r.EmailTest.Cleanup()
}
