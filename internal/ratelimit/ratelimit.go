package ratelimit

import (
	"sync"
	"time"
)

// Limiter is a simple fixed-window rate limiter for a single entity.
type Limiter struct {
	mu          sync.Mutex
	count       int
	windowStart time.Time
	rate        int
	window      time.Duration
}

// New creates a Limiter that allows rate requests per window.
func New(rate int, window time.Duration) *Limiter {
	return &Limiter{
		rate:        rate,
		window:      window,
		windowStart: time.Now(),
	}
}

// Allow returns true if the request is within the rate limit.
func (l *Limiter) Allow() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.windowStart) > l.window {
		l.count = 0
		l.windowStart = now
	}
	l.count++
	return l.count <= l.rate
}
