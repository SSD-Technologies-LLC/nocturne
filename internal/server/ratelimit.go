package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rateLimiter implements a simple per-IP fixed-window rate limiter.
type rateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rate     int           // max requests per window
	window   time.Duration // window duration
	done     chan struct{}
}

// visitor tracks request counts within the current window for a single IP.
type visitor struct {
	count       int
	windowStart time.Time
}

// newRateLimiter creates a rate limiter that allows rate requests per window.
// It starts a background goroutine that cleans up stale entries every minute.
func newRateLimiter(rate int, window time.Duration) *rateLimiter {
	rl := &rateLimiter{
		visitors: make(map[string]*visitor),
		rate:     rate,
		window:   window,
		done:     make(chan struct{}),
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				rl.cleanup()
			case <-rl.done:
				return
			}
		}
	}()
	return rl
}

// close stops the background cleanup goroutine.
func (rl *rateLimiter) close() {
	close(rl.done)
}

// allow returns true if the IP has not exceeded its rate limit.
func (rl *rateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	v, exists := rl.visitors[ip]
	if !exists || now.Sub(v.windowStart) > rl.window {
		rl.visitors[ip] = &visitor{count: 1, windowStart: now}
		return true
	}
	v.count++
	return v.count <= rl.rate
}

// cleanup removes visitor entries whose window has expired.
func (rl *rateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	for ip, v := range rl.visitors {
		if now.Sub(v.windowStart) > rl.window {
			delete(rl.visitors, ip)
		}
	}
}

// getIP extracts the client IP from a request. X-Forwarded-For is only
// trusted when the direct connection comes from localhost (reverse proxy).
func getIP(r *http.Request) string {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "127.0.0.1" || host == "::1" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
	}
	return host
}
