package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter_AllowsUpToRate(t *testing.T) {
	l := New(5, time.Minute)
	for i := 0; i < 5; i++ {
		if !l.Allow() {
			t.Fatalf("request %d should be allowed", i+1)
		}
	}
	if l.Allow() {
		t.Fatal("6th request should be denied")
	}
}

func TestLimiter_ResetsAfterWindow(t *testing.T) {
	l := New(2, 50*time.Millisecond)
	l.Allow()
	l.Allow()
	if l.Allow() {
		t.Fatal("3rd should be denied")
	}
	time.Sleep(60 * time.Millisecond)
	if !l.Allow() {
		t.Fatal("after window reset should be allowed")
	}
}
