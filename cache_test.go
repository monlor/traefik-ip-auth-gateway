package gateway

import (
	"testing"
	"time"
)

func TestMemoryStoreAllowsUntilTTLExpires(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)

	store.Allow("app.example.com", "203.0.113.10", 2*time.Minute, now)

	if !store.IsAllowed("app.example.com", "203.0.113.10", now.Add(90*time.Second)) {
		t.Fatal("expected host/ip pair to be allowed before ttl expiry")
	}

	if store.IsAllowed("app.example.com", "203.0.113.10", now.Add(3*time.Minute)) {
		t.Fatal("expected host/ip pair to expire after ttl")
	}
}

func TestMemoryStoreSeparatesHosts(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)

	store.Allow("app.example.com", "203.0.113.10", 5*time.Minute, now)

	if store.IsAllowed("admin.example.com", "203.0.113.10", now.Add(time.Minute)) {
		t.Fatal("expected allowance to be scoped to host")
	}
}
