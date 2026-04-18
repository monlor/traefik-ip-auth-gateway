package traefik_ip_auth_gateway

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

func TestMemoryStoreCleansExpiredEntriesOnAllow(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)

	store.Allow("app.example.com|GET|/private", "203.0.113.10", time.Minute, now)
	store.Allow("app.example.com|GET|/admin", "203.0.113.10", 5*time.Minute, now.Add(2*time.Minute))

	if len(store.allowed) != 1 {
		t.Fatalf("expected cleanup to remove expired entries, got %d entries", len(store.allowed))
	}
	if !store.IsAllowed("app.example.com|GET|/admin", "203.0.113.10", now.Add(3*time.Minute)) {
		t.Fatal("expected fresh entry to remain after cleanup")
	}
}

func TestMemoryStoreExpiresAtPreservesConcurrentRenewal(t *testing.T) {
	store := NewMemoryStore()
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	scope := "app.example.com|GET|/private"
	ip := "203.0.113.10"

	store.Allow(scope, ip, time.Minute, now)

	beforeDelete := make(chan struct{})
	allowRenewal := make(chan struct{})
	store.beforeDelete = func() {
		close(beforeDelete)
		<-allowRenewal
	}

	result := make(chan struct {
		expiresAt time.Time
		ok        bool
	}, 1)

	go func() {
		expiresAt, ok := store.ExpiresAt(scope, ip, now.Add(2*time.Minute))
		result <- struct {
			expiresAt time.Time
			ok        bool
		}{expiresAt: expiresAt, ok: ok}
	}()

	<-beforeDelete
	store.Allow(scope, ip, 5*time.Minute, now.Add(2*time.Minute))
	close(allowRenewal)

	outcome := <-result
	if !outcome.ok {
		t.Fatal("expected refreshed entry to survive expired-entry eviction")
	}
	expectedExpiry := now.Add(7 * time.Minute)
	if !outcome.expiresAt.Equal(expectedExpiry) {
		t.Fatalf("expected refreshed expiry %v, got %v", expectedExpiry, outcome.expiresAt)
	}
}
