package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHandlerReturns200WhenHostIPAlreadyAllowed(t *testing.T) {
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore()
	store.Allow("app.example.com", "203.0.113.10", 5*time.Minute, now)

	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewHandler(Config{
		DefaultTTL: 5 * time.Minute,
		UpstreamURL: upstream.URL,
	}, store, nowFunc(now))

	req := httptest.NewRequest(http.MethodGet, "http://gateway/check", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get(HeaderCacheStatus); got != "hit" {
		t.Fatalf("expected cache status hit, got %q", got)
	}
	if got := rec.Header().Get(HeaderCacheRemaining); got != "5m0s" {
		t.Fatalf("expected remaining ttl 5m0s, got %q", got)
	}
	if got := rec.Header().Get(HeaderCacheExpiresAt); got != now.Add(5*time.Minute).UTC().Format(time.RFC3339) {
		t.Fatalf("expected expires-at header, got %q", got)
	}
	if upstreamCalls != 0 {
		t.Fatalf("expected no upstream call, got %d", upstreamCalls)
	}
}

func TestHandlerCachesSuccessfulUpstreamAuthentication(t *testing.T) {
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.Header().Set("Remote-User", "alice")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewHandler(Config{
		DefaultTTL: 5 * time.Minute,
		UpstreamURL: upstream.URL,
	}, store, nowFunc(now))

	req := httptest.NewRequest(http.MethodGet, "http://gateway/check", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !store.IsAllowed("app.example.com", "203.0.113.10", now.Add(time.Minute)) {
		t.Fatal("expected successful upstream auth to populate cache")
	}
	if rec.Header().Get("Remote-User") != "alice" {
		t.Fatalf("expected auth response header to be forwarded, got %q", rec.Header().Get("Remote-User"))
	}
	if got := rec.Header().Get(HeaderCacheStatus); got != "stored" {
		t.Fatalf("expected cache status stored, got %q", got)
	}
	if got := rec.Header().Get(HeaderCacheRemaining); got != "5m0s" {
		t.Fatalf("expected remaining ttl 5m0s, got %q", got)
	}
	if got := rec.Header().Get(HeaderCacheExpiresAt); got != now.Add(5*time.Minute).UTC().Format(time.RFC3339) {
		t.Fatalf("expected expires-at header, got %q", got)
	}
	if upstreamCalls != 1 {
		t.Fatalf("expected one upstream call, got %d", upstreamCalls)
	}
}

func TestHandlerUsesPerHostTTLWhenCaching(t *testing.T) {
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewHandler(Config{
		DefaultTTL: 5 * time.Minute,
		UpstreamURL: upstream.URL,
	}, store, nowFunc(now))

	req := httptest.NewRequest(http.MethodGet, "http://gateway/check", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set(HeaderCacheTTL, "1h")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !store.IsAllowed("app.example.com", "203.0.113.10", now.Add(30*time.Minute)) {
		t.Fatal("expected host-specific ttl to be used")
	}
	if store.IsAllowed("app.example.com", "203.0.113.10", now.Add(2*time.Hour)) {
		t.Fatal("expected allowance to expire after host-specific ttl")
	}
}

func TestHandlerPassesThroughUpstreamRejection(t *testing.T) {
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "login required", http.StatusUnauthorized)
	}))
	defer upstream.Close()

	handler := NewHandler(Config{
		DefaultTTL: 5 * time.Minute,
		UpstreamURL: upstream.URL,
	}, store, nowFunc(now))

	req := httptest.NewRequest(http.MethodGet, "http://gateway/check", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "login required") {
		t.Fatalf("expected upstream response body, got %q", string(body))
	}
	if store.IsAllowed("app.example.com", "203.0.113.10", now.Add(time.Minute)) {
		t.Fatal("expected rejected auth not to populate cache")
	}
}

func TestHandlerPassesThroughUpstreamRedirectWithoutFollowing(t *testing.T) {
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		http.Redirect(w, r, "https://auth.example.com/?rd=https%3A%2F%2Fapp.example.com%2F", http.StatusFound)
	}))
	defer upstream.Close()

	handler := NewHandler(Config{
		DefaultTTL: 5 * time.Minute,
		UpstreamURL: upstream.URL,
	}, store, nowFunc(now))

	req := httptest.NewRequest(http.MethodGet, "http://gateway/check", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://auth.example.com/?rd=https%3A%2F%2Fapp.example.com%2F" {
		t.Fatalf("expected redirect location to be forwarded, got %q", got)
	}
	if upstreamCalls != 1 {
		t.Fatalf("expected one upstream call, got %d", upstreamCalls)
	}
	if store.IsAllowed("app.example.com", "203.0.113.10", now.Add(time.Minute)) {
		t.Fatal("expected redirect response not to populate cache")
	}
}

func TestHandlerUsesHeaderDrivenScopeForSameHostServices(t *testing.T) {
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewHandler(Config{
		DefaultTTL: 5 * time.Minute,
		UpstreamURL: upstream.URL,
	}, store, nowFunc(now))

	req := httptest.NewRequest(http.MethodGet, "http://gateway/check", nil)
	req.Host = "example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set(HeaderCacheTTL, "30m")
	req.Header.Set(HeaderCacheKey, "service-a")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if !store.IsAllowed("example.com|service-a", "203.0.113.10", now.Add(10*time.Minute)) {
		t.Fatal("expected custom cache scope to be stored")
	}
	if store.IsAllowed("example.com|service-b", "203.0.113.10", now.Add(10*time.Minute)) {
		t.Fatal("expected different cache scope to remain unauthenticated")
	}
}

func TestHandlerRejectsInvalidTTLHeader(t *testing.T) {
	now := time.Date(2026, 4, 14, 10, 0, 0, 0, time.UTC)
	store := NewMemoryStore()

	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := NewHandler(Config{
		DefaultTTL: 5 * time.Minute,
		UpstreamURL: upstream.URL,
	}, store, nowFunc(now))

	req := httptest.NewRequest(http.MethodGet, "http://gateway/check", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set(HeaderCacheTTL, "not-a-duration")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if upstreamCalls != 0 {
		t.Fatalf("expected invalid ttl to fail before upstream call, got %d calls", upstreamCalls)
	}
}

func TestRealClientIPUsesFirstForwardedAddress(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway/check", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 10.0.0.5")

	if got := RealClientIP(req); got != "203.0.113.10" {
		t.Fatalf("expected first forwarded ip, got %q", got)
	}
}

func TestRealClientIPFallsBackToRemoteAddr(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://gateway/check", nil)
	req.RemoteAddr = "203.0.113.10:12345"

	if got := RealClientIP(req); got != "203.0.113.10" {
		t.Fatalf("expected remote addr ip, got %q", got)
	}
}

func nowFunc(t time.Time) func() time.Time {
	return func() time.Time { return t }
}
