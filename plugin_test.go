package traefik_ip_auth_gateway

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCreateConfigDefaults(t *testing.T) {
	cfg := CreateConfig()

	if cfg.Address != "" {
		t.Fatalf("expected empty default address, got %q", cfg.Address)
	}
	if cfg.GrantTTL != DefaultGrantTTL.String() {
		t.Fatalf("expected default grant ttl, got %q", cfg.GrantTTL)
	}
	if cfg.ChallengeTTL != DefaultChallengeTTL.String() {
		t.Fatalf("expected default challenge ttl, got %q", cfg.ChallengeTTL)
	}
	if cfg.MaxBodySize != DefaultMaxBodySize {
		t.Fatalf("expected default max body size %d, got %d", DefaultMaxBodySize, cfg.MaxBodySize)
	}
}

func TestNewValidatesConfig(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	cases := []struct {
		name string
		cfg  *Config
	}{
		{
			name: "missing address",
			cfg:  &Config{},
		},
		{
			name: "invalid address",
			cfg: &Config{
				Address: "://bad",
			},
		},
		{
			name: "negative grant ttl",
			cfg: &Config{
				Address:  "http://auth.example.com",
				GrantTTL: "-1m",
			},
		},
		{
			name: "invalid challenge ttl",
			cfg: &Config{
				Address:      "http://auth.example.com",
				ChallengeTTL: "nope",
			},
		},
		{
			name: "invalid allowlist",
			cfg: &Config{
				Address:   "http://auth.example.com",
				Allowlist: []string{"not-a-cidr"},
			},
		},
		{
			name: "zero challenge ttl with caching enabled",
			cfg: &Config{
				Address:      "http://auth.example.com",
				GrantTTL:     "5m",
				ChallengeTTL: "0s",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := newMiddleware(next, tc.cfg, "ipauth", nowFunc(time.Now()), nil); err == nil {
				t.Fatal("expected config validation to fail")
			}
		})
	}
}

func TestNewParsesSingleIPAndCIDRAllowlist(t *testing.T) {
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	middleware, err := newMiddleware(next, &Config{
		Address:   "http://auth.example.com",
		Allowlist: []string{"203.0.113.10", "2001:db8::/32"},
	}, "ipauth", nowFunc(time.Now()), nil)
	if err != nil {
		t.Fatalf("expected valid config, got %v", err)
	}

	if !middleware.isAllowlisted("203.0.113.10") {
		t.Fatal("expected single IPv4 to be allowlisted")
	}
	if !middleware.isAllowlisted("2001:db8::5") {
		t.Fatal("expected IPv6 CIDR to be allowlisted")
	}
	if middleware.isAllowlisted("198.51.100.5") {
		t.Fatal("expected unrelated IP not to be allowlisted")
	}
}

func TestMiddlewareBypassesUpstreamForAllowlistedIP(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		upstreamCalls++
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	nextCall := &capturedRequest{}
	handler := mustMiddleware(t, &Config{
		Address:             upstream.URL,
		Allowlist:           []string{"192.168.31.0/24"},
		AuthResponseHeaders: []string{"Remote-User"},
		TrustForwardHeader:  true,
	}, nextCall.handler(), now)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req.Header.Set("X-Forwarded-For", "192.168.31.42")
	req.Header.Set("Remote-User", "spoofed")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected next handler response, got %d", rec.Code)
	}
	if upstreamCalls != 0 {
		t.Fatalf("expected no upstream calls, got %d", upstreamCalls)
	}
	if !nextCall.called {
		t.Fatal("expected next handler to be called")
	}
	if got := nextCall.headers.Get(HeaderCacheStatus); got != "bypass" {
		t.Fatalf("expected bypass cache status, got %q", got)
	}
	if got := nextCall.headers.Get("Remote-User"); got != "" {
		t.Fatalf("expected auth response header to be stripped on bypass, got %q", got)
	}
}

func TestMiddlewareReturnsCacheHitWithoutUpstreamCall(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		upstreamCalls++
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	nextCall := &capturedRequest{}
	handler := mustMiddleware(t, &Config{
		Address:             upstream.URL,
		AuthResponseHeaders: []string{"Remote-User"},
		TrustForwardHeader:  true,
	}, nextCall.handler(), now)

	scope := handler.scope(httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil))
	handler.grants.Allow(scope, "203.0.113.10", 5*time.Minute, now)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("Remote-User", "spoofed")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected next handler response, got %d", rec.Code)
	}
	if upstreamCalls != 0 {
		t.Fatalf("expected no upstream calls, got %d", upstreamCalls)
	}
	if got := nextCall.headers.Get(HeaderCacheStatus); got != "hit" {
		t.Fatalf("expected cache hit status, got %q", got)
	}
	if got := nextCall.headers.Get(HeaderCacheRemaining); got != "5m0s" {
		t.Fatalf("expected cache remaining header, got %q", got)
	}
	if got := nextCall.headers.Get("Remote-User"); got != "" {
		t.Fatalf("expected auth response header not to replay on hit, got %q", got)
	}
}

func TestMiddlewareRequiresChallengeBeforeCachingIP(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	var seenCookies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seenCookies = append(seenCookies, req.Header.Get("Cookie"))
		if req.Header.Get("Cookie") == "" {
			http.Redirect(rw, req, "https://auth.example.com/?rd=https%3A%2F%2Fapp.example.com%2Fprivate", http.StatusFound)
			return
		}
		rw.Header().Set("Remote-User", "alice")
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	nextCall := &capturedRequest{}
	handler := mustMiddleware(t, &Config{
		Address:             upstream.URL,
		GrantTTL:            "5m",
		ChallengeTTL:        "2m",
		AuthResponseHeaders: []string{"Remote-User"},
		TrustForwardHeader:  true,
	}, nextCall.handler(), now)

	req1 := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req1.Host = "app.example.com"
	req1.Header.Set("X-Forwarded-For", "203.0.113.10")
	req1.Header.Set("Cookie", "authelia_session=abc")
	rec1 := httptest.NewRecorder()

	handler.ServeHTTP(rec1, req1)

	if rec1.Code != http.StatusFound {
		t.Fatalf("expected challenge redirect, got %d", rec1.Code)
	}
	if got := seenCookies[0]; got != "" {
		t.Fatalf("expected first probe to strip cookies, got %q", got)
	}

	req2 := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req2.Host = "app.example.com"
	req2.Header.Set("X-Forwarded-For", "203.0.113.10")
	req2.Header.Set("Cookie", "authelia_session=abc")
	req2.Header.Set("Remote-User", "spoofed")
	rec2 := httptest.NewRecorder()

	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusNoContent {
		t.Fatalf("expected next handler response, got %d", rec2.Code)
	}
	if got := seenCookies[1]; got != "authelia_session=abc" {
		t.Fatalf("expected second probe to include cookies, got %q", got)
	}
	if got := nextCall.headers.Get(HeaderCacheStatus); got != "stored" {
		t.Fatalf("expected stored cache status, got %q", got)
	}
	if got := nextCall.headers.Get("Remote-User"); got != "alice" {
		t.Fatalf("expected upstream auth response header, got %q", got)
	}
	if !handler.grants.IsAllowed(handler.scope(req2), "203.0.113.10", now.Add(time.Minute)) {
		t.Fatal("expected IP to be cached after challenged success")
	}

	nextCall.reset()
	req3 := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req3.Host = "app.example.com"
	req3.Header.Set("X-Forwarded-For", "203.0.113.10")
	req3.Header.Set("Remote-User", "spoofed-again")
	rec3 := httptest.NewRecorder()

	handler.ServeHTTP(rec3, req3)

	if rec3.Code != http.StatusNoContent {
		t.Fatalf("expected cached request to reach next handler, got %d", rec3.Code)
	}
	if got := nextCall.headers.Get("Remote-User"); got != "" {
		t.Fatalf("expected hit path not to replay auth header, got %q", got)
	}
}

func TestMiddlewareRequiresNewChallengeForDifferentIP(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	var seenCookies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seenCookies = append(seenCookies, req.Header.Get("Cookie"))
		if req.Header.Get("Cookie") == "" {
			http.Redirect(rw, req, "https://auth.example.com/login", http.StatusFound)
			return
		}
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := mustMiddleware(t, &Config{
		Address:            upstream.URL,
		GrantTTL:           "5m",
		TrustForwardHeader: true,
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), now)

	handler.pendingChallenges.Allow("ipauth|app.example.com", "203.0.113.10", handler.challengeTTL, now)

	reqAllowed := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	reqAllowed.Host = "app.example.com"
	reqAllowed.Header.Set("X-Forwarded-For", "203.0.113.10")
	reqAllowed.Header.Set("Cookie", "authelia_session=abc")
	recAllowed := httptest.NewRecorder()
	handler.ServeHTTP(recAllowed, reqAllowed)

	reqOther := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	reqOther.Host = "app.example.com"
	reqOther.Header.Set("X-Forwarded-For", "198.51.100.24")
	reqOther.Header.Set("Cookie", "authelia_session=abc")
	recOther := httptest.NewRecorder()
	handler.ServeHTTP(recOther, reqOther)

	if recOther.Code != http.StatusFound {
		t.Fatalf("expected different IP to be challenged, got %d", recOther.Code)
	}
	if got := seenCookies[len(seenCookies)-1]; got != "" {
		t.Fatalf("expected different IP probe to strip cookies, got %q", got)
	}
	if handler.grants.IsAllowed("ipauth|app.example.com", "198.51.100.24", now.Add(time.Minute)) {
		t.Fatal("expected different IP not to be cached")
	}
}

func TestMiddlewareExpiredPendingChallengeRequiresRestart(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	var seenCookies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seenCookies = append(seenCookies, req.Header.Get("Cookie"))
		if req.Header.Get("Cookie") == "" {
			http.Redirect(rw, req, "https://auth.example.com/login", http.StatusFound)
			return
		}
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	currentTime := now
	handler, err := newMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), &Config{
		Address:            upstream.URL,
		GrantTTL:           "5m",
		ChallengeTTL:       "1m",
		TrustForwardHeader: true,
	}, "ipauth", func() time.Time { return currentTime }, nil)
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}

	req1 := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req1.Host = "app.example.com"
	req1.Header.Set("X-Forwarded-For", "203.0.113.10")
	req1.Header.Set("Cookie", "authelia_session=abc")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)

	currentTime = now.Add(2 * time.Minute)

	req2 := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req2.Host = "app.example.com"
	req2.Header.Set("X-Forwarded-For", "203.0.113.10")
	req2.Header.Set("Cookie", "authelia_session=abc")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusFound {
		t.Fatalf("expected expired pending challenge to force a new redirect, got %d", rec2.Code)
	}
	if got := seenCookies[len(seenCookies)-1]; got != "" {
		t.Fatalf("expected expired pending challenge to strip cookies again, got %q", got)
	}
}

func TestMiddlewareGrantTTLZeroBehavesLikeForwardAuth(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	var seenCookies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seenCookies = append(seenCookies, req.Header.Get("Cookie"))
		rw.Header().Set("Remote-User", "alice")
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	nextCall := &capturedRequest{}
	handler := mustMiddleware(t, &Config{
		Address:             upstream.URL,
		GrantTTL:            "0s",
		AuthResponseHeaders: []string{"Remote-User"},
	}, nextCall.handler(), now)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	req.Header.Set("Cookie", "authelia_session=abc")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected next handler response, got %d", rec.Code)
	}
	if got := seenCookies[0]; got != "authelia_session=abc" {
		t.Fatalf("expected cookies to be forwarded when grantTTL=0, got %q", got)
	}
	if got := nextCall.headers.Get("Remote-User"); got != "alice" {
		t.Fatalf("expected auth response header to reach downstream request, got %q", got)
	}
	if got := nextCall.headers.Get(HeaderCacheStatus); got != "" {
		t.Fatalf("expected no cache status when cache disabled, got %q", got)
	}
	if handler.grants.IsAllowed(handler.scope(req), "203.0.113.10", now.Add(time.Minute)) {
		t.Fatal("expected cache to stay disabled")
	}
}

func TestMiddlewareDoesNotCacheInvalidClientIP(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	var seenCookies []string
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		seenCookies = append(seenCookies, req.Header.Get("Cookie"))
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	nextCall := &capturedRequest{}
	handler := mustMiddleware(t, &Config{
		Address: upstream.URL,
	}, nextCall.handler(), now)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "not-an-ip"
	req.Header.Set("Cookie", "authelia_session=abc")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected next handler response, got %d", rec.Code)
	}
	if got := seenCookies[0]; got != "authelia_session=abc" {
		t.Fatalf("expected invalid IP request not to strip cookies, got %q", got)
	}
	if got := nextCall.headers.Get(HeaderCacheStatus); got != "" {
		t.Fatalf("expected no cache status for invalid client IP, got %q", got)
	}
}

func TestMiddlewarePassesThroughUpstreamFailure(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Location", "https://auth.example.com/login")
		http.Error(rw, "login required", http.StatusUnauthorized)
	}))
	defer upstream.Close()

	handler := mustMiddleware(t, &Config{
		Address: upstream.URL,
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Fatal("next handler should not be called on upstream failure")
	}), now)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected upstream status code, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://auth.example.com/login" {
		t.Fatalf("expected location header to be preserved, got %q", got)
	}
	body, _ := io.ReadAll(rec.Body)
	if !strings.Contains(string(body), "login required") {
		t.Fatalf("expected upstream body to be preserved, got %q", string(body))
	}
}

func TestMiddlewareAddsForwardHeadersAndFiltersAuthRequestHeaders(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	var captured http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		captured = req.Header.Clone()
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := mustMiddleware(t, &Config{
		Address:            upstream.URL,
		GrantTTL:           "0s",
		AuthRequestHeaders: []string{"Authorization"},
		TrustForwardHeader: true,
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), now)

	req := httptest.NewRequest(http.MethodPost, "https://app.example.com/private?a=1", nil)
	req.Host = "app.example.com"
	req.Header.Set("Authorization", "Bearer token")
	req.Header.Set("X-Custom", "ignore-me")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-For", "203.0.113.10, 10.0.0.5")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected next handler response, got %d", rec.Code)
	}
	if got := captured.Get("Authorization"); got != "Bearer token" {
		t.Fatalf("expected allowed auth request header, got %q", got)
	}
	if got := captured.Get("X-Custom"); got != "" {
		t.Fatalf("expected filtered header to be absent, got %q", got)
	}
	if got := captured.Get("X-Forwarded-Method"); got != "POST" {
		t.Fatalf("expected forwarded method header, got %q", got)
	}
	if got := captured.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("expected forwarded proto header, got %q", got)
	}
	if got := captured.Get("X-Forwarded-Host"); got != "app.example.com" {
		t.Fatalf("expected forwarded host header, got %q", got)
	}
	if got := captured.Get("X-Forwarded-Uri"); got != "/private?a=1" {
		t.Fatalf("expected forwarded uri header, got %q", got)
	}
	if got := captured.Get("X-Forwarded-For"); got != "203.0.113.10, 10.0.0.5" {
		t.Fatalf("expected forwarded for header, got %q", got)
	}
}

func TestMiddlewareDoesNotTrustForwardHeadersByDefault(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	var captured http.Header
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		captured = req.Header.Clone()
		rw.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	handler := mustMiddleware(t, &Config{
		Address:   upstream.URL,
		Allowlist: []string{"192.168.31.0/24"},
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Fatal("next handler should not be called when spoofed forward headers are ignored")
	}), now)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "203.0.113.10:1234"
	req.Header.Set("X-Forwarded-For", "192.168.31.42")
	req.Header.Set("X-Forwarded-Proto", "http")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected upstream challenge, got %d", rec.Code)
	}
	if got := captured.Get("X-Forwarded-For"); got != "203.0.113.10" {
		t.Fatalf("expected remote addr to be forwarded, got %q", got)
	}
	if got := captured.Get("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("expected proto to be derived from the request, got %q", got)
	}
}

func TestMiddlewareScopesGrantByMethodHostAndURI(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		upstreamCalls++
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := mustMiddleware(t, &Config{
		Address:            upstream.URL,
		GrantTTL:           "5m",
		TrustForwardHeader: true,
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), now)

	baseReq := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	baseReq.Host = "app.example.com"
	handler.grants.Allow(handler.scope(baseReq), "203.0.113.10", 5*time.Minute, now)

	cases := []struct {
		name   string
		method string
		url    string
		host   string
	}{
		{name: "different path", method: http.MethodGet, url: "https://app.example.com/admin", host: "app.example.com"},
		{name: "different method", method: http.MethodPost, url: "https://app.example.com/private", host: "app.example.com"},
		{name: "different host", method: http.MethodGet, url: "https://admin.example.com/private", host: "admin.example.com"},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(tc.method, tc.url, nil)
		req.Host = tc.host
		req.Header.Set("X-Forwarded-For", "203.0.113.10")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("%s: expected upstream success path, got %d", tc.name, rec.Code)
		}
		if got := req.Header.Get(HeaderCacheStatus); got == "hit" {
			t.Fatalf("%s: expected cache miss for a different authorization scope", tc.name)
		}
	}

	if upstreamCalls != len(cases) {
		t.Fatalf("expected %d upstream calls for mismatched scopes, got %d", len(cases), upstreamCalls)
	}
}

func TestMiddlewareDoesNotStoreGrantOnFirstUncached200(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		upstreamCalls++
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := mustMiddleware(t, &Config{
		Address:            upstream.URL,
		GrantTTL:           "5m",
		TrustForwardHeader: true,
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusNoContent)
	}), now)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
		req.Host = "app.example.com"
		req.Header.Set("X-Forwarded-For", "203.0.113.10")
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("request %d: expected downstream success, got %d", i+1, rec.Code)
		}
		if got := req.Header.Get(HeaderCacheStatus); got != "" {
			t.Fatalf("request %d: expected no cache status on first-step 200 flow, got %q", i+1, got)
		}
	}

	if upstreamCalls != 2 {
		t.Fatalf("expected upstream to be called for both uncached 200 responses, got %d", upstreamCalls)
	}
}

func TestMiddlewareStartsChallengeForUnauthorizedAndForbiddenResponses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{name: "unauthorized", statusCode: http.StatusUnauthorized},
		{name: "forbidden", statusCode: http.StatusForbidden},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
			var seenCookies []string
			upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
				seenCookies = append(seenCookies, req.Header.Get("Cookie"))
				if req.Header.Get("Cookie") == "" {
					http.Error(rw, "challenge", tc.statusCode)
					return
				}
				rw.Header().Set("Remote-User", "alice")
				rw.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			nextCall := &capturedRequest{}
			handler := mustMiddleware(t, &Config{
				Address:             upstream.URL,
				GrantTTL:            "5m",
				ChallengeTTL:        "2m",
				AuthResponseHeaders: []string{"Remote-User"},
				TrustForwardHeader:  true,
			}, nextCall.handler(), now)

			req1 := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
			req1.Host = "app.example.com"
			req1.Header.Set("X-Forwarded-For", "203.0.113.10")
			req1.Header.Set("Cookie", "authelia_session=abc")
			rec1 := httptest.NewRecorder()
			handler.ServeHTTP(rec1, req1)

			if rec1.Code != tc.statusCode {
				t.Fatalf("expected initial challenge status %d, got %d", tc.statusCode, rec1.Code)
			}
			if seenCookies[0] != "" {
				t.Fatalf("expected first probe to strip cookies, got %q", seenCookies[0])
			}

			req2 := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
			req2.Host = "app.example.com"
			req2.Header.Set("X-Forwarded-For", "203.0.113.10")
			req2.Header.Set("Cookie", "authelia_session=abc")
			rec2 := httptest.NewRecorder()
			handler.ServeHTTP(rec2, req2)

			if rec2.Code != http.StatusNoContent {
				t.Fatalf("expected second request to reach downstream, got %d", rec2.Code)
			}
			if got := req2.Header.Get(HeaderCacheStatus); got != "stored" {
				t.Fatalf("expected second request to store the grant, got %q", got)
			}

			req3 := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
			req3.Host = "app.example.com"
			req3.Header.Set("X-Forwarded-For", "203.0.113.10")
			rec3 := httptest.NewRecorder()
			nextCall.reset()
			handler.ServeHTTP(rec3, req3)

			if rec3.Code != http.StatusNoContent {
				t.Fatalf("expected cached request to reach downstream, got %d", rec3.Code)
			}
			if got := req3.Header.Get(HeaderCacheStatus); got != "hit" {
				t.Fatalf("expected cached hit after %d challenge, got %q", tc.statusCode, got)
			}
		})
	}
}

func TestMiddlewareRewritesRelativeLocationByDefault(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Location", "/login")
		rw.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	handler := mustMiddleware(t, &Config{
		Address:            upstream.URL + "/verify",
		TrustForwardHeader: true,
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Fatal("next handler should not be called on auth redirect")
	}), now)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != upstream.URL+"/login" {
		t.Fatalf("expected relative Location to be rewritten through auth origin, got %q", got)
	}
}

func TestMiddlewarePreservesRelativeLocationWhenConfigured(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.Header().Set("Location", "/login")
		rw.WriteHeader(http.StatusFound)
	}))
	defer upstream.Close()

	handler := mustMiddleware(t, &Config{
		Address:                upstream.URL + "/verify",
		PreserveLocationHeader: true,
		TrustForwardHeader:     true,
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Fatal("next handler should not be called on auth redirect")
	}), now)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	req.Host = "app.example.com"
	req.Header.Set("X-Forwarded-For", "203.0.113.10")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/login" {
		t.Fatalf("expected relative Location to be preserved, got %q", got)
	}
}

func TestMiddlewareForwardsBodyAndMethodToAuthAndDownstream(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	var upstreamMethod string
	var upstreamBody string
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		upstreamMethod = req.Method
		body, _ := io.ReadAll(req.Body)
		upstreamBody = string(body)
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	nextCall := &capturedRequest{}
	handler := mustMiddleware(t, &Config{
		Address:               upstream.URL,
		GrantTTL:              "0s",
		ForwardBody:           true,
		PreserveRequestMethod: true,
		MaxBodySize:           32,
	}, nextCall.handler(), now)

	req := httptest.NewRequest(http.MethodPost, "https://app.example.com/private", strings.NewReader("payload"))
	req.Host = "app.example.com"
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected next handler response, got %d", rec.Code)
	}
	if upstreamMethod != http.MethodPost {
		t.Fatalf("expected preserved request method, got %q", upstreamMethod)
	}
	if upstreamBody != "payload" {
		t.Fatalf("expected upstream body to be forwarded, got %q", upstreamBody)
	}
	if nextCall.body != "payload" {
		t.Fatalf("expected downstream request body to be restored, got %q", nextCall.body)
	}
}

func TestMiddlewareRejectsBodyLargerThanMax(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		upstreamCalls++
		rw.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	handler := mustMiddleware(t, &Config{
		Address:     upstream.URL,
		GrantTTL:    "0s",
		ForwardBody: true,
		MaxBodySize: 4,
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Fatal("next handler should not be called for oversized bodies")
	}), now)

	req := httptest.NewRequest(http.MethodPost, "https://app.example.com/private", strings.NewReader("payload"))
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected oversized body to fail with 401, got %d", rec.Code)
	}
	if upstreamCalls != 0 {
		t.Fatalf("expected upstream not to be called, got %d", upstreamCalls)
	}
}

func TestMiddlewareReturnsBadGatewayWhenUpstreamUnavailable(t *testing.T) {
	now := time.Date(2026, 4, 18, 12, 0, 0, 0, time.UTC)
	handler := mustMiddleware(t, &Config{
		Address: "http://127.0.0.1:1",
	}, http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		t.Fatal("next handler should not be called when upstream is unavailable")
	}), now)

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/private", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadGateway {
		t.Fatalf("expected 502 from unavailable upstream, got %d", rec.Code)
	}
}

type capturedRequest struct {
	called  bool
	method  string
	headers http.Header
	body    string
}

func (c *capturedRequest) handler() http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		c.called = true
		c.method = req.Method
		c.headers = req.Header.Clone()
		if req.Body != nil {
			body, _ := io.ReadAll(req.Body)
			c.body = string(body)
		}
		rw.WriteHeader(http.StatusNoContent)
	})
}

func (c *capturedRequest) reset() {
	c.called = false
	c.method = ""
	c.headers = nil
	c.body = ""
}

func mustMiddleware(t *testing.T, cfg *Config, next http.Handler, now time.Time) *Middleware {
	t.Helper()

	handler, err := newMiddleware(next, cfg, "ipauth", nowFunc(now), nil)
	if err != nil {
		t.Fatalf("new middleware: %v", err)
	}

	return handler
}

func nowFunc(now time.Time) func() time.Time {
	return func() time.Time {
		return now
	}
}

func TestPluginSignatureCompiles(t *testing.T) {
	cfg := CreateConfig()
	cfg.Address = "http://auth.example.com"
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(context.Background(), next, cfg, "ipauth")
	if err != nil {
		t.Fatalf("expected plugin constructor to succeed, got %v", err)
	}
	if handler == nil {
		t.Fatal("expected plugin constructor to return a handler")
	}
}

func TestManifestAndExamplesExist(t *testing.T) {
	paths := []string{
		".traefik.yml",
		"README.md",
		"docker-compose.example.yml",
		"traefik/static.yml",
		"traefik/dynamic.yml",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected %s to exist: %v", path, err)
		}
	}

	manifest, err := os.ReadFile(".traefik.yml")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !strings.Contains(string(manifest), "import: github.com/monlor/traefik-ip-auth-gateway") {
		t.Fatal("expected manifest to reference the plugin module path")
	}
	if !strings.Contains(string(manifest), "type: middleware") {
		t.Fatal("expected manifest to declare a middleware plugin")
	}
}
