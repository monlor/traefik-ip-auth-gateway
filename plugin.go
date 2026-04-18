// Package traefik_ip_auth_gateway provides a Traefik middleware plugin that caches successful
// forward-auth challenges by request host and public client IP.
package traefik_ip_auth_gateway

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	HeaderCacheStatus    = "X-Auth-Cache-Status"
	HeaderCacheRemaining = "X-Auth-Cache-Remaining"
	HeaderCacheExpiresAt = "X-Auth-Cache-Expires-At"
)

const (
	DefaultGrantTTL     = 2 * time.Hour
	DefaultChallengeTTL = 5 * time.Minute
	DefaultMaxBodySize  = int64(-1)
)

var hopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

var errBodyTooLarge = errors.New("request body too large")

// Config is the per-middleware Traefik plugin configuration.
type Config struct {
	Address                string   `json:"address,omitempty" yaml:"address,omitempty"`
	GrantTTL               string   `json:"grantTTL,omitempty" yaml:"grantTTL,omitempty"`
	ChallengeTTL           string   `json:"challengeTTL,omitempty" yaml:"challengeTTL,omitempty"`
	Allowlist              []string `json:"allowlist,omitempty" yaml:"allowlist,omitempty"`
	AuthRequestHeaders     []string `json:"authRequestHeaders,omitempty" yaml:"authRequestHeaders,omitempty"`
	AuthResponseHeaders    []string `json:"authResponseHeaders,omitempty" yaml:"authResponseHeaders,omitempty"`
	TrustForwardHeader     bool     `json:"trustForwardHeader,omitempty" yaml:"trustForwardHeader,omitempty"`
	PreserveLocationHeader bool     `json:"preserveLocationHeader,omitempty" yaml:"preserveLocationHeader,omitempty"`
	PreserveRequestMethod  bool     `json:"preserveRequestMethod,omitempty" yaml:"preserveRequestMethod,omitempty"`
	ForwardBody            bool     `json:"forwardBody,omitempty" yaml:"forwardBody,omitempty"`
	MaxBodySize            int64    `json:"maxBodySize,omitempty" yaml:"maxBodySize,omitempty"`
}

// CreateConfig returns the default middleware configuration.
func CreateConfig() *Config {
	return &Config{
		GrantTTL:     DefaultGrantTTL.String(),
		ChallengeTTL: DefaultChallengeTTL.String(),
		MaxBodySize:  DefaultMaxBodySize,
	}
}

// Middleware implements the Traefik middleware plugin.
type Middleware struct {
	next                   http.Handler
	name                   string
	address                *url.URL
	grantTTL               time.Duration
	challengeTTL           time.Duration
	allowlist              []*net.IPNet
	authRequestHeaders     []string
	authResponseHeaders    []string
	trustForwardHeader     bool
	preserveLocationHeader bool
	preserveRequestMethod  bool
	forwardBody            bool
	maxBodySize            int64
	client                 *http.Client
	grants                 *MemoryStore
	pendingChallenges      *MemoryStore
	now                    func() time.Time
}

// New creates a new middleware plugin instance.
func New(_ context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return newMiddleware(next, config, name, time.Now, nil)
}

func newMiddleware(next http.Handler, config *Config, name string, now func() time.Time, client *http.Client) (*Middleware, error) {
	if next == nil {
		return nil, errors.New("next handler is required")
	}
	if config == nil {
		config = CreateConfig()
	}

	address, err := parseAddress(config.Address)
	if err != nil {
		return nil, err
	}

	grantTTL, err := parseDuration("grantTTL", config.GrantTTL, DefaultGrantTTL)
	if err != nil {
		return nil, err
	}

	challengeTTL, err := parseDuration("challengeTTL", config.ChallengeTTL, DefaultChallengeTTL)
	if err != nil {
		return nil, err
	}
	if grantTTL > 0 && challengeTTL <= 0 {
		return nil, errors.New("challengeTTL must be greater than 0 when grantTTL is enabled")
	}

	allowlist, err := parseAllowlist(config.Allowlist)
	if err != nil {
		return nil, err
	}

	if config.MaxBodySize < 0 && config.MaxBodySize != DefaultMaxBodySize {
		return nil, errors.New("maxBodySize must be -1 or greater")
	}

	if now == nil {
		now = time.Now
	}
	if client == nil {
		client = &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}

	return &Middleware{
		next:                   next,
		name:                   name,
		address:                address,
		grantTTL:               grantTTL,
		challengeTTL:           challengeTTL,
		allowlist:              allowlist,
		authRequestHeaders:     canonicalizeHeaderNames(config.AuthRequestHeaders),
		authResponseHeaders:    canonicalizeHeaderNames(config.AuthResponseHeaders),
		trustForwardHeader:     config.TrustForwardHeader,
		preserveLocationHeader: config.PreserveLocationHeader,
		preserveRequestMethod:  config.PreserveRequestMethod,
		forwardBody:            config.ForwardBody,
		maxBodySize:            config.MaxBodySize,
		client:                 client,
		grants:                 NewMemoryStore(),
		pendingChallenges:      NewMemoryStore(),
		now:                    now,
	}, nil
}

// ServeHTTP checks cache state, optionally consults the configured forward-auth
// endpoint, and then either short-circuits or forwards the request downstream.
func (m *Middleware) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	now := m.now()
	scope := m.scope(req)
	clientIP := realClientIP(req, m.trustForwardHeader)
	validClientIP := net.ParseIP(clientIP) != nil
	cacheEnabled := m.grantTTL > 0 && validClientIP

	if validClientIP && m.isAllowlisted(clientIP) {
		m.prepareDownstreamRequest(req)
		req.Header.Set(HeaderCacheStatus, "bypass")
		m.next.ServeHTTP(rw, req)
		return
	}

	if cacheEnabled {
		if expiresAt, ok := m.grants.ExpiresAt(scope, clientIP, now); ok {
			m.prepareDownstreamRequest(req)
			setDiagnosticHeaders(req.Header, now, expiresAt, "hit")
			m.next.ServeHTTP(rw, req)
			return
		}
	}

	challengePending := cacheEnabled && m.pendingChallenges.IsAllowed(scope, clientIP, now)

	authReq, err := m.buildAuthRequest(req, cacheEnabled, challengePending)
	if err != nil {
		switch {
		case errors.Is(err, errBodyTooLarge):
			rw.WriteHeader(http.StatusUnauthorized)
		default:
			http.Error(rw, "failed to build auth request", http.StatusInternalServerError)
		}
		return
	}

	authResp, err := m.client.Do(authReq)
	if err != nil {
		http.Error(rw, "upstream auth unavailable", http.StatusBadGateway)
		return
	}
	defer authResp.Body.Close()

	if cacheEnabled && shouldStartAuthChallenge(authResp.StatusCode) {
		m.pendingChallenges.Allow(scope, clientIP, m.challengeTTL, now)
	}

	if authResp.StatusCode < http.StatusOK || authResp.StatusCode >= http.StatusMultipleChoices {
		copyResponseHeaders(rw.Header(), authResp.Header, m.address, m.preserveLocationHeader)
		rw.WriteHeader(authResp.StatusCode)
		_, _ = io.Copy(rw, authResp.Body)
		return
	}

	m.prepareDownstreamRequest(req)
	copySelectedHeaders(req.Header, authResp.Header, m.authResponseHeaders)

	if challengePending {
		m.pendingChallenges.Delete(scope, clientIP)
	}

	if cacheEnabled && challengePending {
		expiresAt := now.Add(m.grantTTL)
		m.grants.Allow(scope, clientIP, m.grantTTL, now)
		setDiagnosticHeaders(req.Header, now, expiresAt, "stored")
	}

	req.RequestURI = req.URL.RequestURI()
	m.next.ServeHTTP(rw, req)
}

func (m *Middleware) buildAuthRequest(req *http.Request, cacheEnabled bool, challengePending bool) (*http.Request, error) {
	method := http.MethodGet
	if m.preserveRequestMethod {
		method = req.Method
	}

	authReq, err := http.NewRequestWithContext(req.Context(), method, m.address.String(), nil)
	if err != nil {
		return nil, err
	}

	if m.forwardBody {
		bodyBytes, err := m.readBodyBytes(req)
		if err != nil {
			return nil, err
		}

		req.Body = cloneBody(bodyBytes)
		req.ContentLength = int64(len(bodyBytes))
		authReq.Body = cloneBody(bodyBytes)
		authReq.ContentLength = int64(len(bodyBytes))
	}

	copyRequestHeaders(authReq.Header, req.Header, m.authRequestHeaders)
	removeConnectionHeaders(authReq.Header)
	removeHopHeaders(authReq.Header)
	removeInternalHeaders(authReq.Header, m.authResponseHeaders)
	setForwardHeaders(authReq.Header, req, m.trustForwardHeader)

	if cacheEnabled && !challengePending {
		authReq.Header.Del("Cookie")
	}

	return authReq, nil
}

func (m *Middleware) readBodyBytes(req *http.Request) ([]byte, error) {
	if req.Body == nil || req.Body == http.NoBody {
		return nil, nil
	}

	if m.maxBodySize < 0 {
		return io.ReadAll(req.Body)
	}

	body, err := io.ReadAll(io.LimitReader(req.Body, m.maxBodySize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > m.maxBodySize {
		return nil, errBodyTooLarge
	}

	return body, nil
}

func (m *Middleware) prepareDownstreamRequest(req *http.Request) {
	removeInternalHeaders(req.Header, m.authResponseHeaders)
}

func (m *Middleware) scope(req *http.Request) string {
	return strings.Join([]string{
		m.name,
		req.Method,
		requestHost(req),
		req.URL.RequestURI(),
	}, "|")
}

func (m *Middleware) isAllowlisted(rawIP string) bool {
	ip := net.ParseIP(strings.TrimSpace(rawIP))
	if ip == nil {
		return false
	}

	for _, network := range m.allowlist {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

func parseAddress(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("address is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid address: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, errors.New("address must use http or https")
	}
	if parsed.Host == "" {
		return nil, errors.New("address must include a host")
	}

	return parsed, nil
}

func parseDuration(field, raw string, fallback time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback, nil
	}

	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid Go duration", field)
	}
	if value < 0 {
		return 0, fmt.Errorf("%s must not be negative", field)
	}

	return value, nil
}

func parseAllowlist(entries []string) ([]*net.IPNet, error) {
	var networks []*net.IPNet

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			return nil, errors.New("allowlist entries must not be empty")
		}

		if ip := net.ParseIP(entry); ip != nil {
			networks = append(networks, singleIPNetwork(ip))
			continue
		}

		_, network, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist entry %q: %w", entry, err)
		}
		networks = append(networks, network)
	}

	return networks, nil
}

func singleIPNetwork(ip net.IP) *net.IPNet {
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}
	}

	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}
}

func shouldStartAuthChallenge(statusCode int) bool {
	if statusCode >= 300 && statusCode < 400 {
		return true
	}

	return statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
}

func requestHost(req *http.Request) string {
	host := req.Host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}
	return host
}

func realClientIP(req *http.Request, trustForwardHeader bool) string {
	if trustForwardHeader {
		if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
			parts := strings.Split(forwarded, ",")
			if len(parts) > 0 {
				return strings.TrimSpace(parts[0])
			}
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err == nil {
		return host
	}
	return req.RemoteAddr
}

func setForwardHeaders(dst http.Header, req *http.Request, trustForwardHeader bool) {
	dst.Set("X-Forwarded-Method", req.Method)
	dst.Set("X-Forwarded-Host", req.Host)
	dst.Set("X-Forwarded-Uri", req.URL.RequestURI())

	if trustForwardHeader {
		if proto := strings.TrimSpace(req.Header.Get("X-Forwarded-Proto")); proto != "" {
			dst.Set("X-Forwarded-Proto", proto)
		} else if req.TLS != nil {
			dst.Set("X-Forwarded-Proto", "https")
		} else {
			dst.Set("X-Forwarded-Proto", "http")
		}

		if forwardedFor := strings.TrimSpace(req.Header.Get("X-Forwarded-For")); forwardedFor != "" {
			dst.Set("X-Forwarded-For", forwardedFor)
			return
		}
	} else if req.TLS != nil {
		dst.Set("X-Forwarded-Proto", "https")
	} else {
		dst.Set("X-Forwarded-Proto", "http")
	}

	if clientIP := strings.TrimSpace(realClientIP(req, trustForwardHeader)); clientIP != "" {
		dst.Set("X-Forwarded-For", clientIP)
	}
}

func canonicalizeHeaderNames(headers []string) []string {
	if len(headers) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(headers))
	var result []string
	for _, header := range headers {
		header = http.CanonicalHeaderKey(strings.TrimSpace(header))
		if header == "" {
			continue
		}
		if _, ok := seen[header]; ok {
			continue
		}
		seen[header] = struct{}{}
		result = append(result, header)
	}

	return result
}

func copyRequestHeaders(dst http.Header, src http.Header, allowed []string) {
	if len(allowed) == 0 {
		for key, values := range src {
			dst[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
		}
		return
	}

	for _, header := range allowed {
		values := src.Values(header)
		if len(values) == 0 {
			continue
		}
		dst[header] = append([]string(nil), values...)
	}
}

func copySelectedHeaders(dst http.Header, src http.Header, headers []string) {
	for _, header := range headers {
		dst.Del(header)
		if values := src.Values(header); len(values) > 0 {
			dst[header] = append([]string(nil), values...)
		}
	}
}

func copyResponseHeaders(dst http.Header, src http.Header, authAddress *url.URL, preserveLocationHeader bool) {
	for key, values := range src {
		canonical := http.CanonicalHeaderKey(key)
		if isHopHeader(canonical) {
			continue
		}
		dst.Del(canonical)
		dst[canonical] = append([]string(nil), values...)
	}

	if preserveLocationHeader {
		return
	}

	location := dst.Get("Location")
	if location == "" {
		return
	}

	rewritten, ok := rewriteLocationHeader(location, authAddress)
	if ok {
		dst.Set("Location", rewritten)
	}
}

func rewriteLocationHeader(location string, authAddress *url.URL) (string, bool) {
	if authAddress == nil {
		return "", false
	}

	parsed, err := url.Parse(location)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return "", false
	}

	parsed.Scheme = authAddress.Scheme
	parsed.Host = authAddress.Host
	if !strings.HasPrefix(parsed.Path, "/") {
		parsed.Path = "/" + parsed.Path
	}

	return parsed.String(), true
}

func removeInternalHeaders(header http.Header, authResponseHeaders []string) {
	header.Del(HeaderCacheStatus)
	header.Del(HeaderCacheRemaining)
	header.Del(HeaderCacheExpiresAt)
	for _, name := range authResponseHeaders {
		header.Del(name)
	}
}

func removeHopHeaders(header http.Header) {
	for _, hopHeader := range hopHeaders {
		header.Del(hopHeader)
	}
}

func removeConnectionHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			if token = strings.TrimSpace(token); token != "" {
				header.Del(token)
			}
		}
	}
}

func isHopHeader(header string) bool {
	for _, hopHeader := range hopHeaders {
		if http.CanonicalHeaderKey(hopHeader) == http.CanonicalHeaderKey(header) {
			return true
		}
	}
	return false
}

func cloneBody(body []byte) io.ReadCloser {
	if len(body) == 0 {
		return http.NoBody
	}
	return io.NopCloser(bytes.NewReader(body))
}

func setDiagnosticHeaders(headers http.Header, now, expiresAt time.Time, status string) {
	headers.Set(HeaderCacheStatus, status)
	headers.Set(HeaderCacheRemaining, expiresAt.Sub(now).Round(time.Second).String())
	headers.Set(HeaderCacheExpiresAt, expiresAt.UTC().Format(time.RFC3339))
}
