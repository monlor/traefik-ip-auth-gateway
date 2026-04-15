package gateway

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	HeaderCacheTTL = "X-Auth-Cache-TTL"
	HeaderCacheKey = "X-Auth-Cache-Key"
)

type Handler struct {
	config Config
	store  *MemoryStore
	now    func() time.Time
	client *http.Client
}

func NewHandler(config Config, store *MemoryStore, now func() time.Time) *Handler {
	if now == nil {
		now = time.Now
	}

	return &Handler{
		config: config,
		store:  store,
		now:    now,
		client: &http.Client{
			Timeout: 15 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scope := CacheScope(r)
	ip := RealClientIP(r)
	now := h.now()
	ttl, err := CacheTTL(r, h.config.DefaultTTL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if ttl > 0 && ip != "" && h.store.IsAllowed(scope, ip, now) {
		w.WriteHeader(http.StatusOK)
		return
	}

	upstreamReq, err := http.NewRequestWithContext(r.Context(), r.Method, h.config.UpstreamURL, r.Body)
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}
	upstreamReq.Header = r.Header.Clone()
	upstreamReq.Host = r.Host
	upstreamReq.URL.RawQuery = r.URL.RawQuery

	resp, err := h.client.Do(upstreamReq)
	if err != nil {
		http.Error(w, "upstream auth unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 && ttl > 0 && ip != "" {
		h.store.Allow(scope, ip, ttl, now)
		log.Printf("INFO auth cache allow scope=%q ip=%q ttl=%s upstream_status=%d", scope, ip, ttl, resp.StatusCode)
	}
}

func RealClientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func requestHost(r *http.Request) string {
	host := r.Host
	if parsedHost, _, err := net.SplitHostPort(host); err == nil {
		return parsedHost
	}
	return host
}

func CacheScope(r *http.Request) string {
	host := requestHost(r)
	cacheKey := strings.TrimSpace(r.Header.Get(HeaderCacheKey))
	if cacheKey == "" {
		return host
	}
	return host + "|" + cacheKey
}

func CacheTTL(r *http.Request, fallback time.Duration) (time.Duration, error) {
	raw := strings.TrimSpace(r.Header.Get(HeaderCacheTTL))
	if raw == "" {
		return fallback, nil
	}

	ttl, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a valid Go duration", HeaderCacheTTL)
	}
	if ttl < 0 {
		return 0, fmt.Errorf("%s must not be negative", HeaderCacheTTL)
	}

	return ttl, nil
}

func copyHeader(dst http.Header, src http.Header) {
	for key, values := range src {
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}
