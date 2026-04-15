package gateway

import (
	"sync"
	"time"
)

type MemoryStore struct {
	mu      sync.RWMutex
	allowed map[string]time.Time
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{allowed: make(map[string]time.Time)}
}

func (s *MemoryStore) Allow(scope string, ip string, ttl time.Duration, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.allowed[cacheKey(scope, ip)] = now.Add(ttl)
}

func (s *MemoryStore) ExpiresAt(scope string, ip string, now time.Time) (time.Time, bool) {
	s.mu.RLock()
	expiresAt, ok := s.allowed[cacheKey(scope, ip)]
	s.mu.RUnlock()
	if !ok {
		return time.Time{}, false
	}

	if now.Before(expiresAt) {
		return expiresAt, true
	}

	s.mu.Lock()
	delete(s.allowed, cacheKey(scope, ip))
	s.mu.Unlock()
	return time.Time{}, false
}

func (s *MemoryStore) IsAllowed(scope string, ip string, now time.Time) bool {
	_, ok := s.ExpiresAt(scope, ip, now)
	return ok
}

func cacheKey(scope string, ip string) string {
	return scope + "|" + ip
}
