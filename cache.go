package traefik_ip_auth_gateway

import (
	"sync"
	"time"
)

const defaultCleanupInterval = time.Minute

type MemoryStore struct {
	mu              sync.RWMutex
	allowed         map[string]time.Time
	cleanupInterval time.Duration
	nextCleanup     time.Time
	beforeDelete    func()
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		allowed:         make(map[string]time.Time),
		cleanupInterval: defaultCleanupInterval,
	}
}

func (s *MemoryStore) Allow(scope string, ip string, ttl time.Duration, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cleanupExpiredLocked(now)
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

	if s.beforeDelete != nil {
		s.beforeDelete()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	currentExpiresAt, ok := s.allowed[cacheKey(scope, ip)]
	if !ok {
		return time.Time{}, false
	}
	if now.Before(currentExpiresAt) {
		return currentExpiresAt, true
	}

	delete(s.allowed, cacheKey(scope, ip))
	return time.Time{}, false
}

func (s *MemoryStore) IsAllowed(scope string, ip string, now time.Time) bool {
	_, ok := s.ExpiresAt(scope, ip, now)
	return ok
}

func (s *MemoryStore) Delete(scope string, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.allowed, cacheKey(scope, ip))
}

func (s *MemoryStore) cleanupExpiredLocked(now time.Time) {
	if !s.nextCleanup.IsZero() && now.Before(s.nextCleanup) {
		return
	}

	for key, expiresAt := range s.allowed {
		if !now.Before(expiresAt) {
			delete(s.allowed, key)
		}
	}

	s.nextCleanup = now.Add(s.cleanupInterval)
}

func cacheKey(scope string, ip string) string {
	return scope + "|" + ip
}
