package gateway

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigParsesHostTTLs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	content := []byte(`
listen_addr: ":8080"
upstream_url: "http://authelia:9091/api/authz/forward-auth"
default_ttl: "30m"
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.ListenAddr != ":8080" {
		t.Fatalf("expected listen addr, got %q", cfg.ListenAddr)
	}
	if cfg.UpstreamURL != "http://authelia:9091/api/authz/forward-auth" {
		t.Fatalf("expected upstream url, got %q", cfg.UpstreamURL)
	}
	if cfg.DefaultTTL != 30*time.Minute {
		t.Fatalf("expected default ttl, got %v", cfg.DefaultTTL)
	}
}

func TestLoadConfigUsesBuiltInDefaultTTLWhenMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	content := []byte(`
listen_addr: ":8080"
upstream_url: "http://authelia:9091/api/authz/forward-auth"
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.DefaultTTL != DefaultCacheTTL {
		t.Fatalf("expected default ttl %v, got %v", DefaultCacheTTL, cfg.DefaultTTL)
	}
}
