package gateway

import (
	"errors"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultCacheTTL = 2 * time.Hour

type Config struct {
	ListenAddr string                `yaml:"listen_addr"`
	UpstreamURL string               `yaml:"upstream_url"`
	DefaultTTL time.Duration         `yaml:"default_ttl"`
}

func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = ":8080"
	}
	if cfg.DefaultTTL == 0 {
		cfg.DefaultTTL = DefaultCacheTTL
	}
	if cfg.DefaultTTL < 0 {
		return Config{}, errors.New("default_ttl must not be negative")
	}
	if cfg.UpstreamURL == "" {
		return Config{}, errors.New("upstream_url is required")
	}

	return cfg, nil
}
