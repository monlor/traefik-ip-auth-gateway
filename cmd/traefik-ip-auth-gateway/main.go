package main

import (
	"flag"
	"log"
	"net/http"

	gateway "traefik-ip-auth-gateway"
)

func main() {
	var configPath string
	flag.StringVar(&configPath, "config", "config.yml", "path to config file")
	flag.Parse()

	cfg, err := gateway.LoadConfig(configPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	handler := gateway.NewHandler(cfg, gateway.NewMemoryStore(), nil)

	server := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: handler,
	}

	log.Printf("auth-gateway listening on %s", cfg.ListenAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("serve: %v", err)
	}
}
