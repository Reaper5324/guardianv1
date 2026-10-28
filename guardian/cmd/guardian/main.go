package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	_ "time/tzdata" // embed timezone data so Windows can resolve zones

	"guardian/internal/config"
	"guardian/internal/dnsproxy"
)

func main() {
	cfgPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	store := &config.Store{}
	store.Set(cfg)

	proxy, err := dnsproxy.New(store)
	if err != nil {
		log.Fatalf("proxy: %v", err)
	}
	proxy.OnBlocked = func(name, client string) {
		log.Printf("BLOCKED %s (from %s)", name, client)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	log.Printf("guardian listening on %s", cfg.ListenAddr)
	if err := proxy.Run(ctx); err != nil {
		log.Fatalf("dns server: %v", err)
	}
}
