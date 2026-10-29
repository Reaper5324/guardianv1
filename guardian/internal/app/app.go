// Package app wires Guardian's components together. Both the console
// runner and the Windows service call Run.
package app

import (
	"context"
	"fmt"
	"log"

	"guardian/internal/config"
	"guardian/internal/dnsproxy"
)

// Run loads the config and serves DNS until ctx is cancelled. It returns nil
// on a clean shutdown and an error if startup or serving fails.
func Run(ctx context.Context, cfgPath string) error {
	cfg, usedFallback, err := config.LoadWithFallback(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if usedFallback {
		log.Printf("primary config unavailable or older; using last-known-good config")
	}
	store := &config.Store{}
	if err := store.Set(cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	proxy, err := dnsproxy.New(store)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	proxy.OnBlocked = func(name, client string) {
		log.Printf("BLOCKED %s (from %s)", name, client)
	}

	log.Printf("guardian listening on %s", cfg.ListenAddr)
	return proxy.Run(ctx)
}
