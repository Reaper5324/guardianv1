// Package dashboard serves Guardian's bundled, read-only local dashboard.
package dashboard

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"guardian/internal/config"
)

const address = "127.0.0.1:8765"

//go:embed web/*
var webFiles embed.FS

type status struct {
	Version            uint64    `json:"version"`
	ListenAddr         string    `json:"listen_addr"`
	Timezone           string    `json:"timezone"`
	UpstreamCount      int       `json:"upstream_count"`
	BlockedServices    []string  `json:"blocked_services"`
	BlockedDomainCount int       `json:"blocked_domain_count"`
	AllowedDomainCount int       `json:"allowed_domain_count"`
	BlockDoHProviders  bool      `json:"block_doh_providers"`
	BedtimeEnabled     bool      `json:"bedtime_enabled"`
	BedtimeStart       string    `json:"bedtime_start,omitempty"`
	BedtimeEnd         string    `json:"bedtime_end,omitempty"`
	BedtimeActive      bool      `json:"bedtime_active"`
	UsingFallback      bool      `json:"using_fallback"`
	ReadAt             time.Time `json:"read_at"`
}

// Handler returns a loopback-only read-only dashboard handler for cfgPath.
func Handler(cfgPath string) http.Handler {
	static, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if !allowedHost(r.Host) {
			http.Error(w, "invalid host", http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		cfg, fallback, err := config.LoadWithFallback(cfgPath)
		if err != nil {
			http.Error(w, "configuration unavailable", http.StatusServiceUnavailable)
			return
		}
		data := status{
			Version:            cfg.Version,
			ListenAddr:         cfg.ListenAddr,
			Timezone:           cfg.Timezone,
			UpstreamCount:      len(cfg.UpstreamDoH),
			BlockedServices:    append([]string(nil), cfg.BlockedServices...),
			BlockedDomainCount: len(cfg.BlockedDomains),
			AllowedDomainCount: len(cfg.AllowedDomains),
			BlockDoHProviders:  cfg.BlockDoHProviders,
			BedtimeEnabled:     cfg.Bedtime != nil,
			UsingFallback:      fallback,
			ReadAt:             time.Now(),
		}
		if cfg.Bedtime != nil {
			data.BedtimeStart = cfg.Bedtime.Start
			data.BedtimeEnd = cfg.Bedtime.End
			data.BedtimeActive = cfg.InBedtime(data.ReadAt)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(data)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if !allowedHost(r.Host) {
			http.Error(w, "invalid host", http.StatusMisdirectedRequest)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/")
		if name == "" {
			name = "index.html"
		}
		if name != "index.html" && name != "app.css" && name != "app.js" {
			http.NotFound(w, r)
			return
		}
		content, err := fs.ReadFile(static, name)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		contentType := map[string]string{
			"index.html": "text/html; charset=utf-8",
			"app.css":    "text/css; charset=utf-8",
			"app.js":     "text/javascript; charset=utf-8",
		}[name]
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		_, _ = w.Write(content)
	})
	return mux
}

func allowedHost(host string) bool {
	return strings.EqualFold(host, address)
}

// Run serves the embedded dashboard on IPv4 loopback until ctx is cancelled.
func Run(ctx context.Context, cfgPath string) error {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           Handler(cfgPath),
		ReadHeaderTimeout: 5 * time.Second,
	}
	serveErr := make(chan error, 1)
	go func() {
		err := server.Serve(listener)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serveErr <- err
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-serveErr:
		return err
	}
}
