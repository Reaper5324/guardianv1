// Package dashboard serves Guardian's bundled local operations dashboard.
package dashboard

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"guardian/internal/config"
	"guardian/internal/events"
)

const (
	address             = "127.0.0.1:8765"
	maxRequestBody      = 4096
	minimumPasswordSize = 12
	passwordIterations  = 310000
)

//go:embed web/*
var webFiles embed.FS

type status struct {
	Version            uint64            `json:"version"`
	ListenAddr         string            `json:"listen_addr"`
	DNSListenersReady  bool              `json:"dns_listeners_ready"`
	FirewallRuleCount  int               `json:"firewall_rule_count"`
	FirewallStatus     string            `json:"firewall_status,omitempty"`
	Adapters           []AdapterStatus   `json:"adapters"`
	Timezone           string            `json:"timezone"`
	UpstreamCount      int               `json:"upstream_count"`
	BlockedServices    []string          `json:"blocked_services"`
	BlockedDomainCount int               `json:"blocked_domain_count"`
	AllowedDomainCount int               `json:"allowed_domain_count"`
	BlockDoHProviders  bool              `json:"block_doh_providers"`
	RemoteEnabled      bool              `json:"remote_enabled"`
	SignatureRequired  bool              `json:"signature_required"`
	BedtimeEnabled     bool              `json:"bedtime_enabled"`
	BedtimeStart       string            `json:"bedtime_start,omitempty"`
	BedtimeEnd         string            `json:"bedtime_end,omitempty"`
	BedtimeActive      bool              `json:"bedtime_active"`
	UsingFallback      bool              `json:"using_fallback"`
	ServiceStartedAt   time.Time         `json:"service_started_at,omitempty"`
	LastRemoteSync     string            `json:"last_remote_sync,omitempty"`
	LastRemoteSyncAt   time.Time         `json:"last_remote_sync_at,omitempty"`
	LastDrift          string            `json:"last_drift,omitempty"`
	LastDriftAt        time.Time         `json:"last_drift_at,omitempty"`
	UpstreamHealth     string            `json:"upstream_health,omitempty"`
	BlockedToday       uint64            `json:"blocked_today"`
	BlockedByCategory  map[string]uint64 `json:"blocked_by_category"`
	RecentEvents       []activity        `json:"recent_events"`
	CanRepair          bool              `json:"can_repair"`
	CanUninstall       bool              `json:"can_uninstall"`
	ReadAt             time.Time         `json:"read_at"`
}

type AdapterStatus struct {
	Name    string   `json:"name"`
	Up      bool     `json:"up"`
	IPv4DNS []string `json:"ipv4_dns"`
	IPv6DNS []string `json:"ipv6_dns"`
}

type EnforcementStatus struct {
	Adapters          []AdapterStatus
	FirewallRuleCount int
}

type activity struct {
	Time        time.Time `json:"time"`
	Type        string    `json:"type"`
	Summary     string    `json:"summary"`
	RepeatCount uint64    `json:"repeat_count"`
}

type Options struct {
	StatusPath       string
	ParentAuthPath   string
	OnListening      func()
	Repair           func(context.Context) error
	Inspect          func(context.Context) (EnforcementStatus, error)
	RequestUninstall func() error
}

type passwordFile struct {
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}

// Handler returns a loopback-only read-only dashboard handler for cfgPath.
func Handler(cfgPath string) http.Handler {
	return HandlerWithOptions(cfgPath, Options{})
}

func HandlerWithOptions(cfgPath string, options Options) http.Handler {
	static, err := fs.Sub(webFiles, "web")
	if err != nil {
		panic(err)
	}
	mux := http.NewServeMux()
	throttle := &passwordThrottle{}
	repairGate := &operationGate{minimumInterval: 10 * time.Second}
	inspection := &enforcementCache{}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if !validRequest(r, http.MethodGet) {
			rejectRequest(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		if !validRequest(r, http.MethodGet) {
			rejectRequest(w, r)
			return
		}
		cfg, fallback, err := config.LoadWithFallback(cfgPath)
		if err != nil {
			http.Error(w, "configuration unavailable", http.StatusServiceUnavailable)
			return
		}
		statusPath := options.StatusPath
		if statusPath == "" {
			statusPath = filepath.Join(filepath.Dir(cfgPath), "status.json")
		}
		statusStore, err := events.OpenStatus(statusPath)
		if err != nil {
			http.Error(w, "runtime status unavailable", http.StatusServiceUnavailable)
			return
		}
		runtimeStatus := statusStore.Snapshot()
		todayCounts := runtimeStatus.BlockedHitsPerDay[time.Now().Format("2006-01-02")]
		if todayCounts == nil {
			todayCounts = map[string]uint64{}
		}
		recent := make([]activity, 0, 12)
		first := len(runtimeStatus.Events) - cap(recent)
		if first < 0 {
			first = 0
		}
		for _, event := range runtimeStatus.Events[first:] {
			recent = append(recent, summarize(event))
		}
		now := time.Now()
		data := status{
			Version:            cfg.Version,
			ListenAddr:         cfg.ListenAddr,
			DNSListenersReady:  dnsListenersReady(cfg.ListenAddr),
			Timezone:           cfg.Timezone,
			UpstreamCount:      len(cfg.UpstreamDoH),
			BlockedServices:    append([]string(nil), cfg.BlockedServices...),
			BlockedDomainCount: len(cfg.BlockedDomains),
			AllowedDomainCount: len(cfg.AllowedDomains),
			BlockDoHProviders:  cfg.BlockDoHProviders,
			RemoteEnabled:      cfg.Remote != nil && cfg.Remote.Enabled,
			SignatureRequired:  cfg.Remote != nil && cfg.Remote.Enabled && cfg.Remote.RequireSignature,
			BedtimeEnabled:     cfg.Bedtime != nil,
			UsingFallback:      fallback,
			ServiceStartedAt:   runtimeStatus.ServiceStartedAt,
			LastRemoteSync:     runtimeStatus.LastRemoteSync.Result,
			LastRemoteSyncAt:   runtimeStatus.LastRemoteSync.Time,
			LastDrift:          runtimeStatus.LastDrift.Description,
			LastDriftAt:        runtimeStatus.LastDrift.Time,
			UpstreamHealth:     runtimeStatus.UpstreamHealth,
			BlockedByCategory:  todayCounts,
			RecentEvents:       recent,
			CanRepair:          options.Repair != nil,
			CanUninstall:       options.RequestUninstall != nil && options.ParentAuthPath != "",
			ReadAt:             now,
			Adapters:           []AdapterStatus{},
		}
		if options.Inspect != nil {
			enforcement, inspectErr := inspection.get(r.Context(), options.Inspect)
			if inspectErr != nil {
				data.FirewallStatus = "Inspection failed"
			} else {
				data.Adapters = enforcement.Adapters
				data.FirewallRuleCount = enforcement.FirewallRuleCount
				if enforcement.FirewallRuleCount > 0 {
					data.FirewallStatus = "Rules active"
				} else {
					data.FirewallStatus = "No Guardian rules found"
				}
			}
		} else {
			data.FirewallStatus = "Windows service inspection unavailable"
		}
		for _, count := range todayCounts {
			data.BlockedToday += count
		}
		if cfg.Bedtime != nil {
			data.BedtimeStart = cfg.Bedtime.Start
			data.BedtimeEnd = cfg.Bedtime.End
			data.BedtimeActive = cfg.InBedtime(now)
		}
		writeJSON(w, http.StatusOK, data)
	})
	mux.HandleFunc("/api/repair", func(w http.ResponseWriter, r *http.Request) {
		if !validRequest(r, http.MethodPost) {
			rejectRequest(w, r)
			return
		}
		if options.Repair == nil {
			http.Error(w, "repair is unavailable in this dashboard", http.StatusServiceUnavailable)
			return
		}
		if !repairGate.acquire() {
			http.Error(w, "repair is already running or was run recently", http.StatusTooManyRequests)
			return
		}
		defer repairGate.release()
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()
		if err := options.Repair(ctx); err != nil {
			http.Error(w, "repair failed", http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"result": "repair completed"})
	})
	mux.HandleFunc("/api/uninstall", func(w http.ResponseWriter, r *http.Request) {
		if !validRequest(r, http.MethodPost) {
			rejectRequest(w, r)
			return
		}
		if options.RequestUninstall == nil || options.ParentAuthPath == "" {
			http.Error(w, "uninstall is unavailable in this dashboard", http.StatusServiceUnavailable)
			return
		}
		if !throttle.allow() {
			http.Error(w, "too many password attempts; try again later", http.StatusTooManyRequests)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		var request struct {
			Password string `json:"password"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil ||
			len(request.Password) < minimumPasswordSize || len(request.Password) > 1024 {
			throttle.fail()
			http.Error(w, "invalid parent password", http.StatusUnauthorized)
			return
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			throttle.fail()
			http.Error(w, "invalid parent password", http.StatusUnauthorized)
			return
		}
		if err := VerifyParentPassword(options.ParentAuthPath, request.Password); err != nil {
			throttle.fail()
			http.Error(w, "invalid parent password", http.StatusUnauthorized)
			return
		}
		throttle.succeed()
		if err := options.RequestUninstall(); err != nil {
			http.Error(w, "could not request uninstall", http.StatusServiceUnavailable)
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"result": "uninstall requested"})
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
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		_, _ = w.Write(content)
	})
	return mux
}

func validRequest(r *http.Request, method string) bool {
	if !allowedHost(r.Host) || r.Method != method {
		return false
	}
	return method != http.MethodPost || r.Header.Get("Origin") == "http://"+address
}

func rejectRequest(w http.ResponseWriter, r *http.Request) {
	if !allowedHost(r.Host) {
		http.Error(w, "invalid host", http.StatusMisdirectedRequest)
		return
	}
	w.Header().Set("Allow", http.MethodGet)
	http.Error(w, "method or origin not allowed", http.StatusMethodNotAllowed)
}

func writeJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func dnsListenersReady(configuredAddress string) bool {
	_, port, err := net.SplitHostPort(configuredAddress)
	if err != nil {
		return false
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 150*time.Millisecond)
		if err != nil {
			return false
		}
		_ = conn.Close()
	}
	return true
}

func summarize(event events.Event) activity {
	summary := "Guardian activity"
	switch event.Type {
	case "service-started":
		summary = "Guardian service started"
	case "drift-repaired":
		summary = "Enforcement reconciled"
	case "remote-sync":
		summary = "Remote configuration sync updated"
		if strings.HasPrefix(event.Message, "failed:") {
			summary = "Remote configuration sync failed"
		} else if strings.Contains(event.Message, "unchanged") {
			summary = "Remote configuration is up to date"
		}
	case "remote-sync-failed":
		summary = "Remote configuration sync failed"
	case "config-applied":
		version := strings.TrimPrefix(event.Message, "version=")
		if _, err := strconv.ParseUint(version, 10, 64); err == nil {
			summary = "Configuration version " + version + " applied"
		} else {
			summary = "Configuration updated"
		}
	case "config-rejected":
		summary = "Configuration update rejected"
	case "upstream-health":
		if event.Message == "healthy" {
			summary = "DNS upstreams are reachable"
		} else {
			summary = "DNS upstreams are unreachable"
		}
	case "blocked-hit-count":
		summary = "Blocked requests counted: " + event.Category
	case "events-dropped":
		summary = "Some local activity records were dropped"
	}
	return activity{Time: event.Time, Type: event.Type, Summary: summary, RepeatCount: event.RepeatCount}
}

type passwordThrottle struct {
	mu           sync.Mutex
	failures     int
	blockedUntil time.Time
}

type operationGate struct {
	mu              sync.Mutex
	minimumInterval time.Duration
	lastStarted     time.Time
	inFlight        bool
}

func (g *operationGate) acquire() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.inFlight || !g.lastStarted.IsZero() && now.Sub(g.lastStarted) < g.minimumInterval {
		return false
	}
	g.inFlight = true
	g.lastStarted = now
	return true
}

func (g *operationGate) release() {
	g.mu.Lock()
	g.inFlight = false
	g.mu.Unlock()
}

type enforcementCache struct {
	mu        sync.Mutex
	value     EnforcementStatus
	err       error
	refreshed time.Time
}

func (c *enforcementCache) get(ctx context.Context, inspect func(context.Context) (EnforcementStatus, error)) (EnforcementStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.refreshed) < 5*time.Second {
		return c.value, c.err
	}
	inspectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c.value, c.err = inspect(inspectCtx)
	c.refreshed = time.Now()
	return c.value, c.err
}

func (t *passwordThrottle) allow() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return time.Now().After(t.blockedUntil)
}

func (t *passwordThrottle) fail() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failures++
	if t.failures >= 5 {
		t.blockedUntil = time.Now().Add(time.Minute)
		t.failures = 0
	}
}

func (t *passwordThrottle) succeed() {
	t.mu.Lock()
	t.failures = 0
	t.blockedUntil = time.Time{}
	t.mu.Unlock()
}

func allowedHost(host string) bool {
	return strings.EqualFold(host, address)
}

// SetParentPassword creates the protected password verifier file without
// storing the password itself.
func SetParentPassword(path, password string) error {
	if path == "" || len(password) < minimumPasswordSize || len(password) > 1024 {
		return fmt.Errorf("parent password must be between %d and 1024 bytes", minimumPasswordSize)
	}
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate password salt: %w", err)
	}
	record := passwordFile{
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Hash:       base64.StdEncoding.EncodeToString(derivePassword(password, salt, passwordIterations)),
		Iterations: passwordIterations,
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode password verifier: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create password verifier directory: %w", err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create password verifier: %w", err)
	}
	if _, err := file.Write(append(raw, '\n')); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("write password verifier: %w", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(path)
		return fmt.Errorf("sync password verifier: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("close password verifier: %w", err)
	}
	return nil
}

// VerifyParentPassword checks a candidate against the verifier file.
func VerifyParentPassword(path, password string) error {
	if len(password) < minimumPasswordSize || len(password) > 1024 {
		return errors.New("invalid parent password")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read parent password verifier: %w", err)
	}
	var record passwordFile
	if err := json.Unmarshal(raw, &record); err != nil {
		return errors.New("parent password verifier is invalid")
	}
	salt, saltErr := base64.StdEncoding.DecodeString(record.Salt)
	expected, hashErr := base64.StdEncoding.DecodeString(record.Hash)
	if saltErr != nil || hashErr != nil || len(salt) != 32 || len(expected) != sha256.Size ||
		record.Iterations < 100000 || record.Iterations > 1000000 {
		return errors.New("parent password verifier is invalid")
	}
	actual := derivePassword(password, salt, record.Iterations)
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return errors.New("invalid parent password")
	}
	return nil
}

func derivePassword(password string, salt []byte, iterations int) []byte {
	key := []byte(password)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(salt)
	_, _ = mac.Write([]byte{0, 0, 0, 1})
	value := mac.Sum(nil)
	result := append([]byte(nil), value...)
	for i := 1; i < iterations; i++ {
		mac.Reset()
		_, _ = mac.Write(value)
		value = mac.Sum(value[:0])
		for j := range result {
			result[j] ^= value[j]
		}
	}
	return result
}

// Run serves the embedded dashboard on IPv4 loopback until ctx is cancelled.
func Run(ctx context.Context, cfgPath string) error {
	return RunWithOptions(ctx, cfgPath, Options{})
}

func RunWithOptions(ctx context.Context, cfgPath string, options Options) error {
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		return err
	}
	server := &http.Server{
		Handler:           HandlerWithOptions(cfgPath, options),
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
	if options.OnListening != nil {
		options.OnListening()
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-serveErr:
		return err
	}
}
