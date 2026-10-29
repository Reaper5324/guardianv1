package remote

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"guardian/internal/config"
	"guardian/internal/dnsproxy"
	"guardian/internal/events"
)

func TestPollOnceAppliesConfigAtomicallyAndUsesETag(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	initial := remoteTestConfig(1, false)
	if err := config.SaveLastKnownGood(configPath, initial); err != nil {
		t.Fatal(err)
	}
	store := &config.Store{}
	if err := store.Set(initial); err != nil {
		t.Fatal(err)
	}
	proxy, err := dnsproxy.New(store)
	if err != nil {
		t.Fatal(err)
	}
	remoteBody := remoteConfigJSON(t, remoteTestConfig(2, false), []string{"new-block.example"})
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "Bearer github_test_token" {
			t.Errorf("authorization header = %q", got)
		}
		if r.Header.Get("If-None-Match") == `"revision-2"` {
			w.Header().Set("ETag", `"revision-2"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"revision-2"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(remoteBody)
	}))
	defer server.Close()
	tokenPath := filepath.Join(dir, "github-token.txt")
	if err := os.WriteFile(tokenPath, []byte("github_test_token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	poller := makeTestPoller(store, proxy, configPath, tokenPath, server.URL)
	var recorded []events.Event
	poller.Emit = func(event events.Event) { recorded = append(recorded, event) }

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := store.Get().Version; got != 2 {
		t.Fatalf("active version = %d, want 2", got)
	}
	active := proxyCurrentConfig(t, proxy)
	if len(active.BlockedDomains) != 1 || active.BlockedDomains[0] != "new-block.example" {
		t.Fatalf("proxy config was not atomically updated: %+v", active.BlockedDomains)
	}
	persisted, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := config.Load(configPath + ".last-good.json")
	if err != nil {
		t.Fatal(err)
	}
	if persisted.Version != 2 || backup.Version != 2 {
		t.Fatalf("persisted versions: main=%d backup=%d", persisted.Version, backup.Version)
	}

	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("request count = %d, want 2", requests)
	}
	if store.Get().Version != 2 {
		t.Fatal("304 response changed active config")
	}
	if len(recorded) != 3 || recorded[0].Type != "config-applied" {
		t.Fatalf("unexpected events: %+v", recorded)
	}
}

func TestPollOnceRejectsInvalidAndDowngradedConfig(t *testing.T) {
	for _, test := range []struct {
		name string
		body []byte
	}{
		{name: "invalid json", body: []byte(`{"version":99,"unknown":true}`)},
		{name: "downgrade", body: []byte(`{"version":1,"timezone":"UTC"}`)},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			configPath := filepath.Join(dir, "config.json")
			initial := remoteTestConfig(2, false)
			if err := config.SaveLastKnownGood(configPath, initial); err != nil {
				t.Fatal(err)
			}
			store := &config.Store{}
			if err := store.Set(initial); err != nil {
				t.Fatal(err)
			}
			proxy, err := dnsproxy.New(store)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(test.body)
			}))
			defer server.Close()
			tokenPath := filepath.Join(dir, "github-token.txt")
			if err := os.WriteFile(tokenPath, []byte("github_test_token"), 0o600); err != nil {
				t.Fatal(err)
			}
			poller := makeTestPoller(store, proxy, configPath, tokenPath, server.URL)
			var recorded []events.Event
			poller.Emit = func(event events.Event) { recorded = append(recorded, event) }
			if err := poller.PollOnce(context.Background()); err == nil {
				t.Fatal("PollOnce accepted invalid config")
			}
			if store.Get().Version != 2 {
				t.Fatalf("active config changed to version %d", store.Get().Version)
			}
			persisted, err := config.Load(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if persisted.Version != 2 {
				t.Fatalf("main config version = %d, want unchanged version 2", persisted.Version)
			}
			if len(recorded) != 3 || recorded[0].Type != "config-rejected" {
				t.Fatalf("unexpected rejection events: %+v", recorded)
			}
			for _, event := range recorded {
				if strings.Contains(event.Message, "github_test_token") {
					t.Fatal("event leaked the token")
				}
			}
		})
	}
}

func TestPollOnceVerifiesEd25519Signature(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")
	initial := remoteTestConfig(1, true)
	if err := config.SaveLastKnownGood(configPath, initial); err != nil {
		t.Fatal(err)
	}
	store := &config.Store{}
	if err := store.Set(initial); err != nil {
		t.Fatal(err)
	}
	proxy, err := dnsproxy.New(store)
	if err != nil {
		t.Fatal(err)
	}
	body := remoteConfigJSON(t, remoteTestConfig(2, true), []string{"signed.example"})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signature := base64.StdEncoding.EncodeToString(ed25519.Sign(private, body))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			_, _ = w.Write([]byte(signature))
		} else {
			_, _ = w.Write(body)
		}
	}))
	defer server.Close()
	tokenPath := filepath.Join(dir, "github-token.txt")
	keyPath := filepath.Join(dir, "config-public.key")
	if err := os.WriteFile(tokenPath, []byte("github_test_token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte(base64.StdEncoding.EncodeToString(public)), 0o600); err != nil {
		t.Fatal(err)
	}
	poller := makeTestPoller(store, proxy, configPath, tokenPath, server.URL)
	poller.PublicKeyPath = keyPath
	if err := poller.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if store.Get().Version != 2 {
		t.Fatalf("active version = %d, want 2", store.Get().Version)
	}
}

func remoteTestConfig(version uint64, signature bool) *config.Config {
	cfg := config.Default()
	cfg.ListenAddr = "127.0.0.1:53"
	cfg.Version = version
	cfg.BlockDoHProviders = false
	cfg.Timezone = "UTC"
	cfg.Remote = &config.RemoteSource{
		Enabled:          true,
		Owner:            "parent",
		Repository:       "guardian-config",
		Branch:           "main",
		Path:             "settings/config.json",
		RequireSignature: signature,
	}
	return &cfg
}

func remoteConfigJSON(t *testing.T, cfg *config.Config, blocked []string) []byte {
	t.Helper()
	cfg.BlockedDomains = blocked
	body, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func makeTestPoller(store *config.Store, proxy *dnsproxy.Proxy, configPath, tokenPath, apiBase string) *Poller {
	return &Poller{
		Store:         store,
		Proxy:         proxy,
		ConfigPath:    configPath,
		TokenPath:     tokenPath,
		PublicKeyPath: filepath.Join(filepath.Dir(tokenPath), "config-public.key"),
		APIBase:       apiBase,
		Client:        &http.Client{Timeout: 2 * time.Second},
	}
}

func proxyCurrentConfig(t *testing.T, proxy *dnsproxy.Proxy) *config.Config {
	t.Helper()
	return proxy.CurrentConfig()
}
