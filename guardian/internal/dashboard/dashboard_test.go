package dashboard

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"guardian/internal/events"
)

func TestDashboardServesEmbeddedAssets(t *testing.T) {
	handler := Handler(filepath.Join(t.TempDir(), "config.json"))
	for _, path := range []string{"/", "/app.css", "/app.js"} {
		t.Run(path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765"+path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", response.Code)
			}
			if response.Body.Len() == 0 {
				t.Fatal("embedded asset was empty")
			}
			if got := response.Header().Get("Content-Security-Policy"); got == "" {
				t.Fatal("missing content security policy")
			}
		})
	}
}

func TestRunWithOptionsServesHealthAndStops(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1,"listen_addr":"127.0.0.1:5353","upstream_doh":["https://1.1.1.1/dns-query"],"timezone":"UTC"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listening := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- RunWithOptions(ctx, cfgPath, Options{OnListening: func() { close(listening) }})
	}()
	select {
	case <-listening:
	case err := <-done:
		t.Fatalf("dashboard failed to listen: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("dashboard did not start listening")
	}
	response, err := (&http.Client{Timeout: time.Second}).Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatalf("request dashboard health: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("health status = %d, want 204", response.StatusCode)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("dashboard shutdown: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("dashboard did not stop after cancellation")
	}
}

func TestStatusReturnsCountsWithoutDomainNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{"version":4,"listen_addr":"127.0.0.1:5353","upstream_doh":["https://1.1.1.1/dns-query"],"blocked_services":["instagram"],"blocked_domains":["secret.example"],"allowed_domains":["private.example"],"timezone":"UTC"}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765/api/status", nil)
	response := httptest.NewRecorder()
	Handler(path).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["version"] != float64(4) || got["blocked_domain_count"] != float64(1) || got["allowed_domain_count"] != float64(1) {
		t.Fatalf("unexpected summary: %#v", got)
	}
	if strings.Contains(response.Body.String(), "secret.example") || strings.Contains(response.Body.String(), "private.example") {
		t.Fatal("status exposed configured domain names")
	}
	if got := response.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestDashboardReportsRuntimeStatusWithoutDomainHistory(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	raw := `{"version":4,"listen_addr":"127.0.0.1:5353","upstream_doh":["https://1.1.1.1/dns-query"],"blocked_services":["instagram"],"blocked_domains":["secret.example"],"allowed_domains":["private.example"],"block_doh_providers":true,"timezone":"UTC","remote":{"enabled":true,"owner":"owner","repository":"repo","branch":"main","path":"config.json","require_signature":true}}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	statusStore, err := events.OpenStatus(filepath.Join(dir, "status.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := statusStore.SetServiceStartedAt(time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	hub, err := events.NewHub(statusStore, time.Millisecond, &events.MemorySink{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- hub.Run(ctx) }()
	hub.Record(events.Event{Type: "blocked-hit-count", Category: "instagram", RepeatCount: 7})
	hub.Record(events.Event{Type: "config-rejected", Message: "private.example was rejected"})
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765/api/status", nil)
	response := httptest.NewRecorder()
	Handler(cfgPath).ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", response.Code, response.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["blocked_today"] != float64(7) || got["remote_enabled"] != true || got["signature_required"] != true {
		t.Fatalf("unexpected runtime status: %#v", got)
	}
	if strings.Contains(response.Body.String(), "secret.example") || strings.Contains(response.Body.String(), "private.example") {
		t.Fatal("dashboard exposed domain history")
	}
}

func TestDashboardRepairRequiresSameOriginAndRunsCallback(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1,"listen_addr":"127.0.0.1:5353","upstream_doh":["https://1.1.1.1/dns-query"],"timezone":"UTC"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	handler := HandlerWithOptions(cfgPath, Options{
		Repair: func(context.Context) error {
			calls++
			return nil
		},
	})
	for _, test := range []struct {
		name   string
		origin string
		want   int
	}{
		{name: "foreign origin", origin: "http://evil.example", want: http.StatusMethodNotAllowed},
		{name: "same origin", origin: "http://" + address, want: http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "http://"+address+"/api/repair", nil)
			request.Header.Set("Origin", test.origin)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
	if calls != 1 {
		t.Fatalf("repair callback calls = %d, want 1", calls)
	}
}

func TestOperationGateLimitsRepeatedRepairRequests(t *testing.T) {
	gate := &operationGate{minimumInterval: time.Hour}
	if !gate.acquire() {
		t.Fatal("first operation was rejected")
	}
	if gate.acquire() {
		t.Fatal("concurrent operation was accepted")
	}
	gate.release()
	if gate.acquire() {
		t.Fatal("operation inside cooldown was accepted")
	}
}

func TestParentPasswordVerifierAndUninstallEndpoint(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(cfgPath, []byte(`{"version":1,"listen_addr":"127.0.0.1:5353","upstream_doh":["https://1.1.1.1/dns-query"],"timezone":"UTC"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	authPath := filepath.Join(dir, "parent-auth.json")
	password := "correct horse battery staple"
	if err := SetParentPassword(authPath, password); err != nil {
		t.Fatal(err)
	}
	if err := VerifyParentPassword(authPath, password); err != nil {
		t.Fatalf("valid password rejected: %v", err)
	}
	if err := VerifyParentPassword(authPath, "wrong horse battery staple"); err == nil {
		t.Fatal("invalid password accepted")
	}
	raw, err := os.ReadFile(authPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(password)) {
		t.Fatal("verifier file contains the plaintext password")
	}
	if err := SetParentPassword(authPath, password); err == nil {
		t.Fatal("password setup overwrote an existing verifier")
	}

	requested := false
	handler := HandlerWithOptions(cfgPath, Options{
		ParentAuthPath: authPath,
		RequestUninstall: func() error {
			requested = true
			return nil
		},
	})
	post := func(candidate string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"password": candidate})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "http://"+address+"/api/uninstall", bytes.NewReader(body))
		request.Header.Set("Origin", "http://"+address)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if response := post("wrong horse battery staple"); response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want 401", response.Code)
	}
	if requested {
		t.Fatal("wrong password triggered uninstall")
	}
	if response := post(password); response.Code != http.StatusAccepted {
		t.Fatalf("valid password status = %d, want 202: %s", response.Code, response.Body.String())
	}
	if !requested {
		t.Fatal("valid password did not request uninstall")
	}
}

func TestPasswordDerivationMatchesPBKDF2SHA256Vector(t *testing.T) {
	got := hex.EncodeToString(derivePassword("password", []byte("salt"), 1))
	const want = "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
	if got != want {
		t.Fatalf("derived key = %s, want %s", got, want)
	}
}

func TestDashboardRejectsUnexpectedHostAndWriteMethods(t *testing.T) {
	handler := Handler(filepath.Join(t.TempDir(), "missing.json"))
	for _, test := range []struct {
		name   string
		method string
		host   string
		path   string
		want   int
	}{
		{"foreign host", http.MethodGet, "evil.example", "/api/status", http.StatusMisdirectedRequest},
		{"post status", http.MethodPost, address, "/api/status", http.StatusMethodNotAllowed},
		{"post root", http.MethodPost, address, "/", http.StatusMethodNotAllowed},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, "http://"+test.host+test.path, nil)
			request.Host = test.host
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status = %d, want %d", response.Code, test.want)
			}
		})
	}
}

func TestStatusFailsWithoutValidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765/api/status", nil)
	response := httptest.NewRecorder()
	Handler(path).ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", response.Code)
	}
	if strings.Contains(response.Body.String(), path) {
		t.Fatal("error response leaked the config file path")
	}
}
