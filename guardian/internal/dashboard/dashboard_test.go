package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDashboardServesEmbeddedAssets(t *testing.T) {
	handler := Handler(filepath.Join(t.TempDir(), "config.json"))
	for _, path := range []string{"/", "/app.css", "/app.js"} {
		t.Run(path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765"+path, nil)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", w.Code)
			}
			if w.Body.Len() == 0 {
				t.Fatal("embedded asset was empty")
			}
			if got := w.Header().Get("Content-Security-Policy"); got == "" {
				t.Fatal("missing content security policy")
			}
		})
	}
}

func TestStatusReturnsCountsWithoutDomainNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	raw := `{"version":4,"listen_addr":"127.0.0.1:5353","blocked_services":["instagram"],"blocked_domains":["secret.example"],"allowed_domains":["private.example"]}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	handler := Handler(path)
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765/api/status", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["version"] != float64(4) || got["blocked_domain_count"] != float64(1) || got["allowed_domain_count"] != float64(1) {
		t.Fatalf("unexpected summary: %#v", got)
	}
	if strings.Contains(w.Body.String(), "secret.example") || strings.Contains(w.Body.String(), "private.example") {
		t.Fatal("status exposed configured domain names")
	}
	if got := w.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
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
			r := httptest.NewRequest(test.method, "http://"+test.host+test.path, nil)
			r.Host = test.host
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != test.want {
				t.Fatalf("status = %d, want %d", w.Code, test.want)
			}
		})
	}
}

func TestStatusFailsWithoutValidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8765/api/status", nil)
	w := httptest.NewRecorder()
	Handler(path).ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if strings.Contains(w.Body.String(), path) {
		t.Fatal("error response leaked the config file path")
	}
}
