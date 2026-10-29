package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildVersionReportsSourceRevision(t *testing.T) {
	version := buildVersion()
	if !strings.HasPrefix(version, "Guardian revision=") {
		t.Fatalf("build version %q does not include revision metadata", version)
	}
}

func TestValidateConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"listen_addr":"127.0.0.1:53","timezone":"UTC"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateConfig([]string{"-config", path}); err != nil {
		t.Fatalf("validate valid config: %v", err)
	}
}
