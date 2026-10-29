package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, path, raw string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadWithFallbackSavesValidPrimary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeTestConfig(t, path, `{"version":3,"blocked_domains":["new.example"]}`)

	cfg, usedFallback, err := LoadWithFallback(path)
	if err != nil {
		t.Fatal(err)
	}
	if usedFallback {
		t.Fatal("used fallback for valid primary config")
	}
	if cfg.Version != 3 {
		t.Fatalf("version = %d, want 3", cfg.Version)
	}
	backup, err := Load(path + ".last-good.json")
	if err != nil {
		t.Fatalf("load saved backup: %v", err)
	}
	if backup.Version != 3 {
		t.Fatalf("backup version = %d, want 3", backup.Version)
	}
}

func TestLoadWithFallbackUsesBackupForInvalidPrimary(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeTestConfig(t, path, `{"version":5,"blocked_domains":["good.example"]}`)
	if _, _, err := LoadWithFallback(path); err != nil {
		t.Fatal(err)
	}
	writeTestConfig(t, path, `{"version":99,"blocked_domains":["bad domain.example"]}`)

	cfg, usedFallback, err := LoadWithFallback(path)
	if err != nil {
		t.Fatal(err)
	}
	if !usedFallback || cfg.Version != 5 || len(cfg.BlockedDomains) != 1 || cfg.BlockedDomains[0] != "good.example" {
		t.Fatalf("fallback = (%+v, %v), want known-good version 5", cfg, usedFallback)
	}
	backup, err := Load(path + ".last-good.json")
	if err != nil {
		t.Fatal(err)
	}
	if backup.Version != 5 {
		t.Fatalf("invalid primary replaced backup: backup version = %d", backup.Version)
	}
}

func TestLoadWithFallbackRejectsVersionDowngrade(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeTestConfig(t, path, `{"version":8}`)
	if _, _, err := LoadWithFallback(path); err != nil {
		t.Fatal(err)
	}
	writeTestConfig(t, path, `{"version":7}`)

	cfg, usedFallback, err := LoadWithFallback(path)
	if err != nil {
		t.Fatal(err)
	}
	if !usedFallback || cfg.Version != 8 {
		t.Fatalf("fallback = (%+v, %v), want version 8", cfg, usedFallback)
	}
}

func TestLoadWithFallbackFailsIfBothConfigsAreInvalid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	writeTestConfig(t, path, `not json`)
	writeTestConfig(t, path+".last-good.json", `also not json`)
	if _, _, err := LoadWithFallback(path); err == nil {
		t.Fatal("LoadWithFallback succeeded with invalid primary and backup")
	}
}
