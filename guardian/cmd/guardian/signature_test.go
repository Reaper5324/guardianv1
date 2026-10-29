package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateAndSignConfig(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "private.key")
	publicPath := filepath.Join(dir, "public.key")
	if err := generateSigningKeypair([]string{"-private", privatePath, "-public", publicPath}); err != nil {
		t.Fatal(err)
	}
	privateData, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicData, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(privateData)))
	if err != nil {
		t.Fatal(err)
	}
	publicKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(publicData)))
	if err != nil {
		t.Fatal(err)
	}
	if len(privateKey) != ed25519.PrivateKeySize || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("invalid key sizes: private=%d public=%d", len(privateKey), len(publicKey))
	}

	configPath := filepath.Join(dir, "config.json")
	configBody := []byte(`{"version":1,"timezone":"UTC"}`)
	if err := os.WriteFile(configPath, configBody, 0o600); err != nil {
		t.Fatal(err)
	}
	signaturePath := filepath.Join(dir, "config.json.sig")
	if err := signConfig([]string{"-config", configPath, "-key", privatePath, "-out", signaturePath}); err != nil {
		t.Fatal(err)
	}
	signatureData, err := os.ReadFile(signaturePath)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(signatureData)))
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), configBody, signature) {
		t.Fatal("generated signature did not verify")
	}
	if ed25519.Verify(ed25519.PublicKey(publicKey), append(configBody, ' '), signature) {
		t.Fatal("signature verified after config bytes changed")
	}
}
