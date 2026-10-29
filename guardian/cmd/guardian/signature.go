package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"guardian/internal/config"
)

func generateSigningKeypair(args []string) error {
	flags := flag.NewFlagSet("keygen", flag.ContinueOnError)
	privatePath := flags.String("private", "guardian-config-private.key", "output path for the private signing key")
	publicPath := flags.String("public", "guardian-config-public.key", "output path for the public verification key")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *privatePath == "" || *publicPath == "" || filepath.Clean(*privatePath) == filepath.Clean(*publicPath) {
		return errors.New("private and public key paths must be non-empty and different")
	}
	for _, path := range []string{*privatePath, *publicPath} {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("refusing to overwrite existing key file %q", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("check key path %q: %w", path, err)
		}
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate Ed25519 keypair: %w", err)
	}
	privateData := []byte(base64.StdEncoding.EncodeToString(privateKey) + "\n")
	publicData := []byte(base64.StdEncoding.EncodeToString(publicKey) + "\n")
	if err := writeNewPrivateFile(*privatePath, privateData); err != nil {
		return fmt.Errorf("write private signing key: %w", err)
	}
	if err := writeNewPrivateFile(*publicPath, publicData); err != nil {
		if removeErr := os.Remove(*privatePath); removeErr != nil {
			return errors.Join(fmt.Errorf("write public verification key: %w", err), fmt.Errorf("remove partial private key: %w", removeErr))
		}
		return fmt.Errorf("write public verification key: %w", err)
	}
	fmt.Printf("Generated signing keys.\n  private key (keep secret): %s\n  public key: %s\n", *privatePath, *publicPath)
	return nil
}

func signConfig(args []string) error {
	flags := flag.NewFlagSet("sign", flag.ContinueOnError)
	configPath := flags.String("config", "", "config file to sign")
	privatePath := flags.String("key", "", "base64 Ed25519 private key")
	outputPath := flags.String("out", "", "output signature file")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *configPath == "" || *privatePath == "" || *outputPath == "" {
		return errors.New("sign requires -config, -key, and -out")
	}
	body, err := os.ReadFile(*configPath)
	if err != nil {
		return fmt.Errorf("read config file: %w", err)
	}
	if _, err := config.Parse(body); err != nil {
		return fmt.Errorf("refuse to sign invalid config: %w", err)
	}
	rawKey, err := os.ReadFile(*privatePath)
	if err != nil {
		return fmt.Errorf("read private signing key: %w", err)
	}
	privateKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(rawKey)))
	if err != nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("private key file must contain a base64 Ed25519 private key")
	}
	signature := ed25519.Sign(ed25519.PrivateKey(privateKey), body)
	data := []byte(base64.StdEncoding.EncodeToString(signature) + "\n")
	if err := writeNewPrivateFile(*outputPath, data); err != nil {
		return fmt.Errorf("write signature file: %w", err)
	}
	fmt.Printf("Wrote detached config signature to %s\n", *outputPath)
	return nil
}

func writeNewPrivateFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".guardian-key-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("refusing to overwrite existing file %q", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(tmpPath, path)
}
