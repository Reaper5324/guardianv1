package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadWithFallback loads path and keeps a last-known-good copy beside it. If
// the primary file is invalid, missing, or has an older version than the
// backup, the backup is returned instead. The backup is only replaced after
// the primary config has parsed and passed validation.
func LoadWithFallback(path string) (*Config, bool, error) {
	primary, primaryErr := Load(path)
	backupPath := path + ".last-good.json"
	backup, backupErr := Load(backupPath)

	if primaryErr == nil && (backupErr != nil || primary.Version >= backup.Version) {
		if err := SaveLastKnownGood(backupPath, primary); err != nil {
			return nil, false, fmt.Errorf("save last-known-good config: %w", err)
		}
		return primary, false, nil
	}
	if backupErr == nil {
		return backup, true, nil
	}
	if primaryErr != nil {
		return nil, false, fmt.Errorf("primary config: %w (last-known-good config: %v)", primaryErr, backupErr)
	}
	return nil, false, fmt.Errorf("primary config version %d is older than last-known-good version %d", primary.Version, backup.Version)
}

// SaveLastKnownGood atomically writes a validated config to path. Callers must
// validate the config before saving it.
func SaveLastKnownGood(path string, c *Config) error {
	if c == nil {
		return errors.New("config must not be nil")
	}
	validated := *c
	validated.UpstreamDoH = append([]string(nil), c.UpstreamDoH...)
	validated.BlockedServices = append([]string(nil), c.BlockedServices...)
	validated.BlockedDomains = append([]string(nil), c.BlockedDomains...)
	validated.AllowedDomains = append([]string(nil), c.AllowedDomains...)
	if c.Bedtime != nil {
		window := *c.Bedtime
		validated.Bedtime = &window
	}
	if c.Remote != nil {
		remote := *c.Remote
		validated.Remote = &remote
	}
	if err := validated.validate(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(&validated, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".guardian-config-*.tmp")
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
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	return nil
}
