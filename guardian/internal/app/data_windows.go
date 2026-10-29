//go:build windows

package app

import (
	"os"
	"path/filepath"
)

func dataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Guardian")
}
