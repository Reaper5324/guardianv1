//go:build !windows

package main

import "errors"

// Service support is Windows only; these stubs keep `go run` working
// elsewhere for development.

func isService() bool { return false }
func runService()     {}

func installService(string) error {
	return errors.New("install is only supported on Windows")
	}

	func uninstallService() error {
		return errors.New("uninstall is only supported on Windows")
		}
		