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

	func showStatus() error {
		return errors.New("status is only supported on Windows")
	}

	func showEvents(int) error {
		return errors.New("events are only supported on Windows")
	}

	func repairService() error {
		return errors.New("repair is only supported on Windows")
		}
		