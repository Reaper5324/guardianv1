//go:build !windows

package main

import "errors"

func openDashboardBrowser() error {
	return errors.New("automatic browser launch is available only on Windows")
}
