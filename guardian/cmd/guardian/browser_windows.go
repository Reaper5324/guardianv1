//go:build windows

package main

import (
	"os/exec"
)

func openDashboardBrowser() error {
	return exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", "http://127.0.0.1:8765").Start()
}
