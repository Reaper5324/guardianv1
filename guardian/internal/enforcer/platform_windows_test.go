//go:build windows

package enforcer

import (
	"context"
	"strings"
	"testing"
)

func TestWindowsPlatformRunKeepsWarningsOutOfJSONOutput(t *testing.T) {
	platform := &WindowsPlatform{Runner: execCommandRunner{}, StateDir: t.TempDir()}
	output, err := platform.run(context.Background(), `Write-Warning 'diagnostic'; Write-Output '{"ok":true}'`, nil)
	if err != nil {
		t.Fatalf("run PowerShell script: %v", err)
	}
	if got, want := strings.TrimSpace(string(output)), `{"ok":true}`; got != want {
		t.Fatalf("PowerShell output = %q, want %q", got, want)
	}
}

func TestWindowsPlatformRunReturnsPowerShellErrors(t *testing.T) {
	platform := &WindowsPlatform{Runner: execCommandRunner{}, StateDir: t.TempDir()}
	_, err := platform.run(context.Background(), `throw 'script failure'`, nil)
	if err == nil {
		t.Fatal("expected PowerShell script error")
	}
	if !strings.Contains(err.Error(), "script failure") {
		t.Fatalf("error %q does not include script failure", err)
	}
}
