//go:build !windows

package events

import (
	"context"
	"errors"
)

func OpenWindowsEventLog() (*WindowsEventSink, error) {
	return nil, errors.New("Windows Event Log is only available on Windows")
}

func InstallWindowsEventLog() error {
	return errors.New("Windows Event Log is only available on Windows")
}

func RemoveWindowsEventLog() error {
	return errors.New("Windows Event Log is only available on Windows")
}

type WindowsEventSink struct{}

func (*WindowsEventSink) Emit(_ context.Context, _ Event) error {
	return errors.New("Windows Event Log is only available on Windows")
}

func (*WindowsEventSink) Close() error { return nil }
