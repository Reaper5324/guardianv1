//go:build !windows

package enforcer

import (
	"context"
	"errors"

	"guardian/internal/config"
)

func NewWindowsReconciler(string, EventFunc) (*Reconciler, error) {
	return nil, errors.New("Windows enforcement is only available on Windows")
}

func InstallWatchdog(context.Context, string) error {
	return errors.New("scheduled watchdog is only available on Windows")
}

func RemoveWatchdog(context.Context) error {
	return errors.New("scheduled watchdog is only available on Windows")
}

func SetServiceSecurityDescriptor(context.Context, string) error {
	return errors.New("service security descriptors are only available on Windows")
}

func Repair(context.Context, string, *config.Config, EventFunc) error {
	return errors.New("Windows enforcement is only available on Windows")
}

func Remove(context.Context, string) error {
	return errors.New("Windows enforcement is only available on Windows")
}
