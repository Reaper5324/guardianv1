//go:build windows

package app

import (
	"context"
	"time"

	"guardian/internal/config"
	"guardian/internal/enforcer"
)

func runEnforcement(ctx context.Context, getConfig func() *config.Config, stateDir string, emit func(string)) error {
	reconciler, err := enforcer.NewWindowsReconciler(stateDir, emit)
	if err != nil {
		return err
	}
	return reconciler.Run(ctx, getConfig, 10*time.Second)
}
