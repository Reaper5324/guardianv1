//go:build !windows

package app

import (
	"context"

	"guardian/internal/config"
)

func runEnforcement(ctx context.Context, _ func() *config.Config, _ string, _ func(string)) error {
	<-ctx.Done()
	return nil
}
