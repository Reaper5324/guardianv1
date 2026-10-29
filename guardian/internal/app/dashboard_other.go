//go:build !windows

package app

import "context"

func runDashboard(ctx context.Context, _ string, _ func() error) error {
	<-ctx.Done()
	return nil
}
