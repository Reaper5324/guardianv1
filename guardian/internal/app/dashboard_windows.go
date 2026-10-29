//go:build windows

package app

import (
	"context"
	"path/filepath"

	"guardian/internal/config"
	"guardian/internal/dashboard"
	"guardian/internal/enforcer"
)

func runDashboard(ctx context.Context, cfgPath string, requestUninstall func() error) error {
	stateDir := filepath.Dir(cfgPath)
	return dashboard.RunWithOptions(ctx, cfgPath, dashboard.Options{
		ParentAuthPath: filepath.Join(stateDir, "parent-auth.json"),
		Inspect: func(ctx context.Context) (dashboard.EnforcementStatus, error) {
			platform, err := enforcer.NewWindowsPlatform(stateDir)
			if err != nil {
				return dashboard.EnforcementStatus{}, err
			}
			adapters, err := platform.ListAdapters(ctx)
			if err != nil {
				return dashboard.EnforcementStatus{}, err
			}
			rules, err := platform.FirewallRuleNames(ctx)
			if err != nil {
				return dashboard.EnforcementStatus{}, err
			}
			result := dashboard.EnforcementStatus{FirewallRuleCount: len(rules)}
			for _, adapter := range adapters {
				result.Adapters = append(result.Adapters, dashboard.AdapterStatus{
					Name: adapter.Name, Up: adapter.Up,
					IPv4DNS: adapter.IPv4DNS, IPv6DNS: adapter.IPv6DNS,
				})
			}
			return result, nil
		},
		Repair: func(ctx context.Context) error {
			cfg, _, err := config.LoadWithFallback(cfgPath)
			if err != nil {
				return err
			}
			return enforcer.Repair(ctx, stateDir, cfg, nil)
		},
		RequestUninstall: requestUninstall,
	})
}
