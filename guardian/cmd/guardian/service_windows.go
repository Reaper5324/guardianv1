//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"guardian/internal/app"
	"guardian/internal/config"
	"guardian/internal/enforcer"
	"guardian/internal/events"
)

const (
	serviceName = "GuardianDNS"
	displayName = "Guardian DNS Filter"
)

// dataDir holds the live config and the log. Install locks it down to
// SYSTEM and Administrators only.
func dataDir() string {
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, "Guardian")
}

// isService reports whether the Service Control Manager launched us.
func isService() bool {
	ok, err := svc.IsWindowsService()
	return err == nil && ok
}

// runService is the entry point when launched by the SCM.
func runService() {
	cfgPath := parseConfig(os.Args[1:])

	if f, err := openLog(); err == nil {
		log.SetOutput(f)
		defer f.Close()
	} else {
		log.Printf("cannot open service log: %v", err)
	}
	if err := svc.Run(serviceName, &handler{cfgPath: cfgPath}); err != nil {
		log.Printf("service failed: %v", err)
		os.Exit(1)
	}
}

func openLog() (*os.File, error) {
	dir := dataDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, "guardian.log")
	if st, err := os.Stat(p); err == nil && st.Size() > 5<<20 {
		_ = os.Rename(p, p+".1") // simple rotation: keep one old log
	}
	return os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
}

type handler struct{ cfgPath string }

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, h.cfgPath) }()
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case err := <-done:
			// The proxy stopped on its own. A non-zero exit code makes the
			// recovery actions restart the service.
			if err != nil {
				log.Printf("guardian exited: %v", err)
				return false, 1
			}
			return false, 0
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				select {
				case <-done:
				case <-time.After(10 * time.Second):
				}
				return false, 0
			}
		}
	}
}

// installService copies the binary and config into protected locations,
// registers an auto-start service running as SYSTEM, and sets recovery
// actions so it restarts itself if it dies.
func installService(srcConfig string) (retErr error) {
	if _, err := config.Load(srcConfig); err != nil {
		return fmt.Errorf("config %s: %w", srcConfig, err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot reach the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		defer s.Close()
		return upgradeService(s, srcConfig)
	} else if !errors.Is(err, syscall.Errno(1060)) {
		return fmt.Errorf("check existing service: %w", err)
	}

	self, err := os.Executable()
	if err != nil {
		return err
	}
	progDir := filepath.Join(os.Getenv("ProgramFiles"), "Guardian")
	data := dataDir()
	exe := filepath.Join(progDir, "guardian.exe")
	dstCfg := filepath.Join(data, "config.json")

	for _, d := range []string{progDir, data} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	if err := lockDownPath(data); err != nil {
		return fmt.Errorf("secure ProgramData: %w", err)
	}
	if err := lockDownPath(progDir); err != nil {
		return fmt.Errorf("secure Program Files: %w", err)
	}
	stagedExe := exe + ".new"
	if err := copyFile(self, stagedExe, 0o755); err != nil {
		return fmt.Errorf("copy binary: %w", err)
	}
	if err := replaceFile(stagedExe, exe); err != nil {
		_ = os.Remove(stagedExe)
		return fmt.Errorf("publish binary: %w", err)
	}
	if _, err := os.Stat(dstCfg); os.IsNotExist(err) {
		if err := copyFile(srcConfig, dstCfg, 0o600); err != nil {
			return fmt.Errorf("copy config: %w", err)
		}
	}

	s, err := m.CreateService(serviceName, exe, mgr.Config{
		DisplayName: displayName,
		Description: "Local filtering DNS resolver (parental controls).",
		StartType:   mgr.StartAutomatic,
	}, "-config", dstCfg)
	if err != nil {
		return err
	}
	defer func() {
		_ = s.Close()
	}()
	installed := false
	defer func() {
		if !installed {
			stopErr := stopService(s)
			if stopErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("rollback stop service: %w", stopErr))
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if removeErr := enforcer.Remove(ctx, data); removeErr != nil {
				_ = s.Start()
				retErr = errors.Join(retErr, fmt.Errorf("rollback enforcement: %w; service was kept to avoid leaving DNS broken", removeErr))
				return
			}
			_ = enforcer.RemoveWatchdog(ctx)
			if deleteErr := s.Delete(); deleteErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("rollback service registration: %w", deleteErr))
			}
		}
	}()
	if err := enforcer.SetServiceSecurityDescriptor(context.Background(), serviceName); err != nil {
		return err
	}
	if err := events.InstallWindowsEventLog(); err != nil {
		return err
	}

	// Restart after 5 s, 5 s, then every 30 s. Counter resets after a day.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 30 * time.Second},
	}, 86400); err != nil {
		return fmt.Errorf("recovery actions: %w", err)
	}
	// Also treat a non-zero exit code as a failure, not just a crash.
	if err := s.SetRecoveryActionsOnNonCrashFailures(true); err != nil {
		return fmt.Errorf("recovery flag: %w", err)
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitForDNSListeners(ctx); err != nil {
		return fmt.Errorf("wait for DNS service readiness: %w", err)
	}
	installedConfig, _, err := config.LoadWithFallback(dstCfg)
	if err != nil {
		return fmt.Errorf("installed config: %w", err)
	}
	if err := enforcer.Repair(ctx, data, installedConfig, nil); err != nil {
		return fmt.Errorf("apply enforcement: %w", err)
	}
	installed = true
	if err := enforcer.InstallWatchdog(ctx, exe); err != nil {
		return fmt.Errorf("service is installed and enforcement is active, but watchdog installation failed: %w", err)
	}
	fmt.Printf("Installed and started %s.\n  binary: %s\n  config: %s\n  log:    %s\n",
		serviceName, exe, dstCfg, filepath.Join(data, "guardian.log"))
	return nil
}

func uninstallService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot reach the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("%s is not installed", serviceName)
	}
	defer s.Close()

	if err := stopService(s); err != nil {
		return fmt.Errorf("stop: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := enforcer.Remove(ctx, dataDir()); err != nil {
		if restartErr := s.Start(); restartErr != nil {
			return errors.Join(fmt.Errorf("remove enforcement: %w", err), fmt.Errorf("restart service after failed uninstall: %w", restartErr))
		}
		return fmt.Errorf("remove enforcement (service restarted): %w", err)
	}
	if err := enforcer.RemoveWatchdog(ctx); err != nil {
		if restartErr := s.Start(); restartErr != nil {
			return errors.Join(fmt.Errorf("remove watchdog: %w", err), fmt.Errorf("restart service after failed uninstall: %w", restartErr))
		}
		return fmt.Errorf("remove watchdog (service restarted): %w", err)
	}
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Println("Service removed, firewall and browser policies removed, and adapter DNS restored.")
	fmt.Println("Files in Program Files and ProgramData were left in place.")
	return nil
}

func copyFile(src, dst string, perm os.FileMode) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		return err
	}

	if dstInfo, err := os.Stat(dst); err == nil && os.SameFile(srcInfo, dstInfo) {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, perm)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func showStatus() error {
	state := "Not installed"
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Service Control Manager: %w", err)
	}
	s, err := m.OpenService(serviceName)
	if err == nil {
		st, queryErr := s.Query()
		if queryErr == nil {
			switch st.State {
			case svc.Running:
				state = "Running"
			case svc.Stopped:
				state = "Stopped"
			case svc.StartPending:
				state = "Starting"
			case svc.StopPending:
				state = "Stopping"
			default:
				state = fmt.Sprintf("State %d", st.State)
			}
		} else {
			s.Close()
			m.Disconnect()
			return fmt.Errorf("query service state: %w", queryErr)
		}
		s.Close()
	} else if !strings.Contains(strings.ToLower(err.Error()), "does not exist") &&
		!strings.Contains(strings.ToLower(err.Error()), "1060") {
		m.Disconnect()
		return fmt.Errorf("open service: %w", err)
	}
	m.Disconnect()

	status, err := events.OpenStatus(filepath.Join(dataDir(), "status.json"))
	if err != nil {
		return fmt.Errorf("read status file: %w", err)
	}
	snapshot := status.Snapshot()
	fmt.Printf("Service: %s\n", state)
	fmt.Printf("Started: %s\n", formatTime(snapshot.ServiceStartedAt))
	fmt.Printf("Config version: %d\n", snapshot.ConfigVersion)
	fmt.Printf("Last remote sync: %s\n", formatSync(snapshot.LastRemoteSync))
	fmt.Printf("Last drift: %s\n", formatDrift(snapshot.LastDrift))
	fmt.Printf("Upstream health: %s\n", emptyAsUnknown(snapshot.UpstreamHealth))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	platform, err := enforcer.NewWindowsPlatform(dataDir())
	if err != nil {
		return fmt.Errorf("inspect enforcement: %w", err)
	}
	adapters, adapterErr := platform.ListAdapters(ctx)
	if adapterErr != nil {
		fmt.Printf("Adapter DNS: unavailable (%v)\n", adapterErr)
	} else {
		fmt.Println("Adapter DNS:")
		for _, adapter := range adapters {
			fmt.Printf("  %s: IPv4=%v IPv6=%v\n", adapter.Name, adapter.IPv4DNS, adapter.IPv6DNS)
		}
	}
	rules, ruleErr := platform.FirewallRuleNames(ctx)
	if ruleErr != nil {
		fmt.Printf("Guardian firewall rules: unavailable (%v)\n", ruleErr)
	} else {
		fmt.Printf("Guardian firewall rules: %d present\n", len(rules))
	}
	weak := false
	for _, path := range []string{
		filepath.Join(os.Getenv("ProgramFiles"), "Guardian"),
		filepath.Join(dataDir(), "config.json"),
		filepath.Join(dataDir(), "guardian.log"),
		filepath.Join(dataDir(), "events.log"),
		filepath.Join(dataDir(), "status.json"),
	} {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			fmt.Printf("ACL check %s: unavailable (%v)\n", path, err)
			weak = true
			continue
		}
		if ok, checkErr := protectedACL(path); checkErr != nil {
			fmt.Printf("ACL check %s: unavailable (%v)\n", path, checkErr)
			weak = true
		} else if !ok {
			fmt.Printf("ACL check %s: WEAK\n", path)
			weak = true
		}
	}
	if weak {
		fmt.Println("ACL self-check: warnings found")
	} else {
		fmt.Println("ACL self-check: no weak ACLs detected")
	}
	return nil
}

func showEvents(count int) error {
	status, err := events.OpenStatus(filepath.Join(dataDir(), "status.json"))
	if err != nil {
		return fmt.Errorf("read status file: %w", err)
	}
	all := status.Snapshot().Events
	if count > len(all) {
		count = len(all)
	}
	if count == 0 {
		fmt.Println("No local events recorded.")
		return nil
	}
	for _, event := range all[len(all)-count:] {
		message := event.Message
		if message == "" {
			message = event.Category
		}
		fmt.Printf("%s  %-20s  %s  (repeat=%d)\n",
			event.Time.Local().Format(time.RFC3339), event.Type, message, event.RepeatCount)
	}
	return nil
}

func repairService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to Service Control Manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("%s is not installed: %w", serviceName, err)
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return fmt.Errorf("query service: %w", err)
	}
	if status.State == svc.Stopped {
		if err := s.Start(); err != nil {
			return fmt.Errorf("start stopped service: %w", err)
		}
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			status, err = s.Query()
			if err != nil {
				return fmt.Errorf("wait for service startup: %w", err)
			}
			if status.State == svc.Running {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
		if status.State != svc.Running {
			return fmt.Errorf("service did not start within 30 seconds")
		}
	}
	cfg, _, err := config.LoadWithFallback(filepath.Join(dataDir(), "config.json"))
	if err != nil {
		return fmt.Errorf("load service configuration: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := enforcer.Repair(ctx, dataDir(), cfg, func(message string) {
		log.Printf("drift repaired: %s", message)
	}); err != nil {
		return fmt.Errorf("repair enforcement: %w", err)
	}
	fmt.Println("Guardian service and enforcement repaired.")
	return nil
}

func protectedACL(path string) (bool, error) {
	output, err := exec.Command("icacls.exe", path).CombinedOutput()
	if err != nil {
		return false, fmt.Errorf("icacls: %w: %s", err, strings.TrimSpace(string(output)))
	}
	acl := strings.ToLower(string(output))
	for _, entry := range []string{"\\everyone:(", "\\users:(", "\\authenticated users:("} {
		if strings.Contains(acl, entry) {
			return false, nil
		}
	}
	return true, nil
}

func formatTime(value time.Time) string {
	if value.IsZero() {
		return "unknown"
	}
	return value.Local().Format(time.RFC3339)
}

func formatSync(value events.SyncStatus) string {
	if value.Result == "" {
		return "none recorded"
	}
	return value.Result + " at " + formatTime(value.Time)
}

func formatDrift(value events.DriftStatus) string {
	if value.Description == "" {
		return "none recorded"
	}
	return value.Description + " at " + formatTime(value.Time)
}

func emptyAsUnknown(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}

func lockDownPath(path string) error {
	output, err := exec.Command("icacls.exe", path, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F",
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F", "/T", "/C").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func replaceFile(staged, destination string) error {
	backup := destination + ".install-rollback"
	if err := os.Remove(backup); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale install backup: %w", err)
	}
	hadDestination := false
	if _, err := os.Stat(destination); err == nil {
		if err := os.Rename(destination, backup); err != nil {
			return fmt.Errorf("save previous binary: %w", err)
		}
		hadDestination = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(staged, destination); err != nil {
		if hadDestination {
			_ = os.Rename(backup, destination)
		}
		return err
	}
	if hadDestination {
		if err := os.Remove(backup); err != nil {
			return fmt.Errorf("remove previous binary backup: %w", err)
		}
	}
	return nil
}

func stopService(service *mgr.Service) error {
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	if status.State != svc.StopPending {
		if _, err := service.Control(svc.Stop); err != nil {
			return err
		}
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		status, err = service.Query()
		if err != nil {
			return err
		}
		if status.State == svc.Stopped {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return errors.New("service did not stop within 30 seconds")
}

func waitForDNSListeners(ctx context.Context) error {
	for _, address := range []string{"127.0.0.1:53", "[::1]:53"} {
		ready := false
		for !ready {
			if err := ctx.Err(); err != nil {
				return err
			}
			conn, err := net.DialTimeout("tcp", address, time.Second)
			if err == nil {
				conn.Close()
				ready = true
				continue
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(300 * time.Millisecond):
			}
		}
	}
	return nil
}

func upgradeService(service *mgr.Service, srcConfig string) (retErr error) {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	progDir := filepath.Join(os.Getenv("ProgramFiles"), "Guardian")
	data := dataDir()
	exe := filepath.Join(progDir, "guardian.exe")
	dstConfig := filepath.Join(data, "config.json")
	if err := lockDownPath(progDir); err != nil {
		return fmt.Errorf("secure Program Files: %w", err)
	}
	if err := lockDownPath(data); err != nil {
		return fmt.Errorf("secure ProgramData: %w", err)
	}
	if _, err := os.Stat(dstConfig); os.IsNotExist(err) {
		if err := copyFile(srcConfig, dstConfig, 0o600); err != nil {
			return fmt.Errorf("initialize installed config: %w", err)
		}
	}
	if _, _, err := config.LoadWithFallback(dstConfig); err != nil {
		return fmt.Errorf("installed config: %w", err)
	}
	if err := stopService(service); err != nil {
		return fmt.Errorf("stop service for upgrade: %w", err)
	}
	serviceHandled := false
	defer func() {
		if retErr != nil && !serviceHandled {
			if err := service.Start(); err != nil {
				retErr = errors.Join(retErr, fmt.Errorf("restart previous service: %w", err))
			}
		}
	}()

	rollback := exe + ".upgrade-rollback"
	staged := exe + ".upgrade-new"
	if err := os.Remove(rollback); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale upgrade backup: %w", err)
	}
	if err := os.Remove(staged); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale staged binary: %w", err)
	}
	if err := copyFile(self, staged, 0o755); err != nil {
		return fmt.Errorf("stage upgraded binary: %w", err)
	}
	if err := os.Rename(exe, rollback); err != nil {
		_ = os.Remove(staged)
		return fmt.Errorf("save installed binary for rollback: %w", err)
	}
	if err := os.Rename(staged, exe); err != nil {
		_ = os.Rename(rollback, exe)
		_ = os.Remove(staged)
		return fmt.Errorf("publish upgraded binary: %w", err)
	}

	restore := func(cause error) error {
		serviceHandled = true
		var failures []error
		if err := stopService(service); err != nil {
			failures = append(failures, fmt.Errorf("stop upgraded service: %w", err))
			return errors.Join(append([]error{cause}, failures...)...)
		}
		if err := os.Remove(exe); err != nil && !os.IsNotExist(err) {
			failures = append(failures, fmt.Errorf("remove upgraded binary: %w", err))
		}
		if err := os.Rename(rollback, exe); err != nil {
			failures = append(failures, fmt.Errorf("restore previous binary: %w", err))
		}
		if err := service.Start(); err != nil {
			failures = append(failures, fmt.Errorf("restart previous service: %w", err))
		}
		return errors.Join(append([]error{cause}, failures...)...)
	}

	if err := enforcer.SetServiceSecurityDescriptor(context.Background(), serviceName); err != nil {
		return restore(fmt.Errorf("secure upgraded service: %w", err))
	}
	if err := events.InstallWindowsEventLog(); err != nil {
		return restore(err)
	}
	if err := service.Start(); err != nil {
		return restore(fmt.Errorf("start upgraded service: %w", err))
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := waitForDNSListeners(ctx); err != nil {
		return restore(fmt.Errorf("wait for upgraded service: %w", err))
	}
	cfg, _, err := config.LoadWithFallback(dstConfig)
	if err != nil {
		return restore(fmt.Errorf("load upgraded config: %w", err))
	}
	if err := enforcer.Repair(ctx, data, cfg, nil); err != nil {
		return restore(fmt.Errorf("reconcile upgraded service: %w", err))
	}
	if err := enforcer.InstallWatchdog(ctx, exe); err != nil {
		return restore(fmt.Errorf("install scheduled watchdog: %w", err))
	}
	serviceHandled = true
	if err := os.Remove(rollback); err != nil {
		return fmt.Errorf("remove upgrade rollback binary: %w", err)
	}
	fmt.Printf("Upgraded and restarted %s; existing config was preserved.\n", serviceName)
	return nil
}
