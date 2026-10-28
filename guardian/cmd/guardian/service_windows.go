//go:build windows

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"

	"guardian/internal/app"
	"guardian/internal/config"
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
func installService(srcConfig string) error {
	if _, err := config.Load(srcConfig); err != nil {
		return fmt.Errorf("config %s: %w", srcConfig, err)
	}
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("cannot reach the service manager (run as Administrator): %w", err)
	}
	defer m.Disconnect()

	if s, err := m.OpenService(serviceName); err == nil {
		s.Close()
		return fmt.Errorf("%s is already installed; run uninstall first", serviceName)
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
	// Lock the data dir first so files created in it inherit the lock.
	// SIDs are used so this works on any Windows language.
	out, err := exec.Command("icacls", data, "/inheritance:r",
		"/grant:r", "*S-1-5-18:(OI)(CI)F", // SYSTEM
		"/grant:r", "*S-1-5-32-544:(OI)(CI)F", // Administrators
		"/T").CombinedOutput()
	if err != nil {
		return fmt.Errorf("icacls: %v: %s", err, out)
	}
	if err := copyFile(self, exe, 0o755); err != nil {
		return fmt.Errorf("copy binary: %w", err)
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
			_ = s.Delete()
		}
	}()

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
	installed = true
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

	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		if _, err := s.Control(svc.Stop); err != nil {
			return fmt.Errorf("stop: %w", err)
		}
		for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(300 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil {
		return err
	}
	fmt.Println("Service removed. Files in Program Files and ProgramData were left in place.")
	fmt.Println("If the adapter DNS points at 127.0.0.1, set it back to automatic or the internet will stop resolving.")
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
