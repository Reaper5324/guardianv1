// Package app wires Guardian's components together. Both the console
// runner and the Windows service call Run.
package app

import (
	"context"
	"fmt"
	"log"
	"path/filepath"
	"runtime"
	"time"

	"guardian/internal/config"
	"guardian/internal/dnsproxy"
	"guardian/internal/events"
	"guardian/internal/remote"
)

// Run loads the config and serves DNS until ctx is cancelled. It returns nil
// on a clean shutdown and an error if startup or serving fails.
func Run(ctx context.Context, cfgPath string) error {
	cfg, usedFallback, err := config.LoadWithFallback(cfgPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if usedFallback {
		log.Printf("primary config unavailable or older; using last-known-good config")
	}
	store := &config.Store{}
	if err := store.Set(cfg); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	proxy, err := dnsproxy.New(store)
	if err != nil {
		return fmt.Errorf("proxy: %w", err)
	}
	dataDir := filepath.Dir(cfgPath)
	status, err := events.OpenStatus(filepath.Join(dataDir, "status.json"))
	if err != nil {
		return fmt.Errorf("status: %w", err)
	}
	if err := status.SetServiceStartedAt(time.Now().UTC()); err != nil {
		return fmt.Errorf("status: record service start: %w", err)
	}
	if err := status.SetConfigVersion(cfg.Version); err != nil {
		return fmt.Errorf("status: record config version: %w", err)
	}
	logSink, err := events.OpenRotatingLog(filepath.Join(dataDir, "events.log"))
	if err != nil {
		return fmt.Errorf("events: open rotating log: %w", err)
	}
	defer logSink.Close()
	sinks := []events.EventSink{logSink}
	var windowsSink *events.WindowsEventSink
	if runtime.GOOS == "windows" {
		windowsSink, err = events.OpenWindowsEventLog()
		if err != nil {
			log.Printf("events: Windows Event Log unavailable: %v", err)
		} else {
			defer windowsSink.Close()
			sinks = append(sinks, windowsSink)
		}
	}
	hub, err := events.NewHub(status, 30*time.Second, sinks...)
	if err != nil {
		return fmt.Errorf("events: %w", err)
	}
	hub.OnSinkError = func(err error) { log.Printf("events: %v", err) }
	hub.Record(events.Event{Type: "service-started", Time: time.Now().UTC()})
	proxy.OnBlockedCount = func(category string) { hub.CountBlocked(category) }

	log.Printf("guardian listening on %s", cfg.ListenAddr)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	listening := make(chan struct{})
	proxy.OnListening = func() { close(listening) }
	proxyDone := make(chan error, 1)
	go func() { proxyDone <- proxy.Run(runCtx) }()
	hubDone := make(chan error, 1)
	go func() { hubDone <- hub.Run(runCtx) }()
	select {
	case <-listening:
	case proxyErr := <-proxyDone:
		cancel()
		<-hubDone
		return proxyErr
	case <-ctx.Done():
		cancel()
		<-proxyDone
		<-hubDone
		return nil
	}

	enforcementDone := make(chan error, 1)
	go func() {
		enforcementDone <- runEnforcement(runCtx, store.Get, dataDir, func(description string) {
			hub.Record(events.Event{Type: "drift-repaired", Message: description})
		})
	}()
	upstreamDone := make(chan error, 1)
	go func() { upstreamDone <- monitorUpstreams(runCtx, proxy, hub) }()
	var remoteDone chan error
	if active := store.Get(); active.Remote != nil && active.Remote.Enabled {
		poller, err := remote.NewPoller(store, proxy, cfgPath, dataDir, func(event events.Event) { hub.Record(event) })
		if err != nil {
			cancel()
			<-proxyDone
			<-enforcementDone
			<-upstreamDone
			<-hubDone
			return fmt.Errorf("remote configuration: %w", err)
		}
		remoteDone = make(chan error, 1)
		go func() { remoteDone <- poller.Run(runCtx) }()
	}
	select {
	case proxyErr := <-proxyDone:
		cancel()
		if enforcementErr := <-enforcementDone; enforcementErr != nil {
			log.Printf("enforcement: stopped with errors: %v", enforcementErr)
		}
		if hubErr := <-hubDone; hubErr != nil {
			log.Printf("events: stopped with errors: %v", hubErr)
		}
		return proxyErr
	case enforcementErr := <-enforcementDone:
		if ctx.Err() != nil {
			cancel()
			<-proxyDone
			<-upstreamDone
			if remoteDone != nil {
				<-remoteDone
			}
			<-hubDone
			return nil
		}
		if enforcementErr == nil {
			enforcementErr = fmt.Errorf("enforcement loop stopped unexpectedly")
		}
		if enforcementErr != nil {
			cancel()
			<-proxyDone
			<-upstreamDone
			if remoteDone != nil {
				<-remoteDone
			}
			<-hubDone
			return enforcementErr
		}
		return nil
	case upstreamErr := <-upstreamDone:
		if ctx.Err() != nil {
			cancel()
			<-proxyDone
			<-enforcementDone
			if remoteDone != nil {
				<-remoteDone
			}
			<-hubDone
			return nil
		}
		if upstreamErr == nil {
			upstreamErr = fmt.Errorf("upstream monitor stopped unexpectedly")
		}
		cancel()
		<-proxyDone
		<-enforcementDone
		if remoteDone != nil {
			<-remoteDone
		}
		<-hubDone
		return upstreamErr
	case remoteErr := <-remoteDone:
		if ctx.Err() != nil {
			cancel()
			<-proxyDone
			<-enforcementDone
			<-upstreamDone
			<-hubDone
			return nil
		}
		if remoteErr == nil {
			remoteErr = fmt.Errorf("remote config poller stopped unexpectedly")
		}
		cancel()
		<-proxyDone
		<-enforcementDone
		<-upstreamDone
		<-hubDone
		return remoteErr
	case <-ctx.Done():
		cancel()
		<-proxyDone
		<-enforcementDone
		<-upstreamDone
		if remoteDone != nil {
			<-remoteDone
		}
		if hubErr := <-hubDone; hubErr != nil {
			log.Printf("events: stopped with errors: %v", hubErr)
		}
		return nil
	}
}

func monitorUpstreams(ctx context.Context, proxy *dnsproxy.Proxy, hub *events.Hub) error {
	const unhealthyAfter = 3 * time.Minute
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	var failedAt time.Time
	reportedUnhealthy := false
	probe := func() {
		probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := proxy.ProbeUpstreams(probeCtx)
		cancel()
		if err != nil {
			if failedAt.IsZero() {
				failedAt = time.Now()
			}
			if !reportedUnhealthy && time.Since(failedAt) >= unhealthyAfter {
				hub.Record(events.Event{Type: "upstream-health", Message: "unreachable"})
				reportedUnhealthy = true
			}
			return
		}
		failedAt = time.Time{}
		if reportedUnhealthy {
			hub.Record(events.Event{Type: "upstream-health", Message: "healthy"})
			reportedUnhealthy = false
		}
	}
	probe()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			probe()
		}
	}
}
