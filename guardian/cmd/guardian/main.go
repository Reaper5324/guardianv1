package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "time/tzdata" // embed timezone data so Windows can resolve zones

	"guardian/internal/app"
	"guardian/internal/dashboard"
)

const usage = `usage:
  guardian.exe                            open the local dashboard (config.json beside exe)
  guardian run [-config config.json]      run the DNS service in the console
  guardian ui [-config config.json]       serve the local dashboard
  guardian install [-config config.json]  install and start the Windows service (Administrator)
  guardian uninstall                      stop and remove the service (Administrator)
  guardian status                         show local service and filter status
  guardian events [-n 50]                 show recent local events
  guardian repair                         restore enforcement and start the service
  guardian keygen -private <file> -public <file>
                                          generate an Ed25519 config-signing keypair
  guardian sign -config <file> -key <file> -out <file>
                                          sign exact config bytes for remote updates
`

func main() {
	// Launched by the Service Control Manager.
	if isService() {
		runService()
		return
	}

	cmd, args := "run", os.Args[1:]
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	cfgPath := "config.json"

	switch cmd {
	case "run":
		cfgPath = parseConfig(args)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if len(os.Args) == 1 {
			cfgPath = defaultConfigPath()
			exitOnErr(serveDashboard(ctx, cfgPath, true))
			return
		}
		if err := app.Run(ctx, cfgPath); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			os.Exit(1)
		}
	case "ui":
		cfgPath = parseConfig(args)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		exitOnErr(serveDashboard(ctx, cfgPath, false))
	case "install":
		cfgPath = parseConfig(args)
		exitOnErr(installService(cfgPath))
	case "uninstall":
		exitOnErr(uninstallService())
	case "status":
		exitOnErr(showStatus())
	case "events":
		exitOnErr(showEvents(parseEventCount(args)))
	case "repair":
		exitOnErr(repairService())
	case "keygen":
		exitOnErr(generateSigningKeypair(args))
	case "sign":
		exitOnErr(signConfig(args))
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func serveDashboard(ctx context.Context, cfgPath string, pauseOnError bool) error {
	const dashboardURL = "http://127.0.0.1:8765"
	if dashboardResponds() {
		fmt.Printf("Guardian dashboard is already running: %s\n", dashboardURL)
		_ = openDashboardBrowser()
		return nil
	}
	options := dashboard.Options{OnListening: func() {
		fmt.Printf("Guardian local dashboard: %s\n", dashboardURL)
		if err := openDashboardBrowser(); err != nil {
			fmt.Printf("Open this address in your browser: %s\n", dashboardURL)
		}
	}}
	if err := dashboard.RunWithOptions(ctx, cfgPath, options); err != nil {
		if pauseOnError {
			fmt.Fprintln(os.Stderr, "Guardian dashboard could not start:", err)
			fmt.Fprintln(os.Stderr, "Run this executable from its package folder with config.json beside it.")
			fmt.Fprintln(os.Stderr, "For installation, use the elevated install.ps1 procedure.")
			waitForDefaultLaunchError()
		}
		return err
	}
	return nil
}

func dashboardResponds() bool {
	client := &http.Client{Timeout: 500 * time.Millisecond}
	response, err := client.Get("http://127.0.0.1:8765/healthz")
	if err != nil {
		return false
	}
	defer response.Body.Close()
	return response.StatusCode == http.StatusNoContent
}

func defaultConfigPath() string {
	executable, err := os.Executable()
	if err != nil {
		return "config.json"
	}
	return filepath.Join(filepath.Dir(executable), "config.json")
}

func parseEventCount(args []string) int {
	fs := flag.NewFlagSet("events", flag.ExitOnError)
	count := fs.Int("n", 50, "number of recent events to display")
	_ = fs.Parse(args)
	if *count < 1 || *count > 500 {
		fmt.Fprintln(os.Stderr, "error: -n must be between 1 and 500")
		os.Exit(2)
	}
	return *count
}

// parseConfig reads the -config flag from args.
func parseConfig(args []string) string {
	fs := flag.NewFlagSet("guardian", flag.ExitOnError)
	p := fs.String("config", "config.json", "path to config file")
	_ = fs.Parse(args)
	return *p
}

func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
