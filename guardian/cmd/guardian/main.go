package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	_ "time/tzdata" // embed timezone data so Windows can resolve zones

	"guardian/internal/app"
	"guardian/internal/dashboard"
)

const usage = `usage:
  guardian [run] [-config config.json]    run in the console
  guardian ui [-config config.json]       open the local configuration dashboard
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
		if err := app.Run(ctx, cfgPath); err != nil {
			log.Fatal(err)
		}
	case "ui":
		cfgPath = parseConfig(args)
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		fmt.Println("Guardian dashboard: http://127.0.0.1:8765")
		if err := dashboard.Run(ctx, cfgPath); err != nil {
			log.Fatal(err)
		}
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
