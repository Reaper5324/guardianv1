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
	cfgPath := parseConfig(args)

	switch cmd {
	case "run":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := app.Run(ctx, cfgPath); err != nil {
			log.Fatal(err)
		}
	case "ui":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		fmt.Println("Guardian dashboard: http://127.0.0.1:8765")
		if err := dashboard.Run(ctx, cfgPath); err != nil {
			log.Fatal(err)
		}
	case "install":
		exitOnErr(installService(cfgPath))
	case "uninstall":
		exitOnErr(uninstallService())
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
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
