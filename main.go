// sikkerkey-connector runs inside a customer's network and holds one outbound
// connection to SikkerKey.
//
// It dials out, holds the connection, and opens local sockets only to the
// targets declared on its tunnel. It accepts no inbound connection.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/SikkerKeyOfficial/sikkerkey-connector/internal/config"
	"github.com/SikkerKeyOfficial/sikkerkey-connector/internal/enroll"
	"github.com/SikkerKeyOfficial/sikkerkey-connector/internal/service"
	"github.com/SikkerKeyOfficial/sikkerkey-connector/internal/tunnel"
)

// version is set at build time via `-ldflags="-X main.version=<x.y.z>"`.
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "install":
		cmdInstall()
	case "uninstall":
		cmdUninstall()
	case "run":
		cmdRun()
	case "status":
		cmdStatus()
	case "version":
		fmt.Println("sikkerkey-connector " + resolveVersion())
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

// cmdInstall claims the tunnel for this machine and leaves it running.
//
// Everything checkable is checked before enrollment, which spends the token.
func cmdInstall() {
	token := ""
	if len(os.Args) >= 3 {
		token = strings.TrimSpace(os.Args[2])
	}

	// Already enrolled and given no token: install the service for the existing
	// identity. This is the recovery path when enrollment succeeded and the
	// service step did not, with the token already spent.
	if token == "" {
		if cfg, err := config.Load(); err == nil {
			fmt.Printf("Already enrolled as tunnel %s. Setting up the service.\n\n", cfg.TunnelID)
			if err := service.Install(); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
			fmt.Println()
			fmt.Println("Approve the tunnel on the Tunnels page to finish.")
			return
		}
		fmt.Fprintln(os.Stderr, "usage: sikkerkey-connector install <token>")
		fmt.Fprintln(os.Stderr, "\nCopy the install command from the Tunnels page in your SikkerKey dashboard.")
		os.Exit(1)
	}

	// Refused before the token is spent, since this host already has a tunnel.
	if cfg, err := config.Load(); err == nil {
		fmt.Fprintf(os.Stderr, "This host is already enrolled as tunnel %s.\n", cfg.TunnelID)
		fmt.Fprintln(os.Stderr, "Run 'sikkerkey-connector uninstall' and delete that tunnel from your dashboard first.")
		os.Exit(1)
	}

	// The enrollment below is irreversible.
	if err := service.Preflight(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		fmt.Fprintln(os.Stderr, "\nYour install token has not been used and is still valid.")
		os.Exit(1)
	}

	res, err := enroll.Run(token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Enrolled as tunnel %q\n", res.TunnelName)
	fmt.Printf("  Identity: %s\n", res.KeyPath)
	fmt.Printf("  Endpoint: %s\n", res.TunnelURL)
	fmt.Println()

	if err := service.Install(); err != nil {
		// The identity is written and valid, so report the recovery command.
		fmt.Fprintf(os.Stderr, "The tunnel is enrolled, but the service could not be set up: %v\n", err)
		fmt.Fprintln(os.Stderr, "Fix that, then run 'sikkerkey-connector install' with no token to retry the service.")
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("Approve the tunnel on the Tunnels page to finish.")
}

// cmdUninstall removes the service and keeps the identity, so the same host can
// be brought back without a new tunnel.
func cmdUninstall() {
	if err := service.Uninstall(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("The tunnel identity is kept. Run 'sikkerkey-connector run' to start it again,")
	fmt.Println("or delete the tunnel from your dashboard to revoke it.")
}

// cmdRun holds the tunnel open until the process is signalled. This is what the
// service unit invokes.
func cmdRun() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	client, err := tunnel.New(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	// Closing the context on SIGTERM shuts the socket immediately rather than
	// waiting on the read deadline, so the server sees a clean close.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("sikkerkey-connector %s starting (tunnel %s)\n", resolveVersion(), cfg.TunnelID)
	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("shut down")
}

// cmdStatus reports this host's configuration without connecting. It prints
// whether the key is present, never the key.
func cmdStatus() {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	keyState := "missing"
	if _, err := os.Stat(cfg.PrivateKeyPath); err == nil {
		keyState = "present"
	}
	pinned := "not pinned"
	if cfg.TunnelSigningPublicKey != "" {
		pinned = "pinned"
	}
	fmt.Printf("tunnel:      %s\n", cfg.TunnelID)
	fmt.Printf("endpoint:    %s\n", cfg.TunnelURL)
	fmt.Printf("private key: %s (%s)\n", cfg.PrivateKeyPath, keyState)
	fmt.Printf("sikkerkey key: %s\n", pinned)
}

// resolveVersion prefers the ldflags stamp used for released builds, falling
// back to the module version the Go toolchain records for `go install`.
func resolveVersion() string {
	if version != "dev" {
		return version
	}
	info, ok := debug.ReadBuildInfo()
	if !ok || info.Main.Version == "" || info.Main.Version == "(devel)" {
		return version
	}
	return strings.TrimPrefix(info.Main.Version, "v")
}

func usage() {
	fmt.Println(`sikkerkey-connector - holds a private tunnel between your network and SikkerKey

Usage:
  sikkerkey-connector <command>

Commands:
  install <token>   Claim a tunnel for this host and run it in the background
  install           Set up the service for an already-enrolled host
  uninstall         Stop and remove the background service
  run               Hold the tunnel open (what the service runs)
  status            Show this host's tunnel configuration
  version           Print version

Copy the install command from the Tunnels page in your SikkerKey dashboard.`)
}
