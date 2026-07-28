package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcaseapi"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: alert-case-api <check|serve> --config FILE")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	configPath := fs.String("config", "", "configuration JSON")
	_ = fs.Parse(os.Args[2:])
	cfg, policy, err := alertcaseapi.LoadConfig(*configPath)
	check(err)
	server, err := alertcaseapi.New(cfg, policy)
	check(err)
	switch os.Args[1] {
	case "check":
		check(server.Check(context.Background()))
		write(map[string]any{"status": "ok", "state_directory": cfg.StateDirectory, "postgres_required": cfg.PostgresRequired, "policy_sha256": policy.PolicySHA256})
	case "serve":
		httpServer := &http.Server{Addr: cfg.ListenAddress, Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = httpServer.Shutdown(shutdown)
		}()
		fmt.Fprintf(os.Stderr, "alert-case-api listening on %s\n", cfg.ListenAddress)
		err := httpServer.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			fatal("%v", err)
		}
	default:
		fatal("unknown command %q", os.Args[1])
	}
}
func write(v any) { check(json.NewEncoder(os.Stdout).Encode(v)) }
func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}
func fatal(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
