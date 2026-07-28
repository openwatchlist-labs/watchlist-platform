package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/assistanceapi"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: case-assistance-api <check|serve>")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	configPath := fs.String("config", "", "config JSON")
	_ = fs.Parse(os.Args[2:])
	cfg, policy, snapshot, err := assistanceapi.LoadConfig(*configPath)
	check(err)
	server, err := assistanceapi.New(cfg, policy, snapshot)
	check(err)
	switch os.Args[1] {
	case "check":
		check(server.Check(context.Background()))
		write(map[string]any{"status": "ok", "config": *configPath, "model_mode": cfg.ModelMode, "primary_model_id": cfg.Models.PrimaryModelID, "guardian_model_id": cfg.Models.GuardianModelID, "postgres_required": cfg.PostgresRequired})
	case "serve":
		check(server.Check(context.Background()))
		httpServer := &http.Server{Addr: cfg.ListenAddress, Handler: server.Handler(), ReadHeaderTimeout: cfg.Timeout()}
		fmt.Fprintf(os.Stderr, "case-assistance-api listening on %s\n", cfg.ListenAddress)
		check(httpServer.ListenAndServe())
	default:
		fatal("unknown command %q", os.Args[1])
	}
}
func write(v any) { enc := json.NewEncoder(os.Stdout); enc.SetEscapeHTML(false); check(enc.Encode(v)) }
func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}
func fatal(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
