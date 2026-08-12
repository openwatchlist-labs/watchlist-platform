package main

import (
	"context"
	"flag"
	"fmt"
	"github.com/openwatchlist-labs/watchlist-platform/internal/vendoradapterapi"
	"net/http"
	"os"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "vendor-adapter-api check|serve --config FILE")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	cfgPath := fs.String("config", "configs/vendor-adapters/phase9e-api-example.json", "")
	fs.Parse(os.Args[2:])
	cfg, e := vendoradapterapi.LoadConfig(*cfgPath)
	if e != nil {
		fatal(e)
	}
	s, e := vendoradapterapi.New(cfg)
	if e != nil {
		fatal(e)
	}
	switch os.Args[1] {
	case "check":
		ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout())
		defer cancel()
		if e := s.Check(ctx); e != nil {
			fatal(e)
		}
		fmt.Printf("{\"status\":\"ok\",\"profile_count\":%d,\"postgres_required\":%t}\n", len(s.Profiles), cfg.PostgresRequired)
	case "serve":
		tokens, e := vendoradapterapi.LoadTokenService(cfg)
		if e != nil {
			fatal(e)
		}
		authenticated, e := s.AuthenticatedHandler(tokens, nil)
		if e != nil {
			fatal(e)
		}
		srv := http.Server{Addr: cfg.ListenAddress, Handler: authenticated, ReadHeaderTimeout: 5 * time.Second}
		fmt.Fprintf(os.Stderr, "vendor-adapter-api listening on %s\n", cfg.ListenAddress)
		fatal(srv.ListenAndServe())
	default:
		os.Exit(2)
	}
}
func fatal(e error) { fmt.Fprintln(os.Stderr, e); os.Exit(1) }
