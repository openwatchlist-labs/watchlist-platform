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

	"github.com/openwatchlist-labs/watchlist-platform/internal/platformapi"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: platform-api <check|serve> --config FILE [--listen ADDR]")
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	cfg := fs.String("config", "", "production runtime config")
	listen := fs.String("listen", "", "fixture-only listen override")
	_ = fs.Parse(os.Args[2:])
	s, err := platformapi.New(*cfg)
	check(err)
	defer s.Close()
	switch os.Args[1] {
	case "check":
		r := s.Check(context.Background())
		write(r)
		if r.Status != "ok" {
			os.Exit(1)
		}
	case "serve":
		addr := s.Config.ListenAddress
		if *listen != "" {
			if s.Config.Environment != "fixture" {
				fatal("listen override is fixture-only")
			}
			addr = *listen
		}
		h := &http.Server{Addr: addr, Handler: s.Handler(), ReadHeaderTimeout: time.Duration(s.Config.ReadHeaderTimeoutSeconds) * time.Second, ReadTimeout: time.Duration(s.Config.ReadTimeoutSeconds) * time.Second, WriteTimeout: time.Duration(s.Config.WriteTimeoutSeconds) * time.Second, IdleTimeout: time.Duration(s.Config.IdleTimeoutSeconds) * time.Second, MaxHeaderBytes: s.Config.MaxHeaderBytes}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			s.StartDraining()
			deadline := time.Now().Add(time.Duration(s.Config.ShutdownGraceSeconds) * time.Second)
			sd, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			_ = h.Shutdown(sd)
			for s.InFlight() > 0 && time.Now().Before(deadline) {
				time.Sleep(10 * time.Millisecond)
			}
		}()
		fmt.Fprintf(os.Stderr, "platform-api listening on %s\n", addr)
		err = h.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			fatal("%v", err)
		}
	default:
		fatal("unknown command %q", os.Args[1])
	}
}
func write(v any) { e := json.NewEncoder(os.Stdout); e.SetEscapeHTML(false); check(e.Encode(v)) }
func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}
func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
