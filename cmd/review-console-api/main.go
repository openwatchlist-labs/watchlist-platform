package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/openwatchlist-labs/watchlist-platform/internal/reviewconsoleapi"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: review-console-api <check|serve> --config FILE")
	}
	f := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	p := f.String("config", "", "config")
	f.Parse(os.Args[2:])
	l, e := reviewconsoleapi.LoadConfig(*p)
	check(e)
	s, e := reviewconsoleapi.New(l)
	check(e)
	switch os.Args[1] {
	case "check":
		check(s.Check(context.Background()))
		json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "ok", "registry_sha256": l.Registry.RegistrySHA256, "console_enabled": l.Config.ConsoleEnabled})
	case "serve":
		h := &http.Server{Addr: l.Config.ListenAddress, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: l.Config.Timeout(), WriteTimeout: l.Config.Timeout(), IdleTimeout: 60 * time.Second}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			x, c := context.WithTimeout(context.Background(), 10*time.Second)
			defer c()
			h.Shutdown(x)
		}()
		fmt.Fprintf(os.Stderr, "review-console-api listening on %s\n", l.Config.ListenAddress)
		e = h.ListenAndServe()
		if e != nil && e != http.ErrServerClosed {
			fatal("%v", e)
		}
	default:
		fatal("unknown command")
	}
}
func check(e error) {
	if e != nil {
		fatal("%v", e)
	}
}
func fatal(f string, a ...any) { fmt.Fprintf(os.Stderr, f+"\n", a...); os.Exit(1) }
