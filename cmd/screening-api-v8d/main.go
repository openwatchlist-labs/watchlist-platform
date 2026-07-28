package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningapi"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "screening-api-v8d:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: screening-api-v8d <check|serve|fixture-upstream> [flags]")
	}
	switch args[0] {
	case "check":
		flags := flag.NewFlagSet("check", flag.ContinueOnError)
		flags.SetOutput(stderr)
		configPath := flags.String("config", "", "Phase 8D config JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *configPath == "" {
			return errors.New("--config is required")
		}
		cfg, err := screeningapi.LoadPhase8DConfig(*configPath)
		if err != nil {
			return err
		}
		upstream := screeningapi.NewPhase8DHTTPUpstream(cfg.UpstreamBaseURL, &http.Client{Timeout: cfg.RequestTimeout()})
		server, err := screeningapi.NewPhase8DServer(cfg, upstream)
		if err != nil {
			return err
		}
		_ = server
		return writeJSON(stdout, map[string]any{"status": "ok", "config": *configPath})
	case "serve":
		flags := flag.NewFlagSet("serve", flag.ContinueOnError)
		flags.SetOutput(stderr)
		configPath := flags.String("config", "", "Phase 8D config JSON")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *configPath == "" {
			return errors.New("--config is required")
		}
		cfg, err := screeningapi.LoadPhase8DConfig(*configPath)
		if err != nil {
			return err
		}
		upstream := screeningapi.NewPhase8DHTTPUpstream(cfg.UpstreamBaseURL, &http.Client{Timeout: cfg.RequestTimeout()})
		application, err := screeningapi.NewPhase8DServer(cfg, upstream)
		if err != nil {
			return err
		}
		return serve(cfg.ListenAddress, application.Handler(), stderr)
	case "fixture-upstream":
		return runFixtureUpstream(args[1:], stderr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func serve(address string, handler http.Handler, stderr io.Writer) error {
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	errCh := make(chan error, 1)
	go func() {
		log.New(stderr, "", log.LstdFlags).Printf("listening on %s", address)
		errCh <- server.ListenAndServe()
	}()
	select {
	case signalValue := <-stop:
		log.New(stderr, "", log.LstdFlags).Printf("received %s", signalValue)
		ctx, cancel := context.WithTimeout(context.Background(), screeningapi.Phase8DShutdownTimeout)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func runFixtureUpstream(args []string, stderr io.Writer) error {
	flags := flag.NewFlagSet("fixture-upstream", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("listen", "127.0.0.1:18180", "listen address")
	singlePath := flags.String("single-response", "", "single response fixture")
	batchPath := flags.String("batch-response", "", "batch response fixture")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *singlePath == "" || *batchPath == "" {
		return errors.New("--single-response and --batch-response are required")
	}
	single, err := os.ReadFile(*singlePath)
	if err != nil {
		return err
	}
	batch, err := os.ReadFile(*batchPath)
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ready":true}`))
	})
	mux.HandleFunc("/v1/screenings", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(single)
	})
	mux.HandleFunc("/v1/screenings/batch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(batch)
	})
	return serve(*address, mux, stderr)
}

func writeJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
