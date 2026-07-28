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

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningapiv8e"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "check":
		err = runCheck(os.Args[2:])
	case "serve":
		err = runServe(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "screening-api-v8e:", err)
		os.Exit(1)
	}
}

func configFlag(args []string, name string) (screeningapiv8e.Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	path := flags.String("config", "", "Phase 8E screening API config")
	if err := flags.Parse(args); err != nil {
		return screeningapiv8e.Config{}, err
	}
	if *path == "" {
		return screeningapiv8e.Config{}, fmt.Errorf("--config is required")
	}
	return screeningapiv8e.LoadConfig(*path)
}

func runCheck(args []string) error {
	config, err := configFlag(args, "check")
	if err != nil {
		return err
	}
	server, err := screeningapiv8e.NewServer(config)
	if err != nil {
		return err
	}
	recorder := &statusRecorder{header: http.Header{}}
	request, _ := http.NewRequest(http.MethodGet, "/healthz", nil)
	server.Handler().ServeHTTP(recorder, request)
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"config": config.ActivationStateDirectory,
		"status": "ok",
	})
}

func runServe(args []string) error {
	config, err := configFlag(args, "serve")
	if err != nil {
		return err
	}
	application, err := screeningapiv8e.NewServer(config)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           application.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errors := make(chan error, 1)
	go func() {
		errors <- server.ListenAndServe()
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case signal := <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), screeningapiv8e.ShutdownTimeout)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			return fmt.Errorf("shutdown after %s: %w", signal, err)
		}
		return nil
	case err := <-errors:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}

type statusRecorder struct {
	header http.Header
	status int
}

func (r *statusRecorder) Header() http.Header           { return r.header }
func (r *statusRecorder) Write(raw []byte) (int, error) { return len(raw), nil }
func (r *statusRecorder) WriteHeader(status int)        { r.status = status }

func usage() {
	fmt.Fprintln(os.Stderr, "usage: screening-api-v8e <check|serve> --config PATH")
	os.Exit(2)
}
