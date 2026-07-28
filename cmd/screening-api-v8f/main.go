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

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningapiv8f"
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
		fmt.Fprintln(os.Stderr, "screening-api-v8f:", err)
		os.Exit(1)
	}
}

func loadConfig(args []string, name string) (screeningapiv8f.Config, error) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	path := flags.String("config", "", "Phase 8F screening API config")
	if err := flags.Parse(args); err != nil {
		return screeningapiv8f.Config{}, err
	}
	if *path == "" {
		return screeningapiv8f.Config{}, fmt.Errorf("--config is required")
	}
	return screeningapiv8f.LoadConfig(*path)
}

func runCheck(args []string) error {
	config, err := loadConfig(args, "check")
	if err != nil {
		return err
	}
	if _, err := screeningapiv8f.NewServer(config); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"status": "ok", "promotion_state_directory": config.PromotionStateDirectory,
		"activation_state_directory": config.ActivationStateDirectory, "instance_id": config.InstanceID,
	})
}

func runServe(args []string) error {
	config, err := loadConfig(args, "serve")
	if err != nil {
		return err
	}
	application, err := screeningapiv8f.NewServer(config)
	if err != nil {
		return err
	}
	server := &http.Server{Addr: config.ListenAddress, Handler: application.Handler(), ReadHeaderTimeout: 5 * time.Second}
	errors := make(chan error, 1)
	go func() { errors <- server.ListenAndServe() }()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	select {
	case signal := <-signals:
		ctx, cancel := context.WithTimeout(context.Background(), screeningapiv8f.ShutdownTimeout)
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

func usage() {
	fmt.Fprintln(os.Stderr, "usage: screening-api-v8f <check|serve> --config PATH")
	os.Exit(2)
}
