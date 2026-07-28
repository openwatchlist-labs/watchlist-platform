package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningapiv8g"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: screening-api-v8g <check|serve> --config PATH")
	}
	command := os.Args[1]
	configPath, err := option(os.Args[2:], "--config")
	if err != nil {
		fatal(err.Error())
	}
	config, err := screeningapiv8g.LoadConfig(configPath)
	if err != nil {
		fatal(err.Error())
	}
	server, err := screeningapiv8g.NewServer(config)
	if err != nil {
		fatal(err.Error())
	}
	switch command {
	case "check":
		writeJSON(map[string]any{
			"status":            "ok",
			"instance_id":       config.InstanceID,
			"ledger_directory":  config.LedgerDirectory,
			"postgres_required": config.RequirePostgres,
		})
	case "serve":
		httpServer := &http.Server{Addr: config.ListenAddress, Handler: server.Handler()}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		go func() {
			<-ctx.Done()
			shutdown, cancel := context.WithTimeout(context.Background(), screeningapiv8g.ShutdownTimeout)
			defer cancel()
			_ = httpServer.Shutdown(shutdown)
		}()
		log.Printf("screening-api-v8g listening on %s", config.ListenAddress)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fatal(err.Error())
		}
	default:
		fatal("unknown command: " + command)
	}
}

func option(args []string, name string) (string, error) {
	for i := 0; i < len(args); i++ {
		if args[i] == name && i+1 < len(args) {
			return args[i+1], nil
		}
	}
	return "", fmt.Errorf("%s is required", name)
}
func writeJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		fatal(err.Error())
	}
}
func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
