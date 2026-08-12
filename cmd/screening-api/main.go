package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/scoringactivation"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningapi"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "serve":
		serve(os.Args[2:])
	case "check":
		checkConfig(os.Args[2:])
	default:
		usage()
	}
}

func serve(args []string) {
	set := flag.NewFlagSet("serve", flag.ExitOnError)
	configPath := set.String("config", "configs/screening-api/local.json", "screening API configuration")
	_ = set.Parse(args)
	config, service, runtime := load(*configPath)
	defer runtime.Close()
	if service.Scoring == nil {
		// ADR-0004 §6: scoring is not optional at runtime. No
		// scoring_enabled flag -- a service that starts without scoring is
		// a service that serves unscored results forever without anyone
		// noticing.
		fatalf("scoring_activation_state_directory is required to serve")
	}
	handler := &screeningapi.Handler{Config: config, Service: service, Store: screeningapi.IdempotencyStore{Root: config.IdempotencyRoot}}
	tokens, err := screeningapi.LoadTokenService(config)
	if err != nil {
		fatalf("load token service: %v", err)
	}
	authenticated, err := screeningapi.NewAuthenticatedHandler(handler, tokens, nil)
	if err != nil {
		fatalf("construct authenticated handler: %v", err)
	}
	server := &http.Server{
		Addr:              config.ListenAddress,
		Handler:           authenticated,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       time.Duration(config.RequestTimeoutMS+5000) * time.Millisecond,
		WriteTimeout:      time.Duration(config.RequestTimeoutMS+5000) * time.Millisecond,
		IdleTimeout:       60 * time.Second,
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stop
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	fmt.Fprintf(os.Stderr, "screening-api listening on %s\n", config.ListenAddress)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		fatalf("serve screening API: %v", err)
	}
}

func checkConfig(args []string) {
	set := flag.NewFlagSet("check", flag.ExitOnError)
	configPath := set.String("config", "configs/screening-api/local.json", "screening API configuration")
	_ = set.Parse(args)
	config, service, runtime := load(*configPath)
	defer runtime.Close()
	if err := service.Ready(); err != nil {
		fatalf("screening API is not ready: %v", err)
	}
	output := map[string]any{
		"valid":              true,
		"schema_version":     config.SchemaVersion,
		"api_version":        screeningapi.APIVersion,
		"listen_address":     config.ListenAddress,
		"runtime_bindings":   len(config.RuntimeBindings),
		"max_batch_items":    config.MaxBatchItems,
		"max_candidates":     config.MaxCandidates,
		"request_timeout_ms": config.RequestTimeoutMS,
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		fatalf("encode check output: %v", err)
	}
}

func load(configPath string) (screeningapi.Config, *screeningapi.Service, *screeningapi.RuntimeManager) {
	config, err := screeningapi.LoadConfig(configPath)
	if err != nil {
		fatalf("load config: %v", err)
	}
	loader := screeningapi.FileStateLoader{CatalogRegistryPath: config.CatalogRegistryPath, MappingRegistryPath: config.MappingRegistryPath}
	state, err := loader.Load()
	if err != nil {
		fatalf("load control-plane state: %v", err)
	}
	runtime, err := screeningapi.StartRuntimeManager(context.Background(), config, state.Catalog)
	if err != nil {
		fatalf("start Rust runtime: %v", err)
	}
	service := &screeningapi.Service{Loader: loader, Runtime: runtime, MaxCandidates: config.MaxCandidates}
	// ADR-0004 §4: resolved here, beside StartRuntimeManager and before the
	// Service literal above. The field is not required by ValidateConfig --
	// "check" needs no scoring binding to validate catalog and runtime
	// wiring -- only "serve" (above) refuses to start without one.
	if strings.TrimSpace(config.ScoringActivationStateDirectory) != "" {
		manager, err := scoringactivation.NewManager(config.ScoringActivationStateDirectory)
		if err != nil {
			runtime.Close()
			fatalf("construct scoring activation manager: %v", err)
		}
		snapshot, err := manager.LoadActive()
		if err != nil {
			runtime.Close()
			fatalf("load active scoring tuple: %v", err)
		}
		if err := screeningapi.ValidateScoringRuntimeProfile(runtime, snapshot); err != nil {
			runtime.Close()
			fatalf("validate scoring runtime profile: %v", err)
		}
		binding, err := screeningapi.NewScoringBinding(snapshot)
		if err != nil {
			runtime.Close()
			fatalf("construct scoring binding: %v", err)
		}
		service.Scoring = binding
	}
	if fixed := os.Getenv("OPENWATCHLIST_SCREENING_API_FIXED_TIME"); fixed != "" {
		parsed, parseErr := time.Parse(time.RFC3339, fixed)
		if parseErr != nil {
			runtime.Close()
			fatalf("OPENWATCHLIST_SCREENING_API_FIXED_TIME must be RFC3339: %v", parseErr)
		}
		service.Clock = func() time.Time { return parsed }
	}
	return config, service, runtime
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: screening-api <serve|check> --config <path>")
	os.Exit(2)
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
