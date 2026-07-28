package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/openwatchlist-labs/watchlist-platform/internal/assistanceapi"
	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: case-assistance <check|assist|record|review|status|verify-audit|models|migrate>")
	}
	switch os.Args[1] {
	case "check":
		fs := flag.NewFlagSet("check", flag.ExitOnError)
		config := fs.String("config", "", "config JSON")
		_ = fs.Parse(os.Args[2:])
		server := loadServer(*config)
		check(server.Check(context.Background()))
		write(map[string]any{"status": "ok", "snapshot_sha256": server.Store.Snapshot.SnapshotSHA256, "primary_model_id": server.Config.Models.PrimaryModelID, "reasoning_model_id": server.Config.Models.ReasoningModelID, "guardian_model_id": server.Config.Models.GuardianModelID})
	case "assist":
		fs := flag.NewFlagSet("assist", flag.ExitOnError)
		config := fs.String("config", "", "config JSON")
		input := fs.String("input", "", "request JSON")
		_ = fs.Parse(os.Args[2:])
		server := loadServer(*config)
		var req assistancerag.AssistanceRequest
		readJSON(*input, &req)
		record, replayed, err := server.Store.Assist(context.Background(), req)
		check(err)
		write(map[string]any{"assistance": record, "replayed": replayed})
	case "record":
		fs := flag.NewFlagSet("record", flag.ExitOnError)
		config := fs.String("config", "", "config JSON")
		id := fs.String("id", "", "assistance ID")
		_ = fs.Parse(os.Args[2:])
		record, err := loadServer(*config).Store.Record(*id)
		check(err)
		write(record)
	case "review":
		fs := flag.NewFlagSet("review", flag.ExitOnError)
		config := fs.String("config", "", "config JSON")
		input := fs.String("input", "", "review JSON")
		_ = fs.Parse(os.Args[2:])
		server := loadServer(*config)
		var req assistancerag.ReviewRequest
		readJSON(*input, &req)
		event, replayed, err := server.Store.Review(req)
		check(err)
		write(map[string]any{"review": event, "replayed": replayed})
	case "status":
		fs := flag.NewFlagSet("status", flag.ExitOnError)
		config := fs.String("config", "", "config JSON")
		_ = fs.Parse(os.Args[2:])
		status, err := loadServer(*config).Store.Status()
		check(err)
		write(status)
	case "verify-audit":
		fs := flag.NewFlagSet("verify-audit", flag.ExitOnError)
		config := fs.String("config", "", "config JSON")
		_ = fs.Parse(os.Args[2:])
		count, err := loadServer(*config).Store.VerifyAudit()
		check(err)
		write(map[string]any{"status": "ok", "audit_event_count": count})
	case "models":
		fs := flag.NewFlagSet("models", flag.ExitOnError)
		config := fs.String("config", "", "config JSON")
		_ = fs.Parse(os.Args[2:])
		server := loadServer(*config)
		models, err := server.Client.ListModels(context.Background())
		check(err)
		write(map[string]any{"status": "ok", "models": models})
	case "migrate":
		fs := flag.NewFlagSet("migrate", flag.ExitOnError)
		config := fs.String("config", "", "config JSON")
		_ = fs.Parse(os.Args[2:])
		server := loadServer(*config)
		if server.Postgres == nil {
			fatal("postgres_dsn is required")
		}
		check(server.Postgres.Migrate(context.Background()))
		check(server.Postgres.PersistSnapshot(context.Background(), server.Store.Snapshot))
		write(map[string]any{"status": "ok"})
	default:
		fatal("unknown command %q", os.Args[1])
	}
}
func loadServer(path string) *assistanceapi.Server {
	cfg, policy, snapshot, err := assistanceapi.LoadConfig(path)
	check(err)
	server, err := assistanceapi.New(cfg, policy, snapshot)
	check(err)
	return server
}
func readJSON(path string, dst any) {
	raw, err := os.ReadFile(path)
	check(err)
	check(json.Unmarshal(raw, dst))
}
func write(v any) { enc := json.NewEncoder(os.Stdout); enc.SetEscapeHTML(false); check(enc.Encode(v)) }
func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}
func fatal(format string, args ...any) { fmt.Fprintf(os.Stderr, format+"\n", args...); os.Exit(1) }
