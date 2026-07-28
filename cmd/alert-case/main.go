package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
)

func main() {
	if len(os.Args) < 2 {
		fatal("usage: alert-case <check-policy|create-alert|create-alert-batch|create-case|case-event|case|alert|status|verify-alert|replay-alert|verify-case|verify-audit|migrate>")
	}
	switch os.Args[1] {
	case "check-policy":
		fs := flag.NewFlagSet("check-policy", flag.ExitOnError)
		policyPath := fs.String("policy", "", "policy JSON")
		_ = fs.Parse(os.Args[2:])
		p, err := alertcase.LoadPolicy(*policyPath)
		check(err)
		write(map[string]any{"status": "ok", "policy_id": p.PolicyID, "version": p.Version, "policy_sha256": p.PolicySHA256})
	case "create-alert":
		fs, store, input := commonStoreFlags("create-alert")
		_ = fs.Parse(os.Args[2:])
		s := loadStore(store)
		var req alertcase.CreateAlertRequest
		readJSON(*input, &req)
		out, replayed, err := s.CreateAlert(req)
		check(err)
		write(map[string]any{"alert": out, "replayed": replayed})
	case "create-alert-batch":
		fs, store, input := commonStoreFlags("create-alert-batch")
		_ = fs.Parse(os.Args[2:])
		s := loadStore(store)
		var req alertcase.CreateAlertBatchRequest
		readJSON(*input, &req)
		out, err := s.CreateAlertBatch(req)
		check(err)
		write(out)
	case "create-case":
		fs, store, input := commonStoreFlags("create-case")
		_ = fs.Parse(os.Args[2:])
		s := loadStore(store)
		var req alertcase.CreateCaseRequest
		readJSON(*input, &req)
		out, replayed, err := s.CreateCase(req)
		check(err)
		write(map[string]any{"case": out, "replayed": replayed})
	case "case-event":
		fs, store, input := commonStoreFlags("case-event")
		_ = fs.Parse(os.Args[2:])
		s := loadStore(store)
		var req alertcase.CaseEventRequest
		readJSON(*input, &req)
		projection, event, replayed, err := s.ApplyCaseEvent(req)
		check(err)
		write(map[string]any{"case": projection, "event": event, "replayed": replayed})
	case "case":
		fs, store, _ := commonStoreFlags("case")
		id := fs.String("id", "", "case ID")
		_ = fs.Parse(os.Args[2:])
		out, err := loadStore(store).Case(*id)
		check(err)
		write(out)
	case "alert":
		fs, store, _ := commonStoreFlags("alert")
		id := fs.String("id", "", "alert ID")
		_ = fs.Parse(os.Args[2:])
		out, err := loadStore(store).Alert(*id)
		check(err)
		write(out)
	case "status":
		fs, store, _ := commonStoreFlags("status")
		_ = fs.Parse(os.Args[2:])
		out, err := loadStore(store).Status()
		check(err)
		write(out)
	case "verify-alert":
		fs, store, _ := commonStoreFlags("verify-alert")
		id := fs.String("id", "", "alert ID")
		_ = fs.Parse(os.Args[2:])
		out, err := loadStore(store).VerifyAlert(*id)
		check(err)
		write(map[string]any{"status": "ok", "alert": out})
	case "replay-alert":
		fs, store, input := commonStoreFlags("replay-alert")
		id := fs.String("id", "", "expected alert ID")
		_ = fs.Parse(os.Args[2:])
		var req alertcase.CreateAlertRequest
		readJSON(*input, &req)
		out, err := loadStore(store).ReplayAlert(req, *id)
		check(err)
		write(map[string]any{"status": "exact", "alert": out})
	case "verify-case":
		fs, store, _ := commonStoreFlags("verify-case")
		id := fs.String("id", "", "case ID")
		_ = fs.Parse(os.Args[2:])
		out, err := loadStore(store).VerifyCase(*id)
		check(err)
		write(map[string]any{"status": "ok", "case": out})
	case "verify-audit":
		fs, store, _ := commonStoreFlags("verify-audit")
		_ = fs.Parse(os.Args[2:])
		count, err := loadStore(store).VerifyAudit()
		check(err)
		write(map[string]any{"status": "ok", "audit_event_count": count})
	case "migrate":
		fs := flag.NewFlagSet("migrate", flag.ExitOnError)
		dsn := fs.String("postgres-dsn", "", "PostgreSQL DSN")
		psql := fs.String("psql", "psql", "psql executable")
		_ = fs.Parse(os.Args[2:])
		sink, err := alertcase.NewPostgresSink(*dsn, *psql, nil, 30*time.Second)
		check(err)
		check(sink.Migrate(context.Background()))
		write(map[string]any{"status": "ok"})
	default:
		fatal("unknown command %q", os.Args[1])
	}
}

type storeFlags struct {
	State  *string
	Policy *string
	Stream *string
}

func commonStoreFlags(name string) (*flag.FlagSet, storeFlags, *string) {
	fs := flag.NewFlagSet(name, flag.ExitOnError)
	state := fs.String("state-dir", "", "state directory")
	policy := fs.String("policy", "", "policy JSON")
	stream := fs.String("stream-id", "alert-case-cli", "audit stream ID")
	input := fs.String("input", "", "input JSON")
	return fs, storeFlags{State: state, Policy: policy, Stream: stream}, input
}

func loadStore(flags storeFlags) *alertcase.Store {
	policy, err := alertcase.LoadPolicy(*flags.Policy)
	check(err)
	store, err := alertcase.NewStore(*flags.State, policy, *flags.Stream)
	check(err)
	return store
}

func readJSON(path string, dst any) {
	if path == "" {
		fatal("--input is required")
	}
	raw, err := os.ReadFile(path)
	check(err)
	check(json.Unmarshal(raw, dst))
}
func write(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	check(enc.Encode(v))
}
func check(err error) {
	if err != nil {
		fatal("%v", err)
	}
}
func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
