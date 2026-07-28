package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
)

type options map[string]string

func main() {
	if len(os.Args) < 2 {
		fatal("usage: screening-ledger <migrate|status|verify|sync|replay|export|purge|import-audit> [options]")
	}
	command := os.Args[1]
	opts, err := parseOptions(os.Args[2:])
	if err != nil {
		fatal(err.Error())
	}
	ctx := context.Background()
	switch command {
	case "migrate":
		sink := mustSink(opts)
		must(sink.Migrate(ctx))
		output(map[string]any{"status": "ok", "operation": "migrate"})
	case "status", "verify":
		store := mustStore(opts)
		head, err := store.Verify()
		must(err)
		events, err := store.ListEvents()
		must(err)
		unreplicated := 0
		for _, event := range events {
			if !store.IsReplicated(event.EventID) {
				unreplicated++
			}
		}
		output(map[string]any{"status": "ok", "head": head, "event_count": len(events), "unreplicated_count": unreplicated})
	case "sync":
		store := mustStore(opts)
		sink := mustSink(opts)
		must(sink.Migrate(ctx))
		events, err := store.ListEvents()
		must(err)
		synced := 0
		for _, event := range events {
			if store.IsReplicated(event.EventID) {
				continue
			}
			request, err := store.LoadSnapshot(event.RequestSnapshotSHA256)
			must(err)
			response, err := store.LoadSnapshot(event.ResponseSnapshotSHA256)
			must(err)
			must(sink.Persist(ctx, event, request, response))
			must(store.MarkReplicated(event.EventID, ""))
			audit, err := store.AppendAudit("postgres_replicated", opts.value("--operator", "screening-ledger-cli"), "manual sync", event.EventID, nil)
			must(err)
			must(sink.PersistAudit(ctx, audit))
			synced++
		}
		output(map[string]any{"status": "ok", "synced_event_count": synced})
	case "replay":
		store := mustStore(opts)
		eventID := opts.required("--event-id")
		backend := opts.required("--backend-url")
		timeout := opts.duration("--timeout", 30*time.Second)
		report, err := store.Replay(ctx, eventID, backend, &http.Client{Timeout: timeout})
		must(err)
		output(report)
	case "export":
		store := mustStore(opts)
		policy := screeningledger.RetentionPolicy{
			Class:            "screening-standard",
			RetentionDays:    opts.integer("--retention-days", 2555),
			RedactKeys:       splitCSV(opts.value("--redact-keys", "account_number,iban,bic,passport_number,tax_id")),
			HashKeys:         splitCSV(opts.value("--hash-keys", "name,address,original_value")),
			MaxSnapshotBytes: opts.integer("--max-snapshot-bytes", 2*1024*1024),
		}
		manifest, err := store.ExportBundle(opts.required("--event-id"), opts.required("--output"), opts.value("--mode", "redacted"), policy)
		must(err)
		output(manifest)
	case "purge":
		store := mustStore(opts)
		before := opts.value("--before", time.Now().UTC().Format(time.RFC3339Nano))
		parsed, err := time.Parse(time.RFC3339Nano, before)
		must(err)
		operator := opts.value("--operator", "screening-ledger-cli")
		reason := opts.value("--reason", "retention expiration")
		count, err := store.PurgeExpired(parsed, operator, reason)
		must(err)
		pgPurged := false
		if strings.TrimSpace(opts["--postgres-dsn"]) != "" {
			sink := mustSink(opts)
			must(sink.PurgeExpired(ctx, before, operator, reason))
			pgPurged = true
		}
		output(map[string]any{"status": "ok", "local_snapshot_count": count, "postgres_purge_requested": pgPurged})
	case "import-audit":
		sink := mustSink(opts)
		must(sink.Migrate(ctx))
		count, err := screeningledger.ImportExternalAudit(ctx, sink, opts.value("--source", "phase8f-activation-promotion"), opts.required("--audit-directory"))
		must(err)
		output(map[string]any{"status": "ok", "imported_event_count": count})
	default:
		fatal("unknown command: " + command)
	}
}

func mustStore(opts options) *screeningledger.Store {
	key, err := screeningledger.LoadKey(opts["--key-file"], opts["--key-env"])
	must(err)
	store, err := screeningledger.NewStore(opts.required("--ledger-dir"), key, opts.value("--ledger-id", "screening-ledger-cli"))
	must(err)
	return store
}
func mustSink(opts options) *screeningledger.PostgresSink {
	dsn := opts["--postgres-dsn"]
	if dsn == "" && opts["--postgres-dsn-env"] != "" {
		dsn = os.Getenv(opts["--postgres-dsn-env"])
	}
	sink, err := screeningledger.NewPostgresSink(dsn, opts.value("--psql", "psql"), nil, opts.duration("--timeout", 30*time.Second))
	must(err)
	return sink
}
func parseOptions(args []string) (options, error) {
	out := options{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--") {
			return nil, fmt.Errorf("unexpected argument %q", args[i])
		}
		if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
			return nil, fmt.Errorf("%s requires a value", args[i])
		}
		out[args[i]] = args[i+1]
		i++
	}
	return out, nil
}
func (o options) required(name string) string {
	value := strings.TrimSpace(o[name])
	if value == "" {
		fatal(name + " is required")
	}
	return value
}
func (o options) value(name, fallback string) string {
	if strings.TrimSpace(o[name]) == "" {
		return fallback
	}
	return o[name]
}
func (o options) integer(name string, fallback int) int {
	if o[name] == "" {
		return fallback
	}
	value, err := strconv.Atoi(o[name])
	must(err)
	return value
}
func (o options) duration(name string, fallback time.Duration) time.Duration {
	if o[name] == "" {
		return fallback
	}
	value, err := time.ParseDuration(o[name])
	must(err)
	return value
}
func splitCSV(value string) []string {
	out := []string{}
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
func output(value any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	must(enc.Encode(value))
}
func must(err error) {
	if err != nil {
		fatal(err.Error())
	}
}
func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
