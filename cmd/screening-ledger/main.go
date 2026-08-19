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
		fatal("usage: screening-ledger <migrate|status|verify|sync|anchor|replay|export|purge|import-audit> [options]")
	}
	command := os.Args[1]
	opts, err := parseOptions(os.Args[2:])
	if err != nil {
		fatal(err.Error())
	}
	ctx := context.Background()
	switch command {
	case "migrate":
		sink := mustSink(ctx, opts)
		defer closeSink(ctx, sink)
		must(sink.Migrate(ctx))
		output(map[string]any{"status": "ok", "operation": "migrate"})
	case "status", "verify":
		store := mustStore(opts)
		policy, policySHA256, pubKeyFingerprint := mustLoadPolicy(opts)
		mode, allowGenesis := verificationSettings(opts)
		// ADR-0007 D12 (Addendum 1): every outcome other than a fully
		// checked, successful verification is now a non-nil error --
		// including "no database configured" and "no anchor row yet
		// without --allow-genesis". must() exits 1 on any of them. There
		// is no more "partial" status at exit 0: "I could not check" and
		// "I checked and it was fine" no longer share an outcome.
		var report screeningledger.AnchorVerifyResult
		if dsnEnvName := opts["--postgres-dsn-env"]; strings.TrimSpace(dsnEnvName) != "" {
			sink := mustSink(ctx, opts)
			defer closeSink(ctx, sink)
			kAnchor := mustAnchorKey(opts)
			report, err = store.VerifyAnchored(ctx, screeningledger.AnchorOptions{
				VerifyOptions: screeningledger.VerifyOptions{Policy: policy, Mode: mode, Purges: sink},
				Anchors:       sink, KAnchor: kAnchor, PolicySHA256: policySHA256, AllowGenesis: allowGenesis,
			})
			must(err)
		} else {
			report, err = store.VerifyAnchored(ctx, screeningledger.AnchorOptions{
				VerifyOptions: screeningledger.VerifyOptions{Policy: policy, Mode: mode},
				Anchors:       nil, AllowGenesis: allowGenesis,
			})
			must(err)
		}
		events, err := store.ListEvents()
		must(err)
		unreplicated := 0
		for _, event := range events {
			if !store.IsReplicated(event.EventID) {
				unreplicated++
			}
		}
		output(map[string]any{
			"status":                        "ok",
			"head":                          report.Head,
			"audit_head":                    report.AuditHead,
			"event_frozen_prefix_length":    report.EventFrozenPrefixLength,
			"audit_frozen_prefix_length":    report.AuditFrozenPrefixLength,
			"snapshot_checks_total":         report.SnapshotChecksTotal,
			"snapshot_checks_performed":     report.SnapshotChecksPerformed,
			"anchor_status":                 report.AnchorStatus,
			"anchor_sequence":               report.AnchorSequence,
			"anchor_age_seconds":            report.AnchorAgeSeconds,
			"verification_mode":             report.VerificationMode,
			"policy_public_key_fingerprint": pubKeyFingerprint,
			"event_count":                   len(events),
			"unreplicated_count":            unreplicated,
		})
	case "sync":
		store := mustStore(opts)
		sink := mustSink(ctx, opts)
		defer closeSink(ctx, sink)
		must(sink.Migrate(ctx))
		policy, policySHA256, _ := mustLoadPolicy(opts)
		mode, allowGenesis := verificationSettings(opts)
		kAnchor := mustAnchorKey(opts)
		// ADR-0007 D19/F5: sync used to mirror every unreplicated event
		// with no verification anywhere on the path, reporting "ok"
		// unconditionally. Full anchored-mode verification now runs
		// BEFORE the first Persist and aborts (must() exits 1) on
		// failure, rather than after mirroring forged rows into tables
		// an immutability trigger then makes permanent.
		verifyResult, err := store.VerifyAnchored(ctx, screeningledger.AnchorOptions{
			VerifyOptions: screeningledger.VerifyOptions{Policy: policy, Mode: mode, Purges: sink},
			Anchors:       sink, KAnchor: kAnchor, PolicySHA256: policySHA256, AllowGenesis: allowGenesis,
		})
		must(err)
		events, err := store.ListEvents()
		must(err)
		synced := 0
		verifiedAt := time.Now().UTC().Format(time.RFC3339Nano)
		verification := screeningledger.ReplicationVerification{VerifiedAt: verifiedAt, Mode: verifyResult.VerificationMode}
		for _, event := range events {
			if store.IsReplicated(event.EventID) {
				continue
			}
			request, err := store.LoadSnapshot(event.RequestSnapshotSHA256)
			must(err)
			response, err := store.LoadSnapshot(event.ResponseSnapshotSHA256)
			must(err)
			// ADR-0007 D19: verified_at/verification_mode are written in
			// the same transaction as the replication row (Persist's
			// INSERT into screening_ledger_replication) -- the row's own
			// immutability trigger means this can never be added later.
			must(sink.Persist(ctx, event, request, response, verification))
			must(store.MarkReplicated(event.EventID, ""))
			audit, err := store.AppendAudit("postgres_replicated", opts.value("--operator", "screening-ledger-cli"), "manual sync", event.EventID, nil)
			must(err)
			must(sink.PersistAudit(ctx, audit))
			synced++
		}
		output(map[string]any{"status": "ok", "synced_event_count": synced, "verification_mode": verifyResult.VerificationMode, "anchor_status": verifyResult.AnchorStatus})
	case "anchor":
		// ADR-0007 D19/F1b: the anchor's operational write path. D3
		// designed the mechanism; nothing ever called it. This
		// subcommand connects as owl_ledger_anchor through AnchorSink,
		// verifies the chain first (in the requested mode -- ordinarily
		// `anchored`, which for a ledger's very first anchor means
		// AnchorStatusAbsent, so --allow-genesis is required every time
		// that state is reached, not only "the first time": see this
		// PR's description for why that is a deliberate security
		// decision, not a formality), and only then commits the new head.
		store := mustStore(opts)
		migratorSink := mustSink(ctx, opts)
		defer closeSink(ctx, migratorSink)
		policy, policySHA256, _ := mustLoadPolicy(opts)
		mode, allowGenesis := verificationSettings(opts)
		kAnchor := mustAnchorKey(opts)
		result, err := store.VerifyAnchored(ctx, screeningledger.AnchorOptions{
			VerifyOptions: screeningledger.VerifyOptions{Policy: policy, Mode: mode, Purges: migratorSink},
			Anchors:       migratorSink, KAnchor: kAnchor, PolicySHA256: policySHA256, AllowGenesis: allowGenesis,
		})
		must(err)
		anchorDSN := os.Getenv(opts.required("--anchor-dsn-env"))
		anchorSink, err := screeningledger.NewAnchorSink(ctx, anchorDSN, opts.duration("--timeout", 30*time.Second))
		must(err)
		defer func() {
			if err := anchorSink.Close(ctx); err != nil {
				fmt.Fprintln(os.Stderr, "warning: failed to close anchor connection:", err)
			}
		}()
		must(anchorSink.WriteAnchor(ctx, kAnchor, policy.LedgerID, int64(result.Head.Sequence), result.Head.EventSHA256, result.AuditHead.EventSHA256, int64(result.AuditHead.Sequence), policySHA256))
		output(map[string]any{"status": "ok", "operation": "anchor", "sequence": result.Head.Sequence, "audit_sequence": result.AuditHead.Sequence, "policy_sha256": policySHA256})
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
		if strings.TrimSpace(opts["--postgres-dsn-env"]) != "" {
			sink := mustSink(ctx, opts)
			defer closeSink(ctx, sink)
			must(sink.PurgeExpired(ctx, before, operator, reason))
			pgPurged = true
		}
		output(map[string]any{"status": "ok", "local_snapshot_count": count, "postgres_purge_requested": pgPurged})
	case "import-audit":
		sink := mustSink(ctx, opts)
		defer closeSink(ctx, sink)
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
	ledgerDir := opts.required("--ledger-dir")
	store, err := screeningledger.NewStore(ledgerDir, key, resolveLedgerID(opts))
	must(err)
	return store
}

// resolveLedgerID is ADR-0007 D14: the CLI's "screening-ledger-cli"
// shared-literal default is removed, not changed to a different literal
// -- that default was durably written into the ledger directory on
// first use and became the HKDF salt for every derived subkey (F9), so
// any two CLI-bootstrapped ledgers that didn't pass --ledger-id shared
// K_snap/K_redact/K_chain under a common root secret. --ledger-id is
// now required, or -- per D14's stated alternative -- taken from a
// signed --policy-file, never from an unauthenticated default.
func resolveLedgerID(opts options) string {
	if id := strings.TrimSpace(opts["--ledger-id"]); id != "" {
		return id
	}
	if strings.TrimSpace(opts["--policy-file"]) != "" {
		policy, _, _ := mustLoadPolicy(opts)
		return policy.LedgerID
	}
	fatal("--ledger-id is required (ADR-0007 D14 removed the CLI's shared-literal default), or supply --policy-file so it can be taken from the signed policy")
	return ""
}

// mustLoadPolicy loads and verifies the signed verification policy ADR-0007
// D8/D10 require: the trust-root public key (EA5) is always supplied
// independently by the operator, via --policy-public-key-file/-env, and is
// NEVER read from the policy file itself -- an adversary who can replace
// the policy file could replace an embedded key too. Returns the
// authenticated policy, its canonical-form SHA-256 (D11's anchor binding),
// and the trust-root key's own fingerprint (EA5, for the CLI to report).
func mustLoadPolicy(opts options) (screeningledger.VerificationPolicy, string, string) {
	pubKey, err := screeningledger.LoadEd25519PublicKey(opts["--policy-public-key-file"], opts["--policy-public-key-env"])
	must(err)
	policy, policySHA256, err := screeningledger.LoadSignedVerificationPolicy(opts.required("--policy-file"), pubKey)
	must(err)
	return policy, policySHA256, screeningledger.PolicyPublicKeyFingerprint(pubKey)
}

// verificationSettings reads --verification-mode (default "anchored")
// and --allow-genesis (default "false", must be passed as the literal
// string "true" -- this CLI's minimal option parser has no separate
// boolean-flag shape). ADR-0007 D12/D19: --allow-genesis is required
// every time AnchorStatusAbsent is reached in anchored mode, not only
// "the first time" -- see this PR's description.
func verificationSettings(opts options) (screeningledger.VerificationMode, bool) {
	mode := screeningledger.VerificationMode(opts.value("--verification-mode", string(screeningledger.VerificationModeAnchored)))
	allowGenesis := opts.value("--allow-genesis", "false") == "true"
	return mode, allowGenesis
}

// mustAnchorKey loads K_anchor via the same LoadKey used for the
// snapshot/root key, fixing the misattributed error ADR-0007 D12 names:
// LoadKey's own error text ("snapshot encryption key is required") is
// correct for its usual caller but wrong here, where the missing key is
// K_anchor. Every call site wraps it with a name so an operator does not
// misdiagnose an anchor-key problem as a snapshot-key one.
func mustAnchorKey(opts options) []byte {
	kAnchor, err := screeningledger.LoadKey(opts["--anchor-key-file"], opts["--anchor-key-env"])
	if err != nil {
		fatal(fmt.Sprintf("anchor key (K_anchor): %s", err.Error()))
	}
	return kAnchor
}

// mustSink constructs the PostgreSQL sink from --postgres-dsn-env, which
// names an environment variable holding the DSN rather than accepting
// the DSN as a flag value directly. That is the whole of SEC-3's
// CLI-argv closure for this command (ADR-0005 §11.1, D11): a DSN passed
// as a flag lands in argv and is readable via `ps` by any local user,
// independent of the psql fork this same ADR also removes. There must
// be no `--postgres-dsn` sibling flag accepting the DSN directly --
// that reopens the exposure this flag exists to close.
//
// The DSN this names must be an identity with DDL rights on the ledger
// schema, not owl_app -- see the doc comment on
// screeningledger.PostgresSink.
func mustSink(ctx context.Context, opts options) *screeningledger.PostgresSink {
	dsn := os.Getenv(opts.required("--postgres-dsn-env"))
	sink, err := screeningledger.NewPostgresSink(ctx, dsn, opts.duration("--timeout", 30*time.Second))
	must(err)
	return sink
}

func closeSink(ctx context.Context, sink *screeningledger.PostgresSink) {
	if err := sink.Close(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "warning: failed to close PostgreSQL connection:", err)
	}
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
