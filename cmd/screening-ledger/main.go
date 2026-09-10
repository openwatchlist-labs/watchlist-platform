package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
)

type options map[string]string

// usageMessage is ADR-0007 Addendum 14 D130's own required half of
// removing --retention-days/--max-snapshot-bytes from `export`: this CLI
// silently accepts unknown flags (R58, unfixed by this addendum), so an
// operator who keeps passing either after this change gets exactly the
// silence they got before -- the absence is visible only where an
// operator looks, which is here.
const usageMessage = `usage: screening-ledger <command> [options]

commands:
  migrate      --postgres-dsn-env <var> [--timeout <duration>]
  status       --ledger-dir <dir> --key-file|--key-env <key> --ledger-id <id> --policy-file <file> --policy-public-key-file|--policy-public-key-env <key> [--postgres-dsn-env <var>] [--anchor-key-file|--anchor-key-env <key>] [--verification-mode anchored|historical-unanchored]
  verify       (same flags as status)
  sync         --ledger-dir <dir> --key-file|--key-env <key> --ledger-id <id> --policy-file <file> --policy-public-key-file|--policy-public-key-env <key> --postgres-dsn-env <var> --anchor-key-file|--anchor-key-env <key> [--verification-mode anchored|historical-unanchored] [--operator <name>]
  anchor       --ledger-dir <dir> --key-file|--key-env <key> --ledger-id <id> --policy-file <file> --policy-public-key-file|--policy-public-key-env <key> --postgres-dsn-env <var> --anchor-key-file|--anchor-key-env <key> --anchor-dsn-env <var> [--allow-genesis true] [--verification-mode anchored|historical-unanchored]
  replay       --ledger-dir <dir> --key-file|--key-env <key> --ledger-id <id> --event-id <id> --backend-url <url> [--timeout <duration>]
  export       --ledger-dir <dir> --key-file|--key-env <key> --ledger-id <id> --event-id <id> --output <path> [--mode redacted|internal] [--redact-keys <csv>] [--hash-keys <csv>]
  purge        --ledger-dir <dir> --key-file|--key-env <key> --ledger-id <id> --policy-file <file> --policy-public-key-file|--policy-public-key-env <key> --postgres-dsn-env <var> [--before <RFC3339>] [--operator <name>] [--reason <text>]
  import-audit --postgres-dsn-env <var> [--source <name>] --audit-directory <dir>
`

func main() {
	if len(os.Args) < 2 {
		fatal(usageMessage)
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
		// ADR-0007 Addendum 2 D21 point 3: ownership is reported, not
		// enforced by Migrate() itself -- a SchemaSQL-only bootstrap
		// (owl_migrator) and a fully-provisioned deployment
		// (owl_ledger_ddl) are both valid post-Migrate states, so an
		// operator reading this output can tell which one they have.
		anchorOwner, err := sink.SchemaObjectOwner(ctx, "screening_ledger_anchor")
		must(err)
		// ADR-0007 Addendum 3 D33: the provisioning condition is reported
		// here too, on the same "reported, not enforced" basis -- a
		// SchemaSQL-only bootstrap legitimately has not run
		// scripts/ci/provision_test_roles.sh grant-ddl-ownership yet.
		// VerifyAnchored is where this condition is required, not migrate.
		provisioning, err := sink.CheckProvisioningState(ctx)
		must(err)
		output(map[string]any{
			"status":                        "ok",
			"operation":                     "migrate",
			"screening_ledger_anchor_owner": anchorOwner,
			"provisioned":                   provisioning.Provisioned,
			"provisioning_reason":           provisioning.Reason,
		})
	case "status", "verify":
		store := mustStore(opts)
		policy, policySHA256, pubKeyFingerprint := mustLoadPolicy(opts)
		mode := verificationMode(opts)
		// ADR-0007 D12 (Addendum 1): every outcome other than a fully
		// checked, successful verification is now a non-nil error --
		// including "no database configured" and "no anchor row yet
		// without --allow-genesis". must() exits 1 on any of them. There
		// is no more "partial" status at exit 0: "I could not check" and
		// "I checked and it was fine" no longer share an outcome.
		//
		// ADR-0007 Addendum 2 D24: AllowGenesis is always false here --
		// --allow-genesis has no legitimate meaning on this command (see
		// verificationMode, which rejects the flag outright), so there is
		// no way to reach AnchorStatusAbsent in anchored mode from this
		// path other than a genuine absence.
		var report screeningledger.AnchorVerifyResult
		if dsnEnvName := opts["--postgres-dsn-env"]; strings.TrimSpace(dsnEnvName) != "" {
			sink := mustSink(ctx, opts)
			defer closeSink(ctx, sink)
			kAnchor := mustAnchorKey(opts)
			report, err = store.VerifyAnchored(ctx, screeningledger.AnchorOptions{
				VerifyOptions: screeningledger.VerifyOptions{Policy: policy, Mode: mode, Purges: sink},
				Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: policySHA256,
			})
			mustVerifiedAnchor(err)
		} else {
			report, err = store.VerifyAnchored(ctx, screeningledger.AnchorOptions{
				VerifyOptions: screeningledger.VerifyOptions{Policy: policy, Mode: mode},
				Anchors:       nil,
			})
			mustVerifiedAnchor(err)
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
			// ADR-0007 Addendum 2 D24 (F-C): no longer hard-coded "ok" for
			// every nil-error outcome. Before this, a genesis-allowed run
			// and a fully anchor-verified run shared both the exit code
			// and this top-level field, separable only by reading the
			// sibling anchor_status -- exactly the field a scripted
			// caller checking only status/exit-code is least likely to
			// read. Derived from report.AnchorStatus so "anchor verified"
			// and "no anchor was found" are distinguishable here too.
			"status":                        topLevelStatus(report.AnchorStatus),
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
			// ADR-0007 Addendum 9 D82: named and counted, not just carried
			// silently -- an auditor reading this output is exactly who
			// M-E's invisibility was a defect against. Never causes
			// status/exit-code to reflect failure on its own (D70's scope
			// limit for the adjudicating pass is unchanged); a
			// single-tenant deployment that wants a non-empty list treated
			// as a failure implements that policy itself (R36).
			"out_of_scope_retention_tombstone_count":           outOfScopeCount(report.OutOfScopeRetentionTombstonesChecked, report.OutOfScopeRetentionTombstones),
			"out_of_scope_retention_tombstone_snapshot_sha256": outOfScopeSnapshotSHA256(report.OutOfScopeRetentionTombstones),
		})
	case "sync":
		store := mustStore(opts)
		sink := mustSink(ctx, opts)
		defer closeSink(ctx, sink)
		must(sink.Migrate(ctx))
		policy, policySHA256, _ := mustLoadPolicy(opts)
		mode := verificationMode(opts)
		kAnchor := mustAnchorKey(opts)
		// ADR-0007 D19/F5: sync used to mirror every unreplicated event
		// with no verification anywhere on the path, reporting "ok"
		// unconditionally. Full anchored-mode verification now runs
		// BEFORE the first Persist and aborts (must() exits 1) on
		// failure, rather than after mirroring forged rows into tables
		// an immutability trigger then makes permanent.
		//
		// ADR-0007 Addendum 2 D24: --allow-genesis has no legitimate
		// meaning on sync -- see verificationMode.
		//
		// ADR-0007 Addendum 12 D109: Store.Sync alone may defer EXACTLY
		// one condition -- a chain/mirror event COUNT shortfall for one
		// snapshot, fully accounted for by events this ledger's own
		// store already knows are unreplicated (store.IsReplicated) --
		// mirroring the backlog before re-running the SAME, unmodified
		// verification in full. Every other divergence still aborts
		// before the first Persist, exactly as before D109; status/
		// verify never see this path at all.
		verifyOpts := screeningledger.AnchorOptions{
			VerifyOptions: screeningledger.VerifyOptions{Policy: policy, Mode: mode, Purges: sink},
			Anchors:       sink, Provisioning: sink, KAnchor: kAnchor, PolicySHA256: policySHA256,
		}
		syncResult, err := store.Sync(ctx, sink, verifyOpts, opts.value("--operator", "screening-ledger-cli"))
		mustVerifiedAnchor(err)
		verifyResult := syncResult.VerifyResult
		output(map[string]any{
			"status": "ok", "synced_event_count": syncResult.SyncedEventCount,
			"deferred_verification": syncResult.DeferredReason,
			"verification_mode":     verifyResult.VerificationMode, "anchor_status": verifyResult.AnchorStatus,
			// ADR-0007 Addendum 10 D93(c): sync already runs the same
			// anchored verification status/verify do and discarded these
			// two D82 fields -- the adjudication ran, the reporting pass
			// ran, and an operator whose routine is `sync` never saw a
			// fabricated out-of-scope tombstone. sync is the command an
			// operator actually schedules; D82 exists for the auditor who
			// reads what a scheduled command prints.
			"out_of_scope_retention_tombstone_count":           outOfScopeCount(verifyResult.OutOfScopeRetentionTombstonesChecked, verifyResult.OutOfScopeRetentionTombstones),
			"out_of_scope_retention_tombstone_snapshot_sha256": outOfScopeSnapshotSHA256(verifyResult.OutOfScopeRetentionTombstones),
		})
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
		mode, allowGenesis := anchorVerificationSettings(opts)
		// ADR-0007 Addendum 2 D25 bootstrap ordering: once the signed
		// policy's floor is above zero, --allow-genesis on anchor is
		// refused too -- it would assert something the signed policy
		// already contradicts (that no anchor has ever existed, when the
		// policy itself commits to at least min_anchor_sequence having
		// been reached). A ledger's first policy necessarily carries
		// min_anchor_sequence 0, so this never blocks a genuine genesis.
		if allowGenesis && policy.MinAnchorSequence > 0 {
			fatal(fmt.Sprintf("--allow-genesis was passed but the signed policy commits to a minimum anchor sequence of %d (ADR-0007 Addendum 2 D25): a genuine genesis is only possible under a policy with min_anchor_sequence 0", policy.MinAnchorSequence))
		}
		kAnchor := mustAnchorKey(opts)
		result, err := store.VerifyAnchored(ctx, screeningledger.AnchorOptions{
			VerifyOptions: screeningledger.VerifyOptions{Policy: policy, Mode: mode, Purges: migratorSink},
			Anchors:       migratorSink, Provisioning: migratorSink, KAnchor: kAnchor, PolicySHA256: policySHA256, AllowGenesis: allowGenesis,
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
		// ADR-0007 Addendum 14 D130 (F-G, LOW): --retention-days and
		// --max-snapshot-bytes are removed rather than wired -- the
		// complete set of non-test readers of any RetentionPolicy field
		// is redact.go (RedactKeys, HashKeys) and Store.Append's own
		// retention block; ExportBundle hands this policy only to
		// RedactJSON, which reads neither. Both flags were dead on this
		// path by one mechanism (F-F's own field is one of the two), and
		// wiring a dead flag to a newly-invented meaning here is
		// inventing a contract in the implementing pass (CLAUDE.md rule
		// 7) -- removing them is the smaller, more honest change.
		store := mustStore(opts)
		policy := screeningledger.RetentionPolicy{
			Class:      "screening-standard",
			RedactKeys: splitCSV(opts.value("--redact-keys", "account_number,iban,bic,passport_number,tax_id")),
			HashKeys:   splitCSV(opts.value("--hash-keys", "name,address,original_value")),
		}
		manifest, err := store.ExportBundle(opts.required("--event-id"), opts.required("--output"), opts.value("--mode", "redacted"), policy)
		must(err)
		output(manifest)
	case "purge":
		// ADR-0007 Addendum 2 D28: --postgres-dsn-env is now required,
		// not optional. The local-only purge path this used to allow
		// (no --postgres-dsn-env given) produced the state D28 fixes:
		// PurgeExpired mutating envelopes with no independent record
		// anywhere, permanently unverifiable in anchored mode with no
		// remediation. That path ceases to exist rather than being
		// documented around.
		//
		// ADR-0007 Addendum 13 D116: a signed policy is now also
		// required, so that Tenancy -- an Ed25519-signed fact this CLI
		// cannot fabricate -- reaches PurgeExpired before it ever calls
		// the server's now-global corroboration.
		store := mustStore(opts)
		sink := mustSink(ctx, opts)
		defer closeSink(ctx, sink)
		policy, _, _ := mustLoadPolicy(opts)
		before := opts.value("--before", time.Now().UTC().Format(time.RFC3339Nano))
		parsed, err := time.Parse(time.RFC3339Nano, before)
		must(err)
		operator := opts.value("--operator", "screening-ledger-cli")
		reason := opts.value("--reason", "retention expiration")
		count, err := store.PurgeExpired(ctx, parsed, operator, reason, policy.Tenancy, sink)
		must(err)
		output(map[string]any{"status": "ok", "local_snapshot_count": count})
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

// verificationMode reads --verification-mode (default "anchored") for
// status/verify/sync. ADR-0007 Addendum 2 D24: --allow-genesis has no
// legitimate meaning on any of these -- its only effect, before this fix,
// was converting AnchorStatusAbsent (the exact and only signature of an
// anchor-table wipe) into success on verify. Passing it here is now an
// error rather than a silently ignored flag: silently ignoring it would
// leave a monitoring job holding a flag that looks load-bearing and does
// nothing, the same silent-absence shape this ADR exists to remove.
func verificationMode(opts options) screeningledger.VerificationMode {
	if _, present := opts["--allow-genesis"]; present {
		fatal("--allow-genesis has no effect on this command (ADR-0007 Addendum 2 D24) -- it is meaningful only on `anchor`, where it acknowledges a genuine first anchor")
	}
	return screeningledger.VerificationMode(opts.value("--verification-mode", string(screeningledger.VerificationModeAnchored)))
}

// anchorVerificationSettings reads --verification-mode and
// --allow-genesis (default "false", must be passed as the literal string
// "true" -- this CLI's minimal option parser has no separate boolean-flag
// shape), for `anchor` only -- the one command D24 leaves this flag on.
// ADR-0007 D12/D19: --allow-genesis is required every time
// AnchorStatusAbsent is reached in anchored mode, not only "the first
// time" -- see this PR's description.
func anchorVerificationSettings(opts options) (screeningledger.VerificationMode, bool) {
	mode := screeningledger.VerificationMode(opts.value("--verification-mode", string(screeningledger.VerificationModeAnchored)))
	allowGenesis := opts.value("--allow-genesis", "false") == "true"
	return mode, allowGenesis
}

// topLevelStatus is ADR-0007 Addendum 2 D24 (F-C): the top-level "status"
// field on status/verify's output, derived from the anchor status rather
// than hard-coded "ok" for every nil-error outcome.
func topLevelStatus(anchorStatus screeningledger.AnchorVerifyStatus) string {
	if anchorStatus == screeningledger.AnchorStatusVerified {
		return "ok"
	}
	return string(anchorStatus)
}

// outOfScopeSnapshotSHA256 is ADR-0007 Addendum 9 D82: names, not merely
// counts, every reported out-of-scope tombstone -- an auditor reading
// this output needs the snapshot identity to investigate, not only how
// many there are.
func outOfScopeSnapshotSHA256(records []screeningledger.TombstoneRecord) []string {
	names := make([]string, len(records))
	for i, r := range records {
		names[i] = r.SnapshotSHA256
	}
	return names
}

// outOfScopeCount is ADR-0007 Addendum 11 D101(a): emits the explicit
// not-checked marker rather than the number 0 when
// OutOfScopeRetentionTombstonesChecked says the reporting pass never
// ran -- a plain len() here is exactly what let a not-checked run and a
// genuinely clean one both print 0, distinguishable only by a reader
// correlating this field against anchor_status (D93's own finding,
// D24's lesson one field over).
func outOfScopeCount(status screeningledger.OutOfScopeCheckStatus, records []screeningledger.TombstoneRecord) any {
	if status == screeningledger.OutOfScopeCheckNotPerformed {
		return "not-checked"
	}
	return len(records)
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

// mustVerifiedAnchor is ADR-0007 Addendum 14 D128 (F-D, MEDIUM): status,
// verify and sync all reach screeningledger.ErrAnchorGenesisRequired
// through VerifyAnchored/Sync, and that error's own text names
// --allow-genesis -- a flag valid on exactly one subcommand, `anchor`
// (D24 already refuses it on these three by name, separately, before
// this ever runs). The caller is the only party that knows which
// subcommand it is, so it renders the remedy here rather than printing
// VerifyAnchored's own message verbatim; `anchor`'s own call site still
// uses plain must(err), so this sentinel's Error() text -- unchanged
// from before this addendum -- is exactly what `anchor` prints.
func mustVerifiedAnchor(err error) {
	if err == nil {
		return
	}
	if errors.Is(err, screeningledger.ErrAnchorGenesisRequired) {
		fatal("anchored mode requires an existing anchor row and none was found for this ledger; this command has no --allow-genesis flag -- write the ledger's first anchor with `screening-ledger anchor --anchor-dsn-env <VAR> --allow-genesis true` (the flag requires an explicit value, e.g. \"true\" -- a bare --allow-genesis is refused separately) and re-run this command (ADR-0007 Addendum 14 D128)")
	}
	fatal(err.Error())
}
func fatal(message string) {
	fmt.Fprintln(os.Stderr, message)
	os.Exit(1)
}
