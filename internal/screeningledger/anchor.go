package screeningledger

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// K_anchor (ADR-0007 §5.1) is deliberately not derived from the root
// secret R that feeds deriveChainKeys -- it is an independent secret,
// loaded the same way LoadKey loads R (hex or base64, 32 bytes, from a
// file or an env var), but never through HKDF against R. Anyone who
// derives K_snap/K_redact/K_chain from R does not thereby learn
// K_anchor; that separation is what §5.3 rests the anchor's guarantee
// on.
//
// anchorMAC computes anchor_mac exactly as ADR-0007 §5.3 specifies it,
// extended by Addendum 1 D11 (policySHA256) and AR7 (auditSequence):
// HMAC-SHA256(K_anchor, ledger_id ‖ sequence ‖ event_sha256 ‖
// audit_sha256 ‖ audit_sequence ‖ policy_sha256). The ADR's concatenation
// notation does not specify a wire format; this uses a NUL-byte
// delimiter between fields so that, for example, ledger_id="a"
// sequence=1 cannot collide with ledger_id="a1" sequence=<empty> -- none
// of the inputs (a ledger id, decimal integers, hex digests) can
// themselves contain a NUL byte, so the delimiter introduces no
// ambiguity.
func anchorMAC(kAnchor []byte, ledgerID string, sequence int64, eventSHA256, auditSHA256 string, auditSequence int64, policySHA256 string) string {
	raw := strings.Join([]string{ledgerID, strconv.FormatInt(sequence, 10), eventSHA256, auditSHA256, strconv.FormatInt(auditSequence, 10), policySHA256}, "\x00")
	return macHex(kAnchor, []byte(raw))
}

// Anchor is one row of screening_ledger_anchor, read back for
// VerifyAnchored's cross-check (ADR-0007 §5.3 point 4, extended by D11
// and AR7).
//
// Sequence is the EVENT chain's sequence number at anchor time -- not the
// audit chain's, and not an independent anchor-generation counter. The
// two chains are sequenced independently (AppendAudit has four call
// sites against Append's one, so they drift), so a single column cannot
// carry both; the event chain is the one this repository's ADRs treat as
// authoritative (ADR-0007 §3.2). AuditSequence (Addendum 1 AR7) is the
// audit chain's own sequence number at the same anchor moment, added
// specifically so the audit chain gets the same continuously-checkable
// cross-check the event chain always had -- closing R7, which had
// accepted AuditSHA256 as merely supplementary evidence. PolicySHA256
// (D11) binds this row to the signed verification policy it was written
// under, so a stale, more permissive policy cannot be paired with a
// current anchor. See
// db/migrations/016_screening_ledger_anchor_sequence_comment.sql and
// db/migrations/017_screening_ledger_anchor_policy_binding.sql for the
// same statements as live schema comments.
type Anchor struct {
	LedgerID      string
	Sequence      int64
	EventSHA256   string
	AuditSHA256   string
	AuditSequence int64
	PolicySHA256  string
	AnchoredAt    time.Time
	AnchorMAC     string
}

// Verify reports whether this anchor's own anchor_mac is consistent with
// its committed fields under kAnchor -- i.e. that the row was genuinely
// written by a holder of K_anchor and has not been altered in place
// since. It does not check the row against the live chain; that is
// Store.VerifyAnchored's job.
func (a Anchor) Verify(kAnchor []byte) bool {
	return hmac.Equal([]byte(a.AnchorMAC), []byte(anchorMAC(kAnchor, a.LedgerID, a.Sequence, a.EventSHA256, a.AuditSHA256, a.AuditSequence, a.PolicySHA256)))
}

// AnchorSink writes exactly one relation, screening_ledger_anchor, and is
// deliberately not a method on PostgresSink. The whole point of D3 is
// that the anchoring identity (owl_ledger_anchor) is a different DB role
// than the ledger writer (owl_migrator, the identity PostgresSink
// connects as) -- collapsing them into one Go type would make it easy for
// a future caller to write an anchor row over the ledger-writer's
// connection by accident, silently defeating the role separation the
// schema enforces. AnchorSink has no Migrate: screening_ledger_anchor's
// DDL belongs to db/migrations/015_screening_ledger_anchor.sql and
// 017_screening_ledger_anchor_policy_binding.sql, run by owl_migrator;
// ownership itself does not stay with owl_migrator, or even with
// owl_ledger_anchor -- Addendum 1 D17 gives the table a third role,
// owl_ledger_ddl, as OWNER (nothing connects as it at runtime), so that
// owl_ledger_anchor -- the identity that actually writes at runtime --
// cannot ALTER or DROP the table's own protections (F6). Ownership
// transfer and the INSERT-only/SELECT-only grants below happen in
// scripts/ci/provision_test_roles.sh's grant-anchor-ownership step, run
// by the bootstrap superuser -- never by any of the three roles
// themselves. owl_ledger_anchor is write-only in privilege (INSERT
// only -- no SELECT/UPDATE/DELETE, no DDL, not owner). owl_migrator gets
// SELECT (only) on this table so VerifyAnchored can read anchor rows
// back for cross-checking (ADR-0007 §5.3 point 4) -- see
// grant-anchor-ownership's SELECT grant and its postcondition checks.
// owl_app gets nothing here; it is not tenant-scoped.
type AnchorSink struct {
	conn    *pgx.Conn
	timeout time.Duration
}

func NewAnchorSink(ctx context.Context, dsn string, timeout time.Duration) (*AnchorSink, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("anchor DSN is required")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	connConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	connConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(timeout.Milliseconds(), 10)

	connectCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := pgx.ConnectConfig(connectCtx, connConfig)
	if err != nil {
		return nil, err
	}
	return &AnchorSink{conn: conn, timeout: timeout}, nil
}

func (a *AnchorSink) Close(ctx context.Context) error {
	return a.conn.Close(ctx)
}

// WriteAnchor inserts one anchor row. It does not use ON CONFLICT DO
// NOTHING (CLAUDE.md's "do not swallow conflicts" trap): a primary-key
// collision on (ledger_id, sequence) means two different anchor attempts
// disagree about what was at that sequence, which must surface as an
// error, not vanish silently.
//
// This is the mechanism D3 specifies, given an operational write path by
// Addendum 1 D19's `screening-ledger anchor` subcommand. Cadence remains
// ADR-0007 §8/D6/D18's separate, future gate-PR concern.
func (a *AnchorSink) WriteAnchor(ctx context.Context, kAnchor []byte, ledgerID string, sequence int64, eventSHA256, auditSHA256 string, auditSequence int64, policySHA256 string) error {
	if len(kAnchor) != 32 {
		return errors.New("anchor key (K_anchor) must be 32 bytes")
	}
	mac := anchorMAC(kAnchor, ledgerID, sequence, eventSHA256, auditSHA256, auditSequence, policySHA256)
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	_, err := a.conn.Exec(ctx,
		`INSERT INTO screening_ledger_anchor(ledger_id,sequence,event_sha256,audit_sha256,audit_sequence,policy_sha256,anchor_mac) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		ledgerID, sequence, eventSHA256, auditSHA256, auditSequence, policySHA256, mac)
	return err
}

// AnchorReader is satisfied by *PostgresSink's LatestAnchor. It exists so
// Store.VerifyAnchored can be exercised in tests without a real
// connection and so passing nil (no database configured) is an ordinary,
// typed nil-interface check rather than a *PostgresSink-specific one.
type AnchorReader interface {
	LatestAnchor(ctx context.Context, ledgerID string) (Anchor, bool, error)
}

// AnchorVerifyStatus reports what VerifyAnchored was actually able to
// check. ADR-0007 D12 (Addendum 1) removed the nil-error "partial"
// outcomes this type used to carry for AnchorStatusUnavailable and
// AnchorStatusAbsent: those are now verification failures (a non-nil
// error) in the default `anchored` mode, exactly like AnchorStatusFailed.
// The status constants remain, populated on AnchorVerifyResult even in
// the error return, purely so a caller that wants to log or report which
// kind of failure occurred does not have to string-match the error.
type AnchorVerifyStatus string

const (
	// AnchorStatusVerified: an anchor row exists, its own MAC checks out
	// under K_anchor, its policy_sha256 matches the policy in use, and
	// its committed digests match the file chain's state at that
	// sequence -- event chain and, per AR7, audit chain both.
	AnchorStatusVerified AnchorVerifyStatus = "verified"
	// AnchorStatusUnavailable: no AnchorReader was supplied (no database
	// configured for this verify run). A failure in `anchored` mode; only
	// reachable as a non-failing status under explicitly-selected
	// `historical-unanchored` mode with the policy's allow_unanchored set.
	AnchorStatusUnavailable AnchorVerifyStatus = "unavailable"
	// AnchorStatusAbsent: the database was reachable but this ledger has
	// no anchor row yet. A failure in `anchored` mode UNLESS --allow-genesis
	// was explicitly passed (D19's genesis bootstrap carve-out, required
	// every time this status is reached, not only "the first time" -- see
	// this PR's description) or the mode is `historical-unanchored`.
	AnchorStatusAbsent AnchorVerifyStatus = "absent"
	// AnchorStatusFailed (D12, new): a genuine tamper detection -- MAC
	// invalid, policy_sha256 mismatch, tail truncation, or a digest
	// disagreement with a committed anchor -- distinguishable in the
	// result type from a plumbing error (a database connection failure,
	// for instance, leaves AnchorStatus at its zero value).
	AnchorStatusFailed AnchorVerifyStatus = "failed"
)

// AnchorVerifyResult is VerifyPolicy's report plus what the anchor
// cross-check found. AuditAnchorCoverage/"supplementary_only" (the
// pre-Addendum-1 field) is retired: AR7 makes the audit chain a
// continuously-checked invariant of VerifyAnchored exactly like the
// event chain, so there is no longer a "supplementary only" caveat to
// carry.
type AnchorVerifyResult struct {
	VerifyReport
	AnchorStatus     AnchorVerifyStatus
	AnchorSequence   int64
	VerificationMode VerificationMode
	// AnchorAgeSeconds is R11's "verify should report the age of the
	// newest anchor so the window is visible rather than assumed" --
	// nil when no anchor was found or checked.
	AnchorAgeSeconds *float64
}

// AnchorOptions is what VerifyAnchored needs beyond VerifyPolicy's own
// VerifyOptions: the anchor reader, K_anchor, the policy's own digest
// (for D11's policy_sha256 binding check), and the explicit,
// non-persistent AllowGenesis acknowledgment D12/D19 require every time
// AnchorStatusAbsent is reached in `anchored` mode.
type AnchorOptions struct {
	VerifyOptions
	Anchors      AnchorReader
	KAnchor      []byte
	PolicySHA256 string
	AllowGenesis bool
}

// VerifyAnchored is VerifyPolicy (the full file-chain check: event and
// audit, EA1-EA3, D4 frozen-prefix/genesis-boundary rules, D13 purge
// handling) plus D3's anchor cross-check, extended by D11 (policy
// binding) and AR7 (the audit-chain cross-check R7 used to accept as
// merely supplementary).
//
// Fail-closed per D12: every outcome other than a fully verified anchor
// (or an explicitly, doubly-gated relaxation -- `historical-unanchored`
// mode with the policy's allow_unanchored set, or --allow-genesis against
// a genuinely absent anchor) is a non-nil error. "I could not check" and
// "I checked and it was fine" no longer share an outcome.
//
// opts.Anchors is an interface specifically so passing nil is a real,
// checked nil -- callers must not pass a typed nil *PostgresSink through
// this field, which would not compare equal to the nil this function
// checks for.
func (s *Store) VerifyAnchored(ctx context.Context, opts AnchorOptions) (AnchorVerifyResult, error) {
	report, err := s.VerifyPolicy(ctx, opts.VerifyOptions)
	if err != nil {
		return AnchorVerifyResult{}, err
	}
	mode := opts.modeOrDefault()
	base := AnchorVerifyResult{VerifyReport: report, VerificationMode: mode}

	// The mode+policy double gate itself was already enforced by
	// VerifyPolicy above (it errors before returning if
	// historical-unanchored was requested without policy.AllowUnanchored),
	// so by this point mode == historical-unanchored implies the policy
	// agrees. This only needs to catch a mode string neither recognized
	// value.
	switch mode {
	case VerificationModeAnchored, VerificationModeHistoricalUnanchored:
	default:
		return AnchorVerifyResult{}, fmt.Errorf("unrecognized verification mode %q", mode)
	}

	if opts.Anchors == nil {
		if mode == VerificationModeHistoricalUnanchored {
			base.AnchorStatus = AnchorStatusUnavailable
			return base, nil
		}
		return AnchorVerifyResult{}, errors.New("anchored mode requires a database connection to cross-check the anchor (ADR-0007 D12): no AnchorReader was supplied")
	}

	latest, found, err := opts.Anchors.LatestAnchor(ctx, s.ledgerID)
	if err != nil {
		return AnchorVerifyResult{}, fmt.Errorf("reading latest anchor: %w", err)
	}
	if !found {
		if mode == VerificationModeHistoricalUnanchored {
			base.AnchorStatus = AnchorStatusAbsent
			return base, nil
		}
		if opts.AllowGenesis {
			base.AnchorStatus = AnchorStatusAbsent
			return base, nil
		}
		return AnchorVerifyResult{}, errors.New("anchored mode requires an existing anchor row and none was found for this ledger; pass --allow-genesis explicitly if this is genuinely a first anchor (required every time this state is reached, not only 'the first time' -- ADR-0007 D12/D19)")
	}

	if len(opts.KAnchor) != 32 {
		return AnchorVerifyResult{}, errors.New("anchor key (K_anchor) must be 32 bytes to verify an anchor row")
	}
	if !latest.Verify(opts.KAnchor) {
		base.AnchorStatus = AnchorStatusFailed
		return base, errors.New("anchor row MAC invalid under K_anchor: the row may have been altered since it was written")
	}
	if opts.PolicySHA256 != "" && latest.PolicySHA256 != opts.PolicySHA256 {
		base.AnchorStatus = AnchorStatusFailed
		return base, fmt.Errorf("anchor's policy_sha256 (%s) does not match the policy in use (%s): a policy change requires re-anchoring (ADR-0007 D11)", latest.PolicySHA256, opts.PolicySHA256)
	}

	if latest.Sequence > int64(report.Head.Sequence) {
		base.AnchorStatus = AnchorStatusFailed
		return base, fmt.Errorf("chain head (sequence %d) is behind the newest anchor (sequence %d): possible tail truncation", report.Head.Sequence, latest.Sequence)
	}
	eventAtAnchor := report.Head.EventSHA256
	if latest.Sequence != int64(report.Head.Sequence) {
		event, err := s.eventAtSequence(uint64(latest.Sequence))
		if err != nil {
			return AnchorVerifyResult{}, fmt.Errorf("reading chain state at anchored sequence %d: %w", latest.Sequence, err)
		}
		eventAtAnchor = event.EventSHA256
	}
	if eventAtAnchor != latest.EventSHA256 {
		base.AnchorStatus = AnchorStatusFailed
		return base, fmt.Errorf("chain digest at sequence %d (%s) disagrees with the anchor's committed digest (%s): possible tampering after anchoring", latest.Sequence, eventAtAnchor, latest.EventSHA256)
	}

	// AR7: the audit chain gets the same continuously-checked cross-check
	// the event chain always had -- R7, reopened, is closed here.
	if latest.AuditSequence > int64(report.AuditHead.Sequence) {
		base.AnchorStatus = AnchorStatusFailed
		return base, fmt.Errorf("audit chain head (sequence %d) is behind the newest anchor's audit_sequence (%d): possible tail truncation (AR7)", report.AuditHead.Sequence, latest.AuditSequence)
	}
	auditAtAnchor := report.AuditHead.EventSHA256
	if latest.AuditSequence != int64(report.AuditHead.Sequence) {
		auditEvent, err := s.auditEntryAtSequence(uint64(latest.AuditSequence))
		if err != nil {
			return AnchorVerifyResult{}, fmt.Errorf("reading audit chain state at anchored audit_sequence %d: %w", latest.AuditSequence, err)
		}
		auditAtAnchor = auditEvent.AuditSHA256
	}
	if auditAtAnchor != latest.AuditSHA256 {
		base.AnchorStatus = AnchorStatusFailed
		return base, fmt.Errorf("audit chain digest at sequence %d (%s) disagrees with the anchor's committed audit digest (%s): possible tampering after anchoring (AR7)", latest.AuditSequence, auditAtAnchor, latest.AuditSHA256)
	}

	base.AnchorStatus = AnchorStatusVerified
	base.AnchorSequence = latest.Sequence
	age := time.Since(latest.AnchoredAt).Seconds()
	base.AnchorAgeSeconds = &age
	return base, nil
}
