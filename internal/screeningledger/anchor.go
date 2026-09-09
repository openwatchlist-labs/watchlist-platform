package screeningledger

import (
	"context"
	"crypto/hmac"
	"encoding/json"
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
// extended by Addendum 1 D11 (policySHA256), AR7 (auditSequence) and
// Addendum 10 D88 (anchoredAt): HMAC-SHA256(K_anchor, ledger_id ‖
// sequence ‖ event_sha256 ‖ audit_sha256 ‖ audit_sequence ‖
// policy_sha256 ‖ anchored_at). The ADR's concatenation notation does
// not specify a wire format; this uses a NUL-byte delimiter between
// fields so that, for example, ledger_id="a" sequence=1 cannot collide
// with ledger_id="a1" sequence=<empty> -- none of the inputs (a ledger
// id, decimal integers, hex digests, an RFC3339Nano UTC timestamp) can
// themselves contain a NUL byte, so the delimiter introduces no
// ambiguity.
//
// D88: before this addendum, anchored_at was outside this MAC's input
// entirely -- a genuine row with its timestamp moved still verified
// (measured by execution). anchoredAt must be formatted identically at
// write time and at verify time for the MAC to reconcile: both call
// sites format via anchoredAtMACString (anchoredAt.UTC().Format(time.
// RFC3339Nano)), so a location difference between the writing
// connection (owl_ledger_anchor) and the reading one (owl_migrator)
// cannot silently change what this function hashes.
func anchorMAC(kAnchor []byte, ledgerID string, sequence int64, eventSHA256, auditSHA256 string, auditSequence int64, policySHA256 string, anchoredAt time.Time) string {
	raw := strings.Join([]string{ledgerID, strconv.FormatInt(sequence, 10), eventSHA256, auditSHA256, strconv.FormatInt(auditSequence, 10), policySHA256, anchoredAtMACString(anchoredAt)}, "\x00")
	return macHex(kAnchor, []byte(raw))
}

// anchoredAtMACString is the single, shared serialization anchorMAC uses
// for anchored_at -- see anchorMAC's own comment on why write and verify
// must agree on it exactly.
func anchoredAtMACString(anchoredAt time.Time) string {
	return anchoredAt.UTC().Format(time.RFC3339Nano)
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
	return hmac.Equal([]byte(a.AnchorMAC), []byte(anchorMAC(kAnchor, a.LedgerID, a.Sequence, a.EventSHA256, a.AuditSHA256, a.AuditSequence, a.PolicySHA256, a.AnchoredAt)))
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
//
// ADR-0007 Addendum 10 D88(b): anchored_at is now part of anchorMAC's
// input, which means Go must know its exact value before computing the
// MAC -- the column's own DEFAULT clock_timestamp() (db/migrations/015)
// is no longer usable for that, since a DEFAULT is resolved by Postgres
// only at INSERT execution, after any MAC over it would already need to
// have been computed. This resolves anchored_at with a first round trip
// (SELECT clock_timestamp() on this same connection -- Postgres's own
// clock, not time.Now(), so this introduces no new cross-clock
// comparison: D70/D81/D89 all rest on anchored_at and purged_at being
// the same clock domain, and this keeps it that way) and then supplies
// it explicitly in the INSERT rather than relying on the DEFAULT, which
// becomes unreachable for this call site but is left in the schema
// (harmless: nothing else INSERTs this table).
func (a *AnchorSink) WriteAnchor(ctx context.Context, kAnchor []byte, ledgerID string, sequence int64, eventSHA256, auditSHA256 string, auditSequence int64, policySHA256 string) error {
	if len(kAnchor) != 32 {
		return errors.New("anchor key (K_anchor) must be 32 bytes")
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	var anchoredAt time.Time
	if err := a.conn.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&anchoredAt); err != nil {
		return fmt.Errorf("resolving anchored_at from Postgres's own clock (ADR-0007 Addendum 10 D88): %w", err)
	}
	mac := anchorMAC(kAnchor, ledgerID, sequence, eventSHA256, auditSHA256, auditSequence, policySHA256, anchoredAt)
	_, err := a.conn.Exec(ctx,
		`INSERT INTO screening_ledger_anchor(ledger_id,sequence,event_sha256,audit_sha256,audit_sequence,policy_sha256,anchor_mac,anchored_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		ledgerID, sequence, eventSHA256, auditSHA256, auditSequence, policySHA256, mac, anchoredAt)
	return err
}

// AnchorReader is satisfied by *PostgresSink's LatestAnchor. It exists so
// Store.VerifyAnchored can be exercised in tests without a real
// connection and so passing nil (no database configured) is an ordinary,
// typed nil-interface check rather than a *PostgresSink-specific one.
type AnchorReader interface {
	LatestAnchor(ctx context.Context, ledgerID string) (Anchor, bool, error)
	// PreviousAnchorAt is ADR-0007 Addendum 9 D81, extended by Addendum 10
	// D88(a): this ledger's anchor row with the largest Sequence strictly
	// less than beforeSequence -- the row loadPurgeLowerBoundSource
	// derives the exclusive lower bound purgeAttributionMismatch compares
	// a tombstone's purged_at against, in the same clock domain the upper
	// bound (the anchor being verified) already uses. found is false
	// exactly when beforeSequence names the first anchor in the chain, in
	// which case the genesis fallback (D89's chain-authenticated
	// expires_at floor) applies instead.
	//
	// D88's own finding: before this addendum, PreviousAnchorAt returned
	// only anchored_at, read by nothing that MAC-verified it -- a row at
	// the queried sequence was read and trusted regardless of whether it
	// was ever written by a K_anchor holder. Returning the whole row lets
	// the caller (loadPurgeLowerBoundSource) verify it under K_anchor
	// before using anything from it; this method itself does not
	// verify -- it has no K_anchor to verify with, by the same
	// architectural choice AnchorSink/PostgresSink already make
	// throughout this file (K_anchor is never stored on a sink, only
	// threaded through call parameters at the point of use).
	PreviousAnchorAt(ctx context.Context, ledgerID string, beforeSequence int64) (anchor Anchor, found bool, err error)
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

// ProvisioningStateReader is ADR-0007 Addendum 3 D33: satisfied by
// *PostgresSink's CheckProvisioningState. A separate interface from
// AnchorReader (rather than folding provisioning-state reading into it)
// so a caller that wires a fake AnchorReader for a test does not
// silently also fake provisioning as always-true.
type ProvisioningStateReader interface {
	CheckProvisioningState(ctx context.Context) (ProvisioningState, error)
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
	// Provisioning (ADR-0007 Addendum 3 D33) is required whenever Anchors
	// is non-nil: a verification run against a database whose D26/D34
	// protections and D17/D27 role separation were never installed is
	// exactly the "I could not check" outcome D12 exists to remove, and
	// must not share an exit code with "I checked and it was fine." nil
	// is a checked nil, same discipline as Anchors (anchor.go's existing
	// comment on why that interface exists at all).
	Provisioning ProvisioningStateReader
}

// purgeExpiredAuditDetails is ADR-0007 Addendum 3 D32: the shape
// Store.PurgeExpired (replay.go) writes into an AuditEvent's Details for
// action "purge_expired" -- the sorted, deduplicated set of snapshot
// sha256 values that purge attested to. It replaces the previous
// "snapshot_count" integer: a count cannot be adjudicated against a
// specific PurgeClaim, and Details is already inside the audit chain's
// own HMAC digest (hashAudit marshals the whole AuditEvent), so this
// costs no format change to the chain itself.
type purgeExpiredAuditDetails struct {
	SnapshotSHA256 []string `json:"snapshot_sha256"`
}

// attestingAuditEntries walks the audit chain once and returns, per
// snapshot sha256, the lowest-sequence AuditEvent whose action is
// "purge_expired" and whose Details name it -- any attesting entry
// satisfies condition 1; the lowest is what a caller would want reported
// if this ever needs to explain itself, and comparing the lowest against
// the anchor is a strictly harder bar to clear than comparing an
// arbitrary one. Factored out of adjudicatePurgeClaims (ADR-0007
// Addendum 8 D70) because both the forward and the reverse direction
// below need the full AuditEvent, not merely the sequence the pre-D70
// attestedAt map carried -- D70's forward comparison needs Operator and
// Reason too.
func (s *Store) attestingAuditEntries() (map[string]AuditEvent, error) {
	entries, err := s.readAuditEntries()
	if err != nil {
		return nil, fmt.Errorf("reading audit chain for purge-claim adjudication (ADR-0007 Addendum 3 D32): %w", err)
	}
	attesting := map[string]AuditEvent{}
	for _, entry := range entries {
		if entry.Action != "purge_expired" || len(entry.Details) == 0 {
			continue
		}
		var details purgeExpiredAuditDetails
		if err := json.Unmarshal(entry.Details, &details); err != nil {
			continue
		}
		for _, sha := range details.SnapshotSHA256 {
			if existing, ok := attesting[sha]; !ok || entry.Sequence < existing.Sequence {
				attesting[sha] = entry
			}
		}
	}
	return attesting, nil
}

// purgeAttributionMismatch is ADR-0007 Addendum 8 D70's forward
// comparison, shared by the forward (per-claim) and reverse (per-row)
// loops below: the tombstone row's operator and reason must equal the
// attesting audit entry's, and purged_at is compared against the
// anchor's own AnchoredAt as an ordering bound, never for equality --
// the tombstone's clock_timestamp() and the audit entry's OccurredAt are
// different clocks (a Go process's time.Now() vs. Postgres's own), and
// an equality (or a bound against OccurredAt at all) would be a
// false-failure generator under ordinary clock skew, D45's own
// pre-declared shape to never become. AnchoredAt is the same clock
// domain as purged_at -- both are Postgres clock_timestamp() values from
// the same database -- and a legitimately anchored purge is always
// written (Store.PurgeExpired: RecordPurge, then AppendAudit) before the
// anchor that later attests to it, so PurgedAt must not be after
// AnchoredAt regardless of any Go-process/Postgres clock skew.
//
// ADR-0007 Addendum 9 D81: lowerBound is the exclusive floor in that same
// clock domain -- the anchored_at of the anchor immediately preceding
// the one being verified, or, at genesis (no preceding anchor exists),
// the purged snapshot's own screening_ledger_snapshot.created_at. D70
// bounded purged_at above and left it unbounded below, which is exactly
// the half a retention claim ("purged within N days") is actually stated
// in -- a tombstone backdated to any date after the lower bound verified
// clean before this addendum. The true window is exactly
// (lowerBound, anchoredAt], both endpoints in Postgres's own clock: this
// introduces no new cross-clock comparison on either side.
func purgeAttributionMismatch(record TombstoneRecord, entry AuditEvent, anchoredAt, lowerBound time.Time) error {
	if entry.Operator != record.Operator || entry.Reason != record.Reason {
		return fmt.Errorf("tombstone row for snapshot %s (operator=%q reason=%q) does not match its attesting audit entry (operator=%q reason=%q) (ADR-0007 Addendum 8 D70): possible forged retention attribution", record.SnapshotSHA256, record.Operator, record.Reason, entry.Operator, entry.Reason)
	}
	if record.PurgedAt.After(anchoredAt) {
		return fmt.Errorf("tombstone row for snapshot %s has purged_at %s, after the anchor's own anchored_at %s (ADR-0007 Addendum 8 D70): a purge cannot postdate the anchor that attests to it", record.SnapshotSHA256, record.PurgedAt.Format(time.RFC3339Nano), anchoredAt.Format(time.RFC3339Nano))
	}
	if !record.PurgedAt.After(lowerBound) {
		return fmt.Errorf("tombstone row for snapshot %s has purged_at %s, at or before %s (ADR-0007 Addendum 9 D81): a purge cannot predate the anchor immediately preceding the one that attests to it (or, for a ledger's first anchor, the purged snapshot's own creation)", record.SnapshotSHA256, record.PurgedAt.Format(time.RFC3339Nano), lowerBound.Format(time.RFC3339Nano))
	}
	return nil
}

// purgeLowerBoundSource is ADR-0007 Addendum 9 D81, redesigned by
// Addendum 10 D88/D89: lowerBound(snapshot S, attesting anchor A) =
// max(expiresAt(S), previousAnchoredAt(A)) -- expiresAt(S) always
// applies (D89: screening_ledger_event.expires_at for the event that
// references S, chain-authenticated and corroborated against the
// mirror); previousAnchoredAt(A) applies only when a MAC-verified
// anchor immediately precedes A (D88(a): PreviousAnchorAt's row is
// verified here, once, before any value from it is used -- a
// verification failure is a named, hard failure, never a silent
// fall-through to genesis).
//
// D89 withdraws SnapshotCreatedAt as a referent entirely: it is a
// Go-supplied envelope field on an unprotected relation, covered by no
// MAC anywhere, and protecting the relation does not fix that (see D89's
// own text in docs/adr/0007-audit-chain-integrity.md -- both grounds
// were measured, not assumed). It must not be reinstated in any form.
//
// ADR-0007 Addendum 11 D96/D97: a snapshot's chain-authenticated
// Event.ExpiresAt is not one value, it is a set -- the same content can
// be screened more than once, under different retention policies, and
// every referencing event places its own independent obligation on the
// bytes. snapshotObligation is that set, reduced to what D97's rule
// needs: how many chain events reference the snapshot (compared against
// the mirror's row count, so cardinality is corroborated and not only
// value -- D76's "no member of the comparison may be weaker") and the
// MAXIMUM of their ExpiresAt (the latest promise the chain carries,
// D97's own justification: destroying the bytes when the shortest
// promise expires breaks the longer one).
type snapshotObligation struct {
	count int
	max   time.Time
}

type purgeLowerBoundSource struct {
	previousAnchoredAt time.Time
	hasPrevious        bool
	// obligationsBySnapshot is this ledger's own local, chain-
	// authenticated Event chain reduced to one snapshotObligation per
	// request/response snapshot sha256, read once
	// (loadPurgeLowerBoundSource) since it does not vary per claim/row.
	// Built from ListEvents(), which is this ledger's own directory, so
	// the population is implicitly scoped to this ledger by
	// construction -- the per-ledger half of D98's deliberate
	// floor/eligibility asymmetry (R43).
	obligationsBySnapshot map[string]snapshotObligation
}

func loadPurgeLowerBoundSource(ctx context.Context, store *Store, anchors AnchorReader, kAnchor []byte, ledgerID string, anchorSequence int64) (purgeLowerBoundSource, error) {
	anchor, hasPrevious, err := anchors.PreviousAnchorAt(ctx, ledgerID, anchorSequence)
	if err != nil {
		return purgeLowerBoundSource{}, fmt.Errorf("reading the anchor preceding sequence %d (ADR-0007 Addendum 9 D81): %w", anchorSequence, err)
	}
	var previousAnchoredAt time.Time
	if hasPrevious {
		// ADR-0007 Addendum 10 D88(a): verified here, once, rather than
		// trusted because it was returned by a query at the right
		// sequence -- a row PreviousAnchorAt selects is otherwise read by
		// no MAC check anywhere (D88's own finding).
		if len(kAnchor) != 32 {
			return purgeLowerBoundSource{}, errors.New("anchor key (K_anchor) must be 32 bytes to verify the anchor preceding this one (ADR-0007 Addendum 10 D88)")
		}
		if !anchor.Verify(kAnchor) {
			return purgeLowerBoundSource{}, fmt.Errorf("the anchor preceding sequence %d (its own sequence %d) failed MAC verification under K_anchor (ADR-0007 Addendum 10 D88): the row may have been planted or altered since it was written", anchorSequence, anchor.Sequence)
		}
		previousAnchoredAt = anchor.AnchoredAt
	}
	events, err := store.ListEvents()
	if err != nil {
		return purgeLowerBoundSource{}, fmt.Errorf("reading local event chain for the chain-authenticated expiry floor (ADR-0007 Addendum 10 D89): %w", err)
	}
	obligations, err := computeSnapshotObligations(events)
	if err != nil {
		return purgeLowerBoundSource{}, err
	}
	return purgeLowerBoundSource{previousAnchoredAt: previousAnchoredAt, hasPrevious: hasPrevious, obligationsBySnapshot: obligations}, nil
}

// computeSnapshotObligations is ADR-0007 Addendum 11 D97's reduction of
// a local event chain to one snapshotObligation per referenced sha256,
// factored out so ADR-0007 Addendum 12 D107's purge-time corroboration
// (replay.go, Store.PurgeExpired) computes the SAME aggregate
// forSnapshot verifies with, rather than a second, independently
// written reduction that could drift from it.
func computeSnapshotObligations(events []Event) (map[string]snapshotObligation, error) {
	obligations := make(map[string]snapshotObligation, len(events)*2)
	for _, e := range events {
		expiresAt, err := time.Parse(time.RFC3339Nano, e.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("parsing chain-authenticated expires_at %q for event %s (ADR-0007 Addendum 11 D97): %w", e.ExpiresAt, e.EventID, err)
		}
		// ADR-0007 Addendum 11 D102, corrected by Addendum 12 D105(c):
		// truncated once, here, to the same precision the mirror's
		// timestamptz column carries -- the truncated value is both what
		// is compared against the mirror below AND what a caller later
		// uses as the lower bound, so the two can never diverge on
		// precision alone. Before D105, this was true only in belief: the
		// mirror wrote a TEXT LITERAL through a ::timestamptz cast, which
		// the server rounds half-to-even rather than truncating, so this
		// Truncate and the mirror's actual stored value disagreed on
		// 4,995 of every 9,999 nanosecond values (D104's measurement).
		// D105(a) moves the reduction to the point Event.ExpiresAt is
		// created (mustExpires) and D105(b) binds it to the mirror as a
		// typed parameter with no server-side parser on the path, so this
		// Truncate is now provably the SAME function of the SAME value
		// the write path already applied -- this comment's claim is true
		// by construction, not merely intended.
		expiresAt = expiresAt.Truncate(time.Microsecond)
		// A single event may reference the same sha through both its
		// request and response columns (request bytes == response
		// bytes); the mirror counts that as ONE row (a single OR-matched
		// screening_ledger_event row), so this must count it once too --
		// a set of the distinct sha values this one event references,
		// not one increment per column.
		refs := make(map[string]struct{}, 2)
		if e.RequestSnapshotSHA256 != "" {
			refs[e.RequestSnapshotSHA256] = struct{}{}
		}
		if e.ResponseSnapshotSHA256 != "" {
			refs[e.ResponseSnapshotSHA256] = struct{}{}
		}
		for sha := range refs {
			o := obligations[sha]
			o.count++
			if o.count == 1 || expiresAt.After(o.max) {
				o.max = expiresAt
			}
			obligations[sha] = o
		}
	}
	return obligations, nil
}

// MirrorChainCountDivergence is ADR-0007 Addendum 12 D109: forSnapshot's
// count-mismatch outcome, typed so a caller (sync) can distinguish it
// programmatically from every other verification failure -- errors.As,
// not string matching -- and, when MirrorCount is strictly less than
// ChainCount (a shortfall, not an overage), check whether it is
// EXACTLY the narrow, accounted-for shape D109 permits deferring: every
// missing row corresponds to an event this ledger's own store already
// knows is unreplicated. The max-mismatch outcome deliberately stays a
// plain, untyped error -- D109's own scope: "every other divergence...
// still aborts before the first Persist, unchanged," and a max
// disagreement on a row that IS mirrored is explicitly one of D112 item
// 6's required negatives.
type MirrorChainCountDivergence struct {
	SnapshotSHA256 string
	MirrorCount    int
	ChainCount     int
}

func (e *MirrorChainCountDivergence) Error() string {
	return fmt.Sprintf("snapshot %s's mirror screening_ledger_event row count (%d, this ledger) disagrees with the chain-authenticated event count referencing it (%d) (ADR-0007 Addendum 10 D89 / Addendum 11 D97): mirror/chain divergence", e.SnapshotSHA256, e.MirrorCount, e.ChainCount)
}

// MirrorEventReader is satisfied by *PostgresSink.
// MirroredEventIDsForSnapshot is the one new read
// ShortfallExplainedByUnreplicatedEvents needs (ADR-0007 Addendum 13
// D120): the role already holds SELECT on screening_ledger_event
// (ForeignLedgerIDs's own justification, and the standard
// D33/D41/D45/D59/D68/D76 each held to), so this is a query the sink
// can already run, not a new grant.
type MirrorEventReader interface {
	MirroredEventIDsForSnapshot(ctx context.Context, snapshotSHA256, ledgerID string) ([]string, error)
}

// ShortfallExplainedByUnreplicatedEvents is ADR-0007 Addendum 12 D109's
// discriminator, corrected by ADR-0007 Addendum 13 D120 (F-F, MEDIUM):
// the design's own text (0007:11745-11751) states the deferral applies
// when the missing rows correspond ONE-FOR-ONE to events for which
// IsReplicated is false. The shipped implementation instead computed
// replicatedCount == div.MirrorCount -- an arithmetic identity between
// two TOTALS, which a count cannot express one-for-one with: a shortfall
// covering one crash-mid-step event (mirrored, not yet marked replicated)
// plus one honest backlog event (neither) can produce the same totals as
// a shortfall covering one event MarkReplicated already (wrongly) marked
// replicated -- two different anomalies, only one of which is safe to
// defer, indistinguishable by count alone. This computes the actual
// MISSING SET -- this ledger's own chain event ids referencing
// div.SnapshotSHA256, minus the mirror's own event ids for it (the one
// new read, reader) -- and defers if and only if that set is non-empty
// and EVERY member has IsReplicated == false. "Every member" is
// load-bearing: this is the one condition sync may defer; a shortfall
// covering even one event MarkReplicated already recorded as replicated
// is a genuinely different anomaly and this returns false for it, same
// as it does for an overage or a max-only disagreement (which never
// reaches here at all -- MirrorChainCountDivergence is the count branch
// only).
func (s *Store) ShortfallExplainedByUnreplicatedEvents(ctx context.Context, reader MirrorEventReader, div *MirrorChainCountDivergence) (bool, error) {
	if div.MirrorCount >= div.ChainCount {
		return false, nil
	}
	events, err := s.ListEvents()
	if err != nil {
		return false, err
	}
	mirroredIDs, err := reader.MirroredEventIDsForSnapshot(ctx, div.SnapshotSHA256, s.ledgerID)
	if err != nil {
		return false, err
	}
	mirrored := make(map[string]bool, len(mirroredIDs))
	for _, id := range mirroredIDs {
		mirrored[id] = true
	}
	missing := 0
	for _, e := range events {
		if e.RequestSnapshotSHA256 != div.SnapshotSHA256 && e.ResponseSnapshotSHA256 != div.SnapshotSHA256 {
			continue
		}
		if mirrored[e.EventID] {
			continue
		}
		missing++
		if s.IsReplicated(e.EventID) {
			// A missing row this store's own chain claims IS already
			// replicated is not the accounted-for shape D109 permits
			// deferring -- a genuinely different anomaly.
			return false, nil
		}
	}
	return missing > 0, nil
}

// forSnapshot is D89's rule, generalised by D97/D96 row 16/18 to the
// population D89 did not ask about: the chain's own MAX(Event.ExpiresAt)
// over every local event referencing this snapshot is the authority
// (inside hashEvent's MAC under K_chain, committed under K_anchor
// through the anchor's event_sha256 -- the same termination D70's
// operator/reason comparison already enjoys). The mirror's count and
// MAX(screening_ledger_event.expires_at), scoped to this ledger, is
// corroboration: both must agree with the chain's own count and maximum,
// and a disagreement on EITHER is a named failure reporting mirror/chain
// divergence -- never silently resolved either way, and the mirror value
// is never promoted to the authority (D89's own stated caution, carried
// forward verbatim by D97(d)). Comparing the maximum alone would leave
// the count as an unprotected weaker member (D97(c)/D76): a mirror row
// rewritten to any value below the true maximum would otherwise be
// invisible as long as some other row still carried it.
func (b purgeLowerBoundSource) forSnapshot(ctx context.Context, purges PurgeChecker, ledgerID, snapshotSHA256 string) (time.Time, error) {
	obligation, ok := b.obligationsBySnapshot[snapshotSHA256]
	if !ok {
		return time.Time{}, fmt.Errorf("snapshot %s has a purge claim or tombstone row but no local event chain entry references it (ADR-0007 Addendum 10 D89): mirror/ledger divergence", snapshotSHA256)
	}
	mirrorCount, mirrorMax, found, err := purges.EventExpiresAggregateForSnapshot(ctx, snapshotSHA256, ledgerID)
	if err != nil {
		return time.Time{}, fmt.Errorf("reading mirror screening_ledger_event aggregate for %s (ADR-0007 Addendum 11 D97): %w", snapshotSHA256, err)
	}
	if !found {
		return time.Time{}, fmt.Errorf("snapshot %s has a chain-authenticated event but no mirror screening_ledger_event row references it (ADR-0007 Addendum 10 D89): mirror/ledger divergence", snapshotSHA256)
	}
	if mirrorCount != obligation.count {
		return time.Time{}, &MirrorChainCountDivergence{SnapshotSHA256: snapshotSHA256, MirrorCount: mirrorCount, ChainCount: obligation.count}
	}
	if !mirrorMax.Equal(obligation.max) {
		return time.Time{}, fmt.Errorf("snapshot %s's mirror screening_ledger_event MAX(expires_at) (%s, this ledger) disagrees with the chain-authenticated MAX(Event.ExpiresAt) (%s) (ADR-0007 Addendum 10 D89 / Addendum 11 D97): mirror/chain divergence", snapshotSHA256, mirrorMax.Format(time.RFC3339Nano), obligation.max.Format(time.RFC3339Nano))
	}
	lowerBound := obligation.max
	if b.hasPrevious && b.previousAnchoredAt.After(lowerBound) {
		lowerBound = b.previousAnchoredAt
	}
	return lowerBound, nil
}

// adjudicatePurgeClaims is ADR-0007 Addendum 3 D32's adjudication half of
// the collect/adjudicate split, extended by Addendum 8 D70: after
// VerifyAnchored's own anchor cross-check has succeeded, every PurgeClaim
// VerifyPolicy collected (rather than decided) is checked against a
// four-condition rule. A claim is accepted if and only if (1) a verified
// audit entry attests to it under action "purge_expired", (2) that
// entry's sequence is at or below the anchor's committed audit_sequence,
// (3) an independent tombstone corroborates it, and (4, D70) the
// tombstone row's operator/reason/purged_at are consistent with that
// same attesting entry -- corroboration is no longer merely
// "exists", it is "agrees". A caller must not remove 3/4 on the
// reasoning that 1/2 are the gate, nor re-strengthen 3/4 into a second
// independent authority (ADR-0007 Addendum 3 D32's own stated caution,
// which D70 does not revisit).
//
// D70's reverse direction runs after the forward loop, over every
// tombstone row Postgres has for a snapshot this ledger's chain
// references (knownSnapshotSHA256, VerifyReport.KnownSnapshotSHA256) --
// closing the route the forward loop structurally cannot: a tombstone
// row for a snapshot that was never marked purged locally generates no
// PurgeClaim at all, and is adjudicated by nothing unless something else
// goes looking for it.
//
// There is no partial-skip budget: this returns on the first claim or
// row that fails to adjudicate, which is what makes it strictly stronger
// than the Addendum 2 D28 counter gate it supersedes (CAP #2 §7.3 hid
// exactly one snapshot of four -- a budget of "at least one check ran"
// walks straight past that).
//
// ADR-0007 Addendum 9 D82, split by Addendum 10 D93: the reverse
// direction used to make two passes over one unscoped AllPurgeRecords
// query itself -- adjudicated (in scope) and reported (out of scope) --
// which meant the reporting half only ever ran when this whole function
// did, i.e. only in `anchored` mode (D93's own finding: `historical-
// unanchored` mode reported an out-of-scope count of 0 against the exact
// same database an anchored run reported 3 against). D93 moves the
// reporting half out to reportOutOfScopePurgeRecords below, callable
// with no anchor at all; this function keeps only the in-scope
// adjudication (compared against the attesting entry, failing on
// divergence, exactly as D70 specified) and is unchanged in every other
// respect, including staying gated to `anchored` mode -- condition 2 has
// no anchored audit sequence to compare against otherwise, which is
// D32's own correct reasoning and is not reopened here.
// tenancy is ADR-0007 Addendum 12 D110: under TenancyShared, an
// in-scope tombstone this ledger's own chain does not attest is
// reported (returned, named and counted by the caller) rather than
// failing verification -- one ledger's verifier structurally cannot
// adjudicate another ledger's retention claim (R31/R36, R49). Under the
// default TenancyExclusive (or an empty string, which callers that
// predate D110's policy field are not expected to pass -- VerifyAnchored
// always supplies opts.Policy.Tenancy, already validated non-empty by
// VerificationPolicy.Validate()) this returns the pre-D110 hard failure,
// unchanged. Every OTHER adjudicated condition (forward claims, the
// anchored-sequence bound, the purge/lower-bound comparisons) is
// UNCHANGED by tenancy -- D110 touches only the one branch its own text
// names.
func (s *Store) adjudicatePurgeClaims(ctx context.Context, claims []PurgeClaim, anchoredAuditSequence int64, anchoredAt time.Time, anchorSequence int64, anchors AnchorReader, kAnchor []byte, knownSnapshotSHA256 []string, purges PurgeChecker, tenancy string) ([]TombstoneRecord, error) {
	if len(claims) == 0 && purges == nil {
		return nil, nil
	}
	attesting, err := s.attestingAuditEntries()
	if err != nil {
		return nil, err
	}
	// ADR-0007 Addendum 9 D81, extended by Addendum 10 D88/D89: read
	// once -- this bound is a property of which anchor is being
	// verified, not of any individual claim/row.
	lowerBound, err := loadPurgeLowerBoundSource(ctx, s, anchors, kAnchor, s.ledgerID, anchorSequence)
	if err != nil {
		return nil, err
	}
	for _, claim := range claims {
		entry, attested := attesting[claim.SnapshotSHA256]
		if !attested {
			return nil, fmt.Errorf("snapshot %s (referenced at event sequence %d) is marked purged locally but no audit entry attests to it (ADR-0007 Addendum 3 D32): possible forged retention state", claim.SnapshotSHA256, claim.EventSequence)
		}
		if int64(entry.Sequence) > anchoredAuditSequence {
			return nil, fmt.Errorf("snapshot %s's purge attestation is at audit sequence %d, which is after the anchored audit sequence %d (ADR-0007 Addendum 3 D32): the purge is not yet anchored", claim.SnapshotSHA256, entry.Sequence, anchoredAuditSequence)
		}
		if purges == nil {
			return nil, fmt.Errorf("snapshot %s's purge cannot be corroborated: no independent purge-record source is configured (ADR-0007 Addendum 3 D32)", claim.SnapshotSHA256)
		}
		record, err := purges.PurgeRecord(ctx, claim.SnapshotSHA256)
		if err != nil {
			return nil, fmt.Errorf("checking independent purge record for %s: %w", claim.SnapshotSHA256, err)
		}
		if record == nil {
			return nil, fmt.Errorf("snapshot %s is attested and anchored but has no independent tombstone record (ADR-0007 Addendum 3 D32): mirror/ledger divergence between the audit chain and the retention tombstone table", claim.SnapshotSHA256)
		}
		claimLowerBound, err := lowerBound.forSnapshot(ctx, purges, s.ledgerID, claim.SnapshotSHA256)
		if err != nil {
			return nil, err
		}
		if err := purgeAttributionMismatch(*record, entry, anchoredAt, claimLowerBound); err != nil {
			return nil, err
		}
	}
	if purges == nil {
		return nil, nil
	}
	all, err := purges.AllPurgeRecords(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing tombstone records for reverse purge-claim adjudication (ADR-0007 Addendum 8 D70): %w", err)
	}
	known := make(map[string]struct{}, len(knownSnapshotSHA256))
	for _, sha := range knownSnapshotSHA256 {
		known[sha] = struct{}{}
	}
	var sharedTenancyUnattested []TombstoneRecord
	for _, record := range all {
		if _, inScope := known[record.SnapshotSHA256]; !inScope {
			// ADR-0007 Addendum 9 D82, extended by Addendum 10 D93: outside
			// this ledger's own known history -- reportOutOfScopePurgeRecords
			// (below) reports these; this pass never adjudicates them. D70's
			// reason this ledger has no standing to judge it is unchanged.
			continue
		}
		entry, attested := attesting[record.SnapshotSHA256]
		if !attested {
			if tenancy == TenancyShared {
				sharedTenancyUnattested = append(sharedTenancyUnattested, record)
				continue
			}
			return nil, fmt.Errorf("snapshot %s has a tombstone row in the retention table but no audit entry attests to its purge anywhere in the chain (ADR-0007 Addendum 8 D70): possible fabricated retention record, written outside Store.PurgeExpired", record.SnapshotSHA256)
		}
		if int64(entry.Sequence) > anchoredAuditSequence {
			return nil, fmt.Errorf("snapshot %s's tombstone row is attested at audit sequence %d, which is after the anchored audit sequence %d (ADR-0007 Addendum 8 D70): the purge is not yet anchored", record.SnapshotSHA256, entry.Sequence, anchoredAuditSequence)
		}
		rowLowerBound, err := lowerBound.forSnapshot(ctx, purges, s.ledgerID, record.SnapshotSHA256)
		if err != nil {
			return nil, err
		}
		if err := purgeAttributionMismatch(record, entry, anchoredAt, rowLowerBound); err != nil {
			return nil, err
		}
	}
	return sharedTenancyUnattested, nil
}

// reportOutOfScopePurgeRecords is ADR-0007 Addendum 10 D93(a): the
// reporting half of D82's reverse pass, factored out so it needs no
// anchor and runs in every verification mode -- before this addendum it
// ran only inside adjudicatePurgeClaims, which VerifyAnchored calls only
// when mode == VerificationModeAnchored, so historical-unanchored mode
// reported an out-of-scope count of 0 against the exact same database an
// anchored run reported a nonzero count against (D93's own measured
// finding). Purely a partition of AllPurgeRecords against
// knownSnapshotSHA256; never adjudicates (compares against an attesting
// audit entry) any row, in or out of scope -- that stays
// adjudicatePurgeClaims's job, unchanged.
func (s *Store) reportOutOfScopePurgeRecords(ctx context.Context, knownSnapshotSHA256 []string, purges PurgeChecker) ([]TombstoneRecord, error) {
	if purges == nil {
		return nil, nil
	}
	all, err := purges.AllPurgeRecords(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing tombstone records for the out-of-scope reporting pass (ADR-0007 Addendum 10 D93): %w", err)
	}
	known := make(map[string]struct{}, len(knownSnapshotSHA256))
	for _, sha := range knownSnapshotSHA256 {
		known[sha] = struct{}{}
	}
	var reported []TombstoneRecord
	for _, record := range all {
		if _, inScope := known[record.SnapshotSHA256]; !inScope {
			reported = append(reported, record)
		}
	}
	return reported, nil
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
	// ADR-0007 Addendum 3 D32: VerifyAnchored is the one caller permitted
	// to defer purge-claim adjudication -- allowDeferredPurgeClaims is
	// unexported, so setting it here (inside the same package) is the
	// only place it can be set at all.
	deferredOpts := opts.VerifyOptions
	deferredOpts.allowDeferredPurgeClaims = true
	report, err := s.VerifyPolicy(ctx, deferredOpts)
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
			// ADR-0007 Addendum 11 D101(b): set explicitly, at the return,
			// rather than left to rely on the zero value -- this is the
			// exact path D93's own table row 3 measures ("the Purges
			// connection is live and the database still holds the same
			// nineteen rows, and the count is 0"): the reporting pass never
			// ran here at all, and the marker must say so.
			base.OutOfScopeRetentionTombstonesChecked = OutOfScopeCheckNotPerformed
			return base, nil
		}
		return AnchorVerifyResult{}, errors.New("anchored mode requires a database connection to cross-check the anchor (ADR-0007 D12): no AnchorReader was supplied")
	}

	// ADR-0007 Addendum 3 D33: required whenever a database is supplied,
	// checked before the anchor cross-check so an unprovisioned database
	// fails with a specific, named reason rather than surfacing as a
	// missing-anchor or missing-column error that reads like a different
	// problem.
	if opts.Provisioning == nil {
		return AnchorVerifyResult{}, errors.New("anchored mode requires a provisioning-state reader when a database is supplied (ADR-0007 Addendum 3 D33): no ProvisioningStateReader was configured")
	}
	provisioning, err := opts.Provisioning.CheckProvisioningState(ctx)
	if err != nil {
		return AnchorVerifyResult{}, fmt.Errorf("checking provisioning state (ADR-0007 Addendum 3 D33): %w", err)
	}
	if !provisioning.Provisioned {
		base.AnchorStatus = AnchorStatusFailed
		return base, fmt.Errorf("database is not fully provisioned (ADR-0007 Addendum 3 D33): %s", provisioning.Reason)
	}

	latest, found, err := opts.Anchors.LatestAnchor(ctx, s.ledgerID)
	if err != nil {
		return AnchorVerifyResult{}, fmt.Errorf("reading latest anchor: %w", err)
	}
	if !found {
		// ADR-0007 Addendum 2 D25 point 1 (F-C/F-F): the signed policy's
		// min_anchor_sequence is itself an externally-authenticated
		// commitment that at least that many anchors were genuinely
		// written. An absent anchor is inconsistent with that commitment
		// regardless of mode or --allow-genesis -- both are ways of
		// saying "I could not check" or "I am not checking," and the
		// policy already asserts something stronger than either. This is
		// what makes a full anchor-table wipe (owl_ledger_ddl's residual,
		// CAP §7.3/§7.4) detectable without D26: zero rows is below any
		// floor >= 1.
		if opts.Policy.MinAnchorSequence >= 1 {
			base.AnchorStatus = AnchorStatusFailed
			return base, fmt.Errorf("no anchor row exists for this ledger, but the signed policy commits to a minimum anchor sequence of %d (ADR-0007 Addendum 2 D25): an anchor-table wipe cannot be reported as a legitimate absence once a floor is set", opts.Policy.MinAnchorSequence)
		}
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
	// ADR-0007 Addendum 2 D25 point 2: a PRESENT anchor below the policy's
	// floor is equally a failure, distinct from AnchorStatusAbsent because
	// something was found and it was wrong -- e.g. every anchor above
	// sequence N deleted (or deleted and replaced with a saved copy of the
	// row at N), which the immutability trigger does not prevent once it
	// has been dropped. This bounds rollback to the policy's committed
	// floor; it does not prevent rollback to it (D25's own stated limit).
	if opts.Policy.MinAnchorSequence > 0 && latest.Sequence < int64(opts.Policy.MinAnchorSequence) {
		base.AnchorStatus = AnchorStatusFailed
		return base, fmt.Errorf("anchor sequence %d is below the signed policy's minimum anchor sequence %d (ADR-0007 Addendum 2 D25): the newest surviving anchor predates what the policy committed to", latest.Sequence, opts.Policy.MinAnchorSequence)
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

	// ADR-0007 Addendum 3 D32: purge-claim ADJUDICATION runs only in
	// anchored mode -- historical-unanchored mode has no anchor for
	// condition 2 to compare against (D9/D13's existing double gate
	// already tolerates skipped snapshot checks there, unchanged). Placed
	// after every prior cross-check has succeeded, per D32's own
	// sequencing: "VerifyAnchored adjudicates every claim after the
	// anchor cross-check succeeds." This condition is NOT reopened by
	// D93 -- see the withdrawal condition in D95's text.
	if mode == VerificationModeAnchored {
		// ADR-0007 Addendum 12 D110: exclusive is ASSERTED, not assumed.
		// In exclusive mode, a screening_ledger_event row carrying a
		// ledger_id other than this ledger's is itself a named
		// verification failure, naming the foreign ids found -- checked
		// before adjudication below, which is what a foreign row would
		// otherwise silently widen the scope of.
		if opts.Policy.Tenancy == TenancyExclusive && opts.Purges != nil {
			foreign, err := opts.Purges.ForeignLedgerIDs(ctx, s.ledgerID)
			if err != nil {
				base.AnchorStatus = AnchorStatusFailed
				return base, fmt.Errorf("checking for foreign ledger_id rows under exclusive tenancy (ADR-0007 Addendum 12 D110): %w", err)
			}
			if len(foreign) > 0 {
				base.AnchorStatus = AnchorStatusFailed
				return base, fmt.Errorf("this ledger's verification policy declares exclusive tenancy, but screening_ledger_event carries row(s) for foreign ledger_id(s) %v (ADR-0007 Addendum 12 D110): the schema is shared, contradicting the signed policy", foreign)
			}
		}
		sharedTenancyUnattested, err := s.adjudicatePurgeClaims(ctx, report.PurgeClaims, latest.AuditSequence, latest.AnchoredAt, latest.Sequence, opts.Anchors, opts.KAnchor, report.KnownSnapshotSHA256, opts.Purges, opts.Policy.Tenancy)
		if err != nil {
			base.AnchorStatus = AnchorStatusFailed
			return base, err
		}
		base.SharedTenancyUnattestedTombstones = sharedTenancyUnattested
		// Every claim adjudicated successfully (adjudicatePurgeClaims
		// returns on the first failure otherwise), so each now counts as
		// checked -- SnapshotChecksPerformed only reaches
		// SnapshotChecksTotal once both the originally-decrypted
		// snapshots and every legitimately-purged one are accounted for.
		base.SnapshotChecksPerformed = report.SnapshotChecksPerformed + len(report.PurgeClaims)
	}
	// ADR-0007 Addendum 10 D93(a): the REPORTING pass, unlike adjudication
	// above, needs no anchor -- only a database connection -- so it runs
	// regardless of mode. Before this addendum it ran only inside the
	// anchored-mode branch above, which is exactly what let the same
	// out-of-scope tombstone rows be reported in `anchored` mode and
	// silently unreported (count 0) in `historical-unanchored` mode
	// against the identical database (D93's own measured finding).
	reported, err := s.reportOutOfScopePurgeRecords(ctx, report.KnownSnapshotSHA256, opts.Purges)
	if err != nil {
		base.AnchorStatus = AnchorStatusFailed
		return base, err
	}
	base.OutOfScopeRetentionTombstones = reported
	// ADR-0007 Addendum 11 D101(a): the marker is set explicitly here,
	// at the one point the reporting pass actually ran and returned
	// successfully -- every return above this line leaves
	// OutOfScopeRetentionTombstonesChecked at its zero value,
	// OutOfScopeCheckNotPerformed, by construction (D101(b): this
	// includes the AnchorStatusUnavailable early return below opts.Anchors
	// == nil, the exact path row 3 of D93's own table measures).
	if len(reported) > 0 {
		base.OutOfScopeRetentionTombstonesChecked = OutOfScopeCheckFindings
	} else {
		base.OutOfScopeRetentionTombstonesChecked = OutOfScopeCheckClean
	}

	base.AnchorStatus = AnchorStatusVerified
	base.AnchorSequence = latest.Sequence
	age := time.Since(latest.AnchoredAt).Seconds()
	base.AnchorAgeSeconds = &age
	return base, nil
}
