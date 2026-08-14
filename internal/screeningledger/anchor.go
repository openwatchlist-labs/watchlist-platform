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
// anchorMAC computes anchor_mac exactly as ADR-0007 §5.3 specifies it:
// HMAC-SHA256(K_anchor, ledger_id ‖ sequence ‖ event_sha256 ‖
// audit_sha256). The ADR's concatenation notation does not specify a
// wire format; this uses a NUL-byte delimiter between fields so that,
// for example, ledger_id="a" sequence=1 cannot collide with
// ledger_id="a1" sequence=<empty> -- none of the four inputs (a ledger
// id, a decimal sequence number, two hex digests) can themselves
// contain a NUL byte, so the delimiter introduces no ambiguity.
func anchorMAC(kAnchor []byte, ledgerID string, sequence int64, eventSHA256, auditSHA256 string) string {
	raw := strings.Join([]string{ledgerID, strconv.FormatInt(sequence, 10), eventSHA256, auditSHA256}, "\x00")
	return macHex(kAnchor, []byte(raw))
}

// Anchor is one row of screening_ledger_anchor, read back for Verify's
// cross-check (ADR-0007 §5.3 point 4).
//
// Sequence is the EVENT chain's sequence number at anchor time -- not the
// audit chain's, and not an independent anchor-generation counter. The
// two chains are sequenced independently (AppendAudit has four call
// sites against Append's one, so they drift), so a single column cannot
// carry both; the event chain is the one this repository's ADRs treat as
// authoritative (ADR-0007 §3.2). AuditSHA256 rides alongside it as
// supplementary evidence of what the audit chain's head looked like at
// the same moment -- it is NOT keyed to any particular audit sequence,
// and Verify does not attempt to re-validate it against the live audit
// chain once further audit entries have accrued past that moment; only
// EventSHA256 is a continuously-checkable invariant. See
// db/migrations/016_screening_ledger_anchor_sequence_comment.sql for the
// same statement as a live schema comment.
type Anchor struct {
	LedgerID    string
	Sequence    int64
	EventSHA256 string
	AuditSHA256 string
	AnchoredAt  time.Time
	AnchorMAC   string
}

// Verify reports whether this anchor's own anchor_mac is consistent with
// its four committed fields under kAnchor -- i.e. that the row was
// genuinely written by a holder of K_anchor and has not been altered in
// place since. It does not check the row against the live chain; that is
// Store.VerifyAnchored's job.
func (a Anchor) Verify(kAnchor []byte) bool {
	return hmac.Equal([]byte(a.AnchorMAC), []byte(anchorMAC(kAnchor, a.LedgerID, a.Sequence, a.EventSHA256, a.AuditSHA256)))
}

// AnchorSink writes exactly one relation, screening_ledger_anchor, and is
// deliberately not a method on PostgresSink. The whole point of D3 is
// that the anchoring identity (owl_ledger_anchor) is a different DB role
// than the ledger writer (owl_migrator, the identity PostgresSink
// connects as) -- collapsing them into one Go type would make it easy for
// a future caller to write an anchor row over the ledger-writer's
// connection by accident, silently defeating the role separation the
// schema enforces. AnchorSink has no Migrate: screening_ledger_anchor's
// DDL and ownership transfer belong to db/migrations/015_screening_ledger
// _anchor.sql and scripts/ci/provision_test_roles.sh's
// grant-anchor-ownership step, run by owl_migrator and the bootstrap
// superuser respectively -- never by the anchor role itself, which per
// ADR-0007 §5.3 point 2 holds nothing beyond INSERT on this one table:
// owl_ledger_anchor is write-only in privilege (INSERT only -- no
// SELECT/UPDATE/DELETE), not the table itself write-only to every
// identity. Stage 3 grants owl_migrator SELECT (only) on this table so
// Verify() can read anchor rows back for cross-checking (ADR-0007 §5.3
// point 4) -- see grant-anchor-ownership's SELECT grant and its
// postcondition checks. owl_app gets nothing here; it is not
// tenant-scoped.
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
// This is the mechanism D3 specifies; nothing in this stage calls it on a
// schedule or from the CLI -- ADR-0007 §8/D6, cadence and automation, is
// explicitly a separate, future gate PR.
func (a *AnchorSink) WriteAnchor(ctx context.Context, kAnchor []byte, ledgerID string, sequence int64, eventSHA256, auditSHA256 string) error {
	if len(kAnchor) != 32 {
		return errors.New("anchor key (K_anchor) must be 32 bytes")
	}
	mac := anchorMAC(kAnchor, ledgerID, sequence, eventSHA256, auditSHA256)
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()
	_, err := a.conn.Exec(ctx,
		`INSERT INTO screening_ledger_anchor(ledger_id,sequence,event_sha256,audit_sha256,anchor_mac) VALUES ($1,$2,$3,$4,$5)`,
		ledgerID, sequence, eventSHA256, auditSHA256, mac)
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
// check. ADR-0007's Consequences section is explicit that "verify on a
// host with no database becomes a partial check that must say so rather
// than returning ok" -- AnchorStatusUnavailable is that honest partial
// report, not a silent downgrade to "ok".
type AnchorVerifyStatus string

const (
	// AnchorStatusVerified: an anchor row exists, its own MAC checks out
	// under K_anchor, and its committed digest matches the file chain's
	// state at that sequence.
	AnchorStatusVerified AnchorVerifyStatus = "verified"
	// AnchorStatusUnavailable: no AnchorReader was supplied (no database
	// configured for this verify run). The file chain still fully
	// verified -- VerifyReport is populated -- but nothing outside the
	// ledger directory was checked, so an adversary holding K_chain alone
	// is not ruled out. This is the case ADR-0007's Consequences section
	// requires callers not to silently report as "ok".
	AnchorStatusUnavailable AnchorVerifyStatus = "unavailable"
	// AnchorStatusAbsent: the database was reachable but this ledger has
	// no anchor row yet (e.g. before genesis has been anchored).
	AnchorStatusAbsent AnchorVerifyStatus = "absent"
)

// AuditAnchorCoverage is always AuditAnchorCoverageSupplementaryOnly.
// It is a constant, not a per-call outcome, but it is carried on every
// AnchorVerifyResult -- including the "verified" case -- so it appears
// in the same output an operator reads "anchor_status":"verified" from,
// rather than requiring them to already know to go read a doc comment.
// A security review of this stage found that "verified" on its own
// invites the reasonable but false inference that the audit chain
// received the same anchor protection the event chain did; this field
// exists to make that gap visible at the point of use. ADR-0007 §10
// names it explicitly as an accepted risk.
const AuditAnchorCoverageSupplementaryOnly = "supplementary_only"

// AnchorVerifyResult is VerifyDetail's report plus what the anchor
// cross-check found.
type AnchorVerifyResult struct {
	VerifyReport
	AnchorStatus        AnchorVerifyStatus
	AnchorSequence      int64
	AuditAnchorCoverage string
}

// VerifyAnchored is Verify/VerifyDetail (the full file-chain check, event
// and audit, including the D4 frozen-prefix and genesis-boundary rules)
// plus the D3 anchor cross-check ADR-0007 §5.3 point 4 specifies:
// Verify fails if the chain at an anchored sequence disagrees with the
// anchored digests, and fails if the current head is behind the newest
// anchor (tail truncation, even when the head file itself was rewritten
// consistently -- ADR-0007 §7.1 case 2).
//
// anchors is an interface specifically so passing nil is a real, checked
// nil -- callers must not pass a typed nil *PostgresSink through this
// parameter, which would not compare equal to the nil this function
// checks for.
func (s *Store) VerifyAnchored(ctx context.Context, anchors AnchorReader, kAnchor []byte) (AnchorVerifyResult, error) {
	report, err := s.VerifyDetail()
	if err != nil {
		return AnchorVerifyResult{}, err
	}
	if anchors == nil {
		return AnchorVerifyResult{VerifyReport: report, AnchorStatus: AnchorStatusUnavailable, AuditAnchorCoverage: AuditAnchorCoverageSupplementaryOnly}, nil
	}
	latest, found, err := anchors.LatestAnchor(ctx, s.ledgerID)
	if err != nil {
		return AnchorVerifyResult{}, err
	}
	if !found {
		return AnchorVerifyResult{VerifyReport: report, AnchorStatus: AnchorStatusAbsent, AuditAnchorCoverage: AuditAnchorCoverageSupplementaryOnly}, nil
	}
	if len(kAnchor) != 32 {
		return AnchorVerifyResult{}, errors.New("anchor key (K_anchor) must be 32 bytes to verify an anchor row")
	}
	if !latest.Verify(kAnchor) {
		return AnchorVerifyResult{}, errors.New("anchor row MAC invalid under K_anchor: the row may have been altered since it was written")
	}
	if latest.Sequence > int64(report.Head.Sequence) {
		return AnchorVerifyResult{}, fmt.Errorf("chain head (sequence %d) is behind the newest anchor (sequence %d): possible tail truncation", report.Head.Sequence, latest.Sequence)
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
		return AnchorVerifyResult{}, fmt.Errorf("chain digest at sequence %d (%s) disagrees with the anchor's committed digest (%s): possible tampering after anchoring", latest.Sequence, eventAtAnchor, latest.EventSHA256)
	}
	return AnchorVerifyResult{VerifyReport: report, AnchorStatus: AnchorStatusVerified, AnchorSequence: latest.Sequence, AuditAnchorCoverage: AuditAnchorCoverageSupplementaryOnly}, nil
}
