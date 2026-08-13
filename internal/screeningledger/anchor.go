package screeningledger

import (
	"context"
	"errors"
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
// ADR-0007 §5.3 point 2 should hold nothing beyond INSERT on this one
// table.
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
