// SEC-7 Stage 2 (ADR-0007 D3) empirical proof, exercised against a live
// PostgreSQL connection -- the same standard 014_tenant_isolation.sql was
// held to (CLAUDE.md, "empirical verification"): reviewing the migration
// and provisioning script text does not catch a role-separation control
// that looks installed and silently does nothing.
//
// What this suite proves, and what it does not:
//
//   - It proves the database as CI actually builds it -- db/migrations/*.sql
//     applied in order (through 015_screening_ledger_anchor.sql) by
//     owl_migrator, then scripts/ci/provision_test_roles.sh
//     grant-anchor-ownership run by the bootstrap superuser, exactly as
//     .github/workflows/ci.yml's steps run in this stage -- rejects the
//     writes and TRUNCATEs D3 exists to reject.
//   - It does NOT independently re-prove that path against SchemaSQL run
//     with no db/migrations/ applied first; TestSchemaSQLCarriesTruncateGuards
//     (postgres_schema_test.go) is the check for SchemaSQL's own content,
//     and this suite's TestSEC7ExistingSixTablesRejectTruncate below is
//     gated on the CI-composed database, not a from-scratch SchemaSQL-only
//     one -- building genuine schema isolation for that second path (a
//     role or database owl_migrator is not currently granted CREATE on)
//     is more provisioning machinery than this stage's stated scope
//     (table, role, TRUNCATE trigger) covers, so it is named as a gap
//     rather than silently assumed covered.
//
// Every TRUNCATE attempt below runs inside an explicit transaction that is
// always rolled back, never committed -- even in the failure case where a
// trigger is unexpectedly missing and TRUNCATE would otherwise succeed,
// this suite must not be the thing that empties a shared CI database's
// fixture tables.
package screeningledger

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func requireAnchorDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_LEDGER_ANCHOR_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_LEDGER_ANCHOR_DATABASE_URL not set; SEC-7 anchor role-separation suite requires a live Postgres provisioned via scripts/ci/provision_test_roles.sh grant-anchor-ownership (see scripts/ci/run-ci.sh)")
	}
	return dsn
}

func pgErrorCode(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

// TestSEC7AnchorWriterCanInsertAndOwnsTheRow is the positive half of the
// role-separation proof: the identity D3 designates as the anchor writer
// can actually write, using the real production code path (AnchorSink),
// not a hand-rolled INSERT. Without this half, a test suite that only
// proves "everything is rejected" cannot distinguish correctly-scoped
// isolation from an accidental lockout of every role, including the one
// meant to work.
func TestSEC7AnchorWriterCanInsertAndOwnsTheRow(t *testing.T) {
	anchorDSN := requireAnchorDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewAnchorSink(ctx, anchorDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewAnchorSink: %v", err)
	}
	t.Cleanup(func() {
		if err := sink.Close(context.Background()); err != nil {
			t.Errorf("sink.Close: %v", err)
		}
	})

	kAnchor := bytes.Repeat([]byte{0x77}, 32)
	ledgerID := uniqueID("sec7-anchor-writer")
	if err := sink.WriteAnchor(ctx, kAnchor, ledgerID, 1, "event-sha-fixture", "audit-sha-fixture"); err != nil {
		t.Fatalf("owl_ledger_anchor WriteAnchor: expected success, got %v", err)
	}

	// Independent connection, same idiom as verifyConn: proves the row is
	// truly committed, not just visible on the writer's own session.
	verify := verifyConn(t, ctx, anchorDSN)
	defer verify.Close(context.Background())
	var mac string
	if err := verify.QueryRow(ctx, `SELECT anchor_mac FROM screening_ledger_anchor WHERE ledger_id=$1 AND sequence=1`, ledgerID).Scan(&mac); err != nil {
		t.Fatalf("read back anchor row: %v", err)
	}
	want := anchorMAC(kAnchor, ledgerID, 1, "event-sha-fixture", "audit-sha-fixture")
	if mac != want {
		t.Fatalf("stored anchor_mac = %q, want %q", mac, want)
	}
}

// TestSEC7LedgerWriterCannotInsertAnchor is the negative half: owl_migrator
// -- the identity that writes the screening ledger files/tables this
// anchor is meant to stand outside of -- must not be able to write
// screening_ledger_anchor. This is the whole mechanism D3 exists to
// establish; if this test ever passes with err == nil, the anchor proves
// nothing.
func TestSEC7LedgerWriterCannotInsertAnchor(t *testing.T) {
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer conn.Close(context.Background())

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx,
		`INSERT INTO screening_ledger_anchor(ledger_id,sequence,event_sha256,audit_sha256,anchor_mac) VALUES ($1,$2,$3,$4,$5)`,
		uniqueID("sec7-forged-anchor"), 1, "forged-event-sha", "forged-audit-sha", "forged-mac")
	if err == nil {
		t.Fatal("owl_migrator INSERT into screening_ledger_anchor succeeded; role separation is not holding")
	}
	if code := pgErrorCode(err); code != "42501" {
		t.Fatalf("expected SQLSTATE 42501 (insufficient_privilege), got %q: %v", code, err)
	}
}

// TestSEC7AnchorTableRejectsTruncate proves TRUNCATE is rejected even when
// attempted by screening_ledger_anchor's own owning role -- BEFORE
// TRUNCATE triggers fire regardless of who executes the statement,
// ownership included, so this is a real test of the trigger, not just of
// a permission grant.
func TestSEC7AnchorTableRejectsTruncate(t *testing.T) {
	anchorDSN := requireAnchorDatabaseURL(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, anchorDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_anchor: %v", err)
	}
	defer conn.Close(context.Background())

	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `TRUNCATE screening_ledger_anchor`)
	if err == nil {
		t.Fatal("TRUNCATE screening_ledger_anchor (as its own owner, owl_ledger_anchor) succeeded; TRUNCATE guard is not holding")
	}
	if code := pgErrorCode(err); code != "P0001" {
		t.Fatalf("expected SQLSTATE P0001 (raise_exception, from owl_reject_truncate()), got %q: %v", code, err)
	}
}

// TestSEC7ExistingSixTablesRejectTruncate re-proves, against the live
// database, that the six pre-existing screening-ledger tables
// db/migrations/012_truncate_guards.sql already protects still reject
// TRUNCATE -- a regression guard for the ADR-0007 §3.2/§5.3 premise this
// stage's investigation found stale (012 predates the ADR). Run as
// owl_migrator, the tables' owner, for the same reason as the anchor
// table's own case above: the guard must hold even for the owner.
//
// screening_ledger_event needs its own case: screening_ledger_replication
// and screening_idempotency_receipt both hold a foreign key referencing
// it, so a bare TRUNCATE screening_ledger_event is rejected by Postgres's
// own referential-integrity check (SQLSTATE 0A000) before the trigger
// ever runs -- found empirically running this suite. That FK check is not
// this migration's control and is not what this test exists to prove.
// CASCADE is what an adversary would actually use to route around it, by
// extending the TRUNCATE to the referencing tables instead of being
// blocked by them -- so that is the case that has to reach, and be
// stopped by, owl_reject_truncate().
func TestSEC7ExistingSixTablesRejectTruncate(t *testing.T) {
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	plainTruncateTables := []string{
		"screening_ledger_audit",
		"screening_ledger_replication",
		"screening_ledger_retention_tombstone",
		"screening_ledger_snapshot",
		"screening_idempotency_receipt",
	}

	conn, err := pgx.Connect(ctx, migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer conn.Close(context.Background())

	attempt := func(t *testing.T, sql string) {
		t.Helper()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)

		_, err = tx.Exec(ctx, sql)
		if err == nil {
			t.Fatalf("%q succeeded; TRUNCATE guard is not holding", sql)
		}
		if code := pgErrorCode(err); code != "P0001" {
			t.Fatalf("%q: expected SQLSTATE P0001 (raise_exception), got %q: %v", sql, code, err)
		}
	}

	for _, table := range plainTruncateTables {
		attempt(t, `TRUNCATE `+table)
	}
	attempt(t, `TRUNCATE screening_ledger_event CASCADE`)
}
