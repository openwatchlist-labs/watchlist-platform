// Package schemasqlgate closes a gate blind spot found during the SEC-2
// Sprint 0 register reconciliation: scripts/ci/check_sql_invariants.sh's
// generic "row-level trigger without a matching BEFORE TRUNCATE trigger"
// invariant (test/sql/security_invariants.sql) only ever runs against
// OWL_TEST_DATABASE_URL, a database provisioned by applying every
// db/migrations/*.sql file in order. It never runs against a database
// bootstrapped the other way this repository supports -- calling a
// package's own SchemaSQL const via Migrate(), with no dependency on
// db/migrations/ ever having run (the same REL-9-adjacent shape ADR-0007
// D3/D15 already found and fixed once, in screeningledger's own
// SchemaSQL). That is exactly why internal/alertcase and
// internal/assistancerag's SchemaSQL could independently drift out of
// sync with db/migrations/012_truncate_guards.sql (5 row-immutability
// triggers, 0 TRUNCATE guards, in both) without any existing gate
// noticing: the one gate that would have caught it was never run against
// the one bootstrap path that had the gap.
//
// This package runs the same invariant against a database provisioned by
// SchemaSQL alone, gated on OWL_SCHEMASQL_ONLY_DATABASE_URL
// (scripts/ci/provision_test_roles.sh create-schemasql-only-database),
// so this class of gap cannot recur silently in any package that defines
// a SchemaSQL const, present or future -- not just the two named above.
package schemasqlgate

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/openwatchlist-labs/watchlist-platform/internal/alertcase"
	"github.com/openwatchlist-labs/watchlist-platform/internal/assistancerag"
	"github.com/openwatchlist-labs/watchlist-platform/internal/screeningledger"
)

func requireSchemaSQLOnlyDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_SCHEMASQL_ONLY_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_SCHEMASQL_ONLY_DATABASE_URL not set; the SchemaSQL-only-bootstrap TRUNCATE gate requires a live Postgres provisioned via scripts/ci/provision_test_roles.sh create-schemasql-only-database (see scripts/ci/run-ci.sh)")
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

// bootstrapSchemaSQLOnly runs every known package's SchemaSQL const
// against conn, with no db/migrations/ involved at all -- reproducing
// the exact bootstrap path Migrate() takes from cmd/screening-ledger,
// cmd/case-assistance, and (implicitly, alertcase has no dedicated CLI
// migrate subcommand today) any future one. Order matters:
// assistancerag.SchemaSQL's case_assistance_record table has a foreign
// key on alert_case(case_id), so alertcase.SchemaSQL must run first or
// this fails outright on a missing relation, exactly as it would for a
// real operator running these in the wrong order.
//
// Idempotent by construction (every statement is CREATE ... IF NOT
// EXISTS, DROP TRIGGER IF EXISTS/CREATE TRIGGER, or a to_regclass/
// to_regprocedure-guarded DO block), so calling this against the same
// disposable database across multiple test runs and multiple test
// functions in this package is safe.
func bootstrapSchemaSQLOnly(t *testing.T, ctx context.Context, conn *pgx.Conn) {
	t.Helper()
	for _, sql := range []string{screeningledger.SchemaSQL, alertcase.SchemaSQL, assistancerag.SchemaSQL} {
		if _, err := conn.Exec(ctx, sql); err != nil {
			t.Fatalf("bootstrap SchemaSQL: %v", err)
		}
	}
}

// TestSchemaSQLOnlyBootstrapRejectsTruncateOnAlertCaseAndAssistanceRagTables
// is the direct empirical reproduction the SEC-2 followup asked for:
// provision a database via SchemaSQL alone (no db/migrations/), then
// attempt TRUNCATE against every one of the ten relations
// db/migrations/012_truncate_guards.sql already guards for these two
// packages. Before the SchemaSQL fix, every one of these attempts
// succeeded silently -- confirmed by running this test against the
// pre-fix SchemaSQL text. After the fix, every one is rejected with
// SQLSTATE P0001 from owl_reject_truncate(), the same function and
// error shape db/migrations/012 and screeningledger's own SchemaSQL
// use, so the two sources cannot diverge on behavior.
//
// Every attempt runs inside an explicit transaction that is always
// rolled back, matching internal/screeningledger/anchor_pgx_test.go's
// own convention -- this suite must never be the thing that empties a
// shared fixture database's rows, even in the failure case where a
// guard is unexpectedly missing and TRUNCATE would otherwise succeed.
//
// alert_record, rag_corpus_snapshot, and case_assistance_record are
// each referenced by another table's foreign key (alert_case_membership,
// case_assistance_record, and case_assistance_review respectively), so a
// bare TRUNCATE on any of them is rejected by Postgres's own
// referential-integrity check (SQLSTATE 0A000) before the BEFORE
// TRUNCATE trigger ever runs -- the same shape
// internal/screeningledger/anchor_pgx_test.go found for
// screening_ledger_event. CASCADE is what actually reaches, and must be
// stopped by, owl_reject_truncate() for those three.
func TestSchemaSQLOnlyBootstrapRejectsTruncateOnAlertCaseAndAssistanceRagTables(t *testing.T) {
	dsn := requireSchemaSQLOnlyDatabaseURL(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(context.Background())

	bootstrapSchemaSQLOnly(t, ctx, conn)

	plainTruncateTables := []string{
		"alert_case_event",
		"alert_case_membership",
		"alert_case_idempotency",
		"alert_case_audit",
		"case_assistance_review",
		"case_assistance_idempotency",
		"case_assistance_audit",
	}
	cascadeTruncateTables := []string{
		"alert_record",
		"rag_corpus_snapshot",
		"case_assistance_record",
	}

	attempt := func(t *testing.T, sql string) {
		t.Helper()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(ctx)

		_, err = tx.Exec(ctx, sql)
		if err == nil {
			t.Fatalf("%q succeeded against a SchemaSQL-only-bootstrapped database; TRUNCATE guard is not holding", sql)
		}
		if code := pgErrorCode(err); code != "P0001" {
			t.Fatalf("%q: expected SQLSTATE P0001 (raise_exception, from owl_reject_truncate()), got %q: %v", sql, code, err)
		}
	}

	for _, table := range plainTruncateTables {
		attempt(t, `TRUNCATE `+table)
	}
	for _, table := range cascadeTruncateTables {
		attempt(t, `TRUNCATE `+table+` CASCADE`)
	}
}

// TestSchemaSQLOnlyBootstrapHasNoRelationMissingTruncateGuard is the gate
// extension itself: the same generic invariant
// test/sql/security_invariants.sql already asserts against a
// migration-provisioned database ("every relation with a row-level
// INSERT/DELETE/UPDATE trigger must also carry a statement-level BEFORE
// TRUNCATE trigger"), run here against a SchemaSQL-only-provisioned one
// instead. Unlike the test above, this does not enumerate table names --
// it is the check that would have caught the alertcase/assistancerag gap
// (and any future one, in any package that ever defines a SchemaSQL
// const) without anyone having to notice and name the affected tables
// first.
func TestSchemaSQLOnlyBootstrapHasNoRelationMissingTruncateGuard(t *testing.T) {
	dsn := requireSchemaSQLOnlyDatabaseURL(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(context.Background())

	bootstrapSchemaSQLOnly(t, ctx, conn)

	rows, err := conn.Query(ctx, `
SELECT c.relname AS missing_truncate_guard
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE n.nspname = 'public'
   AND EXISTS (SELECT 1 FROM pg_trigger t
                WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
                  AND (t.tgtype & 28) <> 0)          -- has UPDATE/DELETE/INSERT row trigger
   AND NOT EXISTS (SELECT 1 FROM pg_trigger t
                    WHERE t.tgrelid = c.oid AND NOT t.tgisinternal
                      AND (t.tgtype & 32) <> 0);     -- lacks TRUNCATE trigger
`)
	if err != nil {
		t.Fatalf("invariant query: %v", err)
	}
	defer rows.Close()

	var offending []string
	for rows.Next() {
		var relname string
		if err := rows.Scan(&relname); err != nil {
			t.Fatalf("scan: %v", err)
		}
		offending = append(offending, relname)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows: %v", err)
	}
	if len(offending) > 0 {
		t.Fatalf("SchemaSQL-only bootstrap left %d relation(s) with a row-level guard trigger but no TRUNCATE guard: %v", len(offending), offending)
	}
}
