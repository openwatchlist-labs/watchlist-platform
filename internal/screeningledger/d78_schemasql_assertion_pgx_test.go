// ADR-0007 Addendum 9 D78/D85 test 2 (M-A, the bootstrap half): SchemaSQL's
// presence-only guard ("does the function exist") becomes D21's second
// safe shape -- assert and fail closed -- rather than presence-implies-
// correctness, which never repaired or detected the swap D77 demonstrates.
package screeningledger

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestSchemaSQLRefusesAnAlteredGuardBody is D78's own required
// reproduction: Migrate() against a database whose guard body has been
// swapped reports "provisioned":true (via CheckProvisioningState) and
// leaves the body unrepaired TODAY, and fails closed after, naming the
// function and the remedy.
func TestSchemaSQLRefusesAnAlteredGuardBody(t *testing.T) {
	dsn := requireSchemaSQLOnlyDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	// Bootstrap fresh via SchemaSQL, then substitute the guard body
	// directly -- no event trigger to disable here (this database has
	// never run grant-ddl-ownership, D78's own precondition for the
	// state it addresses: SchemaSQL-only, D34 never installed).
	if err := sink.Migrate(ctx); err != nil {
		t.Fatalf("initial Migrate() should succeed on a fresh SchemaSQL-only database: %v", err)
	}
	// This is the shared OWL_SCHEMASQL_ONLY_DATABASE_URL fixture other
	// suites (internal/schemasqlgate, TestD77AcceptsCleanBaseline) also
	// use -- t.Cleanup unconditionally restores the legitimate body,
	// even on a failing assertion below, so a broken run here cannot
	// leave the shared fixture corrupted for whatever runs next.
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = sink.conn.Exec(bg, "ROLLBACK")
		_, _ = sink.conn.Exec(bg, `CREATE OR REPLACE FUNCTION public.screening_ledger_reject_mutation()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'screening ledger rows are append-only';END $$`)
	})
	if _, err := sink.conn.Exec(ctx, `CREATE OR REPLACE FUNCTION public.screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`); err != nil {
		t.Fatalf("substitute the guard body (no D34 installed yet, so this succeeds as owl_migrator): %v", err)
	}
	var liveDigest string
	if err := sink.conn.QueryRow(ctx, `SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='screening_ledger_reject_mutation()'::regprocedure`).Scan(&liveDigest); err != nil {
		t.Fatal(err)
	}
	if liveDigest == screeningLedgerRejectMutationBodySHA256 {
		t.Fatalf("test precondition failed: the substitution did not change the digest")
	}

	// AFTER (the shipped fix): Migrate() now refuses, naming the function
	// and the remedy, and deliberately does NOT repair.
	err = sink.Migrate(ctx)
	if err == nil {
		t.Fatalf("ADR-0007 Addendum 9 D78: Migrate() succeeded against a database whose guard body was substituted -- expected a fail-closed assertion naming the accepted digest set")
	}
	// SchemaSQL's DO block RAISEs mid-transaction; the connection is left
	// with an aborted transaction open until explicitly rolled back --
	// required before this connection can be used for anything else.
	if _, rbErr := sink.conn.Exec(ctx, "ROLLBACK"); rbErr != nil {
		t.Fatalf("ROLLBACK after the expected Migrate() failure: %v", rbErr)
	}
	if !strings.Contains(err.Error(), "screening_ledger_reject_mutation") {
		t.Fatalf("expected the refusal to name the function, got: %v", err)
	}
	if !strings.Contains(err.Error(), "D78") {
		t.Fatalf("expected the refusal to cite ADR-0007 Addendum 9 D78, got: %v", err)
	}
	if !strings.Contains(err.Error(), "does not repair") && !strings.Contains(err.Error(), "sec7-database-copies.md") {
		t.Fatalf("expected the refusal to name the remedy (docs/operations/sec7-database-copies.md), got: %v", err)
	}

	// Confirm the body is genuinely left unrepaired, not silently fixed
	// and then reported as an error for some other reason.
	var afterDigest string
	if err := sink.conn.QueryRow(ctx, `SELECT encode(sha256(convert_to(prosrc,'UTF8')),'hex') FROM pg_proc WHERE oid='screening_ledger_reject_mutation()'::regprocedure`).Scan(&afterDigest); err != nil {
		t.Fatal(err)
	}
	if afterDigest != liveDigest {
		t.Fatalf("ADR-0007 Addendum 9 D78: expected Migrate() to leave the substituted body unrepaired (deliberate: a repairing CREATE OR REPLACE would be refused by D34 on every already-provisioned database), got digest changed from %q to %q", liveDigest, afterDigest)
	}

	// Repair manually and confirm Migrate() succeeds again -- the
	// documented remedy actually works.
	if _, err := sink.conn.Exec(ctx, `CREATE OR REPLACE FUNCTION public.screening_ledger_reject_mutation()RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'screening ledger rows are append-only';END $$`); err != nil {
		t.Fatalf("manual repair: %v", err)
	}
	if err := sink.Migrate(ctx); err != nil {
		t.Fatalf("Migrate() should succeed once the guard body is repaired to a declared-accepted digest: %v", err)
	}
}

// TestSchemaSQLAcceptsBothBootstrapPathsRepeatedly is D78's over-tightening
// positive: Migrate() on both bootstrap paths, and repeated Migrate() on
// a fully provisioned database, still succeed -- the case D34 would
// refuse if D78 were implemented as a repair rather than an assertion.
func TestSchemaSQLAcceptsBothBootstrapPathsRepeatedly(t *testing.T) {
	t.Run("schemasql_only_repeated", func(t *testing.T) {
		dsn := requireSchemaSQLOnlyDatabaseURL(t)
		ctx := context.Background()
		sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		for i := 0; i < 3; i++ {
			if err := sink.Migrate(ctx); err != nil {
				t.Fatalf("Migrate() call %d on a clean SchemaSQL-only database should succeed: %v", i+1, err)
			}
		}
	})

	t.Run("migration_bootstrapped_repeated", func(t *testing.T) {
		superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
		migratorDSN := requireMigratorDSN(t)
		ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
		ctx := context.Background()
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		sink, err := NewPostgresSink(ctx, withDatabase(t, migratorDSN, clone.dbName), 10*time.Second)
		if err != nil {
			t.Fatalf("NewPostgresSink: %v", err)
		}
		defer sink.Close(context.Background())
		// Migrate() on a fully provisioned (grant-ddl-ownership already
		// run) clone: this is exactly the case D78 must not refuse if it
		// were implemented as a repairing CREATE OR REPLACE -- D34 would
		// block a repair here even though the body is already correct.
		for i := 0; i < 3; i++ {
			if err := sink.Migrate(ctx); err != nil {
				t.Fatalf("Migrate() call %d on a fully provisioned clone should succeed (D78 must not attempt a repairing CREATE OR REPLACE FUNCTION here): %v", i+1, err)
			}
		}
	})
}
