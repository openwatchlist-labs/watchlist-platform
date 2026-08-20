// ADR-0007 Addendum 2 D21/D22 (F-E, CRITICAL): CAP §7.6's exact live
// finding, reproduced as a committed regression against a real Postgres
// rather than asserted from reading SQL. A database migrated through
// db/migrations/016 but not 017 has screening_ledger_anchor present with
// only its TRUNCATE guard -- no row-immutability trigger, no
// audit_sequence/policy_sha256 columns -- yet Migrate() (before this
// fix) reported success, because SchemaSQL's own anchor-table guard
// (postgres.go) only ever checks "does the table exist," never "does it
// carry the protections it claims." owl_migrator, explicitly inside
// ADR-0007 §2's threat model, then forges an anchor row by an ordinary
// in-place UPDATE.
//
// Reproducing this needs a database in exactly that partially-migrated
// state. It cannot be built against owl_ci (the primary CI database):
// db/migrations/ always runs there in full, and after
// grant-anchor-ownership, owl_migrator no longer owns
// screening_ledger_anchor and cannot manipulate its schema. A session-
// local temp schema (search_path=pg_temp) was tried and rejected: Postgres
// does not search pg_temp for unqualified function name resolution even
// when pg_temp is explicitly listed in search_path (confirmed empirically
// against a live server, not assumed from the docs), and SchemaSQL's own
// triggers reference their functions unqualified -- so Migrate() itself
// cannot run under that isolation. Instead, provision_test_roles.sh
// create-stale-anchor-database creates a second, disposable database
// owned by owl_migrator from creation, migrated only through
// db/migrations/016 by CI (see .github/workflows/ci.yml), exposed via
// OWL_MIGRATOR_STALE_DATABASE_URL -- gated through check_db_gates.sh like
// every other OWL_*_DATABASE_URL in the tree, per D18's "this is the
// complete set" invariant.
package screeningledger

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func requireStaleAnchorDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_MIGRATOR_STALE_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_MIGRATOR_STALE_DATABASE_URL not set; ADR-0007 Addendum 2 D21/D22 regression requires a live Postgres database migrated only through db/migrations/016 (see scripts/ci/provision_test_roles.sh create-stale-anchor-database and scripts/ci/run-ci.sh)")
	}
	return dsn
}

// TestMigrateFailsOnStaleAnchorTable is D21's required reproduction: on a
// database migrated through 015/016 but not 017, Migrate() must refuse
// rather than report success, naming the missing row-immutability
// trigger and the migration that installs it. It also reproduces CAP
// §7.6's forgery directly, so the failure this fixes is demonstrated, not
// merely asserted -- and D22's named 42703 diagnostic on LatestAnchor.
func TestMigrateFailsOnStaleAnchorTable(t *testing.T) {
	dsn := requireStaleAnchorDatabaseURL(t)
	ctx := context.Background()

	sink, err := NewPostgresSink(ctx, dsn, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink: %v", err)
	}
	defer sink.Close(context.Background())

	// D21: Migrate() must not report success on this database. Before
	// the fix, SchemaSQL's `IF to_regclass('screening_ledger_anchor') IS
	// NULL` guard sees the table already exists (015 created it) and
	// skips re-touching it entirely, so Migrate() returns nil even though
	// 017's trigger and columns were never installed.
	if err := sink.Migrate(ctx); err == nil {
		t.Fatal("Migrate() succeeded on a database migrated through 016 but not 017; expected a named schema-incomplete error (ADR-0007 Addendum 2 D21) -- the anchor table is missing its row-immutability trigger and F-E's CRITICAL finding is unpatched")
	} else if !strings.Contains(err.Error(), "screening_ledger_anchor_immutable") {
		t.Fatalf("expected Migrate()'s error to name the missing screening_ledger_anchor_immutable trigger, got: %v", err)
	} else if !strings.Contains(err.Error(), "017_screening_ledger_anchor_policy_binding.sql") {
		t.Fatalf("expected Migrate()'s error to name the migration that installs the missing trigger (D21 point 2), got: %v", err)
	}

	// CAP §7.6, reproduced live: as owl_migrator -- explicitly inside
	// ADR-0007 §2's threat model, and the owner of this table in this
	// state -- an ordinary in-place UPDATE forges the anchor's
	// event_sha256. This demonstrates the exposure Migrate()'s refusal
	// above exists to stop an operator from unknowingly deploying into.
	ledgerID := uniqueID("sec7-fe-stale")
	if _, err := sink.conn.Exec(ctx,
		`INSERT INTO screening_ledger_anchor(ledger_id,sequence,event_sha256,audit_sha256,anchor_mac) VALUES ($1,1,'REAL','a','mac')`,
		ledgerID,
	); err != nil {
		t.Fatalf("seed real anchor row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = sink.conn.Exec(context.Background(), `DELETE FROM screening_ledger_anchor WHERE ledger_id=$1`, ledgerID)
	})
	if _, err := sink.conn.Exec(ctx,
		`UPDATE screening_ledger_anchor SET event_sha256='FORGED' WHERE ledger_id=$1`, ledgerID,
	); err != nil {
		t.Fatalf("CAP §7.6's exact finding: an in-place UPDATE forging event_sha256 should succeed on this stale, un-triggered table -- got an error instead, which would mean the fixture no longer reproduces the finding: %v", err)
	}
	var got string
	if err := sink.conn.QueryRow(ctx, `SELECT event_sha256 FROM screening_ledger_anchor WHERE ledger_id=$1`, ledgerID).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "FORGED" {
		t.Fatalf("expected the forged row to read FORGED, got %q", got)
	}

	// D22: LatestAnchor must surface a named 42703 diagnostic -- not
	// unnamed plumbing -- for a caller that reaches this state some other
	// way than Migrate() (e.g. a partially applied db/migrations/ run).
	if _, _, err := sink.LatestAnchor(ctx, ledgerID); err == nil {
		t.Fatal("LatestAnchor succeeded against a table missing audit_sequence/policy_sha256; expected a named schema-incomplete error (ADR-0007 Addendum 2 D22)")
	} else if !strings.Contains(err.Error(), "Addendum 2 F-E/D22") {
		t.Fatalf("expected LatestAnchor's error to name ADR-0007 Addendum 2 F-E/D22, got: %v", err)
	}
}

// TestMigrateInstallsEveryProtectedTrigger is the live-database assertion
// the D15/D16 parity claim never had (ADR-0007 Addendum 2 D21): against a
// fresh, fully-migrated database, Migrate() must leave every trigger
// requiredSchemaObjects names actually present in pg_trigger -- not merely
// present as a substring of the SchemaSQL Go constant, which is all
// TestSchemaSQLCarriesTruncateGuards and
// TestSchemaSQLAnchorTableHasImmutabilityTrigger (postgres_schema_test.go)
// have ever proven.
func TestMigrateInstallsEveryProtectedTrigger(t *testing.T) {
	sink, ctx := newTestSink(t)

	for _, obj := range requiredSchemaObjects {
		ok, err := sink.triggerExists(ctx, obj.table, obj.immutableTrigger)
		if err != nil {
			t.Fatalf("checking %s on %s: %v", obj.immutableTrigger, obj.table, err)
		}
		if !ok {
			t.Fatalf("Migrate() did not install row-immutability trigger %s on %s", obj.immutableTrigger, obj.table)
		}
		ok, err = sink.triggerExists(ctx, obj.table, obj.noTruncateTrigger)
		if err != nil {
			t.Fatalf("checking %s on %s: %v", obj.noTruncateTrigger, obj.table, err)
		}
		if !ok {
			t.Fatalf("Migrate() did not install TRUNCATE-guard trigger %s on %s", obj.noTruncateTrigger, obj.table)
		}
	}
}
