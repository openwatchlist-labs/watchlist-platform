// ADR-0007 Addendum 15 D135 (G-C, LOW) test file (D136 item 8). D124's
// own text names "converts one fact into a different fact on the way
// in" as a defect; the shipped precheck at 024's own
// `coalesce(cardinality(...), 0)` folds NULL ("unset") and '{}' ("empty")
// into one fact before comparing -- the exact construct that text argues
// against. Measured (not argued) to be INERT: the leading precheck is
// the ONLY consumer of the conflated value, and every path on which NULL
// and '{}' differ reaches a destructive expression (`= ANY`) that ranges
// over an EMPTY element set either way. This file pins the two facts
// D135's "inert" verdict rests on, against BOTH bootstrap paths, so a
// later edit that makes either false fails this gate rather than being
// noticed only by a reader of the ADR. DSN-gated on OWL_MIGRATOR_DATABASE_URL
// (skips cleanly when unset, same as every other pgx test in this
// package).
package screeningledger

import (
	"context"
	"testing"
	"time"
)

// d135TruthTableCases is the exact four-row table D135's own transcript
// measured: every NULL/empty combination the leading precheck can see.
var d135TruthTableCases = []struct {
	name       string
	shaIsEmpty bool // false -> NULL, true -> '{}'
	cntIsEmpty bool
}{
	{"NULL_sha_vs_NULL_cnt", false, false},
	{"empty_sha_vs_NULL_cnt", true, false},
	{"NULL_sha_vs_empty_cnt", false, true},
	{"empty_sha_vs_empty_cnt", true, true},
}

// d135CallPurgeWithShape calls the array-form overload with either a
// NULL or an empty ('{}') array in each of the three positional
// arguments, per the case's own shape, and reports whether the call was
// REFUSED (raised an error) -- the "shipped_024_refuses" column in
// D135's own table, which must be false for all four cases.
func d135CallPurgeWithShape(t *testing.T, ctx context.Context, sink *PostgresSink, shaEmpty, cntEmpty bool) (refused bool) {
	t.Helper()
	shaExpr, cntExpr, maxExpr := "NULL::text[]", "NULL::int[]", "NULL::timestamptz[]"
	if shaEmpty {
		shaExpr = "ARRAY[]::text[]"
	}
	if cntEmpty {
		cntExpr = "ARRAY[]::int[]"
		maxExpr = "ARRAY[]::timestamptz[]"
	}
	q := "SELECT screening_ledger_purge_snapshots(" + shaExpr + ", $1, " + cntExpr + ", " + maxExpr + ", 'd135-operator', 'D135 truth table')"
	_, err := sink.conn.Exec(ctx, q, uniqueID("d135-ledger"))
	return err != nil
}

// TestCoalesceConflationInertOnMigrationPath is D136 item 8's migration-
// path half: the shipped 024 body (live on the migration-bootstrapped
// database) refuses NONE of the four NULL/empty combinations.
func TestCoalesceConflationInertOnMigrationPath(t *testing.T) {
	sink, ctx := newTestSink(t)
	for _, c := range d135TruthTableCases {
		t.Run(c.name, func(t *testing.T) {
			if refused := d135CallPurgeWithShape(t, ctx, sink, c.shaIsEmpty, c.cntIsEmpty); refused {
				t.Fatalf("ADR-0007 Addendum 15 D135: expected %s to be a no-op (not refused) on the migration bootstrap path -- the coalesce(cardinality(...),0) conflation was measured inert for exactly this case; if this now refuses, the conflation has become load-bearing (R62's re-entry condition) and D135 must be revisited", c.name)
			}
		})
	}
}

// TestCoalesceConflationInertOnSchemaSQLPath is D136 item 8's SchemaSQL
// half, on a throwaway database bootstrapped via the real
// PostgresSink.Migrate (this package's own SchemaSQL const) -- D125's
// own parity requirement (the array-form body is byte-equivalent on both
// paths) means this must produce the identical outcome.
func TestCoalesceConflationInertOnSchemaSQLPath(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	_, migratorDBDSN := newSchemaSQLOnlyScratchDatabase(t, ctx, superuserDSN, migratorDSN)
	sink, err := NewPostgresSink(ctx, migratorDBDSN, 10*time.Second)
	if err != nil {
		t.Fatalf("NewPostgresSink against the SchemaSQL-bootstrapped scratch database: %v", err)
	}
	defer sink.Close(ctx)

	for _, c := range d135TruthTableCases {
		t.Run(c.name, func(t *testing.T) {
			if refused := d135CallPurgeWithShape(t, ctx, sink, c.shaIsEmpty, c.cntIsEmpty); refused {
				t.Fatalf("ADR-0007 Addendum 15 D135: expected %s to be a no-op (not refused) on the SchemaSQL bootstrap path", c.name)
			}
		})
	}
}

// TestAnyNullAndAnyEmptyBothSelectZeroRows is D136 item 8's second
// pinned fact -- the property D135's inertness verdict actually rests
// on: `= ANY(NULL)` is NULL and `= ANY('{}')` is false, and BOTH select
// ZERO rows from screening_ledger_snapshot, even when the table holds a
// row that WOULD match a non-empty, non-NULL array. Pinned directly
// against the live catalog rather than only argued from PostgreSQL's
// documented NULL semantics.
func TestAnyNullAndAnyEmptyBothSelectZeroRows(t *testing.T) {
	sink, ctx := newTestSink(t)
	sha := uniqueID("d135-anyempty-sha")
	if _, err := sink.conn.Exec(ctx, `INSERT INTO screening_ledger_snapshot (snapshot_sha256, kind, created_at, expires_at, retention_class, envelope_json) VALUES ($1,'request', now(), '2100-01-01T00:00:00-05'::timestamptz, 'screening-standard', '{"nonce_base64":"AAAA","ciphertext_base64":"BBBB"}'::jsonb)`, sha); err != nil {
		t.Fatalf("insert fixture snapshot: %v", err)
	}

	var matchedNull, matchedEmpty int
	if err := sink.conn.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_snapshot WHERE snapshot_sha256 = ANY(NULL::text[])`).Scan(&matchedNull); err != nil {
		t.Fatalf("query = ANY(NULL): %v", err)
	}
	if err := sink.conn.QueryRow(ctx, `SELECT count(*) FROM screening_ledger_snapshot WHERE snapshot_sha256 = ANY(ARRAY[]::text[])`).Scan(&matchedEmpty); err != nil {
		t.Fatalf("query = ANY('{}'): %v", err)
	}
	if matchedNull != 0 {
		t.Fatalf("ADR-0007 Addendum 15 D135: expected `= ANY(NULL)` to select ZERO rows even against a non-empty table -- got %d (this is the fact D135's inertness verdict rests on)", matchedNull)
	}
	if matchedEmpty != 0 {
		t.Fatalf("ADR-0007 Addendum 15 D135: expected `= ANY('{}')` to select ZERO rows even against a non-empty table -- got %d (this is the fact D135's inertness verdict rests on)", matchedEmpty)
	}
}
