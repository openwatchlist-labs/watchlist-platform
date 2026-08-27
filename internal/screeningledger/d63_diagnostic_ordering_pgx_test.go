// ADR-0007 Addendum 7 D63/D67 test 4 (K-C, LOW): D54(b) made the
// relation loop deterministic by ORDER BY identity, but identity is a
// NAME, and the loop runs every property check for relation n before
// relation n+1's existence check -- a database whose anchor merely
// drifted and whose tombstone is entirely absent reports only the
// drift, three times, and never mentions the absence, because
// "screening_ledger_anchor" sorts before
// "screening_ledger_retention_tombstone". This file reproduces exactly
// that composite state and asserts the absent relation is now named
// first (false sorts before true in PostgreSQL), with identity retained
// as the tiebreaker, and that the ordering survives a physically
// reversed heap layout, not just repeated probes against one unchanged
// physical order (which TestD54DiagnosticOrderingIsDeterministic
// already covers and this file does not duplicate).
package screeningledger

import (
	"context"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

// d63BuildCompositeDriftState leaves the clone's anchor relation
// index-drifted (an extra, undeclared index) and the tombstone relation
// entirely dropped -- CAP #6's own composite state, reproduced with the
// event triggers disabled so the drift itself does not trip D34/D40
// before the probe.
func d63BuildCompositeDriftState(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
	t.Helper()
	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, `CREATE INDEX zz_d63_drift_ix ON screening_ledger_anchor (anchored_at)`); err != nil {
			t.Fatalf("drift the anchor's index set: %v", err)
		}
		if _, err := superuser.Exec(ctx, `DROP TABLE screening_ledger_retention_tombstone`); err != nil {
			t.Fatalf("drop the tombstone table: %v", err)
		}
	})
}

func d63AssertAbsenceReportedFirst(t *testing.T, probeErr error) {
	t.Helper()
	if probeErr == nil {
		t.Fatal("ADR-0007 Addendum 7 D63: unrelated DDL succeeded against a database with one relation drifted and one absent")
	}
	msg := probeErr.Error()
	if !strings.Contains(msg, "screening_ledger_retention_tombstone") {
		t.Fatalf("ADR-0007 Addendum 7 D63: expected the ABSENT relation (tombstone) to be reported first (evidence-ordered: absence before drift), got: %v", msg)
	}
	if strings.Contains(msg, "its index set changed") {
		t.Fatalf("ADR-0007 Addendum 7 D63: expected the absence message, not the drift message, to be reported first: %v", msg)
	}
	if !strings.Contains(msg, "no longer exists") {
		t.Fatalf("expected an absence-shaped message, got: %v", msg)
	}
}

func TestD63DiagnosticOrdersByEvidence(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	t.Run("natural_insertion_order", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuser, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuser.Close(context.Background())

		d63BuildCompositeDriftState(t, ctx, superuser)

		_, probeErr := superuser.Exec(ctx, `CREATE TABLE zz_d63_probe_a (id int)`)
		d63AssertAbsenceReportedFirst(t, probeErr)

		// Repeated probes against the same unchanged state must keep
		// reporting the same message -- not merely the same relation.
		var first string
		for i := 0; i < 3; i++ {
			_, err := superuser.Exec(ctx, `CREATE TABLE zz_d63_repeat (id int)`)
			d63AssertAbsenceReportedFirst(t, err)
			if i == 0 {
				first = err.Error()
			} else if err.Error() != first {
				t.Fatalf("message varied across repeated runs:\nrun 0: %s\nrun %d: %s", first, i, err.Error())
			}
		}
	})

	// CAP #6's own stronger check: physically reverse the registry
	// rows' heap order (DELETE then re-INSERT in the opposite order) and
	// confirm the SQL-level ORDER BY -- not incidental heap scan order
	// -- is what determines visitation order.
	t.Run("physically_reversed_heap_order", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuser, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuser.Close(context.Background())

		d63BuildCompositeDriftState(t, ctx, superuser)

		withD34TriggersDisabled(t, ctx, superuser, func() {
			// Re-insert the two rows in reverse identity order (tombstone
			// then anchor) by round-tripping through a temp table, so the
			// registry's on-disk row order no longer matches identity
			// order at all -- the shape CAP #6 built by physically
			// reversing heap order.
			if _, err := superuser.Exec(ctx, `CREATE TEMP TABLE zz_d63_reorder AS SELECT * FROM sec7_protected_relation ORDER BY identity DESC`); err != nil {
				t.Fatalf("snapshot registry in reverse identity order: %v", err)
			}
			if _, err := superuser.Exec(ctx, `DELETE FROM sec7_protected_relation`); err != nil {
				t.Fatalf("clear registry: %v", err)
			}
			if _, err := superuser.Exec(ctx, `INSERT INTO sec7_protected_relation SELECT * FROM zz_d63_reorder`); err != nil {
				t.Fatalf("re-insert registry in reversed order: %v", err)
			}
			if _, err := superuser.Exec(ctx, `DROP TABLE zz_d63_reorder`); err != nil {
				t.Fatalf("drop temp reorder table: %v", err)
			}
		})

		_, probeErr := superuser.Exec(ctx, `CREATE TABLE zz_d63_probe_b (id int)`)
		d63AssertAbsenceReportedFirst(t, probeErr)
	})
}
