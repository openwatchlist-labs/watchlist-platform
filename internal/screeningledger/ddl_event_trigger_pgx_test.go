// ADR-0007 Addendum 2 D26 (F-F, the highest-risk item in this addendum,
// with its own gated empirical proof obligation): "This design does not
// get to assert D26 works." CAP §7.3 executed five forms of DDL against
// screening_ledger_anchor as owl_ledger_ddl -- the table's own owner --
// and all five succeeded: DROP TRIGGER screening_ledger_anchor_immutable;
// a drop-then-DELETE transaction; a drop-both-then-TRUNCATE transaction;
// ALTER TABLE ... DISABLE TRIGGER ALL; and DROP TABLE. D26's superuser-
// provisioned event trigger (scripts/ci/provision_test_roles.sh
// grant-anchor-ownership) is discharged only by reproducing that exact
// sequence here, against a real Postgres, with every attempt blocked and
// its SQLSTATE captured rather than inferred.
//
// The 19 D17 role-separation escalation attempts this stage must not
// weaken are anchor_pgx_test.go's own suite (TestSEC7AnchorWriter*,
// TestSEC7LedgerWriterCannotInsertAnchor, TestSEC7*Truncate); they are
// unmodified by this addendum and run alongside this file in the same
// package -- confirmed together, not re-asserted here.
package screeningledger

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

// TestD26EventTriggerBlocksAllFiveCAPAttackForms is CAP §7.3's exact
// sequence, executed as owl_ledger_ddl over OWL_LEDGER_DDL_DATABASE_URL --
// the same connection and identity anchor_pgx_test.go's
// TestSEC7AnchorTableRejectsTruncate already uses to prove the guard holds
// even for the table's true owner. Each of the five forms runs in its own
// transaction, always rolled back, so this suite never actually empties or
// alters the shared CI database's anchor table -- even in the failure case
// where the event trigger is unexpectedly absent and a DROP or ALTER would
// otherwise succeed.
func TestD26EventTriggerBlocksAllFiveCAPAttackForms(t *testing.T) {
	ddlDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, ddlDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer conn.Close(context.Background())

	attempt := func(t *testing.T, name string, stmts ...string) {
		t.Helper()
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("%s: begin: %v", name, err)
		}
		defer tx.Rollback(ctx)

		var lastErr error
		for _, sql := range stmts {
			if _, execErr := tx.Exec(ctx, sql); execErr != nil {
				lastErr = execErr
				break
			}
		}
		if lastErr == nil {
			t.Fatalf("%s: succeeded as owl_ledger_ddl (the table's own owner); expected D26's event trigger to block it", name)
		}
		if code := pgErrorCode(lastErr); code != "P0001" {
			t.Fatalf("%s: expected SQLSTATE P0001 (raise_exception, from D26's event trigger), got %q: %v", name, code, lastErr)
		}
		t.Logf("%s: correctly blocked, SQLSTATE %s: %v", name, pgErrorCode(lastErr), lastErr)
	}

	attempt(t, "form 1: DROP TRIGGER screening_ledger_anchor_immutable",
		`DROP TRIGGER screening_ledger_anchor_immutable ON screening_ledger_anchor`)

	attempt(t, "form 2: drop-then-DELETE transaction",
		`DROP TRIGGER screening_ledger_anchor_immutable ON screening_ledger_anchor`,
		`DELETE FROM screening_ledger_anchor`)

	attempt(t, "form 3: drop-both-then-TRUNCATE transaction",
		`DROP TRIGGER screening_ledger_anchor_immutable ON screening_ledger_anchor`,
		`DROP TRIGGER screening_ledger_anchor_no_truncate ON screening_ledger_anchor`,
		`TRUNCATE screening_ledger_anchor`)

	attempt(t, "form 4: ALTER TABLE ... DISABLE TRIGGER ALL",
		`ALTER TABLE screening_ledger_anchor DISABLE TRIGGER ALL`)

	attempt(t, "form 5: DROP TABLE",
		`DROP TABLE screening_ledger_anchor`)
}

// TestD26EventTriggersAreEnabledAlways is a direct catalog check that the
// two event triggers provisioning installs are both present and
// ENABLE ALWAYS -- D26's own stated reason: "so it also fires under
// session_replication_role = 'replica'." A misconfigured DISABLE or
// ENABLE REPLICA state would not be caught by
// TestD26EventTriggerBlocksAllFiveCAPAttackForms alone if that test
// happened to run under the default session_replication_role, so this
// asserts the catalog state directly.
func TestD26EventTriggersAreEnabledAlways(t *testing.T) {
	migratorDSN := requireMigratorDSN(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, migratorDSN)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer conn.Close(context.Background())

	for _, name := range []string{"sec7_protect_ddl_objects_on_drop", "sec7_protect_ddl_objects_on_alter"} {
		var enabled string
		if err := conn.QueryRow(ctx, `SELECT evtenabled FROM pg_event_trigger WHERE evtname = $1`, name).Scan(&enabled); err != nil {
			t.Fatalf("event trigger %s: %v (has scripts/ci/provision_test_roles.sh grant-anchor-ownership run?)", name, err)
		}
		if enabled != "A" {
			t.Fatalf("event trigger %s has evtenabled=%q, want %q (ENABLE ALWAYS)", name, enabled, "A")
		}
	}
}
