// ADR-0007 Addendum 3 D34/D37 (G-B, G-D, G-G): CAP #2 got past D26's
// event trigger three ways -- DROP OWNED BY (outside the sql_drop
// trigger's WHEN TAG list entirely, G-B), CREATE OR REPLACE FUNCTION on
// the shared guard functions every one of the eight protected tables'
// row-immutability trigger calls (a tag neither trigger watched, G-D),
// and ALTER TABLE ... RENAME TO (caught by tag, but object_identity
// changes on rename while the OID does not, G-G). D34 replaces the
// tag-filtered, identity-matched pair with two unfiltered, OID-matched
// event triggers backed by the sec7_protected_object registry.
//
// ddl_event_trigger_pgx_test.go's TestD26EventTriggerBlocksAllFiveCAPAttackForms
// already proves the five original D26 forms still block against the
// anchor table -- unchanged, run alongside this file in the same
// package, not re-asserted here. This file adds what that suite does
// not cover: the same four applicable forms against the tombstone
// relation (CAP #2 §7.1's own extension, which no committed test
// covered before this), the three CAP #2 escapes themselves, and the
// collateral-damage case an unfiltered trigger has to pass -- ordinary
// DDL against objects the registry does not name must be completely
// unaffected.
package screeningledger

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func requireBootstrapSuperuserDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_BOOTSTRAP_SUPERUSER_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_BOOTSTRAP_SUPERUSER_DATABASE_URL not set; ADR-0007 Addendum 3 D34/G-G's RENAME TO/SET SCHEMA reproduction requires a role with CREATE on schema public to separate the event trigger's own effect from a privilege accident (see scripts/ci/run-ci.sh)")
	}
	return dsn
}

// attemptBlocked runs stmts in one transaction, always rolled back
// (never committed, even on the failure path where the trigger is
// unexpectedly absent and a destructive statement would otherwise
// succeed), and asserts the LAST statement fails with SQLSTATE P0001 --
// the same shape ddl_event_trigger_pgx_test.go's own attempt helper
// uses, reused here rather than duplicated with a different signature.
func attemptBlocked(t *testing.T, ctx context.Context, conn *pgx.Conn, name string, stmts ...string) {
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
		t.Fatalf("%s: succeeded; expected D34's event trigger to block it", name)
	}
	if code := pgErrorCode(lastErr); code != "P0001" {
		t.Fatalf("%s: expected SQLSTATE P0001 (raise_exception, from D34's event trigger), got %q: %v", name, code, lastErr)
	}
	t.Logf("%s: correctly blocked, SQLSTATE %s: %v", name, pgErrorCode(lastErr), lastErr)
}

// TestD34TombstoneTableRejectsAllFourApplicableCAPForms is CAP #2 §7.1's
// own extension, run as owl_ledger_ddl (the tombstone table's owner, per
// D27) against screening_ledger_retention_tombstone -- the four forms
// applicable there (there is no "drop-both-then-TRUNCATE" distinct case;
// TRUNCATE is covered by the same DISABLE/DROP-guard forms), which no
// committed test covered before this addendum even though D26's own
// identity list and D27's closing paragraph both claimed this relation
// was protected.
func TestD34TombstoneTableRejectsAllFourApplicableCAPForms(t *testing.T) {
	ddlDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	conn, err := pgx.Connect(ctx, ddlDSN)
	if err != nil {
		t.Fatalf("connect as owl_ledger_ddl: %v", err)
	}
	defer conn.Close(context.Background())

	attemptBlocked(t, ctx, conn, "tombstone form 1: DROP TRIGGER screening_ledger_retention_tombstone_immutable",
		`DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone`)

	attemptBlocked(t, ctx, conn, "tombstone form 2: drop-then-DELETE transaction",
		`DROP TRIGGER screening_ledger_retention_tombstone_immutable ON screening_ledger_retention_tombstone`,
		`DELETE FROM screening_ledger_retention_tombstone`)

	attemptBlocked(t, ctx, conn, "tombstone form 3: ALTER TABLE ... DISABLE TRIGGER ALL",
		`ALTER TABLE screening_ledger_retention_tombstone DISABLE TRIGGER ALL`)

	attemptBlocked(t, ctx, conn, "tombstone form 4: DROP TABLE",
		`DROP TABLE screening_ledger_retention_tombstone`)
}

// TestD34EventTriggerBlocksEveryCAPTwoEscape is D37's required
// reproduction of the three CAP #2 findings D34 exists to close, each
// as its own attempt with the SQLSTATE captured, plus the
// collateral-damage case that proves the unfiltered trigger costs
// nothing on ordinary DDL.
func TestD34EventTriggerBlocksEveryCAPTwoEscape(t *testing.T) {
	ddlDSN := requireLedgerDDLDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	ctx := context.Background()

	t.Run("G-B_DROP_OWNED_BY_escapes_tag_filter_entirely", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, ddlDSN)
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer conn.Close(context.Background())
		// DROP OWNED BY carries command tag "DROP OWNED", which was
		// outside D26's WHEN TAG IN ('DROP TABLE', 'DROP TRIGGER') list
		// entirely -- the sql_drop trigger never fired at all, and both
		// protected tables were destroyed with the event triggers still
		// enabled but blind to this tag. D34 removes the tag filter, so
		// this is now caught by object-identity (objid) membership alone,
		// regardless of what DDL form reached it.
		attemptBlocked(t, ctx, conn, "G-B: DROP OWNED BY owl_ledger_ddl",
			`DROP OWNED BY owl_ledger_ddl`)
	})

	t.Run("G-D_CREATE_OR_REPLACE_FUNCTION_on_shared_guard_functions", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, migratorDSN)
		if err != nil {
			t.Fatalf("connect as owl_migrator: %v", err)
		}
		defer conn.Close(context.Background())
		// owl_migrator owns screening_ledger_reject_mutation() and
		// owl_reject_truncate() (created by 008g/012 and again by
		// SchemaSQL, all run as owl_migrator) -- every row-immutability
		// and TRUNCATE-guard trigger on all eight protected tables calls
		// one of these two functions. CREATE OR REPLACE FUNCTION carries
		// command tag "CREATE FUNCTION", which was on neither of D26's
		// two WHEN TAG lists ('DROP TABLE'/'DROP TRIGGER' on sql_drop,
		// 'ALTER TABLE' on ddl_command_end) -- CAP #2 §7.4 neutered both
		// functions this way with no DDL D26 inspected at all. D34
		// registers both functions themselves as protected objects, by
		// OID, so this is now caught regardless of tag.
		attemptBlocked(t, ctx, conn, "G-D: CREATE OR REPLACE FUNCTION screening_ledger_reject_mutation()",
			`CREATE OR REPLACE FUNCTION screening_ledger_reject_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NEW; END $$`)
		attemptBlocked(t, ctx, conn, "G-D: CREATE OR REPLACE FUNCTION owl_reject_truncate()",
			`CREATE OR REPLACE FUNCTION owl_reject_truncate() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END $$`)
	})

	t.Run("G-G_RENAME_TO_and_SET_SCHEMA_do_not_escape_OID_matching", func(t *testing.T) {
		// A privileged connection is required to separate "the event
		// trigger blocked it" from "a privilege accident blocked it":
		// owl_ledger_ddl owns the anchor table but is deliberately
		// granted no CREATE on schema public, so a bare attempt as that
		// role fails on 42501 before the trigger ever runs -- exactly
		// what CAP #2 §7.2 found and deliberately separated by testing as
		// the bootstrap superuser instead. object_identity changes on
		// RENAME TO / SET SCHEMA; the OID this addendum's own design pass
		// confirmed by execution does not -- so D34's OID-keyed match
		// must catch both regardless of who runs them.
		conn, err := pgx.Connect(ctx, superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer conn.Close(context.Background())

		attemptBlocked(t, ctx, conn, "G-G: ALTER TABLE screening_ledger_anchor RENAME TO",
			`ALTER TABLE screening_ledger_anchor RENAME TO sec7_d34_test_renamed`)

		schemaTx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer schemaTx.Rollback(ctx)
		if _, err := schemaTx.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS sec7_d34_test_schema`); err != nil {
			t.Fatalf("create scratch schema: %v", err)
		}
		if _, err := schemaTx.Exec(ctx, `ALTER TABLE screening_ledger_anchor SET SCHEMA sec7_d34_test_schema`); err == nil {
			t.Fatal("ALTER TABLE screening_ledger_anchor SET SCHEMA succeeded; expected D34's event trigger to block it")
		} else if code := pgErrorCode(err); code != "P0001" {
			t.Fatalf("SET SCHEMA: expected SQLSTATE P0001, got %q: %v", code, err)
		} else {
			t.Logf("G-G: ALTER TABLE screening_ledger_anchor SET SCHEMA: correctly blocked, SQLSTATE %s: %v", code, err)
		}
	})

	t.Run("collateral_damage_ordinary_DDL_is_unaffected", func(t *testing.T) {
		// The whole cost of D31's principle (unfiltered triggers, seeing
		// every DDL statement) is that a defect in the guard function
		// would break DDL database-wide (R17) -- this is the committed
		// proof that, as shipped, it does not. Run as owl_migrator, on
		// objects nowhere in sec7_protected_object.
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

		scratch := "sec7_d34_collateral_" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if _, err := tx.Exec(ctx, `CREATE TABLE `+scratch+`(id int)`); err != nil {
			t.Fatalf("unrelated CREATE TABLE should succeed under D34's unfiltered trigger: %v", err)
		}
		if _, err := tx.Exec(ctx, `CREATE OR REPLACE FUNCTION sec7_d34_collateral_fn() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$`); err != nil {
			t.Fatalf("unrelated CREATE OR REPLACE FUNCTION should succeed under D34's unfiltered trigger: %v", err)
		}
		if _, err := tx.Exec(ctx, `DROP TABLE `+scratch); err != nil {
			t.Fatalf("unrelated DROP TABLE should succeed under D34's unfiltered trigger: %v", err)
		}
		if _, err := tx.Exec(ctx, `DROP FUNCTION sec7_d34_collateral_fn()`); err != nil {
			t.Fatalf("unrelated DROP FUNCTION should succeed under D34's unfiltered trigger: %v", err)
		}
	})
}
