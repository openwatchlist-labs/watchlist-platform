// ADR-0007 Addendum 4 D40 (H-D HIGH, H-F MEDIUM): sec7_protect_ddl_objects()'s
// second phase -- CREATE RULE, inheritance attachment (all three forms),
// CREATE TRIGGER, CREATE INDEX and CREATE POLICY against a protected
// relation, none of which reports the protected relation's own OID to
// the objid membership check D34 already has, so none of them was
// caught before this addendum. D34's own five original forms and D26's
// tombstone extension are proven unchanged by
// ddl_event_trigger_pgx_test.go and d34_object_scoped_pgx_test.go,
// already running in this same package -- not re-asserted here, per the
// convention d34_object_scoped_pgx_test.go's own header sets for
// ddl_event_trigger_pgx_test.go's coverage.
package screeningledger

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// scratchTableOwnedByDDL creates a table with the same column shape as
// screening_ledger_anchor (so it can legally be an INHERITS child of
// it), owned by owl_ledger_ddl, via a committed statement outside any
// later rolled-back attempt transaction -- attemptBlocked's transaction
// is always rolled back, so anything the attempt itself depends on
// existing beforehand must be set up and committed separately.
func scratchTableOwnedByDDL(t *testing.T, ctx context.Context, superuserConn *pgx.Conn, superuserDSN, name string) {
	t.Helper()
	if _, err := superuserConn.Exec(ctx, `CREATE TABLE `+name+` (LIKE screening_ledger_anchor INCLUDING ALL)`); err != nil {
		t.Fatalf("create scratch table %s: %v", name, err)
	}
	if _, err := superuserConn.Exec(ctx, `ALTER TABLE `+name+` OWNER TO owl_ledger_ddl`); err != nil {
		t.Fatalf("chown scratch table %s to owl_ledger_ddl: %v", name, err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		cleanup, err := pgx.Connect(bg, superuserDSN)
		if err != nil {
			return
		}
		defer cleanup.Close(bg)
		_, _ = cleanup.Exec(bg, `DROP TABLE IF EXISTS `+name)
	})
}

// TestD40ProtectedRelationInvariantHoldsUnderEveryForm is D40 / D42
// point 4.
func TestD40ProtectedRelationInvariantHoldsUnderEveryForm(t *testing.T) {
	ddlDSN := requireLedgerDDLDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	ctx := context.Background()

	superuserSetup, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser (setup): %v", err)
	}
	defer superuserSetup.Close(context.Background())

	t.Run("CREATE_RULE", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, ddlDSN)
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer conn.Close(context.Background())
		attemptBlocked(t, ctx, conn, "D40: CREATE RULE ... DO INSTEAD NOTHING on screening_ledger_anchor",
			`CREATE RULE sec7_d40_rule AS ON INSERT TO screening_ledger_anchor DO INSTEAD NOTHING`)
	})

	t.Run("CREATE_TABLE_INHERITS", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer conn.Close(context.Background())
		// A brand-new child via CREATE TABLE ... INHERITS needs CREATE on
		// schema public, which owl_ledger_ddl deliberately lacks (D41
		// part three) -- run as superuser so this attempt isolates D40's
		// own protection from that privilege coincidence, the same
		// separation TestD34EventTriggerBlocksEveryCAPTwoEscape's G-G
		// subtest already established for RENAME TO/SET SCHEMA.
		name := "sec7_d40_inherit_child_" + strconv.FormatInt(time.Now().UnixNano(), 10)
		attemptBlocked(t, ctx, conn, "D40: CREATE TABLE ... INHERITS (screening_ledger_anchor)",
			`CREATE TABLE `+name+` (LIKE screening_ledger_anchor INCLUDING ALL) INHERITS (screening_ledger_anchor)`)
	})

	t.Run("CREATE_TEMP_TABLE_INHERITS_needs_no_grant", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, ddlDSN)
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer conn.Close(context.Background())
		// TEMP is held by default -- no schema CREATE grant needed at
		// all, so this form exists today with no privilege coincidence
		// standing in the way; only D40's own mechanism can block it.
		attemptBlocked(t, ctx, conn, "D40: CREATE TEMP TABLE ... INHERITS (screening_ledger_anchor)",
			`CREATE TEMP TABLE sec7_d40_temp_child (LIKE screening_ledger_anchor INCLUDING ALL) INHERITS (screening_ledger_anchor)`)
	})

	t.Run("ALTER_TABLE_INHERIT_pre_existing_child", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, ddlDSN)
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer conn.Close(context.Background())
		child := "sec7_d40_alter_inherit_child"
		scratchTableOwnedByDDL(t, ctx, superuserSetup, superuserDSN, child)
		attemptBlocked(t, ctx, conn, "D40: ALTER TABLE ... INHERIT screening_ledger_anchor",
			`ALTER TABLE `+child+` INHERIT screening_ledger_anchor`)
	})

	t.Run("CREATE_TRIGGER_raised_by_no_CAP", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, ddlDSN)
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer conn.Close(context.Background())
		attemptBlocked(t, ctx, conn, "D40: CREATE TRIGGER ... ON screening_ledger_anchor",
			`CREATE TRIGGER sec7_d40_trigger BEFORE INSERT ON screening_ledger_anchor FOR EACH ROW EXECUTE FUNCTION owl_reject_truncate()`)
	})

	t.Run("CREATE_UNIQUE_INDEX_raised_by_no_CAP", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer conn.Close(context.Background())
		// CREATE INDEX creates a new relation in the schema, so it needs
		// schema CREATE the same way CREATE TABLE does -- owl_ledger_ddl
		// lacks it (D41 part three), so this runs as superuser to
		// isolate D40's own protection. Indexed on (ledger_id, sequence)
		// rather than the addendum's own lab expression ((1)) -- this
		// database's screening_ledger_anchor carries real rows from
		// other tests in this package, and a UNIQUE index on a constant
		// expression would fail on a pre-existing 23505 the moment more
		// than one row exists, which is not the property this case is
		// testing. (ledger_id, sequence) is already unique by the
		// table's own primary key, so a second unique index over the
		// same columns cannot collide with existing data either way.
		attemptBlocked(t, ctx, conn, "D40: CREATE UNIQUE INDEX ON screening_ledger_anchor",
			`CREATE UNIQUE INDEX sec7_d40_index ON screening_ledger_anchor (ledger_id, sequence)`)
	})

	t.Run("CREATE_POLICY_raised_by_no_CAP", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, ddlDSN)
		if err != nil {
			t.Fatalf("connect as owl_ledger_ddl: %v", err)
		}
		defer conn.Close(context.Background())
		attemptBlocked(t, ctx, conn, "D40: CREATE POLICY ON screening_ledger_anchor",
			`CREATE POLICY sec7_d40_policy ON screening_ledger_anchor USING (true)`)
	})

	t.Run("collateral_CREATE_VIEW_and_DROP_VIEW_over_protected_table_succeed", func(t *testing.T) {
		// D37's collateral-safety requirement, and the case pg_depend's
		// deptype='a' resolver was rejected over: a view selecting from a
		// protected table is legitimate and must not be blocked.
		conn, err := pgx.Connect(ctx, superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer conn.Close(context.Background())
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(context.Background())
		if _, err := tx.Exec(ctx, `CREATE VIEW sec7_d40_collateral_view AS SELECT * FROM screening_ledger_anchor`); err != nil {
			t.Fatalf("CREATE VIEW over screening_ledger_anchor should succeed (D37 collateral safety): %v", err)
		}
		if _, err := tx.Exec(ctx, `DROP VIEW sec7_d40_collateral_view`); err != nil {
			t.Fatalf("DROP VIEW over screening_ledger_anchor should succeed (D37 collateral safety): %v", err)
		}
	})

	t.Run("collateral_unrelated_DDL_and_superuser_DDL_are_unaffected", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, migratorDSN)
		if err != nil {
			t.Fatalf("connect as owl_migrator: %v", err)
		}
		defer conn.Close(context.Background())
		tx, err := conn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer tx.Rollback(context.Background())

		scratch := "sec7_d40_collateral_" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if _, err := tx.Exec(ctx, `CREATE TABLE `+scratch+`(id int)`); err != nil {
			t.Fatalf("unrelated CREATE TABLE should succeed under D40's second phase: %v", err)
		}
		if _, err := tx.Exec(ctx, `CREATE OR REPLACE FUNCTION sec7_d40_collateral_fn() RETURNS int LANGUAGE sql AS $$ SELECT 1 $$`); err != nil {
			t.Fatalf("unrelated CREATE OR REPLACE FUNCTION should succeed under D40's second phase: %v", err)
		}
		if _, err := tx.Exec(ctx, `DROP TABLE `+scratch); err != nil {
			t.Fatalf("unrelated DROP TABLE should succeed under D40's second phase: %v", err)
		}

		superConn, err := pgx.Connect(ctx, superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superConn.Close(context.Background())
		superTx, err := superConn.Begin(ctx)
		if err != nil {
			t.Fatalf("begin (superuser): %v", err)
		}
		defer superTx.Rollback(context.Background())
		superScratch := "sec7_d40_super_collateral_" + strconv.FormatInt(time.Now().UnixNano(), 10)
		if _, err := superTx.Exec(ctx, `CREATE TABLE `+superScratch+`(id int)`); err != nil {
			t.Fatalf("unrelated superuser CREATE TABLE should succeed under D40's second phase: %v", err)
		}
		if _, err := superTx.Exec(ctx, `ALTER TABLE `+superScratch+` ADD COLUMN v int`); err != nil {
			t.Fatalf("unrelated superuser ALTER TABLE should succeed under D40's second phase: %v", err)
		}
		if _, err := superTx.Exec(ctx, `DROP TABLE `+superScratch); err != nil {
			t.Fatalf("unrelated superuser DROP TABLE should succeed under D40's second phase: %v", err)
		}
	})
}
