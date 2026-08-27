// ADR-0007 Addendum 5 D46/D49 test 5: I-A's second sub-case (a full
// restore) gets three distinct diagnostic messages instead of one bare,
// now-meaningless integer -- "this is a copy" (naming both instances),
// "dropped and recreated in place", and "genuinely gone, do not
// re-provision over this." Each is reproduced here against its own real
// scenario, plus the negative that makes D46's safety property real: a
// corrupted diagnostic column can change only the error text, never the
// passing path.
package screeningledger

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// withD34TriggersDisabled runs fn with both D34/D40 event triggers
// disabled (the documented, verified recovery-path mechanism,
// docs/operations/sec7-database-copies.md: "ALTER EVENT TRIGGER ...
// DISABLE succeeds even while the invariant is failing"), then always
// re-enables them -- via a real `defer`, not t.Cleanup, so control returns
// to the caller with the triggers already back on, including when fn
// itself calls t.Fatal (which unwinds through defers via runtime.Goexit).
// A t.Cleanup-based re-enable would instead run only at subtest teardown,
// after every "unrelated DDL should now be refused" probe a caller runs
// immediately following this call -- silently defeating those probes.
func withD34TriggersDisabled(t *testing.T, ctx context.Context, superuser *pgx.Conn, fn func()) {
	t.Helper()
	if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`); err != nil {
		t.Fatalf("disable sql_drop event trigger: %v", err)
	}
	if _, err := superuser.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
		t.Fatalf("disable ddl_command_end event trigger: %v", err)
	}
	defer func() {
		bg := context.Background()
		if _, err := superuser.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop ENABLE ALWAYS`); err != nil {
			t.Errorf("re-enable sql_drop event trigger: %v", err)
		}
		if _, err := superuser.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS`); err != nil {
			t.Errorf("re-enable ddl_command_end event trigger: %v", err)
		}
	}()
	fn()
}

func TestD40DiagnosticNamesTheRelationAndTheInstance(t *testing.T) {
	ctx := context.Background()
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)

	t.Run("copy", func(t *testing.T) {
		restoredDSN := requireRestoredDatabaseURL(t)
		conn, err := pgx.Connect(ctx, restoredDSN)
		if err != nil {
			t.Fatalf("connect to the restored database as owl_migrator: %v", err)
		}
		defer conn.Close(context.Background())

		_, err = conn.Exec(ctx, `GRANT SELECT ON screening_ledger_event TO owl_app`)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 5 D46: unrelated DDL succeeded against a restored database with dangling registry OIDs")
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "P0001" {
			t.Fatalf("expected SQLSTATE P0001 (raise_exception, from D40's diagnostic), got %q: %v", pgErrorCode(err), err)
		}
		if !strings.Contains(err.Error(), "This database is a copy or restore of another") {
			t.Fatalf("expected message (a) (\"this is a copy\"), got: %v", err)
		}
		if !strings.Contains(err.Error(), "registry recorded instance") || !strings.Contains(err.Error(), "live instance") {
			t.Fatalf("expected message (a) to name both instances, got: %v", err)
		}
	})

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())
	migrator, err := pgx.Connect(ctx, migratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migrator.Close(context.Background())

	// registerScratchRelation gives a throwaway table (unrelated to the
	// two real protected relations) a sec7_protected_relation row of its
	// own -- D40's second phase loops over every row in that table,
	// regardless of what the triggering DDL statement targeted, so a
	// scratch relation exercises the same code path the real
	// anchor/tombstone rows do without any risk to them.
	registerScratchRelation := func(t *testing.T, name string) {
		t.Helper()
		if _, err := superuser.Exec(ctx, `
			INSERT INTO sec7_protected_relation (objid, relowner, relkind, relrowsecurity, relforcerowsecurity, trigger_oids, index_defs, policy_oids, identity)
			SELECT c.oid, c.relowner, c.relkind, c.relrowsecurity, c.relforcerowsecurity, ARRAY[]::oid[], ARRAY[]::text[], ARRAY[]::oid[], $1
			FROM pg_class c WHERE c.relname = $2
		`, "public."+name, name); err != nil {
			t.Fatalf("register scratch relation %s: %v", name, err)
		}
	}

	// cleanupScratch tears a scenario down as ONE ordered operation
	// (disable triggers, drop the leftover table and the stale registry
	// row, re-enable) rather than as separately t.Cleanup-registered
	// steps: Go's Cleanup stack runs LIFO, and a plain "DROP TABLE" step
	// registered after "DELETE the registry row" would run BEFORE it at
	// teardown -- tripping the still-registered stale row it exists to
	// remove. Safe to call whether or not the table still exists (DROP
	// TABLE IF EXISTS) or the row was ever inserted (DELETE matching
	// zero rows).
	cleanupScratch := func(t *testing.T, name string) {
		t.Helper()
		bg := context.Background()
		if _, err := superuser.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`); err != nil {
			t.Errorf("cleanup %s: disable sql_drop trigger: %v", name, err)
			return
		}
		if _, err := superuser.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
			t.Errorf("cleanup %s: disable ddl_command_end trigger: %v", name, err)
		}
		if _, err := superuser.Exec(bg, `DROP TABLE IF EXISTS `+name); err != nil {
			t.Errorf("cleanup %s: drop table: %v", name, err)
		}
		if _, err := superuser.Exec(bg, `DELETE FROM sec7_protected_relation WHERE identity = $1`, "public."+name); err != nil {
			t.Errorf("cleanup %s: delete registry row: %v", name, err)
		}
		if _, err := superuser.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop ENABLE ALWAYS`); err != nil {
			t.Errorf("cleanup %s: re-enable sql_drop trigger: %v", name, err)
		}
		if _, err := superuser.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS`); err != nil {
			t.Errorf("cleanup %s: re-enable ddl_command_end trigger: %v", name, err)
		}
	}

	t.Run("dropped_and_recreated_in_place", func(t *testing.T) {
		const name = "d46_probe_recreated"
		withD34TriggersDisabled(t, ctx, superuser, func() {
			if _, err := superuser.Exec(ctx, `CREATE TABLE `+name+` (id int PRIMARY KEY)`); err != nil {
				t.Fatalf("create scratch table: %v", err)
			}
			registerScratchRelation(t, name)
			if _, err := superuser.Exec(ctx, `DROP TABLE `+name); err != nil {
				t.Fatalf("drop scratch table: %v", err)
			}
			if _, err := superuser.Exec(ctx, `CREATE TABLE `+name+` (id int PRIMARY KEY)`); err != nil {
				t.Fatalf("recreate scratch table: %v", err)
			}
		})
		t.Cleanup(func() { cleanupScratch(t, name) })

		// Triggers are back ENABLE ALWAYS now (withD34TriggersDisabled's
		// defer already ran). Any DDL, by anyone, re-runs D40's second
		// phase over every row in sec7_protected_relation -- including
		// the stale one this scenario just built. The statement below is
		// refused inside its own implicit transaction, so the table is
		// never actually created -- nothing to clean up afterward, and a
		// DROP TABLE IF EXISTS probe here would itself re-trip the same
		// still-registered stale row.
		_, err := superuser.Exec(ctx, `CREATE TABLE d46_unrelated_recreated (x int)`)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 5 D46: unrelated DDL succeeded while a registered relation had been dropped and recreated in place")
		}
		if !strings.Contains(err.Error(), "the relation was dropped and recreated") {
			t.Fatalf("expected message (b) (\"dropped and recreated in place\"), got: %v", err)
		}
		if strings.Contains(err.Error(), "This database is a copy") {
			t.Fatalf("message (b) must not read as message (a) -- the instance binding matches here, only the relation's own OID changed: %v", err)
		}
	})

	t.Run("name_absent", func(t *testing.T) {
		const name = "d46_probe_absent"
		withD34TriggersDisabled(t, ctx, superuser, func() {
			if _, err := superuser.Exec(ctx, `CREATE TABLE `+name+` (id int PRIMARY KEY)`); err != nil {
				t.Fatalf("create scratch table: %v", err)
			}
			registerScratchRelation(t, name)
			if _, err := superuser.Exec(ctx, `DROP TABLE `+name); err != nil {
				t.Fatalf("drop scratch table: %v", err)
			}
		})
		t.Cleanup(func() { cleanupScratch(t, name) })

		// As above: refused inside its own implicit transaction, so
		// nothing is left to clean up.
		_, err := superuser.Exec(ctx, `CREATE TABLE d46_unrelated_absent (x int)`)
		if err == nil {
			t.Fatal("ADR-0007 Addendum 5 D46: unrelated DDL succeeded while a registered relation was genuinely gone")
		}
		if !strings.Contains(err.Error(), "no relation of that name is present") {
			t.Fatalf("expected message (c) (\"genuinely gone\"), got: %v", err)
		}
	})

	t.Run("corrupted_identity_cannot_affect_the_passing_path", func(t *testing.T) {
		// D46's own safety property: identity is read only AFTER the
		// existence check has already decided to pass. Corrupting it on
		// an otherwise-healthy database must not change that decision.
		var original string
		if err := superuser.QueryRow(ctx, `SELECT identity FROM sec7_protected_relation WHERE identity = 'public.screening_ledger_retention_tombstone'`).Scan(&original); err != nil {
			t.Fatalf("read original identity: %v", err)
		}
		if _, err := superuser.Exec(ctx, `UPDATE sec7_protected_relation SET identity = 'public.this_name_resolves_to_nothing' WHERE identity = $1`, original); err != nil {
			t.Fatalf("corrupt identity column: %v", err)
		}
		t.Cleanup(func() {
			if _, err := superuser.Exec(context.Background(), `UPDATE sec7_protected_relation SET identity = $1 WHERE identity = 'public.this_name_resolves_to_nothing'`, original); err != nil {
				t.Errorf("restore identity column: %v", err)
			}
		})

		if _, err := migrator.Exec(ctx, `CREATE TABLE d46_negative_probe (x int)`); err != nil {
			t.Fatalf("ADR-0007 Addendum 5 D46: unrelated DDL failed with a corrupted (but unreachable, since objid still resolves) identity column -- the diagnostic column must never affect the passing path: %v", err)
		}
		if _, err := migrator.Exec(ctx, `DROP TABLE d46_negative_probe`); err != nil {
			t.Fatalf("cleanup d46_negative_probe: %v", err)
		}
	})
}
