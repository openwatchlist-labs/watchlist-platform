// ADR-0007 Addendum 6 D55/D58 test 7 (J-E, LOW): one referent, one
// spelling. sec7_protected_relation.identity is written from
// pg_identify_object, which quotes an identifier when SQL requires it;
// D46's resolver used to compare against an unquoted nspname||'.'||
// relname concatenation, which never quotes -- so any protected
// relation whose schema or table name required quoting always
// degraded to message (c) ("genuinely gone"), and the unquoted key was
// ambiguous besides (two different relations can share one
// concatenated string). The fix joins through pg_identify_object on
// both sides, so the value being matched and the value that was
// recorded cannot disagree by construction.
package screeningledger

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// d55RegisterAndDropRecreate registers objid/identity as a protected
// relation, then drops and recreates it in place (with the D34/D40
// event triggers disabled for the setup, per the established
// withD34TriggersDisabled convention), leaving the caller to trip the
// diagnostic with a subsequent unrelated DDL statement.
func d55RegisterAndDropRecreate(t *testing.T, ctx context.Context, superuser *pgx.Conn, createStmt, identityQuery, dropStmt string) {
	t.Helper()
	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, createStmt); err != nil {
			t.Fatalf("create scratch relation: %v", err)
		}
		var objid uint32
		var identity string
		if err := superuser.QueryRow(ctx, identityQuery).Scan(&objid, &identity); err != nil {
			t.Fatalf("resolve scratch relation identity: %v", err)
		}
		if _, err := superuser.Exec(ctx, `
			INSERT INTO sec7_protected_relation (objid, relowner, relkind, relrowsecurity, relforcerowsecurity, trigger_oids, index_defs, policy_oids, identity)
			SELECT $1, c.relowner, c.relkind, c.relrowsecurity, c.relforcerowsecurity, ARRAY[]::oid[], ARRAY[]::text[], ARRAY[]::oid[], $2
			FROM pg_class c WHERE c.oid = $1
		`, objid, identity); err != nil {
			t.Fatalf("register scratch relation: %v", err)
		}
		if _, err := superuser.Exec(ctx, dropStmt); err != nil {
			t.Fatalf("drop scratch relation: %v", err)
		}
		if _, err := superuser.Exec(ctx, createStmt); err != nil {
			t.Fatalf("recreate scratch relation: %v", err)
		}
	})
}

func TestD55ResolverAgreesWithRecordedIdentity(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	ctx := context.Background()

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	cases := []struct {
		name     string
		setup    []string
		create   string
		identity string // WHERE clause value passed to identityQuery below
		drop     string
		cleanup  []string
	}{
		{
			// pg_identify_object renders: "a.b".c
			name:     `schema_name_contains_dot`,
			setup:    []string{`CREATE SCHEMA IF NOT EXISTS "d55_a.b"`},
			create:   `CREATE TABLE "d55_a.b".c (id int PRIMARY KEY)`,
			identity: `"d55_a.b".c`,
			drop:     `DROP TABLE "d55_a.b".c`,
			cleanup:  []string{`DROP SCHEMA IF EXISTS "d55_a.b" CASCADE`},
		},
		{
			// pg_identify_object renders: d55_a."b.c"
			name:     `table_name_contains_dot`,
			setup:    []string{`CREATE SCHEMA IF NOT EXISTS d55_a`},
			create:   `CREATE TABLE d55_a."b.c" (id int PRIMARY KEY)`,
			identity: `d55_a."b.c"`,
			drop:     `DROP TABLE d55_a."b.c"`,
			cleanup:  []string{`DROP SCHEMA IF EXISTS d55_a CASCADE`},
		},
		{
			// pg_identify_object renders: public."Weird Name"
			name:     `mixed_case_and_space`,
			setup:    nil,
			create:   `CREATE TABLE public."D55 Weird Name" (id int PRIMARY KEY)`,
			identity: `public."D55 Weird Name"`,
			drop:     `DROP TABLE public."D55 Weird Name"`,
			cleanup:  []string{`DROP TABLE IF EXISTS public."D55 Weird Name"`},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, stmt := range tc.setup {
				if _, err := superuser.Exec(ctx, stmt); err != nil {
					t.Fatalf("setup %q: %v", stmt, err)
				}
			}
			t.Cleanup(func() {
				bg := context.Background()
				c, err := pgx.Connect(bg, superuserDSN)
				if err != nil {
					t.Errorf("cleanup connect: %v", err)
					return
				}
				defer c.Close(bg)
				if _, err := c.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`); err != nil {
					t.Errorf("cleanup disable drop trigger: %v", err)
				}
				if _, err := c.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
					t.Errorf("cleanup disable alter trigger: %v", err)
				}
				if _, err := c.Exec(bg, `DELETE FROM sec7_protected_relation WHERE identity = $1`, tc.identity); err != nil {
					t.Errorf("cleanup delete registry row: %v", err)
				}
				for _, stmt := range tc.cleanup {
					if _, err := c.Exec(bg, stmt); err != nil {
						t.Errorf("cleanup %q: %v", stmt, err)
					}
				}
				if _, err := c.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop ENABLE ALWAYS`); err != nil {
					t.Errorf("cleanup re-enable drop trigger: %v", err)
				}
				if _, err := c.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS`); err != nil {
					t.Errorf("cleanup re-enable alter trigger: %v", err)
				}
			})

			identityQuery := `SELECT c.oid, (pg_identify_object('pg_class'::regclass, c.oid, 0)).identity FROM pg_class c WHERE ` +
				identityWhereClause(tc.identity)
			d55RegisterAndDropRecreate(t, ctx, superuser, tc.create, identityQuery, tc.drop)

			_, probeErr := superuser.Exec(ctx, `CREATE TABLE zz_d55_probe_`+sanitizeForIdent(tc.name)+` (id int)`)
			defer func() {
				_, _ = superuser.Exec(ctx, `DROP TABLE IF EXISTS zz_d55_probe_`+sanitizeForIdent(tc.name))
			}()
			if probeErr == nil {
				t.Fatalf("ADR-0007 Addendum 6 D55: expected the drop-and-recreate on %s to trip the diagnostic", tc.identity)
			}
			var pgErr *pgconn.PgError
			if !errors.As(probeErr, &pgErr) || pgErr.Code != "P0001" {
				t.Fatalf("expected SQLSTATE P0001, got %q: %v", pgErrorCode(probeErr), probeErr)
			}
			if !strings.Contains(probeErr.Error(), "the relation was dropped and recreated in place") {
				t.Fatalf("ADR-0007 Addendum 6 D55: expected message (b) (\"dropped and recreated in place\") -- a resolver that disagrees with the recorded spelling would instead report message (c) (\"genuinely gone\") -- got: %v", probeErr)
			}
		})
	}
}

// identityWhereClause and sanitizeForIdent are small test-local
// conveniences, not production logic: they let the table above name
// each case's identity once and derive both the resolving WHERE clause
// and a safe probe-table suffix from it.
func identityWhereClause(identity string) string {
	return `(pg_identify_object('pg_class'::regclass, c.oid, 0)).identity = '` + strings.ReplaceAll(identity, "'", "''") + `'`
}

func sanitizeForIdent(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, s)
}

// TestD55AmbiguousKeyResolvesDeterministically is D55's other half:
// before this addendum, the unquoted nspname||'.'||relname join key was
// ambiguous -- two different relations could concatenate to the same
// string (schema "d55_amb.b" table c, and schema "d55_amb" table
// "b.c" both concatenate to "d55_amb.b.c") -- so `SELECT ... INTO`
// could silently bind to whichever one heap order returned first. The
// pg_identify_object-keyed join is exact, not a string match, so only
// the relation that was actually registered is ever resolved.
func TestD55AmbiguousKeyResolvesDeterministically(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	ctx := context.Background()

	superuser, err := pgx.Connect(ctx, superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuser.Close(context.Background())

	t.Cleanup(func() {
		bg := context.Background()
		c, err := pgx.Connect(bg, superuserDSN)
		if err != nil {
			t.Errorf("cleanup connect: %v", err)
			return
		}
		defer c.Close(bg)
		_, _ = c.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop DISABLE`)
		_, _ = c.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`)
		_, _ = c.Exec(bg, `DELETE FROM sec7_protected_relation WHERE identity = '"d55_amb.b".c'`)
		_, _ = c.Exec(bg, `DROP SCHEMA IF EXISTS "d55_amb.b" CASCADE`)
		_, _ = c.Exec(bg, `DROP SCHEMA IF EXISTS d55_amb CASCADE`)
		_, _ = c.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_drop ENABLE ALWAYS`)
		_, _ = c.Exec(bg, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter ENABLE ALWAYS`)
	})

	var registeredOID uint32
	withD34TriggersDisabled(t, ctx, superuser, func() {
		if _, err := superuser.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS "d55_amb.b"`); err != nil {
			t.Fatalf("create schema d55_amb.b: %v", err)
		}
		if _, err := superuser.Exec(ctx, `CREATE TABLE "d55_amb.b".c (id int PRIMARY KEY)`); err != nil {
			t.Fatalf("create table c in d55_amb.b: %v", err)
		}
		if _, err := superuser.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS d55_amb`); err != nil {
			t.Fatalf("create schema d55_amb: %v", err)
		}
		if _, err := superuser.Exec(ctx, `CREATE TABLE d55_amb."b.c" (id int PRIMARY KEY)`); err != nil {
			t.Fatalf("create table b.c in d55_amb: %v", err)
		}

		if err := superuser.QueryRow(ctx, `SELECT c.oid FROM pg_class c WHERE (pg_identify_object('pg_class'::regclass, c.oid, 0)).identity = '"d55_amb.b".c'`).Scan(&registeredOID); err != nil {
			t.Fatalf("resolve \"d55_amb.b\".c oid: %v", err)
		}
		// Confirm the old, unquoted key really was ambiguous between
		// the two relations before registering either -- the precondition
		// this test's claim depends on.
		var ambiguousCount int
		if err := superuser.QueryRow(ctx, `
			SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
			WHERE n.nspname || '.' || c.relname = 'd55_amb.b.c'
		`).Scan(&ambiguousCount); err != nil {
			t.Fatalf("count ambiguous matches: %v", err)
		}
		if ambiguousCount != 2 {
			t.Fatalf("test precondition failed: expected the unquoted concatenation to match 2 relations, found %d", ambiguousCount)
		}

		// Only the "d55_amb.b".c relation is registered.
		if _, err := superuser.Exec(ctx, `
			INSERT INTO sec7_protected_relation (objid, relowner, relkind, relrowsecurity, relforcerowsecurity, trigger_oids, index_defs, policy_oids, identity)
			SELECT c.oid, c.relowner, c.relkind, c.relrowsecurity, c.relforcerowsecurity, ARRAY[]::oid[], ARRAY[]::text[], ARRAY[]::oid[], '"d55_amb.b".c'
			FROM pg_class c WHERE c.oid = $1
		`, registeredOID); err != nil {
			t.Fatalf("register scratch relation: %v", err)
		}
		if _, err := superuser.Exec(ctx, `DROP TABLE "d55_amb.b".c`); err != nil {
			t.Fatalf("drop \"d55_amb.b\".c: %v", err)
		}
		if _, err := superuser.Exec(ctx, `CREATE TABLE "d55_amb.b".c (id int PRIMARY KEY)`); err != nil {
			t.Fatalf("recreate \"d55_amb.b\".c: %v", err)
		}
	})

	_, probeErr := superuser.Exec(ctx, `CREATE TABLE zz_d55_amb_probe (id int)`)
	defer func() { _, _ = superuser.Exec(ctx, `DROP TABLE IF EXISTS zz_d55_amb_probe`) }()
	if probeErr == nil {
		t.Fatal("ADR-0007 Addendum 6 D55: expected the drop-and-recreate to trip the diagnostic")
	}
	var pgErr *pgconn.PgError
	if !errors.As(probeErr, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("expected SQLSTATE P0001, got %q: %v", pgErrorCode(probeErr), probeErr)
	}
	if !strings.Contains(probeErr.Error(), `"d55_amb.b".c`) {
		t.Fatalf("ADR-0007 Addendum 6 D55: expected the message to name the registered relation \"d55_amb.b\".c specifically, got: %v", probeErr)
	}
	if !strings.Contains(probeErr.Error(), "dropped and recreated in place") {
		t.Fatalf("expected message (b), got: %v", probeErr)
	}
}
