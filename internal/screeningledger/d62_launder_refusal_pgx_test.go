// ADR-0007 Addendum 7 D62/D67 test 3 (K-B, MEDIUM): grant-ddl-ownership
// must refuse to launder an attacker-planted object into
// sec7_protected_relation's recording, by name, rather than record it as
// legitimate. Reproduces CAP #6 §7.5's exact sequence -- an attacker
// index, then the operator document's own recovery run verbatim -- and
// proves both halves per D42/D47's convention: the pre-fix mechanism (a
// bare DELETE/INSERT ... SELECT straight out of the live catalog,
// asserted only by a row count) DOES record the attacker's index, while
// the shipped script -- which now asserts live state against the
// declared literal before recording anything -- refuses, naming it.
// Plus the two positives that make this safe to install: a genuine
// pg_dump|psql restore still re-provisions, and a first-ever run on a
// freshly migrated database still succeeds.
package screeningledger

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// preD62RecordProtectedRelationState reconstructs the DELETE/INSERT ...
// SELECT ADR-0007 Addendum 7 D62(a) now guards -- the shipped mechanism
// before this addendum, straight out of the live catalog with no
// comparison against a declared literal. Per D42/D47's convention:
// proving only the post-fix refusal cannot distinguish a working fix
// from a test that never exercised the gap.
func preD62RecordProtectedRelationState(t *testing.T, ctx context.Context, superuser *pgx.Conn) {
	t.Helper()
	if _, err := superuser.Exec(ctx, `DELETE FROM sec7_protected_relation`); err != nil {
		t.Fatalf("pre-D62 DELETE FROM sec7_protected_relation: %v", err)
	}
	if _, err := superuser.Exec(ctx, `
		INSERT INTO sec7_protected_relation (objid, relowner, relkind, relrowsecurity, relforcerowsecurity, trigger_oids, index_defs, policy_oids, identity)
		SELECT c.oid, c.relowner, c.relkind, c.relrowsecurity, c.relforcerowsecurity,
		  COALESCE((SELECT array_agg(t.oid ORDER BY t.oid) FROM pg_trigger t WHERE t.tgrelid = c.oid AND NOT t.tgisinternal), ARRAY[]::oid[]),
		  COALESCE((SELECT array_agg(pg_get_indexdef(ix.indexrelid) ORDER BY pg_get_indexdef(ix.indexrelid)) FROM pg_index ix WHERE ix.indrelid = c.oid), ARRAY[]::text[]),
		  COALESCE((SELECT array_agg(p.oid ORDER BY p.oid) FROM pg_policy p WHERE p.polrelid = c.oid), ARRAY[]::oid[]),
		  (pg_identify_object('pg_class'::regclass, c.oid, 0)).identity
		FROM pg_class c
		WHERE c.oid IN ('screening_ledger_anchor'::regclass::oid, 'screening_ledger_retention_tombstone'::regclass::oid)
	`); err != nil {
		t.Fatalf("pre-D62 INSERT INTO sec7_protected_relation: %v", err)
	}
}

func d62ScriptPath(t *testing.T) string {
	t.Helper()
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	return filepath.Join(repoRoot, "scripts", "ci", "provision_test_roles.sh")
}

func TestGrantDdlOwnershipRefusesToRecordUndeclaredState(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()
	scriptPath := d62ScriptPath(t)

	t.Run("pre-D62 mechanism launders the attacker's index", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuserConn.Close(context.Background())

		if _, err := superuserConn.Exec(ctx, `CREATE INDEX CONCURRENTLY cap7_evil ON screening_ledger_anchor (anchored_at)`); err == nil {
			t.Fatal("expected CREATE INDEX CONCURRENTLY on a protected relation to wedge the database (ADR-0007 Addendum 6 D50)")
		}
		assertWedged(t, ctx, clone.superuserDSN, "zz_d62_pre_wedge_probe")

		withD34TriggersDisabled(t, ctx, superuserConn, func() {
			preD62RecordProtectedRelationState(t, ctx, superuserConn)
		})

		var indexDefs []string
		if err := superuserConn.QueryRow(ctx, `SELECT index_defs FROM sec7_protected_relation WHERE identity = 'public.screening_ledger_anchor'`).Scan(&indexDefs); err != nil {
			t.Fatalf("read recorded index_defs: %v", err)
		}
		found := false
		for _, d := range indexDefs {
			if strings.Contains(d, "cap7_evil") {
				found = true
			}
		}
		if !found {
			t.Fatalf("ADR-0007 Addendum 7 D62: expected the pre-fix mechanism to record the attacker's index cap7_evil as legitimate; index_defs=%v", indexDefs)
		}
	})

	t.Run("shipped grant-ddl-ownership refuses, naming the index", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuserConn.Close(context.Background())

		if _, err := superuserConn.Exec(ctx, `CREATE INDEX CONCURRENTLY cap7_evil ON screening_ledger_anchor (anchored_at)`); err == nil {
			t.Fatal("expected CREATE INDEX CONCURRENTLY on a protected relation to wedge the database (ADR-0007 Addendum 6 D50)")
		}
		assertWedged(t, ctx, clone.superuserDSN, "zz_d62_shipped_wedge_probe")

		if _, err := superuserConn.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
			t.Fatalf("disable event trigger (recovery step 1): %v", err)
		}

		host, port, superuser, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)
		cmd := exec.Command(scriptPath, "grant-ddl-ownership")
		cmd.Env = append(cmd.Environ(),
			"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+clone.dbName,
			"PGSUPERUSER="+superuser, "PGSUPERPASSWORD="+superpassword,
		)
		output, runErr := cmd.CombinedOutput()
		t.Logf("grant-ddl-ownership output:\n%s", output)
		if runErr == nil {
			t.Fatal("ADR-0007 Addendum 7 D62: grant-ddl-ownership succeeded against a database with an undeclared attacker index -- expected refusal")
		}
		if !strings.Contains(string(output), "cap7_evil") {
			t.Fatalf("expected the refusal to name cap7_evil, got:\n%s", output)
		}
		if !strings.Contains(string(output), "D62") {
			t.Fatalf("expected the refusal to cite ADR-0007 Addendum 7 D62, got:\n%s", output)
		}
	})

	t.Run("genuine pg_dump|psql restore still re-provisions", func(t *testing.T) {
		clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
		host, port, superuser, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)

		superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuserConn.Close(context.Background())

		restoredDB := fmt.Sprintf("owl_ci_d62_restored_%d", time.Now().UnixNano())
		if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s`, pgx.Identifier{restoredDB}.Sanitize())); err != nil {
			t.Fatalf("CREATE DATABASE %s: %v", restoredDB, err)
		}
		t.Cleanup(func() {
			bg := context.Background()
			c, err := pgx.Connect(bg, clone.superuserDSN)
			if err != nil {
				t.Errorf("drop %s: connect: %v", restoredDB, err)
				return
			}
			defer c.Close(bg)
			if _, err := c.Exec(bg, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{restoredDB}.Sanitize())); err != nil {
				t.Errorf("drop %s: %v", restoredDB, err)
			}
		})

		dumpCmd := exec.Command("sh", "-c", `pg_dump -h "$SRC_HOST" -p "$SRC_PORT" -U "$SRC_USER" -d "$SRC_DB" | psql -h "$SRC_HOST" -p "$SRC_PORT" -U "$SRC_USER" -d "$DST_DB" -X -q -v ON_ERROR_STOP=1`)
		dumpCmd.Env = append(os.Environ(),
			"SRC_HOST="+host, "SRC_PORT="+port, "SRC_USER="+superuser, "SRC_DB="+clone.dbName,
			"DST_DB="+restoredDB, "PGPASSWORD="+superpassword,
		)
		if out, err := dumpCmd.CombinedOutput(); err != nil {
			t.Fatalf("pg_dump | psql restore: %v\n%s", err, out)
		}

		restoredSuperuserConn, err := pgx.Connect(ctx, withDatabase(t, superuserDSN, restoredDB))
		if err != nil {
			t.Fatalf("connect to restored database: %v", err)
		}
		defer restoredSuperuserConn.Close(context.Background())

		// The restore is genuinely bricked by D46 first (OIDs changed).
		_, probeErr := restoredSuperuserConn.Exec(ctx, `CREATE TABLE zz_d62_restore_probe (id int)`)
		if probeErr == nil {
			t.Fatal("test precondition failed: an unrelated CREATE TABLE on the freshly restored database should be refused by D46 before recovery")
		}
		if !strings.Contains(probeErr.Error(), "Addendum 5 D46") {
			t.Fatalf("expected the D46 copy/restore refusal, got: %v", probeErr)
		}

		if _, err := restoredSuperuserConn.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
			t.Fatalf("disable event trigger (recovery step 1): %v", err)
		}
		restoredHost, restoredPort, _, _ := pgConnParamsFromDSN(t, withDatabase(t, superuserDSN, restoredDB))
		cmd := exec.Command(scriptPath, "grant-ddl-ownership")
		cmd.Env = append(cmd.Environ(),
			"PGHOST="+restoredHost, "PGPORT="+restoredPort, "PGDATABASE="+restoredDB,
			"PGSUPERUSER="+superuser, "PGSUPERPASSWORD="+superpassword,
		)
		output, runErr := cmd.CombinedOutput()
		t.Logf("grant-ddl-ownership output on restored database:\n%s", output)
		if runErr != nil {
			t.Fatalf("ADR-0007 Addendum 7 D62: grant-ddl-ownership should still succeed against a genuine restore (I-A recovery path), got: %v", runErr)
		}

		assertHealthy(t, ctx, withDatabase(t, superuserDSN, restoredDB), "zz_d62_restore_recovered_probe")
	})

	t.Run("first-ever run on a freshly migrated database still succeeds", func(t *testing.T) {
		superuserConn, err := pgx.Connect(ctx, superuserDSN)
		if err != nil {
			t.Fatalf("connect as bootstrap superuser: %v", err)
		}
		defer superuserConn.Close(context.Background())

		freshDB := fmt.Sprintf("owl_ci_d62_fresh_%d", time.Now().UnixNano())
		if _, err := superuserConn.Exec(ctx, fmt.Sprintf(`CREATE DATABASE %s OWNER owl_migrator`, pgx.Identifier{freshDB}.Sanitize())); err != nil {
			t.Fatalf("CREATE DATABASE %s: %v", freshDB, err)
		}
		t.Cleanup(func() {
			bg := context.Background()
			c, err := pgx.Connect(bg, superuserDSN)
			if err != nil {
				t.Errorf("drop %s: connect: %v", freshDB, err)
				return
			}
			defer c.Close(bg)
			if _, err := c.Exec(bg, fmt.Sprintf(`DROP DATABASE IF EXISTS %s WITH (FORCE)`, pgx.Identifier{freshDB}.Sanitize())); err != nil {
				t.Errorf("drop %s: %v", freshDB, err)
			}
		})

		migratorHost, migratorPort, migratorUser, migratorPassword := pgConnParamsFromDSN(t, withDatabase(t, migratorDSN, freshDB))
		repoRoot, err := filepath.Abs("../..")
		if err != nil {
			t.Fatalf("resolve repo root: %v", err)
		}
		migDir := filepath.Join(repoRoot, "db", "migrations")
		entries, err := os.ReadDir(migDir)
		if err != nil {
			t.Fatalf("read %s: %v", migDir, err)
		}
		var files []string
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
				files = append(files, e.Name())
			}
		}
		sort.Strings(files)
		if len(files) == 0 {
			t.Fatalf("no migration files found in %s", migDir)
		}
		for _, f := range files {
			cmd := exec.Command("psql", "-h", migratorHost, "-p", migratorPort, "-U", migratorUser, "-d", freshDB, "-X", "-q", "-v", "ON_ERROR_STOP=1", "-f", filepath.Join(migDir, f))
			cmd.Env = append(cmd.Environ(), "PGPASSWORD="+migratorPassword)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("apply migration %s: %v\n%s", f, err, out)
			}
		}

		host, port, superuser, superpassword := pgConnParamsFromDSN(t, superuserDSN)
		cmd := exec.Command(scriptPath, "grant-ddl-ownership")
		cmd.Env = append(cmd.Environ(),
			"PGHOST="+host, "PGPORT="+port, "PGDATABASE="+freshDB,
			"PGSUPERUSER="+superuser, "PGSUPERPASSWORD="+superpassword,
		)
		output, runErr := cmd.CombinedOutput()
		t.Logf("grant-ddl-ownership output on freshly migrated database:\n%s", output)
		if runErr != nil {
			t.Fatalf("ADR-0007 Addendum 7 D62: a first-ever grant-ddl-ownership run on a freshly migrated database should succeed, got: %v", runErr)
		}
	})
}
