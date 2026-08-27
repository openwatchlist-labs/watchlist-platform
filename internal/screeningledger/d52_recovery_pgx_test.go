// ADR-0007 Addendum 6 D52/D58 test 4: the drifted, non-copied database
// (J-A's residual before D50/D51 landed, and still reachable to a
// superuser after) gets a tested recovery, not only a documented one.
// Per D58's own explicit decision (CAP #5 §11 point 1(c), answered "no"
// rather than defaulted): this is NOT a permanent CI fixture. The wedge
// is built and torn down inside this test, from a TEMPLATE clone, the
// same way d50_index_referent_pgx_test.go's tests do -- a database in
// which every DDL statement fails is a poor shared fixture, and J-B
// (D53) is the standing demonstration of what a shared fixture with
// destructive state costs.
package screeningledger

import (
	"context"
	"errors"
	"net/url"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pgConnParamsFromDSN extracts host, port, user and password from a
// postgres:// DSN produced by provision_test_roles.sh, for handing to
// the script itself as PGHOST/PGPORT/PGSUPERUSER/PGSUPERPASSWORD --
// the same variables the script reads (scripts/ci/provision_test_roles.sh:33-37).
func pgConnParamsFromDSN(t *testing.T, dsn string) (host, port, user, password string) {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatalf("parse DSN %q: %v", dsn, err)
	}
	host = u.Hostname()
	port = u.Port()
	user = u.User.Username()
	password, _ = u.User.Password()
	return host, port, user, password
}

func TestD52WedgedDatabaseRecoversByDocumentedProcedure(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	// This test wedges the clone itself. D50 makes the REINDEX ...
	// CONCURRENTLY route this doc section was originally written around
	// no longer wedge (that repair is d50_index_referent_pgx_test.go's
	// own scope); D52's own text says every OTHER D40 branch --
	// owner, relkind, RLS flags, rules, inheritance, triggers, policies
	// -- still raises the bare-integer form and still wedges, so this
	// test drifts the RECORDED relowner directly (the same DML-only
	// tamper d47_recorded_state_pgx_test.go uses, which the D26/D34
	// event triggers never see since they fire on DDL, not DML) --
	// the general "drifted, non-copied database" shape D52 exists for,
	// with the real catalog owner left untouched so grant-ddl-ownership
	// re-derives the correct value in step 2.
	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	if _, err := superuserConn.Exec(ctx, `UPDATE sec7_protected_relation SET relowner = 'owl_migrator'::regrole::oid WHERE identity = 'public.screening_ledger_anchor'`); err != nil {
		t.Fatalf("drift recorded relowner (test precondition): %v", err)
	}
	assertWedged(t, ctx, clone.superuserDSN, "zz_d52_wedge_probe")

	// Step 1: get DDL working again.
	defer superuserConn.Close(context.Background())
	if _, err := superuserConn.Exec(ctx, `ALTER EVENT TRIGGER sec7_protect_ddl_objects_on_alter DISABLE`); err != nil {
		t.Fatalf("step 1 (ALTER EVENT TRIGGER ... DISABLE) should succeed even while the invariant is failing: %v", err)
	}

	// Step 2: re-record the registries against this database's actual
	// OIDs, by running the real, committed script -- not a
	// reimplementation of it -- against the wedged clone.
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	scriptPath := filepath.Join(repoRoot, "scripts", "ci", "provision_test_roles.sh")
	host, port, superuser, superpassword := pgConnParamsFromDSN(t, clone.superuserDSN)
	cmd := exec.Command(scriptPath, "grant-ddl-ownership")
	cmd.Env = append(cmd.Environ(),
		"PGHOST="+host,
		"PGPORT="+port,
		"PGDATABASE="+clone.dbName,
		"PGSUPERUSER="+superuser,
		"PGSUPERPASSWORD="+superpassword,
	)
	output, runErr := cmd.CombinedOutput()
	t.Logf("grant-ddl-ownership output:\n%s", output)
	if runErr != nil {
		t.Fatalf("step 2 (grant-ddl-ownership) failed: %v", runErr)
	}

	// Step 3: confirm both event triggers are back to ENABLE ALWAYS.
	rows, err := superuserConn.Query(ctx, `SELECT evtname, evtenabled FROM pg_event_trigger WHERE evtname IN ('sec7_protect_ddl_objects_on_drop', 'sec7_protect_ddl_objects_on_alter')`)
	if err != nil {
		t.Fatalf("query event trigger state: %v", err)
	}
	states := map[string]string{}
	for rows.Next() {
		var name, enabled string
		if err := rows.Scan(&name, &enabled); err != nil {
			t.Fatalf("scan event trigger row: %v", err)
		}
		states[name] = enabled
	}
	rows.Close()
	for _, name := range []string{"sec7_protect_ddl_objects_on_drop", "sec7_protect_ddl_objects_on_alter"} {
		if states[name] != "A" {
			t.Fatalf("expected %s to be ENABLE ALWAYS ('A') after recovery, got %q", name, states[name])
		}
	}

	// DDL works afterwards, for everyone -- the recovery's actual
	// point, not merely that the script exited 0.
	assertHealthy(t, ctx, clone.superuserDSN, "zz_d52_recovered_probe")
	migratorRecoveredDSN := withDatabase(t, migratorDSN, clone.dbName)
	migratorConn, err := pgx.Connect(ctx, migratorRecoveredDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer migratorConn.Close(context.Background())
	if _, err := migratorConn.Exec(ctx, `CREATE TABLE zz_d52_migrator_probe (id int)`); err != nil {
		t.Fatalf("unrelated CREATE TABLE as owl_migrator should succeed after recovery: %v", err)
	}
	if _, err := migratorConn.Exec(ctx, `DROP TABLE zz_d52_migrator_probe`); err != nil {
		t.Fatalf("cleanup zz_d52_migrator_probe: %v", err)
	}

	// D52 part 1: the per-branch diagnostic now names the relation on
	// every D40 branch, not only on the D46 copy/restore branch. A real
	// ALTER TABLE ... OWNER TO against a currently-registered protected
	// table is caught by D34's own objid membership check before D40's
	// second phase ever runs (confirmed above by grant-ddl-ownership's
	// own re-population), so the owner-changed branch specifically is
	// reached the same way this test's own wedge was built: drifting
	// the RECORDED value directly (DML, invisible to the DDL event
	// triggers), then tripping any subsequent DDL statement.
	if _, err := superuserConn.Exec(ctx, `UPDATE sec7_protected_relation SET relowner = 'owl_migrator'::regrole::oid WHERE identity = 'public.screening_ledger_anchor'`); err != nil {
		t.Fatalf("drift recorded relowner again: %v", err)
	}
	_, probeErr := superuserConn.Exec(ctx, `CREATE TABLE zz_d52_owner_probe (id int)`)
	if probeErr == nil {
		t.Fatal("ADR-0007 Addendum 4 D40: unrelated CREATE TABLE succeeded with a drifted recorded relowner")
	}
	var pgErr *pgconn.PgError
	if !errors.As(probeErr, &pgErr) || pgErr.Code != "P0001" {
		t.Fatalf("expected SQLSTATE P0001, got %q: %v", pgErrorCode(probeErr), probeErr)
	}
	if !strings.Contains(probeErr.Error(), `protected relation "public.screening_ledger_anchor"`) || !strings.Contains(probeErr.Error(), "its owner changed") {
		t.Fatalf("ADR-0007 Addendum 6 D52: expected the owner-changed diagnostic to name the relation by identity, got: %v", probeErr)
	}
}
