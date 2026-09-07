// ADR-0007 Addendum 11 D101/D103 test 9 (the provisioning half): D96
// rows 19 and 20 found two provisioning assertions in
// scripts/ci/provision_test_roles.sh that select a catalog object by
// bare name -- proname alone (row 19) and relname alone, nine sites (row
// 20) -- each reachable by a section 2 role with an ordinary,
// unprivileged statement. Both must FAIL TODAY (before the fix) with a
// false stated reason, and PASS after. This runs the real, committed
// script via exec.Command, exactly as d52_recovery_pgx_test.go and
// d62_launder_refusal_pgx_test.go already do -- not a reimplementation
// of its SQL.
package screeningledger

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func requireTestDatabaseURL(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("OWL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("OWL_TEST_DATABASE_URL not set")
	}
	return dsn
}

// runGrantDDLOwnership (this file's calls) reuses the shared helper of
// the same name in d77_body_digest_pgx_test.go, which runs the real,
// committed script via exec.Command and returns (output, error) rather
// than (output, ok) -- ok is derived at each call site below.

// TestGrantDdlOwnershipSurvivesASameNamedFunctionElsewhere is D96 row 19
// / D101(O-D): owl_migrator -- which holds CREATE on schema public, the
// only section 2 role that does -- creates an OVERLOAD of
// sec7_protect_ddl_objects (a different argument list, not a
// replacement; the genuine SECURITY DEFINER function is untouched). The
// pre-fix bare `proname='sec7_protect_ddl_objects'` query returns both
// rows and `[[ "$x" == "t" ]]` fails against the resulting "t\nf" (or
// "f\nt"), reporting the genuine function as not SECURITY DEFINER -- a
// false reason. The qualified query (schema + zero-arg identity) ignores
// the overload entirely.
func TestGrantDdlOwnershipSurvivesASameNamedFunctionElsewhere(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)

	scriptPath := d62ScriptPath(t)
	// Pristine control: the script already passes on an untouched clone.
	if output, err := runGrantDDLOwnership(t, scriptPath, superuserDSN, clone.dbName); err != nil {
		t.Fatalf("pristine control: grant-ddl-ownership should pass on an untouched T1 clone, output:\n%s\nerr: %v", output, err)
	}

	cloneMigratorDSN := withDatabase(t, migratorDSN, clone.dbName)
	asMigrator, err := pgx.Connect(ctx, cloneMigratorDSN)
	if err != nil {
		t.Fatalf("connect as owl_migrator: %v", err)
	}
	defer asMigrator.Close(context.Background())

	if _, err := asMigrator.Exec(ctx, `CREATE FUNCTION public.sec7_protect_ddl_objects(a11probe int) RETURNS int LANGUAGE sql AS 'SELECT 1'`); err != nil {
		t.Fatalf("owl_migrator should be able to create this overload (CREATE on schema public, D96 row 19's own precondition): %v", err)
	}

	output, err := runGrantDDLOwnership(t, scriptPath, superuserDSN, clone.dbName)
	if err != nil {
		t.Fatalf("ADR-0007 Addendum 11 D101: expected grant-ddl-ownership to PASS despite an unrelated same-named function overload (the qualified query ignores it), got a FAIL:\n%s\nerr: %v", output, err)
	}
	if strings.Contains(output, "is not SECURITY DEFINER") {
		t.Fatalf("ADR-0007 Addendum 11 D101: grant-ddl-ownership reported the false 'not SECURITY DEFINER' reason D96 row 19 found:\n%s", output)
	}
}

// TestGrantDdlOwnershipSurvivesAConcurrentTempTable is D96 row 20 /
// D101(O-D): owl_app -- the LEAST privileged section 2 role, holding no
// grant on screening_ledger_anchor at all -- holds one ordinary,
// committed TEMP table of the same name in a concurrent session (PUBLIC
// gets CREATE TEMP by Postgres default). The pre-fix bare
// `relname='screening_ledger_anchor'` query returns two rows and
// `[[ "$x" == "1" ]]` fails against "1\n1", reporting the table as
// missing -- a false, and merely TRANSIENT, reason: the same command
// succeeds once the temp session ends. The namespace-qualified query
// (relnamespace='public') ignores the pg_temp_N row entirely, since
// CREATE TEMP TABLE never creates a relation in schema public regardless
// of search_path.
func TestGrantDdlOwnershipSurvivesAConcurrentTempTable(t *testing.T) {
	superuserDSN := requireBootstrapSuperuserDatabaseURL(t)
	migratorDSN := requireMigratorDSN(t)
	ledgerDDLDSN := requireLedgerDDLDatabaseURL(t)
	appDSN := requireTestDatabaseURL(t)
	ctx := context.Background()

	clone := newD50Clone(t, ctx, superuserDSN, migratorDSN, ledgerDDLDSN)
	cloneAppDSN := withDatabase(t, appDSN, clone.dbName)

	scriptPath := d62ScriptPath(t)
	if output, err := runGrantDDLOwnership(t, scriptPath, superuserDSN, clone.dbName); err != nil {
		t.Fatalf("pristine control: grant-ddl-ownership should pass on an untouched T1 clone, output:\n%s\nerr: %v", output, err)
	}

	asApp, err := pgx.Connect(ctx, cloneAppDSN)
	if err != nil {
		t.Fatalf("connect as owl_app: %v", err)
	}
	defer asApp.Close(context.Background())
	if _, err := asApp.Exec(ctx, `CREATE TEMP TABLE screening_ledger_anchor(x int)`); err != nil {
		t.Fatalf("owl_app should be able to create an ordinary temp table (PUBLIC's default CREATE TEMP privilege, D96 row 20's own precondition): %v", err)
	}
	// Confirm the ambiguity is genuinely present before asserting the fix
	// survives it -- the same unqualified query D96 row 20 named.
	var ambiguousRowCount int
	superuserConn, err := pgx.Connect(ctx, clone.superuserDSN)
	if err != nil {
		t.Fatalf("connect as bootstrap superuser: %v", err)
	}
	defer superuserConn.Close(context.Background())
	if err := superuserConn.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relname = 'screening_ledger_anchor'`).Scan(&ambiguousRowCount); err != nil {
		t.Fatal(err)
	}
	if ambiguousRowCount != 2 {
		t.Fatalf("test construction error: expected 2 rows to match the bare relname (public + pg_temp), got %d", ambiguousRowCount)
	}

	output, err := runGrantDDLOwnership(t, scriptPath, superuserDSN, clone.dbName)
	if err != nil {
		t.Fatalf("ADR-0007 Addendum 11 D101: expected grant-ddl-ownership to PASS despite a concurrent same-named temp table (the namespace-qualified query ignores it), got a FAIL:\n%s\nerr: %v", output, err)
	}
	if strings.Contains(output, "FAIL:") {
		t.Fatalf("ADR-0007 Addendum 11 D101: grant-ddl-ownership reported a FAIL line despite the fix, output:\n%s", output)
	}

	// Transience, per D96 row 20's own severity note: once the temp
	// session ends, the ambiguity is gone even under the OLD query --
	// asserted here so a reader does not mistake this fix for having
	// changed that.
	if err := asApp.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// Give the backend a moment to actually terminate and drop its temp
	// schema before checking.
	for i := 0; i < 50; i++ {
		if err := superuserConn.QueryRow(ctx, `SELECT count(*) FROM pg_class WHERE relname = 'screening_ledger_anchor'`).Scan(&ambiguousRowCount); err != nil {
			t.Fatal(err)
		}
		if ambiguousRowCount == 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if ambiguousRowCount != 1 {
		t.Fatalf("expected the temp table's pg_class row to be gone once its session closed, still see %d matching rows", ambiguousRowCount)
	}
}
